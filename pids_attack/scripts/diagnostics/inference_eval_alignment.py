#!/usr/bin/env python3
"""推理 vs eval 严格对齐测试(层次 C)。

假设:**数据源对齐** —— 推理跟 eval 用同一份 `test_data`(PIDSMaker 的
`get_preprocessed_graphs()` 返回),不走 SQL → cdm_to_nx_graph 重建路径。

测试逻辑:
  1. 用 PIDSMakerEngine 加载训练好的模型 + threshold + kmeans 配置
  2. 拿 PIDSMaker 的 test_data,逐 TW 图 forward
  3. 镜像 PIDSMaker `node_evaluation.py` 的聚合方式:
       跨 TW 收集 per-node losses → reduce_to_max → apply_threshold(+ kmeans)
  4. 跟 eval pkl 的 y_preds 按 node_id 严格 per-node 比对
  5. 输出每个 detector 的 (uniq_nodes, matched, diff, yp_sum)

剩余预期偏差源(物理):
  ① TGN nb_loader 状态:推理重建 vs eval 累积训练状态 → kairos/velox/orthrus
  ② kmeans 全局 vs 单图:orthrus 走 kmeans 分支
  ③ magic 随机采样:NearestNeighbors 抽 5000 节点不固定 seed

用法:
    conda run -n mimicattack python scripts/diagnostics/inference_eval_alignment.py
    conda run -n mimicattack python scripts/diagnostics/inference_eval_alignment.py kairos
"""
from __future__ import annotations
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "PIDSMaker"))


def collect_inference_y_preds(det_name: str):
    """喂 eval 用过的 test_data 给推理代码,出 per-unique-node y_pred.

    跨 TW 聚合方式严格镜像 PIDSMaker node_evaluation.py:
      - threatrace / flash: 遍历同 node 所有 obs,任一满足 (score > thr ∧ correct_pred==1) → y=1
      - magic:              遍历同 node 所有 obs,任一满足 score > thr → y=1
      - loss-based:         max(loss across obs) > thr → y=1
      - kmeans (orthrus):   per-node pred_score = max(loss),然后 top-K 簇
    """
    import torch
    from collections import defaultdict

    from detection.training.pidsmaker import (
        PIDSMakerEngine,
        compute_detector_score,
        _kmeans_top_k_labels,
    )
    from pidsmaker.tasks.batching import get_preprocessed_graphs

    eng = PIDSMakerEngine(det_name)
    eng._ensure_loaded()
    model = eng._model
    cfg = eng._cfg
    thr = eng._threshold
    method = eng._threshold_method
    use_kmeans = eng._use_kmeans
    topK = eng._kmeans_top_K
    device = eng._device

    _, _, test_data, _, _ = get_preprocessed_graphs(cfg)

    # 跨 TW 收集每个 node 的所有 obs
    node_to_obs = defaultdict(list)
    with torch.no_grad():
        for tw in test_data:
            for batch in tw:
                batch_iter = batch if isinstance(batch, list) else [batch]
                for data in batch_iter:
                    data_iter = data if isinstance(data, list) else [data]
                    for d in data_iter:
                        d = d.to(device)
                        if hasattr(model, "reset_state"):
                            model.reset_state()
                        out = model(d, inference=True, validation=False)
                        node_list = compute_detector_score(
                            out, d, cfg,
                            magic_train_distance=eng._magic_train_distance,
                            model=model,
                        )
                        for nd in node_list:
                            node_to_obs[nd["node"]].append(nd)

    # 镜像 PIDSMaker node_evaluation.py 的「任一 obs 满足条件」聚合
    y_preds_dict = {}
    pred_scores = {}  # for kmeans

    for nid, obs_list in node_to_obs.items():
        if method == "threatrace":
            label = 0
            for obs in obs_list:
                if (obs.get("threatrace_score", 0.0) > thr
                        and obs.get("correct_pred", 0) == 1):
                    label = 1
                    break
            y_preds_dict[nid] = label
            pred_scores[nid] = max(o.get("threatrace_score", 0.0) for o in obs_list)
        elif method == "flash":
            label = 0
            for obs in obs_list:
                if (obs.get("flash_score", 0.0) > thr
                        and obs.get("correct_pred", 0) == 1):
                    label = 1
                    break
            y_preds_dict[nid] = label
            pred_scores[nid] = max(o.get("flash_score", 0.0) for o in obs_list)
        elif method == "magic":
            label = 0
            for obs in obs_list:
                if obs.get("magic_score", 0.0) > thr:
                    label = 1
                    break
            y_preds_dict[nid] = label
            pred_scores[nid] = max(o.get("magic_score", 0.0) for o in obs_list)
        else:
            # max_val_loss / nodlink / p90/p98/p99_val_loss
            max_loss = max(o.get("loss", 0.0) for o in obs_list)
            y_preds_dict[nid] = int(max_loss > thr)
            pred_scores[nid] = max_loss

    # kmeans 覆盖(orthrus)—— 镜像 PIDSMaker compute_kmeans_labels:全 node pred_score 排,top-K + 2 簇
    if use_kmeans and len(pred_scores) >= 2:
        score_dicts = [{"loss": pred_scores[nid]} for nid in pred_scores]
        ids_in_order = list(pred_scores.keys())
        # _kmeans_top_k_labels 用 "loss" 字段(method 不 in {threatrace,flash,magic} 时)
        # orthrus 的 threshold_method 是 max_val_loss,走这分支
        y_arr = _kmeans_top_k_labels(score_dicts, topK, method)
        y_preds_dict = {nid: int(bool(y)) for nid, y in zip(ids_in_order, y_arr)}

    return y_preds_dict


def collect_eval_y_preds(det_name: str):
    """从 eval pkl 拿 (node_id → y_pred) 字典."""
    from detection.training.pidsmaker import load_eval_pkl
    data, _ = load_eval_pkl(det_name)
    if data is None:
        return None
    return dict(zip(list(data["nodes"]), list(data["y_preds"])))


def compare(det_name: str):
    inf = collect_inference_y_preds(det_name)
    ev = collect_eval_y_preds(det_name)
    if ev is None:
        return None

    common = set(inf.keys()) & set(ev.keys())
    inf_only = set(inf.keys()) - set(ev.keys())
    ev_only = set(ev.keys()) - set(inf.keys())
    diff_nodes = [n for n in common if inf[n] != ev[n]]

    return {
        "inf_total": len(inf),
        "ev_total": len(ev),
        "common": len(common),
        "inf_only": len(inf_only),
        "ev_only": len(ev_only),
        "diff": len(diff_nodes),
        "inf_yp_sum": sum(inf.values()),
        "ev_yp_sum": sum(ev.values()),
        "diff_nodes_sample": diff_nodes[:5],  # 前 5 个 diff 节点 ID
    }


def main(argv):
    detectors = argv or [
        "threatrace", "kairos", "magic", "flash",
        "velox", "rcaid", "nodlink", "orthrus",
    ]

    print()
    print("=" * 92)
    print("  推理代码 vs eval pkl 严格对齐(数据源对齐:都用 PIDSMaker test_data)")
    print("=" * 92)
    print(f"  {'detector':<12} {'inf':>5}/{'eval':>5} "
          f"{'共同':>5} {'inf独':>5} {'ev独':>5} "
          f"{'diff':>5}  {'inf_yp':>7} {'ev_yp':>7}  状态")
    print("  " + "-" * 88)

    summary = []
    for d in detectors:
        try:
            r = compare(d)
        except Exception as e:
            print(f"  {d:<12} ERROR: {type(e).__name__}: {e}")
            continue
        if r is None:
            print(f"  {d:<12} (no eval pkl, skip)")
            continue
        status = (
            "✓ 完美等价" if r["diff"] == 0 and r["inf_only"] == 0 and r["ev_only"] == 0
            else f"△ {r['diff']} diff" if r["diff"] < 25
            else f"✗ {r['diff']} diff"
        )
        print(f"  {d:<12} {r['inf_total']:>5}/{r['ev_total']:>5} "
              f"{r['common']:>5} {r['inf_only']:>5} {r['ev_only']:>5} "
              f"{r['diff']:>5}  {r['inf_yp_sum']:>7} {r['ev_yp_sum']:>7}  {status}")
        summary.append((d, r))

    print()
    print("  列说明:")
    print("    inf/eval — 各自 unique node 数")
    print("    共同      — 两边都有该 node 的 unique node 数")
    print("    inf独/ev独 — 仅一边有的 node 数(表示节点集合本身有差异)")
    print("    diff      — 共同 node 上 y_pred 不一致的数量")
    print("    inf_yp / ev_yp — 各自标 y=1 的 node 数")
    print()
    print("  预期残留偏差源(非代码 bug):")
    print("    TGN nb_loader 状态(kairos/velox/orthrus 推理冷启动)")
    print("    kmeans 全局 vs 单图(orthrus)")
    print("    magic 随机采样 NearestNeighbors(seed 不固定)")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
