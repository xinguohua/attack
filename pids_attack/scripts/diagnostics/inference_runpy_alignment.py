#!/usr/bin/env python3
"""推理 SQL 流程 vs eval 路径对齐(数据源物理换掉后的端到端验证)。

测 4 件事:
  ① 图-节点  推理 cdm_to_nx_graph 出的节点 ⊆ eval PIDSMaker construction 节点(同 path)
  ② 图-边    推理重建的边 ⊆ eval transformation 后的边(同 src_path, dst_path, edge_type)
  ③ 特征     共同节点上 (node_type, label) 是否一致(featurization 输入对齐)
  ④ 结果     共同节点上 y_pred 一致比例(端到端结果)

用法:
    conda run -n mimicattack python scripts/diagnostics/inference_runpy_alignment.py
    conda run -n mimicattack python scripts/diagnostics/inference_runpy_alignment.py kairos
"""
from __future__ import annotations
import os
import sys
import glob

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "PIDSMaker"))

ATTACK_DIR = os.path.join(PROJECT_ROOT, "detection", "data", "test_traces", "attack")
ATTACK_SCENARIOS = [
    "juiceshop_basket_idor",
    "juiceshop_db_schema_union_sqli",
    "juiceshop_directory_listing_ftp",
    "juiceshop_exposed_metrics",
    "juiceshop_login_admin_sqli",
    "juiceshop_login_bender_sqli",
    "juiceshop_login_jim_sqli",
    "juiceshop_redirect_open",
    "juiceshop_register_admin_mass_assignment",
    "juiceshop_weak_password_admin",
]
ATTACK_TO_DATE = {
    "juiceshop_basket_idor":                  "2026-01-05",
    "juiceshop_db_schema_union_sqli":         "2026-01-06",
    "juiceshop_directory_listing_ftp":        "2026-01-05",
    "juiceshop_exposed_metrics":              "2026-01-06",
    "juiceshop_login_admin_sqli":             "2026-01-05",
    "juiceshop_login_bender_sqli":            "2026-01-06",
    "juiceshop_login_jim_sqli":               "2026-01-05",
    "juiceshop_redirect_open":                "2026-01-06",
    "juiceshop_register_admin_mass_assignment": "2026-01-05",
    "juiceshop_weak_password_admin":          "2026-01-06",
}


def _parse_sql_paths(sql_path: str):
    """从 SQL 抽 idx_id → canonical path(跟 PIDSMaker `get_node_to_path_and_type` 对齐)."""
    from detection.training.pidsmaker import (
        _INSERT_NETFLOW_RE, _INSERT_SUBJECT_RE, _INSERT_FILE_RE,
    )
    with open(sql_path, "r", encoding="utf-8", errors="ignore") as f:
        sql = f.read()
    out = {}
    for m in _INSERT_NETFLOW_RE.finditer(sql):
        _, _, src_addr, src_port, dst_addr, dst_port, idx_id = m.groups()
        out[int(idx_id)] = f"{src_addr}:{src_port}->{dst_addr}:{dst_port}"
    for m in _INSERT_SUBJECT_RE.finditer(sql):
        _, _, path, _, idx_id = m.groups()
        out[int(idx_id)] = path
    for m in _INSERT_FILE_RE.finditer(sql):
        _, _, path, idx_id = m.groups()
        out[int(idx_id)] = path
    return out


def build_inference_graph(det_name: str, sql_path: str):
    """跟 predict_per_node 同一条路径但只到 cdm_to_nx_graph (+ transformation)."""
    from detection.training.pidsmaker import (
        _build_args, parse_sql_to_events_and_nodes, cdm_to_nx_graph,
    )
    from pidsmaker.config.pipeline import get_yml_cfg

    args = _build_args(det_name)
    cfg = get_yml_cfg(args)
    with open(sql_path, "r", encoding="utf-8", errors="ignore") as f:
        sql = f.read()
    events, indexid2msg = parse_sql_to_events_and_nodes(sql, cfg)
    graph = cdm_to_nx_graph(events, indexid2msg, cfg)
    # 不走 transformation,只看「读 SQL」这一步的图。跟 eval 比 construction 阶段。
    return graph, indexid2msg


def load_eval_graph(det_name: str, date: str):
    """读 PIDSMaker construction step 落盘的 nx 图."""
    import torch
    from detection.training.pidsmaker import _build_args
    from pidsmaker.config.pipeline import get_yml_cfg

    args = _build_args(det_name)
    cfg = get_yml_cfg(args)
    base = cfg.construction._graphs_dir
    files = glob.glob(os.path.join(base, f"graph_{date}", "*"))
    if not files:
        return None
    g = torch.load(files[0])
    return g


def graph_node_path_set(graph, idx_to_path):
    """nx graph → set of (path, node_type, label).
    用三元组当 key,避免同 path/type 但 cmd_line 不同的多个 subject 节点 collision."""
    out = set()
    for nid, attrs in graph.nodes(data=True):
        path = idx_to_path.get(int(nid), "") if idx_to_path is not None else ""
        if not path:
            continue
        out.add((path, attrs.get("node_type", ""), attrs.get("label", "")))
    return out


def graph_edge_path_set(graph, idx_to_path):
    """nx graph → {(src_path, dst_path, edge_type)}. 过滤掉 src 或 dst path 为空的边."""
    out = set()
    for u, v, k, attrs in graph.edges(data=True, keys=True):
        if idx_to_path is not None:
            su = idx_to_path.get(int(u), "")
            sv = idx_to_path.get(int(v), "")
        else:
            su, sv = u, v
        et = attrs.get("label", "")
        if su and sv:
            out.add((su, sv, et))
    return out


def get_eval_pkl_y(det_name: str, scenario_idx: int):
    """eval pkl 里这个 scenario GT attack 节点的 path → y_pred."""
    from detection.training.pidsmaker import _build_args
    from detection.training.pidsmaker import load_eval_pkl
    from pidsmaker.config.pipeline import get_yml_cfg
    from pidsmaker.utils.utils import get_node_to_path_and_type

    eval_data, _ = load_eval_pkl(det_name)
    if eval_data is None:
        return None, None
    cfg = get_yml_cfg(_build_args(det_name))
    id2label = {nid: info.get("path", "") for nid, info in get_node_to_path_and_type(cfg).items()}
    nodes = list(eval_data["nodes"])
    y_preds = list(eval_data["y_preds"])
    y_truth = list(eval_data["y_truth"])
    n2a = eval_data["node2attacks"]
    gt_path_to_y = {}
    for i, nid in enumerate(nodes):
        if y_truth[i] != 1: continue
        if scenario_idx not in n2a.get(nid, set()): continue
        lbl = id2label.get(nid, "")
        if lbl and (lbl not in gt_path_to_y or y_preds[i] == 1):
            gt_path_to_y[lbl] = int(y_preds[i])
    # 全 paths→y(不只 GT, 用于 ④ 结果比对)
    all_path_to_y = {}
    for i, nid in enumerate(nodes):
        lbl = id2label.get(nid, "")
        if lbl and (lbl not in all_path_to_y or y_preds[i] == 1):
            all_path_to_y[lbl] = int(y_preds[i])
    return gt_path_to_y, all_path_to_y


def test_one(det, det_name, scenario_idx, sid):
    sql = os.path.join(ATTACK_DIR, f"{sid}.strace.sql")
    if not os.path.exists(sql):
        return None

    # 推理侧:cdm_to_nx_graph + SQL paths
    idx_to_path = _parse_sql_paths(sql)
    inf_g, _ = build_inference_graph(det_name, sql)
    inf_nodes = graph_node_path_set(inf_g, idx_to_path)
    inf_edges = graph_edge_path_set(inf_g, idx_to_path)

    # eval 侧:同 date 的 PIDSMaker construction 图
    date = ATTACK_TO_DATE.get(sid)
    eval_g = load_eval_graph(det_name, date)
    if eval_g is None:
        return None
    # eval 图节点 idx_id 是 global ID,反查 path
    from detection.training.pidsmaker import _build_args
    from pidsmaker.config.pipeline import get_yml_cfg
    from pidsmaker.utils.utils import get_node_to_path_and_type
    cfg = get_yml_cfg(_build_args(det_name))
    id2path = {nid: info.get("path", "") for nid, info in get_node_to_path_and_type(cfg).items()}
    # 用 global id 反查 path 重建 eval 节点/边集
    # key 用 (path, node_type, label) 三元组 — 同 path/type 不同 cmd_line 的 subject 节点
    # 不会 collision
    eval_nodes = set()
    for nid, attrs in eval_g.nodes(data=True):
        path = id2path.get(int(nid), "")
        if not path:
            continue
        eval_nodes.add((path, attrs.get("node_type", ""), attrs.get("label", "")))
    eval_edges = set()
    for u, v, k, attrs in eval_g.edges(data=True, keys=True):
        su = id2path.get(int(u), "")
        sv = id2path.get(int(v), "")
        et = attrs.get("label", "")
        if su and sv:
            eval_edges.add((su, sv, et))

    # 提取仅 (path, type) 用于 ① 节点对齐
    inf_pt = {(p, t) for (p, t, _) in inf_nodes}
    eval_pt = {(p, t) for (p, t, _) in eval_nodes}
    node_match = len(inf_pt & eval_pt)
    node_inf_only = len(inf_pt - eval_pt)

    # ② 边:推理边 ⊆ eval 边?
    edge_match = len(inf_edges & eval_edges)
    edge_inf_only = len(inf_edges - eval_edges)

    # ③ 特征:三元组 (path, type, label) 推理 ⊆ eval?
    # 即对每个推理节点的 label,eval 图里是否存在同 (path, type, label) 的节点
    feat_match = len(inf_nodes & eval_nodes)
    common_paths = inf_pt & eval_pt  # 为 ① 数字保留

    # ④ 结果:跑 predict_per_node 拿 y_pred, 跟 eval pkl 比
    from detection.training.pidsmaker import _LocalDetector  # noqa
    inf_y = {}
    for nd in det.predict_per_node(sql):
        p = idx_to_path.get(nd["node"], "")
        if p and (p not in inf_y or nd["y_pred"] == 1):
            inf_y[p] = int(nd["y_pred"])
    _, eval_all_y = get_eval_pkl_y(det_name, scenario_idx)
    yp_common = set(inf_y) & set(eval_all_y)
    yp_match = sum(1 for p in yp_common if inf_y[p] == eval_all_y[p])

    return {
        "inf_n": len(inf_pt), "ev_n": len(eval_pt), "n_match": node_match, "n_inf_only": node_inf_only,
        "inf_feat": len(inf_nodes), "ev_feat": len(eval_nodes),
        "inf_e": len(inf_edges), "ev_e": len(eval_edges), "e_match": edge_match, "e_inf_only": edge_inf_only,
        "feat_common": len(common_paths), "feat_match": feat_match,
        "yp_common": len(yp_common), "yp_match": yp_match,
    }


def main(argv):
    detectors = argv or [
        "threatrace", "kairos", "magic", "flash",
        "velox", "rcaid", "nodlink", "orthrus",
    ]
    from detection.training.pidsmaker import _LocalDetector

    print("\n" + "=" * 108)
    print("  推理 SQL 流程 vs eval pkl 端到端对齐(节点 + 边 + 特征 + y_pred)")
    print("=" * 108)

    for det_name in detectors:
        det = _LocalDetector(det_name)
        agg = {k: 0 for k in [
            "inf_n", "ev_n", "n_match",
            "inf_e", "ev_e", "e_match",
            "inf_feat", "ev_feat", "feat_match",
            "feat_common", "yp_common", "yp_match",
        ]}
        n_scen = 0
        for idx, sid in enumerate(ATTACK_SCENARIOS):
            r = test_one(det, det_name, idx, sid)
            if r is None: continue
            for k in agg:
                agg[k] += r[k]
            n_scen += 1

        def pct(num, den): return (num / den * 100) if den else 0.0
        node_rate = pct(agg["n_match"], agg["inf_n"])
        edge_rate = pct(agg["e_match"], agg["inf_e"])
        feat_rate = pct(agg["feat_match"], agg["inf_feat"])
        yp_rate = pct(agg["yp_match"], agg["yp_common"])

        print(f"\n  ──── {det_name} ──── ({n_scen} scenarios)")
        print(f"    ① 节点(path, type):  推理 {agg['inf_n']},eval 命中 {agg['n_match']} = {node_rate:.1f}% ⊆ eval")
        print(f"    ② 边(src,dst,etype): 推理 {agg['inf_e']},eval 命中 {agg['e_match']} = {edge_rate:.1f}% ⊆ eval")
        print(f"    ③ 特征(path,type,label): 推理 {agg['inf_feat']},eval 完全等价 {agg['feat_match']} = {feat_rate:.1f}% ⊆ eval")
        print(f"    ④ y_pred:共同 path {agg['yp_common']} 个,{agg['yp_match']} 一致 = {yp_rate:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
