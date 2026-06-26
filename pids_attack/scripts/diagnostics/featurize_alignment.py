#!/usr/bin/env python3
"""Test 1:特征拼接对齐 —— 同一张 nx 图喂给两条路径,对比 PyG data 各字段.

输入对齐:
  - 都用 PIDSMaker transformation 落盘的 nx 图(load_from_disk)

两条路径:
  A 路 → 我的 single_graph_to_temporal_data(模拟 batching 阶段)
  B 路 → PIDSMaker 的 batching(get_preprocessed_graphs 返回的 test_data)

对比:
  - src / dst / t / y / edge_type 集合
  - msg 向量(按 edge canonical key 配对后逐元素比)

通过标准:每个字段 max|diff| < 1e-6,且 edge 集合完全等价 → 特征拼接 bit 级对齐.
"""
from __future__ import annotations
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "PIDSMaker"))


def run_one(det_name: str):
    import torch
    import glob
    from detection.training.pidsmaker import (
        PIDSMakerEngine, single_graph_to_temporal_data,
    )
    from pidsmaker.tasks.batching import get_preprocessed_graphs
    from pidsmaker.utils.data_utils import extract_msg_from_data

    eng = PIDSMakerEngine(det_name)
    eng._ensure_loaded()
    cfg = eng._cfg

    # B 路:test_data from PIDSMaker(已经走过 extract_msg + reindex)
    _, _, test_data, _, _ = get_preprocessed_graphs(cfg)

    def first_data(td):
        for tw in td:
            for batch in (tw if isinstance(tw, list) else [tw]):
                for d in (batch if isinstance(batch, list) else [batch]):
                    return d
        return None
    data_B = first_data(test_data)

    # 找对应 nx graph(test_data 第一张 = 第一个 test_date)
    base = cfg.transformation._graphs_dir
    test_dates = cfg.dataset.test_dates
    nx_files = sorted(glob.glob(os.path.join(base, f"graph_{test_dates[0]}", "*")))
    nx_g = torch.load(nx_files[0])

    # A 路:用 nx 图跑 single_graph_to_temporal_data + extract_msg_from_data(对齐 PIDSMaker 完整 batching)
    data_A_raw = single_graph_to_temporal_data(
        nx_g, eng._indexid2vec, eng._etype2oh, eng._ntype2oh,
        eng._oov_emb_fn, cfg,
    )
    data_A_list = extract_msg_from_data([data_A_raw], cfg)
    data_A = data_A_list[0]

    # 对齐前的字段统计
    print(f"\n  ── {det_name} ──")
    print(f"  数据形状:")
    print(f"    A (推理): src={tuple(data_A.src.shape)} dst={tuple(data_A.dst.shape)} "
          f"t={tuple(data_A.t.shape)} msg={tuple(data_A.msg.shape)} y={tuple(data_A.y.shape)}")
    print(f"    B (eval): src={tuple(data_B.src.shape)} dst={tuple(data_B.dst.shape)} "
          f"t={tuple(data_B.t.shape)} "
          f"msg={tuple(data_B.msg.shape) if hasattr(data_B,'msg') else '-'} "
          f"y={tuple(data_B.y.shape)}")

    # ===== 逐字段对齐 =====
    n_a = data_A.src.numel()
    n_b = data_B.src.numel()
    print(f"  edge 数:A={n_a}, B={n_b}, 一致 = {n_a == n_b}")
    if n_a != n_b:
        return

    # 按 (src_global, dst_global, t) canonical key 配对
    # 非 TGN 路径 src/dst 是 reindex 后的 local ID,用 original_edge_index 还原 global
    def canonical(d):
        oei = getattr(d, "original_edge_index", None)
        if oei is not None:
            return [(int(oei[0, i].item()), int(oei[1, i].item()), int(d.t[i].item()))
                    for i in range(d.t.numel())]
        return [(int(d.src[i].item()), int(d.dst[i].item()), int(d.t[i].item()))
                for i in range(d.src.numel())]
    keys_A = canonical(data_A)
    keys_B = canonical(data_B)

    set_a, set_b = set(keys_A), set(keys_B)
    common = set_a & set_b
    a_only = set_a - set_b
    b_only = set_b - set_a
    print(f"  (src,dst,t) 集合:共同 {len(common)},A 独有 {len(a_only)},B 独有 {len(b_only)}")

    if a_only or b_only:
        print(f"    (A 独有前 3) {list(a_only)[:3]}")
        print(f"    (B 独有前 3) {list(b_only)[:3]}")
        return

    # 字段比对:按 key 排序后逐字段比
    idx_A = sorted(range(n_a), key=lambda i: keys_A[i])
    idx_B = sorted(range(n_b), key=lambda i: keys_B[i])

    def check_field(name):
        if not hasattr(data_A, name) or not hasattr(data_B, name):
            print(f"    {name}: 缺失(A={hasattr(data_A,name)}, B={hasattr(data_B,name)})")
            return
        va = getattr(data_A, name)
        vb = getattr(data_B, name)
        # reorder
        va_r = va[idx_A] if va.dim() >= 1 else va
        vb_r = vb[idx_B] if vb.dim() >= 1 else vb
        try:
            diff = (va_r.float() - vb_r.float()).abs().max().item()
            print(f"    {name:<18}: shape A={tuple(va_r.shape)}  B={tuple(vb_r.shape)}  "
                  f"max|diff|={diff:.6e}")
        except Exception as e:
            print(f"    {name}: 对比失败 ({e})")

    for f in ["msg", "edge_type", "y", "x_src", "x_dst", "node_type_src", "node_type_dst"]:
        check_field(f)


def main(argv):
    detectors = argv or [
        "threatrace", "kairos", "magic", "flash",
        "velox", "rcaid", "nodlink", "orthrus",
    ]
    print("\n" + "=" * 80)
    print("  Test 1: 特征拼接对齐(同 nx 图 → 我的 single_graph_to_temporal_data vs PIDSMaker batching)")
    print("=" * 80)
    for d in detectors:
        try:
            run_one(d)
        except Exception as e:
            print(f"\n  {d}: ERROR {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
