"""§3 threatrace — 图空间扰动(P1 shared-neighbor dilution 作用于 BL 自己).

threatrace 用 per-node GraphSAGE 学 edges_distribution → node_type.
扰动:对每个 BL 节点应用 P1(共邻 dilution)— 加 N 个新 cat process,
      每个对 BL 发 type-typical op edge → BL 的 edges_distribution 像训练时的良性 pattern.

  file 类 BL:    ops=[EVENT_OPEN]
  netflow 类 BL: ops=[EVENT_CONNECT, EVENT_SENDTO, EVENT_RECVFROM]

统一 evade 指标:BL = {y=1},evade_rate = |evaded ∈ BL| / |BL|.

USAGE:
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/threatrace.py
"""
from __future__ import annotations
import sys, re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    load_baseline, save_result,
    predict_all_nodes, compute_evade_rate,
    shared_neighbor_dilution, edge_rerouting, find_incoming_edge_source,
)


def find_node_hash_by_idx(sql, idx):
    for table in ["file_node_table", "netflow_node_table", "subject_node_table"]:
        for m in re.finditer(rf"INSERT INTO {table}[^;]+'([0-9a-f]{{32}})'[^;]+, {idx}\) ON CONFLICT", sql):
            return m.group(1)
    return None


def get_node_type(sql, idx):
    for table, t in [("file_node_table", "file"),
                     ("netflow_node_table", "netflow"),
                     ("subject_node_table", "subject")]:
        if re.search(rf"INSERT INTO {table}[^;]+, {idx}\) ON CONFLICT", sql):
            return t
    return None


def variant_p1_dilution_universal(n=100):
    """★ P1 shared-neighbor dilution 作用于每个 BL 节点(type-typical incoming op)."""
    oracle, sql, _ = load_baseline("threatrace")
    bl_pred = predict_all_nodes(oracle, sql)
    bl_flagged = sorted({nid for nid, info in bl_pred.items() if info["y_pred"] == 1})

    perturbed_sql = sql
    per_target_info = []
    base_ts = 200000
    for idx in bl_flagged:
        ntype = get_node_type(sql, idx)
        target_hash = find_node_hash_by_idx(sql, idx)
        if ntype == "file":
            ops = ["EVENT_OPEN"]
        elif ntype == "netflow":
            ops = ["EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVFROM"]
        elif ntype == "subject":
            ops = ["EVENT_OPEN", "EVENT_READ"]
        else:
            continue
        perturbed_sql, _ = shared_neighbor_dilution(
            perturbed_sql, target_hash, n=n, ops=ops,
            proc_cmd="/usr/bin/cat", base_ts=base_ts,
        )
        per_target_info.append({"node_idx": idx, "type": ntype, "ops": ops})
        base_ts += n * len(ops) + 1000

    af_pred = predict_all_nodes(oracle, perturbed_sql)
    sweep = []
    for info in per_target_info:
        idx = info["node_idx"]
        b = bl_pred.get(idx, {})
        a = af_pred.get(idx, {})
        sweep.append({
            **info,
            "baseline": {"score": b.get("score"), "cor": b.get("correct_pred"), "y": b.get("y_pred")},
            "after":    {"score": a.get("score"), "cor": a.get("correct_pred"), "y": a.get("y_pred")},
            "evaded": b.get("y_pred") == 1 and a.get("y_pred") == 0,
        })

    return {
        "variant": f"p1_dilution_universal_n{n}",
        "atomic_mode": "P1 shared-neighbor dilution",
        "target_class": "每个 BL 节点本身(按 type 选 op)",
        "params": {"target_count": len(per_target_info), "n_per_target": n,
                   "ops_by_type": {"file": ["EVENT_OPEN"],
                                   "netflow": ["EVENT_CONNECT", "EVENT_SENDTO", "EVENT_RECVFROM"]},
                   "proc_cmd": "/usr/bin/cat"},
        "sweep": sweep,
        **compute_evade_rate(sql, bl_pred, perturbed_sql, af_pred),
    }


def variant_p2_rerouting(n=3):
    """P2 edge rerouting — 对每个 BL 节点找一个入边 reroute 经 midway."""
    oracle, sql, _ = load_baseline("threatrace")
    bl_pred = predict_all_nodes(oracle, sql)
    bl_flagged = sorted({nid for nid, info in bl_pred.items() if info["y_pred"] == 1})

    perturbed_sql = sql
    base_ts = 800000
    per_target = []
    for idx in bl_flagged:
        target_hash = find_node_hash_by_idx(sql, idx)
        src_hash = find_incoming_edge_source(sql, target_hash)
        if src_hash is None:
            per_target.append({"node_idx": idx, "skipped": True, "reason": "no incoming edge"})
            continue
        perturbed_sql, _ = edge_rerouting(
            perturbed_sql, src_hash, target_hash,
            midway_path="/usr/bin/socat", midway_cmd="socat nat", n=n, ts_base=base_ts,
        )
        per_target.append({"node_idx": idx, "skipped": False, "src": src_hash[:8]})
        base_ts += 100

    af_pred = predict_all_nodes(oracle, perturbed_sql)
    sweep = []
    for idx in bl_flagged:
        ntype = get_node_type(sql, idx)
        b = bl_pred.get(idx, {})
        a = af_pred.get(idx, {})
        sweep.append({
            "node_idx": idx, "type": ntype,
            "baseline": {"score": b.get("score"), "cor": b.get("correct_pred"), "y": b.get("y_pred")},
            "after":    {"score": a.get("score"), "cor": a.get("correct_pred"), "y": a.get("y_pred")},
            "evaded": b.get("y_pred") == 1 and a.get("y_pred") == 0,
        })
    return {
        "variant": f"p2_rerouting_n{n}",
        "atomic_mode": "P2 edge rerouting",
        "target_class": "每个 BL 节点的一个入边 → midway 中转",
        "params": {"midway": "socat", "n_per_target": n, "targets": len(bl_flagged)},
        "sweep": sweep,
        **compute_evade_rate(sql, bl_pred, perturbed_sql, af_pred),
    }


def _fmt_rate(r):
    return f"{r*100:.1f}%" if r is not None else "N/A"


def main():
    print("="*72)
    print("§3 threatrace — P1 + P2 原子扰动")
    print("="*72)
    r1 = variant_p1_dilution_universal(100)
    print(f"\n--- ★ variant_p1_dilution_universal ---")
    print(f"  atomic mode:  {r1['atomic_mode']}")
    print(f"  target_class: {r1['target_class']}")
    for s in r1["sweep"]:
        mark = " ★" if s["evaded"] else " ✗"
        bl, af = s["baseline"], s["after"]
        ops_short = "+".join(o.replace("EVENT_", "") for o in s["ops"])
        print(f"  node {s['node_idx']:>3d} ({s['type']:8s}) +{ops_short:<30s}  "
              f"score {bl['score']:.3f}→{af['score']:>7.3f}  cor {bl['cor']}→{af['cor']}  "
              f"y {bl['y']}→{af['y']}{mark}")
    print(f"  ▸ BL flagged: {r1['baseline_flagged_count']}  evaded: {r1['evaded_count']}  "
          f"evade_rate: {_fmt_rate(r1['evade_rate'])}")

    r2 = variant_p2_rerouting(3)
    print(f"\n--- variant_p2_rerouting ---")
    print(f"  atomic mode:  {r2['atomic_mode']}")
    print(f"  target_class: {r2['target_class']}")
    for s in r2["sweep"]:
        mark = " ★" if s["evaded"] else " ✗"
        bl, af = s["baseline"], s["after"]
        print(f"  node {s['node_idx']:>3d} ({s['type']:8s})  "
              f"score {bl['score']:.3f}→{af['score']:>7.3f}  cor {bl['cor']}→{af['cor']}  "
              f"y {bl['y']}→{af['y']}{mark}")
    print(f"  ▸ BL flagged: {r2['baseline_flagged_count']}  evaded: {r2['evaded_count']}  "
          f"evade_rate: {_fmt_rate(r2['evade_rate'])}")

    p = save_result("threatrace", [r1, r2])
    print(f"\n→ {p}")


if __name__ == "__main__":
    main()
