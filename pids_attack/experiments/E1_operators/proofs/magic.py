"""§1 magic — 图空间扰动(P1 shared-neighbor dilution 作用于 BL 邻居 file).

magic 是 reconstruction 类 detector,BL 节点都是 subject(curl)。
扰动:对 BL 邻居的 file 节点应用 P1(共邻 dilution)— 加 N 个新 cat process,
      每个 OPEN 已有 file,改变 file 入边分布 → file embedding 暴变 → BL curl
      embedding 跟着变 → score 跌出 threshold ★ 100% evade.

USAGE:
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/magic.py
"""
from __future__ import annotations
import sys, re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    load_baseline, next_free_idx, save_result,
    predict_all_nodes, compute_evade_rate,
    shared_neighbor_dilution, edge_rerouting,
    find_attack_post, find_socket_3000, find_incoming_edge_source,
)


def find_existing_file_hashes(sql, n=5):
    return re.findall(
        r"INSERT INTO file_node_table[^;]+'([0-9a-f]{32})'[^;]+, (\d+)\) ON CONFLICT",
        sql,
    )[:n]


def variant_baseline():
    oracle, sql, _ = load_baseline("magic")
    bl = predict_all_nodes(oracle, sql)
    flagged = sorted({nid for nid, info in bl.items() if info["y_pred"] == 1})
    unique_scores = sorted(set(round(i["score"], 2) for i in bl.values()))
    return {
        "variant": "baseline",
        "total_nodes": len(bl),
        "baseline_flagged_count": len(flagged),
        "baseline_flagged_nodes": flagged[:20],
        "unique_scores": unique_scores,
    }


def variant_p1_dilution(n_per_target=100, n_targets=5):
    """★ P1 shared-neighbor dilution 作用于 BL 邻居的 file 节点."""
    oracle, sql, _ = load_baseline("magic")
    bl = predict_all_nodes(oracle, sql)

    targets = find_existing_file_hashes(sql, n_targets)
    if len(targets) < n_targets:
        raise RuntimeError(f"only {len(targets)} file nodes; need {n_targets}")

    perturbed_sql = sql
    all_new_nodes = []
    for ti, (target_hash, _) in enumerate(targets):
        perturbed_sql, new_nodes = shared_neighbor_dilution(
            perturbed_sql, target_hash, n=n_per_target,
            ops=["EVENT_OPEN"], proc_cmd="/usr/bin/cat",
            base_ts=200000 + ti * 1000,
        )
        all_new_nodes.extend(new_nodes)

    af = predict_all_nodes(oracle, perturbed_sql)
    er = compute_evade_rate(sql, bl, perturbed_sql, af)
    new_set = set(all_new_nodes)
    af_flagged = {nid for nid, info in af.items() if info["y_pred"] == 1}
    delta_flagged = af_flagged & new_set

    bl_flagged = {nid for nid, i in bl.items() if i["y_pred"] == 1}
    bl_scores_before = sorted(set(round(bl[n]["score"], 2) for n in bl_flagged))
    bl_scores_after = sorted(set(round(af.get(n, {"score": -1})["score"], 2) for n in bl_flagged))

    return {
        "variant": f"p1_dilution_n{n_per_target}_t{n_targets}",
        "atomic_mode": "P1 shared-neighbor dilution",
        "target_class": "BL 邻居 file 节点",
        "params": {"target_count": n_targets, "n_per_target": n_per_target,
                   "ops": ["EVENT_OPEN"], "proc_cmd": "/usr/bin/cat"},
        "new_nodes_added": len(all_new_nodes),
        "BL_scores_before": bl_scores_before,
        "BL_scores_after": bl_scores_after,
        **er,
        "F2_delta_flagged_count": len(delta_flagged),
        "after_total_flagged": len(af_flagged),
    }


def variant_p2_rerouting(n=3):
    """P2 edge rerouting — 对 BL 代表节点的关联 edge 加 socat 中转."""
    oracle, sql, _ = load_baseline("magic")
    bl_pred = predict_all_nodes(oracle, sql)

    src_hash, _ = find_attack_post(sql)
    dst_hash = find_socket_3000(sql)
    perturbed_sql, _ = edge_rerouting(
        sql, src_hash, dst_hash,
        midway_path="/usr/bin/socat", midway_cmd="socat nat", n=n, ts_base=60000,
    )
    af_pred = predict_all_nodes(oracle, perturbed_sql)
    er = compute_evade_rate(sql, bl_pred, perturbed_sql, af_pred)

    bl_flagged = {nid for nid, i in bl_pred.items() if i["y_pred"] == 1}
    bl_scores_before = sorted(set(round(bl_pred[n]["score"], 2) for n in bl_flagged))
    bl_scores_after = sorted(set(round(af_pred.get(n, {"score": -1})["score"], 2) for n in bl_flagged))

    return {
        "variant": f"p2_rerouting_socat_n{n}",
        "atomic_mode": "P2 edge rerouting",
        "target_class": "BL 代表节点 → :3000 socket 边",
        "params": {"midway": "socat", "n": n},
        "BL_scores_before": bl_scores_before,
        "BL_scores_after": bl_scores_after,
        **er,
    }


def _fmt_rate(r):
    return f"{r*100:.1f}%" if r is not None else "N/A"


def main():
    print("\n=== §1 magic — P1 shared-neighbor dilution(BL 邻居 file)===")

    print("\n--- variant_baseline ---")
    bl = variant_baseline()
    print(f"  total_nodes:           {bl['total_nodes']}")
    print(f"  baseline_flagged (BL): {bl['baseline_flagged_count']}")
    print(f"  BL nodes:              {bl['baseline_flagged_nodes']}")
    print(f"  全图 unique scores:    {bl['unique_scores']}")

    print("\n--- ★ variant_p1_dilution ---")
    b = variant_p1_dilution(100, 5)
    print(f"  atomic mode:           {b['atomic_mode']}")
    print(f"  target_class:          {b['target_class']}")
    print(f"  params:                {b['params']}")
    print(f"  BL scores: {b['BL_scores_before']}  →  {b['BL_scores_after']}")
    print(f"  evade_rate:            {_fmt_rate(b['evade_rate'])}  ({b['evaded_count']}/{b['baseline_flagged_count']})")
    print(f"  F2 δ 误进:             {b['F2_delta_flagged_count']}/{b['new_nodes_added']}")

    print("\n--- variant_p2_rerouting ---")
    c = variant_p2_rerouting(3)
    print(f"  atomic mode:           {c['atomic_mode']}")
    print(f"  target_class:          {c['target_class']}")
    print(f"  params:                {c['params']}")
    print(f"  BL scores: {c['BL_scores_before']}  →  {c['BL_scores_after']}")
    print(f"  evade_rate:            {_fmt_rate(c['evade_rate'])}  ({c['evaded_count']}/{c['baseline_flagged_count']})")

    p = save_result("magic", [bl, b, c])
    print(f"\n→ {p}")


if __name__ == "__main__":
    main()
