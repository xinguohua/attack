"""一次性 precompute G_benign + R3 reference statistics(attacker prior 版本)。

数据源 = 完全公开 attacker-side prior:
  - shared/candidate_pool.txt(115 条 GTFOBins / ART / coreutils 公开命令)
  - cmd_graph/benign.py BENIGN_WORKFLOWS(典型 Linux sysadmin / web / file / network workflow)
  - cmd_graph/benign.py WRAPPER_TEMPLATES(bash -c / sudo / find -exec 等)

NO defender-side trace,符合 p2_mcts.md §5.1 S1 attacker prior 威胁模型。

输出 shared/g_benign.pkl:含 graph / c_benign / power_law / stats。
"""
from __future__ import annotations
import argparse
import pickle
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cmd_graph.benign import build_g_benign_from_pool, BENIGN_WORKFLOWS, WRAPPER_TEMPLATES
from cmd_graph.nettack import precompute_co_occurrence, precompute_power_law


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-pool", default="shared/candidate_pool.txt")
    ap.add_argument("--output", default="shared/g_benign.pkl")
    args = ap.parse_args()

    pool_path = Path(args.candidate_pool)
    if not pool_path.is_absolute():
        pool_path = PROJECT_ROOT / pool_path
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = PROJECT_ROOT / out_path
    print(f"[build_g_benign] attacker prior 版本(no defender trace)")
    print(f"  candidate_pool: {pool_path}")
    print(f"  workflows: {len(BENIGN_WORKFLOWS)} 条(共 {sum(len(w) for w in BENIGN_WORKFLOWS)} 命令)")
    print(f"  wrappers: {len(WRAPPER_TEMPLATES)} 条")

    t0 = time.time()
    G = build_g_benign_from_pool(pool_path)
    print(f"  G_benign: |V|={len(G.nodes)} |E_seq|={len(G.e_seq)} "
          f"|E_res|={len(G.e_res)} |E_spawn|={len(G.e_spawn)} "
          f"({time.time()-t0:.1f}s)")

    t1 = time.time()
    c_benign = precompute_co_occurrence(G)
    print(f"  C_benign: |type_pairs|={len(c_benign['type_pairs'])} "
          f"type_freq keys={list(c_benign['type_freq'].keys())} "
          f"|neighbor_types_by_cmd|={len(c_benign['neighbor_types_by_cmd'])} "
          f"({time.time()-t1:.1f}s)")

    t2 = time.time()
    pl = precompute_power_law(G)
    print(f"  power-law: α={pl['alpha']:.3f}  l={pl['l']:.1f}  d_min={pl['d_min']}  "
          f"|degrees|={len(pl['degrees'])} ({time.time()-t2:.1f}s)")

    out = {
        "graph": G,
        "c_benign": c_benign,
        "power_law": pl,
        "stats": {
            "source": "attacker_prior",
            "n_candidate_pool": sum(1 for _ in open(pool_path)
                                     if _.strip() and not _.strip().startswith("#")),
            "n_workflows": len(BENIGN_WORKFLOWS),
            "n_wrappers": len(WRAPPER_TEMPLATES),
            "n_nodes": len(G.nodes),
            "n_e_seq": len(G.e_seq),
            "n_e_res": len(G.e_res),
            "n_e_spawn": len(G.e_spawn),
            "n_type_pairs": len(c_benign["type_pairs"]),
            "alpha_benign": pl["alpha"],
            "wall_clock_sec": time.time() - t0,
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(out, f)
    print(f"→ {out_path}  ({out_path.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
