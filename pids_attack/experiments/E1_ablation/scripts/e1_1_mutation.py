"""E1.1 Mutation primitive — §4 operators ablation.

Variants(对应 `p3_results.md` §3.8):
  add_only / add_rewrite / add_rewrite_move / all4(default)

cfg.operator_set 选 dispatch。所有变量都通过同一 attack.safemimic_cmd 框架运行。
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence


PROJ_ROOT = Path(__file__).resolve().parents[3]
if str(PROJ_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJ_ROOT))

from attack.framework import SafeMimicConfig
from attack.safemimic_cmd.runner import (
    build_run_summary, load_attack_scenario, load_candidate_pool_for_config,
    make_query_fn, run_one_attack, write_summary,
)


VARIANTS: Dict[str, Dict[str, Any]] = {
    "add_only":          {"operator_set": "add_only"},
    "add_rewrite":       {"operator_set": "add_rewrite"},
    "add_rewrite_move":  {"operator_set": "add_rewrite_move"},
    "all4":              {"operator_set": "all4"},
}


def build_config(args: argparse.Namespace) -> SafeMimicConfig:
    base = SafeMimicConfig(
        scenario=args.scenario,
        detector=args.detector,
        seed=args.seed,
        B_max=args.B_max,
        T_GA=args.T_GA,
        m_pop=args.m,
        n_init_random=args.n_init_random,
        benign_trace_dir=args.benign_trace_dir,
        candidate_pool_path=args.candidate_pool,
    )
    for k, v in VARIANTS[args.variant].items():
        setattr(base, k, v)
    return base


def main(argv: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    p = argparse.ArgumentParser(description="E1.1 mutation primitive ablation")
    p.add_argument("--scenario", required=True)
    p.add_argument("--detector", default="threatrace_g1g2")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--variant", required=True, choices=list(VARIANTS.keys()))
    p.add_argument("--B-max", dest="B_max", type=int, default=3)
    p.add_argument("--T-GA", dest="T_GA", type=int, default=6)
    p.add_argument("--m", type=int, default=8)
    p.add_argument("--n-init-random", dest="n_init_random", type=int, default=3)
    p.add_argument("--benign-trace-dir", dest="benign_trace_dir",
                   default="detection/data/training_traces")
    p.add_argument("--candidate-pool", default="shared/candidate_pool.txt")
    p.add_argument("--output", required=True)
    args = p.parse_args(argv)

    scenario, scenario_path = load_attack_scenario(args.scenario)
    cfg = build_config(args)
    pool = load_candidate_pool_for_config(cfg)
    query_fn = make_query_fn(args.detector, seed=cfg.seed, benign_trace_dir=cfg.benign_trace_dir)

    t0 = time.time()
    result = run_one_attack(scenario, cfg, pool, query_fn,
                             algo="random" if cfg.search_policy == "random" else "full")
    wall = time.time() - t0
    summary = build_run_summary(
        scenario=scenario, scenario_path=scenario_path, cfg=cfg, result=result,
        wall_clock_sec=wall, algo=cfg.search_policy,
    )
    summary["variant"] = args.variant
    summary["experiment"] = "E1.1_mutation"
    write_summary(summary, args.output)
    print(
        f"[E1.1/{args.variant}] produced={summary.get('mutation_produced')} "
        f"converged={summary['converged']} q={summary['q_used']} "
        f"|Δ|={summary.get('active_delta_len', summary['delta_len'])} "
        f"R1={summary.get('r1_valid_rate')} R2={summary.get('r2_valid_rate')} "
        f"wall={wall:.1f}s"
    )
    return summary


if __name__ == "__main__":
    main()
