"""E1.4 Surrogate — §5.2 WL + Sparse BLR + ARD ablation.

Variants(对应 `p3_results.md` §3.11):
  blr_ard / blr_noard / no_posterior

cfg.surrogate 选 dispatch。所有变量都通过同一 attack.safemimic_cmd 框架运行。
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
    "blr_ard":      {"surrogate": "blr_ard"},
    "blr_noard":    {"surrogate": "blr_noard"},
    "no_posterior": {"surrogate": "no_posterior"},
}


def build_config(args: argparse.Namespace) -> SafeMimicConfig:
    base = SafeMimicConfig(scenario=args.scenario, detector=args.detector, seed=args.seed)
    for k, v in VARIANTS[args.variant].items():
        setattr(base, k, v)
    return base


def main(argv: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    p = argparse.ArgumentParser(description="E1.4 surrogate ablation")
    p.add_argument("--scenario", required=True)
    p.add_argument("--detector", default="threatrace_g1g2")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--variant", required=True, choices=list(VARIANTS.keys()))
    p.add_argument("--output", required=True)
    args = p.parse_args(argv)

    scenario, scenario_path = load_attack_scenario(args.scenario)
    cfg = build_config(args)
    pool = load_candidate_pool_for_config(cfg)
    query_fn = make_query_fn(args.detector, seed=cfg.seed)

    t0 = time.time()
    result = run_one_attack(scenario, cfg, pool, query_fn,
                             algo="random" if cfg.search_policy == "random" else "full")
    wall = time.time() - t0
    summary = build_run_summary(
        scenario=scenario, scenario_path=scenario_path, cfg=cfg, result=result,
        wall_clock_sec=wall, algo=cfg.search_policy,
    )
    summary["variant"] = args.variant
    summary["experiment"] = "E1.4_surrogate"
    write_summary(summary, args.output)
    print(f"[E1.4/{args.variant}] converged={summary['converged']} q={summary['q_used']} |Δ|={summary['delta_len']} wall={wall:.1f}s")
    return summary


if __name__ == "__main__":
    main()
