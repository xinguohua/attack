"""E1.0 experiment entry — SafeMimic-CMD minimal closed-loop pilot.

跟 e1_1..e1_5 同款结构:build SafeMimicConfig → 调 `attack.safemimic_cmd.run_attack(cfg)`,
0 行攻击逻辑。E1.0 走 `search_policy="one_shot"` 派发(`safemimic_cmd/search/one_shot.py`)。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence


PROJ_ROOT = Path(__file__).resolve().parents[3]
if str(PROJ_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJ_ROOT))

from attack.framework import SafeMimicConfig
from attack.safemimic_cmd.runner import run_attack, write_summary


VARIANTS: Dict[str, Dict[str, Any]] = {
    "minimal_add": {
        "search_policy": "one_shot",
        "operator_set":  "add_only",
        "B_max":         1,
    },
}


def build_config(args: argparse.Namespace) -> SafeMimicConfig:
    base = SafeMimicConfig(scenario=args.scenario, detector=args.detector, seed=args.seed)
    for k, v in VARIANTS[args.variant].items():
        setattr(base, k, v)
    if args.candidate_pool:
        base.candidate_pool_path = args.candidate_pool
    return base


def to_e1_0_result(cfg: SafeMimicConfig, result: Any, variant: str) -> Dict[str, Any]:
    """把 AttackResult 拼成 E1.0 JSON schema(pass_condition / e1_0_passed 等字段)。"""
    extra = result.extra or {}
    metrics = dict(extra.get("metrics") or {})
    e1_0_passed = bool(metrics.get("framework_passed"))
    metrics["e1_0_passed"] = e1_0_passed
    metrics["json_ok"] = True
    metrics["aggregate_ok"] = None
    return {
        "schema_version": "safemimic.e1_0_framework.v1",
        "framework": "safemimic_cmd",
        "framework_profile": extra.get("policy_profile", "one_shot_minimal_add"),
        "experiment": "E1.0_framework",
        "variant": variant,
        "scenario_id": extra.get("scenario_id"),
        "scenario_path": extra.get("scenario_path"),
        "detector": cfg.detector,
        "seed": cfg.seed,
        "config": cfg.to_dict(),
        "delta": extra.get("delta"),
        "e0_gt": extra.get("e0_gt"),
        "execution": extra.get("execution"),
        "detector_query": extra.get("detector_query"),
        "metrics": metrics,
        "pass_condition": {
            "requires_real_query": True,
            "requires_e0_gt_loaded": True,
            "requires_r1_valid": True,
            "requires_r2_valid": True,
            "requires_json_schema": True,
            "requires_evasion": False,
            "passed": e1_0_passed,
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    p = argparse.ArgumentParser(description="E1.0 framework bootstrap pilot")
    p.add_argument("--scenario", required=True, help="scenario id (e.g. 01) or JSON path")
    p.add_argument("--detector", default="threatrace_g1g2")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--variant", default="minimal_add", choices=list(VARIANTS.keys()))
    p.add_argument("--delta-command", default=None, help="override δ command (default = preferred minimal)")
    p.add_argument("--position", type=int, default=None, help="override δ insertion position (default = 0)")
    p.add_argument("--candidate-pool", default=None)
    p.add_argument("--output", required=True)
    p.add_argument("--no-reset", action="store_true", help="don't reset docker target")
    args = p.parse_args(argv)

    cfg = build_config(args)
    result = run_attack(
        cfg, scenario=None,
        reset=not args.no_reset,
        delta_command=args.delta_command,
        position=args.position,
    )
    summary = to_e1_0_result(cfg, result, args.variant)
    write_summary(summary, args.output)

    delta = summary["delta"] or {}
    cmd = (delta.get("commands") or [None])[0]
    pos = (delta.get("positions") or [None])[0]
    print("=== E1.0 framework bootstrap ===")
    print(f"scenario={summary['scenario_id']} detector={cfg.detector} variant={args.variant}")
    print(f"delta={cmd!r} position={pos} position_valid={delta.get('position_valid')}")
    print(f"query_ok={summary['metrics']['query_ok']} "
          f"r1={summary['metrics']['r1_valid']} r2={summary['metrics']['r2_valid']}")
    print(f"e0_gt_loaded={(summary['e0_gt'] or {}).get('loaded')} passed={summary['pass_condition']['passed']}")
    print(f"output={args.output}")
    return summary


if __name__ == "__main__":
    main()
