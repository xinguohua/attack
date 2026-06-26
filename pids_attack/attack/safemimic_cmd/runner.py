"""SafeMimic-CMD canonical runner — single CLI + by-config dispatch.

This file is the SafeMimic-CMD framework's public entry point: scenario
loading, query function factory, candidate pool loading, run dispatch, summary
serialization, and argparse CLI.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np

from attack.framework import (
    AttackScenario, AttackResult, QueryHistory, QueryRecord, QueryResult,
    SafeMimicConfig,
)
from attack.safemimic_cmd.operators import AtomicOp, apply_delta
from attack.safemimic_cmd.search import SafeMimicCMDAttack, _target_flagged_count, load_candidate_pool
from cmd_graph.builder import build_g_from_a0
from cmd_graph.translator import graph_to_shell


PROJ_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJ_ROOT))


# ============================================================
# Random baseline(E1.3 reference baseline)
# ============================================================

def random_baseline_run(scenario, candidate_pool, query_fn, cfg) -> AttackResult:
    """每 stage 随机选 δ command + 随机插点 — literature reference baseline。"""
    rng = random.Random(cfg.seed)
    G_0 = build_g_from_a0(scenario.raw)
    Delta: List[AtomicOp] = []
    best_F = None
    best_delta: List[AtomicOp] = []
    history = QueryHistory()
    q_used = 0
    converged = False
    t0 = time.time()
    for stage in range(cfg.B_max):
        cmd = rng.choice(candidate_pool)
        tokens = cmd.split()
        op = AtomicOp(type="add", params={
            "raw_command": cmd,
            "args": tokens[1:] if len(tokens) > 1 else [],
            "edge": (0, 1),
            "inputs": [],
            "outputs": [],
        })
        Delta_new = Delta + [op]
        G_new, ok = apply_delta(Delta_new, G_0)
        if not ok or G_new is None:
            continue
        Delta = Delta_new
        shell_cmds = graph_to_shell(G_new)
        try:
            qres = query_fn(scenario, shell_cmds, G_new)
        except TypeError:
            qres = query_fn(scenario, shell_cmds)
        q_used += 1
        history.add(QueryRecord(
            iteration=stage, candidate={"delta": [o.to_dict() for o in Delta]},
            cmd_sequence=shell_cmds, y=qres.y, checker_passed=qres.valid,
            failed_step=qres.failed_step,
            flagged_nodes=qres.extra.get("all_flagged") if qres.extra else None,
            gt_persistence=qres.gt_persistence,
            delta_gt_score=qres.delta_gt_score,
            score_vec=qres.score_vec, extra=qres.extra,
        ))
        if qres.y is None:
            continue
        F_count = _target_flagged_count(qres)
        if F_count is None:
            continue
        if best_F is None or F_count < best_F:
            best_F = F_count
            best_delta = list(Delta)
        if qres.y == 0:
            converged = True
            break
    return AttackResult(
        state={"delta": [o.to_dict() for o in best_delta], "best_F_count": best_F},
        history=history,
        best_candidate=best_delta,
        final_y=0 if converged else 1,
        converged=converged,
        wall_clock_sec=time.time() - t0,
        extra={"q_used": q_used, "delta_len": len(best_delta),
               "n_unflagged_in_R": 0, "n_flagged_in_R": 0, "blr_n_active": 0},
    )


# ============================================================
# Query function factory(real docker oracle)
# ============================================================

def _normalise_command(cmd: str) -> str:
    return " ".join(str(cmd).strip().split())


def _extract_delta_from_shell(scenario: AttackScenario, shell_cmds: List[str]) -> Tuple[List[str], List[int]]:
    """Approximate Add-δ extraction from a mutated shell sequence.

    E1.0/E1.1 bootstrap currently validates Add-dominant command insertion.
    Full Rewrite/Move/Remove execution semantics will be tightened when those
    operator stages migrate; until then, commands not matching the original A0
    sequence are executed as δ inside the E0-compatible mixed window.
    """
    raw_steps = (scenario.raw or {}).get("steps", [])
    a0 = [_normalise_command(step.get("command", "")) for step in raw_steps]
    n_steps = len(a0)
    j = 0
    delta_commands: List[str] = []
    delta_positions: List[int] = []
    for cmd in shell_cmds:
        norm = _normalise_command(cmd)
        if j < n_steps and norm == a0[j]:
            j += 1
            continue
        if not norm:
            continue
        delta_commands.append(cmd)
        delta_positions.append(max(0, min(j, n_steps - 1 if n_steps else 0)))
    return delta_commands, delta_positions


def make_query_fn(detector_name: str, seed: int = 0, benign_trace_dir: Optional[str] = None):
    """Build the real query callable: mixed workload + strace + CDM + detector."""
    from attack.framework.oracle import query_with_validation_mixed

    def _q(scenario, cmds, G_new=None):
        delta_commands, delta_positions = _extract_delta_from_shell(scenario, list(cmds or []))
        return query_with_validation_mixed(
            scenario,
            delta_commands=delta_commands,
            delta_positions=delta_positions,
            detector_name=detector_name,
            benign_trace_dir=benign_trace_dir,
            benign_seed=seed,
        )
    return _q


# ============================================================
# Scenario + candidate pool loaders
# ============================================================

def resolve_scenario_path(scenario_arg: str) -> Path:
    """Map scenario id (`01`, `juiceshop_login_admin_sqli`, ...) or path → JSON file."""
    if os.path.isfile(scenario_arg):
        return Path(scenario_arg)
    matches = sorted((PROJ_ROOT / "scenarios/juiceshop").glob(f"{scenario_arg}*.json"))
    if not matches:
        raise FileNotFoundError(f"scenario {scenario_arg!r} not found")
    return matches[0]


def load_attack_scenario(scenario_arg: str) -> Tuple[AttackScenario, Path]:
    scenario_path = resolve_scenario_path(scenario_arg)
    with scenario_path.open() as f:
        raw = json.load(f)
    a0 = [step.get("command", "") for step in raw.get("steps", [])]
    return AttackScenario(scenario_id=raw.get("scenario_id", scenario_path.stem), A0=a0, raw=raw), scenario_path


def load_candidate_pool_for_config(cfg: SafeMimicConfig) -> List[str]:
    path = cfg.candidate_pool_path
    if not os.path.isabs(path):
        path = str(PROJ_ROOT / path)
    return load_candidate_pool(path)


# ============================================================
# Dispatch
# ============================================================

# `cfg.search_policy` → backend algo name
_SEARCH_POLICY_TO_ALGO = {"full": "full", "random": "random", "one_shot": "one_shot"}


def run_one_attack(
    scenario: AttackScenario,
    cfg: SafeMimicConfig,
    candidate_pool: List[str],
    query_fn: Callable,
    algo: str = "full",
    **policy_kwargs: Any,
) -> AttackResult:
    """Run one complete attack — scenario+cfg+pool+query_fn ready.

    `policy_kwargs` 透传给 policy 特有 runtime params(例如 one_shot 的 `reset` / overrides)。
    """
    if algo == "random":
        return random_baseline_run(scenario, candidate_pool, query_fn, cfg)
    if algo == "full":
        return SafeMimicCMDAttack(cfg).run(scenario, candidate_pool, query_fn)
    if algo == "one_shot":
        from attack.safemimic_cmd.search.one_shot import run_one_shot
        return run_one_shot(cfg, **policy_kwargs)
    raise ValueError(f"unknown algo {algo!r}")


def run_attack(
    cfg: SafeMimicConfig,
    scenario: Optional[AttackScenario] = None,
    *,
    query_fn=None,
    candidate_pool: Optional[List[str]] = None,
    reset: bool = True,
    delta_command: Optional[str] = None,
    position: Optional[int] = None,
) -> AttackResult:
    """SafeMimic-CMD by-config dispatch — 唯一入口。

    `cfg.search_policy` 选 dispatch:
      - `"one_shot"` — E1.0 最小闭环(1 次 docker query),不需传 scenario / query_fn / pool。
                       支持运行时 kwarg:`reset` / `delta_command` / `position`。
      - `"full"`     — §5.3 sequential + §5.4 inner GA(SafeMimic-CMD 主算法)。
      - `"random"`   — random reference baseline。
    """
    if cfg.search_policy not in _SEARCH_POLICY_TO_ALGO:
        raise NotImplementedError(
            f"search_policy={cfg.search_policy!r} 未接入。可用:{sorted(_SEARCH_POLICY_TO_ALGO.keys())}。"
        )
    algo = _SEARCH_POLICY_TO_ALGO[cfg.search_policy]

    if algo == "one_shot":
        return run_one_attack(
            scenario, cfg, [], None, algo="one_shot",
            reset=reset,
            delta_command_override=delta_command,
            position_override=position,
        )

    # full / random 需要 scenario + pool + query_fn
    if scenario is None:
        scenario, _ = load_attack_scenario(cfg.scenario)
    if candidate_pool is None:
        candidate_pool = load_candidate_pool_for_config(cfg)
    if query_fn is None:
        query_fn = make_query_fn(cfg.detector, seed=cfg.seed, benign_trace_dir=cfg.benign_trace_dir)
    return run_one_attack(scenario, cfg, candidate_pool, query_fn, algo=algo)


# ============================================================
# JSON summary
# ============================================================

def _serialize_delta(best_candidate: Optional[Any]) -> List[Dict[str, Any]]:
    if not best_candidate:
        return []
    return [op.to_dict() if hasattr(op, "to_dict") else op for op in best_candidate]


_OPERATOR_SET_EXPECTED = {
    "add_only": ["add"],
    "add_rewrite": ["add", "rewrite"],
    "add_rewrite_move": ["add", "rewrite", "move"],
    "all4": ["add", "rewrite", "move", "remove"],
}


def _delta_entries_from_candidate(candidate: Any) -> List[Dict[str, Any]]:
    if not isinstance(candidate, dict):
        return []
    delta = candidate.get("delta")
    return delta if isinstance(delta, list) else []


def _operator_types_from_delta(delta: List[Any]) -> Set[str]:
    out: Set[str] = set()
    for item in delta:
        if isinstance(item, AtomicOp):
            out.add(item.type)
        elif isinstance(item, dict) and item.get("type"):
            out.add(str(item["type"]))
    return out


def _mutation_production_summary(cfg: SafeMimicConfig, result: AttackResult) -> Dict[str, Any]:
    expected = _OPERATOR_SET_EXPECTED.get(cfg.operator_set, _OPERATOR_SET_EXPECTED["all4"])
    observed: Set[str] = set()
    if result.history:
        for record in result.history.records:
            observed |= _operator_types_from_delta(_delta_entries_from_candidate(record.candidate))
    observed |= _operator_types_from_delta(_serialize_delta(result.best_candidate))
    missing = [op for op in expected if op not in observed]
    return {
        "mutation_produced": not missing,
        "mutation_expected_types": expected,
        "mutation_observed_types": sorted(observed),
        "mutation_missing_types": missing,
    }


def _history_validity_summary(result: AttackResult) -> Dict[str, Any]:
    records = result.history.records if result.history else []
    r1_values: List[bool] = []
    r2_values: List[bool] = []
    for record in records:
        extra = record.extra or {}
        if "all_steps_passed" in extra or "final_attack_succeeded" in extra:
            r1_values.append(bool(extra.get("all_steps_passed")) and bool(extra.get("final_attack_succeeded")))
        elif record.y is not None:
            r1_values.append(bool(record.checker_passed))

        if "delta_command_success" in extra:
            r2_values.append(bool(extra.get("delta_command_success")))
        elif record.y is not None:
            r2_values.append(bool(record.checker_passed))

    r1_rate = (sum(r1_values) / len(r1_values)) if r1_values else None
    r2_rate = (sum(r2_values) / len(r2_values)) if r2_values else None
    return {
        "r1_valid_rate": r1_rate,
        "r2_valid_rate": r2_rate,
        "attack_impact_rate": (1.0 - r1_rate) if r1_rate is not None else None,
    }


def _best_metric_record(result: AttackResult) -> Optional[QueryRecord]:
    records = result.history.records if result.history else []
    with_counts: List[Tuple[int, int, QueryRecord]] = []
    for idx, record in enumerate(records):
        extra = record.extra or {}
        if "gt_flagged_nodes" in extra:
            try:
                with_counts.append((int(extra.get("gt_flagged_nodes") or 0), idx, record))
            except (TypeError, ValueError):
                pass
    if not with_counts:
        return records[-1] if records else None
    with_counts.sort(key=lambda x: (x[0], x[1]))
    return with_counts[0][2]


def _node_metric_summary(result: AttackResult) -> Dict[str, Any]:
    record = _best_metric_record(result)
    if record is None:
        return {}
    extra = record.extra or {}
    node_metrics = extra.get("node_metrics") or {}
    tp = node_metrics.get("tp", extra.get("gt_flagged_nodes"))
    gt_count = node_metrics.get("gt_count", extra.get("gt_count"))
    try:
        recall = (float(tp) / float(gt_count)) if gt_count else None
    except (TypeError, ValueError, ZeroDivisionError):
        recall = None
    return {
        "recall": recall,
        "mcc": node_metrics.get("mcc"),
        "gt_flagged_nodes": extra.get("gt_flagged_nodes", tp),
        "gt_count": gt_count,
        "n_flagged": extra.get("n_flagged", node_metrics.get("flagged_count")),
        "n_nodes": extra.get("n_nodes", node_metrics.get("all_nodes_count")),
        "tp": node_metrics.get("tp"),
        "fp": node_metrics.get("fp"),
        "tn": node_metrics.get("tn"),
        "fn": node_metrics.get("fn"),
    }


def _normalise_delta_ops(delta: List[Any]) -> Optional[List[AtomicOp]]:
    ops: List[AtomicOp] = []
    for item in delta:
        if isinstance(item, AtomicOp):
            ops.append(item)
        elif isinstance(item, dict) and item.get("type"):
            ops.append(AtomicOp.from_dict(item))
        else:
            return None
    return ops


def _active_delta_len(scenario: AttackScenario, result: AttackResult) -> Optional[int]:
    ops = _normalise_delta_ops(list(result.best_candidate or []))
    if ops is None:
        return None
    if not ops:
        return 0
    G_0 = build_g_from_a0(scenario.raw)
    G_new, ok = apply_delta(ops, G_0)
    if not ok or G_new is None:
        return None
    delta_commands, _ = _extract_delta_from_shell(scenario, graph_to_shell(G_new))
    return len(delta_commands)


def build_run_summary(
    *,
    scenario: AttackScenario,
    scenario_path: Path,
    cfg: SafeMimicConfig,
    result: AttackResult,
    wall_clock_sec: float,
    algo: str,
) -> Dict[str, Any]:
    mutation_summary = _mutation_production_summary(cfg, result)
    validity_summary = _history_validity_summary(result)
    metric_summary = _node_metric_summary(result)
    active_delta_len = _active_delta_len(scenario, result)
    r1_rate = validity_summary.get("r1_valid_rate")
    r2_rate = validity_summary.get("r2_valid_rate")
    mutation_effective = bool(result.converged and r1_rate == 1.0 and r2_rate == 1.0)
    return {
        "scenario_id": scenario.scenario_id,
        "scenario_path": str(scenario_path),
        "detector": cfg.detector,
        "algo": algo,
        "config": cfg.to_dict(),
        "converged": bool(result.converged),
        "asr": 1 if result.converged else 0,
        "q_used": (result.extra or {}).get("q_used", 0),
        "delta_len": (result.extra or {}).get("delta_len", 0),
        "active_delta_len": active_delta_len,
        "best_F_count": (result.state or {}).get("best_F_count"),
        "wall_clock_sec": wall_clock_sec,
        "mutation_effective": mutation_effective,
        "n_unflagged_in_R": (result.extra or {}).get("n_unflagged_in_R", 0),
        "n_flagged_in_R": (result.extra or {}).get("n_flagged_in_R", 0),
        "blr_n_active_features": (result.extra or {}).get("blr_n_active", 0),
        "best_delta": _serialize_delta(result.best_candidate),
        "history": result.history.to_serializable() if result.history else [],
        **mutation_summary,
        **validity_summary,
        **metric_summary,
    }


def write_summary(summary: Dict[str, Any], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)


# ============================================================
# CLI
# ============================================================

def build_config_from_args(args: argparse.Namespace) -> SafeMimicConfig:
    return SafeMimicConfig(
        scenario=args.scenario,
        detector=args.detector,
        seed=args.seed,
        B_max=args.B_max,
        tau=args.tau,
        candidate_pool_path=args.candidate_pool,
        early_stop_on_evade=True,
        search_policy="one_shot" if args.algo == "one_shot" else ("random" if args.algo == "random" else "full"),
        feature_method=args.feature,
        surrogate=args.surrogate,
        f2_metric=args.f2,
        scalarize=args.scalarize,
        commit_mode=args.commit,
        acquisition=args.acquisition,
        scalarize_beta=args.beta,
        lcb_beta=args.beta_lcb,
        k_nn=args.k_nn,
        T_GA=args.T_GA,
        m_pop=args.m,
        H=args.H,
        D_cap=args.D_cap,
        f2_warmstart_n=args.warm_start_n,
        benign_trace_dir=args.benign_trace_dir,
    )


def main(argv: Optional[Sequence[str]] = None, prog: Optional[str] = None) -> Dict[str, Any]:
    """`scripts/run.py attack run` 入口 — SafeMimic-CMD canonical CLI."""
    p = argparse.ArgumentParser(prog=prog, description="SafeMimic-CMD attack runner")
    p.add_argument("--scenario", required=True, help="scenario id or JSON path")
    p.add_argument("--detector", default="threatrace_g1g2")
    p.add_argument("--algo", default="full", choices=("full", "random", "one_shot"),
                   help="full = §5 SafeMimic-CMD; random = reference baseline")
    p.add_argument("--B-max", dest="B_max", type=int, default=20)
    p.add_argument("--tau", type=float, default=0.5)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--feature", default="wl")
    p.add_argument("--surrogate", default="blr_ard")
    p.add_argument("--f2", default="knn")
    p.add_argument("--scalarize", default="tcheby")
    p.add_argument("--commit", default="single")
    p.add_argument("--acquisition", default="lcb")
    p.add_argument("--beta", type=float, default=5.0)
    p.add_argument("--beta-lcb", dest="beta_lcb", type=float, default=0.5)
    p.add_argument("--k-nn", dest="k_nn", type=int, default=5)
    p.add_argument("--T-GA", dest="T_GA", type=int, default=50)
    p.add_argument("--m", type=int, default=20)
    p.add_argument("--H", type=int, default=3)
    p.add_argument("--D-cap", dest="D_cap", type=int, default=200)
    p.add_argument("--warm-start-n", dest="warm_start_n", type=int, default=30)
    p.add_argument("--benign-trace-dir", dest="benign_trace_dir",
                   default="detection/data/training_traces")
    p.add_argument("--candidate-pool", default="shared/candidate_pool.txt")
    p.add_argument("--output", required=True)
    args = p.parse_args(argv)

    cfg = build_config_from_args(args)
    scenario, scenario_path = load_attack_scenario(args.scenario)
    if args.algo == "one_shot":
        candidate_pool = []
        query_fn = None
    else:
        candidate_pool = load_candidate_pool_for_config(cfg)
        query_fn = make_query_fn(args.detector, seed=cfg.seed, benign_trace_dir=cfg.benign_trace_dir)

    canonical_algo = args.algo
    print(f"[SafeMimic-CMD] scenario={scenario.scenario_id} detector={args.detector} algo={canonical_algo}")
    print(f"[SafeMimic-CMD] B_max={cfg.B_max} surrogate={cfg.surrogate} acquisition={cfg.acquisition}")

    t0 = time.time()
    result = run_attack(
        cfg,
        scenario=scenario,
        query_fn=query_fn,
        candidate_pool=candidate_pool,
    )
    wall = time.time() - t0

    summary = build_run_summary(
        scenario=scenario, scenario_path=scenario_path, cfg=cfg, result=result,
        wall_clock_sec=wall, algo=canonical_algo,
    )
    write_summary(summary, args.output)
    print(f"[SafeMimic-CMD] converged={summary['converged']} q_used={summary['q_used']} "
          f"|Δ|={summary['delta_len']} wall={wall:.1f}s")
    print(f"[SafeMimic-CMD] output={args.output}")
    return summary


__all__ = [
    "random_baseline_run",
    "make_query_fn",
    "resolve_scenario_path", "load_attack_scenario",
    "load_candidate_pool_for_config",
    "build_config_from_args",
    "run_one_attack", "run_attack",
    "build_run_summary", "write_summary",
    "main",
]
