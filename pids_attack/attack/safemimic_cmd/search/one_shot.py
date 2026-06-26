"""SafeMimic-CMD `search_policy="one_shot"` — E1.0 最小闭环 search policy。

一次 mixed-workload query 就结束:从候选池选 1 个最 trivial 的命令,
位置 0,跑 E0 同款 benign background + marker(A0⊕δ) + strace + SQL +
detector inference + E0-style GT/metrics,产出 AttackResult。

跟 `search/sequential.py`(full)和 random 是平行的 search policy,通过 `runner.run_attack`
的 `cfg.search_policy` 派发。
"""
from __future__ import annotations

import json
import os
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from attack.framework import AttackResult, AttackScenario, SafeMimicConfig


PROJ_ROOT = Path(__file__).resolve().parents[3]

PREFERRED_MINIMAL_COMMANDS = (
    "true",
    "printf '' > /dev/null",
    "echo > /dev/null",
    "stat /etc/hostname > /dev/null 2>&1",
)

E0_GT_ROOT = PROJ_ROOT / "experiments/E0_detection/test_data"


# ============================================================
# Helpers for the E1.0 one-shot profile
# ============================================================

def _load_json(path: Path) -> Dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def _resolve_scenario_path(scenario_arg: str) -> Path:
    if os.path.isfile(scenario_arg):
        return Path(scenario_arg)
    matches = sorted((PROJ_ROOT / "scenarios/juiceshop").glob(f"{scenario_arg}*.json"))
    if not matches:
        raise FileNotFoundError(f"scenario {scenario_arg!r} not found")
    return matches[0]


def _load_candidate_pool(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line[: line.index("#")].strip()
        if line:
            out.append(line)
    return out


def _choose_minimal_command(pool: List[str], seed: int, override: Optional[str]) -> Tuple[str, str]:
    if override:
        return override, "cli_override"
    pool_set = set(pool)
    for cmd in PREFERRED_MINIMAL_COMMANDS:
        if cmd in pool_set:
            return cmd, "preferred_candidate_pool"
    if not pool:
        raise RuntimeError("candidate pool is empty")
    rng = random.Random(seed)
    return rng.choice(pool), "seeded_candidate_pool"


def _choose_position(scenario: Dict[str, Any], override: Optional[int]) -> Tuple[int, bool, List[int]]:
    n_steps = len(scenario.get("steps", []))
    allowed_raw = scenario.get("allowed_insertion_positions")
    allowed = [int(p) for p in allowed_raw] if isinstance(allowed_raw, list) else list(range(n_steps))
    valid_allowed = [p for p in allowed if 0 <= p < n_steps]
    if override is not None:
        pos = int(override)
    elif 0 in valid_allowed:
        pos = 0
    elif valid_allowed:
        pos = valid_allowed[0]
    else:
        pos = 0
    return pos, 0 <= pos < n_steps, valid_allowed


def _load_e0_gt_summary(scenario_id: str, path_override: Optional[str] = None) -> Dict[str, Any]:
    path = Path(path_override) if path_override else E0_GT_ROOT / scenario_id / "gt.json"
    if not path.exists():
        return {"loaded": False, "path": str(path), "reason": "missing_gt_json", "gt_count": 0}
    data = _load_json(path)
    subject_ids = data.get("gt_subject_index_ids") or []
    file_ids = data.get("gt_file_index_ids") or []
    netflow_ids = data.get("gt_netflow_index_ids") or []
    return {
        "loaded": True,
        "path": str(path),
        "gt_source": data.get("gt_source"),
        "gt_version": data.get("gt_version"),
        "scenario_id": data.get("scenario_id"),
        "gt_subject_count": len(subject_ids),
        "gt_file_count": len(file_ids),
        "gt_netflow_count": len(netflow_ids),
        "gt_count": len(subject_ids) + len(file_ids) + len(netflow_ids),
        "all_node_count": data.get("all_node_count") or {},
    }


# ============================================================
# Real query payload(E0-compatible mixed oracle)
# ============================================================

def _run_real_query(
    *,
    scenario: Dict[str, Any],
    detector: str,
    delta_commands: List[str],
    delta_positions: List[int],
    benign_trace_dir: str,
    benign_seed: int,
    reset: bool,
) -> Dict[str, Any]:
    from attack.framework.oracle import query_with_validation_mixed

    t0 = time.time()
    qres = query_with_validation_mixed(
        scenario,
        delta_commands=delta_commands,
        delta_positions=delta_positions,
        detector_name=detector,
        benign_trace_dir=benign_trace_dir,
        benign_seed=benign_seed,
        reset=reset,
    )
    extra = qres.extra or {}
    execution = {
        "all_steps_passed": bool(extra.get("all_steps_passed") if extra else qres.valid),
        "final_attack_succeeded": bool(extra.get("final_attack_succeeded") if extra else qres.valid),
        "failed_step": qres.failed_step,
        "trace_path": extra.get("trace_path"),
        "step_results": extra.get("attack_step_results") or [],
        "command_outputs": extra.get("delta_outputs") or [],
        "wall_clock_sec": time.time() - t0,
    }
    if not qres.valid:
        return {
            "execution": execution,
            "detector_query": {
                "attempted": True,
                "valid": False,
                "reason": extra.get("reason", "mixed_oracle_invalid"),
                "trace_path": extra.get("trace_path"),
                "sql_path": extra.get("sql_path") or extra.get("dump"),
                "gt_json": extra.get("gt_json"),
                "mixed_mode": extra.get("mixed_mode"),
                "benign_trace": extra.get("benign_trace"),
                "attack_raw_strace": extra.get("attack_raw_strace"),
                "oracle_target": extra.get("oracle_target", "mixed_node_level"),
            },
        }

    node_metrics = extra.get("node_metrics") or {}
    return {
        "execution": execution,
        "detector_query": {
            "attempted": True, "valid": True, "detector": detector,
            "trace_path": extra.get("trace_path"),
            "sql_path": extra.get("sql_path") or extra.get("dump"),
            "gt_json": extra.get("gt_json"),
            "mixed_mode": extra.get("mixed_mode"),
            "benign_trace": extra.get("benign_trace"),
            "attack_raw_strace": extra.get("attack_raw_strace"),
            "n_nodes": node_metrics.get("all_nodes_count"),
            "n_flagged": node_metrics.get("flagged_count"),
            "node_metrics": node_metrics,
            "evidence": extra.get("evidence"),
            "gt_count": node_metrics.get("gt_count"),
            "gt_flagged_nodes": node_metrics.get("tp"),
            "attack_detected": bool((node_metrics.get("tp") or 0) > 0),
            "oracle_target": extra.get("oracle_target", "mixed_node_level"),
            "y": qres.y,
        },
    }


# ============================================================
# 主入口 — search_policy="one_shot"
# ============================================================

def run_one_shot(
    cfg: SafeMimicConfig,
    *,
    reset: bool = True,
    delta_command_override: Optional[str] = None,
    position_override: Optional[int] = None,
) -> AttackResult:
    """E1.0 minimal Add closed-loop。1 次 docker query 就结束。

    返回 AttackResult,`extra` 里塞 E1.0 schema 关心的所有字段
    (execution / detector_query / e0_gt / delta_meta / metrics 等)。
    """
    t0 = time.time()
    scenario_path = _resolve_scenario_path(cfg.scenario)
    scenario = _load_json(scenario_path)

    pool_path = cfg.candidate_pool_path
    if not os.path.isabs(pool_path):
        pool_path = str(PROJ_ROOT / pool_path)
    pool = _load_candidate_pool(Path(pool_path))

    delta_command, delta_source = _choose_minimal_command(pool, cfg.seed, delta_command_override)
    delta_position, position_valid, valid_allowed = _choose_position(scenario, position_override)
    scenario_id = scenario.get("scenario_id", scenario_path.stem)

    payload = _run_real_query(
        scenario=scenario,
        detector=cfg.detector,
        delta_commands=[delta_command],
        delta_positions=[delta_position],
        benign_trace_dir=cfg.benign_trace_dir,
        benign_seed=cfg.seed,
        reset=reset,
    )

    execution = payload["execution"]
    detector_query = payload["detector_query"]
    e0_gt = _load_e0_gt_summary(scenario_id, detector_query.get("gt_json"))
    command_outputs = execution.get("command_outputs") or []
    delta_outputs = [co for co in command_outputs if co.get("command") == delta_command]
    delta_exit_codes = [co.get("exit_code") for co in delta_outputs]
    delta_command_success = bool(delta_outputs) and all(c == 0 for c in delta_exit_codes)
    r1_valid = bool(execution.get("all_steps_passed") and execution.get("final_attack_succeeded"))
    r2_valid = bool(position_valid and delta_command and delta_command_success)
    query_ok = bool(r1_valid and detector_query.get("valid") and detector_query.get("attempted"))
    asr = bool(query_ok and not detector_query.get("attack_detected"))
    framework_passed = bool(query_ok and e0_gt.get("loaded") and r1_valid and r2_valid)

    wall = time.time() - t0
    return AttackResult(
        state={"delta_command": delta_command, "delta_position": delta_position,
               "best_F_count": detector_query.get("gt_flagged_nodes")},
        history=None,
        best_candidate=[delta_command] if r2_valid else [],
        final_y=detector_query.get("y", 1),
        converged=asr,
        wall_clock_sec=wall,
        extra={
            # E1.0 schema 关心的全量字段,e1_0 CLI 直接读这里拼 JSON
            "policy_profile": "one_shot_minimal_add",
            "scenario_path": str(scenario_path),
            "scenario_id": scenario_id,
            "delta": {
                "commands": [delta_command],
                "positions": [delta_position],
                "source": delta_source,
                "delta_len": 1,
                "position_valid": position_valid,
                "delta_command_success": delta_command_success,
                "delta_exit_codes": delta_exit_codes,
                "valid_allowed_positions": valid_allowed,
                "operator_usage": {
                    "sampled":   {"Add": 1, "Rewrite": 0, "Move": 0, "Remove": 0},
                    "valid":     {"Add": int(r2_valid), "Rewrite": 0, "Move": 0, "Remove": 0},
                    "committed": {"Add": int(r2_valid), "Rewrite": 0, "Move": 0, "Remove": 0},
                },
                "invalid_mutation_rate": 0.0 if r2_valid else 1.0,
            },
            "e0_gt": e0_gt,
            "execution": execution,
            "detector_query": detector_query,
            "metrics": {
                "framework_passed": framework_passed,
                "query_ok": query_ok,
                "r1_valid": r1_valid,
                "r2_valid": r2_valid,
                "delta_command_success": delta_command_success,
                "asr": asr,
                "invalid_mutation_rate": 0.0 if r2_valid else 1.0,
                "q_used": 1 if query_ok else 0,
                "attempted_queries": 1,
                "delta_len": 1,
                "gt_flagged_nodes": detector_query.get("gt_flagged_nodes"),
                "n_flagged": detector_query.get("n_flagged"),
                "n_nodes": detector_query.get("n_nodes"),
                "wall_clock_sec": wall,
            },
        },
    )


__all__ = ["run_one_shot", "PREFERRED_MINIMAL_COMMANDS"]
