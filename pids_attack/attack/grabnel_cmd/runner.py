"""SafeMimic-CMD v3 GRABNEL driver helpers.

承 p2_mcts_v3.md §5 + p3_implementation_plan.md Step 3.8。
Canonical CLI is `scripts/run.py attack run`; this module holds the reusable runner
implementation imported by the unified entry.

调用:
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack run \
      --scenario 01 --detector magic --B-max 20 \
      --feature wl --surrogate blr --f2 knn --scalarize tcheby \
      --commit single --acquisition lcb \
      --beta 5.0 --beta-lcb 0.5 --k-nn 5 --T-GA 50 --m 20 \
      --seed 1 --output /tmp/grabnel_run.json

Smoke 模式(--mock):mock detector,不需要 docker。
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

PROJ_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJ_ROOT))

from attack.framework import AttackScenario, AttackResult, QueryHistory, QueryRecord, QueryResult
from attack.grabnel_cmd import GrabnelCMDAttack, GrabnelConfig
from attack.grabnel_cmd.algorithm import _target_flagged_count
from attack.grabnel_cmd.config import AtomicOp
from attack.grabnel_cmd.inner_ga import apply_delta, load_candidate_pool
from cmd_graph.builder import build_g_from_a0
from cmd_graph.translator import graph_to_shell


def random_baseline_run(scenario, candidate_pool, query_fn, cfg) -> AttackResult:
    """E2.0 random baseline:每 stage 随机选 δ command + 随机插点。"""
    import random as _rand
    rng = _rand.Random(cfg.seed)
    G_0 = build_g_from_a0(scenario.raw)
    Delta: List[AtomicOp] = []
    best_F = None
    best_delta: List[AtomicOp] = []
    history = QueryHistory()
    q_used = 0
    converged = False
    t0 = time.time()
    for stage in range(cfg.B_max):
        # 随机生成 add op(签名跟 InnerGA._random_atomic_op 对齐)
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
        history.add(QueryRecord(iteration=stage, candidate={"delta": [o.to_dict() for o in Delta]},
                                cmd_sequence=shell_cmds, y=qres.y,
                                checker_passed=qres.valid,
                                failed_step=qres.failed_step,
                                flagged_nodes=qres.extra.get("all_flagged") if qres.extra else None,
                                gt_persistence=qres.gt_persistence,
                                delta_gt_score=qres.delta_gt_score,
                                score_vec=qres.score_vec,
                                extra=qres.extra))
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
# Query function adapter
# ============================================================

def _extract_delta_from_graph(G_t, G_0):
    """从 G_t 拆出 δ commands + δ positions(相对 A_0 的插入点)。

    简化版:δ = is_attack=False 的节点;positions = δ 在 G_t.sequence() 里的索引。
    """
    seq = G_t.sequence()
    delta_cmds: List[str] = []
    delta_positions: List[int] = []
    mutated_a0: List[Optional[str]] = []
    a0_idx = 0
    for pos, nid in enumerate(seq):
        node = G_t.nodes[nid]
        if node.is_attack:
            # A_0 节点
            orig = G_0.nodes.get(nid)
            if orig and orig.raw_command != node.raw_command:
                # Rewrite 过的 A_0
                mutated_a0.append(node.raw_command)
            else:
                mutated_a0.append(None)
            a0_idx += 1
        else:
            # δ 节点
            delta_cmds.append(node.raw_command)
            delta_positions.append(a0_idx)
    return delta_cmds, delta_positions, mutated_a0


def make_real_query_fn(detector_name: str):
    """生成真 query_fn:wrap pidsmaker_wrapper.query_with_validation_strict。"""
    from attack.oracle import PIDSOracle, query_with_validation_strict

    oracle = PIDSOracle(detector_name=detector_name)

    def query_fn(scenario: AttackScenario, shell_cmds: List[str], G_t=None) -> QueryResult:
        if G_t is None:
            # fallback:直接用 shell_cmds 当 δ + delta_positions = 全 0
            return QueryResult.invalid_(failed_step=-1,
                                        extra={"reason": "G_t missing for real query"})
        G_0 = build_g_from_a0(scenario.raw)
        delta_cmds, delta_positions, mutated_a0 = _extract_delta_from_graph(G_t, G_0)
        # mutated_a0 全 None 时直接传 None(execute_with_checks 会用原始 A_0)
        if mutated_a0 and all(m is None for m in mutated_a0):
            mutated_a0 = None
        return query_with_validation_strict(
            scenario.raw, delta_cmds, delta_positions, oracle,
            mutated_a0=mutated_a0,
        )
    return query_fn


def make_mock_query_fn(seed: int = 0):
    """生成 mock query_fn:不调 docker / detector,模拟 stage 4 后攻击成功。"""
    rng = np.random.default_rng(seed)
    state = {"call": 0}

    def query_fn(scenario: AttackScenario, shell_cmds: List[str], G_t=None) -> QueryResult:
        state["call"] += 1
        n = max(1, len(shell_cmds))
        # mock 政策:前 3 次 query 都标红第 1 个节点;之后随机 50% evade
        if state["call"] < 4:
            score_vec = [0.1] * n
            score_vec[0] = 0.8
            return QueryResult.valid_(
                y=1,
                score_vec=score_vec,
                gt_persistence=1.0,
                extra={"gt_flagged_nodes": 1, "oracle_target": "mock_gt_attack_node"},
            )
        # 之后随机
        score_vec = rng.uniform(0, 0.6, size=n).tolist()
        y = 1 if max(score_vec) > 0.5 else 0
        return QueryResult.valid_(
            y=y,
            score_vec=score_vec,
            gt_persistence=float(y),
            extra={"gt_flagged_nodes": int(y), "oracle_target": "mock_gt_attack_node"},
        )
    return query_fn


# ============================================================
# Single-run helpers
# ============================================================

def resolve_scenario_path(scenario_arg: str) -> Path:
    """Resolve a scenario id such as '01' or a concrete JSON path."""
    if os.path.isfile(scenario_arg):
        return Path(scenario_arg)
    cands = sorted((PROJ_ROOT / "scenarios/juiceshop").glob(f"{scenario_arg}*.json"))
    if not cands:
        raise FileNotFoundError(f"scenario {scenario_arg} not found in scenarios/juiceshop/")
    return cands[0]


def load_attack_scenario(scenario_arg: str) -> Tuple[AttackScenario, Path]:
    """Load scenario JSON and wrap it in the framework-neutral object."""
    scn_path = resolve_scenario_path(scenario_arg)
    with open(scn_path) as f:
        raw = json.load(f)
    scenario = AttackScenario(
        scenario_id=raw.get("scenario_id", scn_path.stem),
        A0=[s.get("command", "") for s in raw.get("steps", [])],
        raw=raw,
    )
    return scenario, scn_path


def build_config_from_args(args: argparse.Namespace) -> GrabnelConfig:
    """Build the GRABNEL config from CLI args."""
    return GrabnelConfig(
        detector=args.detector,
        seed=args.seed,
        B_max=args.B_max,
        T_GA=args.T_GA,
        m_pop=args.m_pop,
        H=args.H,
        D_cap=args.D_cap,
        beta=args.beta,
        beta_lcb=args.beta_lcb,
        k_nn=args.k_nn,
        tau=args.tau,
        feature_method=args.feature_method,
        surrogate=args.surrogate,
        f2_metric=args.f2_metric,
        scalarize=args.scalarize,
        commit_mode=args.commit_mode,
        acquisition=args.acquisition,
        ga_mutation_weighted=args.ga_mutation_weighted,
        ga_constrained_mut=args.ga_constrained_mut,
    )


def load_candidate_pool_for_config(cfg: GrabnelConfig) -> List[str]:
    """Load the command candidate pool using the project-root relative config path."""
    cand_path = Path(cfg.candidate_pool_path)
    if not cand_path.is_absolute():
        cand_path = PROJ_ROOT / cand_path
    return load_candidate_pool(str(cand_path))


def make_query_fn(detector_name: str, mock: bool, seed: int):
    """Create the query callback for a run."""
    return make_mock_query_fn(seed=seed) if mock else make_real_query_fn(detector_name=detector_name)


def run_one_attack(
    scenario: AttackScenario,
    cfg: GrabnelConfig,
    candidate_pool: List[str],
    query_fn,
    algo: str = "grabnel",
) -> AttackResult:
    """Run one complete attack with an already-built scenario/config/query_fn."""
    if algo == "random":
        return random_baseline_run(scenario, candidate_pool, query_fn, cfg)
    if algo == "grabnel":
        return GrabnelCMDAttack(cfg).run(scenario, candidate_pool, query_fn)
    raise ValueError(f"unknown algo {algo!r}")


def _serialize_delta(best_candidate: Optional[Any]) -> List[Dict[str, Any]]:
    if not best_candidate:
        return []
    out = []
    for op in best_candidate:
        out.append(op.to_dict() if hasattr(op, "to_dict") else op)
    return out


def build_run_summary(
    *,
    scenario: AttackScenario,
    scenario_path: Path,
    cfg: GrabnelConfig,
    result: AttackResult,
    wall_clock_sec: float,
    algo: str,
    mock: bool,
) -> Dict[str, Any]:
    """Build the persisted result JSON.

    Top-level legacy fields are kept so existing aggregators continue to work.
    New nested fields make the run self-describing for future runners.
    """
    q_used = result.extra.get("q_used")
    delta_len = result.extra.get("delta_len")
    best_F_count = result.state.get("best_F_count") if isinstance(result.state, dict) else None
    best_delta = _serialize_delta(result.best_candidate)
    queries = result.history.to_serializable()

    summary = {
        "schema_version": "safemimic.attack_run.v1",
        # Legacy / aggregator-compatible fields.
        "scenario_id": scenario.scenario_id,
        "detector": cfg.detector,
        "algo": algo,
        "mock": mock,
        "config": cfg.to_dict(),
        "converged": result.converged,
        "q_used": q_used,
        "delta_len": delta_len,
        "best_F_count": best_F_count,
        "wall_clock_sec": wall_clock_sec,
        "n_unflagged_in_R": result.extra.get("n_unflagged_in_R"),
        "n_flagged_in_R": result.extra.get("n_flagged_in_R"),
        "blr_n_active_features": result.extra.get("blr_n_active"),
        "best_delta": best_delta,
        # Structured fields for the cleaned framework.
        "run": {
            "scenario_id": scenario.scenario_id,
            "scenario_path": str(scenario_path),
            "detector": cfg.detector,
            "algo": algo,
            "seed": cfg.seed,
            "mock": mock,
        },
        "metrics": {
            "success": result.converged,
            "q_used": q_used,
            "query_budget": cfg.B_max,
            "delta_len": delta_len,
            "best_F_count": best_F_count,
            "wall_clock_sec": wall_clock_sec,
            "final_y": result.final_y,
        },
        "artifacts": {
            "queries": [
                {
                    "iteration": q.get("iteration"),
                    "trace_path": (q.get("extra") or {}).get("trace_path"),
                    "sql_path": (q.get("extra") or {}).get("dump"),
                    "n_nodes": (q.get("extra") or {}).get("n_nodes"),
                    "n_flagged": (q.get("extra") or {}).get("n_flagged"),
                    "gt_flagged_nodes": (q.get("extra") or {}).get("gt_flagged_nodes"),
                    "attack_detected": (q.get("extra") or {}).get("attack_detected"),
                }
                for q in queries
            ],
        },
        "queries": queries,
    }
    return summary


def write_summary(summary: Dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)


def print_run_header(scenario: AttackScenario, cfg: GrabnelConfig, algo: str, mock: bool) -> None:
    print(f"\n=== SafeMimic-CMD v3 GRABNEL ===")
    print(f"scenario: {scenario.scenario_id}")
    print(f"detector: {cfg.detector} {'(MOCK)' if mock else '(REAL)'}")
    print(f"algo={algo}, B_max={cfg.B_max}, T_GA={cfg.T_GA}, m={cfg.m_pop}, seed={cfg.seed}")
    print(f"feature={cfg.feature_method}, surrogate={cfg.surrogate}, f2={cfg.f2_metric}")
    print(f"scalarize={cfg.scalarize}, commit={cfg.commit_mode}, acquisition={cfg.acquisition}")


def print_run_result(summary: Dict[str, Any]) -> None:
    print(f"\n=== Result ===")
    print(f"converged: {summary['converged']}")
    print(f"q_used: {summary['q_used']} / {summary['config']['B_max']}")
    print(f"|Delta|: {summary['delta_len']}, best_F_count: {summary['best_F_count']}")
    print(f"wall: {summary['wall_clock_sec']:.2f}s")


# ============================================================
# Driver main
# ============================================================

def main(
    argv: Optional[Sequence[str]] = None,
    prog: str = "scripts/run.py attack",
):
    p = argparse.ArgumentParser(
        prog=prog,
        description="SafeMimic-CMD v3 (GRABNEL) driver",
    )
    # scenario / detector
    p.add_argument("--scenario", required=True,
                   help="scenario id (e.g. '01') 或完整 JSON 路径")
    p.add_argument("--detector", default="magic",
                   help="detector name(magic/orthrus/threatrace/g1/g2/g1g2/magic_g1g2)")
    p.add_argument("--mock", action="store_true",
                   help="使用 mock query_fn(不需要 docker / pidsmaker)")
    # 主超参
    p.add_argument("--B-max", type=int, default=20, dest="B_max")
    p.add_argument("--T-GA", type=int, default=50, dest="T_GA")
    p.add_argument("--m", type=int, default=20, dest="m_pop")
    p.add_argument("--H", type=int, default=3)
    p.add_argument("--D-cap", type=int, default=200, dest="D_cap")
    p.add_argument("--beta", type=float, default=5.0)
    p.add_argument("--beta-lcb", type=float, default=0.5, dest="beta_lcb")
    p.add_argument("--k-nn", type=int, default=5, dest="k_nn")
    p.add_argument("--tau", type=float, default=0.5)
    # ablation switches
    p.add_argument("--feature", default="wl", dest="feature_method",
                   choices=["wl", "gnn", "random_walk", "graph2vec", "domain"])
    p.add_argument("--surrogate", default="blr",
                   choices=["blr", "gp_wl", "gp_rbf", "rf", "ensemble"])
    p.add_argument("--f2", default="knn", dest="f2_metric",
                   choices=["knn", "dist_weighted", "kde", "gmm"])
    p.add_argument("--scalarize", default="tcheby",
                   choices=["tcheby", "weighted", "lex"])
    p.add_argument("--commit", default="single", dest="commit_mode",
                   choices=["single", "batch_2", "beam_3", "lookahead_2"])
    p.add_argument("--acquisition", default="lcb",
                   choices=["lcb", "ei", "thompson", "lcb_anneal"])
    p.add_argument("--ga-mut-weighted", action="store_true",
                   dest="ga_mutation_weighted")
    p.add_argument("--ga-constrained-mut", action="store_true",
                   dest="ga_constrained_mut")
    # algo (E2.0 random baseline)
    p.add_argument("--algo", default="grabnel", choices=["grabnel", "random"],
                   help="grabnel = full GRABNEL pipeline; random = baseline random Δ search")
    # runtime
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--output", default="/tmp/grabnel_run.json")
    args = p.parse_args(argv)

    scenario, scenario_path = load_attack_scenario(args.scenario)
    cfg = build_config_from_args(args)
    query_fn = make_query_fn(detector_name=args.detector, mock=args.mock, seed=args.seed)
    candidate_pool = load_candidate_pool_for_config(cfg)
    print_run_header(scenario, cfg, args.algo, args.mock)

    t0 = time.time()
    result = run_one_attack(scenario, cfg, candidate_pool, query_fn, algo=args.algo)
    wall = time.time() - t0

    summary = build_run_summary(
        scenario=scenario,
        scenario_path=scenario_path,
        cfg=cfg,
        result=result,
        wall_clock_sec=wall,
        algo=args.algo,
        mock=args.mock,
    )
    print_run_result(summary)
    write_summary(summary, args.output)
    print(f"output: {args.output}")
    return summary


if __name__ == "__main__":
    main()
