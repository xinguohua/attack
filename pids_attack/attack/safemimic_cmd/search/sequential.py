"""SafeMimicCMDAttack — SafeMimic-CMD v3 主算法。

实现 p2_mcts_v3.md §5.4 Algorithm 1:
    1. Init R from 30 benign traces + BLR prior
    2. For t = 1 to B_max:
         Inner GA on surrogate → argmin α 个体 Δ_t*
         Commit Δ ← Δ_t*
         Real query D_target(apply(Δ, G_0)) → g, F
         Early stop F = ∅
         Compute f_1, f_2, s(G_t)
         Update R, BLR posterior
    3. Return Δ if success else ⊥
"""
from __future__ import annotations

import random
import time
from typing import Callable, List, Optional, Set, Tuple

import numpy as np

from cmd_graph.builder import build_g_from_a0
from cmd_graph.graph import CommandGraph
from cmd_graph.translator import graph_to_shell

from attack.framework import (
    AttackAlgorithm, AttackScenario, AttackResult,
    QueryHistory, QueryRecord, QueryResult,
)

from attack.framework import SafeMimicConfig
from attack.safemimic_cmd.operators import AtomicOp
from attack.safemimic_cmd.surrogate import SparseBLR, wl_feature_vector
from attack.safemimic_cmd.objectives import (
    f1_hinge, tchebycheff, weighted_sum, lexicographic, Reference, get_f2_fn,
)
from attack.safemimic_cmd.acquisition import lcb, ei, thompson
from .inner_ga import InnerGA, Individual, apply_delta, load_candidate_pool
from .commit import commit_single


def _target_flagged_count(qres: QueryResult) -> Optional[int]:
    """Return the number of flagged GT/attack nodes for success accounting."""
    extra = qres.extra or {}
    if "gt_flagged_nodes" in extra:
        return int(extra.get("gt_flagged_nodes") or 0)

    gt_nodes = extra.get("gt_nodes")
    if isinstance(gt_nodes, list):
        node_ids = {m.get("node_id") for m in gt_nodes if isinstance(m, dict) and m.get("node_id") is not None}
        return len(node_ids)

    if qres.y is not None:
        return int(qres.y)
    return None


class SafeMimicCMDAttack(AttackAlgorithm):
    """SafeMimic-CMD v3 主算法(GRABNEL BO + Inner GA + Sparse BLR + LCB)。"""

    def __init__(self, cfg: SafeMimicConfig) -> None:
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.np_rng = np.random.default_rng(cfg.seed)

    # ─── helper:fitness 合成 ────────────────────────────

    def _compute_fitness(
        self,
        G_t: CommandGraph,
        score_vec: List[float],
        reference: Reference,
        phi_G: np.ndarray,
        gt_persistence: Optional[float] = None,
    ) -> Tuple[float, float, float, float]:
        """算 (L_1, L_2, s, f_1') — §5.3 Eq 9-11。"""
        if gt_persistence is not None:
            L1 = max(0.0, min(1.0, float(gt_persistence)))                      # attack-node objective
            f1_normalized = -L1                                                  # keep old sign convention
        else:
            f1_normalized = f1_hinge(score_vec, tau=self.cfg.tau, normalize=True)  # ∈ [-1, 0]
            L1 = -f1_normalized                                                     # ∈ [0, 1]

        if reference.size > 0:
            f2_fn = get_f2_fn(self.cfg.f2_metric)
            f2 = f2_fn(phi_G, reference, k=self.cfg.k_nn)                       # ∈ [0, 1]
        else:
            f2 = 0.5                                                            # R 空时中性
        L2 = 1.0 - f2

        # 合成
        if self.cfg.scalarize == "tcheby":
            s = tchebycheff(L1, L2, beta=self.cfg.scalarize_beta)
        elif self.cfg.scalarize in ("weighted", "weighted_sum"):
            s = weighted_sum(L1, L2, w=0.5)
        elif self.cfg.scalarize == "lex":
            # 词典序:返回 tuple,但合成为 scalar(主目标主排,副目标 tiebreak)
            pair = lexicographic(L1, L2, eps=1e-3)
            s = pair[0]
        else:
            s = tchebycheff(L1, L2, beta=self.cfg.scalarize_beta)
        return L1, L2, s, f1_normalized

    # ─── main run ────────────────────────────────────────

    def run(
        self,
        scenario: AttackScenario,
        candidate_pool: List[str],
        query_fn: Callable[[AttackScenario, List[str]], QueryResult],
    ) -> AttackResult:
        """Algorithm 1 主入口。"""
        t_start = time.time()

        # ─── Init ──────────────────────────────────────
        G_0 = build_g_from_a0(scenario.raw)
        if not candidate_pool:
            candidate_pool = load_candidate_pool(self.cfg.candidate_pool_path)

        # Reference warm-start(若 sql_to_cmd_graph 未实现,会返回空 ref)
        reference = self._build_warm_reference()
        # surrogate prior
        blr = SparseBLR(
            D=self.cfg.D_cap,
            k=self.cfg.ard_k, theta=self.cfg.ard_theta,
            sigma_n2=self.cfg.sigma_n2,
        )
        # Inner GA
        ga = InnerGA(self.cfg, blr, G_0, candidate_pool, rng=self.rng)

        history = QueryHistory()
        history_T: List[Tuple[List[AtomicOp], float]] = []          # (Δ, s) for GA init seeds
        Delta: List[AtomicOp] = []                                  # 当前 commit 序列
        best_delta: List[AtomicOp] = []
        best_F_count: Optional[int] = None
        q_used = 0
        converged = False

        # ─── Sequential perturbation selection (§5.3) ──
        for stage in range(self.cfg.B_max):
            # Inner GA(0 真 query)
            best_ind = ga.run(history_T=history_T, current_delta=Delta)

            # Commit
            Delta_new = commit_single(Delta, best_ind)
            # Validate before真 query
            G_new, ok = apply_delta(Delta_new, G_0)
            if not ok or G_new is None or len(G_new.nodes) == 0:
                # 退路:保留 Delta 不变,GA 没找到合法 Δ_t* → 提前停
                continue
            Delta = Delta_new

            # Real query(stage 唯一真 query)
            # query_fn 优先支持 3-arg(传 G_t,让 driver 能拆 δ vs A_0)
            shell_cmds = graph_to_shell(G_new)
            try:
                qres = query_fn(scenario, shell_cmds, G_new)
            except TypeError:
                qres = query_fn(scenario, shell_cmds)
            q_used += 1

            # 记录
            history.add(QueryRecord(
                iteration=stage,
                candidate={"delta": [op.to_dict() for op in Delta]},
                cmd_sequence=shell_cmds,
                y=qres.y,
                checker_passed=qres.valid,
                failed_step=qres.failed_step,
                flagged_nodes=qres.extra.get("all_flagged") if qres.extra else None,
                gt_persistence=qres.gt_persistence,
                delta_gt_score=qres.delta_gt_score,
                score_vec=qres.score_vec,
                extra=qres.extra,
            ))

            # invalid query → skip update
            if qres.y is None or qres.score_vec is None:
                continue

            # Early termination
            score_vec = list(qres.score_vec)
            F_count = _target_flagged_count(qres)
            if F_count is None:
                continue
            if best_F_count is None or F_count < best_F_count:
                best_F_count = F_count
                best_delta = list(Delta)

            if qres.y == 0 and self.cfg.early_stop_on_evade:
                converged = True
                break

            # Fitness + surrogate + reference update
            phi_G = wl_feature_vector(G_new, H=self.cfg.H, D_cap=self.cfg.D_cap)
            L1, L2, s, f1n = self._compute_fitness(
                G_new, score_vec, reference, phi_G, gt_persistence=qres.gt_persistence
            )
            reference.add(G_new, phi_G, flagged=(qres.y == 1))
            blr.update(phi_G, s)
            history_T.append((list(Delta), s))

        wall = time.time() - t_start
        return AttackResult(
            state={"delta": [op.to_dict() for op in best_delta], "best_F_count": best_F_count},
            history=history,
            best_candidate=best_delta,
            final_y=0 if converged else 1,
            converged=converged,
            wall_clock_sec=wall,
            extra={
                "q_used": q_used,
                "delta_len": len(best_delta),
                "n_unflagged_in_R": reference.n_unflagged,
                "n_flagged_in_R": reference.n_flagged,
                "blr_n_active": int(blr.n_active_features),
            },
        )

    # ─── Reference warm-start(可能 stub) ───────────────

    def _build_warm_reference(self) -> Reference:
        """Reference.warm_start_from_benign(可能 stub,Step 4.1 完成后启用 sql_to_cmd_graph)。"""
        sql_to_cmd_graph_fn = None
        try:
            from detection.training.rules import sql_to_cmd_graph as fn
            sql_to_cmd_graph_fn = fn
        except ImportError:
            pass
        return Reference.warm_start_from_benign(
            n=self.cfg.f2_warmstart_n,
            benign_dir=self.cfg.benign_trace_dir,
            D_cap=self.cfg.D_cap, H=self.cfg.H,
            sql_to_cmd_graph_fn=sql_to_cmd_graph_fn,
        )
