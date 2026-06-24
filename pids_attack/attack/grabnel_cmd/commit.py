"""Sequential commit 策略(p2_mcts_v3.md §5.3 + E2.5 TODO)。

默认 commit_single:每 stage commit GA 选出的 argmin α 个体的整 Δ(替换当前 Δ)。
E2.5 备选:batch_2(每 stage 2 op)/ beam_3 / lookahead_2 — 后续 ablation 实现。
"""
from __future__ import annotations

from typing import List, Tuple

from .config import AtomicOp
from .inner_ga import Individual


def commit_single(current_delta: List[AtomicOp], best_individual: Individual) -> List[AtomicOp]:
    """默认 commit:用 GA 选出的 Δ* 替换当前 Δ。

    GRABNEL "1-edit per stage" 在 §5.4 Inner GA 内部隐式实现(Mutation 主要为 add 1 op
    跟 remove 1 op,所以 Δ_t* 通常跟 Δ_{t-1} 差 1 op)。
    """
    return list(best_individual.delta)
