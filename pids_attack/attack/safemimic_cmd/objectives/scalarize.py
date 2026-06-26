"""双目标 fitness 合成单 scalar(p2_mcts_v3.md §5.3 Eq 11)。

默认:soft-min Tchebycheff scalarization(承 MOS-Attack [arXiv 2501.07251, 2025])
    s(G) = - (1/β) · log [ exp(-β · L_1(G)) + exp(-β · L_2(G)) ]
    其中  L_1(G) = -f_1'(G)   ∈ [0, 1]   (越小越好)
         L_2(G) = 1 - f_2(G)  ∈ [0, 1]   (越小越好)
         β = 5  (MOS-Attack 推荐)
soft-min 由较"差"那项主导,**两种 partial-success 都被惩罚**。

E1.4 备选:
- weighted_sum(λ_1, λ_2 加权和)
- lexicographic(主目标主排,副目标 tiebreak)
"""
from __future__ import annotations

import math
from typing import Tuple


def tchebycheff(L1: float, L2: float, beta: float = 5.0) -> float:
    """§5.3 Eq (11) — soft-min Tchebycheff scalarization。

    L1, L2 ∈ [0, 1](越小越好),返回 s ∈ ℝ(越小越好)。
    """
    # 用 -1/β log Σ exp(-β·L) 形式,这是 -soft-max(-L_i) ≈ -min(L_i)
    # 实际计算:s = -(1/β) log [ exp(-β L1) + exp(-β L2) ]
    # 数值稳定:log-sum-exp trick
    a = -beta * L1
    b = -beta * L2
    m = max(a, b)
    lse = m + math.log(math.exp(a - m) + math.exp(b - m))
    s = -(1.0 / beta) * lse
    return float(s)


def weighted_sum(L1: float, L2: float, w: float = 0.5) -> float:
    """E1.4 备选:加权和 s = w · L1 + (1 - w) · L2。"""
    return float(w * L1 + (1.0 - w) * L2)


def lexicographic(L1: float, L2: float, eps: float = 1e-3) -> Tuple[float, float]:
    """E1.4 备选:词典序合成(返回 tuple,用作 sort key)。

    主目标 L1 + 副目标 L2 * eps(让主目标主排,副目标 tiebreak)。
    """
    return (L1 + L2 * eps, L2)
