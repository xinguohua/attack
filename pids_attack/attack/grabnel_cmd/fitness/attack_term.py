"""主目标 f_1 — 攻击效果(p2_mcts_v3.md §5.3 Eq 9)。

公式:
    f_1(G) = - Σ_{v ∈ V(G)} max(0, g(G)[v] - τ)
    归一: f_1'(G) = f_1(G) / |V(G)|  ∈ [-1, 0]

含义:只罚被 detector 标红的节点(g(G)[v] > τ),全图无标红时 f_1 = 0。
CW-style 推广到 set-level,跟 §5 Eq (1) 主目标一致。
"""
from __future__ import annotations

from typing import Iterable

import numpy as np


def f1_hinge(score_vec: Iterable[float], tau: float = 0.5, normalize: bool = True) -> float:
    """Eq (9) — Per-node CW-style hinge sum,可归一到 [-1, 0]。

    Args:
        score_vec: g(G)[v] 全 node anomaly score list
        tau: detector 报警阈值
        normalize: True 时除以 |V| 归一到 [-1, 0]

    Returns:
        f_1' ∈ [-1, 0] if normalize else f_1 ∈ (-∞, 0]
    """
    arr = np.asarray(list(score_vec), dtype=np.float64)
    if arr.size == 0:
        return 0.0
    excess = np.maximum(0.0, arr - tau)
    f1 = -float(excess.sum())
    if normalize:
        return f1 / arr.size
    return f1
