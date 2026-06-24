"""Lower Confidence Bound (LCB) acquisition — p2_mcts_v3.md §5.4 Eq 12。

承 GRABNEL [Wan et al. NeurIPS'21] Block D + Srinivas et al. [ICML'10] GP-UCB 同族。

公式:
    α(G) = μ(G) - β_LCB · σ(G)         β_LCB = 0.5(默认)

Inner GA argmin α 选下一 stage commit 候选 — surrogate 预测 s 最低(攻击效果好)+
不确定度高的优先真 query,实现 explore-exploit 平衡。
"""
from __future__ import annotations

from typing import Union

import numpy as np


def lcb(
    mu: Union[float, np.ndarray],
    sigma: Union[float, np.ndarray],
    beta_lcb: float = 0.5,
) -> Union[float, np.ndarray]:
    """Eq (12) — α = μ - β_LCB · σ。

    Args:
        mu:        BLR 后验均值(scalar 或 batch np.ndarray)
        sigma:     BLR 后验 std
        beta_lcb:  explore 强度(0.5 默认,GRABNEL 推荐;大值偏 explore)

    Returns:
        α 跟 mu/sigma 同 type/shape
    """
    return mu - beta_lcb * sigma
