"""Thompson sampling — E2.6 备选(p3 Step 6)。

从 BLR posterior N(μ, σ²) 直接采样 s_sample,用作 fitness。
argmin s_sample 选下一候选。

Thompson 天然平衡 explore-exploit:σ 大的候选采样方差大,有几率被选中。
"""
from __future__ import annotations

from typing import Union

import numpy as np


_RNG = np.random.default_rng()


def thompson(
    mu: Union[float, np.ndarray],
    sigma: Union[float, np.ndarray],
    rng: np.random.Generator = None,
) -> Union[float, np.ndarray]:
    """从 N(μ, σ²) 采一个样作 fitness。

    Args:
        mu:    BLR posterior 均值
        sigma: BLR posterior std
        rng:   numpy Generator(默认全局)

    Returns:
        采样的 s_sample(argmin 选)
    """
    r = rng if rng is not None else _RNG
    if isinstance(mu, np.ndarray):
        return mu + sigma * r.standard_normal(size=mu.shape)
    return float(mu) + float(sigma) * float(r.standard_normal())
