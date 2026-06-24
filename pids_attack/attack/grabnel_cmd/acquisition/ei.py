"""Expected Improvement (EI) acquisition — E2.6 备选(p3 Step 6)。

我们目标是 minimize s(G),所以 EI 形式:
    EI(x) = E[max(s_best - s(x), 0)]
         = (s_best - μ) Φ(z) + σ φ(z),  z = (s_best - μ) / σ
    其中 Φ 是标准正态 CDF,φ 是 PDF。

argmin acquisition 等价于 argmax EI(x)。所以返回 -EI(x) 跟 LCB 同接口。
"""
from __future__ import annotations

import math
from typing import Union

import numpy as np


def _norm_pdf(x: float) -> float:
    return math.exp(-0.5 * x * x) / math.sqrt(2.0 * math.pi)


def _norm_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def ei(
    mu: Union[float, np.ndarray],
    sigma: Union[float, np.ndarray],
    s_best: float,
    xi: float = 0.01,
) -> Union[float, np.ndarray]:
    """Expected Improvement 取负数(让 argmin 接口跟 LCB 一致)。

    Args:
        mu:     BLR posterior μ(scalar 或 batch)
        sigma:  BLR posterior σ
        s_best: 当前已观测 s 的最小值
        xi:     improvement margin(default 0.01)

    Returns:
        -EI(x):argmin 得 best候选。
    """
    if isinstance(mu, np.ndarray):
        improvement = s_best - mu - xi
        sigma_safe = np.maximum(sigma, 1e-9)
        z = improvement / sigma_safe
        # vectorize using scipy-style erf
        from scipy.special import erf
        Phi = 0.5 * (1.0 + erf(z / np.sqrt(2.0)))
        phi = np.exp(-0.5 * z * z) / np.sqrt(2.0 * np.pi)
        EI = improvement * Phi + sigma_safe * phi
        return -EI
    # scalar
    sigma_safe = max(float(sigma), 1e-9)
    improvement = s_best - float(mu) - xi
    z = improvement / sigma_safe
    EI = improvement * _norm_cdf(z) + sigma_safe * _norm_pdf(z)
    return -float(EI)
