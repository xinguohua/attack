"""副目标 f_2 — 良性 topology 合规度(p2_mcts_v3.md §5.3 Eq 10)。

公式:
    f_2(G) = #k-NN_unflagged(G | R) / k  ∈ [0, 1]

R = (R_unflagged, R_flagged) 在 sequential stage 累积。
WL graph kernel 距离 = 1 - cosine(Φ(G_a), Φ(G_b))。
取 G 在 R 全集里的 top-k 最近邻,数其中多少在 R_unflagged 簇。

§5.3 TODO E1.3 备选:dist_weighted / KDE / GMM(本文件先实现 default k-NN)。
"""
from __future__ import annotations

from typing import List

import numpy as np

# 注:从 reference 模块取 Reference 类,这里不再 import 避免循环
# 但需要类型注解 — 用 forward ref


def _cosine_distance(phi_a: np.ndarray, phi_b: np.ndarray) -> float:
    """1 - cosine similarity,稳定版(0 向量→距离 = 1)。"""
    na = float(np.linalg.norm(phi_a))
    nb = float(np.linalg.norm(phi_b))
    if na < 1e-12 or nb < 1e-12:
        return 1.0
    return 1.0 - float(phi_a @ phi_b) / (na * nb)


def _compute_distances(phi_G: np.ndarray, reference: "Reference") -> List[tuple]:  # noqa: F821
    """计算 phi_G 到 R 中每图的 distance + label list,sorted by distance asc。"""
    dists: List[tuple[float, str]] = []
    phi_unf = reference.phi_unflagged
    phi_flg = reference.phi_flagged
    for i in range(phi_unf.shape[0]):
        dists.append((_cosine_distance(phi_G, phi_unf[i]), "unflagged"))
    for i in range(phi_flg.shape[0]):
        dists.append((_cosine_distance(phi_G, phi_flg[i]), "flagged"))
    dists.sort(key=lambda x: x[0])
    return dists


def f2_knn_ratio(phi_G: np.ndarray, reference: "Reference", k: int = 5) -> float:  # noqa: F821
    """Eq (10) — f_2(G) = #k-NN_unflagged / k,∈ [0, 1]。"""
    n_total = reference.phi_unflagged.shape[0] + reference.phi_flagged.shape[0]
    if n_total == 0:
        return 0.5
    top_k = _compute_distances(phi_G, reference)[: min(k, n_total)]
    n_unflagged_in_top = sum(1 for _, lbl in top_k if lbl == "unflagged")
    return float(n_unflagged_in_top) / float(k)


def f2_dist_weighted(phi_G: np.ndarray, reference: "Reference", k: int = 5) -> float:  # noqa: F821
    """E1.3 备选:距离加权 k-NN。

    f_2 = Σ_{v ∈ top-k} w(v) · 𝟙[unflagged] / Σ_{v ∈ top-k} w(v)
        其中 w(v) = 1 / (1 + d(G, v))
    """
    n_total = reference.phi_unflagged.shape[0] + reference.phi_flagged.shape[0]
    if n_total == 0:
        return 0.5
    top_k = _compute_distances(phi_G, reference)[: min(k, n_total)]
    weights = [1.0 / (1.0 + d) for d, _ in top_k]
    w_sum = sum(weights)
    if w_sum < 1e-12:
        return 0.5
    w_unf = sum(w for w, (_, lbl) in zip(weights, top_k) if lbl == "unflagged")
    return float(w_unf / w_sum)


def f2_kde(phi_G: np.ndarray, reference: "Reference", k: int = 5,  # noqa: F821
           bandwidth: float = 0.5) -> float:
    """E1.3 备选:KDE 密度比例(简化版,Gaussian kernel on cosine distance)。

    f_2 = density_unflagged(G) / (density_unflagged + density_flagged)

    `k` 参数仅为接口对齐(dispatcher 统一传 k=cfg.k_nn),KDE 实际不用。
    """
    phi_unf = reference.phi_unflagged
    phi_flg = reference.phi_flagged
    n_unf = phi_unf.shape[0]
    n_flg = phi_flg.shape[0]
    if n_unf + n_flg == 0:
        return 0.5
    def _kernel_sum(phis: np.ndarray) -> float:
        if phis.shape[0] == 0:
            return 0.0
        s = 0.0
        for i in range(phis.shape[0]):
            d = _cosine_distance(phi_G, phis[i])
            s += float(np.exp(-d * d / (2 * bandwidth * bandwidth)))
        return s
    p_unf = _kernel_sum(phi_unf) / max(1, n_unf)
    p_flg = _kernel_sum(phi_flg) / max(1, n_flg)
    total = p_unf + p_flg
    if total < 1e-12:
        return 0.5
    return float(p_unf / total)


def f2_gmm(phi_G: np.ndarray, reference: "Reference", k: int = 5) -> float:  # noqa: F821
    """E1.3 备选:GMM 简化版 — 用 inverse-distance 概率,跟 dist_weighted 类似但 softmax。

    简化避免引入 sklearn,但效果相近。
    """
    n_total = reference.phi_unflagged.shape[0] + reference.phi_flagged.shape[0]
    if n_total == 0:
        return 0.5
    top_k = _compute_distances(phi_G, reference)[: min(k, n_total)]
    # softmax over -d
    ds = np.array([d for d, _ in top_k], dtype=np.float64)
    z = np.exp(-ds * 5.0)
    z = z / z.sum() if z.sum() > 0 else np.ones_like(z) / len(z)
    w_unf = sum(z[i] for i, (_, lbl) in enumerate(top_k) if lbl == "unflagged")
    return float(w_unf)
