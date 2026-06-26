"""SafeMimic-CMD §5.3 two-objective fitness — f_1 evasion + f_2 stealth + scalarization.

- `attack_term.f1_hinge`                     — 主目标 f_1(Eq 9 CW-style hinge sum)
- `stealth_term.f2_{knn,dist_weighted,kde,gmm}` — 副目标 f_2(Eq 10 k-NN to endogenous R)
- `scalarize.{tchebycheff,weighted_sum,lexicographic}` — Eq 11 合成 s(G)
- `reference.Reference`                       — R = (R_unflagged, R_flagged) 状态 + warm_start
"""
from ._protocol import F1Protocol, F2Protocol, ScalarizeProtocol, ObjectiveProtocol
from .attack_term import f1_hinge
from .stealth_term import f2_knn_ratio, f2_dist_weighted, f2_kde, f2_gmm
from .scalarize import tchebycheff, weighted_sum, lexicographic
from .reference import Reference


def get_f2_fn(metric: str):
    """Dispatch f_2 metric."""
    table = {
        "knn": f2_knn_ratio,
        "dist_weighted": f2_dist_weighted,
        "kde": f2_kde,
        "gmm": f2_gmm,
    }
    return table.get(metric, f2_knn_ratio)


__all__ = [
    "F1Protocol", "F2Protocol", "ScalarizeProtocol", "ObjectiveProtocol",
    "f1_hinge",
    "f2_knn_ratio", "f2_dist_weighted", "f2_kde", "f2_gmm",
    "get_f2_fn",
    "tchebycheff", "weighted_sum", "lexicographic",
    "Reference",
]
