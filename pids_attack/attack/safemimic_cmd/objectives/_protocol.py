"""§5.3 Two-objective fitness Protocols — f_1 evasion / f_2 stealth / scalarization."""
from __future__ import annotations
from typing import Any, Dict, List, Protocol, runtime_checkable

from attack.framework import QueryResult


@runtime_checkable
class F1Protocol(Protocol):
    """§5.3 Eq 9 — attack-node hinge sum (CW-style flagged-node score)."""

    name: str  # e.g. "f1_hinge"

    def __call__(self, query_result: QueryResult, *, tau: float, normalize: bool = True) -> float:
        """Return f_1(G) ∈ [-1, 0] when `normalize=True`. 0 = full evasion."""
        ...


@runtime_checkable
class F2Protocol(Protocol):
    """§5.3 Eq 10 — stealth term: similarity to endogenous reference R = (R_unflagged, R_flagged)."""

    name: str  # "knn" | "dist_weighted" | "kde" | "gmm"

    def __call__(
        self,
        graph_feature: Any,
        reference_unflagged: List[Any],
        reference_flagged: List[Any],
        *,
        k: int = 5,
    ) -> float:
        """Return f_2(G; R) ∈ [0, 1]. 1 = G looks like R_unflagged distribution."""
        ...


@runtime_checkable
class ScalarizeProtocol(Protocol):
    """§5.3 Eq 11 — combine (f_1, f_2) into single scalar reward `s(G)`."""

    name: str  # "tcheby" | "weighted_sum" | "lex"

    def __call__(self, l1: float, l2: float, *, beta: float = 5.0, **kwargs: Any) -> float:
        """Return scalarized loss s(G). `l_i = -f_i'` so smaller is better.

        Tchebycheff form (default): s = -(1/β)·log[exp(-β·l1) + exp(-β·l2)]
        """
        ...


# Convenience: single Objective callable that combines f_1 + f_2 + scalarize.
@runtime_checkable
class ObjectiveProtocol(Protocol):
    """End-to-end objective — produces single scalar `s(G)` from QueryResult.

    Composed of F1 + (optional) F2 + Scalarize at construction time.
    """

    name: str  # "f1_only" | "f1_f2"

    def __call__(
        self,
        query_result: QueryResult,
        *,
        reference_unflagged: List[Any] | None = None,
        reference_flagged: List[Any] | None = None,
        **kwargs: Any,
    ) -> float:
        ...
