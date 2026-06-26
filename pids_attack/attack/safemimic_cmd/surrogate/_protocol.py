"""§5.2 Surrogate model Protocol — WL features + Sparse BLR + ARD prior."""
from __future__ import annotations
from typing import Any, List, Protocol, Tuple, runtime_checkable


@runtime_checkable
class FeatureExtractorProtocol(Protocol):
    """§5.2 graph feature extractor — turn command graph into sparse feature vector.

    Default: WL (Weisfeiler-Lehman) hash features with `H` iterations + `D_cap` hash buckets.
    Ablations: gnn / random_walk / graph2vec / domain (in E1.4 only `wl` is wired; rest stub).
    """

    name: str  # "wl" | "gnn" | "random_walk" | "graph2vec" | "domain"

    def extract(self, graph: Any, *, H: int = 3, D_cap: int = 200) -> Any:
        """Return feature vector (np.ndarray or sparse equivalent) for the graph."""
        ...


@runtime_checkable
class SurrogateProtocol(Protocol):
    """§5.2 probabilistic regressor over (Φ(G), s(G)) — gives posterior (μ, σ).

    Default: Sparse Bayesian Linear Regression with ARD prior + closed-form posterior update.
    Ablations: blr_noard (no ARD), no_posterior (no surrogate at all), wl_gp (GP instead of BLR).
    """

    name: str  # "blr_ard" | "blr_noard" | "no_posterior" | "wl_gp"

    def fit(self, X: List[Any], y: List[float]) -> None:
        """Update posterior with new (feature, scalar reward) pairs."""
        ...

    def predict(self, X: List[Any]) -> Tuple[List[float], List[float]]:
        """Return (μ_list, σ_list) posterior mean / std for a batch of candidates."""
        ...

    @property
    def n_active_features(self) -> int:
        """Number of ARD-active feature dims (sparsity diagnostic). 0 for no_posterior."""
        ...
