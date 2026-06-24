"""GRABNEL-CMD surrogate models(承 p2_mcts_v3.md §5.2)。

- wl_features.WL feature extractor → Φ(G) ∈ ℝ^D
- sparse_blr.SparseBLR + ARD posterior(默认 surrogate)
- (E2.2 备选)gp / rf / ensemble 待 Step 之后实现
"""
from .wl_features import wl_feature_vector, wl_feature_vector_batch
from .sparse_blr import SparseBLR

__all__ = [
    "wl_feature_vector",
    "wl_feature_vector_batch",
    "SparseBLR",
]
