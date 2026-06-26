"""§5.4 Acquisition function Protocol — LCB / EI / Thompson."""
from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class AcquisitionProtocol(Protocol):
    """§5.4 acquisition over surrogate posterior — produces scalar score for ranking candidates.

    Lower score = more attractive (matches `argmin acquisition` convention in §5.4).
    Default: LCB(β=0.5). Alternatives: EI, Thompson sampling.
    """

    name: str  # "lcb" | "ei" | "thompson"

    def __call__(
        self,
        mu: float,
        sigma: float,
        *,
        best_so_far: float | None = None,
        beta: float = 0.5,
    ) -> float:
        """Score a single candidate. `best_so_far` is required by EI; ignored by LCB/Thompson."""
        ...
