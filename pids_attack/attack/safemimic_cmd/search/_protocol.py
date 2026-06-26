"""§5.3 Sequential perturbation selection + §5.4 Inner GA Protocols."""
from __future__ import annotations
from typing import Any, List, Protocol, runtime_checkable

from attack.framework import AttackScenario, AttackResult, QueryHistory


@runtime_checkable
class SearchPolicyProtocol(Protocol):
    """Top-level search policy — produces next Δ candidate for the outer K-stage loop.

    `name` selects between the §5.3 sequential default and the §6.1 baselines:
      - "one_shot": E1.0 bootstrap — single fixed Add δ, one real query.
      - "full": §5.3 K-stage sequential commit + §5.4 inner GA on acquisition (default).
      - "random": uniform sample over legal Δ.
    """

    name: str

    def run(
        self,
        scenario: AttackScenario,
        cfg: Any,                        # SafeMimicConfig
        oracle: Any,                     # callable: scenario × Δ → QueryResult
    ) -> AttackResult:
        """Execute the full search loop and return AttackResult (history + best Δ + converged)."""
        ...


@runtime_checkable
class InnerOptimizerProtocol(Protocol):
    """§5.4 inner optimizer — picks next Δ candidate given history + surrogate.

    Used by `search_policy="full"`; not used by random/one_shot baselines.
    """

    name: str  # "inner_ga"

    def step(
        self,
        history: QueryHistory,
        scenario: AttackScenario,
        cfg: Any,                        # SafeMimicConfig
        surrogate: Any,                  # SurrogateProtocol
        acquisition: Any,                # AcquisitionProtocol
    ) -> List[Any]:
        """Return the Δ candidate to commit in this stage."""
        ...
