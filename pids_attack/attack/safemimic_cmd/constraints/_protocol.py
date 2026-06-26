"""§3 Validity constraints Protocol — R1 attack integrity / R2 δ executable."""
from __future__ import annotations
from typing import Any, List, Protocol, runtime_checkable

from attack.framework import AttackScenario, QueryResult


@runtime_checkable
class ConstraintProtocol(Protocol):
    """§3 validity constraint. Returns True if the constraint holds for a query.

    Constraints are evaluated after the oracle returns. A query with any failing
    constraint is marked invalid; the search algorithm retries with a new Δ.
    """

    name: str  # "r1_attack_integrity" | "r2_delta_executable"

    def check(
        self,
        scenario: AttackScenario,
        delta: List[Any],
        query_result: QueryResult,
    ) -> bool:
        """Return True if this constraint passes for the given (scenario, delta, query_result)."""
        ...
