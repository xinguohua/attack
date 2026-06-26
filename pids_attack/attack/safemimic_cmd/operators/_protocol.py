"""§4 Mutation operator Protocol — Add / Rewrite / Move / Remove."""
from __future__ import annotations
from typing import Any, Dict, List, Protocol, runtime_checkable

from attack.framework import AttackScenario


@runtime_checkable
class OperatorProtocol(Protocol):
    """§4 atomic mutation operator over a Δ sequence.

    Each operator transforms a Δ (op 序列) into a new Δ given operator-specific params.
    `precondition` checks R1/R2 + dependency-aware placement before `apply`.
    Operators must NOT call oracle / detector — they only mutate the symbolic Δ.
    """

    name: str  # "add" | "rewrite" | "move" | "remove"

    def precondition(self, scenario: AttackScenario, delta: List[Any], params: Dict[str, Any]) -> bool:
        """Return True if this operator can legally apply at the given (scenario, delta, params)."""
        ...

    def apply(self, scenario: AttackScenario, delta: List[Any], params: Dict[str, Any]) -> List[Any]:
        """Return a new Δ after applying this operator. Must not mutate `delta` in place."""
        ...
