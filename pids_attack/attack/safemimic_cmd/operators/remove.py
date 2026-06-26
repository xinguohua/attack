"""§4 remove-op — thin wrapper that conforms to OperatorProtocol via cmd_graph implementations."""
from __future__ import annotations

from typing import Any, Dict, List

from cmd_graph.graph import CommandGraph
from cmd_graph.operators import apply_remove, precondition_remove

from .atomic_op import AtomicOp


name = "remove"


def make(**params: Any) -> AtomicOp:
    """Build an AtomicOp of type remove with the given params."""
    return AtomicOp(type="remove", params=dict(params))
