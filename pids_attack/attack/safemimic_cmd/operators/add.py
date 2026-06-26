"""§4 add-op — thin wrapper that conforms to OperatorProtocol via cmd_graph implementations."""
from __future__ import annotations

from typing import Any, Dict, List

from cmd_graph.graph import CommandGraph
from cmd_graph.operators import apply_add, precondition_add

from .atomic_op import AtomicOp


name = "add"


def make(**params: Any) -> AtomicOp:
    """Build an AtomicOp of type add with the given params."""
    return AtomicOp(type="add", params=dict(params))
