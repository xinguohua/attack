"""§4 move-op — thin wrapper that conforms to OperatorProtocol via cmd_graph implementations."""
from __future__ import annotations

from typing import Any, Dict, List

from cmd_graph.graph import CommandGraph
from cmd_graph.operators import apply_move, precondition_move

from .atomic_op import AtomicOp


name = "move"


def make(**params: Any) -> AtomicOp:
    """Build an AtomicOp of type move with the given params."""
    return AtomicOp(type="move", params=dict(params))
