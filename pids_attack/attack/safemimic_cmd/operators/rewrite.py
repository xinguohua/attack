"""§4 rewrite-op — thin wrapper that conforms to OperatorProtocol via cmd_graph implementations."""
from __future__ import annotations

from typing import Any, Dict, List

from cmd_graph.graph import CommandGraph
from cmd_graph.operators import apply_rewrite, precondition_rewrite

from .atomic_op import AtomicOp


name = "rewrite"


def make(**params: Any) -> AtomicOp:
    """Build an AtomicOp of type rewrite with the given params."""
    return AtomicOp(type="rewrite", params=dict(params))
