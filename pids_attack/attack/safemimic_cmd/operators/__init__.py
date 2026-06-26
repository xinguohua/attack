"""SafeMimic-CMD §4 mutation operators — Add / Rewrite / Move / Remove."""
from ._protocol import OperatorProtocol
from .atomic_op import AtomicOp
from .apply import apply_delta

__all__ = ["OperatorProtocol", "AtomicOp", "apply_delta"]
