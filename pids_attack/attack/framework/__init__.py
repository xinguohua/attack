"""算法无关的共用基础:AttackAlgorithm ABC + QueryHistory + QueryResult + AttackResult + AttackConfig."""
from .base import AttackAlgorithm, AttackScenario, AttackResult
from .config import AttackConfig
from .history import QueryHistory, QueryRecord
from .result import QueryResult

__all__ = [
    "AttackAlgorithm",
    "AttackScenario",
    "AttackResult",
    "AttackConfig",
    "QueryHistory",
    "QueryRecord",
    "QueryResult",
]
