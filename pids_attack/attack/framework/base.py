"""AttackAlgorithm ABC + AttackScenario + AttackResult — 算法无关接口。"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .history import QueryHistory
from .result import QueryResult


@dataclass
class AttackScenario:
    """A_0 攻击场景:scenario_id + 攻击命令序列 + raw JSON。"""
    scenario_id: str
    A0: List[str]
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    """攻击 run 完后的结果。"""
    state: Any                                       # 算法层自己定义(EA 是 SearchState,MCTS 是 root_i 或 Δ)
    history: QueryHistory
    best_candidate: Optional[Any] = None             # 最佳候选(EA Individual / MCTS Δ / cmd seq …)
    final_y: Optional[int] = None
    converged: bool = False
    wall_clock_sec: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)


# query callback 签名:对外攻击算法 run(...) 接收的 query function
QueryFn = Callable[[AttackScenario, List[str]], QueryResult]


class AttackAlgorithm(ABC):
    """攻击算法 ABC。EA / MCTS-CMD 等具体算法 implement 这个接口。"""

    @abstractmethod
    def run(
        self,
        scenario: AttackScenario,
        candidate_pool: List[str],
        query_fn: QueryFn,
    ) -> AttackResult:
        """跑一次完整攻击,返回 AttackResult。"""
        ...
