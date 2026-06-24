"""黑盒命令级 PIDS 对抗攻击算法。

v3 重构(2026-06-02):
  - MCTS-CMD 整个砍掉,GRABNEL-CMD 取代(承 p2_mcts_v3.md §5)
  - attack/framework/ 算法无关基础(AttackAlgorithm ABC + QueryHistory + ...)
  - attack/grabnel_cmd/ 是唯一算法实现(GRABNEL BO + Inner GA + WL+BLR + LCB)

详见 pids_attack/p3_implementation_plan.md。
"""
from .framework import (
    AttackAlgorithm,
    AttackScenario,
    AttackResult,
    AttackConfig,
    QueryHistory,
    QueryRecord,
    QueryResult,
)

__all__ = [
    "AttackAlgorithm",
    "AttackScenario",
    "AttackResult",
    "AttackConfig",
    "QueryHistory",
    "QueryRecord",
    "QueryResult",
]
