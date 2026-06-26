"""黑盒命令级 PIDS 对抗攻击算法 — SafeMimic-CMD。

  - attack/framework/ 算法无关基础(AttackAlgorithm ABC + QueryHistory + SafeMimicConfig + ...)
  - attack/safemimic_cmd/ 唯一 paper-facing 攻击框架(按 paper §5 子层分层)
  - attack/safemimic_cmd/ — SafeMimic-CMD paper-facing implementation.

详见 pids_attack/p3_results.md §3.0 finding-driven 6 阶段 gate。
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
