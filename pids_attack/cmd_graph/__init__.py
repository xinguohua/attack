"""命令依赖图 G + 4 atomic 算子(承 1_p1_formulation.md §4.2)。

Phase 1 模块:
  graph.py        — CommandNode + CommandGraph 数据结构
  operators.py    — Add / Rewrite / Move / Remove 4 算子
  builder.py      — build_g_from_a0(json) + build_g_from_strace(strace)
  translator.py   — graph_to_shell(G) → List[str]

完全独立于搜索算法;v3 起被 SafeMimic full profile 调用。
"""
from .graph import CommandGraph, CommandNode
from .operators import (
    apply_add, precondition_add,
    apply_rewrite, precondition_rewrite,
    apply_move, precondition_move,
    apply_remove, precondition_remove,
    OperatorError,
)
from .builder import build_g_from_a0
from .benign import build_g_benign_from_pool, BENIGN_WORKFLOWS, WRAPPER_TEMPLATES
from .nettack import (
    precompute_co_occurrence, precompute_power_law,
    eq12_check, eq10_incremental_lambda, r3_filter,
    resource_type, is_system_library, filter_resources,
)
from .translator import graph_to_shell
from .wl_hash import wl_canonical_hash

__all__ = [
    "CommandGraph", "CommandNode",
    "apply_add", "apply_rewrite", "apply_move", "apply_remove",
    "precondition_add", "precondition_rewrite", "precondition_move", "precondition_remove",
    "OperatorError",
    "build_g_from_a0", "build_g_benign_from_pool",
    "BENIGN_WORKFLOWS", "WRAPPER_TEMPLATES",
    "precompute_co_occurrence", "precompute_power_law",
    "eq12_check", "eq10_incremental_lambda", "r3_filter",
    "resource_type", "is_system_library", "filter_resources",
    "graph_to_shell",
    "wl_canonical_hash",
]
