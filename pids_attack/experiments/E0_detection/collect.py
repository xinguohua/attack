"""Compatibility wrapper for shared mixed-workload collection.

The real implementation lives in `range.mixed_workload` so E0, E1, and E2 use
the same detector context: benign background + marker window + A0/A0⊕δ.
"""

from range.mixed_workload import (
    _parse_step_outputs,
    collect_attack_only_signature,
    collect_mixed_workload,
    e0_collect_attack_only_scenario,
    e0_collect_scenario,
)

__all__ = [
    "_parse_step_outputs",
    "collect_attack_only_signature",
    "collect_mixed_workload",
    "e0_collect_attack_only_scenario",
    "e0_collect_scenario",
]
