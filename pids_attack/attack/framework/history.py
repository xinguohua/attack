"""QueryHistory + QueryRecord — append-only 查询日志,算法无关。

不强耦合"individual"概念(以前 EA 专属):任何算法可以把自己的 candidate(EA Individual / MCTS TreeNode / cmd seq …)放到 `candidate` 字段。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _safe_serialize(value: Any) -> Any:
    """Return a JSON-friendly representation without dropping plain dicts."""
    if value is None:
        return None
    if hasattr(value, "serialize"):
        return value.serialize()
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_safe_serialize(v) for v in value]
    if isinstance(value, tuple):
        return [_safe_serialize(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _safe_serialize(v) for k, v in value.items()}
    return repr(value)


@dataclass
class QueryRecord:
    iteration: int
    candidate: Any = None                            # EA Individual / MCTS TreeNode / cmd seq,算法层自决
    cmd_sequence: Optional[List[str]] = None         # 真跑到 docker 的完整 shell 序列(可选)
    y: Optional[int] = None                          # legacy binary outcome
    checker_passed: bool = True
    failed_step: Optional[int] = None
    wall_clock_sec: float = 0.0
    flagged_nodes: Optional[List[Any]] = None        # 通用 per-node 报警集(MCTS 用)
    gt_persistence: Optional[float] = None
    delta_gt_score: Optional[float] = None
    score_vec: Optional[List[float]] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return self.checker_passed and self.y is not None


class QueryHistory:
    """append-only history of all queries(valid + invalid)。算法无关。"""

    def __init__(self) -> None:
        self._records: List[QueryRecord] = []

    def add(self, record: QueryRecord) -> None:
        self._records.append(record)

    @property
    def records(self) -> List[QueryRecord]:
        return list(self._records)

    @property
    def valid_records(self) -> List[QueryRecord]:
        return [r for r in self._records if r.is_valid]

    @property
    def invalid_records(self) -> List[QueryRecord]:
        return [r for r in self._records if not r.is_valid]

    @property
    def total_queries(self) -> int:
        return len(self._records)

    @property
    def valid_query_count(self) -> int:
        return len(self.valid_records)

    @property
    def invalid_query_count(self) -> int:
        return len(self.invalid_records)

    def to_serializable(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for r in self._records:
            out.append({
                "iteration": r.iteration,
                "candidate": _safe_serialize(r.candidate),
                "cmd_sequence": r.cmd_sequence,
                "y": r.y,
                "checker_passed": r.checker_passed,
                "failed_step": r.failed_step,
                "wall_clock_sec": r.wall_clock_sec,
                "flagged_nodes": r.flagged_nodes,
                "gt_persistence": r.gt_persistence,
                "delta_gt_score": r.delta_gt_score,
                "score_vec": r.score_vec,
                "extra": r.extra,
            })
        return out
