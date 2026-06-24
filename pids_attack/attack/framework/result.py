"""QueryResult — pids_query_with_validation_strict 的返回结构。

算法无关:任何攻击算法(EA / MCTS / …)的 query callback 都返回这个类型。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class QueryResult:
    """单次 PIDS query 的返回结构。

    字段:
      valid             — checker 是否全过(False = invalid,不消耗 query 预算)
      y                 — attack-node binary 标签(GT/attack node 被 flag → y=1,否则 y=0)
      failed_step       — invalid 时指明哪个 step 挂掉
      score_vec         — 全节点 raw score 向量
      gt_persistence    — GT 节点中仍被 flagged 的占比(关键词驱动)
      delta_gt_score    — baseline GT avg score − current GT avg score
      gt_n_dropped      — GT 节点中被漏抓的数量
      extra             — 任意附加数据(trace_path / dump / step_results …)
    """
    valid: bool
    y: Optional[int]
    failed_step: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    score_vec: Optional[List[float]] = None
    gt_persistence: Optional[float] = None
    delta_gt_score: Optional[float] = None
    gt_n_dropped: Optional[int] = None

    @classmethod
    def invalid_(cls, failed_step: Optional[int] = None,
                 extra: Optional[Dict[str, Any]] = None) -> "QueryResult":
        return cls(valid=False, y=None, failed_step=failed_step, extra=extra or {})

    @classmethod
    def valid_(cls, y: int, extra: Optional[Dict[str, Any]] = None,
               score_vec: Optional[List[float]] = None,
               gt_persistence: Optional[float] = None,
               delta_gt_score: Optional[float] = None,
               gt_n_dropped: Optional[int] = None) -> "QueryResult":
        return cls(valid=True, y=y, failed_step=None, extra=extra or {},
                   score_vec=score_vec, gt_persistence=gt_persistence,
                   delta_gt_score=delta_gt_score, gt_n_dropped=gt_n_dropped)

    def is_invalid(self) -> bool:
        return not self.valid

    def reward(self) -> float:
        """连续 reward:invalid → 0;valid 时 = 1 − gt_persistence。

        契约:valid=True 时调用方必须保证 gt_persistence 非 None;
        否则抛 ValueError(由 oracle 或 caller 决定如何兜底,framework 不再 binary-fallback)。
        """
        if not self.valid:
            return 0.0
        if self.gt_persistence is None:
            raise ValueError(
                "QueryResult.reward() requires gt_persistence to be set when valid=True; "
                "no binary-y fallback. Caller must handle None case explicitly."
            )
        return 1.0 - float(self.gt_persistence)
