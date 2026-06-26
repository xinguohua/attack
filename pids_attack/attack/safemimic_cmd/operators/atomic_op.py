"""§4 AtomicOp dataclass — Δ 序列里一个 atomic op。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class AtomicOp:
    """Δ 序列里的单个 atomic op,承 `cmd_graph/operators.py` 4 op 接口。

    `type` 字段定 op 类型,`params` dict 含 op 特有参数:
      - type="add":     raw_command, args, edge=(src,dst), inputs?, outputs?
      - type="rewrite": node_id, new_args, new_inputs?, new_outputs?, new_raw_command?
      - type="move":    node_id, new_edge=(src,dst)
      - type="remove":  node_id
    """

    type: str                                       # "add" | "rewrite" | "move" | "remove"
    params: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in ("add", "rewrite", "move", "remove"):
            raise ValueError(f"AtomicOp.type 必须是 add/rewrite/move/remove,got {self.type}")

    def to_dict(self) -> Dict[str, Any]:
        # params 里可能有 tuple / set,序列化时转 list
        norm_params: Dict[str, Any] = {}
        for k, v in self.params.items():
            if isinstance(v, tuple):
                norm_params[k] = list(v)
            elif isinstance(v, set):
                norm_params[k] = sorted(v)
            else:
                norm_params[k] = v
        return {"type": self.type, "params": norm_params}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AtomicOp":
        return cls(type=d["type"], params=dict(d.get("params", {})))
