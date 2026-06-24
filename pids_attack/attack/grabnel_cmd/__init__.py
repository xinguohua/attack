"""SafeMimic-CMD v3:GRABNEL-aligned BO + Inner GA + Sparse BLR + LCB acquisition。

承接 p2_mcts_v3.md §5 + p3_implementation_plan.md。

主入口:
  - GrabnelCMDAttack:外层 BO + Inner GA(实现 §5.4 Algorithm 1)
  - GrabnelConfig:所有超参 + ablation flag(对应 §5 7 个 TODO)
  - AtomicOp:Δ 序列里单个 op 的 dataclass 封装
"""
from .config import GrabnelConfig, AtomicOp
from .algorithm import GrabnelCMDAttack

__all__ = [
    "GrabnelConfig",
    "AtomicOp",
    "GrabnelCMDAttack",
]
