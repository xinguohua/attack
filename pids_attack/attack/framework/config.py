"""AttackConfig — 算法无关的运行配置基础。

v3 后:GRABNEL 专有字段(beta / beta_lcb / k_nn / T_GA / m_pop / 等)在 attack/grabnel_cmd/config.py 的 GrabnelConfig 里。
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict


@dataclass
class AttackConfig:
    """算法无关基础配置 — query 预算 + iteration 上限 + checker retry + detector 选择 + seed。"""
    query_budget: int = 200                          # 全局 D_target query 上限(B)
    max_iterations: int = 500                        # 主循环最大 iteration(GRABNEL stage 上限等)
    checker_retry_count: int = 1                     # checker 失败时 retry 次数
    detector: str = "orthrus"                        # 哪个 PIDSMaker detector
    seed: int = 42                                   # RNG seed
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AttackConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        kwargs = {k: v for k, v in d.items() if k in known}
        extra = {k: v for k, v in d.items() if k not in known}
        cfg = cls(**kwargs)
        cfg.extra.update(extra)
        return cfg
