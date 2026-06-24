"""Endogenous Reference R = (R_unflagged, R_flagged)(p2_mcts_v3.md §5.3 Eq 10)。

R 在 sequential stage 过程中累积:
  - 真 query 完 F(G_t) = ∅ → G_t 加进 R_unflagged
  - F(G_t) ≠ ∅ → G_t 加进 R_flagged

f_2 k-NN ratio 用 phi_unflagged / phi_flagged 缓存 WL features 算距离(stealth_term.py)。

warm_start_from_benign:从 detection/data/training_traces/benign_*.sql 重建 CommandGraph 填 R_unflagged。
  注意:本步骤依赖 detection/rules.py(Step 4.1)。Step 4.1 完成前,warm_start
  为 no-op stub(R 起步空,前几 stage f_2 ≈ 0.5 中性)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import numpy as np

from cmd_graph.graph import CommandGraph


@dataclass
class Reference:
    """R = (R_unflagged, R_flagged) + 缓存 WL features 加速 f_2 计算。"""

    R_unflagged: List[CommandGraph] = field(default_factory=list)
    R_flagged: List[CommandGraph] = field(default_factory=list)
    phi_unflagged: np.ndarray = field(default_factory=lambda: np.zeros((0, 0)))
    phi_flagged: np.ndarray = field(default_factory=lambda: np.zeros((0, 0)))
    D: int = 0                                            # WL feature dim

    def add(self, G: CommandGraph, phi: np.ndarray, flagged: bool) -> None:
        """加一个新 reference graph + 它的 WL features。"""
        phi = np.asarray(phi, dtype=np.float64).reshape(-1)
        if self.D == 0:
            self.D = phi.shape[0]
            self.phi_unflagged = np.zeros((0, self.D), dtype=np.float64)
            self.phi_flagged = np.zeros((0, self.D), dtype=np.float64)
        if phi.shape[0] != self.D:
            raise ValueError(f"phi dim={phi.shape[0]} ≠ D={self.D}")
        if flagged:
            self.R_flagged.append(G)
            self.phi_flagged = np.vstack([self.phi_flagged, phi[np.newaxis, :]])
        else:
            self.R_unflagged.append(G)
            self.phi_unflagged = np.vstack([self.phi_unflagged, phi[np.newaxis, :]])

    @property
    def size(self) -> int:
        return len(self.R_unflagged) + len(self.R_flagged)

    @property
    def n_unflagged(self) -> int:
        return len(self.R_unflagged)

    @property
    def n_flagged(self) -> int:
        return len(self.R_flagged)

    @classmethod
    def warm_start_from_benign(
        cls,
        n: int = 30,
        benign_dir: str = "detection/data/training_traces",
        D_cap: int = 200,
        H: int = 3,
        sql_to_cmd_graph_fn=None,
    ) -> "Reference":
        """从 n 份 benign trace 起步填 R_unflagged。

        Args:
            n: 取前 n 份 benign trace
            benign_dir: 目录路径
            D_cap, H: WL 特征维度 / 迭代轮数(必须跟 surrogate 一致)
            sql_to_cmd_graph_fn: callable(sql_path) → CommandGraph(Step 4.1 提供)
                若为 None,返回空 Reference(stub mode,前几 stage f_2 中性)

        Returns:
            Reference 实例
        """
        from attack.grabnel_cmd.surrogate import wl_feature_vector

        ref = cls()
        if sql_to_cmd_graph_fn is None:
            # Step 4.1 还没实现 sql_to_cmd_graph 之前的 stub
            return ref

        benign_path = Path(benign_dir)
        if not benign_path.exists():
            return ref
        sqls = sorted(benign_path.glob("benign_*.sql"))[:n]
        for sql in sqls:
            try:
                G = sql_to_cmd_graph_fn(str(sql))
                if G is None or len(G.nodes) == 0:
                    continue
                phi = wl_feature_vector(G, H=H, D_cap=D_cap)
                ref.add(G, phi, flagged=False)
            except Exception:
                # 某份 trace parse 失败不影响其他
                continue
        return ref
