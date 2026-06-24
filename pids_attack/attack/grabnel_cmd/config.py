"""GrabnelConfig + AtomicOp — v3 GRABNEL-CMD 算法配置与原子操作 dataclass。

GrabnelConfig 字段覆盖 p2_mcts_v3.md §5 全部超参,加 7 个 ablation switch
对应 p3_implementation_plan.md §3.4 E2.1-E2.7。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

from attack.framework.config import AttackConfig


# ============================================================
# AtomicOp dataclass —— Δ 序列里一个 op
# ============================================================

@dataclass
class AtomicOp:
    """Δ 序列里的单个 atomic op。承 cmd_graph/operators.py 4 op 接口。

    type 字段定 op 类型,params dict 含 op 特有参数:
      - type="add":raw_command, args, edge=(src,dst), inputs?, outputs?
      - type="rewrite":node_id, new_args, new_inputs?, new_outputs?, new_raw_command?
      - type="move":node_id, new_edge=(src,dst)
      - type="remove":node_id
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


# ============================================================
# GrabnelConfig dataclass
# ============================================================

@dataclass
class GrabnelConfig(AttackConfig):
    """SafeMimic-CMD v3 主配置(GRABNEL BO + Inner GA + Sparse BLR + LCB)。"""

    # ─── core(§5 Algorithm 1 顶层超参)────────────────────
    B_max: int = 20                       # query 预算(§5.3 Eq 2,真 query 次数上限)
    H: int = 3                            # WL 迭代轮数(§5.2 Eq 5)
    D_cap: int = 200                      # WL feature 维度上限(hash 桶化)
    beta: float = 5.0                     # Tchebycheff β(§5.3 Eq 11)
    beta_lcb: float = 0.5                 # LCB β(§5.4 Eq 12)
    k_nn: int = 5                         # f_2 k-NN k 值(§5.3 Eq 10)
    T_GA: int = 50                        # Inner GA 代数(§5.4)
    m_pop: int = 20                       # Inner GA 种群大小(§5.4)
    tau: float = 0.5                      # detector 报警阈值(§5.2 Eq 9,通常跟 PIDSMaker 默认对齐)
    n_init_random: int = 3                # 首 stage 随机 Δ 初始长度上限

    # ─── ablation switches(对应 §5 7 个 TODO,E2.1-E2.7)─
    feature_method: str = "wl"            # E2.1: wl|gnn|random_walk|graph2vec|domain
    surrogate: str = "blr"                # E2.2: blr|gp_wl|gp_rbf|rf|ensemble
    f2_metric: str = "knn"                # E2.3: knn|dist_weighted|kde|gmm
    scalarize: str = "tcheby"             # E2.4: tcheby|weighted|lex
    commit_mode: str = "single"           # E2.5: single|batch_2|beam_3|lookahead_2
    acquisition: str = "lcb"              # E2.6: lcb|ei|thompson|lcb_anneal
    ga_mutation_weighted: bool = False    # E2.7: Mutation Add 是否按 R_unflagged 频率加权
    ga_constrained_mut: bool = False      # E2.7: Mutation 是否 constrained 不需后过滤
    ga_edit_edge: bool = False            # E2.7: 1-edit neighborhood 是 op 级还是 edge 级

    # ─── BLR + ARD prior 超参(§5.2 Eq 6-8)──────────────
    ard_k: float = 1e-4                   # ARD Gamma hyperprior shape
    ard_theta: float = 1e-4               # ARD Gamma hyperprior scale
    sigma_n2: float = 0.1                 # likelihood noise variance

    # ─── reference warm-start(§5.3)─────────────────────
    warm_start_n: int = 30                # R_unflagged 起步用 N 份 benign trace
    benign_trace_dir: str = "detection/data/training_traces"

    # ─── candidate pool ─────────────────────────────────
    candidate_pool_path: str = "shared/candidate_pool.txt"

    # ─── runtime ────────────────────────────────────────
    early_stop_on_evade: bool = True      # F(G) = ∅ 立即 return Δ

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GrabnelConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        kwargs = {k: v for k, v in d.items() if k in known}
        extra = {k: v for k, v in d.items() if k not in known}
        cfg = cls(**kwargs)
        cfg.extra.update(extra)
        return cfg
