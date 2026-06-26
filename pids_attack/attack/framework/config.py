"""AttackConfig + SafeMimicConfig — 算法无关的运行配置基础。

`AttackConfig` 是算法无关基础;`SafeMimicConfig` 是 SafeMimic-CMD 唯一 paper-facing 配置类,
字段覆盖 `p3_results.md` §3.7-§3.12 的 E1.0-E1.5 全部 variants。
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict


@dataclass
class AttackConfig:
    """算法无关基础配置 — query 预算 + iteration 上限 + checker retry + detector 选择 + seed。"""
    query_budget: int = 200                          # 全局 D_target query 上限(B)
    max_iterations: int = 500                        # 主循环最大 iteration
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


# ============================================================
# SafeMimicConfig — paper-facing 唯一 config
# ============================================================

@dataclass
class SafeMimicConfig(AttackConfig):
    """SafeMimic-CMD 唯一 paper-facing 配置 — 覆盖 E1.0-E1.5 全部 variants。

    字段按 `p3_results.md` §3.7-§3.12 分块,每个 E1.x cell 通过改字段值切换 variant,
    不需新 config 类。`AttackConfig` 的 base 字段(detector / query_budget / seed)继承不重复。
    """

    # ─── E1.0 攻击闭环基础 ──────────────────────────
    scenario: str = ""                       # A0 scenario id
    B_max: int = 20                          # query 预算(§5 Eq 2,真 query 上限)
    tau: float = 0.5                         # detector 报警阈值(§5.2 Eq 9)
    candidate_pool_path: str = "shared/candidate_pool.txt"
    benign_trace_dir: str = "detection/data/training_traces"
    early_stop_on_evade: bool = True         # F(G) = ∅ 立即返回 Δ

    # ─── E1.1 Mutation primitive (§4 operators) ───
    operator_set: str = "all4"               # add_only | add_rewrite | add_rewrite_move | all4
    n_init_random: int = 3                   # 首 stage 随机 Δ 初始长度上限

    # ─── E1.2 Fitness design (§5.3 objectives) ───
    objective: str = "f1_f2"                 # f1_only | f1_f2
    f2_metric: str = "knn"                   # knn | dist_weighted | kde | gmm
    f2_warmstart_n: int = 30                 # R_unflagged 起步用 N 份 benign trace
    k_nn: int = 5                            # f_2 k-NN k 值(§5.3 Eq 10)
    scalarize: str = "tcheby"                # tcheby | weighted_sum | lex
    scalarize_beta: float = 5.0              # Tchebycheff β(§5.3 Eq 11)

    # ─── E1.3 Search structure (§5.3 sequential + §5.4 inner GA) ───
    search_policy: str = "full"              # full | random | one_shot
    T_GA: int = 50                           # Inner GA 代数(§5.4)
    m_pop: int = 20                          # Inner GA 种群大小(§5.4)
    commit_mode: str = "single"              # single | batch_2 | beam_3 | lookahead_2

    # ─── E1.4 Surrogate (§5.2 WL + Sparse BLR + ARD) ───
    surrogate: str = "blr_ard"               # blr_ard | blr_noard | no_posterior | wl_gp
    feature_method: str = "wl"               # wl(default)| gnn | random_walk | graph2vec | domain
    H: int = 3                               # WL 迭代轮数(§5.2 Eq 5)
    D_cap: int = 200                         # WL feature 维度上限(hash 桶化)
    ard_k: float = 1e-4                      # ARD Gamma hyperprior shape
    ard_theta: float = 1e-4                  # ARD Gamma hyperprior scale
    sigma_n2: float = 0.1                    # likelihood noise variance

    # ─── E1.5 Acquisition (§5.4 LCB / EI / Thompson) ───
    acquisition: str = "lcb"                 # lcb | ei | thompson
    lcb_beta: float = 0.5                    # LCB β(§5.4 Eq 12)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SafeMimicConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        kwargs = {k: v for k, v in d.items() if k in known}
        extra = {k: v for k, v in d.items() if k not in known}
        cfg = cls(**kwargs)
        cfg.extra.update(extra)
        return cfg
