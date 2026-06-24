"""Inner GA — p2_mcts_v3.md §5.4 / BagAmmo §5.3 4 组件(跳 Immigration)。

每 stage 在 surrogate 上跑 T_GA 代 GA,**0 真 query**:
  (1) Population & Individual    — m 条 Δ 序列,每个 op ∈ §4 atomic op
  (2) Fitness & Selection         — LCB acquisition α(Δ) = μ - β·σ,elitist top-m
  (3) Crossover                   — 两 Δ subsequence swap
  (4) Mutation                    — Add / Remove / Replace 3 模式

R1(攻击 op 不可改)+ R2(序列可执行 partial order)硬过滤违规个体。
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from cmd_graph.graph import CommandGraph
from cmd_graph.operators import (
    apply_add, apply_remove, apply_rewrite, apply_move,
    precondition_add, precondition_remove, precondition_rewrite, precondition_move,
    OperatorError,
)
from .config import AtomicOp, GrabnelConfig
from .surrogate import SparseBLR, wl_feature_vector
from .acquisition import lcb, ei, thompson


# ============================================================
# Individual
# ============================================================

@dataclass
class Individual:
    """Inner GA 个体:一条 Δ 序列 + 缓存。"""
    delta: List[AtomicOp] = field(default_factory=list)
    G_cache: Optional[CommandGraph] = None
    phi: Optional[np.ndarray] = None
    alpha: Optional[float] = None
    valid: bool = True             # R1/R2 是否合法

    def reset_cache(self) -> None:
        self.G_cache = None
        self.phi = None
        self.alpha = None
        self.valid = True


# ============================================================
# Δ 应用 + R1/R2 验证
# ============================================================

def apply_delta(delta: List[AtomicOp], G_0: CommandGraph) -> Tuple[Optional[CommandGraph], bool]:
    """对 G_0 顺序施加 Δ,返回 (G_new, valid)。

    任一 op 违反 precondition / R1 / R2 → 返回 (None, False)。
    """
    G = G_0
    for op in delta:
        try:
            t = op.type
            p = op.params
            if t == "add":
                if not precondition_add(G, tuple(p["edge"])):
                    return None, False
                G = apply_add(
                    G,
                    raw_command=p["raw_command"],
                    args=list(p.get("args", [])),
                    edge=tuple(p["edge"]),
                    inputs=set(p.get("inputs", [])) if p.get("inputs") else None,
                    outputs=set(p.get("outputs", [])) if p.get("outputs") else None,
                )
            elif t == "rewrite":
                if not precondition_rewrite(G, p["node_id"]):
                    return None, False
                G = apply_rewrite(
                    G,
                    node_id=p["node_id"],
                    new_args=list(p.get("new_args", [])),
                    new_inputs=set(p.get("new_inputs", [])) if p.get("new_inputs") else None,
                    new_outputs=set(p.get("new_outputs", [])) if p.get("new_outputs") else None,
                    new_raw_command=p.get("new_raw_command"),
                )
            elif t == "move":
                if not precondition_move(G, p["node_id"], tuple(p["new_edge"])):
                    return None, False
                G = apply_move(G, node_id=p["node_id"], new_edge=tuple(p["new_edge"]))
            elif t == "remove":
                if not precondition_remove(G, p["node_id"]):
                    return None, False
                G = apply_remove(G, node_id=p["node_id"])
            else:
                return None, False
        except (OperatorError, KeyError, TypeError):
            return None, False
    return G, True


# ============================================================
# Candidate pool loader
# ============================================================

def load_candidate_pool(path: str) -> List[str]:
    """读 shared/candidate_pool.txt,返回有效命令字符串列表(去注释 + 空行)。"""
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 行内注释截掉
        if "#" in line:
            line = line[: line.index("#")].strip()
        if line:
            out.append(line)
    return out


# ============================================================
# Inner GA
# ============================================================

class InnerGA:
    """Inner GA — p2_mcts_v3.md §5.4 / BagAmmo §5.3 风格。

    Algorithm:
        1. initialise_population(T, current_delta) → m 条 Δ
        2. 跑 T_GA 代:
              for each Δ_i:
                  G_i = apply(Δ_i, G_0)
                  μ, σ = BLR(Φ(G_i))
                  α(Δ_i) = lcb(μ, σ)
              Selection elitist top-m
              Crossover 子序列交换
              Mutation Add/Remove/Replace
              R1/R2 硬过滤
        3. return argmin α 的 Δ
    """

    def __init__(
        self,
        cfg: GrabnelConfig,
        surrogate: SparseBLR,
        G_0: CommandGraph,
        cmd_pool: List[str],
        rng: Optional[random.Random] = None,
    ) -> None:
        self.cfg = cfg
        self.surrogate = surrogate
        self.G_0 = G_0
        self.cmd_pool = list(cmd_pool) if cmd_pool else []
        self.rng = rng or random.Random(cfg.seed)

    # ─── (1) Population & Individual init ────────────────

    def initialise_population(
        self,
        history_T: List[Tuple[List[AtomicOp], float]],
        current_delta: List[AtomicOp],
    ) -> List[Individual]:
        """初始 population。

        - 若 history_T 有数据,抽 top-k 高 s 个体作 seed,mutation 填满 m 个
        - 否则首 stage:从 atomic op 空间随机采 m 条短 Δ(长度 1-n_init_random)
        """
        m = self.cfg.m_pop
        pop: List[Individual] = []

        if history_T:
            # top-k high-s seeds
            sorted_T = sorted(history_T, key=lambda x: -x[1])
            top_k = sorted_T[: max(1, m // 4)]
            for i in range(m):
                seed_delta = list(self.rng.choice(top_k)[0]) if top_k else []
                ind = Individual(delta=seed_delta)
                # mutation 一次扩散
                ind = self._mutate(ind)
                pop.append(ind)
        else:
            # 首 stage:从随机采样起步
            for _ in range(m):
                length = self.rng.randint(1, max(1, self.cfg.n_init_random))
                delta: List[AtomicOp] = []
                # 先把 current_delta(可能为空)作起点
                delta = list(current_delta)
                for _ in range(length):
                    op = self._random_atomic_op(delta_so_far=delta)
                    if op is not None:
                        delta.append(op)
                pop.append(Individual(delta=delta))

        return pop

    # ─── (2) Fitness & Selection ─────────────────────────

    def _evaluate(self, pop: List[Individual]) -> None:
        """评 fitness:每个 individual 算 phi → posterior → acquisition (LCB/EI/Thompson)。"""
        # 计算 s_best(用于 EI)
        s_best = None
        if self.cfg.acquisition == "ei" and self.surrogate.s_hist.size > 0:
            s_best = float(self.surrogate.s_hist.min())
        for ind in pop:
            if ind.alpha is not None:
                continue                                # 已缓存
            G_new, ok = apply_delta(ind.delta, self.G_0)
            ind.valid = ok
            if not ok or G_new is None or len(G_new.nodes) == 0:
                ind.alpha = float("inf")                # 无效 → 最差
                continue
            ind.G_cache = G_new
            ind.phi = wl_feature_vector(G_new, H=self.cfg.H, D_cap=self.cfg.D_cap)
            mu, sigma = self.surrogate.posterior(ind.phi)
            acq = self.cfg.acquisition
            if acq == "ei" and s_best is not None:
                ind.alpha = float(ei(mu, sigma, s_best=s_best))
            elif acq == "thompson":
                ind.alpha = float(thompson(mu, sigma))
            elif acq == "lcb_anneal":
                # β_LCB 随种群代数 anneal:这里没 gen 信息,简化用 beta_lcb
                ind.alpha = float(lcb(mu, sigma, beta_lcb=self.cfg.beta_lcb))
            else:
                ind.alpha = float(lcb(mu, sigma, beta_lcb=self.cfg.beta_lcb))

    def _select_top_m(self, pop: List[Individual]) -> List[Individual]:
        """Elitist:argmin α top-m。"""
        valid = [p for p in pop if p.valid and p.alpha is not None and np.isfinite(p.alpha)]
        valid.sort(key=lambda x: x.alpha)
        return valid[: self.cfg.m_pop] if valid else pop[: self.cfg.m_pop]

    # ─── (3) Crossover ───────────────────────────────────

    def _crossover(self, pop: List[Individual]) -> List[Individual]:
        """从种群随机选 K 对,subsequence swap 产生 offspring。"""
        if len(pop) < 2:
            return pop
        new_inds: List[Individual] = []
        n_pairs = max(1, len(pop) // 2)
        for _ in range(n_pairs):
            p1, p2 = self.rng.sample(pop, 2)
            if not p1.delta or not p2.delta:
                continue
            cut1 = self.rng.randint(0, len(p1.delta))
            cut2 = self.rng.randint(0, len(p2.delta))
            child1_delta = p1.delta[:cut1] + p2.delta[cut2:]
            child2_delta = p2.delta[:cut2] + p1.delta[cut1:]
            new_inds.append(Individual(delta=child1_delta))
            new_inds.append(Individual(delta=child2_delta))
        return new_inds

    # ─── (4) Mutation ────────────────────────────────────

    def _mutate(self, ind: Individual) -> Individual:
        """3 种 mutation 模式之一:Add / Remove / Replace。"""
        delta = list(ind.delta)
        mode_choices: List[str] = ["add", "remove", "replace"]
        if not delta:
            mode_choices = ["add"]                      # 空 Δ 只能 add
        mode = self.rng.choice(mode_choices)

        if mode == "add":
            op = self._random_atomic_op(delta_so_far=delta)
            if op is not None:
                # 末尾 append 是 GRABNEL Fig 2 风格;TODO E2.7 可改成随机插入
                delta.append(op)
        elif mode == "remove":
            idx = self.rng.randrange(len(delta))
            delta.pop(idx)
        elif mode == "replace":
            idx = self.rng.randrange(len(delta))
            op = self._random_atomic_op(delta_so_far=delta[:idx])
            if op is not None:
                delta[idx] = op

        return Individual(delta=delta)

    def _random_atomic_op(self, delta_so_far: List[AtomicOp]) -> Optional[AtomicOp]:
        """随机生成一个 atomic op,默认 Add 模式(因为命令空间最大)。

        简化版:只生成 Add op(注入新命令)。Rewrite/Move/Remove 需要拿到当前 G 才能采,
        交给后续迭代 Mutation 的 remove/replace 模式去做。
        """
        if not self.cmd_pool:
            return None
        cmd = self.rng.choice(self.cmd_pool)
        # 解析 args(简单 split)
        tokens = cmd.split()
        raw = cmd
        args = tokens[1:] if len(tokens) > 1 else []
        # 边选 (0, 1) — TODO 后续应该根据当前 Δ 应用后的 G 选合法 edge,
        # 这里简化为 (0, 1)(几乎所有 G_0 都有这条 e_seq);apply_delta 会验
        edge = (0, 1)
        return AtomicOp(
            type="add",
            params={
                "raw_command": raw,
                "args": args,
                "edge": edge,
                "inputs": [],
                "outputs": [],
            },
        )

    # ─── main run ────────────────────────────────────────

    def run(
        self,
        history_T: List[Tuple[List[AtomicOp], float]],
        current_delta: List[AtomicOp],
    ) -> Individual:
        """跑 T_GA 代 GA,返回 argmin α 的 Δ*。"""
        pop = self.initialise_population(history_T, current_delta)
        self._evaluate(pop)

        best_overall: Optional[Individual] = None
        for gen in range(self.cfg.T_GA):
            # Selection
            pop = self._select_top_m(pop)
            if pop:
                if best_overall is None or pop[0].alpha < best_overall.alpha:
                    best_overall = pop[0]

            # Crossover + Mutation produce offspring
            offspring: List[Individual] = self._crossover(pop)
            mutated = [self._mutate(p) for p in pop]
            new_pop = pop + offspring + mutated
            self._evaluate(new_pop)
            pop = new_pop

        # final selection
        pop = self._select_top_m(pop)
        if pop and (best_overall is None or pop[0].alpha < best_overall.alpha):
            best_overall = pop[0]
        # fallback:无任何 valid 个体 → 返回空 Δ
        if best_overall is None:
            return Individual(delta=list(current_delta))
        return best_overall
