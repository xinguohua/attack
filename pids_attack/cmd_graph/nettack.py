"""Nettack [Zugner+ KDD'18] §4.1 unnoticeable perturbation constraints
— 命令图 R3 filter(承 p2_mcts.md §5.3.2 S1)。

两族约束:
  Eq. 10 (Degree distribution preservation):
    Λ = -2·(l(D_combined|α) − l(D|α) − l(D'|α'))
    扰动若使 Λ ≥ τ_Λ → reject

  Eq. 12 (Feature co-occurrence preservation):
    p(t_new ∈ S_v) = (1/|S_v|) Σ_{t' ∈ S_v} (1/d_t') · 𝟙[(t', t_new) ∈ E_C]
    若 p ≤ σ → reject

实现是 graph-agnostic — 接 networkx 风格的 (nodes, edges) 表示,通过 type 函数让 caller 决定怎么把 G_benign 投影成 type-co-occurrence + degree distribution。
"""
from __future__ import annotations
import math
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, Iterable, Optional, Set, Tuple

from .graph import CommandGraph


# ============================================================
# Resource type abstraction
# ============================================================

def resource_type(res: str) -> str:
    """资源 ID → 类型标签:用于 Eq. 12 co-occurrence。

    file path 含 / → "file";含 ip:port 模式 → "netflow";其他 → "other"。
    """
    if not res:
        return "other"
    if res.startswith("/"):
        return "file"
    # netflow:host:port 或 ip:port
    if ":" in res and res.split(":")[-1].isdigit():
        return "netflow"
    if res.startswith("unix:"):
        return "unix"
    return "other"


def is_system_library(res: str) -> bool:
    """系统库 / 动态链接器路径过滤(Phase 1 finding [P1]:G_benign |E_res|=108k 因系统库共享爆图)。

    黑名单:/lib/* / /usr/lib/* / /etc/ld.so.cache / /etc/nsswitch.conf 等
    """
    if not isinstance(res, str) or not res:
        return False
    patterns = (
        "/lib/", "/usr/lib/", "/lib64/", "/usr/lib64/",
        "/etc/ld.so.", "/etc/nsswitch.conf",
        "/etc/host.conf", "/etc/resolv.conf",
        # 注意:/etc/passwd / /etc/shadow 是攻击常用 target,不过滤
    )
    return any(p in res for p in patterns)


def filter_resources(resources: Iterable[str]) -> Set[str]:
    """剥掉系统库 / 公共配置类资源(Phase 5 R3 reference 前置过滤)。"""
    return {r for r in resources if r and not is_system_library(r)}


# ============================================================
# Eq. 12 — co-occurrence preservation
# ============================================================

def precompute_co_occurrence(G_benign: CommandGraph) -> Dict[str, Any]:
    """对 G_benign 跑 type-co-occurrence 预统计。

    输出:
      type_pairs:  set of (t1, t2) — 在 G_benign 某节点上同时出现过的类型对(无序对)
      type_freq:   Counter — 每个类型 t 在 G_benign 整图上的频率(资源条数)
      neighbor_types_by_node: Dict[(cmd_name_signature) → set of types]
                              用作 v 在 G_benign 上的典型邻居类型集 S_v 参考

    cmd_name_signature 用节点 raw_command 的第一个 token(命令名),用于把 G_state 节点跟 G_benign 对齐。
    """
    type_pairs: Set[Tuple[str, str]] = set()
    type_freq: Counter = Counter()
    neighbor_types_by_cmd: Dict[str, Set[str]] = defaultdict(set)

    for nid, node in G_benign.nodes.items():
        resources = filter_resources(node.resources)        # Phase 5 finding 应用
        types = {resource_type(r) for r in resources}
        cmd_name = node.raw_command.split()[0] if node.raw_command else ""
        # 该节点贡献的类型频次
        for t in types:
            type_freq[t] += 1
        # 同时出现过的类型对(无序对,key 用 sorted tuple)
        types_list = sorted(types)
        for i in range(len(types_list)):
            for j in range(i + 1, len(types_list)):
                type_pairs.add((types_list[i], types_list[j]))
        # 同一命令名下的"典型邻居类型集"
        neighbor_types_by_cmd[cmd_name] |= types

    return {
        "type_pairs": type_pairs,
        "type_freq": dict(type_freq),
        "neighbor_types_by_cmd": {k: set(v) for k, v in neighbor_types_by_cmd.items()},
    }


def eq12_check(
    op_affected_node_types_before: Set[str],
    op_affected_node_types_after: Set[str],
    cmd_name: str,
    c_benign: Dict[str, Any],
    sigma: float = 0.05,
) -> bool:
    """Nettack Eq. 12 co-occurrence preservation check(p2_mcts.md §5.3.2)。

    S_v 取 G_benign 中该 cmd_name 节点的典型邻居类型集(`neighbor_types_by_cmd[cmd_name]`),
    fallback 到 op_affected_node_types_before(扰动前节点已有的类型),都为空就用全图任意类型对作 sanity。

    若扰动后引入了 (t', t_new) 这种从未在 G_benign 中共现过的类型对,
    且 (1/|S_v|) Σ (1/d_t') · 𝟙[(t', t_new) ∈ C_benign] ≤ σ → reject。

    Returns:
      True  = check 通过(unnoticeable)
      False = reject
    """
    type_pairs: Set[Tuple[str, str]] = c_benign.get("type_pairs", set())
    type_freq: Dict[str, int] = c_benign.get("type_freq", {})
    neighbor_types_by_cmd = c_benign.get("neighbor_types_by_cmd", {})

    new_types = op_affected_node_types_after - op_affected_node_types_before
    if not new_types:
        return True

    # S_v = G_benign 中该 cmd_name 节点的典型邻居类型集;空就 fallback 到扰动前节点已有类型
    S_v = set(neighbor_types_by_cmd.get(cmd_name, set())) or set(op_affected_node_types_before)
    # 若 cmd_name 完全未知 + 扰动前也无类型 → conservative 拒(新 op 在 G_benign 中无前例)
    if not S_v:
        return False

    for t_new in new_types:
        if t_new in S_v:
            continue                                  # 该 cmd_name 见过此类型,pass
        # 该 cmd_name 没见过 t_new — 但 G_benign 中是否有 (t', t_new) 共现?
        has_co = any(
            tuple(sorted((tp, t_new))) in type_pairs
            for tp in S_v
        )
        if not has_co:
            return False
        # 共现过 → 算 p 卡 σ
        p = sum(
            1.0 / max(1, type_freq.get(tp, 1))
            for tp in S_v
            if tuple(sorted((tp, t_new))) in type_pairs
        ) / len(S_v)
        if p <= sigma:
            return False
    return True


# ============================================================
# Eq. 10 — degree distribution preservation
# ============================================================

def _power_law_likelihood(degrees: list, alpha: float, d_min: float = 1.0) -> float:
    """Nettack Eq. 7 log-likelihood:
      l(D|α) = n·log(α-1) - n·log(d_min - 0.5)
               - α · Σ log(d_i / (d_min - 0.5))
    Phase 5 简化:用 Nettack 论文公式略 simplification。
    """
    n = len(degrees)
    if n == 0:
        return 0.0
    # 偏移 0.5 防 log(0)
    log_sum = sum(math.log(d + 0.5) for d in degrees if d >= 0)
    # 用经典公式 l = n·log(α) + α·n·log(d_min) − (α+1)·log_sum
    return n * math.log(alpha) + alpha * n * math.log(d_min) - (alpha + 1) * log_sum


def _fit_power_law_alpha(degrees: list, d_min: float = 1.0) -> float:
    """对 degree 序列拟合 power-law α(MLE 估计)。

    Clauset et al. 2009 标准 estimator:
      α̂ = 1 + n / Σ ln(d_i / (d_min - 0.5))
    """
    n = len(degrees)
    if n == 0:
        return 2.0
    s = sum(math.log((d + 0.5) / d_min) for d in degrees if d + 0.5 > d_min)
    if s <= 0:
        return 2.0
    return 1.0 + n / s


def precompute_power_law(G_benign: CommandGraph, d_min: float = 1.0) -> Dict[str, float]:
    """对 G_benign 拟合 degree power-law,返回 (α, l, degrees)。"""
    # degree = E_res 度数(只考虑命令-命令资源依赖,跟 Eq. 12 一致)
    degree_count: Counter = Counter()
    for a, b in G_benign.e_res:
        degree_count[a] += 1
        degree_count[b] += 1
    # 包含孤立点(degree=0)
    for nid in G_benign.nodes:
        if nid not in degree_count:
            degree_count[nid] = 0

    degrees = list(degree_count.values())
    alpha = _fit_power_law_alpha(degrees, d_min)
    l = _power_law_likelihood(degrees, alpha, d_min)
    return {"alpha": alpha, "l": l, "degrees": degrees, "d_min": d_min}


def eq10_incremental_lambda(
    degrees_before: list,
    degrees_after: list,
    power_law: Dict[str, float],
) -> float:
    """Nettack Eq. 10 + Theorem 5.2 简化版:扰动加入新 degree 在 baseline power-law 下的
    negative log-likelihood 之和。

    Power-law p(d) ∝ (d + 0.5)^{-α} ⇒ -log p(d) = α·log(d + 0.5) + const

    Λ = Σ_{d ∈ diff} (-log p(d)) / max(1, |diff|)
      = α · mean( log(d + 0.5) ) 对所有新 degree 求和

    Larger d_new ⇒ larger Λ ⇒ 越违反 baseline power-law。
    简单可靠:大 N baseline 中加入 outlier degree(如 Contorter inflation 10→62)
    Λ 至少 = α·log(62.5) ≈ 5,远超 τ_Λ=0.004。
    """
    alpha = power_law["alpha"]
    before_c = Counter(degrees_before)
    after_c = Counter(degrees_after)
    diff_c = after_c - before_c                          # 新加入或变化
    if not diff_c:
        return 0.0
    total_nll = 0.0
    n_new = 0
    for d, count in diff_c.items():
        if d <= 0:
            continue
        nll = alpha * math.log(d + 0.5)
        total_nll += count * nll
        n_new += count
    return total_nll / max(1, n_new)


# ============================================================
# Top-level R3 filter for Phase 5(Expansion 钩子用)
# ============================================================

def r3_filter(
    G_state_before: CommandGraph,
    G_state_after: CommandGraph,
    affected_node_ids: Iterable[int],
    c_benign: Dict[str, Any],
    power_law: Dict[str, float],
    tau_lambda: float = 0.004,
    sigma: float = 0.05,
) -> Tuple[bool, str]:
    """R3 = Eq. 12 + Eq. 10 联合 check。

    Returns:
      (passed: bool, reason: str)
      passed=True 表示 op 通过 R3 unnoticeable check;passed=False 给 reason
    """
    # Eq. 12: 对每个 affected 节点查 co-occurrence preservation
    for nid in affected_node_ids:
        node_after = G_state_after.nodes.get(nid)
        if node_after is None:
            continue
        types_after = {resource_type(r) for r in filter_resources(node_after.resources)}
        node_before = G_state_before.nodes.get(nid)
        types_before = set()
        if node_before is not None:
            types_before = {resource_type(r) for r in filter_resources(node_before.resources)}
        cmd_name = node_after.raw_command.split()[0] if node_after.raw_command else ""
        if not eq12_check(types_before, types_after, cmd_name, c_benign, sigma):
            return False, f"eq12_violation: node {nid} ({cmd_name}) types {types_before} → {types_after}"

    # Eq. 10: degree distribution preservation(整体 Λ)
    deg_before = _node_degrees(G_state_before)
    deg_after = _node_degrees(G_state_after)
    lam = eq10_incremental_lambda(deg_before, deg_after, power_law)
    if lam >= tau_lambda:
        return False, f"eq10_violation: Λ={lam:.4f} ≥ τ={tau_lambda}"

    return True, ""


def _node_degrees(G: CommandGraph) -> list:
    """计算每个节点的 e_res degree(用于 Eq. 10)。"""
    counter: Counter = Counter()
    for a, b in G.e_res:
        counter[a] += 1
        counter[b] += 1
    for nid in G.nodes:
        if nid not in counter:
            counter[nid] = 0
    return list(counter.values())
