"""方案 1:Nettack [Zugner+ KDD'18] §4.1 严格版 — 对照 baselines/nettack/nettack/nettack.py 源码实现。

参考(2026-05-26 cross-check):
  - compute_alpha (line 587):   α = n / (S_d - n·log(d_min - 0.5)) + 1
  - compute_log_likelihood (line 651): n·log(α) + n·α·log(d_min) - (α+1)·S_d
                                       S_d = Σ log(d_i) for d_i ≥ d_min
  - Λ (line 405-409):    -2·ll_combined + 2·(ll_new + ll_orig)
  - δ_cutoff = 0.004(filter_chisquare,Chi²(1) p=0.95)
  - d_min = 2(Nettack 默认)
  - Eq.12 (line 59-97):
      cooc_matrix = X.T @ X(feature-feature cooccur count)
      word_degrees = sum(cooc_matrix > 0, axis=0)        # cooc-graph 上每 feature 度
      inv_word_degrees = 1 / (word_degrees + ε)
      sd[n] = Σ_{j ∈ S_n} (1/d_j)                       # 节点自身基线 score
      score(n, t) = Σ_{j ∈ S_n, (j,t) ∈ cooc} (1/d_j)
      allow t ⇔ score(n, t) > 0.5 · sd[n]
"""
from __future__ import annotations
import math
from collections import Counter
from typing import Any, Dict, Iterable, List, Set, Tuple

from .graph import CommandGraph
from .nettack import resource_type, filter_resources, _node_degrees


# ============================================================
# Nettack source code constants
# ============================================================

D_MIN_STRICT: float = 2.0                                  # Nettack 源码默认 d_min
TAU_LAMBDA_STRICT: float = 0.004                           # Nettack 源码 δ_cutoff(χ²(1) p=0.95)


# ============================================================
# Eq. 6 + Eq. 7 — 源码 compute_alpha / compute_log_likelihood
# ============================================================

def _compute_S_d(degrees: Iterable[float], d_min: float = D_MIN_STRICT) -> float:
    """S_d = Σ log(d_i) for d_i ≥ d_min(源码精确公式)。"""
    return sum(math.log(d) for d in degrees if d >= d_min)


def _compute_n(degrees: Iterable[float], d_min: float = D_MIN_STRICT) -> int:
    """n = #{d_i ≥ d_min}(源码精确公式)。"""
    return sum(1 for d in degrees if d >= d_min)


def _compute_alpha_strict(n: int, S_d: float, d_min: float = D_MIN_STRICT) -> float:
    """Nettack 源码 compute_alpha (line 587-608)。

      α = n / (S_d - n·log(d_min - 0.5)) + 1

    退化保护:n=0 或 denom ≤ 0 时返回 2.0(Nettack 默认 α 量级)。
    """
    if n == 0:
        return 2.0
    denom = S_d - n * math.log(d_min - 0.5)
    if denom <= 0:
        return 2.0
    return n / denom + 1.0


def _compute_log_likelihood_strict(n: int, alpha: float, S_d: float,
                                    d_min: float = D_MIN_STRICT) -> float:
    """Nettack 源码 compute_log_likelihood (line 651-674)。

      ll = n·log(α) + n·α·log(d_min) - (α+1)·S_d
    """
    if n == 0 or alpha <= 0:
        return 0.0
    return n * math.log(alpha) + n * alpha * math.log(d_min) - (alpha + 1) * S_d


# ============================================================
# Eq. 10 严格版 — likelihood ratio test(源码 line 405-409)
# ============================================================

def eq10_strict_lambda(
    degrees_before: List[float],
    degrees_after: List[float],
    d_min: float = D_MIN_STRICT,
) -> float:
    """Nettack §4.1 Eq. 10 严格 likelihood ratio test(源码精确版)。

      Λ = -2·ll_combined + 2·(ll_new + ll_orig)

    H_0:扰动后 power-law parameter 未变;Λ < δ_cutoff=0.004 → 接受 H_0 → unnoticeable。
    """
    if not degrees_before and not degrees_after:
        return 0.0

    S_d_0 = _compute_S_d(degrees_before, d_min)
    n_0 = _compute_n(degrees_before, d_min)
    alpha_0 = _compute_alpha_strict(n_0, S_d_0, d_min)
    ll_0 = _compute_log_likelihood_strict(n_0, alpha_0, S_d_0, d_min)

    S_d_p = _compute_S_d(degrees_after, d_min)
    n_p = _compute_n(degrees_after, d_min)
    alpha_p = _compute_alpha_strict(n_p, S_d_p, d_min)
    ll_p = _compute_log_likelihood_strict(n_p, alpha_p, S_d_p, d_min)

    S_d_c = S_d_0 + S_d_p
    n_c = n_0 + n_p
    alpha_c = _compute_alpha_strict(n_c, S_d_c, d_min)
    ll_c = _compute_log_likelihood_strict(n_c, alpha_c, S_d_c, d_min)

    return -2.0 * ll_c + 2.0 * (ll_p + ll_0)


# ============================================================
# Eq. 12 严格版 — 源码精确公式(line 59-97)
# ============================================================

def _compute_cooc_degrees(c_benign: Dict[str, Any]) -> Dict[str, int]:
    """Nettack 源码 word_degrees:每个 feature(我们的 resource type)在 cooc-graph 上的度
    = 跟多少不同 feature 共现过(无向 binary cooccur graph)。

    源码 (line 78-80):
      words_graph.setdiag(0)
      words_graph = (words_graph > 0)
      word_degrees = np.sum(words_graph, axis=0).A1
    """
    type_pairs: Set[Tuple[str, str]] = c_benign.get("type_pairs", set())
    cooc_degrees: Dict[str, int] = {}
    types_all: Set[str] = set()
    for (a, b) in type_pairs:
        types_all.add(a)
        types_all.add(b)
    for t in types_all:
        cooc_degrees[t] = sum(1 for (a, b) in type_pairs if a == t or b == t)
    return cooc_degrees


def eq12_strict_check(
    types_before: Set[str],
    types_after: Set[str],
    c_benign: Dict[str, Any],
) -> bool:
    """Nettack §4.1 Eq. 12 源码精确版。

    源码 (line 76-97):
      sd[n]      = Σ_{j ∈ S_n} (1/d_j)                节点 n 自身基线
      score(n,t) = Σ_{j ∈ S_n, (j,t) ∈ cooc} (1/d_j)
      σ_n        = 0.5 · sd[n]
      allow t ⇔ score(n, t) > σ_n

    Args:
      types_before: S_u (node u 已有 feature)
      types_after:  扰动后 node u feature 集
      c_benign:     precompute_co_occurrence 输出(含 type_pairs)

    Returns:
      True  = unnoticeable (扰动通过 σ_n 阈值)
      False = noticeable / reject
    """
    new_types = types_after - types_before
    if not new_types:
        return True
    S_u = types_before
    if not S_u:
        # 严格 Nettack:node 无已有 feature → S_u 空 → sd[n]=0 → σ_n=0 → score 必须 >0 才过
        # 但 score 公式 over empty S_u 也是 0 → 任何新 feature 都 score=0 ≤ σ_n=0 → reject
        return False

    type_pairs: Set[Tuple[str, str]] = c_benign.get("type_pairs", set())
    cooc_degrees = _compute_cooc_degrees(c_benign)

    # inv_d for j ∈ S_u
    eps = 1e-8
    inv_d: Dict[str, float] = {
        t: 1.0 / (cooc_degrees.get(t, 0) + eps)
        for t in S_u
    }
    sd_n = sum(inv_d.values())
    sigma_n = 0.5 * sd_n

    for t_new in new_types:
        if t_new in S_u:
            continue
        # score(n, t_new) = Σ_{j ∈ S_u, (j, t_new) ∈ cooc} (1/d_j)
        score = sum(
            inv_d[j]
            for j in S_u
            if tuple(sorted((j, t_new))) in type_pairs
        )
        if score <= sigma_n:
            return False
    return True


# ============================================================
# Top-level R3 filter — 严格 Nettack §4.1
# ============================================================

def r3_filter_strict(
    G_state_before: CommandGraph,
    G_state_after: CommandGraph,
    affected_node_ids: Iterable[int],
    c_benign: Dict[str, Any],
    tau_lambda: float = TAU_LAMBDA_STRICT,
    d_min: float = D_MIN_STRICT,
) -> Tuple[bool, str]:
    """方案 1 — Nettack §4.1 严格原版(源码 cross-check 后)R3 filter。

    Returns: (passed, reason)
    """
    # Eq. 12:每个 affected 节点查 strict co-occurrence preservation
    for nid in affected_node_ids:
        node_after = G_state_after.nodes.get(nid)
        if node_after is None:
            continue
        types_after = {resource_type(r) for r in filter_resources(node_after.resources)}
        node_before = G_state_before.nodes.get(nid)
        types_before = set()
        if node_before is not None:
            types_before = {resource_type(r) for r in filter_resources(node_before.resources)}
        if not eq12_strict_check(types_before, types_after, c_benign):
            return False, f"eq12_strict_violation: node {nid} types {types_before} → {types_after}"

    # Eq. 10:严格 likelihood ratio Λ
    deg_before = _node_degrees(G_state_before)
    deg_after = _node_degrees(G_state_after)
    lam = eq10_strict_lambda(deg_before, deg_after, d_min)
    if lam >= tau_lambda:
        return False, f"eq10_strict_violation: Λ={lam:.6f} ≥ τ={tau_lambda}"

    return True, ""
