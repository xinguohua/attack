"""WL feature extractor — 把 CommandGraph G 映射成 D 维稀疏向量 Φ(G) ∈ ℝ^D。

p2_mcts_v3.md §5.2 Eq (5):
    x^{h+1}(v) = HASH( x^h(v), {{ x^h(u) : u ∈ N(v) }} ),  ∀ h ∈ {0, 1, ..., H-1}

每一层 h 上,φ_h(G) 是 G 上各 hash label 的出现次数计数。
H 轮后 φ(G) = concat(φ_0(G), ..., φ_H(G)) ∈ ℝ^D,D ≈ 200(hash 桶化到 D_cap)。

承 GRABNEL [Wan et al. NeurIPS'21] §2 Surrogate model 块的 WL feature extractor,
跟 GRABNEL Eq 3 离散版 WL hash 直接对应。

节点 label 复用 cmd_graph/wl_hash.py::_node_label(raw_command # sorted(R(c)) # is_attack)。
"""
from __future__ import annotations

import hashlib
from collections import Counter
from typing import Iterable, List

import numpy as np

from cmd_graph.graph import CommandGraph
from cmd_graph.wl_hash import _node_label


# ============================================================
# 内部 helper
# ============================================================

def _hash_bucket(label: str, D_cap: int) -> int:
    """把 label 字符串 hash 到 [0, D_cap) 整数桶。"""
    h = hashlib.md5(label.encode("utf-8")).hexdigest()
    return int(h, 16) % D_cap


def _neighbor_labels_with_etype(G: CommandGraph, node_id: int, current_labels: dict) -> List[str]:
    """返回节点 v 的所有邻居 label(按 edge type 区分,sorted)。

    复用 cmd_graph/wl_hash.py 同款边类型合并:
      - e_seq 有向 (a → b)
      - e_res 无向 (a ↔ b) → 两边都算邻居
      - e_spawn 有向 (a → b)

    邻居 label = "{etype}|{neighbor_current_label}",最后排序。
    """
    out: List[str] = []
    # e_seq:有向 successor / predecessor 都算邻居(WL 是无向操作)
    for a, b in G.e_seq:
        if a == node_id:
            out.append(f"seq|{current_labels.get(b, '?')}")
        elif b == node_id:
            out.append(f"seq|{current_labels.get(a, '?')}")
    # e_res:无向
    for a, b in G.e_res:
        if a == node_id:
            out.append(f"res|{current_labels.get(b, '?')}")
        elif b == node_id:
            out.append(f"res|{current_labels.get(a, '?')}")
    # e_spawn:有向
    for a, b in G.e_spawn:
        if a == node_id:
            out.append(f"spawn|{current_labels.get(b, '?')}")
        elif b == node_id:
            out.append(f"spawn|{current_labels.get(a, '?')}")
    return sorted(out)


# ============================================================
# 公共 API
# ============================================================

def wl_feature_vector(
    G: CommandGraph,
    H: int = 3,
    D_cap: int = 200,
) -> np.ndarray:
    """WL feature extractor —— 把图 G 映射到 D_cap 维稀疏 count 向量 Φ(G) ∈ ℝ^D_cap。

    Algorithm(对应 §5.2 Eq 5):
      1. 每节点 v 初始 label x^0(v) = _node_label(v)
      2. 每轮 h ∈ {0, ..., H-1}:
           x^{h+1}(v) = hash( x^h(v) + sorted(neighbor labels with etype) )
      3. 每层 h 上的 label 计数 → bucket 到 [0, D_cap)
      4. 全 H 层 + 初始 = (H+1) 个 sparse count 向量 → 求和到一个 D_cap 维向量

    返回:np.ndarray shape=(D_cap,),dtype=float64
    """
    if len(G.nodes) == 0:
        return np.zeros(D_cap, dtype=np.float64)

    # 第 0 轮:初始 label
    current_labels = {nid: _node_label(node) for nid, node in G.nodes.items()}

    # 累计 count 到统一 D_cap 维向量
    phi = np.zeros(D_cap, dtype=np.float64)

    # 第 0 层:初始 label 计数
    for label in current_labels.values():
        phi[_hash_bucket(f"h0|{label}", D_cap)] += 1.0

    # 第 1, 2, ..., H 层:WL 迭代
    for h in range(H):
        new_labels = {}
        for nid in G.nodes:
            nb_labels = _neighbor_labels_with_etype(G, nid, current_labels)
            combined = current_labels[nid] + "#" + ",".join(nb_labels)
            new_labels[nid] = hashlib.md5(combined.encode("utf-8")).hexdigest()[:16]
        # 计数到 phi
        for label in new_labels.values():
            phi[_hash_bucket(f"h{h+1}|{label}", D_cap)] += 1.0
        current_labels = new_labels

    return phi


def wl_feature_vector_batch(
    Gs: Iterable[CommandGraph],
    H: int = 3,
    D_cap: int = 200,
) -> np.ndarray:
    """批量 WL feature extraction。

    返回:np.ndarray shape=(n, D_cap),每行一个图的 Φ。
    """
    phis = [wl_feature_vector(G, H=H, D_cap=D_cap) for G in Gs]
    if not phis:
        return np.zeros((0, D_cap), dtype=np.float64)
    return np.vstack(phis)
