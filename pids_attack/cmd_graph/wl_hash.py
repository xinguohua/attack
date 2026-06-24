"""Weisfeiler-Lehman canonical hash on CommandGraph(承 p2_mcts.md §5.3.3 (a) S3)。

用 networkx.weisfeiler_lehman_graph_hash 作底层实现。

节点 label = `raw_command # sorted(R(c)) # is_attack`
  - raw_command 区分命令字面(R1 严守)
  - R(c) = inputs ∪ outputs 是资源指纹
  - is_attack 区分 A_0 攻击节点 vs δ 节点

边 etype ∈ {"seq", "res", "spawn"} 区分 3 类边

同构 G(节点 label + 边类型 + 拓扑相同)→ 同 hash。Phase 4 Validation 严格 verify:
  - 同构但节点编号 reshuffle → hash 相同
  - 多一条边 / 改节点 label → hash 不同
"""
from __future__ import annotations
import networkx as nx

from .graph import CommandGraph


def _node_label(node) -> str:
    """节点 label:raw_command + 资源指纹 + is_attack。"""
    rsig = "|".join(sorted(node.resources))
    return f"{node.raw_command}#{rsig}#{int(node.is_attack)}"


def wl_canonical_hash(G: CommandGraph, iters: int = 3) -> str:
    """WL canonical hash on CommandGraph,返回 32 hex char digest。

    p2_mcts.md §5.3.3 (a):同构 G 映射到同一 key,docker 真跑输出必相同。

    实现:用 nx.DiGraph(WL 不支持 MultiDiGraph),同一对节点的多类边
    合并成 sorted etype 字符串作 edge attr。
    """
    nxg = nx.DiGraph()
    for nid, node in G.nodes.items():
        nxg.add_node(nid, label=_node_label(node))

    # 合并多类边到 (src, dst) → etype set
    edge_types: dict = {}
    for a, b in G.e_seq:
        edge_types.setdefault((a, b), set()).add("seq")
    for a, b in G.e_res:                            # e_res 无向 → 加双向
        edge_types.setdefault((a, b), set()).add("res")
        edge_types.setdefault((b, a), set()).add("res")
    for a, b in G.e_spawn:
        edge_types.setdefault((a, b), set()).add("spawn")
    for (a, b), types in edge_types.items():
        nxg.add_edge(a, b, etype="|".join(sorted(types)))

    if nxg.number_of_nodes() == 0:
        return "empty:0"
    return nx.weisfeiler_lehman_graph_hash(
        nxg,
        edge_attr="etype",
        node_attr="label",
        iterations=iters,
    )
