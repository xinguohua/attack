"""CommandGraph → shell 命令序列(承 1_p1_formulation.md §4.2 "Translating Command-Graph Mutation to Shell-Level Perturbation")。

Phase 1 实现:沿 E_seq chain 走出顺序,每个节点直接输出其 raw_command(R1 字面严守)。
"""
from __future__ import annotations
from typing import List

from .graph import CommandGraph


def graph_to_shell(G: CommandGraph) -> List[str]:
    """G → List[str] shell 命令序列(按 E_seq chain 顺序,raw_command 字面输出)。"""
    return [G.nodes[nid].raw_command for nid in G.sequence()]
