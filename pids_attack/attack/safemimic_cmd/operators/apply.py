"""Apply a Δ sequence to G_0 with R1/R2 preconditions enforced per op."""
from __future__ import annotations

from typing import List, Optional, Tuple

from cmd_graph.graph import CommandGraph
from cmd_graph.operators import (
    apply_add, apply_remove, apply_rewrite, apply_move,
    precondition_add, precondition_remove, precondition_rewrite, precondition_move,
    OperatorError,
)

from .atomic_op import AtomicOp


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
                new_inputs = set(p.get("new_inputs", [])) if p.get("new_inputs") else None
                new_outputs = set(p.get("new_outputs", [])) if p.get("new_outputs") else None
                if not precondition_rewrite(
                    G,
                    p["node_id"],
                    list(p.get("new_args", [])),
                    new_inputs,
                    new_outputs,
                ):
                    return None, False
                G = apply_rewrite(
                    G,
                    node_id=p["node_id"],
                    new_args=list(p.get("new_args", [])),
                    new_inputs=new_inputs,
                    new_outputs=new_outputs,
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
