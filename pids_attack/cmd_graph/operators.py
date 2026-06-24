"""4 atomic 算子 — 承 1_p1_formulation.md §4.2(3)。

Add / Rewrite / Move / Remove。每个算子:
  precondition_<op>(G, ...) → bool        检查前置条件(R1 攻击不可动 / R2 partial order)
  apply_<op>(G, ...) → CommandGraph       返回 deep-copy 新图;违反 precondition 抛 OperatorError

R1 enforce:apply_rewrite / apply_move / apply_remove 拒绝 is_attack=True 节点
R2 enforce:apply_move 检查新位置仍 respect partial order;apply_remove 检查 δ 是叶子
"""
from __future__ import annotations
from typing import List, Optional, Set, Tuple

from .graph import CommandGraph


class OperatorError(Exception):
    """算子前置条件违反时抛出。"""
    pass


# ---------- Add ----------

def precondition_add(
    G: CommandGraph,
    edge: Tuple[int, int],
) -> bool:
    """Add 前置条件:e=(c_prev, c_next) 必须是 E_seq 上的现有边。"""
    return tuple(edge) in G.e_seq


def apply_add(
    G: CommandGraph,
    raw_command: str,
    args: List[str],
    edge: Tuple[int, int],
    inputs: Optional[Set[str]] = None,
    outputs: Optional[Set[str]] = None,
    spawn_parent: Optional[int] = None,
) -> CommandGraph:
    """Add(δ_cmd, e):在 E_seq 边 e=(c_prev, c_next) 处插入新节点 δ。

    新节点 δ:
      raw_command / args 由参数给(R1 字面严守)
      R_in / R_out 由 inputs / outputs 参数给(否则空集)
      is_attack = False(δ 是 attacker 加的,不属 A_0)
    状态转移:
      V_C ← V_C ∪ {δ}
      E_seq ← (E_seq \\ {(c_prev, c_next)}) ∪ {(c_prev, δ), (δ, c_next)}
      E_res ← refresh(δ)
      E_spawn ← E_spawn ∪ {(spawn_parent, δ)} if 给定
    """
    if not precondition_add(G, edge):
        raise OperatorError(f"Add: edge {edge} 不在 E_seq 上")

    new_g = G.clone()
    c_prev, c_next = edge
    delta_id = new_g.add_node(
        raw_command=raw_command,
        args=args,
        inputs=inputs,
        outputs=outputs,
        is_attack=False,
    )
    # 替换 E_seq 边
    new_g.e_seq.remove((c_prev, c_next))
    new_g.e_seq.append((c_prev, delta_id))
    new_g.e_seq.append((delta_id, c_next))
    # 更新 E_res(只对 δ 增量)
    new_g.refresh_e_res_for(delta_id)
    # E_spawn
    if spawn_parent is not None and spawn_parent in new_g.nodes:
        new_g.e_spawn.add((spawn_parent, delta_id))
    return new_g


# ---------- Rewrite ----------

def precondition_rewrite(
    G: CommandGraph,
    node_id: int,
    new_args: List[str],
    new_inputs: Optional[Set[str]] = None,
    new_outputs: Optional[Set[str]] = None,
) -> bool:
    """Rewrite 前置条件:
      (1) node_id ∈ V_C 且非 A_0(R1 不可动攻击命令)
      (2) 新 args 至少使 R(δ) 跟某条 existing 命令的资源集相交(论文要求 — 否则不是 Add Edge 语义)
    """
    if node_id not in G.nodes:
        return False
    if G.nodes[node_id].is_attack:
        return False
    new_in = new_inputs or set()
    new_out = new_outputs or set()
    new_resources = new_in | new_out
    if not new_resources:
        return False
    for other_id, other in G.nodes.items():
        if other_id == node_id:
            continue
        if new_resources & other.resources:
            return True
    return False


def apply_rewrite(
    G: CommandGraph,
    node_id: int,
    new_args: List[str],
    new_inputs: Optional[Set[str]] = None,
    new_outputs: Optional[Set[str]] = None,
    new_raw_command: Optional[str] = None,
) -> CommandGraph:
    """Rewrite(δ, args'):改 δ.args + R_in/R_out,只动 E_res。V_C / E_seq / E_spawn 不变。"""
    if not precondition_rewrite(G, node_id, new_args, new_inputs, new_outputs):
        raise OperatorError(f"Rewrite: 前置条件不满足 node_id={node_id}")
    new_g = G.clone()
    node = new_g.nodes[node_id]
    node.args = list(new_args)
    if new_inputs is not None:
        node.inputs = set(new_inputs)
    if new_outputs is not None:
        node.outputs = set(new_outputs)
    if new_raw_command is not None:
        node.raw_command = new_raw_command
    new_g.refresh_e_res_for(node_id)
    return new_g


# ---------- Move ----------

def precondition_move(
    G: CommandGraph,
    node_id: int,
    new_edge: Tuple[int, int],
) -> bool:
    """Move 前置条件:
      (1) node_id ∈ V_C 且非 A_0(R1)
      (2) new_edge ∈ E_seq 且 ≠ δ 当前的入 / 出 E_seq 边
      (3) δ 的新位置必须使 E_seq chain 仍 respect partial order(R2)
    """
    if node_id not in G.nodes:
        return False
    if G.nodes[node_id].is_attack:
        return False
    edge = tuple(new_edge)
    if edge not in G.e_seq:
        return False
    pred = G.predecessor(node_id)
    succ = G.successor(node_id)
    if edge == (pred, node_id) or edge == (node_id, succ):
        return False
    # 试 apply,检查 partial order
    try:
        tentative = _move_inplace(G.clone(), node_id, edge)
    except OperatorError:
        return False
    return tentative.respects_partial_order()


def apply_move(
    G: CommandGraph,
    node_id: int,
    new_edge: Tuple[int, int],
) -> CommandGraph:
    """Move(δ, e_new):detach δ → 在 e_new=(c_a, c_b) 处 insert。只动 E_seq。"""
    if not precondition_move(G, node_id, new_edge):
        raise OperatorError(f"Move: 前置条件不满足 node_id={node_id} new_edge={new_edge}")
    return _move_inplace(G.clone(), node_id, new_edge)


def _move_inplace(g: CommandGraph, node_id: int, new_edge: Tuple[int, int]) -> CommandGraph:
    """实际 detach + insert,直接 mutate 传入的 g(已是 clone)。"""
    c_a, c_b = new_edge
    pred = g.predecessor(node_id)
    succ = g.successor(node_id)
    # detach
    if pred is not None and (pred, node_id) in g.e_seq:
        g.e_seq.remove((pred, node_id))
    if succ is not None and (node_id, succ) in g.e_seq:
        g.e_seq.remove((node_id, succ))
    if pred is not None and succ is not None:
        g.e_seq.append((pred, succ))
    # insert
    if (c_a, c_b) not in g.e_seq:
        raise OperatorError(f"Move: new_edge {new_edge} 不在 E_seq 上(detach 后)")
    g.e_seq.remove((c_a, c_b))
    g.e_seq.append((c_a, node_id))
    g.e_seq.append((node_id, c_b))
    return g


# ---------- Remove ----------

def precondition_remove(G: CommandGraph, node_id: int) -> bool:
    """Remove 前置条件:
      (1) node_id ∈ V_C 且非 A_0(R1)
      (2) δ 是叶子节点:无下游 dataflow consumer + 无 E_spawn child
    """
    if node_id not in G.nodes:
        return False
    if G.nodes[node_id].is_attack:
        return False
    node = G.nodes[node_id]
    # (i) R_out(δ) ∩ R_in(c) 非空 → δ 是 c 的 producer,删了 c 拿不到输入
    for other_id, other in G.nodes.items():
        if other_id == node_id:
            continue
        if node.outputs & other.inputs:
            return False
    # (ii) (δ, c) ∈ E_spawn → δ 是 c 的 fork-exec parent
    for parent, child in G.e_spawn:
        if parent == node_id:
            return False
    return True


def apply_remove(G: CommandGraph, node_id: int) -> CommandGraph:
    """Remove(δ):删 δ 节点,E_seq chain 自动接回。"""
    if not precondition_remove(G, node_id):
        raise OperatorError(f"Remove: 前置条件不满足 node_id={node_id}")
    new_g = G.clone()
    pred = new_g.predecessor(node_id)
    succ = new_g.successor(node_id)
    new_g.remove_node(node_id)
    # E_seq chain 自动接回
    if pred is not None and succ is not None and (pred, succ) not in new_g.e_seq:
        new_g.e_seq.append((pred, succ))
    return new_g
