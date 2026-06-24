"""CommandGraph 数据结构 — 承 1_p1_formulation.md §4.2 形式化。

G = (V_C, E_res, E_spawn, E_seq)
  V_C   节点 = (raw_command, args, inputs, outputs);R(c) = R_in(c) ∪ R_out(c) ⊆ Resources
  E_res  资源依赖(共读 / 共写 / 数据流):(c1, c2) ∈ E_res ⇔ R(c1) ∩ R(c2) ≠ ∅
  E_spawn 派生依赖:(c1, c2) ∈ E_spawn ⇔ c1 fork-exec c2
  E_seq  执行序 chain(每节点入度 / 出度 ≤ 1)

R1(攻击功能保持):V_C^0 ⊆ V_C 标记不可动节点(is_attack=True)
R2(可执行):E_seq chain 必须 respect 由 E_res dataflow + E_spawn 导出的 partial order
"""
from __future__ import annotations
import copy
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple


@dataclass
class CommandNode:
    """V_C 中的单个命令节点。

    属性:
      node_id     图内唯一 id(整数自增)
      raw_command 原始 shell 命令字符串(translator 直接输出,A_0 节点字面严守 R1)
      args        参数 tokens(Rewrite 算子改它);若 raw_command 字面没用到,可空
      inputs      R_in(c):输入资源 ids(file path / host:port)
      outputs     R_out(c):输出资源 ids
      is_attack   True ⇔ ∈ V_C^0(A_0 节点,Move/Rewrite/Remove 不可触,R1)
      index_id    SQL CDM dump 的全局 index_id(仅 detector-side 由 sql_to_cmd_graph 写入);
                  attack-side 构造时永远 None,detector-side 用作跟 SQL flagged 节点对齐
    """
    node_id: int
    raw_command: str
    args: List[str] = field(default_factory=list)
    inputs: Set[str] = field(default_factory=set)
    outputs: Set[str] = field(default_factory=set)
    is_attack: bool = False
    index_id: Optional[int] = None

    @property
    def resources(self) -> Set[str]:
        return self.inputs | self.outputs


@dataclass
class CommandGraph:
    """G = (V_C, E_res, E_spawn, E_seq)。

    内部表示:
      nodes        Dict[node_id, CommandNode]
      e_seq        List[(pred_id, succ_id)] — chain,每节点入 / 出度 ≤ 1
      e_res        Set[(c1_id, c2_id)] — 共享资源(无向,统一存 (min, max))
      e_spawn      Set[(parent_id, child_id)] — 有向

    invariant:
      e_seq 顺序唯一(任意节点至多一个前驱 / 后继)
      e_res 是无向边(存 sorted tuple)
      e_spawn 是有向边
    """
    nodes: Dict[int, CommandNode] = field(default_factory=dict)
    e_seq: List[Tuple[int, int]] = field(default_factory=list)
    e_res: Set[Tuple[int, int]] = field(default_factory=set)
    e_spawn: Set[Tuple[int, int]] = field(default_factory=set)
    # file path / netflow addr → SQL CDM dump 的全局 index_id;
    # 仅 detector-side 由 sql_to_cmd_graph 写入,attack-side 永远空 dict。
    # 用于 rule detector 在判 file/netflow 节点 flag 时拿到 SQL node_index_id。
    resource_index_id: Dict[str, int] = field(default_factory=dict)
    _next_id: int = 0

    # -------- node manipulation --------

    def add_node(
        self,
        raw_command: str,
        args: Optional[List[str]] = None,
        inputs: Optional[Set[str]] = None,
        outputs: Optional[Set[str]] = None,
        is_attack: bool = False,
    ) -> int:
        """加节点。返回 node_id;不维护 E_seq / E_res / E_spawn(算子负责)。"""
        nid = self._next_id
        self._next_id += 1
        self.nodes[nid] = CommandNode(
            node_id=nid,
            raw_command=raw_command,
            args=list(args) if args else [],
            inputs=set(inputs) if inputs else set(),
            outputs=set(outputs) if outputs else set(),
            is_attack=is_attack,
        )
        return nid

    def remove_node(self, node_id: int) -> None:
        """删节点。同步删 E_seq / E_res / E_spawn 上所有关联边。"""
        if node_id not in self.nodes:
            return
        del self.nodes[node_id]
        self.e_seq = [(a, b) for a, b in self.e_seq if a != node_id and b != node_id]
        self.e_res = {(a, b) for a, b in self.e_res if a != node_id and b != node_id}
        self.e_spawn = {(a, b) for a, b in self.e_spawn if a != node_id and b != node_id}

    # -------- E_seq traversal --------

    def sequence(self) -> List[int]:
        """沿 E_seq chain 走出 ordered node id list。无 chain 则按 insertion order。"""
        if not self.e_seq and self.nodes:
            return list(self.nodes.keys())
        # 构正向映射
        succ = {a: b for a, b in self.e_seq}
        pred = {b: a for a, b in self.e_seq}
        # 找 head(没前驱)
        all_nids = set(self.nodes.keys())
        heads = [nid for nid in all_nids if nid not in pred]
        if not heads:
            return list(self.nodes.keys())
        # 假设单 chain
        head = heads[0]
        seq = [head]
        cur = head
        while cur in succ:
            cur = succ[cur]
            seq.append(cur)
        # 加上没在 chain 上的孤立节点
        for nid in self.nodes:
            if nid not in seq:
                seq.append(nid)
        return seq

    def predecessor(self, node_id: int) -> Optional[int]:
        for a, b in self.e_seq:
            if b == node_id:
                return a
        return None

    def successor(self, node_id: int) -> Optional[int]:
        for a, b in self.e_seq:
            if a == node_id:
                return b
        return None

    # -------- E_res refresh --------

    def refresh_e_res(self) -> None:
        """全图重算 E_res — 任两节点共享资源(R 交集非空)就连。"""
        self.e_res.clear()
        nids = list(self.nodes.keys())
        for i in range(len(nids)):
            for j in range(i + 1, len(nids)):
                ci, cj = self.nodes[nids[i]], self.nodes[nids[j]]
                if ci.resources & cj.resources:
                    self.e_res.add((min(nids[i], nids[j]), max(nids[i], nids[j])))

    def refresh_e_res_for(self, node_id: int) -> None:
        """只对指定节点重算 E_res(增量版,Move / Rewrite 用)。"""
        # 删跟该节点相关的现有 e_res
        self.e_res = {(a, b) for a, b in self.e_res if a != node_id and b != node_id}
        if node_id not in self.nodes:
            return
        c = self.nodes[node_id]
        for other_id, other in self.nodes.items():
            if other_id == node_id:
                continue
            if c.resources & other.resources:
                self.e_res.add((min(node_id, other_id), max(node_id, other_id)))

    # -------- partial-order check(R2) --------

    def respects_partial_order(self) -> bool:
        """E_seq chain 是否 respect E_res dataflow + E_spawn 导出的 partial order。

        Phase 1 简化版:
          - E_spawn(parent, child):seq 中 parent 必先于 child
          - E_res dataflow:R_out(c1) ∩ R_in(c2) ≠ ∅ 时 c1 必先于 c2

        E_res 是无向的 — 仅根据 R_in/R_out 方向能识别 dataflow 时才约束。
        """
        seq = self.sequence()
        pos = {nid: i for i, nid in enumerate(seq)}
        # E_spawn 约束
        for parent, child in self.e_spawn:
            if parent in pos and child in pos and pos[parent] >= pos[child]:
                return False
        # E_res dataflow 约束(producer-consumer)
        for nid_a, node_a in self.nodes.items():
            for nid_b, node_b in self.nodes.items():
                if nid_a == nid_b:
                    continue
                if node_a.outputs & node_b.inputs:
                    if pos.get(nid_a, -1) >= pos.get(nid_b, -1):
                        return False
        return True

    # -------- deep copy --------

    def clone(self) -> "CommandGraph":
        """深拷贝。算子语义需要不可变 G,apply 返回 new graph。"""
        new = CommandGraph()
        new.nodes = {nid: copy.deepcopy(n) for nid, n in self.nodes.items()}
        new.e_seq = list(self.e_seq)
        new.e_res = set(self.e_res)
        new.e_spawn = set(self.e_spawn)
        new._next_id = self._next_id
        return new

    # -------- 统计便于调试 --------

    def __repr__(self) -> str:
        return (f"CommandGraph(|V|={len(self.nodes)} "
                f"|E_seq|={len(self.e_seq)} "
                f"|E_res|={len(self.e_res)} "
                f"|E_spawn|={len(self.e_spawn)})")
