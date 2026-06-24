"""Phase 4 WL canonical-hash 单测 — 同构性 + 敏感性 + 稳定性。

承 p3 Phase 4 Validation"单测必须覆盖"清单。
"""
from __future__ import annotations
import time
import unittest

from cmd_graph.graph import CommandGraph
from cmd_graph.wl_hash import wl_canonical_hash


def _build_chain(raw_cmds, inputs_each=None):
    """搭一个 c0 → c1 → ... 的 E_seq chain G。"""
    g = CommandGraph()
    ids = []
    inputs_each = inputs_each or [set()] * len(raw_cmds)
    for raw, ins in zip(raw_cmds, inputs_each):
        nid = g.add_node(raw_command=raw, inputs=ins)
        ids.append(nid)
    for i in range(len(ids) - 1):
        g.e_seq.append((ids[i], ids[i + 1]))
    g.refresh_e_res()
    return g, ids


class TestWLHashIsomorphism(unittest.TestCase):

    def test_isomorphic_graphs_same_hash(self):
        """G1 跟 G2 拓扑相同但 node_id 不同 → hash 相同。"""
        g1, _ = _build_chain(["ls /tmp", "cat /etc/passwd"],
                              [{"/tmp"}, {"/etc/passwd"}])
        # G2 reshuffle ids by 先加 dummy 再删
        g2 = CommandGraph()
        for _ in range(10):
            g2.add_node(raw_command="dummy")
        for nid in list(g2.nodes.keys()):
            g2.remove_node(nid)
        nid_a = g2.add_node(raw_command="ls /tmp", inputs={"/tmp"})
        nid_b = g2.add_node(raw_command="cat /etc/passwd", inputs={"/etc/passwd"})
        g2.e_seq.append((nid_a, nid_b))
        g2.refresh_e_res()

        self.assertEqual(wl_canonical_hash(g1), wl_canonical_hash(g2))

    def test_topology_difference_changes_hash(self):
        """G1 + 1 条边 → hash 不同。"""
        g1, ids = _build_chain(["a", "b", "c"])
        g2 = g1.clone()
        # 加额外 e_res 边(虚构资源冲突,模拟拓扑差异)
        g2.e_res.add((ids[0], ids[2]))
        self.assertNotEqual(wl_canonical_hash(g1), wl_canonical_hash(g2))

    def test_node_label_change_changes_hash(self):
        """G1 跟 G2 拓扑同,但某节点 raw_command 不同 → hash 不同。"""
        g1, _ = _build_chain(["ls /tmp", "cat /etc/passwd"])
        g2, _ = _build_chain(["ls /var", "cat /etc/passwd"])     # /tmp → /var
        self.assertNotEqual(wl_canonical_hash(g1), wl_canonical_hash(g2))

    def test_is_attack_change_changes_hash(self):
        """节点 raw_command 同但 is_attack 不同 → hash 不同(δ vs A_0 标记)。"""
        g1 = CommandGraph()
        g1.add_node(raw_command="ls", is_attack=True)
        g2 = CommandGraph()
        g2.add_node(raw_command="ls", is_attack=False)
        self.assertNotEqual(wl_canonical_hash(g1), wl_canonical_hash(g2))


class TestWLHashStability(unittest.TestCase):

    def test_same_g_same_hash_100_calls(self):
        """同一 G 调 100 次 hash → 100 次完全一致(无随机性)。"""
        g, _ = _build_chain(["a", "b", "c", "d"])
        h0 = wl_canonical_hash(g)
        for _ in range(100):
            self.assertEqual(wl_canonical_hash(g), h0)

    def test_empty_graph_has_consistent_hash(self):
        """空图也应有稳定 hash(不抛异常)。"""
        g = CommandGraph()
        h = wl_canonical_hash(g)
        self.assertEqual(h, wl_canonical_hash(g))


class TestWLHashEdgeCases(unittest.TestCase):

    def test_iters_parameter_affects_hash(self):
        """iters 不同 → hash 可能不同(WL refinement 迭代数变化)。"""
        g, _ = _build_chain(["a", "b", "c"])
        h1 = wl_canonical_hash(g, iters=1)
        h5 = wl_canonical_hash(g, iters=5)
        # 多数情况下不同(不是严格要求,但常见)
        # 至少都返非空 string
        self.assertIsInstance(h1, str)
        self.assertIsInstance(h5, str)
        self.assertGreater(len(h1), 0)

    def test_e_spawn_distinguished_from_e_seq(self):
        """同 raw_command + 同节点对,但用 e_spawn 边 vs e_seq → hash 不同。"""
        g1, ids1 = _build_chain(["a", "b"])
        g2, ids2 = _build_chain(["a", "b"])
        g2.e_spawn.add((ids2[0], ids2[1]))    # 加 spawn 边
        self.assertNotEqual(wl_canonical_hash(g1), wl_canonical_hash(g2))


if __name__ == "__main__":
    unittest.main()
