"""cmd_graph 单测 — 4 算子 + 2 builder + translator。

承 p3 Phase 1 Validation 节"单测必须覆盖"清单:
  - 4 算子 apply on 手搭 G:Add 增节点 + 边 / Rewrite 改 args 不动拓扑 / Move 改边端点 / Remove 删节点 + 关联边
  - 4 算子 precondition:Add 重复节点 = False / Move 目标边不存在 = False / Remove 破坏 partial-order = False
  - `build_g_from_a0` round-trip:`G = build_g_from_a0(json); shell = graph_to_shell(G)`,shell 长度 ≥ scenario.steps 长度
  - `wl_canonical_hash` 占位(Phase 4 真实现):此 phase 接口未在 cmd_graph 中提供,Phase 4 添
"""
import os
import unittest
from pathlib import Path

from cmd_graph.graph import CommandGraph, CommandNode
from cmd_graph.operators import (
    apply_add, precondition_add,
    apply_rewrite, precondition_rewrite,
    apply_move, precondition_move,
    apply_remove, precondition_remove,
    OperatorError,
)
from cmd_graph.builder import build_g_from_a0
from cmd_graph.translator import graph_to_shell


def _build_simple_g(is_attack: bool = False) -> tuple:
    """搭一个简单 G:3 个节点 c0 → c1 → c2,有 E_seq chain。

    Returns (G, [c0_id, c1_id, c2_id])
    """
    g = CommandGraph()
    n0 = g.add_node(raw_command="ls /tmp", args=["/tmp"], inputs={"/tmp"},
                    is_attack=is_attack)
    n1 = g.add_node(raw_command="cat /etc/hostname", args=["/etc/hostname"],
                    inputs={"/etc/hostname"}, is_attack=is_attack)
    n2 = g.add_node(raw_command="echo done", args=["done"],
                    is_attack=is_attack)
    g.e_seq.append((n0, n1))
    g.e_seq.append((n1, n2))
    g.refresh_e_res()
    return g, [n0, n1, n2]


class TestCommandGraph(unittest.TestCase):
    """CommandGraph 数据结构基本性质。"""

    def test_add_node_assigns_unique_ids(self):
        g = CommandGraph()
        n0 = g.add_node(raw_command="ls")
        n1 = g.add_node(raw_command="cat")
        self.assertNotEqual(n0, n1)
        self.assertEqual(len(g.nodes), 2)

    def test_sequence_follows_e_seq(self):
        g, ids = _build_simple_g()
        self.assertEqual(g.sequence(), ids)

    def test_predecessor_successor(self):
        g, ids = _build_simple_g()
        self.assertIsNone(g.predecessor(ids[0]))
        self.assertEqual(g.predecessor(ids[1]), ids[0])
        self.assertEqual(g.successor(ids[1]), ids[2])
        self.assertIsNone(g.successor(ids[2]))

    def test_refresh_e_res_finds_shared_resources(self):
        g = CommandGraph()
        n0 = g.add_node(raw_command="cat /etc/passwd", inputs={"/etc/passwd"})
        n1 = g.add_node(raw_command="grep root /etc/passwd", inputs={"/etc/passwd"})
        n2 = g.add_node(raw_command="echo hi")
        g.refresh_e_res()
        self.assertIn((min(n0, n1), max(n0, n1)), g.e_res)
        self.assertNotIn((min(n0, n2), max(n0, n2)), g.e_res)

    def test_clone_is_deep(self):
        g, _ = _build_simple_g()
        g2 = g.clone()
        # 改 g 不影响 g2
        list(g.nodes.values())[0].args.append("extra")
        self.assertNotEqual(
            list(g.nodes.values())[0].args,
            list(g2.nodes.values())[0].args,
        )

    def test_repr(self):
        g, _ = _build_simple_g()
        r = repr(g)
        self.assertIn("|V|=3", r)


class TestAddOperator(unittest.TestCase):

    def test_add_precondition_pass(self):
        g, ids = _build_simple_g()
        self.assertTrue(precondition_add(g, (ids[0], ids[1])))

    def test_add_precondition_fail_non_existent_edge(self):
        g, ids = _build_simple_g()
        self.assertFalse(precondition_add(g, (ids[0], ids[2])))

    def test_add_inserts_node_and_splits_e_seq(self):
        g, ids = _build_simple_g()
        before_n = len(g.nodes)
        g2 = apply_add(g, "stat /etc/hostname", ["stat", "/etc/hostname"],
                       (ids[0], ids[1]),
                       inputs={"/etc/hostname"})
        # 增 1 个节点
        self.assertEqual(len(g2.nodes), before_n + 1)
        # 原 E_seq 边消失,新边出现
        self.assertNotIn((ids[0], ids[1]), g2.e_seq)
        # 新节点的 id(g.clone() 后 _next_id 保留)
        new_nid = max(g2.nodes.keys())
        self.assertIn((ids[0], new_nid), g2.e_seq)
        self.assertIn((new_nid, ids[1]), g2.e_seq)
        # E_res 自动更新:新节点跟 c_1(`cat /etc/hostname`)共享 /etc/hostname
        self.assertIn((min(new_nid, ids[1]), max(new_nid, ids[1])), g2.e_res)

    def test_add_raises_on_invalid_edge(self):
        g, ids = _build_simple_g()
        with self.assertRaises(OperatorError):
            apply_add(g, "stat", [], (ids[0], ids[2]))


class TestRewriteOperator(unittest.TestCase):

    def test_rewrite_refuses_attack_node(self):
        g, ids = _build_simple_g(is_attack=True)
        self.assertFalse(precondition_rewrite(g, ids[0], ["new_arg"],
                                              new_inputs={"/etc/hostname"}))

    def test_rewrite_requires_resource_overlap_with_existing(self):
        g, ids = _build_simple_g(is_attack=False)
        # 改成完全独立的资源 → 应 reject(论文要求 R(δ) 跟某 existing 相交)
        self.assertFalse(precondition_rewrite(g, ids[0], ["x"],
                                              new_inputs={"/foo/unique/path"}))
        # 改成共用 c_1 的资源 → 通过
        self.assertTrue(precondition_rewrite(g, ids[0], ["new_arg"],
                                             new_inputs={"/etc/hostname"}))

    def test_rewrite_updates_args_and_e_res(self):
        g, ids = _build_simple_g(is_attack=False)
        g2 = apply_rewrite(g, ids[0], ["/etc/hostname"],
                           new_inputs={"/etc/hostname"})
        # args 更新
        self.assertEqual(g2.nodes[ids[0]].args, ["/etc/hostname"])
        # E_seq 不动
        self.assertEqual(g2.e_seq, g.e_seq)
        # E_res 增:ids[0] 现在跟 ids[1] 共享 /etc/hostname
        self.assertIn((min(ids[0], ids[1]), max(ids[0], ids[1])), g2.e_res)


class TestMoveOperator(unittest.TestCase):

    def test_move_refuses_attack_node(self):
        g, ids = _build_simple_g(is_attack=True)
        self.assertFalse(precondition_move(g, ids[1], (ids[0], ids[1])))

    def test_move_refuses_target_not_in_e_seq(self):
        g, ids = _build_simple_g(is_attack=False)
        self.assertFalse(precondition_move(g, ids[1], (ids[0], ids[2])))

    def test_move_refuses_current_edges(self):
        g, ids = _build_simple_g(is_attack=False)
        # 把 ids[1] move 到当前入边 — 没意义,reject
        self.assertFalse(precondition_move(g, ids[1], (ids[0], ids[1])))

    def test_move_changes_e_seq_only(self):
        # 搭 4 节点 chain c0→c1→c2→c3,把 c1 move 到 (c2, c3) 之间
        g = CommandGraph()
        ids = [g.add_node(raw_command=f"c{i}") for i in range(4)]
        for i in range(3):
            g.e_seq.append((ids[i], ids[i + 1]))
        g2 = apply_move(g, ids[1], (ids[2], ids[3]))
        # 新顺序应该是 c0 → c2 → c1 → c3
        seq = g2.sequence()
        self.assertEqual(seq, [ids[0], ids[2], ids[1], ids[3]])


class TestRemoveOperator(unittest.TestCase):

    def test_remove_refuses_attack_node(self):
        g, ids = _build_simple_g(is_attack=True)
        self.assertFalse(precondition_remove(g, ids[1]))

    def test_remove_refuses_node_with_dataflow_consumer(self):
        # δ writes /tmp/x,δ_consumer reads /tmp/x → δ 不可删
        g = CommandGraph()
        n_prod = g.add_node(raw_command="touch /tmp/x", outputs={"/tmp/x"})
        n_cons = g.add_node(raw_command="cat /tmp/x", inputs={"/tmp/x"})
        g.e_seq.append((n_prod, n_cons))
        g.refresh_e_res()
        self.assertFalse(precondition_remove(g, n_prod))
        self.assertTrue(precondition_remove(g, n_cons))   # consumer 可删

    def test_remove_refuses_spawn_parent(self):
        g = CommandGraph()
        n_p = g.add_node(raw_command="bash -c ls")
        n_c = g.add_node(raw_command="ls")
        g.e_seq.append((n_p, n_c))
        g.e_spawn.add((n_p, n_c))
        self.assertFalse(precondition_remove(g, n_p))
        self.assertTrue(precondition_remove(g, n_c))

    def test_remove_drops_node_and_reconnects_e_seq(self):
        g, ids = _build_simple_g(is_attack=False)
        # ids[1] 是叶子节点(无 spawn 关系,outputs 空 → 没人消费)
        g2 = apply_remove(g, ids[1])
        self.assertNotIn(ids[1], g2.nodes)
        # E_seq 接回 c0 → c2
        self.assertIn((ids[0], ids[2]), g2.e_seq)
        self.assertNotIn((ids[0], ids[1]), g2.e_seq)
        self.assertNotIn((ids[1], ids[2]), g2.e_seq)


class TestBuildGFromA0(unittest.TestCase):

    def setUp(self):
        # 找 canonical scenario 目录
        self.scenarios_dir = Path(__file__).resolve().parent.parent / "scenarios" / "juiceshop"
        if not self.scenarios_dir.exists():
            self.skipTest(f"{self.scenarios_dir} 不存在,跳过 builder 测试")

    def test_all_scenarios_build(self):
        """所有 10 个 attack scenario 都能 build_g_from_a0 成功且 |V| ≥ n_steps。"""
        import json
        scenarios = sorted(self.scenarios_dir.glob("*.json"))
        self.assertGreater(len(scenarios), 0)
        for path in scenarios:
            with open(path) as f:
                data = json.load(f)
            n_steps = len(data.get("steps", []))
            g = build_g_from_a0(path)
            self.assertEqual(len(g.nodes), n_steps,
                             f"{path.name}: |V|={len(g.nodes)} 应该 = n_steps={n_steps}")
            self.assertEqual(len(g.e_seq), max(0, n_steps - 1),
                             f"{path.name}: |E_seq|={len(g.e_seq)} 应该 = n_steps-1")
            # 所有节点应该 is_attack
            for n in g.nodes.values():
                self.assertTrue(n.is_attack, f"{path.name}: G_0 节点应全 is_attack=True")

    def test_a0_round_trip_shell_sequence(self):
        """build_g_from_a0 + graph_to_shell:shell 长度 ≥ scenario.steps 长度。"""
        import json
        path = self.scenarios_dir / "01_juiceshop_login_admin_sqli.json"
        if not path.exists():
            self.skipTest("01_juiceshop_login_admin_sqli.json 不存在")
        with open(path) as f:
            data = json.load(f)
        g = build_g_from_a0(path)
        shell = graph_to_shell(g)
        self.assertEqual(len(shell), len(data["steps"]))
        # 每个 step 的 raw_command 应该 byte-identical 复现
        for i, step in enumerate(data["steps"]):
            self.assertEqual(shell[i], step["command"])


class TestTranslator(unittest.TestCase):

    def test_translator_uses_raw_command(self):
        g = CommandGraph()
        g.add_node(raw_command="cat /etc/passwd > /dev/null", args=["/etc/passwd"])
        shell = graph_to_shell(g)
        self.assertEqual(shell, ["cat /etc/passwd > /dev/null"])

    def test_translator_outputs_raw_command_verbatim(self):
        g = CommandGraph()
        g.add_node(raw_command="ls -la /tmp", args=["-la", "/tmp"])
        self.assertEqual(graph_to_shell(g), ["ls -la /tmp"])

    def test_translator_follows_e_seq_order(self):
        g, ids = _build_simple_g()
        shell = graph_to_shell(g)
        self.assertEqual(shell[0], "ls /tmp")
        self.assertEqual(shell[1], "cat /etc/hostname")
        self.assertEqual(shell[2], "echo done")


if __name__ == "__main__":
    unittest.main()
