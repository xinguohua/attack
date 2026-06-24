"""v6 TODO #5 (C8) — range/checker.py apply_a0_mutation 单测.

验证 mutated_a0 真改 A0 的 command 字段:
- case 1:替换某 step 的 cmd,其他 step 不变
- case 2:断言节点总数等价(checker / step_id / final_check 字段保持)
- case 3:None / 长度不匹配 边界行为
"""
import unittest


class TestApplyA0Mutation(unittest.TestCase):

    def setUp(self):
        # 模拟一个 attack scenario 的 step list
        self.A0_steps = [
            {"step_id": 1, "command": "curl http://localhost:3000/",
             "checker": {"type": "http_ok"}},
            {"step_id": 2, "command": "curl -X POST .../user/login",
             "checker": {"type": "http_ok"}},
            {"step_id": 3, "command": "head -30",
             "checker": {"type": "exit_zero"}},
        ]

    def test_none_returns_a0_unchanged(self):
        """mutated_a0=None → 原样返回(浅拷贝)。"""
        from range.checker import apply_a0_mutation
        result = apply_a0_mutation(self.A0_steps, None)
        self.assertEqual(len(result), 3)
        for orig, ret in zip(self.A0_steps, result):
            self.assertEqual(orig, ret)

    def test_mutation_replaces_command_only(self):
        """mutated_a0 列表 → 各 step 的 command 字段被替换,其他字段不动。"""
        from range.checker import apply_a0_mutation
        mutated = [
            "python3 -c 'pass'",                  # 替 step 1 cmd
            "bash -c 'curl -X POST ...'",         # 替 step 2 cmd(WRAPPER_INJECTION 风格)
            "head -30",                            # 不变
        ]
        result = apply_a0_mutation(self.A0_steps, mutated)
        # 验证 step 数 == baseline(关键:没新增节点)
        self.assertEqual(len(result), len(self.A0_steps))
        # 验证 command 被替换
        self.assertEqual(result[0]["command"], "python3 -c 'pass'")
        self.assertEqual(result[1]["command"], "bash -c 'curl -X POST ...'")
        self.assertEqual(result[2]["command"], "head -30")
        # 验证 checker / step_id 字段保留
        self.assertEqual(result[0]["step_id"], 1)
        self.assertEqual(result[0]["checker"], {"type": "http_ok"})
        self.assertEqual(result[2]["step_id"], 3)
        self.assertEqual(result[2]["checker"], {"type": "exit_zero"})

    def test_step_count_invariant(self):
        """节点总数(step 数)等于 baseline — 这是和 ADD 的关键区别。"""
        from range.checker import apply_a0_mutation
        mutated = ["a", "b", "c"]
        result = apply_a0_mutation(self.A0_steps, mutated)
        self.assertEqual(len(result), 3)  # 没多没少
        # ADD 会在 sequence 里追加 δ 命令 → 节点变多;但 MUTATE 不变

    def test_length_mismatch_raises(self):
        """mutated_a0 长度跟 A0 不匹配 → ValueError(避免静默漏 step)。"""
        from range.checker import apply_a0_mutation
        with self.assertRaises(ValueError) as ctx:
            apply_a0_mutation(self.A0_steps, ["a", "b"])
        self.assertIn("length", str(ctx.exception))

    def test_no_inplace_mutation(self):
        """apply_a0_mutation 不修改原 A0_steps。"""
        from range.checker import apply_a0_mutation
        before = [dict(s) for s in self.A0_steps]
        _ = apply_a0_mutation(self.A0_steps, ["x", "y", "z"])
        self.assertEqual(self.A0_steps, before)  # 原数据保持

    def test_mutation_carries_edge_type_wrapper(self):
        """MUTATE_EDGE_TYPE 风格:cmd 前加 syscall wrapper (setsid / nohup)."""
        from range.checker import apply_a0_mutation
        mutated = [
            "setsid curl http://localhost:3000/",       # edge type 改变(产生 setsid syscall)
            "nohup curl -X POST .../user/login",        # 同上
            "stdbuf -o0 head -30",
        ]
        result = apply_a0_mutation(self.A0_steps, mutated)
        self.assertTrue(result[0]["command"].startswith("setsid"))
        self.assertTrue(result[1]["command"].startswith("nohup"))
        # 节点总数仍 = 3
        self.assertEqual(len(result), 3)


if __name__ == "__main__":
    unittest.main()
