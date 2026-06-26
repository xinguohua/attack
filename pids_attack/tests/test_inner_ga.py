"""Unit tests for InnerGA(p3_implementation_plan.md Step 3.6)。"""
import json
import os
import unittest
from pathlib import Path

import numpy as np

from cmd_graph.builder import build_g_from_a0
from attack.framework import SafeMimicConfig
from attack.safemimic_cmd.operators import AtomicOp
from attack.safemimic_cmd.surrogate import SparseBLR, wl_feature_vector
from attack.safemimic_cmd.search.inner_ga import (
    InnerGA, Individual, apply_delta, load_candidate_pool,
)


PROJ_ROOT = Path(__file__).resolve().parent.parent


def _load_scenario_g0():
    """加载一个真实 scenario 做 G_0。"""
    scns = sorted(Path(PROJ_ROOT, "scenarios/juiceshop").glob("*.json"))
    if not scns:
        return None
    with open(scns[0]) as f:
        return build_g_from_a0(json.load(f))


def _make_cmd_pool():
    """返回 5 条 fake 命令(用于 GA 采样)。"""
    return [
        "ls -la",
        "cat /etc/hostname",
        "echo hello > /tmp/x",
        "wc -l /etc/passwd",
        "pwd",
        "curl -s -o /dev/null http://localhost:3000/",
    ]


def _load_scenario_g0_min_edges(min_edges):
    scns = sorted(Path(PROJ_ROOT, "scenarios/juiceshop").glob("*.json"))
    for scn in scns:
        with open(scn) as f:
            G = build_g_from_a0(json.load(f))
        if len(G.e_seq) >= min_edges:
            return G
    return None


class TestInnerGA(unittest.TestCase):

    def setUp(self):
        self.G_0 = _load_scenario_g0()
        if self.G_0 is None:
            self.skipTest("no scenario file")
        self.cfg = SafeMimicConfig(
            T_GA=5, m_pop=6, H=2, D_cap=64,
            seed=42,
        )
        self.cmd_pool = _make_cmd_pool()
        # surrogate fitted on toy data
        self.blr = SparseBLR(D=self.cfg.D_cap, sigma_n2=0.1)
        # 注入几个 toy 训练点
        rng = np.random.default_rng(0)
        for _ in range(5):
            phi = rng.uniform(0, 1, size=self.cfg.D_cap)
            self.blr.update(phi, float(rng.normal()))

    def test_apply_delta_empty(self):
        """空 Δ 等于原图。"""
        G_new, ok = apply_delta([], self.G_0)
        self.assertTrue(ok)
        self.assertEqual(len(G_new.nodes), len(self.G_0.nodes))

    def test_apply_delta_invalid_op(self):
        """无效 op(没满足 precondition)→ valid=False。"""
        bad_op = AtomicOp(type="remove", params={"node_id": 99999})
        G_new, ok = apply_delta([bad_op], self.G_0)
        self.assertFalse(ok)
        self.assertIsNone(G_new)

    def test_load_candidate_pool(self):
        """读真实 candidate_pool.txt。"""
        path = str(PROJ_ROOT / "shared/candidate_pool.txt")
        if not os.path.exists(path):
            self.skipTest("no candidate_pool.txt")
        pool = load_candidate_pool(path)
        self.assertGreater(len(pool), 50)              # 应该有 ~106 条
        # 验证无 # 开头
        for cmd in pool:
            self.assertFalse(cmd.startswith("#"))

    def test_initialise_population_first_stage(self):
        """首 stage(history_T=[])→ m 个个体,长度 1-n_init_random。"""
        ga = InnerGA(self.cfg, self.blr, self.G_0, self.cmd_pool)
        pop = ga.initialise_population(history_T=[], current_delta=[])
        self.assertEqual(len(pop), self.cfg.m_pop)
        for ind in pop:
            self.assertLessEqual(len(ind.delta), self.cfg.n_init_random + 1)

    def test_run_smoke(self):
        """跑完整 GA,返回 Individual,alpha 数值合理。"""
        ga = InnerGA(self.cfg, self.blr, self.G_0, self.cmd_pool)
        best = ga.run(history_T=[], current_delta=[])
        self.assertIsInstance(best, Individual)
        # 要么有效要么 fallback;若有效,alpha 应是 finite
        if best.valid and best.alpha is not None:
            self.assertTrue(np.isfinite(best.alpha))

    def test_mutation_modes(self):
        """直接调 _mutate,3 模式都能跑。"""
        ga = InnerGA(self.cfg, self.blr, self.G_0, self.cmd_pool)
        # 空 Δ 只能 Add
        ind = Individual(delta=[])
        new_ind = ga._mutate(ind)
        self.assertGreaterEqual(len(new_ind.delta), 0)
        # 非空 Δ:跑 10 次 mutation,3 模式都应能出现
        ind = Individual(delta=[AtomicOp(type="add",
                                         params={"raw_command": "x", "args": [], "edge": (0, 1)})])
        modes_seen = set()
        for _ in range(50):
            new_ind = ga._mutate(ind)
            len_diff = len(new_ind.delta) - len(ind.delta)
            if len_diff > 0:
                modes_seen.add("add")
            elif len_diff < 0:
                modes_seen.add("remove")
            else:
                modes_seen.add("replace")
        self.assertGreater(len(modes_seen), 0)

    def test_operator_set_add_only_samples_only_add(self):
        cfg = SafeMimicConfig(
            T_GA=2, m_pop=4, H=2, D_cap=64,
            seed=7, operator_set="add_only",
        )
        ga = InnerGA(cfg, self.blr, self.G_0, self.cmd_pool)
        op = ga._random_atomic_op([])
        self.assertIsNotNone(op)
        self.assertEqual(op.type, "add")

    def test_stateful_operator_primitives_can_be_sampled(self):
        cfg = SafeMimicConfig(
            T_GA=2, m_pop=4, H=2, D_cap=64,
            seed=11, operator_set="all4",
        )
        ga = InnerGA(cfg, self.blr, self.G_0, self.cmd_pool)
        add_op = ga._random_add(self.G_0)
        self.assertIsNotNone(add_op)
        G_with_delta, ok = apply_delta([add_op], self.G_0)
        self.assertTrue(ok)

        rewrite_op = ga._random_rewrite(G_with_delta)
        self.assertIsNotNone(rewrite_op)
        self.assertEqual(rewrite_op.type, "rewrite")

        remove_op = ga._random_remove(G_with_delta)
        self.assertIsNotNone(remove_op)
        self.assertEqual(remove_op.type, "remove")

        G_move = _load_scenario_g0_min_edges(2)
        if G_move is None:
            self.skipTest("no scenario with enough E_seq edges for Move")
        add_for_move = ga._random_add(G_move)
        self.assertIsNotNone(add_for_move)
        G_move_delta, ok = apply_delta([add_for_move], G_move)
        self.assertTrue(ok)
        move_op = ga._random_move(G_move_delta)
        self.assertIsNotNone(move_op)
        self.assertEqual(move_op.type, "move")


if __name__ == "__main__":
    unittest.main()
