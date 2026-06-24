"""Unit test for GrabnelCMDAttack 主算法(Step 3.7)。

用 mock query_fn 测试整个 BO 循环不调用真 detector。
"""
import json
import unittest
from pathlib import Path
from typing import List

import numpy as np

from attack.framework import AttackScenario, QueryResult
from attack.grabnel_cmd import GrabnelConfig, GrabnelCMDAttack


PROJ_ROOT = Path(__file__).resolve().parent.parent


class MockQueryFn:
    """模拟 detector:前 K 次 query 都返回 flagged,之后随机标 unflagged。"""

    def __init__(self, flip_at: int = 3, seed: int = 0):
        self.flip_at = flip_at
        self.call_count = 0
        self.rng = np.random.default_rng(seed)

    def __call__(self, scenario, full_cmd_seq, G_t=None):
        self.call_count += 1
        n_nodes = max(1, len(full_cmd_seq))
        if self.call_count >= self.flip_at:
            # 全节点 score < τ → 攻击成功
            score_vec = [0.1] * n_nodes
            y = 0
        else:
            # 至少 1 节点超 τ
            score_vec = [0.1] * n_nodes
            score_vec[0] = 0.8                                  # 第一节点标红
            y = 1
        return QueryResult.valid_(y=y, score_vec=score_vec)


class TestGrabnelCMDAttack(unittest.TestCase):

    def setUp(self):
        scns = sorted(Path(PROJ_ROOT, "scenarios/juiceshop").glob("*.json"))
        if not scns:
            self.skipTest("no scenario")
        with open(scns[0]) as f:
            raw = json.load(f)
        self.scenario = AttackScenario(
            scenario_id=raw.get("scenario_id", "test"),
            A0=[s.get("command", "") for s in raw.get("steps", [])],
            raw=raw,
        )

    def test_run_smoke_short(self):
        """跑 B_max=3, T_GA=3, m=4 的短 BO,mock query 第 2 次 evade。"""
        cfg = GrabnelConfig(B_max=3, T_GA=3, m_pop=4, H=2, D_cap=64, seed=42)
        algo = GrabnelCMDAttack(cfg)
        mock = MockQueryFn(flip_at=2, seed=0)
        # 用 fake candidate pool 跑(避免读真文件)
        cand = ["ls", "pwd", "echo hi"]
        result = algo.run(self.scenario, cand, mock)

        self.assertTrue(hasattr(result, "history"))
        self.assertTrue(hasattr(result, "converged"))
        # 应在 ≤ 3 stage 内停(mock 第 2 次成功)
        self.assertLessEqual(result.extra["q_used"], 3)

    def test_no_evade_runs_full_budget(self):
        """flip_at 设很大 → mock 不让攻击成功 → 跑完 B_max stage。"""
        cfg = GrabnelConfig(B_max=3, T_GA=2, m_pop=3, H=2, D_cap=32, seed=1)
        algo = GrabnelCMDAttack(cfg)
        mock = MockQueryFn(flip_at=999, seed=0)                  # 永不停
        cand = ["ls", "pwd"]
        result = algo.run(self.scenario, cand, mock)
        self.assertFalse(result.converged)
        self.assertEqual(result.extra["q_used"], 3)


if __name__ == "__main__":
    unittest.main()
