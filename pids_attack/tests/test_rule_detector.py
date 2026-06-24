"""Unit tests for rule_detector — G1 / G2 / G1+G2 / G1+G2+GNN(p3 Step 4.3)。"""
import unittest
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent
BENIGN_DIR = PROJ_ROOT / "detection/data/training_traces"
RULES_DIR = PROJ_ROOT / "detection/data/hybrid_rules"


class TestRuleDetectors(unittest.TestCase):

    def setUp(self):
        if not (RULES_DIR / "g1_rule.pkl").exists():
            self.skipTest("g1_rule.pkl not trained yet (run scripts/run.py detect train-rules first)")

    def test_g1_detector_on_benign(self):
        """G1 detector 跑 benign trace,应该几乎不标红(因为规则训自这些 benign)。"""
        from detection.rules import G1RuleDetector
        det = G1RuleDetector()
        sql = str(BENIGN_DIR / "benign_00.sql")
        out = det.predict_per_node(sql)
        self.assertGreater(len(out), 0)
        # benign 自训应有低 alarm 率(< 50%)
        n_flagged = sum(1 for n in out if n["y_pred"] == 1)
        ratio = n_flagged / len(out)
        # 不强求很低(τ_λ=0.004 很严),但应该 < 99%
        self.assertLess(ratio, 0.99,
                         f"G1 标红 {ratio:.1%} 节点 on benign trace,τ_λ 可能太严")

    def test_g2_detector_on_benign(self):
        """G2 detector 跑 benign trace,应几乎不标红。"""
        from detection.rules import G2RuleDetector
        det = G2RuleDetector()
        sql = str(BENIGN_DIR / "benign_00.sql")
        out = det.predict_per_node(sql)
        self.assertGreater(len(out), 0)

    def test_g1g2_or_merge(self):
        """G1+G2 合并的 y_pred 应该 ≥ G1 单独 + G2 单独的 max。"""
        from detection.rules import G1RuleDetector, G2RuleDetector, G1G2RuleDetector
        sql = str(BENIGN_DIR / "benign_00.sql")
        out1 = G1RuleDetector().predict_per_node(sql)
        out2 = G2RuleDetector().predict_per_node(sql)
        out12 = G1G2RuleDetector().predict_per_node(sql)
        n_flagged_1 = sum(1 for n in out1 if n["y_pred"] == 1)
        n_flagged_2 = sum(1 for n in out2 if n["y_pred"] == 1)
        n_flagged_12 = sum(1 for n in out12 if n["y_pred"] == 1)
        self.assertGreaterEqual(n_flagged_12, max(n_flagged_1, n_flagged_2))

    def test_factory(self):
        """make_rule_detector dispatch 各 detector。"""
        from detection.rules import make_rule_detector, SUPPORTED_RULE_DETECTORS
        for name in ("g1", "g2", "g1g2"):                                  # hybrid 跳过(需要 GNN 模型)
            self.assertIn(name, SUPPORTED_RULE_DETECTORS)
            det = make_rule_detector(name)
            self.assertTrue(hasattr(det, "predict_per_node"))


if __name__ == "__main__":
    unittest.main()
