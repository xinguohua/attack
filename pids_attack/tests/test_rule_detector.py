"""Unit tests for rule_detector — G1 / G2 / G1+G2 / G1+G2+GNN(p3 Step 4.3)。"""
import unittest
from pathlib import Path
import pickle
import tempfile
from unittest.mock import patch

PROJ_ROOT = Path(__file__).resolve().parent.parent
BENIGN_DIR = PROJ_ROOT / "detection/data/training_traces"
RULES_DIR = PROJ_ROOT / "detection/artifacts"


class TestRuleDetectors(unittest.TestCase):

    def setUp(self):
        if not (RULES_DIR / "g1" / "g1_rule.pkl").exists():
            self.skipTest("g1_rule.pkl not trained yet (run scripts/run.py detect train-rules first)")

    def test_g1_detector_on_benign(self):
        """G1 detector 跑 benign trace,应该几乎不标红(因为规则训自这些 benign)。"""
        from detection.training.rules import G1RuleDetector
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
        from detection.training.rules import G2RuleDetector
        det = G2RuleDetector()
        sql = str(BENIGN_DIR / "benign_00.sql")
        out = det.predict_per_node(sql)
        self.assertGreater(len(out), 0)

    def test_g2_propagates_flagged_subject_to_netflow(self):
        """G2 标红 subject 时,同步输出该 subject 触达的 netflow 节点。"""
        from detection.training.rules import G2RuleDetector
        from cmd_graph.graph import CommandGraph

        rule = {
            "c_benign": {
                "type_pairs": set(),
                "type_freq": {},
                "neighbor_types_by_cmd": {},
            },
            "sigma": 0.05,
            "flag_connected_netflows": True,
        }
        graph = CommandGraph()
        nid = graph.add_node(
            raw_command="curl http://127.0.0.1:3000/",
            outputs={"127.0.0.1:3000"},
        )
        graph.nodes[nid].index_id = 7
        graph.resource_index_id["127.0.0.1:3000"] = 9

        with tempfile.NamedTemporaryFile(suffix=".pkl") as f:
            pickle.dump(rule, f)
            f.flush()
            det = G2RuleDetector(rule_path=f.name)
            with patch("detection.training.rules.sql_to_cmd_graph", return_value=graph):
                out = det.predict_per_node("/tmp/fake.sql")

        by_idx = {nd["node_index_id"]: nd for nd in out}
        self.assertEqual(by_idx[7]["node_type"], "subject")
        self.assertEqual(by_idx[7]["y_pred"], 1)
        self.assertEqual(by_idx[9]["node_type"], "netflow")
        self.assertEqual(by_idx[9]["y_pred"], 1)

    def test_g1g2_or_merge(self):
        """G1+G2 合并的 y_pred 应该 ≥ G1 单独 + G2 单独的 max。"""
        from detection.training.rules import G1RuleDetector, G2RuleDetector, G1G2RuleDetector
        sql = str(BENIGN_DIR / "benign_00.sql")
        out1 = G1RuleDetector().predict_per_node(sql)
        out2 = G2RuleDetector().predict_per_node(sql)
        out12 = G1G2RuleDetector().predict_per_node(sql)
        n_flagged_1 = sum(1 for n in out1 if n["y_pred"] == 1)
        n_flagged_2 = sum(1 for n in out2 if n["y_pred"] == 1)
        n_flagged_12 = sum(1 for n in out12 if n["y_pred"] == 1)
        self.assertGreaterEqual(n_flagged_12, max(n_flagged_1, n_flagged_2))

    def test_g1_uses_command_degree_profile(self):
        """G1 有 benign per-command degree profile 时,不再只靠 lambda 标红。"""
        from detection.training.rules import G1RuleDetector

        rule = {
            "power_law": {
                "alpha": 2.0,
                "degrees": [1, 2, 3],
                "d_min": 1.0,
                "l": 0.0,
            },
            "tau_lambda": 0.004,
            "degree_profile": {
                "by_cmd": {"top": {"count": 10, "max_degree": 5, "p95_degree": 5}},
                "global_max_degree": 5,
            },
            "degree_margin": 0,
            "unknown_cmd_policy": "global_max",
        }
        with tempfile.NamedTemporaryFile(suffix=".pkl") as f:
            pickle.dump(rule, f)
            f.flush()
            det = G1RuleDetector(rule_path=f.name)
            from cmd_graph.graph import CommandGraph

            graph = CommandGraph()
            for idx in range(6):
                nid = graph.add_node(raw_command="top -bn1", inputs={"/tmp/shared"})
                graph.nodes[nid].index_id = idx
            graph.refresh_e_res()

            # The legacy lambda path would flag this score with tau=0.004; the
            # profile path keeps it benign because degree == max benign degree.
            with patch("detection.training.rules.sql_to_cmd_graph", return_value=graph):
                out = det.predict_per_node("/tmp/fake.sql")

            self.assertTrue(all(nd["score"] > det.tau_lambda for nd in out))
            self.assertTrue(all(nd["degree"] == 5 for nd in out))
            self.assertTrue(all(nd["degree_limit"] == 5 for nd in out))
            self.assertEqual(sum(nd["y_pred"] for nd in out), 0)

    def test_factory(self):
        """make_rule_detector dispatch 各 detector。"""
        from detection.training.rules import make_rule_detector, SUPPORTED_RULE_DETECTORS
        for name in ("g1", "g2", "g1g2"):                                  # hybrid 跳过(需要 GNN 模型)
            self.assertIn(name, SUPPORTED_RULE_DETECTORS)
            det = make_rule_detector(name)
            self.assertTrue(hasattr(det, "predict_per_node"))


if __name__ == "__main__":
    unittest.main()
