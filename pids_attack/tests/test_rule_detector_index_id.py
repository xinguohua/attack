"""Unit tests for rule detector 输出统一 node_index_id (E0 Step 3)。"""
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

PROJ_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJ_ROOT / "detection/data/hybrid_rules"


def _make_sql() -> str:
    return """
CREATE TABLE IF NOT EXISTS subject_node_table (a INT);
CREATE TABLE IF NOT EXISTS file_node_table (a INT);
CREATE TABLE IF NOT EXISTS netflow_node_table (a INT);
CREATE TABLE IF NOT EXISTS event_table (a INT);

INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id)
VALUES ('net-uuid-1', 'hash-net-1', '', '', '127.0.0.1', '3000', 0) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-1', 'hash-subj-1', '/usr/bin/bash', 'bash -c x', 1) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-2', 'hash-subj-2', '/usr/bin/curl', 'curl http://x', 2) ON CONFLICT DO NOTHING;

INSERT INTO file_node_table (node_uuid, hash_id, path, index_id)
VALUES ('file-uuid-1', 'hash-file-1', '/etc/passwd', 3) ON CONFLICT DO NOTHING;
"""


class TestRuleDetectorOutputsIndexId(unittest.TestCase):

    def setUp(self):
        if not (RULES_DIR / "g1_rule.pkl").exists():
            self.skipTest("g1_rule.pkl 不存在,跳过 — 需要先 run scripts/run.py detect train-rules")
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sql", mode="w", delete=False)
        self.tmp.write(_make_sql())
        self.tmp.flush()
        self.sql_path = Path(self.tmp.name)

    def tearDown(self):
        if hasattr(self, "sql_path"):
            self.sql_path.unlink(missing_ok=True)

    def test_g1_emits_node_index_id(self):
        from detection.rules import G1RuleDetector
        det = G1RuleDetector()
        out = det.predict_per_node(str(self.sql_path))
        self.assertGreater(len(out), 0)
        for nd in out:
            self.assertIn("node_index_id", nd)
            self.assertNotIn("node", nd)
        # 2 subject node_index_id ∈ {1, 2}
        idxs = sorted(nd["node_index_id"] for nd in out)
        self.assertEqual(idxs, [1, 2])

    def test_g2_emits_node_index_id(self):
        from detection.rules import G2RuleDetector
        det = G2RuleDetector()
        out = det.predict_per_node(str(self.sql_path))
        self.assertGreater(len(out), 0)
        for nd in out:
            self.assertIn("node_index_id", nd)
            self.assertNotIn("node", nd)

    def test_g1g2_per_node_or_by_index_id(self):
        from detection.rules import G1G2RuleDetector
        det = G1G2RuleDetector()
        out = det.predict_per_node(str(self.sql_path))
        self.assertGreater(len(out), 0)
        for nd in out:
            self.assertIn("node_index_id", nd)
            self.assertNotIn("node", nd)
        # 2 subject node_index_id ∈ {1, 2}
        idxs = sorted(nd["node_index_id"] for nd in out)
        self.assertEqual(idxs, [1, 2])


class TestHybridGNNPerNodeOR(unittest.TestCase):
    """HybridGNN 真 per-node OR 单测 — mock GNN + 真 rule。"""

    def setUp(self):
        if not (RULES_DIR / "g1_rule.pkl").exists():
            self.skipTest("g1_rule.pkl 不存在,跳过")

    def test_hybrid_per_node_or(self):
        # 用 mock 隔离 GNN(避免实际 load 模型)
        gnn_mock_out: List[Dict[str, Any]] = [
            {"node_index_id": 1, "y_pred": 1, "score": 0.9, "label": "subj1"},
            {"node_index_id": 2, "y_pred": 0, "score": 0.1, "label": "subj2"},
            {"node_index_id": 3, "y_pred": 0, "score": 0.2, "label": "file1"},
        ]
        rule_mock_out: List[Dict[str, Any]] = [
            {"node_index_id": 1, "y_pred": 0, "score": 0.0, "raw_command": "bash"},
            {"node_index_id": 2, "y_pred": 1, "score": 1.0, "raw_command": "curl"},
        ]

        from detection import rules as rule_detector
        with patch.object(rule_detector, "_LocalDetector", create=True), \
             patch.object(rule_detector.G1G2RuleDetector, "predict_per_node",
                           return_value=rule_mock_out):
            det = rule_detector.HybridGNNRuleDetector(base_gnn="magic")
            det._base.predict_per_node = lambda _: gnn_mock_out  # type: ignore[attr-defined]
            out = det.predict_per_node("/tmp/fake.sql")

        out_by_idx = {nd["node_index_id"]: nd for nd in out}
        # idx 1: GNN flag → hybrid flag,score = max(0.9, 0.0) = 0.9
        self.assertEqual(out_by_idx[1]["y_pred"], 1)
        self.assertAlmostEqual(out_by_idx[1]["score"], 0.9)
        # idx 2: Rule flag → hybrid flag,score = max(0.1, 1.0) = 1.0
        self.assertEqual(out_by_idx[2]["y_pred"], 1)
        self.assertAlmostEqual(out_by_idx[2]["score"], 1.0)
        # idx 3: 只 GNN 有,Rule 没;y_pred=0,score=0.2
        self.assertEqual(out_by_idx[3]["y_pred"], 0)
        self.assertAlmostEqual(out_by_idx[3]["score"], 0.2)


if __name__ == "__main__":
    unittest.main()
