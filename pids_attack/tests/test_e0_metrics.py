"""Unit tests for E0 attack-signature node-level metrics."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from experiments.E0_detection.gt_signature import (
    TRACE_MODE,
    SIGNATURE_VERSION,
    collect_signature_window_gt_from_sql,
    build_attack_gt_signature,
    normalize_signature_text,
)
from experiments.E0_detection.collector import _parse_step_outputs
from experiments.E0_detection.run import (
    DEFAULT_DETECTORS,
    DETECTORS,
    GNN_REQUIRED_ARTIFACTS,
    RULE_REQUIRED_ARTIFACTS,
    _missing_detector_artifacts,
    assert_detector_artifacts_ready,
    _load_or_collect_attack_signature,
    _sql_node_catalog,
    _write_orthrus_summary,
    compute_metrics,
)


class TestE0NodeMetrics(unittest.TestCase):

    def test_default_detectors_cover_gnn_rule_and_hybrid(self):
        expected = (
            "magic",
            "orthrus",
            "threatrace",
            "g1",
            "g2",
            "g1g2",
            "magic_g1g2",
            "orthrus_g1g2",
            "threatrace_g1g2",
        )
        self.assertEqual(DEFAULT_DETECTORS, expected)
        self.assertEqual(DETECTORS, expected)

    def test_missing_gnn_artifact_fails_fast(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            def best_dir(_detector):
                return root / "empty_best_model"

            missing = _missing_detector_artifacts(
                ["magic"],
                gnn_best_model_dir_fn=best_dir,
            )
            self.assertTrue(any("state_dict.pkl" in item for item in missing))

            with self.assertRaisesRegex(SystemExit, "detect train-gnn"):
                assert_detector_artifacts_ready(
                    ["magic"],
                    gnn_best_model_dir_fn=best_dir,
                )

    def test_missing_rule_artifact_fails_fast(self):
        with tempfile.TemporaryDirectory() as td:
            rule_dir = Path(td) / "hybrid_rules"
            missing = _missing_detector_artifacts(["g1"], rule_dir=rule_dir)

            for filename in RULE_REQUIRED_ARTIFACTS:
                self.assertTrue(any(filename in item for item in missing))

            with self.assertRaisesRegex(SystemExit, "detect train-rules"):
                assert_detector_artifacts_ready(["g1"], rule_dir=rule_dir)

    def test_hybrid_artifacts_require_base_gnn_and_rules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            best = root / "magic_best_model"
            best.mkdir()
            for filename in GNN_REQUIRED_ARTIFACTS["magic"]:
                (best / filename).write_text("ok")

            rule_dir = root / "hybrid_rules"
            rule_dir.mkdir()
            for filename in RULE_REQUIRED_ARTIFACTS:
                (rule_dir / filename).write_text("ok")

            missing = _missing_detector_artifacts(
                ["magic_g1g2"],
                rule_dir=rule_dir,
                gnn_best_model_dir_fn=lambda _detector: best,
            )
            self.assertEqual(missing, [])

    def _write_sql(self) -> Path:
        sql = """
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('s1', 'h1', '/usr/bin/curl', 'curl -s -i http://localhost:3000/', 1) ON CONFLICT DO NOTHING;
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('s2', 'h2', '/usr/bin/curl', 'curl -s -i http://localhost:3000/api/Users', 2) ON CONFLICT DO NOTHING;
INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id) VALUES ('n1', 'h3', '', '', '127.0.0.1', '3000', 3) ON CONFLICT DO NOTHING;
INSERT INTO file_node_table (node_uuid, hash_id, path, index_id) VALUES ('f1', 'h4', '/tmp/out.stdout', 4) ON CONFLICT DO NOTHING;
"""
        f = tempfile.NamedTemporaryFile(suffix=".sql", mode="w", delete=False)
        f.write(sql)
        f.flush()
        return Path(f.name)

    def _write_text(self, text: str) -> Path:
        f = tempfile.NamedTemporaryFile(suffix=".sql", mode="w", delete=False)
        f.write(text)
        f.flush()
        return Path(f.name)

    def test_gt_union_intersection_precision_and_mcc(self):
        sql_path = self._write_sql()
        try:
            catalog = _sql_node_catalog(sql_path)
            gt = {
                "gt_subject_index_ids": [1, 2],
                "gt_file_index_ids": [4],
                "gt_netflow_index_ids": [3],
                "all_node_count": {"total": 4},
            }
            nodes = [
                {"node_index_id": 2, "y_pred": 1, "score": 9.0},
                {"node_index_id": 4, "y_pred": 1, "score": 8.0},
                {"node_index_id": 1, "y_pred": 0, "score": 1.0},
                {"node_index_id": 3, "y_pred": 0, "score": 1.0},
            ]

            metrics, evidence = compute_metrics(nodes, gt, catalog)

            self.assertEqual(metrics["all_nodes_count"], 4)
            self.assertEqual(metrics["flagged_count"], 2)
            self.assertEqual(metrics["gt_count"], 4)
            self.assertEqual(metrics["tp"], 2)
            self.assertEqual(metrics["fp"], 0)
            self.assertEqual(metrics["tn"], 0)
            self.assertEqual(metrics["fn"], 2)
            self.assertEqual(metrics["node_precision"], 1.0)
            self.assertIsNone(metrics["mcc"])
            self.assertEqual(len(evidence["gt_nodes"]), 4)
            self.assertEqual(len(evidence["flagged_nodes"]), 2)
            self.assertEqual(len(evidence["gt_flagged_nodes"]), 2)
            self.assertEqual(len(evidence["gt_missed_nodes"]), 2)
            self.assertEqual(len(evidence["flagged_outside_gt_nodes"]), 0)
            for group in (
                "gt_nodes",
                "flagged_nodes",
                "gt_flagged_nodes",
                "gt_missed_nodes",
            ):
                for record in evidence[group]:
                    self.assertIn("node_index_id", record)
                    self.assertIn("node_type", record)
                    self.assertIn("label", record)
                    self.assertIn("score", record)
                    self.assertIn("y_pred", record)
        finally:
            sql_path.unlink(missing_ok=True)

    def test_flagged_outside_gt_is_kept_for_debugging(self):
        sql_path = self._write_sql()
        try:
            catalog = _sql_node_catalog(sql_path)
            gt = {
                "gt_subject_index_ids": [1],
                "gt_file_index_ids": [],
                "gt_netflow_index_ids": [],
                "all_node_count": {"total": 4},
            }
            nodes = [
                {"node_index_id": 1, "y_pred": 0, "score": 1.0},
                {"node_index_id": 4, "y_pred": 1, "score": 8.0},
            ]

            metrics, evidence = compute_metrics(nodes, gt, catalog)

            self.assertEqual(metrics["flagged_count"], 1)
            self.assertEqual(metrics["gt_count"], 1)
            self.assertEqual(metrics["tp"], 0)
            self.assertEqual(metrics["fp"], 1)
            self.assertEqual(metrics["tn"], 2)
            self.assertEqual(metrics["fn"], 1)
            self.assertEqual(metrics["node_precision"], 0.0)
            self.assertAlmostEqual(metrics["mcc"], -1 / 3)
            self.assertEqual(len(evidence["gt_flagged_nodes"]), 0)
            self.assertEqual(len(evidence["gt_missed_nodes"]), 1)
            self.assertEqual(len(evidence["flagged_outside_gt_nodes"]), 1)
            self.assertEqual(
                evidence["flagged_outside_gt_nodes"][0]["node_index_id"], 4
            )
        finally:
            sql_path.unlink(missing_ok=True)

    def test_orthrus_summary_keeps_scenario_detector_rows(self):
        out = Path(tempfile.NamedTemporaryFile(suffix=".csv", delete=False).name)
        try:
            _write_orthrus_summary(out, [
                {
                    "scenario_id": "s1",
                    "detector": "magic",
                    "tp": 1,
                    "fp": 2,
                    "tn": 30,
                    "fn": 4,
                },
                {
                    "scenario_id": "s2",
                    "detector": "magic",
                    "tp": 5,
                    "fp": 6,
                    "tn": 70,
                    "fn": 8,
                },
            ])
            with out.open() as f:
                rows = list(csv.DictReader(f))
            self.assertEqual([r["Scenario"] for r in rows], ["s1", "s2"])
            self.assertEqual([r["System"] for r in rows], ["magic", "magic"])
            self.assertEqual(rows[0]["TP"], "1")
            self.assertEqual(rows[0]["FP"], "2")
            self.assertEqual(rows[0]["TN"], "30")
            self.assertEqual(rows[0]["FN"], "4")
            self.assertEqual(rows[1]["TP"], "5")
        finally:
            out.unlink(missing_ok=True)

    def test_signature_normalizes_run_id_and_whitespace(self):
        left = "curl   -s   http://localhost:3000/rest/basket/2"
        right = "curl -s http://localhost:3000/rest/basket/2"
        self.assertEqual(
            normalize_signature_text(left),
            normalize_signature_text(right),
        )

    def test_attack_signature_and_marker_window_both_required(self):
        attack_sql = """
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('as1', 'ahs1', '/usr/bin/curl', 'curl -s http://localhost:3000/rest/basket/2', 1) ON CONFLICT DO NOTHING;
INSERT INTO file_node_table (node_uuid, hash_id, path, index_id) VALUES ('af1', 'ahf1', '/usr/bin/curl', 2) ON CONFLICT DO NOTHING;
INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id) VALUES ('an1', 'ahn1', '', '', '127.0.0.1', '3000', 3) ON CONFLICT DO NOTHING;
"""
        mixed_sql = """
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('ms1', 'mhs1', '/usr/bin/curl', 'curl    -s http://localhost:3000/rest/basket/2', 1) ON CONFLICT DO NOTHING;
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('ms2', 'mhs2', '/usr/bin/pgrep', 'pgrep -l bash', 2) ON CONFLICT DO NOTHING;
INSERT INTO file_node_table (node_uuid, hash_id, path, index_id) VALUES ('mf1', 'mhf1', '/usr/bin/curl', 3) ON CONFLICT DO NOTHING;
INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id) VALUES ('mn1', 'mhn1', '', '', '127.0.0.1', '3000', 4) ON CONFLICT DO NOTHING;
INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec) VALUES ('mhs1', 'mhs1', 'EVENT_EXECUTE', 'mhf1', 'mhf1', 'e1', 150);
INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec) VALUES ('mhs2', 'mhs2', 'EVENT_EXECUTE', 'mhf1', 'mhf1', 'e2', 160);
INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec) VALUES ('mhs1', 'mhs1', 'EVENT_CONNECT', 'mhn1', 'mhn1', 'e3', 250);
"""
        attack_path = self._write_text(attack_sql)
        mixed_path = self._write_text(mixed_sql)
        try:
            signature_doc, _nodes_doc = build_attack_gt_signature(attack_path)
            signature_sets = {
                k: set(v) for k, v in signature_doc["signatures"].items()
            }
            gt = collect_signature_window_gt_from_sql(
                sql_path=mixed_path,
                t_begin_ns=100,
                t_end_ns=200,
                signature_sets=signature_sets,
            )

            self.assertEqual(gt["gt_source"], "attack_only_signature_marker_window")
            self.assertEqual(gt["gt_subject_index_ids"], [1])
            self.assertEqual(gt["gt_file_index_ids"], [3])
            self.assertEqual(gt["gt_netflow_index_ids"], [])
            self.assertEqual(gt["gt_window_event_count"], 2)
        finally:
            attack_path.unlink(missing_ok=True)
            mixed_path.unlink(missing_ok=True)

    def test_cached_attack_signature_is_reused(self):
        scenario = {"scenario_id": "s1"}
        signature_doc = {
            "signature_version": SIGNATURE_VERSION,
            "trace_mode": TRACE_MODE,
            "gt_source": "attack_only_signature",
            "scenario_id": "s1",
            "all_steps_passed": True,
            "final_attack_succeeded": True,
            "failed_step": None,
            "signatures": {
                "subject": ["subject|/usr/bin/curl|curl http://localhost:3000"],
                "file": ["file|/usr/bin/curl"],
                "netflow": ["netflow|:->127.0.0.1:3000"],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            attack_only_dir = Path(td) / "attack_only"
            attack_only_dir.mkdir()
            (attack_only_dir / "attack_gt_signature.json").write_text(
                json.dumps(signature_doc)
            )

            attack_only = _load_or_collect_attack_signature(
                scenario,
                attack_only_dir,
                refresh=False,
                reset_container_before=False,
            )

            self.assertTrue(attack_only["reused"])
            self.assertTrue(attack_only["all_steps_passed"])
            self.assertTrue(attack_only["final_attack_succeeded"])
            self.assertEqual(
                attack_only["signature_sets"]["subject"],
                {"subject|/usr/bin/curl|curl http://localhost:3000"},
            )

    def test_unexpected_attack_signature_version_is_rejected(self):
        scenario = {"scenario_id": "s1"}
        signature_doc = {
            "signature_version": 0,
            "gt_source": "attack_only_signature",
            "scenario_id": "s1",
            "all_steps_passed": True,
            "final_attack_succeeded": True,
            "signatures": {"subject": [], "file": [], "netflow": []},
        }
        with tempfile.TemporaryDirectory() as td:
            attack_only_dir = Path(td) / "attack_only"
            attack_only_dir.mkdir()
            (attack_only_dir / "attack_gt_signature.json").write_text(
                json.dumps(signature_doc)
            )

            with self.assertRaisesRegex(RuntimeError, "unexpected attack signature"):
                _load_or_collect_attack_signature(
                    scenario,
                    attack_only_dir,
                    refresh=False,
                    reset_container_before=False,
                )

    def test_step_stdout_markers_split_outputs(self):
        steps = [
            {"step_id": 1, "command": "echo first"},
            {"step_id": 2, "command": "echo second"},
        ]
        stdout = (
            "__E0_STEP_BEGIN__ step=1\n"
            "first output\n"
            "__E0_STEP_END__ step=1 rc=0\n"
            "__E0_STEP_BEGIN__ step=2\n"
            "second output\n"
            "__E0_STEP_END__ step=2 rc=7\n"
        )

        outputs = _parse_step_outputs(stdout, "", steps)

        self.assertEqual(len(outputs), 2)
        self.assertEqual(outputs[0].stdout, "first output\n")
        self.assertEqual(outputs[0].exit_code, 0)
        self.assertEqual(outputs[1].stdout, "second output\n")
        self.assertEqual(outputs[1].exit_code, 7)


if __name__ == "__main__":
    unittest.main()
