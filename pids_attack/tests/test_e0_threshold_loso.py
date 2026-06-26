"""Unit tests for E0 threshold LOSO calibration diagnostics."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from detection.diagnostics import (
    _current_threshold,
    _evaluate_threshold_cases,
    _hybrid_merge_summary_rows,
    _loso_threshold_calibration,
    _patch_runtime_threshold_manifest,
    _rewrite_hybrid_rows_from_evidence,
    _runtime_already_matches_calibrated_threshold,
    _scenario_dirs_under,
    _scenario_input_dir,
    _select_best_threshold,
    _select_best_threshold_with_scenario_guard,
    _threshold_orthrus_rows,
)


class TestE0ThresholdLoso(unittest.TestCase):

    def test_current_threshold_forces_lazy_engine_load(self):
        class FakeEngine:
            _threshold = None

            def _ensure_loaded(self):
                self._threshold = 1.5

        class FakeDetector:
            def __init__(self):
                self.engine = FakeEngine()

            def _get_engine(self):
                return self.engine

        class FakeOracle:
            def __init__(self):
                self.det = FakeDetector()

            def _ensure_detector(self):
                return self.det

        self.assertEqual(_current_threshold(FakeOracle(), "threatrace"), 1.5)

    def test_select_best_threshold_uses_training_cases(self):
        cases = [
            {
                "scenario_id": "train",
                "all_ids": {"train:1", "train:2"},
                "gt_ids": {"train:1"},
                "nodes": [
                    {"_global_node_id": "train:1", "score": 9.0},
                    {"_global_node_id": "train:2", "score": 1.0},
                ],
            },
        ]

        best = _select_best_threshold(cases, "score_gt_threshold")

        self.assertIsNotNone(best)
        self.assertEqual(best["tp"], 1)
        self.assertEqual(best["fp"], 0)
        self.assertEqual(best["tn"], 1)
        self.assertEqual(best["fn"], 0)
        self.assertAlmostEqual(best["mcc"], 1.0)

    def test_loso_calibration_aggregates_heldout_metrics(self):
        cases = [
            {
                "scenario_id": "s1",
                "all_ids": {"s1:1", "s1:2"},
                "gt_ids": {"s1:1"},
                "nodes": [
                    {"_global_node_id": "s1:1", "score": 9.0},
                    {"_global_node_id": "s1:2", "score": 1.0},
                ],
            },
            {
                "scenario_id": "s2",
                "all_ids": {"s2:1", "s2:2"},
                "gt_ids": {"s2:1"},
                "nodes": [
                    {"_global_node_id": "s2:1", "score": 8.0},
                    {"_global_node_id": "s2:2", "score": 0.0},
                ],
            },
        ]
        current = {
            "tp": 0,
            "fp": 0,
            "tn": 2,
            "fn": 2,
            "flagged": 0,
            "precision": None,
            "recall": 0.0,
            "mcc": None,
        }

        summary, detail, orth_rows = _loso_threshold_calibration(
            "toy",
            "score_gt_threshold",
            cases,
            current,
            current_threshold=0.0,
        )

        self.assertIsNotNone(summary)
        self.assertEqual(len(detail), 2)
        self.assertEqual(len(orth_rows), 2)
        self.assertEqual(summary["loso_tp"], 2)
        self.assertEqual(summary["loso_fp"], 0)
        self.assertEqual(summary["loso_tn"], 2)
        self.assertEqual(summary["loso_fn"], 0)
        self.assertEqual(summary["loso_flagged"], 2)
        self.assertAlmostEqual(summary["loso_precision"], 1.0)
        self.assertAlmostEqual(summary["loso_recall"], 1.0)
        self.assertAlmostEqual(summary["loso_mcc"], 1.0)
        self.assertEqual(
            {row["System"] for row in orth_rows},
            {"toy_threshold_loso"},
        )

    def test_independent_calibration_threshold_evaluates_test_cases(self):
        calibration_cases = [
            {
                "scenario_id": "calib",
                "all_ids": {"calib:1", "calib:2", "calib:3"},
                "gt_ids": {"calib:1", "calib:2"},
                "nodes": [
                    {"_global_node_id": "calib:1", "score": 9.0},
                    {"_global_node_id": "calib:2", "score": 8.0},
                    {"_global_node_id": "calib:3", "score": 1.0},
                ],
            }
        ]
        test_cases = [
            {
                "scenario_id": "test",
                "all_ids": {"test:1", "test:2", "test:3"},
                "gt_ids": {"test:1"},
                "nodes": [
                    {"_global_node_id": "test:1", "score": 7.0},
                    {"_global_node_id": "test:2", "score": 6.0},
                    {"_global_node_id": "test:3", "score": 0.0},
                ],
            }
        ]

        selected = _select_best_threshold(calibration_cases, "score_gt_threshold")
        self.assertIsNotNone(selected)
        test_metrics = _evaluate_threshold_cases(
            test_cases,
            float(selected["threshold"]),
            "score_gt_threshold",
        )
        orth_rows = _threshold_orthrus_rows(
            detector="toy",
            cases=test_cases,
            threshold=float(selected["threshold"]),
            mode="score_gt_threshold",
            system_suffix="threshold_calibrated",
        )

        self.assertEqual(test_metrics["tp"], 1)
        self.assertEqual(test_metrics["fp"], 1)
        self.assertEqual(test_metrics["tn"], 1)
        self.assertEqual(test_metrics["fn"], 0)
        self.assertEqual(orth_rows[0]["Scenario"], "test")
        self.assertEqual(orth_rows[0]["System"], "toy_threshold_calibrated")

    def test_threshold_guard_rejects_large_scenario_regression(self):
        cases = [
            {
                "scenario_id": "stable",
                "all_ids": {"stable:1", "stable:2"},
                "gt_ids": {"stable:1"},
                "nodes": [
                    {"_global_node_id": "stable:1", "score": 0.50, "y_pred": 1, "correct_pred": 1},
                    {"_global_node_id": "stable:2", "score": 0.90, "y_pred": 0, "correct_pred": 1},
                ],
            },
            {
                "scenario_id": "fragile",
                "all_ids": {"fragile:1", "fragile:2"},
                "gt_ids": {"fragile:1"},
                "nodes": [
                    {"_global_node_id": "fragile:1", "score": 0.56, "y_pred": 1, "correct_pred": 1},
                    {"_global_node_id": "fragile:2", "score": 0.90, "y_pred": 0, "correct_pred": 1},
                ],
            },
        ]

        guarded = _select_best_threshold_with_scenario_guard(
            cases,
            "score_lt_threshold_or_wrong_type",
            max_scenario_mcc_drop=0.02,
        )

        self.assertIsNotNone(guarded)
        self.assertGreaterEqual(float(guarded["threshold"]), 0.56)
        self.assertLessEqual(float(guarded["guard_worst_mcc_drop"]), 0.02)

    def test_threshold_guard_default_keeps_mcc_primary(self):
        nodes = [
            {"_global_node_id": "s:gt_high", "score": 10.0, "y_pred": 0},
            {"_global_node_id": "s:gt_low", "score": 0.7, "y_pred": 0},
            *[
                {"_global_node_id": f"s:fp{i}", "score": 0.8, "y_pred": 0}
                for i in range(5)
            ],
            *[
                {"_global_node_id": f"s:tn{i}", "score": 0.2, "y_pred": 0}
                for i in range(3)
            ],
        ]
        cases = [{
            "scenario_id": "s",
            "all_ids": {nd["_global_node_id"] for nd in nodes},
            "gt_ids": {"s:gt_high", "s:gt_low"},
            "nodes": nodes,
        }]

        strict = _select_best_threshold_with_scenario_guard(
            cases,
            "score_gt_threshold",
        )
        recall_biased = _select_best_threshold_with_scenario_guard(
            cases,
            "score_gt_threshold",
            mcc_tolerance_for_recall_guard=1.0,
        )

        self.assertIsNotNone(strict)
        self.assertIsNotNone(recall_biased)
        self.assertEqual(strict["tp"], 1)
        self.assertEqual(strict["fp"], 0)
        self.assertEqual(strict["fn"], 1)
        self.assertEqual(strict["mcc"], 2 / 3)
        self.assertGreater(recall_biased["recall"], strict["recall"])
        self.assertLess(recall_biased["mcc"], strict["mcc"])

    def test_dependent_hybrid_is_recomputed_from_base_and_rule_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            result_dir = Path(td)
            scenario_dir = result_dir / "scenario_a"
            scenario_dir.mkdir()
            (scenario_dir / "clean.strace.sql").write_text("""
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('s1', 'h1', '/bin/a', 'a', 1) ON CONFLICT DO NOTHING;
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('s2', 'h2', '/bin/b', 'b', 2) ON CONFLICT DO NOTHING;
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('s3', 'h3', '/bin/c', 'c', 3) ON CONFLICT DO NOTHING;
INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) VALUES ('s4', 'h4', '/bin/d', 'd', 4) ON CONFLICT DO NOTHING;
""")
            (scenario_dir / "gt.json").write_text(json.dumps({
                "gt_subject_index_ids": [1, 2],
                "gt_file_index_ids": [],
                "gt_netflow_index_ids": [],
                "all_node_count": {"total": 4},
            }))

            def rec(index_id, y_pred, score):
                return {
                    "node_index_id": index_id,
                    "node_type": "subject",
                    "label": str(index_id),
                    "score": score,
                    "y_pred": y_pred,
                }

            evidence = {
                "magic": {
                    "gt_nodes": [rec(1, 1, 9.0), rec(2, 0, 1.0)],
                    "flagged_nodes": [rec(1, 1, 9.0), rec(3, 1, 8.0)],
                    "gt_flagged_nodes": [rec(1, 1, 9.0)],
                    "gt_missed_nodes": [rec(2, 0, 1.0)],
                    "flagged_outside_gt_nodes": [rec(3, 1, 8.0)],
                },
                "g1": {
                    "gt_nodes": [rec(1, 0, 0.0), rec(2, 1, 4.0)],
                    "flagged_nodes": [rec(2, 1, 4.0)],
                    "gt_flagged_nodes": [rec(2, 1, 4.0)],
                    "gt_missed_nodes": [rec(1, 0, 0.0)],
                    "flagged_outside_gt_nodes": [],
                },
                "g2": {
                    "gt_nodes": [rec(1, 0, 0.0), rec(2, 0, 0.0)],
                    "flagged_nodes": [rec(4, 1, 3.0)],
                    "gt_flagged_nodes": [],
                    "gt_missed_nodes": [rec(1, 0, 0.0), rec(2, 0, 0.0)],
                    "flagged_outside_gt_nodes": [rec(4, 1, 3.0)],
                },
            }
            (scenario_dir / "node_evidence.json").write_text(json.dumps(evidence))

            rows = [
                {
                    "scenario_id": "scenario_a",
                    "detector": detector,
                    "valid": True,
                    "all_steps_passed": True,
                    "final_attack_succeeded": True,
                    "all_nodes_count": 4,
                    "flagged_count": 0,
                    "gt_count": 2,
                    "tp": 0,
                    "fp": 0,
                    "tn": 2,
                    "fn": 2,
                    "node_precision": "",
                    "mcc": "",
                    "wall_sec": 1.0,
                    "failed_step": "",
                    "gt_source": "attack_only_signature_marker_window",
                }
                for detector in ["magic", "g1", "g2", "magic_g1g2"]
            ]
            for path in [result_dir / "summary_all.csv", scenario_dir / "summary.csv"]:
                with open(path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=list(rows[0]))
                    writer.writeheader()
                    writer.writerows(rows)
            (scenario_dir / "detector_results.json").write_text("{}")

            updated = _rewrite_hybrid_rows_from_evidence(
                result_dir=result_dir,
                hybrid_detector="magic_g1g2",
            )

            hybrid = next(r for r in updated if r["detector"] == "magic_g1g2")
            self.assertEqual(hybrid["tp"], 2)
            self.assertEqual(hybrid["fp"], 2)
            self.assertEqual(hybrid["fn"], 0)
            self.assertEqual(hybrid["flagged_count"], 4)
            refreshed = json.loads((scenario_dir / "node_evidence.json").read_text())
            self.assertEqual(len(refreshed["magic_g1g2"]["gt_flagged_nodes"]), 2)
            self.assertEqual(len(refreshed["magic_g1g2"]["flagged_outside_gt_nodes"]), 2)

            merge_rows = _hybrid_merge_summary_rows(
                result_dir=result_dir,
                base_detectors=["magic"],
            )
            base_or_g2 = next(r for r in merge_rows if r["variant"] == "base_or_g2")
            self.assertEqual(base_or_g2["tp"], 1)
            self.assertEqual(base_or_g2["fp"], 2)
            self.assertEqual(base_or_g2["fn"], 1)

    def test_runtime_threshold_patch_updates_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            runtime_dir = Path(td)
            manifest_path = runtime_dir / "manifest.json"
            manifest_path.write_text(json.dumps({
                "detector": "threatrace",
                "threshold": {"method": "threatrace", "threshold": 1.5},
                "e0_metrics": {
                    "tp": 4,
                    "fp": 1,
                    "tn": 9,
                    "fn": 2,
                    "flagged_count": 5,
                },
            }))

            _patch_runtime_threshold_manifest(
                runtime_dir=runtime_dir,
                detector="threatrace",
                threshold=0.75,
                calibration_summary=Path("/tmp/calibration.csv"),
                calibration_orthrus=Path("/tmp/orth.csv"),
            )

            patched = json.loads(manifest_path.read_text())
            self.assertEqual(patched["threshold"]["inference_threshold"], 0.75)
            self.assertEqual(
                patched["threshold"]["calibration_source"]["type"],
                "independent_calibration_split",
            )
            self.assertEqual(
                patched["calibration_applied"]["selected_threshold"],
                0.75,
            )

    def test_runtime_match_reads_manifest_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            runtime_dir = Path(td)
            (runtime_dir / "manifest.json").write_text(json.dumps({
                "detector": "threatrace",
                "threshold": {
                    "method": "threatrace",
                    "threshold": 1.5,
                    "inference_threshold": 0.75,
                },
                "e0_metrics": {
                    "tp": 4,
                    "fp": 1,
                    "tn": 9,
                    "fn": 2,
                    "flagged_count": 5,
                },
            }))

            self.assertTrue(_runtime_already_matches_calibrated_threshold(
                runtime_dir=runtime_dir,
                threshold=0.75,
                calibrated_metrics={
                    "test_calibrated_tp": 4,
                    "test_calibrated_fp": 1,
                    "test_calibrated_tn": 9,
                    "test_calibrated_fn": 2,
                    "test_calibrated_flagged": 5,
                },
            ))

    def test_result_dir_can_use_sibling_test_data_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            result_scenario = root / "results" / "scenario_a"
            input_scenario = root / "test_data" / "scenario_a"
            result_scenario.mkdir(parents=True)
            input_scenario.mkdir(parents=True)
            (input_scenario / "clean.strace.sql").write_text("-- sql")
            (input_scenario / "gt.json").write_text(json.dumps({
                "gt_subject_index_ids": [],
                "gt_file_index_ids": [],
                "gt_netflow_index_ids": [],
            }))

            dirs = _scenario_dirs_under(root / "results", None)

            self.assertEqual(dirs, [result_scenario])
            self.assertEqual(_scenario_input_dir(result_scenario), input_scenario)


if __name__ == "__main__":
    unittest.main()
