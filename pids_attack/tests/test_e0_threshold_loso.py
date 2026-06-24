"""Unit tests for E0 threshold LOSO calibration diagnostics."""
import unittest

from detection.diagnostics import (
    _loso_threshold_calibration,
    _select_best_threshold,
)


class TestE0ThresholdLoso(unittest.TestCase):

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


if __name__ == "__main__":
    unittest.main()
