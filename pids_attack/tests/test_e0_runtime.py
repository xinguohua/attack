"""Tests for loading final detector artifacts from detection/artifacts."""
import json
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from detection.inference.registry import (
    load_e0_oracle,
    load_e0_runtime,
    write_artifact_manifest,
)


class TestE0RuntimeLoader(unittest.TestCase):
    def _write_artifact(
        self,
        root: Path,
        detector_type: str,
        detector: str,
        mcc: float,
        *,
        files=None,
        threshold=None,
        base_gnn=None,
        rule_components=None,
    ) -> Path:
        runtime = root / detector
        runtime.mkdir(parents=True)
        file_docs = []
        for filename, payload in files or []:
            path = runtime / filename
            if filename.endswith(".pkl") and isinstance(payload, dict):
                with path.open("wb") as f:
                    pickle.dump(payload, f)
            else:
                path.write_text(str(payload))
            file_docs.append({
                "kind": "rule" if filename.endswith("_rule.pkl") else "model",
                "filename": filename,
                "path": str(path),
                "exists": True,
            })
        manifest = {
            "detector": detector,
            "detector_type": detector_type,
            "base_gnn": base_gnn,
            "merge_policy": "or" if detector_type == "hybrid" else "single",
            "rule_components": list(rule_components or []),
            "pidsmaker_artifact_root": str(root / "_pidsmaker"),
            "files": file_docs,
            "threshold": threshold,
            "postprocess": {"policy_version": "e0_controller_artifacts_only_v1"},
            "e0_metrics": {
                "detector": detector,
                "detector_type": detector_type,
                "scenario_count": 10,
                "valid_count": 10,
                "all_steps_passed_count": 10,
                "final_attack_succeeded_count": 10,
                "overall_mcc": mcc,
                "macro_mcc": mcc,
                "precision": 0.5,
                "recall": 0.5,
                "tp": 1,
                "fp": 1,
                "tn": 1,
                "fn": 1,
                "flagged_count": 2,
                "gt_count": 2,
                "wall_sec": 0.1,
                "per_scenario": [],
            },
        }
        (runtime / "manifest.json").write_text(json.dumps(manifest))
        return runtime

    def test_load_global_class_and_direct_oracle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_artifact(root, "gnn", "threatrace", 0.4, files=[("state_dict.pkl", "x")])
            self._write_artifact(root, "rule", "g2", 0.1, files=[("g2_rule.pkl", {"sigma": 0.05, "c_benign": {}})], rule_components=["g2"])
            self._write_artifact(root, "hybrid", "threatrace_g1g2", 0.5, files=[("g2_rule.pkl", {"sigma": 0.05, "c_benign": {}})], base_gnn="threatrace", rule_components=["g2"])
            write_artifact_manifest(root)

            config, metrics = load_e0_runtime("global_best", root)
            self.assertEqual(config["detector"], "threatrace_g1g2")
            self.assertEqual(metrics["overall_mcc"], 0.5)

            rule_config, _rule_metrics = load_e0_runtime("best_by_class.rule", root)
            self.assertEqual(rule_config["detector"], "g2")

            oracle = load_e0_oracle("hybrid", root)
            self.assertEqual(oracle.detector_name, "threatrace_g1g2")

            direct_oracle = load_e0_oracle("detector.threatrace", root)
            self.assertEqual(direct_oracle.detector_name, "threatrace")

    def test_rule_oracle_loads_configured_rule_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_artifact(
                root,
                "rule",
                "g2",
                0.1,
                files=[("g2_rule.pkl", {"sigma": 0.05, "c_benign": {}})],
                rule_components=["g2"],
            )

            oracle = load_e0_oracle("g2", root)
            detector = oracle._ensure_detector()

            self.assertEqual(detector.__class__.__name__, "G2RuleDetector")
            self.assertEqual(detector.sigma, 0.05)

    def test_gnn_oracle_carries_configured_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = self._write_artifact(
                root,
                "gnn",
                "threatrace",
                0.4,
                files=[("state_dict.pkl", "x")],
                threshold={"inference_threshold": 0.75},
            )

            oracle = load_e0_oracle("threatrace", root)
            detector = oracle._ensure_detector()

            self.assertEqual(detector.detector_name, "threatrace")
            self.assertEqual(detector.model_path, str(runtime))
            self.assertEqual(detector.artifact_dir, str(root / "_pidsmaker"))
            self.assertEqual(detector.threshold_override, 0.75)

    def test_training_threshold_doc_is_not_runtime_override(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_artifact(
                root,
                "gnn",
                "orthrus",
                0.4,
                files=[("state_dict.pkl", "x")],
                threshold={"method": "max_val_loss", "threshold": 1.23},
            )

            oracle = load_e0_oracle("orthrus", root)
            detector = oracle._ensure_detector()

            self.assertIsNone(detector.threshold_override)

    def test_hybrid_oracle_carries_rule_components(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_artifact(
                root,
                "hybrid",
                "threatrace_g1g2",
                0.2,
                files=[
                    ("state_dict.pkl", "x"),
                    ("g2_rule.pkl", {"sigma": 0.05, "c_benign": {}}),
                ],
                base_gnn="threatrace",
                rule_components=["g2"],
                threshold={"inference_threshold": 0.7},
            )

            with patch("detection.training.rules.HybridGNNRuleDetector") as cls:
                oracle = load_e0_oracle("threatrace_g1g2", root)
                oracle._ensure_detector()

            kwargs = cls.call_args.kwargs
            self.assertEqual(kwargs["base_gnn"], "threatrace")
            self.assertEqual(kwargs["rule_components"], ["g2"])
            self.assertEqual(kwargs["gnn_model_path"], str(root / "threatrace_g1g2"))
            self.assertEqual(kwargs["gnn_artifact_dir"], str(root / "_pidsmaker"))
            self.assertEqual(kwargs["gnn_threshold_override"], 0.7)

    def test_rejects_missing_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = self._write_artifact(root, "rule", "g2", 0.1)
            manifest_path = runtime / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"] = [{
                "filename": "g2_rule.pkl",
                "path": str(runtime / "missing.pkl"),
                "exists": False,
            }]
            manifest_path.write_text(json.dumps(manifest))

            with self.assertRaisesRegex(FileNotFoundError, "missing detector artifact"):
                load_e0_runtime("g2", root)


if __name__ == "__main__":
    unittest.main()
