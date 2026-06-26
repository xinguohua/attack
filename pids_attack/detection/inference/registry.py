"""Detector artifact registry used by E0 and attack-time inference.

The registry stores one final runnable configuration per detector under:

    detection/artifacts/<detector>/manifest.json

E0 updates these manifests when a detector beats its own previous best. The
attack framework loads detectors through this module instead of reading E0
result directories.
"""
from __future__ import annotations

import json
import math
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_ROOT = PROJECT_ROOT / "detection" / "artifacts"
PIDSMAKER_ARTIFACT_ROOT = PROJECT_ROOT / "detection" / "training" / "artifacts"
DETECTOR_CLASSES = ("gnn", "rule", "hybrid")
GNN_DETECTORS = ("magic", "orthrus", "threatrace")
RULE_DETECTORS = ("g1", "g2", "g1g2")
HYBRID_DETECTORS = ("magic_g1g2", "orthrus_g1g2", "threatrace_g1g2")
HYBRID_BASE_GNN = {
    "magic_g1g2": "magic",
    "orthrus_g1g2": "orthrus",
    "threatrace_g1g2": "threatrace",
}
RULE_COMPONENTS = {
    "g1": ("g1",),
    "g2": ("g2",),
    "g1g2": ("g1", "g2"),
    "magic_g1g2": ("g1", "g2"),
    "orthrus_g1g2": ("g2",),
    "threatrace_g1g2": ("g2",),
}
GNN_REQUIRED_ARTIFACTS = {
    "magic": ("state_dict.pkl", "threshold.pkl", "train_distance.txt"),
    "orthrus": ("state_dict.pkl", "threshold.pkl", "neighbor_loader.pkl"),
    "threatrace": ("state_dict.pkl", "threshold.pkl"),
}


def detector_type(detector: str) -> str:
    if detector in GNN_DETECTORS:
        return "gnn"
    if detector in RULE_DETECTORS:
        return "rule"
    if detector in HYBRID_DETECTORS:
        return "hybrid"
    return "unknown"


def _node_precision(tp: int, fp: int) -> Optional[float]:
    den = tp + fp
    return (tp / den) if den else None


def _mcc(tp: int, fp: int, tn: int, fn: int) -> Optional[float]:
    den = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return ((tp * tn - fp * fn) / math.sqrt(den)) if den else None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def aggregate_detector_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_detector: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        detector = str(row.get("detector", ""))
        if detector:
            by_detector.setdefault(detector, []).append(row)

    out: List[Dict[str, Any]] = []
    for detector, det_rows in by_detector.items():
        tp = sum(int(r.get("tp") or 0) for r in det_rows)
        fp = sum(int(r.get("fp") or 0) for r in det_rows)
        tn = sum(int(r.get("tn") or 0) for r in det_rows)
        fn = sum(int(r.get("fn") or 0) for r in det_rows)
        precision = _node_precision(tp, fp)
        recall = (tp / (tp + fn)) if (tp + fn) else None
        mcc = _mcc(tp, fp, tn, fn)
        per_scenario = []
        for row in sorted(det_rows, key=lambda r: str(r.get("scenario_id", ""))):
            r_tp = int(row.get("tp") or 0)
            r_fp = int(row.get("fp") or 0)
            r_tn = int(row.get("tn") or 0)
            r_fn = int(row.get("fn") or 0)
            per_scenario.append({
                "scenario_id": row.get("scenario_id", ""),
                "mcc": _mcc(r_tp, r_fp, r_tn, r_fn),
                "precision": _node_precision(r_tp, r_fp),
                "recall": (r_tp / (r_tp + r_fn)) if (r_tp + r_fn) else None,
                "tp": r_tp,
                "fp": r_fp,
                "tn": r_tn,
                "fn": r_fn,
                "flagged_count": int(row.get("flagged_count") or 0),
                "gt_count": int(row.get("gt_count") or 0),
                "all_nodes_count": int(row.get("all_nodes_count") or 0),
                "wall_sec": float(row.get("wall_sec") or 0.0),
            })
        scenario_mccs = [
            float(item["mcc"]) for item in per_scenario if item.get("mcc") is not None
        ]
        out.append({
            "detector": detector,
            "detector_type": detector_type(detector),
            "scenario_count": len(det_rows),
            "valid_count": sum(_truthy(r.get("valid")) for r in det_rows),
            "all_steps_passed_count": sum(_truthy(r.get("all_steps_passed")) for r in det_rows),
            "final_attack_succeeded_count": sum(_truthy(r.get("final_attack_succeeded")) for r in det_rows),
            "all_nodes_count": sum(int(r.get("all_nodes_count") or 0) for r in det_rows),
            "flagged_count": sum(int(r.get("flagged_count") or 0) for r in det_rows),
            "gt_count": sum(int(r.get("gt_count") or 0) for r in det_rows),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "mcc": mcc,
            "overall_mcc": mcc,
            "macro_mcc": (
                sum(scenario_mccs) / len(scenario_mccs)
                if scenario_mccs else None
            ),
            "wall_sec": sum(float(r.get("wall_sec") or 0.0) for r in det_rows),
            "per_scenario": per_scenario,
        })
    return out


def _rank(metrics: Dict[str, Any]) -> Tuple[Any, ...]:
    scenario_count = int(metrics.get("scenario_count") or 0)
    return (
        int(metrics.get("valid_count") or 0) == scenario_count,
        int(metrics.get("all_steps_passed_count") or 0) == scenario_count,
        int(metrics.get("final_attack_succeeded_count") or 0) == scenario_count,
        float(metrics.get("overall_mcc") if metrics.get("overall_mcc") is not None else -999.0),
        float(metrics.get("macro_mcc") if metrics.get("macro_mcc") is not None else -999.0),
        float(metrics.get("precision") if metrics.get("precision") is not None else -1.0),
        float(metrics.get("recall") if metrics.get("recall") is not None else -1.0),
        -int(metrics.get("fp") or 0),
        -int(metrics.get("fn") or 0),
        -float(metrics.get("wall_sec") or 0.0),
    )


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _manifest_path(root: Path, detector: str) -> Path:
    return root / detector / "manifest.json"


def _existing_metrics(root: Path, detector: str) -> Optional[Dict[str, Any]]:
    path = _manifest_path(root, detector)
    if not path.exists():
        return None
    try:
        return _read_json(path).get("e0_metrics")
    except Exception:
        return None


def _candidate_is_better(candidate: Dict[str, Any], existing: Optional[Dict[str, Any]]) -> bool:
    if existing is None:
        return True
    return _rank(candidate) > _rank(existing)


def _copy_file(src: Path, dst: Path, kind: str) -> Dict[str, Any]:
    item = {
        "kind": kind,
        "filename": src.name,
        "source_path": str(src),
        "path": str(dst),
        "exists": src.exists(),
    }
    if src.exists() and src.resolve() != dst.resolve():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return item


def _default_gnn_best_model_dir(detector: str) -> Path:
    from detection.training.pidsmaker import _build_args, _get_yml_cfg_safe

    cfg = _get_yml_cfg_safe(_build_args(detector))
    return Path(cfg.training._trained_models_dir) / "best_model"


def _rule_artifact_path(component: str, root: Path) -> Path:
    return root / component / f"{component}_rule.pkl"


def _threshold_doc(detector: str, best_dir: Path, copied: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if detector not in GNN_DETECTORS:
        return None
    path = best_dir / "threshold.pkl"
    doc: Dict[str, Any] = {"path": str(path)}
    local = next((item for item in copied if item["filename"] == "threshold.pkl"), None)
    if local:
        doc["local_path"] = local["path"]
    try:
        import torch

        loaded = torch.load(path, map_location="cpu")
        if isinstance(loaded, dict):
            doc["method"] = loaded.get("method")
            doc["threshold"] = float(loaded.get("threshold"))
        else:
            doc["threshold"] = float(loaded)
    except Exception as exc:
        doc["error"] = f"{type(exc).__name__}: {exc}"
    return doc


def _manifest_doc(
    detector: str,
    metrics: Dict[str, Any],
    *,
    result_dir: Path,
    copied_files: List[Dict[str, Any]],
    pidsmaker_artifact_root: Path,
    gnn_best_model_dir_fn=_default_gnn_best_model_dir,
) -> Dict[str, Any]:
    dtype = detector_type(detector)
    base_gnn = HYBRID_BASE_GNN.get(detector, detector if dtype == "gnn" else None)
    rule_components = list(RULE_COMPONENTS.get(detector, ()))
    best_model_dir = None
    threshold = None
    if base_gnn in GNN_DETECTORS:
        best_model_dir = gnn_best_model_dir_fn(base_gnn)
        threshold = _threshold_doc(base_gnn, best_model_dir, copied_files)
    return {
        "detector": detector,
        "detector_type": dtype,
        "base_gnn": base_gnn,
        "merge_policy": "or" if dtype == "hybrid" or detector == "g1g2" else "single",
        "rule_components": rule_components,
        "pidsmaker_artifact_root": str(pidsmaker_artifact_root),
        "best_model_dir": str(best_model_dir) if best_model_dir else None,
        "files": copied_files,
        "threshold": threshold,
        "postprocess": {
            "policy_version": "e0_controller_artifacts_only_v1",
            "rules": [
                "subject:/tmp/e0_*/{benign.stop,bg.pids}",
                "file:/tmp/e0_*/benign.stop",
            ],
        },
        "e0_metrics": metrics,
        "source_experiment": str(result_dir / "summary_orthrus.csv"),
        "marker_visible_to_detector": False,
        "uses_gt_for_detector_decision": False,
        "created_at": datetime.now().astimezone().isoformat(),
    }


def _inherit_base_threshold_override(
    manifest: Dict[str, Any],
    *,
    artifact_root: Path,
) -> None:
    """Carry calibrated base-GNN threshold overrides into hybrid manifests."""
    if manifest.get("detector_type") != "hybrid":
        return
    base_gnn = manifest.get("base_gnn")
    if base_gnn not in GNN_DETECTORS:
        return
    base_manifest_path = artifact_root / str(base_gnn) / "manifest.json"
    if not base_manifest_path.exists():
        return
    try:
        base_manifest = _read_json(base_manifest_path)
    except Exception:
        return
    base_threshold = base_manifest.get("threshold")
    if not isinstance(base_threshold, dict):
        return
    inference_threshold = base_threshold.get("inference_threshold")
    if inference_threshold is None:
        return
    threshold_doc = manifest.get("threshold")
    if not isinstance(threshold_doc, dict):
        threshold_doc = {}
    threshold_doc["inference_threshold"] = float(inference_threshold)
    if "calibration_source" in base_threshold:
        threshold_doc["calibration_source"] = base_threshold["calibration_source"]
    if "threshold_override_disables_kmeans" in base_threshold:
        threshold_doc["threshold_override_disables_kmeans"] = base_threshold[
            "threshold_override_disables_kmeans"
        ]
    manifest["threshold"] = threshold_doc
    manifest["inherits_base_threshold_override"] = {
        "base_gnn": str(base_gnn),
        "base_manifest": str(base_manifest_path),
    }


def save_detector_artifacts_best(
    rows: List[Dict[str, Any]],
    *,
    result_dir: Path,
    artifact_root: Path = ARTIFACT_ROOT,
    pidsmaker_artifact_root: Path = PIDSMAKER_ARTIFACT_ROOT,
    gnn_best_model_dir_fn=_default_gnn_best_model_dir,
) -> Dict[str, Dict[str, Any]]:
    """Update final detector artifact manifests from an E0 result table."""
    artifact_root.mkdir(parents=True, exist_ok=True)
    written: Dict[str, Dict[str, Any]] = {}
    aggregated = aggregate_detector_rows(rows)

    for metrics in aggregated:
        detector = str(metrics["detector"])
        dtype = str(metrics["detector_type"])
        if dtype not in DETECTOR_CLASSES:
            continue
        target = artifact_root / detector
        existing = _existing_metrics(artifact_root, detector)
        if not _candidate_is_better(metrics, existing):
            written[detector] = {
                "detector": detector,
                "updated": False,
                "path": str(target),
                "existing_overall_mcc": None if existing is None else existing.get("overall_mcc"),
                "candidate_overall_mcc": metrics.get("overall_mcc"),
            }
            continue

        target.mkdir(parents=True, exist_ok=True)
        for stale_name in (
            "config.json",
            "metrics.json",
            "summary_all.csv",
            "summary_orthrus.csv",
            "manifest.json",
        ):
            (target / stale_name).unlink(missing_ok=True)

        copied: List[Dict[str, Any]] = []
        base_gnn = HYBRID_BASE_GNN.get(detector, detector if dtype == "gnn" else None)
        if base_gnn in GNN_DETECTORS:
            best_dir = gnn_best_model_dir_fn(base_gnn)
            for filename in GNN_REQUIRED_ARTIFACTS[base_gnn]:
                kind = "threshold" if filename == "threshold.pkl" else "model"
                copied.append(_copy_file(best_dir / filename, target / filename, kind))
        for component in RULE_COMPONENTS.get(detector, ()):
            path = _rule_artifact_path(component, artifact_root)
            copied.append(_copy_file(path, target / path.name, "rule"))

        manifest = _manifest_doc(
            detector,
            metrics,
            result_dir=result_dir,
            copied_files=copied,
            pidsmaker_artifact_root=pidsmaker_artifact_root,
            gnn_best_model_dir_fn=gnn_best_model_dir_fn,
        )
        _inherit_base_threshold_override(manifest, artifact_root=artifact_root)
        (target / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
        written[detector] = {
            "detector": detector,
            "updated": True,
            "path": str(target),
            "manifest": manifest,
        }

    written["_summary"] = write_artifact_manifest(artifact_root)
    return written


def write_artifact_manifest(artifact_root: Path = ARTIFACT_ROOT) -> Dict[str, Any]:
    manifests: List[Dict[str, Any]] = []
    for path in sorted(artifact_root.glob("*/manifest.json")):
        doc = _read_json(path)
        metrics = doc.get("e0_metrics") or {}
        manifests.append({
            "detector": doc.get("detector"),
            "detector_type": doc.get("detector_type"),
            "artifact_path": str(path.parent),
            "manifest_path": str(path),
            "overall_mcc": metrics.get("overall_mcc"),
            "macro_mcc": metrics.get("macro_mcc"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "tp": metrics.get("tp"),
            "fp": metrics.get("fp"),
            "tn": metrics.get("tn"),
            "fn": metrics.get("fn"),
            "flagged_count": metrics.get("flagged_count"),
            "gt_count": metrics.get("gt_count"),
            "wall_sec": metrics.get("wall_sec"),
            "scenario_count": metrics.get("scenario_count"),
            "valid_count": metrics.get("valid_count"),
            "all_steps_passed_count": metrics.get("all_steps_passed_count"),
            "final_attack_succeeded_count": metrics.get("final_attack_succeeded_count"),
        })
    global_best = max(manifests, key=_rank) if manifests else None
    best_by_class: Dict[str, Any] = {}
    for dtype in DETECTOR_CLASSES:
        candidates = [m for m in manifests if m.get("detector_type") == dtype]
        if candidates:
            best_by_class[dtype] = max(candidates, key=_rank)
    doc = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "selection_policy": (
            "valid/all_steps/final_attack first, then overall MCC, macro MCC, "
            "Precision, Recall, lower FP, lower FN, lower wall time"
        ),
        "global_best": None if global_best is None else global_best["detector"],
        "best_by_class": {
            key: value["detector"] for key, value in best_by_class.items()
        },
        "detectors": manifests,
    }
    (artifact_root / "manifest.json").write_text(json.dumps(doc, indent=2, default=str))
    return doc


def _selector_to_detector(selector: str, artifact_root: Path) -> str:
    selector = selector.strip().lower()
    root_doc = _read_json(artifact_root / "manifest.json") if (artifact_root / "manifest.json").exists() else {}
    if selector == "global_best":
        detector = root_doc.get("global_best")
        if detector:
            return str(detector)
    if selector.startswith("best_by_class."):
        dtype = selector.split(".", 1)[1]
        detector = (root_doc.get("best_by_class") or {}).get(dtype)
        if detector:
            return str(detector)
    if selector in DETECTOR_CLASSES:
        detector = (root_doc.get("best_by_class") or {}).get(selector)
        if detector:
            return str(detector)
    if selector.startswith("detector."):
        return selector.split(".", 1)[1]
    return selector


def load_e0_runtime(
    selector: str = "global_best",
    root: Path = ARTIFACT_ROOT,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    detector = _selector_to_detector(selector, root)
    manifest_path = _manifest_path(root, detector)
    if not manifest_path.exists():
        raise FileNotFoundError(f"detector artifact manifest not found: {manifest_path}")
    manifest = _read_json(manifest_path)
    if manifest.get("detector") != detector:
        raise RuntimeError(f"detector mismatch in {manifest_path}")
    if manifest.get("detector_type") not in DETECTOR_CLASSES:
        raise RuntimeError(f"detector_type missing or invalid in {manifest_path}")
    for item in manifest.get("files", []):
        path = Path(item.get("path", ""))
        if not path.exists():
            raise FileNotFoundError(f"missing detector artifact: {path}")
    return manifest, manifest.get("e0_metrics") or {}


def _artifact_path(config: Dict[str, Any], filename: str) -> str | None:
    for item in config.get("files", []):
        if item.get("filename") == filename:
            return item.get("path")
    return None


def _model_artifact_dir(config: Dict[str, Any]) -> str | None:
    state_dict = _artifact_path(config, "state_dict.pkl")
    return None if state_dict is None else str(Path(state_dict).parent)


def _threshold_override(config: Dict[str, Any]) -> float | None:
    threshold = config.get("threshold")
    if not isinstance(threshold, dict):
        return None
    value = threshold.get("inference_threshold")
    return None if value is None else float(value)


class E0RuntimeOracle:
    """Manifest-backed oracle with the subset of PIDSOracle API used by attacks."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.detector_name = str(config["detector"])
        self.detector_type = str(config["detector_type"])
        self._detector = None

    def _ensure_detector(self):
        if self._detector is not None:
            return self._detector
        if self.detector_type == "gnn":
            from detection.training.pidsmaker import _LocalDetector

            self._detector = _LocalDetector(
                detector_name=self.detector_name,
                model_path=_model_artifact_dir(self.config),
                artifact_dir=self.config.get("pidsmaker_artifact_root"),
                threshold_override=_threshold_override(self.config),
                suppress_system_resource_alerts_enabled=True,
            )
        elif self.detector_type == "rule":
            from detection.training.rules import G1RuleDetector, G2RuleDetector, G1G2RuleDetector

            g1 = _artifact_path(self.config, "g1_rule.pkl")
            g2 = _artifact_path(self.config, "g2_rule.pkl")
            if self.detector_name == "g1":
                self._detector = G1RuleDetector(rule_path=g1)
            elif self.detector_name == "g2":
                self._detector = G2RuleDetector(rule_path=g2)
            elif self.detector_name == "g1g2":
                self._detector = G1G2RuleDetector(
                    g1_rule_path=g1,
                    g2_rule_path=g2,
                    components=self.config.get("rule_components"),
                )
            else:
                raise ValueError(f"unknown rule detector {self.detector_name}")
        elif self.detector_type == "hybrid":
            from detection.training.rules import HybridGNNRuleDetector

            self._detector = HybridGNNRuleDetector(
                base_gnn=self.config.get("base_gnn") or self.detector_name.removesuffix("_g1g2"),
                g1_rule_path=_artifact_path(self.config, "g1_rule.pkl"),
                g2_rule_path=_artifact_path(self.config, "g2_rule.pkl"),
                gnn_model_path=_model_artifact_dir(self.config),
                gnn_artifact_dir=self.config.get("pidsmaker_artifact_root"),
                gnn_threshold_override=_threshold_override(self.config),
                gnn_suppress_system_resource_alerts_enabled=True,
                rule_components=self.config.get("rule_components"),
            )
        else:
            raise ValueError(f"unknown detector_type {self.detector_type}")
        return self._detector

    def predict(self, sql_path: str) -> int:
        return int(self._ensure_detector().predict(sql_path))

    def predict_per_node_from_sql(self, sql_path: str):
        return self._ensure_detector().predict_per_node(sql_path)


def load_e0_oracle(selector: str = "global_best", root: Path = ARTIFACT_ROOT) -> E0RuntimeOracle:
    config, _metrics = load_e0_runtime(selector, root)
    return E0RuntimeOracle(config)
