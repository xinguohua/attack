#!/usr/bin/env python3
"""E0 attack-only-signature + marker-window node-level detection experiment.

For each scenario:
    1. load cached attack_gt_signature.json, or collect it once if missing.
    2. a mixed run executes benign background + real A0 attack and writes
       raw.strace, clean.strace, clean.strace.sql, and gt.json.
    3. gt.json contains mixed marker-window nodes whose normalized signatures
       appear in the attack-only run.
    4. each detector runs on the same mixed clean.strace.sql and returns per-node
       predictions.
    5. metrics compare GT nodes against detector flagged nodes using
       Orthrus-style TP/FP/TN/FN, Precision, Recall, and MCC.

The marker lines are stripped before detector inference. E0 intentionally uses
no scenario keyword GT and no noise filter.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.E0_detection.collect import (
    e0_collect_attack_only_scenario,
    e0_collect_scenario,
)
from experiments.E0_detection.gt import (
    GT_SOURCE,
    SIGNATURE_VERSION,
    TRACE_MODE,
    load_signature_sets,
)
from attack.framework.oracle import PIDSOracle
from experiments.E0_detection.metrics import (
    _gt_sets,
    _mcc,
    _node_precision,
    _sql_node_catalog,
    _write_csv,
    _write_orthrus_summary,
    compute_metrics,
)
from detection.inference.registry import save_detector_artifacts_best


GNN_DETECTORS = ("magic", "orthrus", "threatrace")
RULE_DETECTORS = ("g1", "g2", "g1g2")
HYBRID_DETECTORS = (
    "magic_g1g2",
    "orthrus_g1g2",
    "threatrace_g1g2",
)
DETECTORS = GNN_DETECTORS + RULE_DETECTORS + HYBRID_DETECTORS
DEFAULT_DETECTORS = DETECTORS
DEFAULT_WARMUP_SEC = 10
DEFAULT_COOLDOWN_SEC = 20
SCENARIO_DIR = PROJECT_ROOT / "scenarios" / "juiceshop"
TEST_DATA_DIR = PROJECT_ROOT / "experiments" / "E0_detection" / "test_data"
RESULT_DIR = PROJECT_ROOT / "experiments" / "E0_detection" / "results"
DETECTOR_ARTIFACT_ROOT = PROJECT_ROOT / "detection" / "artifacts"
PIDSMAKER_ARTIFACT_ROOT = PROJECT_ROOT / "detection" / "training" / "artifacts"
RULE_ARTIFACT_DIR = DETECTOR_ARTIFACT_ROOT
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
RULE_REQUIRED_ARTIFACTS = ("g1_rule.pkl", "g2_rule.pkl")
DETECTOR_CLASSES = ("gnn", "rule", "hybrid")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Run E0 attack-only-signature + marker-window node-level detection."
    )
    ap.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="scenario id whitelist (default: all)",
    )
    ap.add_argument(
        "--detectors",
        nargs="*",
        default=list(DEFAULT_DETECTORS),
        help=(
            "detector list (default: magic orthrus threatrace "
            "g1 g2 g1g2 magic_g1g2 orthrus_g1g2 threatrace_g1g2)"
        ),
    )
    ap.add_argument("--warmup-sec", type=int, default=DEFAULT_WARMUP_SEC)
    ap.add_argument("--cooldown-sec", type=int, default=DEFAULT_COOLDOWN_SEC)
    ap.add_argument(
        "--refresh-signature",
        action="store_true",
        help="rebuild attack_only/attack_gt_signature.json before fresh mixed collection",
    )
    ap.add_argument(
        "--output-dir",
        default=str(RESULT_DIR),
        help="E0 result directory (default: experiments/E0_detection/results)",
    )
    ap.add_argument(
        "--test-data-dir",
        default=str(TEST_DATA_DIR),
        help="E0 test data directory (default: experiments/E0_detection/test_data)",
    )
    ap.add_argument(
        "--no-runtime-update",
        action="store_true",
        help="write E0 results only; do not update detection/artifacts manifests",
    )
    return ap.parse_args(argv)


def _resolve_output_dir(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def load_scenarios(whitelist: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    scenarios: List[Dict[str, Any]] = []
    for path in sorted(SCENARIO_DIR.glob("*.json")):
        with open(path) as f:
            scenario = json.load(f)
        if whitelist and scenario.get("scenario_id") not in whitelist:
            continue
        scenario["_path"] = str(path)
        scenarios.append(scenario)
    if not scenarios:
        raise SystemExit(f"[abort] no scenarios match under {SCENARIO_DIR}")
    return scenarios


def _base_gnn_detectors(detectors: Iterable[str]) -> Tuple[str, ...]:
    bases: List[str] = []
    for name in detectors:
        base = name if name in GNN_DETECTORS else HYBRID_BASE_GNN.get(name)
        if base and base not in bases:
            bases.append(base)
    return tuple(bases)


def _needs_rule_artifacts(detectors: Iterable[str]) -> bool:
    return any(name in RULE_DETECTORS or name in HYBRID_DETECTORS for name in detectors)


def _rule_artifact_path(rule_dir: Path, filename: str) -> Path:
    if filename == "g1_rule.pkl":
        return Path(rule_dir) / "g1" / filename
    if filename == "g2_rule.pkl":
        return Path(rule_dir) / "g2" / filename
    return Path(rule_dir) / filename


def _gnn_best_model_dir(detector_name: str) -> Path:
    from detection.training.pidsmaker import PIDSMAKER_DIR, _build_args, _get_yml_cfg_safe

    if PIDSMAKER_DIR not in sys.path:
        sys.path.insert(0, PIDSMAKER_DIR)

    cfg = _get_yml_cfg_safe(_build_args(detector_name))
    return Path(cfg.training._trained_models_dir) / "best_model"


def _missing_detector_artifacts(
    detectors: Iterable[str],
    *,
    rule_dir: Path = RULE_ARTIFACT_DIR,
    gnn_best_model_dir_fn=_gnn_best_model_dir,
) -> List[str]:
    missing: List[str] = []

    for detector in _base_gnn_detectors(detectors):
        best_dir = gnn_best_model_dir_fn(detector)
        for filename in GNN_REQUIRED_ARTIFACTS[detector]:
            path = best_dir / filename
            if not path.exists():
                missing.append(f"{detector}: missing {path}")

    if _needs_rule_artifacts(detectors):
        for filename in RULE_REQUIRED_ARTIFACTS:
            path = _rule_artifact_path(Path(rule_dir), filename)
            if not path.exists():
                missing.append(f"rule: missing {path}")

    return missing


def assert_detector_artifacts_ready(
    detectors: Iterable[str],
    *,
    rule_dir: Path = RULE_ARTIFACT_DIR,
    gnn_best_model_dir_fn=_gnn_best_model_dir,
) -> None:
    detector_list = tuple(detectors)
    missing = _missing_detector_artifacts(
        detector_list,
        rule_dir=rule_dir,
        gnn_best_model_dir_fn=gnn_best_model_dir_fn,
    )
    if not missing:
        return

    lines = ["[abort] E0 detector artifacts are not ready."]
    lines.extend(f"  - {item}" for item in missing)
    if _base_gnn_detectors(detector_list):
        lines.append(
            "Train GNN artifacts first: "
            "PYTHONPATH=pids_attack /opt/anaconda3/envs/mimicattack/bin/python "
            "pids_attack/scripts/run.py detect train-gnn --skip-ingest "
            "-d magic orthrus threatrace"
        )
    if _needs_rule_artifacts(detector_list):
        lines.append(
            "Train rule artifacts first: "
            "PYTHONPATH=pids_attack /opt/anaconda3/envs/mimicattack/bin/python "
            "pids_attack/scripts/run.py detect train-rules"
        )
    raise SystemExit("\n".join(lines))


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def _float_or_none(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _detector_type(detector: str) -> str:
    if detector in GNN_DETECTORS:
        return "gnn"
    if detector in RULE_DETECTORS:
        return "rule"
    if detector in HYBRID_DETECTORS:
        return "hybrid"
    return "unknown"


def _required_rule_files(detector: str) -> Tuple[str, ...]:
    if detector == "g1":
        return ("g1_rule.pkl",)
    if detector == "g2":
        return ("g2_rule.pkl",)
    if detector in RULE_DETECTORS or detector in HYBRID_DETECTORS:
        return RULE_REQUIRED_ARTIFACTS
    return ()


def _per_scenario_metrics(det_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in sorted(det_rows, key=lambda r: str(r.get("scenario_id", ""))):
        tp = int(row.get("tp") or 0)
        fp = int(row.get("fp") or 0)
        tn = int(row.get("tn") or 0)
        fn = int(row.get("fn") or 0)
        precision = _node_precision(tp, fp)
        recall = (tp / (tp + fn)) if (tp + fn) else None
        out.append({
            "scenario_id": row.get("scenario_id", ""),
            "mcc": _mcc(tp, fp, tn, fn),
            "precision": precision,
            "recall": recall,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "flagged_count": int(row.get("flagged_count") or 0),
            "gt_count": int(row.get("gt_count") or 0),
            "all_nodes_count": int(row.get("all_nodes_count") or 0),
            "wall_sec": float(row.get("wall_sec") or 0.0),
        })
    return out


def _aggregate_detector_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

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
        per_scenario = _per_scenario_metrics(det_rows)
        scenario_mccs = [
            float(item["mcc"]) for item in per_scenario if item.get("mcc") is not None
        ]
        macro_mcc = (
            sum(scenario_mccs) / len(scenario_mccs)
            if scenario_mccs else None
        )
        out.append({
            "detector": detector,
            "detector_type": _detector_type(detector),
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
            "macro_mcc": macro_mcc,
            "wall_sec": sum(float(r.get("wall_sec") or 0.0) for r in det_rows),
            "per_scenario": per_scenario,
        })
    return out


def _best_detector_row(
    rows: List[Dict[str, Any]],
    detector_type: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    aggregated = _aggregate_detector_rows(rows)
    if detector_type:
        aggregated = [
            row for row in aggregated
            if row.get("detector_type") == detector_type
        ]
    if not aggregated:
        return None

    def rank(row: Dict[str, Any]) -> Tuple[Any, ...]:
        scenario_count = int(row.get("scenario_count") or 0)
        return (
            int(row.get("valid_count") or 0) == scenario_count,
            int(row.get("all_steps_passed_count") or 0) == scenario_count,
            int(row.get("final_attack_succeeded_count") or 0) == scenario_count,
            float(row.get("overall_mcc") if row.get("overall_mcc") is not None else -999.0),
            float(row.get("precision") if row.get("precision") is not None else -1.0),
            float(row.get("recall") if row.get("recall") is not None else -1.0),
            -int(row.get("fp") or 0),
            -int(row.get("fn") or 0),
        )

    return max(aggregated, key=rank)


def write_detector_best_runtime_bundles(
    rows: List[Dict[str, Any]],
    *,
    result_dir: Path = RESULT_DIR,
    out_root: Path = DETECTOR_ARTIFACT_ROOT,
    gnn_best_model_dir_fn=_gnn_best_model_dir,
    rule_dir: Path = RULE_ARTIFACT_DIR,
) -> Dict[str, Dict[str, Any]]:
    """Compatibility shim for tests; E0 now writes detection/artifacts."""
    return save_detector_artifacts_best(
        rows,
        result_dir=result_dir,
        artifact_root=out_root,
        pidsmaker_artifact_root=PIDSMAKER_ARTIFACT_ROOT,
        gnn_best_model_dir_fn=gnn_best_model_dir_fn,
    )


def write_best_detector_config(
    rows: List[Dict[str, Any]],
    *,
    result_dir: Path = RESULT_DIR,
    out_path: Optional[Path] = None,
    artifact_root: Path = DETECTOR_ARTIFACT_ROOT,
) -> Optional[Dict[str, Any]]:
    """Return the best detector summary without writing E0-local config files."""
    best = _best_detector_row(rows)
    if best is None:
        return None
    doc = {
        "detector": best["detector"],
        "metrics": best,
        "source_experiment": str(result_dir / "summary_orthrus.csv"),
        "artifact_manifest": str(Path(artifact_root) / "manifest.json"),
        "gt_source": GT_SOURCE,
        "marker_visible_to_detector": False,
        "uses_gt_for_detector_decision": False,
    }
    if out_path is not None:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(doc, indent=2, default=str))
    return doc


def _load_current_signature_doc(signature_path: Path, scenario_id: str) -> Dict[str, Any]:
    doc = json.loads(signature_path.read_text())
    if doc.get("gt_source") != "attack_only_signature":
        raise RuntimeError(f"unexpected attack signature source in {signature_path}")
    if doc.get("signature_version") != SIGNATURE_VERSION:
        raise RuntimeError(
            f"unexpected attack signature version in {signature_path}; "
            "rerun with --refresh-signature"
        )
    if doc.get("trace_mode") != TRACE_MODE:
        raise RuntimeError(
            f"unexpected attack signature trace_mode in {signature_path}; "
            "rerun with --refresh-signature"
        )
    if doc.get("scenario_id") and doc.get("scenario_id") != scenario_id:
        raise RuntimeError(
            f"signature scenario mismatch in {signature_path}: "
            f"{doc.get('scenario_id')} != {scenario_id}"
        )
    return doc


def _load_or_collect_attack_signature(
    scenario: Dict[str, Any],
    attack_only_dir: Path,
    refresh: bool,
    reset_container_before: bool,
) -> Dict[str, Any]:
    signature_path = attack_only_dir / "attack_gt_signature.json"
    if signature_path.exists() and not refresh:
        doc = _load_current_signature_doc(signature_path, scenario["scenario_id"])
        all_steps_passed = bool(doc.get("all_steps_passed", True))
        final_attack_succeeded = bool(doc.get("final_attack_succeeded", True))
        print(f"  [attack-only] reuse {signature_path}", flush=True)
        return {
            "signature_path": signature_path,
            "signature_doc": doc,
            "signature_sets": load_signature_sets(signature_path),
            "all_steps_passed": all_steps_passed,
            "final_attack_succeeded": final_attack_succeeded,
            "failed_step": doc.get("failed_step"),
            "reused": True,
        }

    t_attack = time.time()
    attack_only = e0_collect_attack_only_scenario(
        scenario,
        attack_only_dir,
        reset_container_before=reset_container_before,
    )
    print(
        f"  [attack-only] collect {time.time() - t_attack:.1f}s, "
        f"all_steps_passed={attack_only['all_steps_passed']}, "
        f"final_attack_succeeded={attack_only['final_attack_succeeded']}",
        flush=True,
    )
    attack_only["reused"] = False
    return attack_only


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    result_dir = _resolve_output_dir(args.output_dir)
    test_data_dir = _resolve_output_dir(args.test_data_dir)
    detectors: List[str] = list(args.detectors)
    for d in detectors:
        if d not in DETECTORS:
            raise SystemExit(f"[abort] unknown detector {d}; valid={DETECTORS}")
    assert_detector_artifacts_ready(detectors)
    scenarios = load_scenarios(args.scenarios)
    result_dir.mkdir(parents=True, exist_ok=True)
    test_data_dir.mkdir(parents=True, exist_ok=True)

    # Reuse detector objects across scenarios so each model loads once.
    oracle_pool: Dict[str, PIDSOracle] = {name: PIDSOracle(name) for name in detectors}

    summary_all_rows: List[Dict[str, Any]] = []

    for scenario in scenarios:
        sid = scenario["scenario_id"]
        data_scen_dir = test_data_dir / sid
        result_scen_dir = result_dir / sid
        data_scen_dir.mkdir(parents=True, exist_ok=True)
        result_scen_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n=== scenario: {sid} ===", flush=True)

        t0 = time.time()
        try:
            attack_only_dir = data_scen_dir / "attack_only"
            attack_only = _load_or_collect_attack_signature(
                scenario,
                attack_only_dir,
                refresh=args.refresh_signature,
                reset_container_before=True,
            )
            if not (
                attack_only["all_steps_passed"]
                and attack_only["final_attack_succeeded"]
            ):
                raise RuntimeError(
                    f"attack-only failed; failed_step={attack_only.get('failed_step')}"
                )
            artifact = e0_collect_scenario(
                scenario,
                data_scen_dir,
                warmup_sec=args.warmup_sec,
                cooldown_sec=args.cooldown_sec,
                reset_container_before=True,
                attack_gt_signature_sets=attack_only["signature_sets"],
                attack_gt_signature_path=attack_only["signature_path"],
            )
        except Exception as e:
            print(f"[error] collect/load failed for {sid}: {e}", flush=True)
            continue
        wall_collect = time.time() - t0

        gt_source = artifact.get("gt_source", artifact.get("window_source", ""))
        print(
            f"  [collect] {wall_collect:.1f}s, all_steps_passed={artifact['all_steps_passed']}",
            flush=True,
        )
        print(
            f"  [check] final_attack_succeeded={artifact['final_attack_succeeded']}, "
            f"failed_step={artifact.get('failed_step')}, "
            f"server_attached={artifact.get('server_attached')}",
            flush=True,
        )
        print(
            f"  [gt] subject={len(artifact['gt']['gt_subject_index_ids'])}, "
            f"file={len(artifact['gt']['gt_file_index_ids'])}, "
            f"netflow={len(artifact['gt']['gt_netflow_index_ids'])}, "
            f"event_count={artifact['gt'].get('gt_window_event_count')}, "
            f"source={gt_source}",
            flush=True,
        )

        detector_results: Dict[str, Any] = {}
        node_evidence: Dict[str, Any] = {}
        scen_rows: List[Dict[str, Any]] = []
        node_catalog = _sql_node_catalog(Path(artifact["clean_sql"]))
        collection_valid = bool(
            artifact["all_steps_passed"]
            and artifact["final_attack_succeeded"]
            and gt_source == GT_SOURCE
        )

        for det_name in detectors:
            t1 = time.time()
            try:
                flagged = oracle_pool[det_name].predict_per_node_from_sql(
                    str(artifact["clean_sql"])
                )
                detector_valid = True
            except Exception as e:
                print(f"  [error] detector {det_name}: {e}", flush=True)
                flagged = []
                detector_valid = False
            wall_det = time.time() - t1

            metrics, evidence = compute_metrics(flagged, artifact["gt"], node_catalog)
            row = {
                "scenario_id": sid,
                "detector": det_name,
                "valid": bool(collection_valid and detector_valid),
                "all_steps_passed": bool(artifact["all_steps_passed"]),
                "final_attack_succeeded": bool(artifact["final_attack_succeeded"]),
                **metrics,
                "wall_sec": round(wall_det, 3),
                "failed_step": artifact.get("failed_step"),
                "gt_source": gt_source,
            }
            detector_results[det_name] = row
            node_evidence[det_name] = evidence
            scen_rows.append(row)
            summary_all_rows.append(row)
            print(
                f"  [det] {det_name}: flagged={metrics['flagged_count']}, "
                f"precision={metrics['tp']}/{metrics['flagged_count']}"
                f"={metrics['node_precision']}, "
                f"mcc={metrics['mcc']}, "
                f"wall={wall_det:.2f}s",
                flush=True,
            )

        (result_scen_dir / "detector_results.json").write_text(
            json.dumps(detector_results, indent=2, default=str)
        )
        (result_scen_dir / "node_evidence.json").write_text(
            json.dumps(node_evidence, indent=2, default=str)
        )
        _write_csv(result_scen_dir / "summary.csv", scen_rows)

    if not summary_all_rows:
        print(
            "\n=== E0 produced 0 detector rows; keeping existing summaries and "
            "skipping detector artifact update ===",
            flush=True,
        )
        return

    _write_csv(result_dir / "summary_all.csv", summary_all_rows)
    _write_orthrus_summary(result_dir / "summary_orthrus.csv", summary_all_rows)
    artifact_updates: Dict[str, Dict[str, Any]] = {}
    if not args.no_runtime_update:
        artifact_updates = save_detector_artifacts_best(
            summary_all_rows,
            result_dir=result_dir,
        )
    print(
        f"\n=== E0 done: {len(summary_all_rows)} rows -> "
        f"{result_dir / 'summary_all.csv'} ===",
        flush=True,
    )
    updated = [
        item for name, item in artifact_updates.items()
        if name != "_summary" and item.get("updated")
    ]
    skipped = [
        item for name, item in artifact_updates.items()
        if name != "_summary" and not item.get("updated")
    ]
    for item in updated:
        metrics = item["manifest"]["e0_metrics"]
        print(
            f"=== E0 detector artifact updated {item['detector']}: "
            f"overall_MCC={metrics['overall_mcc']} macro_MCC={metrics['macro_mcc']} "
            f"Precision={metrics['precision']} Recall={metrics['recall']} "
            f"-> {item['path']} ===",
            flush=True,
        )
    if skipped:
        names = ", ".join(str(item["detector"]) for item in skipped)
        print(
            f"=== E0 detector artifacts unchanged: {names} ===",
            flush=True,
        )
    summary = artifact_updates.get("_summary", {})
    global_best = summary.get("global_best") if isinstance(summary, dict) else None
    if global_best:
        print(
            f"=== E0 global best: {global_best} "
            f"-> {DETECTOR_ARTIFACT_ROOT / 'manifest.json'} ===",
            flush=True,
        )
    best_by_class = summary.get("best_by_class", {}) if isinstance(summary, dict) else {}
    for detector_type in DETECTOR_CLASSES:
        detector = best_by_class.get(detector_type)
        if not detector:
            continue
        print(
            f"=== E0 class best {detector_type}: {detector} ===",
            flush=True,
        )


if __name__ == "__main__":
    main()
