#!/usr/bin/env python3
"""训练 + 检测框架诊断入口。

不修改 PIDSMaker 原生代码,只读取当前 artifact / eval pkl / E0 结果。

用途:
  1. 看训练数据是否齐。
  2. 看 GNN / rule detector artifact 是否齐。
  3. 汇总 PIDSMaker 原始 evaluation 指标。
  4. 汇总 E0 mixed-run node-level 检测基线。
  5. 给出下一步调优优先级。

跑法:
  PYTHONPATH=pids_attack /opt/anaconda3/envs/mimicattack/bin/python \
    pids_attack/scripts/diagnostics/detection_pipeline_audit.py
"""
from __future__ import annotations

import csv
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.E0_detection.run import (  # noqa: E402
    DEFAULT_DETECTORS as E0_DETECTORS,
    GNN_DETECTORS,
    HYBRID_DETECTORS,
    RULE_ARTIFACT_DIR,
    RULE_DETECTORS,
    RULE_REQUIRED_ARTIFACTS,
    _gnn_best_model_dir,
)
from detection.training.pidsmaker import compute_metrics, load_eval_pkl  # noqa: E402
from detection.training.pidsmaker import SUPPORTED_DETECTORS  # noqa: E402


TRAINING_TRACE_DIR = PROJECT_ROOT / "detection" / "data" / "training_traces"
E0_RESULT_DIR = PROJECT_ROOT / "experiments" / "E0_detection" / "results"
E0_THRESHOLD_SUMMARY = E0_RESULT_DIR / "threshold_diagnostics" / "threshold_sweep_summary.csv"
E0_THRESHOLD_LOSO_SUMMARY = E0_RESULT_DIR / "threshold_diagnostics" / "threshold_loso_summary.csv"
E0_THRESHOLD_CALIBRATION_SUMMARY = (
    E0_RESULT_DIR
    / "threshold_diagnostics"
    / "calibration_split"
    / "threshold_calibration_summary.csv"
)


def _fmt_float(value: Optional[float], digits: int = 3) -> str:
    if value is None:
        return "-"
    return f"{value:.{digits}f}"


def _csv_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _print_table(headers: List[str], rows: List[List[Any]]) -> None:
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def line(vals: Iterable[Any]) -> str:
        return "  " + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals))

    print(line(headers))
    print("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        print(line(row))


def audit_training_data() -> Dict[str, int]:
    benign_sql = sorted(TRAINING_TRACE_DIR.glob("benign_*.sql"))
    attack_sql = sorted((TRAINING_TRACE_DIR / "attack").glob("*.strace.sql"))
    return {
        "benign_sql": len(benign_sql),
        "attack_sql": len(attack_sql),
    }


def audit_gnn_artifacts() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for detector in SUPPORTED_DETECTORS:
        try:
            best_dir = _gnn_best_model_dir(detector)
        except Exception as exc:
            rows.append({
                "detector": detector,
                "status": "config_error",
                "best_dir": "",
                "missing": [type(exc).__name__],
            })
            continue

        required = ["state_dict.pkl", "threshold.pkl"]
        if detector == "magic":
            required.append("train_distance.txt")
        if detector in {"orthrus", "kairos", "velox"}:
            required.append("neighbor_loader.pkl")

        missing = [name for name in required if not (best_dir / name).exists()]
        rows.append({
            "detector": detector,
            "status": "ready" if not missing else "missing",
            "best_dir": str(best_dir),
            "missing": missing,
        })
    return rows


def audit_rule_artifacts() -> Dict[str, Any]:
    missing = [
        name for name in RULE_REQUIRED_ARTIFACTS
        if not (RULE_ARTIFACT_DIR / name).exists()
    ]
    return {
        "status": "ready" if not missing else "missing",
        "rule_dir": str(RULE_ARTIFACT_DIR),
        "missing": missing,
    }


def load_pidsmaker_eval() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for detector in SUPPORTED_DETECTORS:
        eval_data, pkl_path = load_eval_pkl(detector)
        if eval_data is None:
            out.append({
                "detector": detector,
                "status": "missing_eval",
                "pkl": "",
            })
            continue
        metrics = compute_metrics(eval_data)
        out.append({
            "detector": detector,
            "status": "ready",
            "pkl": pkl_path,
            **metrics,
        })
    return out


def _mcc(tp: int, fp: int, tn: int, fn: int) -> Optional[float]:
    den = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return ((tp * tn - fp * fn) / math.sqrt(den)) if den else None


def load_e0_summary() -> List[Dict[str, Any]]:
    path = E0_RESULT_DIR / "summary_all.csv"
    if not path.exists():
        return []
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))

    out: List[Dict[str, Any]] = []
    for detector in E0_DETECTORS:
        det_rows = [r for r in rows if r.get("detector") == detector]
        if not det_rows:
            out.append({"detector": detector, "status": "missing_e0"})
            continue
        tp = sum(int(r["tp"]) for r in det_rows)
        fp = sum(int(r["fp"]) for r in det_rows)
        tn = sum(int(r["tn"]) for r in det_rows)
        fn = sum(int(r["fn"]) for r in det_rows)
        precision = tp / (tp + fp) if (tp + fp) else None
        out.append({
            "detector": detector,
            "status": "ready",
            "rows": len(det_rows),
            "valid": sum(r.get("valid") == "True" for r in det_rows),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": precision,
            "mcc": _mcc(tp, fp, tn, fn),
        })
    return out


def load_threshold_sweep() -> List[Dict[str, Any]]:
    if not E0_THRESHOLD_SUMMARY.exists():
        return []
    with open(E0_THRESHOLD_SUMMARY, newline="") as f:
        return list(csv.DictReader(f))


def load_threshold_loso() -> List[Dict[str, Any]]:
    if not E0_THRESHOLD_LOSO_SUMMARY.exists():
        return []
    with open(E0_THRESHOLD_LOSO_SUMMARY, newline="") as f:
        return list(csv.DictReader(f))


def load_threshold_calibration() -> List[Dict[str, Any]]:
    if not E0_THRESHOLD_CALIBRATION_SUMMARY.exists():
        return []
    with open(E0_THRESHOLD_CALIBRATION_SUMMARY, newline="") as f:
        return list(csv.DictReader(f))


def detector_family(detector: str) -> str:
    if detector in GNN_DETECTORS:
        return "GNN"
    if detector in RULE_DETECTORS:
        return "Rule"
    if detector in HYBRID_DETECTORS:
        return "Hybrid"
    return "Other"


def print_training_data() -> None:
    data = audit_training_data()
    print("\n== 数据输入 ==")
    _print_table(
        ["item", "count", "status"],
        [
            ["benign_*.sql", data["benign_sql"], "OK" if data["benign_sql"] >= 30 else "LOW"],
            ["attack/*.strace.sql", data["attack_sql"], "OK" if data["attack_sql"] == 10 else "CHECK"],
        ],
    )


def print_artifacts() -> None:
    print("\n== Detector Artifact ==")
    gnn_rows = []
    for row in audit_gnn_artifacts():
        gnn_rows.append([
            row["detector"],
            row["status"],
            ", ".join(row["missing"]) if row["missing"] else "-",
        ])
    _print_table(["GNN detector", "status", "missing"], gnn_rows)

    rule = audit_rule_artifacts()
    print()
    _print_table(
        ["rule artifact", "status", "missing"],
        [["G1/G2", rule["status"], ", ".join(rule["missing"]) if rule["missing"] else "-"]],
    )


def print_eval() -> None:
    print("\n== PIDSMaker 原始 Evaluation ==")
    rows = []
    for row in load_pidsmaker_eval():
        if row["status"] != "ready":
            rows.append([row["detector"], row["status"], "-", "-", "-", "-", "-", "-", "-"])
            continue
        rows.append([
            row["detector"],
            "ready",
            row["gt_attack"],
            row["yp_sum"],
            row["tp"],
            row["fp"],
            _fmt_float(row["precision"], 4),
            _fmt_float(row["recall"], 4),
            _fmt_float(row["f1"], 4),
        ])
    _print_table(
        ["detector", "status", "GT", "yp", "TP", "FP", "Prec", "Recall", "F1"],
        rows,
    )


def print_e0() -> None:
    print("\n== E0 Mixed-run Node-level Baseline ==")
    rows = []
    for row in load_e0_summary():
        if row["status"] != "ready":
            rows.append([row["detector"], detector_family(row["detector"]), row["status"], "-", "-", "-", "-", "-"])
            continue
        rows.append([
            row["detector"],
            detector_family(row["detector"]),
            f"{row['valid']}/{row['rows']}",
            row["tp"],
            row["fp"],
            row["fn"],
            _fmt_float(row["precision"]),
            _fmt_float(row["mcc"]),
        ])
    _print_table(
        ["detector", "family", "valid", "TP", "FP", "FN", "Prec", "MCC"],
        rows,
    )


def print_threshold_sweep() -> None:
    rows = []
    for row in load_threshold_sweep():
        rows.append([
            row["detector"],
            row["current_threshold"],
            _fmt_float(float(row["current_precision"]) if row["current_precision"] else None),
            _fmt_float(float(row["current_recall"]) if row["current_recall"] else None),
            _fmt_float(float(row["current_mcc"]) if row["current_mcc"] else None),
            row["best_mcc_threshold"],
            _fmt_float(float(row["best_mcc_precision"]) if row["best_mcc_precision"] else None),
            _fmt_float(float(row["best_mcc_recall"]) if row["best_mcc_recall"] else None),
            _fmt_float(float(row["best_mcc"]) if row["best_mcc"] else None),
        ])
    if not rows:
        return

    print("\n== E0 Threshold Sweep Diagnostic ==")
    _print_table(
        ["detector", "cur_thr", "cur_P", "cur_R", "cur_MCC", "best_thr", "best_P", "best_R", "best_MCC"],
        rows,
    )

    loso_rows = []
    for row in load_threshold_loso():
        loso_rows.append([
            row["detector"],
            _fmt_float(float(row["current_precision"]) if row["current_precision"] else None),
            _fmt_float(float(row["current_mcc"]) if row["current_mcc"] else None),
            _fmt_float(float(row["loso_precision"]) if row["loso_precision"] else None),
            _fmt_float(float(row["loso_recall"]) if row["loso_recall"] else None),
            _fmt_float(float(row["loso_mcc"]) if row["loso_mcc"] else None),
            _fmt_float(float(row["delta_mcc"]) if row["delta_mcc"] else None),
        ])
    if loso_rows:
        print("\n== E0 Threshold LOSO Calibration ==")
        _print_table(
            ["detector", "cur_P", "cur_MCC", "loso_P", "loso_R", "loso_MCC", "delta_MCC"],
            loso_rows,
        )

    calibration_rows = []
    for row in load_threshold_calibration():
        applied = _csv_bool(row.get("applied_to_test_results"))
        status = "applied" if applied else "diagnostic"
        if not applied and row.get("apply_skip_reason"):
            status = "not_applied"
        calibration_rows.append([
            row["detector"],
            _fmt_float(float(row["selected_threshold"]) if row["selected_threshold"] else None, 6),
            status,
            _fmt_float(float(row["test_current_mcc"]) if row["test_current_mcc"] else None),
            _fmt_float(float(row["test_calibrated_precision"]) if row["test_calibrated_precision"] else None),
            _fmt_float(float(row["test_calibrated_recall"]) if row["test_calibrated_recall"] else None),
            _fmt_float(float(row["test_calibrated_mcc"]) if row["test_calibrated_mcc"] else None),
            _fmt_float(float(row["delta_mcc"]) if row["delta_mcc"] else None),
        ])
    if calibration_rows:
        print("\n== E0 Independent Threshold Calibration ==")
        _print_table(
            ["detector", "threshold", "status", "base_MCC", "cal_P", "cal_R", "cal_MCC", "delta_MCC"],
            calibration_rows,
        )


def print_recommendations() -> None:
    eval_rows = [r for r in load_pidsmaker_eval() if r["status"] == "ready"]
    e0_rows = [r for r in load_e0_summary() if r["status"] == "ready"]
    missing_eval = [r["detector"] for r in load_pidsmaker_eval() if r["status"] != "ready"]

    print("\n== 当前瓶颈和调优优先级 ==")
    if missing_eval:
        print(f"- PIDSMaker GNN artifact 不全:缺 {', '.join(missing_eval)} 的 eval/model 结果。")
        print("  下一步若要比较 8 个 PIDSMaker detector,先补训缺失 detector;不要在 E0 内自动训练。")

    if eval_rows:
        best_eval = max(eval_rows, key=lambda r: r["f1"])
        print(
            f"- PIDSMaker 原始 eval 当前 F1 最好的是 {best_eval['detector']} "
            f"(F1={best_eval['f1']:.4f},P={best_eval['precision']:.4f},R={best_eval['recall']:.4f})。"
        )

    if e0_rows:
        best_mcc = max(e0_rows, key=lambda r: r["mcc"] if r["mcc"] is not None else -999)
        best_precision = max(e0_rows, key=lambda r: r["precision"] if r["precision"] is not None else -1)
        print(
            f"- E0 mixed-run 当前 MCC 最好的是 {best_mcc['detector']} "
            f"(MCC={best_mcc['mcc']:.3f},TP={best_mcc['tp']},FP={best_mcc['fp']})。"
        )
        print(
            f"- E0 mixed-run 当前 Precision 最好的是 {best_precision['detector']} "
            f"(Precision={best_precision['precision']:.3f},TP={best_precision['tp']},FP={best_precision['fp']})。"
        )

    noisy = [
        r for r in e0_rows
        if r["precision"] is not None and r["precision"] < 0.02 and r["tp"] > 0
    ]
    if noisy:
        names = ", ".join(r["detector"] for r in noisy)
        print(f"- 过度报警 detector:{names}。它们能命中 GT,但 FP 太高,调优重点应是降 FP。")

    sweep_rows = load_threshold_sweep()
    improved = []
    for row in sweep_rows:
        cur = float(row["current_mcc"]) if row.get("current_mcc") else None
        best = float(row["best_mcc"]) if row.get("best_mcc") else None
        if cur is not None and best is not None and best > cur:
            improved.append((row["detector"], cur, best, row["best_mcc_threshold"]))
    if improved:
        best_gain = max(improved, key=lambda x: x[2] - x[1])
        print(
            f"- 阈值扫描显示 {best_gain[0]} 有可调空间: "
            f"MCC {best_gain[1]:.3f} → {best_gain[2]:.3f}, "
            f"候选 threshold={best_gain[3]}。"
        )

    loso_rows = load_threshold_loso()
    loso_improved = []
    for row in loso_rows:
        cur = float(row["current_mcc"]) if row.get("current_mcc") else None
        loso = float(row["loso_mcc"]) if row.get("loso_mcc") else None
        if cur is not None and loso is not None and loso > cur and loso > 0:
            loso_improved.append((row["detector"], cur, loso))
    if loso_improved:
        best_loso = max(loso_improved, key=lambda x: x[2] - x[1])
        print(
            f"- 留一场景阈值校准显示 {best_loso[0]} 的可泛化调参空间: "
            f"MCC {best_loso[1]:.3f} → {best_loso[2]:.3f}。"
        )

    calibration_rows = load_threshold_calibration()
    for row in calibration_rows:
        cur = float(row["test_current_mcc"]) if row.get("test_current_mcc") else None
        calibrated = (
            float(row["test_calibrated_mcc"])
            if row.get("test_calibrated_mcc") else None
        )
        if cur is not None and calibrated is not None and calibrated > cur:
            if _csv_bool(row.get("applied_to_test_results")):
                print(
                    f"- 独立 calibration 已应用到 {row['detector']}: "
                    f"MCC {cur:.3f} → {calibrated:.3f}, "
                    f"threshold={float(row['selected_threshold']):.6f}。"
                )
            else:
                reason = row.get("apply_skip_reason") or "not selected for runtime"
                print(
                    f"- 独立 calibration 诊断显示 {row['detector']} 可变为 "
                    f"MCC {cur:.3f} → {calibrated:.3f}, "
                    f"threshold={float(row['selected_threshold']):.6f}; "
                    f"未应用: {reason}。"
                )

    print("- PIDSMaker 原生代码保持不动;调优优先从训练数据覆盖、artifact 完整性、阈值配置和 wrapper 诊断入手。")


def audit_main(argv=None) -> int:
    print("训练 + 检测框架诊断")
    print(f"PROJECT_ROOT={PROJECT_ROOT}")
    print_training_data()
    print_artifacts()
    print_eval()
    print_e0()
    print_threshold_sweep()
    print_recommendations()
    return 0


# ============================================================================
# E0 threshold sweep diagnostic
# ============================================================================

#!/usr/bin/env python3
"""E0 detector threshold diagnostic.

This is a read-only tuning diagnostic for the training + detection framework.
It does not modify PIDSMaker code or model artifacts. It reuses E0 mixed SQL
and GT files, reruns detector per-node inference to get full-node scores, and
sweeps a single detector threshold offline.

Default sweep targets detectors with a meaningful scalar score:
  - magic: score > threshold
  - orthrus: loss/score > threshold
  - threatrace: score < threshold or wrong node-type prediction
  - g1: lambda score > threshold

Run:
  PYTHONPATH=pids_attack /opt/anaconda3/envs/mimicattack/bin/python \
    pids_attack/scripts/diagnostics/e0_threshold_sweep.py
"""

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.E0_detection.run import (  # noqa: E402
    DETECTORS,
    DETECTOR_ARTIFACT_ROOT,
    HYBRID_BASE_GNN,
    RULE_COMPONENTS,
    RESULT_DIR,
    compute_metrics as _e0_compute_metrics,
    _gt_sets,
    _write_csv,
    _write_orthrus_summary,
    _aggregate_detector_rows,
    _sql_node_catalog,
    assert_detector_artifacts_ready,
    write_best_detector_config,
    write_detector_best_runtime_bundles,
)
from attack.framework.oracle import PIDSOracle  # noqa: E402
from detection.inference.registry import _rank as _runtime_rank  # noqa: E402


DEFAULT_SWEEP_DETECTORS = ("magic", "orthrus", "threatrace", "g1")
APPLY_THRESHOLD_DETECTORS = {"magic", "orthrus", "threatrace"}
PER_NODE_CACHE_VERSION = 8
OUT_DIR = RESULT_DIR / "threshold_diagnostics"
PER_NODE_DIR = OUT_DIR / "per_node"
SUMMARY_CSV = OUT_DIR / "threshold_sweep_summary.csv"
DETAIL_CSV = OUT_DIR / "threshold_sweep_detail.csv"
LOSO_SUMMARY_CSV = OUT_DIR / "threshold_loso_summary.csv"
LOSO_DETAIL_CSV = OUT_DIR / "threshold_loso_by_scenario.csv"
LOSO_ORTHRUS_CSV = OUT_DIR / "summary_orthrus_threshold_loso.csv"
CALIBRATION_DIR = OUT_DIR / "calibration_split"
CALIBRATION_SUMMARY_CSV = CALIBRATION_DIR / "threshold_calibration_summary.csv"
CALIBRATION_ORTHRUS_CSV = CALIBRATION_DIR / "summary_orthrus_threshold_calibrated.csv"
HYBRID_MERGE_CSV = RESULT_DIR / "hybrid_merge_summary.csv"


def threshold_parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Sweep E0 detector thresholds over existing mixed SQL traces."
    )
    ap.add_argument(
        "--detectors",
        nargs="*",
        default=list(DEFAULT_SWEEP_DETECTORS),
        help="detectors to sweep (default: magic orthrus threatrace g1)",
    )
    ap.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="scenario id whitelist (default: all E0 result scenarios)",
    )
    return ap.parse_args(argv)


def threshold_calibrate_parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Select a threshold on an independent E0-format calibration split "
            "and evaluate it on the E0 test split."
        )
    )
    ap.add_argument("--detector", default="threatrace")
    ap.add_argument(
        "--calibration-dir",
        required=True,
        help="E0-format calibration result directory with summary_all.csv and gt.json files",
    )
    ap.add_argument(
        "--test-dir",
        default=str(RESULT_DIR),
        help="E0-format test result directory (default: experiments/E0_detection/results)",
    )
    ap.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="scenario id whitelist for both splits",
    )
    ap.add_argument(
        "--apply-to-test-results",
        action="store_true",
        help=(
            "if calibrated test MCC improves the detector, rewrite that detector's "
            "rows/evidence in the test result directory and refresh detection/artifacts"
        ),
    )
    ap.add_argument(
        "--max-scenario-mcc-drop",
        type=float,
        default=0.02,
        help=(
            "calibration guard: reject thresholds that lower any calibration "
            "scenario MCC by more than this value versus the deployed threshold"
        ),
    )
    ap.add_argument(
        "--mcc-tolerance-for-recall-guard",
        type=float,
        default=0.0,
        help=(
            "among calibration thresholds within this MCC distance from the "
            "guarded best, prefer the recall-preserving operating point; "
            "default 0.0 keeps MCC strictly primary"
        ),
    )
    return ap.parse_args(argv)


def hybrid_merge_parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Compare GNN, GNN OR G1, GNN OR G2, and GNN OR G1 OR G2 "
            "over existing E0 node_evidence."
        )
    )
    ap.add_argument(
        "--base-detectors",
        nargs="*",
        default=list(GNN_DETECTORS),
        choices=GNN_DETECTORS,
        help="GNN bases to compare (default: magic orthrus threatrace)",
    )
    ap.add_argument(
        "--scenarios",
        nargs="*",
        default=None,
        help="scenario id whitelist (default: all E0 scenarios)",
    )
    ap.add_argument(
        "--output",
        default=str(HYBRID_MERGE_CSV),
        help="CSV output path (default: experiments/E0_detection/results/hybrid_merge_summary.csv)",
    )
    return ap.parse_args(argv)


def refresh_e0_parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Refresh detector rows/evidence over existing E0 SQL traces without "
            "rerunning docker/strace collection."
        )
    )
    ap.add_argument(
        "--detectors",
        nargs="*",
        default=list(DETECTORS),
        choices=DETECTORS,
        help="detectors to refresh (default: all E0 detectors)",
    )
    ap.add_argument(
        "--result-dir",
        default=str(RESULT_DIR),
        help="E0 result directory to update (default: experiments/E0_detection/results)",
    )
    return ap.parse_args(argv)


def _fmt(value: Optional[float], digits: int = 6) -> str:
    if value is None or value == "":
        return ""
    return f"{float(value):.{digits}f}"


def _mcc(tp: int, fp: int, tn: int, fn: int) -> Optional[float]:
    den = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return ((tp * tn - fp * fn) / math.sqrt(den)) if den else None


def _metrics(all_ids: Set[Any], gt_ids: Set[Any], flagged_ids: Set[Any]) -> Dict[str, Any]:
    tp = len(flagged_ids & gt_ids)
    fp = len(flagged_ids - gt_ids)
    fn = len(gt_ids - flagged_ids)
    tn = max(0, len(all_ids) - tp - fp - fn)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "flagged": len(flagged_ids),
        "precision": precision,
        "recall": recall,
        "mcc": _mcc(tp, fp, tn, fn),
    }


def _scenario_dirs_under(result_dir: Path, whitelist: Optional[Sequence[str]]) -> List[Path]:
    dirs = []
    allowed = set(whitelist or [])
    for path in sorted(result_dir.iterdir()):
        if not path.is_dir():
            continue
        if path.name.startswith("threshold_"):
            continue
        if allowed and path.name not in allowed:
            continue
        if _scenario_has_inputs(path):
            dirs.append(path)
    if not dirs:
        raise SystemExit(f"[abort] no E0 scenario result dirs found under {result_dir}")
    return dirs


def _scenario_dirs(whitelist: Optional[Sequence[str]]) -> List[Path]:
    return _scenario_dirs_under(RESULT_DIR, whitelist)


def _candidate_input_dirs(scenario_dir: Path) -> List[Path]:
    """Candidate locations for E0 SQL/GT inputs for a result scenario dir."""
    return [
        scenario_dir,
        scenario_dir.parent.parent / "test_data" / scenario_dir.name,
        scenario_dir.parent / "test_data" / scenario_dir.name,
    ]


def _scenario_has_inputs(scenario_dir: Path) -> bool:
    return any(
        (candidate / "clean.strace.sql").exists()
        and (candidate / "gt.json").exists()
        for candidate in _candidate_input_dirs(scenario_dir)
    )


def _scenario_input_dir(scenario_dir: Path) -> Path:
    for candidate in _candidate_input_dirs(scenario_dir):
        if (candidate / "clean.strace.sql").exists() and (candidate / "gt.json").exists():
            return candidate
    raise SystemExit(f"[abort] missing E0 SQL/GT inputs for scenario: {scenario_dir}")


def _load_gt_ids(gt_path: Path) -> Set[int]:
    gt = json.loads(gt_path.read_text())
    _subj, _file, _net, total = _gt_sets(gt)
    return total


def _cache_namespace(result_dir: Path) -> str:
    raw = str(result_dir.resolve())
    safe = "".join(ch if ch.isalnum() else "_" for ch in raw)
    return safe[-120:]


def _node_cache_path(scenario_id: str, detector: str, namespace: str = "main") -> Path:
    return PER_NODE_DIR / namespace / f"{scenario_id}__{detector}.json"


def _load_or_predict_nodes(
    oracle: PIDSOracle,
    detector: str,
    scenario_dir: Path,
    namespace: str = "main",
) -> List[Dict[str, Any]]:
    input_dir = _scenario_input_dir(scenario_dir)
    sql_path = input_dir / "clean.strace.sql"
    cache_path = _node_cache_path(scenario_dir.name, detector, namespace)
    sql_mtime = sql_path.stat().st_mtime
    if cache_path.exists():
        try:
            doc = json.loads(cache_path.read_text())
            if (
                doc.get("cache_version") == PER_NODE_CACHE_VERSION
                and doc.get("sql_path") == str(sql_path)
                and doc.get("sql_mtime") == sql_mtime
            ):
                return list(doc.get("nodes", []))
        except Exception:
            pass

    nodes = oracle.predict_per_node_from_sql(str(sql_path))
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({
        "scenario_id": scenario_dir.name,
        "detector": detector,
        "cache_version": PER_NODE_CACHE_VERSION,
        "sql_path": str(sql_path),
        "sql_mtime": sql_mtime,
        "nodes": nodes,
    }, indent=2))
    return nodes


def _build_threshold_cases(
    *,
    result_dir: Path,
    detector: str,
    oracle: PIDSOracle,
    whitelist: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    namespace = _cache_namespace(result_dir)
    for scenario_dir in _scenario_dirs_under(result_dir, whitelist):
        input_dir = _scenario_input_dir(scenario_dir)
        catalog = _sql_node_catalog(input_dir / "clean.strace.sql")
        scenario_all_ids = set(catalog)
        scenario_gt_ids = _load_gt_ids(input_dir / "gt.json")
        nodes = _load_or_predict_nodes(
            oracle,
            detector,
            scenario_dir,
            namespace=namespace,
        )
        prefix = scenario_dir.name + ":"
        case_all_ids = {prefix + str(idx) for idx in scenario_all_ids}
        case_gt_ids = {prefix + str(idx) for idx in scenario_gt_ids}
        case_nodes: List[Dict[str, Any]] = []
        for nd in nodes:
            nd2 = dict(nd)
            idx = nd.get("node_index_id")
            if idx is not None:
                nd2["_global_node_id"] = prefix + str(int(idx))
            case_nodes.append(nd2)
        cases.append({
            "scenario_id": scenario_dir.name,
            "all_ids": case_all_ids,
            "gt_ids": case_gt_ids,
            "nodes": case_nodes,
        })
    return cases


def _resolve_result_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def _current_threshold(oracle: PIDSOracle, detector: str) -> Optional[float]:
    if detector in GNN_DETECTORS:
        try:
            import torch

            threshold_path = _gnn_best_model_dir(detector) / "threshold.pkl"
            loaded = torch.load(threshold_path, map_location="cpu")
            if isinstance(loaded, dict):
                return float(loaded.get("threshold", 0.0))
            return float(loaded)
        except Exception:
            pass

    det = oracle._ensure_detector()
    if detector == "g1":
        return float(getattr(det, "tau_lambda", 0.0))
    if detector == "g1g2":
        return float(getattr(det.g1, "tau_lambda", 0.0))
    if hasattr(det, "_get_engine"):
        engine = det._get_engine()
        # _LocalDetector lazily loads PIDSMaker artifacts on first prediction.
        # Cached per-node diagnostics may skip prediction, so force artifact load
        # before reporting the current threshold. This keeps the diagnostic table
        # aligned with the actual y_pred operating point.
        if getattr(engine, "_threshold", None) is None and hasattr(engine, "_ensure_loaded"):
            engine._ensure_loaded()
        return float(getattr(engine, "_threshold", 0.0))
    return None


def _sweep_mode(detector: str) -> Optional[str]:
    if detector in {"magic", "orthrus", "g1"}:
        return "score_gt_threshold"
    if detector == "threatrace":
        return "score_lt_threshold_or_wrong_type"
    return None


def _candidate_thresholds(scores: Iterable[float]) -> List[float]:
    vals = sorted({float(s) for s in scores if math.isfinite(float(s))})
    if not vals:
        return []
    eps = max(1e-9, abs(vals[-1] - vals[0]) * 1e-12)
    out = [vals[0] - eps, vals[-1] + eps]
    out.extend(vals)
    out.extend((a + b) / 2.0 for a, b in zip(vals, vals[1:]))
    return sorted(set(out))


def _flagged_for_threshold(
    nodes: Sequence[Dict[str, Any]],
    threshold: float,
    mode: str,
) -> Set[Any]:
    out: Set[Any] = set()
    for nd in nodes:
        global_id = nd.get("_global_node_id")
        if global_id is None:
            continue
        score = float(nd.get("score", 0.0))
        if mode == "score_gt_threshold":
            flag = score > threshold
        elif mode == "score_lt_threshold_or_wrong_type":
            correct = int(nd.get("correct_pred", -1))
            flag = score < threshold or correct != 1
        else:
            flag = False
        if flag:
            out.add(global_id)
    return out


def _better(candidate: Dict[str, Any], current: Optional[Dict[str, Any]], key: str) -> bool:
    if current is None:
        return True
    c_val = candidate.get(key)
    cur_val = current.get(key)
    c_cmp = c_val if c_val is not None else -999.0
    cur_cmp = cur_val if cur_val is not None else -999.0
    if c_cmp != cur_cmp:
        return c_cmp > cur_cmp
    # Tie-breaker: prefer higher precision, then higher recall, then fewer FP.
    return (
        (candidate.get("precision") or -1.0),
        (candidate.get("recall") or -1.0),
        -int(candidate.get("fp") or 0),
        -int(candidate.get("flagged") or 0),
        float(candidate.get("_threshold_preference") or 0.0),
    ) > (
        (current.get("precision") or -1.0),
        (current.get("recall") or -1.0),
        -int(current.get("fp") or 0),
        -int(current.get("flagged") or 0),
        float(current.get("_threshold_preference") or 0.0),
    )


def _threshold_preference(threshold: float, mode: str) -> float:
    # Conservative tie-breaker: high threshold for score>thr, low threshold for score<thr.
    if mode == "score_gt_threshold":
        return float(threshold)
    if mode == "score_lt_threshold_or_wrong_type":
        return -float(threshold)
    return 0.0


def _recall_preserving_threshold_preference(threshold: float, mode: str) -> float:
    # score>thr detectors preserve recall with lower thresholds; score<thr
    # detectors preserve recall with higher thresholds.
    if mode == "score_gt_threshold":
        return -float(threshold)
    if mode == "score_lt_threshold_or_wrong_type":
        return float(threshold)
    return 0.0


def _best_under_recall_floor(
    rows: Sequence[Dict[str, Any]],
    floor: float,
) -> Optional[Dict[str, Any]]:
    best: Optional[Dict[str, Any]] = None
    for row in rows:
        recall = row.get("recall")
        if recall is None or recall < floor:
            continue
        if _better(row, best, "precision"):
            best = row
    return best


def _merge_cases(cases: Sequence[Dict[str, Any]]) -> Tuple[Set[Any], Set[Any], List[Dict[str, Any]]]:
    all_ids: Set[Any] = set()
    gt_ids: Set[Any] = set()
    nodes: List[Dict[str, Any]] = []
    for case in cases:
        all_ids.update(case["all_ids"])
        gt_ids.update(case["gt_ids"])
        nodes.extend(case["nodes"])
    return all_ids, gt_ids, nodes


def _select_best_threshold(
    cases: Sequence[Dict[str, Any]],
    mode: str,
) -> Optional[Dict[str, Any]]:
    all_ids, gt_ids, nodes = _merge_cases(cases)
    best: Optional[Dict[str, Any]] = None
    for threshold in _candidate_thresholds(float(nd.get("score", 0.0)) for nd in nodes):
        flagged = _flagged_for_threshold(nodes, threshold, mode)
        metrics = _metrics(all_ids, gt_ids, flagged)
        row = {
            "threshold": threshold,
            "_threshold_preference": _threshold_preference(threshold, mode),
            **metrics,
        }
        if _better(row, best, "mcc"):
            best = row
    return best


def _current_case_metrics(case: Dict[str, Any]) -> Dict[str, Any]:
    flagged = {
        nd["_global_node_id"]
        for nd in case["nodes"]
        if nd.get("_global_node_id") is not None and int(nd.get("y_pred", 0)) == 1
    }
    return _metrics(case["all_ids"], case["gt_ids"], flagged)


def _select_best_threshold_with_scenario_guard(
    cases: Sequence[Dict[str, Any]],
    mode: str,
    *,
    max_scenario_mcc_drop: float = 0.02,
    mcc_tolerance_for_recall_guard: float = 0.0,
) -> Optional[Dict[str, Any]]:
    """Select threshold on calibration cases with a per-scenario regression guard."""
    all_ids, gt_ids, nodes = _merge_cases(cases)
    current_by_scenario = {
        str(case["scenario_id"]): _current_case_metrics(case)
        for case in cases
    }
    rows: List[Dict[str, Any]] = []
    for threshold in _candidate_thresholds(float(nd.get("score", 0.0)) for nd in nodes):
        worst_drop = 0.0
        worst_scenario = ""
        ok = True
        for case in cases:
            current = current_by_scenario[str(case["scenario_id"])]
            candidate = _evaluate_threshold_case(case, threshold, mode)
            current_mcc = current.get("mcc")
            candidate_mcc = candidate.get("mcc")
            if current_mcc is None or candidate_mcc is None:
                continue
            drop = float(current_mcc) - float(candidate_mcc)
            if drop > worst_drop:
                worst_drop = drop
                worst_scenario = str(case["scenario_id"])
            if drop > max_scenario_mcc_drop:
                ok = False
                break
        if not ok:
            continue
        flagged = _flagged_for_threshold(nodes, threshold, mode)
        metrics = _metrics(all_ids, gt_ids, flagged)
        rows.append({
            "threshold": threshold,
            "_threshold_preference": _threshold_preference(threshold, mode),
            "_recall_preserving_threshold_preference": (
                _recall_preserving_threshold_preference(threshold, mode)
            ),
            "guard_max_scenario_mcc_drop": max_scenario_mcc_drop,
            "guard_worst_scenario": worst_scenario,
            "guard_worst_mcc_drop": worst_drop,
            **metrics,
        })
    if not rows:
        return None

    best_mcc = max(
        float(row.get("mcc") if row.get("mcc") is not None else -999.0)
        for row in rows
    )
    near_best = [
        row for row in rows
        if row.get("mcc") is not None
        and float(row["mcc"]) >= best_mcc - mcc_tolerance_for_recall_guard
    ]
    # Default policy is strict MCC-first.  A caller may explicitly pass a
    # positive tolerance to trade a bounded amount of calibration MCC for
    # higher recall, but E0's primary metric remains MCC.
    return max(
        near_best,
        key=lambda row: (
            float(row.get("recall") if row.get("recall") is not None else -1.0),
            float(row.get("_recall_preserving_threshold_preference") or 0.0),
            float(row.get("mcc") if row.get("mcc") is not None else -999.0),
            float(row.get("precision") if row.get("precision") is not None else -1.0),
            -int(row.get("fp") or 0),
        ),
    )


def _evaluate_threshold_case(
    case: Dict[str, Any],
    threshold: float,
    mode: str,
) -> Dict[str, Any]:
    flagged = _flagged_for_threshold(case["nodes"], threshold, mode)
    return _metrics(case["all_ids"], case["gt_ids"], flagged)


def _median(values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _sum_confusion(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "tp": sum(int(r.get("tp") or 0) for r in rows),
        "fp": sum(int(r.get("fp") or 0) for r in rows),
        "tn": sum(int(r.get("tn") or 0) for r in rows),
        "fn": sum(int(r.get("fn") or 0) for r in rows),
        "flagged": sum(int(r.get("flagged") or 0) for r in rows),
    }


def _loso_threshold_calibration(
    detector: str,
    mode: str,
    cases: Sequence[Dict[str, Any]],
    current: Dict[str, Any],
    current_threshold: Optional[float],
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Leave-one-scenario-out threshold calibration.

    For each held-out scenario, select the best MCC threshold from all other
    scenarios, then evaluate that threshold only on the held-out scenario.
    This keeps the diagnostic from selecting a threshold on the same GT it
    evaluates.
    """
    if len(cases) < 2:
        return None, [], []

    detail_rows: List[Dict[str, Any]] = []
    orthrus_rows: List[Dict[str, Any]] = []
    selected_thresholds: List[float] = []

    for heldout_idx, heldout in enumerate(cases):
        train_cases = [
            case for idx, case in enumerate(cases)
            if idx != heldout_idx
        ]
        best = _select_best_threshold(train_cases, mode)
        if best is None:
            continue
        threshold = float(best["threshold"])
        selected_thresholds.append(threshold)
        metrics = _evaluate_threshold_case(heldout, threshold, mode)
        row = {
            "detector": detector,
            "scenario_id": heldout["scenario_id"],
            "selected_threshold": threshold,
            "train_tp": best["tp"],
            "train_fp": best["fp"],
            "train_tn": best["tn"],
            "train_fn": best["fn"],
            "train_precision": best["precision"],
            "train_recall": best["recall"],
            "train_mcc": best["mcc"],
            **metrics,
        }
        detail_rows.append(row)
        orthrus_rows.append({
            "Scenario": heldout["scenario_id"],
            "System": f"{detector}_threshold_loso",
            "TP": metrics["tp"],
            "FP": metrics["fp"],
            "TN": metrics["tn"],
            "FN": metrics["fn"],
            "Precision": metrics["precision"] if metrics["precision"] is not None else "",
            "MCC": metrics["mcc"] if metrics["mcc"] is not None else "",
        })

    if not detail_rows:
        return None, [], []

    totals = _sum_confusion(detail_rows)
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) else None
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) else None
    loso_mcc = _mcc(totals["tp"], totals["fp"], totals["tn"], totals["fn"])
    current_mcc = current.get("mcc")
    delta_mcc = (
        None if current_mcc is None or loso_mcc is None
        else float(loso_mcc) - float(current_mcc)
    )
    all_ids, gt_ids, _nodes = _merge_cases(cases)
    summary = {
        "detector": detector,
        "mode": mode,
        "scenario_count": len(cases),
        "node_count": len(all_ids),
        "gt_count": len(gt_ids),
        "current_threshold": _fmt(current_threshold),
        "current_tp": current["tp"],
        "current_fp": current["fp"],
        "current_tn": current["tn"],
        "current_fn": current["fn"],
        "current_flagged": current["flagged"],
        "current_precision": current["precision"],
        "current_recall": current["recall"],
        "current_mcc": current["mcc"],
        "loso_tp": totals["tp"],
        "loso_fp": totals["fp"],
        "loso_tn": totals["tn"],
        "loso_fn": totals["fn"],
        "loso_flagged": totals["flagged"],
        "loso_precision": precision,
        "loso_recall": recall,
        "loso_mcc": loso_mcc,
        "delta_mcc": delta_mcc,
        "selected_threshold_min": min(selected_thresholds),
        "selected_threshold_median": _median(selected_thresholds),
        "selected_threshold_max": max(selected_thresholds),
    }
    return summary, detail_rows, orthrus_rows


def _write_summary(rows: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = [
        "detector",
        "mode",
        "scenario_count",
        "node_count",
        "gt_count",
        "current_threshold",
        "current_tp",
        "current_fp",
        "current_tn",
        "current_fn",
        "current_flagged",
        "current_precision",
        "current_recall",
        "current_mcc",
        "best_mcc_threshold",
        "best_mcc_tp",
        "best_mcc_fp",
        "best_mcc_tn",
        "best_mcc_fn",
        "best_mcc_flagged",
        "best_mcc_precision",
        "best_mcc_recall",
        "best_mcc",
        "best_precision_recall_ge_0_50_threshold",
        "best_precision_recall_ge_0_50_precision",
        "best_precision_recall_ge_0_50_recall",
        "best_precision_recall_ge_0_50_mcc",
        "best_precision_recall_ge_0_80_threshold",
        "best_precision_recall_ge_0_80_precision",
        "best_precision_recall_ge_0_80_recall",
        "best_precision_recall_ge_0_80_mcc",
    ]
    merged: Dict[str, Dict[str, Any]] = {}
    if SUMMARY_CSV.exists():
        with open(SUMMARY_CSV, newline="") as f:
            for row in csv.DictReader(f):
                detector = str(row.get("detector", ""))
                if detector:
                    merged[detector] = dict(row)
    for row in rows:
        detector = str(row.get("detector", ""))
        if detector:
            merged[detector] = row
    with open(SUMMARY_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for detector in sorted(merged):
            row = merged[detector]
            writer.writerow({k: row.get(k, "") for k in fields})


def _write_detail(rows: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = [
        "detector",
        "threshold",
        "tp",
        "fp",
        "tn",
        "fn",
        "flagged",
        "precision",
        "recall",
        "mcc",
    ]
    detectors = {str(row.get("detector", "")) for row in rows if row.get("detector")}
    merged: List[Dict[str, Any]] = []
    if DETAIL_CSV.exists():
        with open(DETAIL_CSV, newline="") as f:
            for row in csv.DictReader(f):
                if str(row.get("detector", "")) not in detectors:
                    merged.append(dict(row))
    merged.extend(rows)
    with open(DETAIL_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in merged:
            writer.writerow({k: row.get(k, "") for k in fields})


def _write_loso_summary(rows: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = [
        "detector",
        "mode",
        "scenario_count",
        "node_count",
        "gt_count",
        "current_threshold",
        "current_tp",
        "current_fp",
        "current_tn",
        "current_fn",
        "current_flagged",
        "current_precision",
        "current_recall",
        "current_mcc",
        "loso_tp",
        "loso_fp",
        "loso_tn",
        "loso_fn",
        "loso_flagged",
        "loso_precision",
        "loso_recall",
        "loso_mcc",
        "delta_mcc",
        "selected_threshold_min",
        "selected_threshold_median",
        "selected_threshold_max",
    ]
    merged: Dict[str, Dict[str, Any]] = {}
    if LOSO_SUMMARY_CSV.exists():
        with open(LOSO_SUMMARY_CSV, newline="") as f:
            for row in csv.DictReader(f):
                detector = str(row.get("detector", ""))
                if detector:
                    merged[detector] = dict(row)
    for row in rows:
        detector = str(row.get("detector", ""))
        if detector:
            merged[detector] = row
    with open(LOSO_SUMMARY_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for detector in sorted(merged):
            row = merged[detector]
            writer.writerow({k: row.get(k, "") for k in fields})


def _write_loso_detail(rows: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = [
        "detector",
        "scenario_id",
        "selected_threshold",
        "train_tp",
        "train_fp",
        "train_tn",
        "train_fn",
        "train_precision",
        "train_recall",
        "train_mcc",
        "tp",
        "fp",
        "tn",
        "fn",
        "flagged",
        "precision",
        "recall",
        "mcc",
    ]
    detectors = {str(row.get("detector", "")) for row in rows if row.get("detector")}
    merged: List[Dict[str, Any]] = []
    if LOSO_DETAIL_CSV.exists():
        with open(LOSO_DETAIL_CSV, newline="") as f:
            for row in csv.DictReader(f):
                if str(row.get("detector", "")) not in detectors:
                    merged.append(dict(row))
    merged.extend(rows)
    with open(LOSO_DETAIL_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in merged:
            writer.writerow({k: row.get(k, "") for k in fields})


def _write_loso_orthrus(rows: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["Scenario", "System", "TP", "FP", "TN", "FN", "Precision", "MCC"]
    systems = {str(row.get("System", "")) for row in rows if row.get("System")}
    merged: List[Dict[str, Any]] = []
    if LOSO_ORTHRUS_CSV.exists():
        with open(LOSO_ORTHRUS_CSV, newline="") as f:
            for row in csv.DictReader(f):
                if str(row.get("System", "")) not in systems:
                    merged.append(dict(row))
    merged.extend(rows)
    with open(LOSO_ORTHRUS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in merged:
            writer.writerow({k: row.get(k, "") for k in fields})


def _current_metrics_from_cases(cases: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    all_ids, gt_ids, nodes = _merge_cases(cases)
    current_flagged = {
        nd["_global_node_id"]
        for nd in nodes
        if nd.get("_global_node_id") is not None and int(nd.get("y_pred", 0)) == 1
    }
    return _metrics(all_ids, gt_ids, current_flagged)


def _evaluate_threshold_cases(
    cases: Sequence[Dict[str, Any]],
    threshold: float,
    mode: str,
) -> Dict[str, Any]:
    all_ids, gt_ids, nodes = _merge_cases(cases)
    flagged = _flagged_for_threshold(nodes, threshold, mode)
    return _metrics(all_ids, gt_ids, flagged)


def _detector_summary_row(
    rows: Sequence[Dict[str, Any]],
    detector: str,
) -> Optional[Dict[str, Any]]:
    for row in _aggregate_detector_rows(list(rows)):
        if row.get("detector") == detector:
            return row
    return None


def _calibrated_test_improves(
    current_rows: Sequence[Dict[str, Any]],
    calibrated_rows: Sequence[Dict[str, Any]],
    detector: str,
) -> bool:
    current = _detector_summary_row(current_rows, detector)
    calibrated = _detector_summary_row(calibrated_rows, detector)
    if calibrated is None:
        return False
    if current is None:
        return True
    return _runtime_rank(calibrated) > _runtime_rank(current)


def _historical_runtime_metrics(detector: str) -> Optional[Dict[str, Any]]:
    path = DETECTOR_ARTIFACT_ROOT / detector / "manifest.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text()).get("e0_metrics")
    except Exception:
        return None


def _threshold_candidate_runtime_row(
    detector: str,
    metrics: Dict[str, Any],
    scenario_count: int,
) -> Dict[str, Any]:
    return {
        "detector": detector,
        "scenario_count": scenario_count,
        "valid_count": scenario_count,
        "all_steps_passed_count": scenario_count,
        "final_attack_succeeded_count": scenario_count,
        "overall_mcc": metrics.get("mcc"),
        "macro_mcc": metrics.get("mcc"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "tp": metrics.get("tp"),
        "fp": metrics.get("fp"),
        "tn": metrics.get("tn"),
        "fn": metrics.get("fn"),
        "flagged_count": metrics.get("flagged"),
        "wall_sec": 0.0,
    }


def _load_summary_rows(result_dir: Path) -> List[Dict[str, Any]]:
    summary_path = result_dir / "summary_all.csv"
    if not summary_path.exists():
        raise SystemExit(f"[abort] missing summary_all.csv: {summary_path}")
    with open(summary_path, newline="") as f:
        return list(csv.DictReader(f))


def _adjust_nodes_for_threshold(
    *,
    scenario_id: str,
    nodes: Sequence[Dict[str, Any]],
    threshold: float,
    mode: str,
) -> List[Dict[str, Any]]:
    flagged = _flagged_for_threshold(nodes, threshold, mode)
    adjusted: List[Dict[str, Any]] = []
    for nd in nodes:
        nd2 = dict(nd)
        idx = nd.get("node_index_id")
        if idx is None:
            adjusted.append(nd2)
            continue
        global_id = nd.get("_global_node_id", f"{scenario_id}:{int(idx)}")
        nd2["y_pred"] = 1 if global_id in flagged else 0
        adjusted.append(nd2)
    return adjusted


def _replace_rows_for_detector(
    rows: Sequence[Dict[str, Any]],
    detector: str,
    replacements: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        sid = str(row.get("scenario_id", ""))
        if row.get("detector") == detector and sid in replacements:
            out.append(replacements[sid])
            seen.add(sid)
        else:
            out.append(dict(row))
    for sid, row in replacements.items():
        if sid not in seen:
            out.append(row)
    return out


def _refresh_detector_rows_from_sql(
    *,
    result_dir: Path,
    detectors: Sequence[str],
) -> List[Dict[str, Any]]:
    """Rerun detector inference over existing E0 SQL and rewrite node evidence."""
    rows = _load_summary_rows(result_dir)
    oracle_pool = {detector: PIDSOracle(detector) for detector in detectors}

    for scenario_dir in _scenario_dirs_under(result_dir, None):
        sid = scenario_dir.name
        input_dir = _scenario_input_dir(scenario_dir)
        gt = json.loads((input_dir / "gt.json").read_text())
        catalog = _sql_node_catalog(input_dir / "clean.strace.sql")
        detector_results_path = scenario_dir / "detector_results.json"
        detector_results = (
            json.loads(detector_results_path.read_text())
            if detector_results_path.exists() else {}
        )
        evidence_path = scenario_dir / "node_evidence.json"
        evidence_doc = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}

        replacements: Dict[str, Dict[str, Any]] = {}
        for detector in detectors:
            current = _scenario_row(rows, sid, detector)
            nodes = oracle_pool[detector].predict_per_node_from_sql(
                str(input_dir / "clean.strace.sql")
            )
            metrics, evidence = _e0_compute_metrics(nodes, gt, catalog)
            new_row = {
                "scenario_id": sid,
                "detector": detector,
                "valid": current.get("valid", True),
                "all_steps_passed": current.get("all_steps_passed", True),
                "final_attack_succeeded": current.get(
                    "final_attack_succeeded", True
                ),
                **metrics,
                "wall_sec": current.get("wall_sec", 0),
                "failed_step": current.get("failed_step"),
                "gt_source": current.get(
                    "gt_source", "attack_only_signature_marker_window"
                ),
            }
            replacements[detector] = new_row
            detector_results[detector] = new_row
            evidence_doc[detector] = evidence

        detector_results_path.write_text(
            json.dumps(detector_results, indent=2, default=str)
        )
        evidence_path.write_text(json.dumps(evidence_doc, indent=2, default=str))

        scenario_summary_path = scenario_dir / "summary.csv"
        scenario_rows = []
        if scenario_summary_path.exists():
            with open(scenario_summary_path, newline="") as f:
                scenario_rows = list(csv.DictReader(f))
        for detector, row in replacements.items():
            scenario_rows = _replace_rows_for_detector(
                scenario_rows,
                detector,
                {sid: row},
            )
        _write_csv(scenario_summary_path, scenario_rows)

        for detector, row in replacements.items():
            rows = _replace_rows_for_detector(rows, detector, {sid: row})

    _write_csv(result_dir / "summary_all.csv", rows)
    _write_orthrus_summary(result_dir / "summary_orthrus.csv", rows)
    runtime_updates = write_detector_best_runtime_bundles(
        rows,
        result_dir=result_dir,
    )
    write_best_detector_config(
        rows,
        result_dir=result_dir,
        out_path=result_dir / "best_detector_config.json",
    )
    updated = [
        name for name, bundle in runtime_updates.items()
        if name != "_summary" and bundle.get("updated")
    ]
    if updated:
        print("[refresh] updated detector-best runtime:", ", ".join(updated))
    else:
        print("[refresh] detector-best runtime unchanged")
    return rows


def refresh_e0_main(argv=None) -> int:
    args = refresh_e0_parse_args(argv)
    result_dir = _resolve_result_dir(args.result_dir)
    detectors = list(args.detectors)
    assert_detector_artifacts_ready(detectors)
    rows = _refresh_detector_rows_from_sql(
        result_dir=result_dir,
        detectors=detectors,
    )
    summary_rows = [
        row for row in _aggregate_detector_rows(rows)
        if row.get("detector") in set(detectors)
    ]
    print("\n== Refreshed E0 detectors ==")
    _print_table(
        ["detector", "TP", "FP", "FN", "Precision", "Recall", "MCC"],
        [
            [
                row["detector"],
                row["tp"],
                row["fp"],
                row["fn"],
                _fmt(row.get("precision"), 3),
                _fmt(row.get("recall"), 3),
                _fmt(row.get("overall_mcc"), 3),
            ]
            for row in sorted(summary_rows, key=lambda r: str(r.get("detector")))
        ],
    )
    print(f"\nsummary_all:     {result_dir / 'summary_all.csv'}")
    print(f"summary_orthrus: {result_dir / 'summary_orthrus.csv'}")
    print(f"best_config:     {result_dir / 'best_detector_config.json'}")
    return 0


def _apply_threshold_to_e0_result_dir(
    *,
    result_dir: Path,
    detector: str,
    threshold: float,
    mode: str,
    oracle: PIDSOracle,
    whitelist: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Rewrite one detector's E0 test rows/evidence using a calibrated threshold."""
    rows = _load_summary_rows(result_dir)
    replacements: Dict[str, Dict[str, Any]] = {}
    namespace = _cache_namespace(result_dir)

    for scenario_dir in _scenario_dirs_under(result_dir, whitelist):
        sid = scenario_dir.name
        input_dir = _scenario_input_dir(scenario_dir)
        gt = json.loads((input_dir / "gt.json").read_text())
        catalog = _sql_node_catalog(input_dir / "clean.strace.sql")
        nodes = _load_or_predict_nodes(
            oracle,
            detector,
            scenario_dir,
            namespace=namespace,
        )
        prefix = sid + ":"
        nodes_with_ids: List[Dict[str, Any]] = []
        for nd in nodes:
            nd2 = dict(nd)
            idx = nd.get("node_index_id")
            if idx is not None:
                nd2["_global_node_id"] = prefix + str(int(idx))
            nodes_with_ids.append(nd2)
        adjusted = _adjust_nodes_for_threshold(
            scenario_id=sid,
            nodes=nodes_with_ids,
            threshold=threshold,
            mode=mode,
        )
        metrics, evidence = _e0_compute_metrics(adjusted, gt, catalog)

        current = next(
            (
                row for row in rows
                if row.get("scenario_id") == sid and row.get("detector") == detector
            ),
            {},
        )
        new_row = {
            "scenario_id": sid,
            "detector": detector,
            "valid": current.get("valid", True),
            "all_steps_passed": current.get("all_steps_passed", True),
            "final_attack_succeeded": current.get("final_attack_succeeded", True),
            **metrics,
            "wall_sec": current.get("wall_sec", 0),
            "failed_step": current.get("failed_step"),
            "gt_source": current.get("gt_source", "attack_only_signature_marker_window"),
        }
        replacements[sid] = new_row

        detector_results_path = scenario_dir / "detector_results.json"
        detector_results = (
            json.loads(detector_results_path.read_text())
            if detector_results_path.exists() else {}
        )
        detector_results[detector] = new_row
        detector_results_path.write_text(json.dumps(detector_results, indent=2, default=str))

        evidence_path = scenario_dir / "node_evidence.json"
        evidence_doc = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
        evidence_doc[detector] = evidence
        evidence_path.write_text(json.dumps(evidence_doc, indent=2, default=str))

        scenario_summary_path = scenario_dir / "summary.csv"
        if scenario_summary_path.exists():
            with open(scenario_summary_path, newline="") as f:
                scenario_rows = list(csv.DictReader(f))
        else:
            scenario_rows = []
        _write_csv(
            scenario_summary_path,
            _replace_rows_for_detector(scenario_rows, detector, {sid: new_row}),
        )

    updated_rows = _replace_rows_for_detector(rows, detector, replacements)
    _write_csv(result_dir / "summary_all.csv", updated_rows)
    _write_orthrus_summary(result_dir / "summary_orthrus.csv", updated_rows)
    return updated_rows


def _source_detectors_for_hybrid(hybrid_detector: str) -> List[str]:
    base = HYBRID_BASE_GNN[hybrid_detector]
    return [base, *RULE_COMPONENTS.get(hybrid_detector, ("g1", "g2"))]


def _dependent_hybrids_for_base(base_detector: str) -> List[str]:
    return [
        hybrid
        for hybrid, base in HYBRID_BASE_GNN.items()
        if base == base_detector
    ]


def _records_by_node_id(
    evidence_doc: Dict[str, Any],
    detector: str,
) -> Dict[int, Dict[str, Any]]:
    detector_evidence = evidence_doc.get(detector)
    if not detector_evidence:
        raise SystemExit(
            f"[abort] missing node_evidence for source detector {detector}"
        )

    records: Dict[int, Dict[str, Any]] = {}
    for group in (
        "gt_nodes",
        "flagged_nodes",
        "gt_flagged_nodes",
        "gt_missed_nodes",
        "flagged_outside_gt_nodes",
    ):
        for record in detector_evidence.get(group, []):
            idx = record.get("node_index_id")
            if idx is None:
                continue
            index_id = int(idx)
            candidate = dict(record)
            candidate["node_index_id"] = index_id
            old = records.get(index_id)
            if old is None or float(candidate.get("score", 0.0)) > float(old.get("score", 0.0)):
                records[index_id] = candidate
    return records


def _merged_or_nodes_from_evidence(
    evidence_doc: Dict[str, Any],
    source_detectors: Sequence[str],
) -> List[Dict[str, Any]]:
    merged_records: Dict[int, Dict[str, Any]] = {}
    flagged_ids: Set[int] = set()

    for source in source_detectors:
        source_evidence = evidence_doc.get(source)
        if not source_evidence:
            raise SystemExit(
                f"[abort] missing node_evidence for source detector {source}"
            )
        for record in source_evidence.get("flagged_nodes", []):
            if record.get("node_index_id") is not None:
                flagged_ids.add(int(record["node_index_id"]))
        for index_id, record in _records_by_node_id(evidence_doc, source).items():
            old = merged_records.get(index_id)
            if old is None or float(record.get("score", 0.0)) > float(old.get("score", 0.0)):
                merged_records[index_id] = record

    for index_id in flagged_ids:
        merged_records.setdefault(index_id, {"node_index_id": index_id, "score": 0.0})

    nodes: List[Dict[str, Any]] = []
    for index_id, record in merged_records.items():
        nd = dict(record)
        nd["node_index_id"] = index_id
        nd["y_pred"] = 1 if index_id in flagged_ids else 0
        nodes.append(nd)
    return nodes


def _scenario_row(
    rows: Sequence[Dict[str, Any]],
    scenario_id: str,
    detector: str,
) -> Dict[str, Any]:
    for row in rows:
        if row.get("scenario_id") == scenario_id and row.get("detector") == detector:
            return dict(row)
    return {}


def _scenario_wall_sec(
    rows: Sequence[Dict[str, Any]],
    scenario_id: str,
    source_detectors: Sequence[str],
    fallback: Any,
) -> float:
    total = 0.0
    seen = False
    for source in source_detectors:
        row = _scenario_row(rows, scenario_id, source)
        if row:
            total += float(row.get("wall_sec") or 0.0)
            seen = True
    if seen:
        return total
    return float(fallback or 0.0)


def _rewrite_hybrid_rows_from_evidence(
    *,
    result_dir: Path,
    hybrid_detector: str,
    whitelist: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Refresh one OR-hybrid from already materialized base/rule evidence."""
    source_detectors = _source_detectors_for_hybrid(hybrid_detector)
    rows = _load_summary_rows(result_dir)
    replacements: Dict[str, Dict[str, Any]] = {}

    for scenario_dir in _scenario_dirs_under(result_dir, whitelist):
        sid = scenario_dir.name
        input_dir = _scenario_input_dir(scenario_dir)
        gt = json.loads((input_dir / "gt.json").read_text())
        catalog = _sql_node_catalog(input_dir / "clean.strace.sql")
        evidence_path = scenario_dir / "node_evidence.json"
        evidence_doc = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
        nodes = _merged_or_nodes_from_evidence(evidence_doc, source_detectors)
        metrics, evidence = _e0_compute_metrics(nodes, gt, catalog)

        current = _scenario_row(rows, sid, hybrid_detector)
        base = _scenario_row(rows, sid, source_detectors[0])
        new_row = {
            "scenario_id": sid,
            "detector": hybrid_detector,
            "valid": current.get("valid", base.get("valid", True)),
            "all_steps_passed": current.get(
                "all_steps_passed",
                base.get("all_steps_passed", True),
            ),
            "final_attack_succeeded": current.get(
                "final_attack_succeeded",
                base.get("final_attack_succeeded", True),
            ),
            **metrics,
            "wall_sec": _scenario_wall_sec(
                rows,
                sid,
                source_detectors,
                current.get("wall_sec", base.get("wall_sec", 0)),
            ),
            "failed_step": current.get("failed_step", base.get("failed_step")),
            "gt_source": current.get(
                "gt_source",
                base.get("gt_source", "attack_only_signature_marker_window"),
            ),
        }
        replacements[sid] = new_row

        detector_results_path = scenario_dir / "detector_results.json"
        detector_results = (
            json.loads(detector_results_path.read_text())
            if detector_results_path.exists() else {}
        )
        detector_results[hybrid_detector] = new_row
        detector_results_path.write_text(json.dumps(detector_results, indent=2, default=str))

        evidence_doc[hybrid_detector] = evidence
        evidence_path.write_text(json.dumps(evidence_doc, indent=2, default=str))

        scenario_summary_path = scenario_dir / "summary.csv"
        if scenario_summary_path.exists():
            with open(scenario_summary_path, newline="") as f:
                scenario_rows = list(csv.DictReader(f))
        else:
            scenario_rows = []
        _write_csv(
            scenario_summary_path,
            _replace_rows_for_detector(
                scenario_rows,
                hybrid_detector,
                {sid: new_row},
            ),
        )

    updated_rows = _replace_rows_for_detector(rows, hybrid_detector, replacements)
    _write_csv(result_dir / "summary_all.csv", updated_rows)
    _write_orthrus_summary(result_dir / "summary_orthrus.csv", updated_rows)
    return updated_rows


def _refresh_dependent_hybrids(
    *,
    result_dir: Path,
    base_detector: str,
    whitelist: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    updated_rows = _load_summary_rows(result_dir)
    refreshed: Dict[str, Any] = {}
    for hybrid_detector in _dependent_hybrids_for_base(base_detector):
        updated_rows = _rewrite_hybrid_rows_from_evidence(
            result_dir=result_dir,
            hybrid_detector=hybrid_detector,
            whitelist=whitelist,
        )
        refreshed[hybrid_detector] = _detector_summary_row(updated_rows, hybrid_detector)
    if refreshed:
        runtime_updates = write_detector_best_runtime_bundles(
            updated_rows,
            result_dir=result_dir,
        )
        write_best_detector_config(
            updated_rows,
            result_dir=result_dir,
            out_path=result_dir / "best_detector_config.json",
        )
        refreshed["_runtime_updates"] = {
            k: v for k, v in runtime_updates.items() if k in refreshed or k == "_summary"
        }
    return refreshed


def _variant_source_detectors(base_detector: str) -> List[Tuple[str, List[str]]]:
    return [
        ("base", [base_detector]),
        ("base_or_g1", [base_detector, "g1"]),
        ("base_or_g2", [base_detector, "g2"]),
        ("base_or_g1g2", [base_detector, "g1", "g2"]),
    ]


def _variant_public_detector(base_detector: str) -> Optional[str]:
    for detector, base in HYBRID_BASE_GNN.items():
        if base == base_detector:
            return detector
    return None


def _rule_components_for_sources(source_detectors: Sequence[str]) -> List[str]:
    return [name for name in ("g1", "g2") if name in source_detectors]


def _hybrid_merge_summary_rows(
    *,
    result_dir: Path,
    base_detectors: Sequence[str],
    whitelist: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    scenario_dirs = _scenario_dirs_under(result_dir, whitelist)
    current_rows = _load_summary_rows(result_dir)
    variant_detector_cache: Dict[Tuple[str, Tuple[str, ...]], Any] = {}
    use_runtime_variants = result_dir.resolve() == RESULT_DIR.resolve()

    def variant_detector(base_detector: str, source_detectors: Sequence[str]) -> Any:
        components = tuple(_rule_components_for_sources(source_detectors))
        key = (base_detector, components)
        if key in variant_detector_cache:
            return variant_detector_cache[key]
        if not components:
            detector = PIDSOracle(base_detector)
        else:
            from detection.inference.registry import load_e0_runtime
            from detection.training.rules import HybridGNNRuleDetector

            base_config, _base_metrics = load_e0_runtime(base_detector)
            threshold_doc = base_config.get("threshold")
            threshold_override = None
            if isinstance(threshold_doc, dict):
                value = threshold_doc.get(
                    "inference_threshold",
                    threshold_doc.get("threshold"),
                )
                if value is not None:
                    threshold_override = float(value)
            post_filter = base_config.get("post_filter")
            post_filter = post_filter if isinstance(post_filter, dict) else {}
            detector = HybridGNNRuleDetector(
                base_gnn=base_detector,
                g1_rule_path=str(RULE_ARTIFACT_DIR / "g1" / "g1_rule.pkl"),
                g2_rule_path=str(RULE_ARTIFACT_DIR / "g2" / "g2_rule.pkl"),
                gnn_artifact_dir=base_config.get("pidsmaker_artifact_root"),
                gnn_threshold_override=threshold_override,
                gnn_suppress_system_resource_alerts_enabled=bool(
                    post_filter.get("system_resource_alerts", False)
                ),
                rule_components=components,
            )
        variant_detector_cache[key] = detector
        return detector

    def predict_variant_nodes(detector: Any, sql_path: Path) -> List[Dict[str, Any]]:
        if hasattr(detector, "predict_per_node_from_sql"):
            return detector.predict_per_node_from_sql(str(sql_path))
        return detector.predict_per_node(str(sql_path))

    for base_detector in base_detectors:
        public_detector = _variant_public_detector(base_detector)
        current_components = (
            list(RULE_COMPONENTS.get(public_detector, ()))
            if public_detector else []
        )
        for variant, source_detectors in _variant_source_detectors(base_detector):
            tp = fp = tn = fn = flagged = gt_count = all_nodes = 0
            wall_sec = 0.0
            for scenario_dir in scenario_dirs:
                sid = scenario_dir.name
                input_dir = _scenario_input_dir(scenario_dir)
                gt = json.loads((input_dir / "gt.json").read_text())
                catalog = _sql_node_catalog(input_dir / "clean.strace.sql")
                if use_runtime_variants:
                    detector = variant_detector(base_detector, source_detectors)
                    nodes = predict_variant_nodes(
                        detector,
                        input_dir / "clean.strace.sql",
                    )
                else:
                    evidence_path = scenario_dir / "node_evidence.json"
                    evidence_doc = (
                        json.loads(evidence_path.read_text())
                        if evidence_path.exists() else {}
                    )
                    nodes = _merged_or_nodes_from_evidence(
                        evidence_doc,
                        source_detectors,
                    )
                metrics, _evidence = _e0_compute_metrics(nodes, gt, catalog)
                tp += int(metrics["tp"])
                fp += int(metrics["fp"])
                tn += int(metrics["tn"])
                fn += int(metrics["fn"])
                flagged += int(metrics["flagged_count"])
                gt_count += int(metrics["gt_count"])
                all_nodes += int(metrics["all_nodes_count"])
                wall_sec += _scenario_wall_sec(
                    current_rows,
                    sid,
                    source_detectors,
                    0,
                )

            precision = tp / (tp + fp) if (tp + fp) else None
            recall = tp / (tp + fn) if (tp + fn) else None
            variant_components = _rule_components_for_sources(source_detectors)
            out.append({
                "base_detector": base_detector,
                "variant": variant,
                "source_detectors": "+".join(source_detectors),
                "rule_components": "+".join(variant_components),
                "is_current_runtime": variant_components == current_components,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "flagged_count": flagged,
                "gt_count": gt_count,
                "all_nodes_count": all_nodes,
                "precision": precision,
                "recall": recall,
                "mcc": _mcc(tp, fp, tn, fn),
                "wall_sec": wall_sec,
            })
    return out


def _write_hybrid_merge_summary(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    fields = [
        "base_detector",
        "variant",
        "source_detectors",
        "rule_components",
        "is_current_runtime",
        "tp",
        "fp",
        "tn",
        "fn",
        "flagged_count",
        "gt_count",
        "all_nodes_count",
        "precision",
        "recall",
        "mcc",
        "wall_sec",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def _hybrid_merge_print_table(rows: Sequence[Dict[str, Any]]) -> None:
    headers = ["base", "variant", "current", "TP", "FP", "FN", "Precision", "Recall", "MCC"]
    table = []
    for row in rows:
        table.append([
            row["base_detector"],
            row["variant"],
            "yes" if _csv_bool(row.get("is_current_runtime")) else "",
            row["tp"],
            row["fp"],
            row["fn"],
            _fmt(row.get("precision"), 3),
            _fmt(row.get("recall"), 3),
            _fmt(row.get("mcc"), 3),
        ])
    _print_table(headers, table)


def hybrid_merge_main(argv=None) -> int:
    args = hybrid_merge_parse_args(argv)
    output = Path(args.output)
    if not output.is_absolute():
        output = PROJECT_ROOT / output
    rows = _hybrid_merge_summary_rows(
        result_dir=RESULT_DIR,
        base_detectors=args.base_detectors,
        whitelist=args.scenarios,
    )
    _write_hybrid_merge_summary(output, rows)
    print("\n== E0 Hybrid Merge Diagnostic ==")
    _hybrid_merge_print_table(rows)
    print(f"\nsummary: {output}")
    return 0


def _threshold_orthrus_rows(
    *,
    detector: str,
    cases: Sequence[Dict[str, Any]],
    threshold: float,
    mode: str,
    system_suffix: str,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for case in cases:
        metrics = _evaluate_threshold_case(case, threshold, mode)
        rows.append({
            "Scenario": case["scenario_id"],
            "System": f"{detector}_{system_suffix}",
            "TP": metrics["tp"],
            "FP": metrics["fp"],
            "TN": metrics["tn"],
            "FN": metrics["fn"],
            "Precision": metrics["precision"] if metrics["precision"] is not None else "",
            "MCC": metrics["mcc"] if metrics["mcc"] is not None else "",
        })
    return rows


def _write_calibration_summary(rows: List[Dict[str, Any]]) -> None:
    CALIBRATION_DIR.mkdir(parents=True, exist_ok=True)
    fields = [
        "detector",
        "mode",
        "calibration_dir",
        "test_dir",
        "calibration_scenario_count",
        "test_scenario_count",
        "selected_threshold",
        "guard_max_scenario_mcc_drop",
        "mcc_tolerance_for_recall_guard",
        "guard_worst_scenario",
        "guard_worst_mcc_drop",
        "applied_to_test_results",
        "apply_skip_reason",
        "calibration_tp",
        "calibration_fp",
        "calibration_tn",
        "calibration_fn",
        "calibration_flagged",
        "calibration_precision",
        "calibration_recall",
        "calibration_mcc",
        "test_current_tp",
        "test_current_fp",
        "test_current_tn",
        "test_current_fn",
        "test_current_flagged",
        "test_current_precision",
        "test_current_recall",
        "test_current_mcc",
        "test_calibrated_tp",
        "test_calibrated_fp",
        "test_calibrated_tn",
        "test_calibrated_fn",
        "test_calibrated_flagged",
        "test_calibrated_precision",
        "test_calibrated_recall",
        "test_calibrated_mcc",
        "delta_mcc",
    ]
    merged: Dict[str, Dict[str, Any]] = {}
    if CALIBRATION_SUMMARY_CSV.exists():
        with open(CALIBRATION_SUMMARY_CSV, newline="") as f:
            for row in csv.DictReader(f):
                detector = str(row.get("detector", ""))
                if detector:
                    merged[detector] = dict(row)
    for row in rows:
        detector = str(row.get("detector", ""))
        if detector:
            merged[detector] = row
    with open(CALIBRATION_SUMMARY_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for detector in sorted(merged):
            row = merged[detector]
            writer.writerow({k: row.get(k, "") for k in fields})


def _write_calibration_orthrus(rows: List[Dict[str, Any]]) -> None:
    CALIBRATION_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["Scenario", "System", "TP", "FP", "TN", "FN", "Precision", "MCC"]
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if CALIBRATION_ORTHRUS_CSV.exists():
        with open(CALIBRATION_ORTHRUS_CSV, newline="") as f:
            for row in csv.DictReader(f):
                merged[(str(row.get("Scenario", "")), str(row.get("System", "")))] = dict(row)
    for row in rows:
        merged[(str(row.get("Scenario", "")), str(row.get("System", "")))] = row
    with open(CALIBRATION_ORTHRUS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for key in sorted(merged):
            row = merged[key]
            writer.writerow({k: row.get(k, "") for k in fields})


def _patch_runtime_threshold_manifest(
    *,
    runtime_dir: Path,
    detector: str,
    threshold: float,
    calibration_summary: Path,
    calibration_orthrus: Path,
    source_type: str = "independent_calibration_split",
    source_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    manifest_path = runtime_dir / "manifest.json"
    if not manifest_path.exists():
        return
    manifest = json.loads(manifest_path.read_text())
    threshold_doc = manifest.get("threshold")
    if not isinstance(threshold_doc, dict):
        threshold_doc = {}
    threshold_doc["inference_threshold"] = float(threshold)
    threshold_doc["calibration_source"] = {
        "type": source_type,
        "detector": detector,
        "summary_csv": str(calibration_summary),
        "orth_style_csv": str(calibration_orthrus),
    }
    if source_metadata:
        threshold_doc["calibration_source"].update(source_metadata)
    if detector == "orthrus":
        threshold_doc["threshold_override_disables_kmeans"] = True
    manifest["threshold"] = threshold_doc
    manifest["calibration_applied"] = {
        "detector": detector,
        "selected_threshold": float(threshold),
        "source_type": source_type,
        "summary_csv": str(calibration_summary),
        "orth_style_csv": str(calibration_orthrus),
    }
    if source_metadata:
        manifest["calibration_applied"].update(source_metadata)
    manifest_path.write_text(json.dumps(manifest, indent=2, default=str))


def _runtime_already_matches_calibrated_threshold(
    *,
    runtime_dir: Path,
    threshold: float,
    calibrated_metrics: Dict[str, Any],
) -> bool:
    manifest_path = runtime_dir / "manifest.json"
    if not manifest_path.exists():
        return False
    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception:
        return False

    threshold_doc = manifest.get("threshold")
    if not isinstance(threshold_doc, dict):
        return False
    runtime_threshold = threshold_doc.get("inference_threshold")
    if runtime_threshold is None:
        return False
    if not math.isclose(float(runtime_threshold), float(threshold), rel_tol=0.0, abs_tol=1e-9):
        return False

    metrics = manifest.get("e0_metrics") or {}
    key_pairs = [
        ("tp", "test_calibrated_tp"),
        ("fp", "test_calibrated_fp"),
        ("tn", "test_calibrated_tn"),
        ("fn", "test_calibrated_fn"),
        ("flagged_count", "test_calibrated_flagged"),
    ]
    for runtime_key, calibrated_key in key_pairs:
        if int(metrics.get(runtime_key) or 0) != int(calibrated_metrics.get(calibrated_key) or 0):
            return False
    return True


def _threshold_calibration_print_table(rows: List[Dict[str, Any]]) -> None:
    headers = [
        "detector",
        "thr",
        "guard worst",
        "calib P/R/MCC",
        "test current P/R/MCC",
        "test calibrated P/R/MCC",
        "delta MCC",
    ]
    table = []
    for row in rows:
        table.append([
            row["detector"],
            _fmt(row["selected_threshold"], 6),
            _fmt(row.get("guard_worst_mcc_drop"), 3),
            (
                f"{_fmt(row['calibration_precision'], 3)}/"
                f"{_fmt(row['calibration_recall'], 3)}/"
                f"{_fmt(row['calibration_mcc'], 3)}"
            ),
            (
                f"{_fmt(row['test_current_precision'], 3)}/"
                f"{_fmt(row['test_current_recall'], 3)}/"
                f"{_fmt(row['test_current_mcc'], 3)}"
            ),
            (
                f"{_fmt(row['test_calibrated_precision'], 3)}/"
                f"{_fmt(row['test_calibrated_recall'], 3)}/"
                f"{_fmt(row['test_calibrated_mcc'], 3)}"
            ),
            _fmt(row.get("delta_mcc"), 3),
        ])

    widths = [len(h) for h in headers]
    for line in table:
        for i, cell in enumerate(line):
            widths[i] = max(widths[i], len(str(cell)))

    def emit(vals: Sequence[Any]) -> None:
        print("  " + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals)))

    emit(headers)
    print("  " + "  ".join("-" * w for w in widths))
    for line in table:
        emit(line)


def _threshold_print_table(rows: List[Dict[str, Any]]) -> None:
    headers = ["detector", "current P/R/MCC", "best-MCC thr", "best P/R/MCC", "recall>=0.8 P/MCC"]
    table = []
    for row in rows:
        table.append([
            row["detector"],
            (
                f"{_fmt(row['current_precision'], 3)}/"
                f"{_fmt(row['current_recall'], 3)}/"
                f"{_fmt(row['current_mcc'], 3)}"
            ),
            _fmt(row.get("best_mcc_threshold"), 6),
            (
                f"{_fmt(row['best_mcc_precision'], 3)}/"
                f"{_fmt(row['best_mcc_recall'], 3)}/"
                f"{_fmt(row['best_mcc'], 3)}"
            ),
            (
                f"{_fmt(row.get('best_precision_recall_ge_0_80_precision'), 3)}/"
                f"{_fmt(row.get('best_precision_recall_ge_0_80_mcc'), 3)}"
            ),
        ])

    widths = [len(h) for h in headers]
    for line in table:
        for i, cell in enumerate(line):
            widths[i] = max(widths[i], len(str(cell)))

    def emit(vals: Sequence[Any]) -> None:
        print("  " + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals)))

    emit(headers)
    print("  " + "  ".join("-" * w for w in widths))
    for line in table:
        emit(line)


def _threshold_loso_print_table(rows: List[Dict[str, Any]]) -> None:
    headers = ["detector", "current P/R/MCC", "LOSO P/R/MCC", "delta MCC", "threshold median"]
    table = []
    for row in rows:
        table.append([
            row["detector"],
            (
                f"{_fmt(row['current_precision'], 3)}/"
                f"{_fmt(row['current_recall'], 3)}/"
                f"{_fmt(row['current_mcc'], 3)}"
            ),
            (
                f"{_fmt(row['loso_precision'], 3)}/"
                f"{_fmt(row['loso_recall'], 3)}/"
                f"{_fmt(row['loso_mcc'], 3)}"
            ),
            _fmt(row.get("delta_mcc"), 3),
            _fmt(row.get("selected_threshold_median"), 6),
        ])

    widths = [len(h) for h in headers]
    for line in table:
        for i, cell in enumerate(line):
            widths[i] = max(widths[i], len(str(cell)))

    def emit(vals: Sequence[Any]) -> None:
        print("  " + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals)))

    emit(headers)
    print("  " + "  ".join("-" * w for w in widths))
    for line in table:
        emit(line)


def threshold_sweep_main(argv=None) -> int:
    args = threshold_parse_args(argv)
    detectors = list(args.detectors)
    for detector in detectors:
        if detector not in DETECTORS:
            raise SystemExit(f"[abort] unknown detector {detector}; valid={DETECTORS}")
        if _sweep_mode(detector) is None:
            raise SystemExit(
                f"[abort] detector {detector} has no scalar threshold sweep mode yet"
            )
    assert_detector_artifacts_ready(detectors)

    scenario_dirs = _scenario_dirs(args.scenarios)
    print(
        f"E0 threshold sweep: {len(scenario_dirs)} scenarios, "
        f"{len(detectors)} detectors"
    )

    summary_rows: List[Dict[str, Any]] = []
    detail_rows: List[Dict[str, Any]] = []
    loso_summary_rows: List[Dict[str, Any]] = []
    loso_detail_rows: List[Dict[str, Any]] = []
    loso_orthrus_rows: List[Dict[str, Any]] = []
    for detector in detectors:
        mode = _sweep_mode(detector)
        assert mode is not None
        oracle = PIDSOracle(detector)
        scenario_cases: List[Dict[str, Any]] = []

        print(f"\n[detector] {detector}", flush=True)
        for scenario_dir in scenario_dirs:
            input_dir = _scenario_input_dir(scenario_dir)
            catalog = _sql_node_catalog(input_dir / "clean.strace.sql")
            scenario_all_ids = set(catalog)
            scenario_gt_ids = _load_gt_ids(input_dir / "gt.json")
            nodes = _load_or_predict_nodes(oracle, detector, scenario_dir)

            # Prefix node ids by scenario in the aggregate to avoid collisions.
            prefix = scenario_dir.name + ":"
            case_all_ids: Set[str] = set()
            case_gt_ids: Set[str] = set()
            case_nodes: List[Dict[str, Any]] = []
            for idx in scenario_all_ids:
                case_all_ids.add(prefix + str(idx))
            for idx in scenario_gt_ids:
                case_gt_ids.add(prefix + str(idx))
            for nd in nodes:
                nd2 = dict(nd)
                idx = nd.get("node_index_id")
                if idx is not None:
                    nd2["_global_node_id"] = prefix + str(int(idx))
                case_nodes.append(nd2)
            scenario_cases.append({
                "scenario_id": scenario_dir.name,
                "all_ids": case_all_ids,
                "gt_ids": case_gt_ids,
                "nodes": case_nodes,
            })
            print(f"  {scenario_dir.name}: nodes={len(catalog)} gt={len(scenario_gt_ids)}")

        all_ids, gt_ids, all_nodes = _merge_cases(scenario_cases)
        current_flagged = {
            nd["_global_node_id"]
            for nd in all_nodes
            if nd.get("_global_node_id") is not None and int(nd.get("y_pred", 0)) == 1
        }
        current = _metrics(all_ids, gt_ids, current_flagged)

        sweep_rows: List[Dict[str, Any]] = []
        for threshold in _candidate_thresholds(float(nd.get("score", 0.0)) for nd in all_nodes):
            flagged = _flagged_for_threshold(all_nodes, threshold, mode)
            metrics = _metrics(all_ids, gt_ids, flagged)
            row = {
                "detector": detector,
                "threshold": threshold,
                "_threshold_preference": _threshold_preference(threshold, mode),
                **metrics,
            }
            sweep_rows.append(row)
            detail_rows.append({
                "detector": detector,
                "threshold": _fmt(threshold),
                "tp": metrics["tp"],
                "fp": metrics["fp"],
                "tn": metrics["tn"],
                "fn": metrics["fn"],
                "flagged": metrics["flagged"],
                "precision": _fmt(metrics["precision"]),
                "recall": _fmt(metrics["recall"]),
                "mcc": _fmt(metrics["mcc"]),
            })

        best_mcc: Optional[Dict[str, Any]] = None
        for row in sweep_rows:
            if _better(row, best_mcc, "mcc"):
                best_mcc = row
        if best_mcc is None:
            best_mcc = {"threshold": "", **current}

        best_p50 = _best_under_recall_floor(sweep_rows, 0.50)
        best_p80 = _best_under_recall_floor(sweep_rows, 0.80)
        current_threshold = _current_threshold(oracle, detector)

        summary_rows.append({
            "detector": detector,
            "mode": mode,
            "scenario_count": len(scenario_dirs),
            "node_count": len(all_ids),
            "gt_count": len(gt_ids),
            "current_threshold": _fmt(current_threshold),
            "current_tp": current["tp"],
            "current_fp": current["fp"],
            "current_tn": current["tn"],
            "current_fn": current["fn"],
            "current_flagged": current["flagged"],
            "current_precision": current["precision"],
            "current_recall": current["recall"],
            "current_mcc": current["mcc"],
            "best_mcc_threshold": best_mcc.get("threshold"),
            "best_mcc_tp": best_mcc["tp"],
            "best_mcc_fp": best_mcc["fp"],
            "best_mcc_tn": best_mcc["tn"],
            "best_mcc_fn": best_mcc["fn"],
            "best_mcc_flagged": best_mcc["flagged"],
            "best_mcc_precision": best_mcc["precision"],
            "best_mcc_recall": best_mcc["recall"],
            "best_mcc": best_mcc["mcc"],
            "best_precision_recall_ge_0_50_threshold": "" if best_p50 is None else best_p50["threshold"],
            "best_precision_recall_ge_0_50_precision": "" if best_p50 is None else best_p50["precision"],
            "best_precision_recall_ge_0_50_recall": "" if best_p50 is None else best_p50["recall"],
            "best_precision_recall_ge_0_50_mcc": "" if best_p50 is None else best_p50["mcc"],
            "best_precision_recall_ge_0_80_threshold": "" if best_p80 is None else best_p80["threshold"],
            "best_precision_recall_ge_0_80_precision": "" if best_p80 is None else best_p80["precision"],
            "best_precision_recall_ge_0_80_recall": "" if best_p80 is None else best_p80["recall"],
            "best_precision_recall_ge_0_80_mcc": "" if best_p80 is None else best_p80["mcc"],
        })

        loso_summary, loso_detail, loso_orthrus = _loso_threshold_calibration(
            detector,
            mode,
            scenario_cases,
            current,
            current_threshold,
        )
        if loso_summary is not None:
            loso_summary_rows.append(loso_summary)
            loso_detail_rows.extend(loso_detail)
            loso_orthrus_rows.extend(loso_orthrus)

    _write_summary(summary_rows)
    _write_detail(detail_rows)
    _write_loso_summary(loso_summary_rows)
    _write_loso_detail(loso_detail_rows)
    _write_loso_orthrus(loso_orthrus_rows)
    print("\n== Threshold sweep summary ==")
    _threshold_print_table(summary_rows)
    if loso_summary_rows:
        print("\n== Threshold LOSO calibration summary ==")
        _threshold_loso_print_table(loso_summary_rows)
    print(f"\nsummary: {SUMMARY_CSV}")
    print(f"detail:  {DETAIL_CSV}")
    print(f"loso summary: {LOSO_SUMMARY_CSV}")
    print(f"loso detail:  {LOSO_DETAIL_CSV}")
    print(f"loso orth-style: {LOSO_ORTHRUS_CSV}")
    return 0


def threshold_calibrate_main(argv=None) -> int:
    args = threshold_calibrate_parse_args(argv)
    detector = args.detector
    if detector not in DETECTORS:
        raise SystemExit(f"[abort] unknown detector {detector}; valid={DETECTORS}")
    mode = _sweep_mode(detector)
    if mode is None:
        raise SystemExit(
            f"[abort] detector {detector} has no scalar threshold calibration mode yet"
        )
    assert_detector_artifacts_ready([detector])

    calibration_dir = _resolve_result_dir(args.calibration_dir)
    test_dir = _resolve_result_dir(args.test_dir)
    if not calibration_dir.exists():
        raise SystemExit(f"[abort] calibration dir not found: {calibration_dir}")
    if not test_dir.exists():
        raise SystemExit(f"[abort] test dir not found: {test_dir}")

    print("E0 independent threshold calibration")
    print(f"  detector        = {detector}")
    print(f"  calibration dir = {calibration_dir}")
    print(f"  test dir        = {test_dir}")

    oracle = PIDSOracle(detector)
    calibration_cases = _build_threshold_cases(
        result_dir=calibration_dir,
        detector=detector,
        oracle=oracle,
        whitelist=args.scenarios,
    )
    test_cases = _build_threshold_cases(
        result_dir=test_dir,
        detector=detector,
        oracle=oracle,
        whitelist=args.scenarios,
    )

    selected = _select_best_threshold_with_scenario_guard(
        calibration_cases,
        mode,
        max_scenario_mcc_drop=args.max_scenario_mcc_drop,
        mcc_tolerance_for_recall_guard=args.mcc_tolerance_for_recall_guard,
    )
    if selected is None:
        raise SystemExit(
            "[abort] no candidate threshold found in calibration split "
            "under the per-scenario guard"
        )

    threshold = float(selected["threshold"])
    test_current = _current_metrics_from_cases(test_cases)
    test_calibrated = _evaluate_threshold_cases(test_cases, threshold, mode)
    current_mcc = test_current.get("mcc")
    calibrated_mcc = test_calibrated.get("mcc")
    delta_mcc = (
        None if current_mcc is None or calibrated_mcc is None
        else float(calibrated_mcc) - float(current_mcc)
    )

    summary_row = {
        "detector": detector,
        "mode": mode,
        "calibration_dir": str(calibration_dir),
        "test_dir": str(test_dir),
        "calibration_scenario_count": len(calibration_cases),
        "test_scenario_count": len(test_cases),
        "selected_threshold": threshold,
        "guard_max_scenario_mcc_drop": selected.get("guard_max_scenario_mcc_drop"),
        "mcc_tolerance_for_recall_guard": args.mcc_tolerance_for_recall_guard,
        "guard_worst_scenario": selected.get("guard_worst_scenario"),
        "guard_worst_mcc_drop": selected.get("guard_worst_mcc_drop"),
        "applied_to_test_results": False,
        "apply_skip_reason": "",
        "calibration_tp": selected["tp"],
        "calibration_fp": selected["fp"],
        "calibration_tn": selected["tn"],
        "calibration_fn": selected["fn"],
        "calibration_flagged": selected["flagged"],
        "calibration_precision": selected["precision"],
        "calibration_recall": selected["recall"],
        "calibration_mcc": selected["mcc"],
        "test_current_tp": test_current["tp"],
        "test_current_fp": test_current["fp"],
        "test_current_tn": test_current["tn"],
        "test_current_fn": test_current["fn"],
        "test_current_flagged": test_current["flagged"],
        "test_current_precision": test_current["precision"],
        "test_current_recall": test_current["recall"],
        "test_current_mcc": test_current["mcc"],
        "test_calibrated_tp": test_calibrated["tp"],
        "test_calibrated_fp": test_calibrated["fp"],
        "test_calibrated_tn": test_calibrated["tn"],
        "test_calibrated_fn": test_calibrated["fn"],
        "test_calibrated_flagged": test_calibrated["flagged"],
        "test_calibrated_precision": test_calibrated["precision"],
        "test_calibrated_recall": test_calibrated["recall"],
        "test_calibrated_mcc": test_calibrated["mcc"],
        "delta_mcc": delta_mcc,
    }
    orthrus_rows = _threshold_orthrus_rows(
        detector=detector,
        cases=test_cases,
        threshold=threshold,
        mode=mode,
        system_suffix="threshold_calibrated",
    )

    print("\n== Independent calibration summary ==")
    _threshold_calibration_print_table([summary_row])
    if args.apply_to_test_results:
        if detector not in APPLY_THRESHOLD_DETECTORS:
            summary_row["apply_skip_reason"] = (
                f"threshold override is not runtime-reproducible for {detector}"
            )
            print(
                f"\n[skip] {detector} threshold diagnostics were not applied: "
                f"{summary_row['apply_skip_reason']}."
            )
        elif (
            test_current.get("mcc") is None
            or test_calibrated.get("mcc") is None
            or float(test_calibrated["mcc"]) <= float(test_current["mcc"])
        ):
            summary_row["apply_skip_reason"] = "calibrated test MCC did not improve"
            print(
                "\n[skip] calibrated threshold did not improve test MCC; "
                "E0 results and detector artifacts were not modified."
            )
        elif (
            (historical := _historical_runtime_metrics(detector)) is not None
            and _runtime_rank(
                _threshold_candidate_runtime_row(
                    detector,
                    test_calibrated,
                    len(test_cases),
                )
            ) <= _runtime_rank(historical)
        ):
            summary_row["apply_skip_reason"] = "calibrated test MCC did not improve historical best"
            print(
                "\n[skip] calibrated threshold improves current rows but not "
                "the detector's historical best; E0 results and detector artifacts "
                "were not modified."
            )
        else:
            updated_rows = _apply_threshold_to_e0_result_dir(
                result_dir=test_dir,
                detector=detector,
                threshold=threshold,
                mode=mode,
                oracle=oracle,
                whitelist=args.scenarios,
            )
            runtime_updates = write_detector_best_runtime_bundles(
                updated_rows,
                result_dir=test_dir,
            )
            bundle = runtime_updates.get(detector)
            if bundle and bundle.get("updated"):
                runtime_dir = Path(bundle["path"])
                _patch_runtime_threshold_manifest(
                    runtime_dir=runtime_dir,
                    detector=detector,
                    threshold=threshold,
                    calibration_summary=CALIBRATION_SUMMARY_CSV,
                    calibration_orthrus=CALIBRATION_ORTHRUS_CSV,
                )
                summary_row["applied_to_test_results"] = True
                print(
                    f"\n[apply] updated {detector} rows/evidence and runtime: "
                    f"{runtime_dir}"
                )
            elif bundle:
                runtime_dir = Path(bundle["path"])
                if _runtime_already_matches_calibrated_threshold(
                    runtime_dir=runtime_dir,
                    threshold=threshold,
                    calibrated_metrics=summary_row,
                ):
                    summary_row["applied_to_test_results"] = True
                    summary_row["apply_skip_reason"] = "already current historical runtime"
                    print(
                        f"\n[apply] {detector} calibrated threshold already matches "
                        f"current historical runtime: {runtime_dir}"
                    )
                else:
                    summary_row["apply_skip_reason"] = "historical runtime was not improved"
                    print(
                        f"\n[apply] test rows/evidence updated, but historical runtime "
                        f"for {detector} was not improved: {runtime_dir}"
                    )
            else:
                summary_row["apply_skip_reason"] = "no runtime bundle was produced"
                print(
                    f"\n[apply] test rows/evidence updated, but no runtime bundle "
                    f"was produced for {detector}"
                )
            hybrid_refresh = _refresh_dependent_hybrids(
                result_dir=test_dir,
                base_detector=detector,
                whitelist=args.scenarios,
            )
            for hybrid_detector, hybrid_row in hybrid_refresh.items():
                if hybrid_detector == "_runtime_updates" or not hybrid_row:
                    continue
                print(
                    f"[apply] refreshed dependent hybrid {hybrid_detector}: "
                    f"P/R/MCC="
                    f"{_fmt(hybrid_row.get('precision'), 3)}/"
                    f"{_fmt(hybrid_row.get('recall'), 3)}/"
                    f"{_fmt(hybrid_row.get('overall_mcc'), 3)}"
                )
            write_best_detector_config(
                _load_summary_rows(test_dir),
                result_dir=test_dir,
                out_path=test_dir / "best_detector_config.json",
            )
    _write_calibration_summary([summary_row])
    _write_calibration_orthrus(orthrus_rows)
    print(f"\nsummary:    {CALIBRATION_SUMMARY_CSV}")
    print(f"orth-style: {CALIBRATION_ORTHRUS_CSV}")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "audit":
        return audit_main(argv[1:])
    if argv and argv[0] == "threshold-sweep":
        return threshold_sweep_main(argv[1:])
    if argv and argv[0] == "threshold-calibrate":
        return threshold_calibrate_main(argv[1:])
    if argv and argv[0] == "hybrid-merge":
        return hybrid_merge_main(argv[1:])
    if argv and argv[0] == "refresh-e0":
        return refresh_e0_main(argv[1:])
    print("usage: python -m detection.diagnostics [audit|threshold-sweep|threshold-calibrate|hybrid-merge|refresh-e0] ...")
    print("internal diagnostics only; public detect CLI is scripts/run.py detect [collect|train-gnn|train-rules|e0] ...")
    return None


if __name__ == "__main__":
    raise SystemExit(main())
