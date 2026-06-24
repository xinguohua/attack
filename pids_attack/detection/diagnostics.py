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
from detection.pidsmaker import compute_metrics, load_eval_pkl  # noqa: E402
from detection.pidsmaker import SUPPORTED_DETECTORS  # noqa: E402


TRAINING_TRACE_DIR = PROJECT_ROOT / "detection" / "data" / "training_traces"
E0_RESULT_DIR = PROJECT_ROOT / "experiments" / "E0_detection" / "results_window"
E0_THRESHOLD_SUMMARY = E0_RESULT_DIR / "threshold_diagnostics" / "threshold_sweep_summary.csv"
E0_THRESHOLD_LOSO_SUMMARY = E0_RESULT_DIR / "threshold_diagnostics" / "threshold_loso_summary.csv"


def _fmt_float(value: Optional[float], digits: int = 3) -> str:
    if value is None:
        return "-"
    return f"{value:.{digits}f}"


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


if __name__ == "__main__":
    raise SystemExit(main())


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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.E0_detection.run import (  # noqa: E402
    DETECTORS,
    RESULT_DIR,
    _gt_sets,
    _sql_node_catalog,
    assert_detector_artifacts_ready,
)
from attack.oracle import PIDSOracle  # noqa: E402


DEFAULT_SWEEP_DETECTORS = ("magic", "orthrus", "threatrace", "g1")
OUT_DIR = RESULT_DIR / "threshold_diagnostics"
PER_NODE_DIR = OUT_DIR / "per_node"
SUMMARY_CSV = OUT_DIR / "threshold_sweep_summary.csv"
DETAIL_CSV = OUT_DIR / "threshold_sweep_detail.csv"
LOSO_SUMMARY_CSV = OUT_DIR / "threshold_loso_summary.csv"
LOSO_DETAIL_CSV = OUT_DIR / "threshold_loso_by_scenario.csv"
LOSO_ORTHRUS_CSV = OUT_DIR / "summary_orthrus_threshold_loso.csv"


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


def _scenario_dirs(whitelist: Optional[Sequence[str]]) -> List[Path]:
    dirs = []
    allowed = set(whitelist or [])
    for path in sorted(RESULT_DIR.iterdir()):
        if not path.is_dir():
            continue
        if path.name.startswith("threshold_"):
            continue
        if allowed and path.name not in allowed:
            continue
        if (path / "clean.strace.sql").exists() and (path / "gt.json").exists():
            dirs.append(path)
    if not dirs:
        raise SystemExit(f"[abort] no E0 scenario result dirs found under {RESULT_DIR}")
    return dirs


def _load_gt_ids(gt_path: Path) -> Set[int]:
    gt = json.loads(gt_path.read_text())
    _subj, _file, _net, total = _gt_sets(gt)
    return total


def _node_cache_path(scenario_id: str, detector: str) -> Path:
    return PER_NODE_DIR / f"{scenario_id}__{detector}.json"


def _load_or_predict_nodes(
    oracle: PIDSOracle,
    detector: str,
    scenario_dir: Path,
) -> List[Dict[str, Any]]:
    sql_path = scenario_dir / "clean.strace.sql"
    cache_path = _node_cache_path(scenario_dir.name, detector)
    sql_mtime = sql_path.stat().st_mtime
    if cache_path.exists():
        try:
            doc = json.loads(cache_path.read_text())
            if doc.get("sql_path") == str(sql_path) and doc.get("sql_mtime") == sql_mtime:
                return list(doc.get("nodes", []))
        except Exception:
            pass

    nodes = oracle.predict_per_node_from_sql(str(sql_path))
    PER_NODE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({
        "scenario_id": scenario_dir.name,
        "detector": detector,
        "sql_path": str(sql_path),
        "sql_mtime": sql_mtime,
        "nodes": nodes,
    }, indent=2))
    return nodes


def _current_threshold(oracle: PIDSOracle, detector: str) -> Optional[float]:
    det = oracle._ensure_detector()
    if detector == "g1":
        return float(getattr(det, "tau_lambda", 0.0))
    if detector == "g1g2":
        return float(getattr(det.g1, "tau_lambda", 0.0))
    if hasattr(det, "_get_engine"):
        engine = det._get_engine()
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
    with open(SUMMARY_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
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
    with open(DETAIL_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
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
    with open(LOSO_SUMMARY_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
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
    with open(LOSO_DETAIL_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def _write_loso_orthrus(rows: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["Scenario", "System", "TP", "FP", "TN", "FN", "Precision", "MCC"]
    with open(LOSO_ORTHRUS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


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
            catalog = _sql_node_catalog(scenario_dir / "clean.strace.sql")
            scenario_all_ids = set(catalog)
            scenario_gt_ids = _load_gt_ids(scenario_dir / "gt.json")
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


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "audit":
        return audit_main(argv[1:])
    if argv and argv[0] == "threshold-sweep":
        return threshold_sweep_main(argv[1:])
    print("usage: python -m detection.diagnostics [audit|threshold-sweep] ...")
    print("public: python scripts/run.py detect [audit|threshold-sweep] ...")
    return None


if __name__ == "__main__":
    raise SystemExit(main())
