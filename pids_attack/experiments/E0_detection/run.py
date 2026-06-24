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
       Orthrus-style TP/FP/TN/FN, Precision, and MCC.

The marker lines are stripped before detector inference. E0 intentionally uses
no scenario keyword GT and no noise filter.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.E0_detection.collector import (
    e0_collect_attack_only_scenario,
    e0_collect_scenario,
)
from experiments.E0_detection.gt_signature import (
    GT_SOURCE,
    SIGNATURE_VERSION,
    TRACE_MODE,
    load_signature_sets,
)
from attack.oracle import PIDSOracle


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
RESULT_DIR = PROJECT_ROOT / "experiments" / "E0_detection" / "results_window"
RULE_ARTIFACT_DIR = PROJECT_ROOT / "detection" / "data" / "hybrid_rules"
HYBRID_BASE_GNN = {
    "magic_g1g2": "magic",
    "orthrus_g1g2": "orthrus",
    "threatrace_g1g2": "threatrace",
}
GNN_REQUIRED_ARTIFACTS = {
    "magic": ("state_dict.pkl", "threshold.pkl", "train_distance.txt"),
    "orthrus": ("state_dict.pkl", "threshold.pkl", "neighbor_loader.pkl"),
    "threatrace": ("state_dict.pkl", "threshold.pkl"),
}
RULE_REQUIRED_ARTIFACTS = ("g1_rule.pkl", "g2_rule.pkl")


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
    return ap.parse_args(argv)


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


def _gnn_best_model_dir(detector_name: str) -> Path:
    from detection.pidsmaker import PIDSMAKER_DIR, _build_args, _get_yml_cfg_safe

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
            path = Path(rule_dir) / filename
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


_INSERT_SUBJECT_RE = re.compile(
    r"INSERT INTO subject_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'((?:[^'\\]|\\.)*)',\s*'((?:[^'\\]|\\.)*)',\s*(\d+)\)",
    re.IGNORECASE,
)
_INSERT_FILE_RE = re.compile(
    r"INSERT INTO file_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'((?:[^'\\]|\\.)*)',\s*(\d+)\)",
    re.IGNORECASE,
)
_INSERT_NETFLOW_RE = re.compile(
    r"INSERT INTO netflow_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*(\d+)\)",
    re.IGNORECASE,
)


def _unescape_sql_value(value: str) -> str:
    return value.replace("''", "'").replace("\\\\", "\\")


def _sql_node_catalog(sql_path: Path) -> Dict[int, Dict[str, Any]]:
    """Map SQL index_id back to readable node metadata for evidence files."""
    text = Path(sql_path).read_text(errors="ignore")
    catalog: Dict[int, Dict[str, Any]] = {}

    for m in _INSERT_SUBJECT_RE.finditer(text):
        _uuid, hash_id, path, cmd, idx = m.groups()
        index_id = int(idx)
        path = _unescape_sql_value(path)
        cmd = _unescape_sql_value(cmd)
        catalog[index_id] = {
            "node_type": "subject",
            "hash_id": hash_id,
            "path": path,
            "cmd": cmd,
            "label": f"{path} | {cmd}".strip(),
        }

    for m in _INSERT_FILE_RE.finditer(text):
        _uuid, hash_id, path, idx = m.groups()
        index_id = int(idx)
        path = _unescape_sql_value(path)
        catalog[index_id] = {
            "node_type": "file",
            "hash_id": hash_id,
            "path": path,
            "cmd": "",
            "label": path,
        }

    for m in _INSERT_NETFLOW_RE.finditer(text):
        _uuid, hash_id, src_addr, src_port, dst_addr, dst_port, idx = m.groups()
        index_id = int(idx)
        local = f"{src_addr}:{src_port}" if (src_addr or src_port) else ""
        remote = f"{dst_addr}:{dst_port}"
        label = f"{local}->{remote}" if local else remote
        catalog[index_id] = {
            "node_type": "netflow",
            "hash_id": hash_id,
            "path": "",
            "cmd": "",
            "label": label,
        }

    return catalog


def _gt_sets(gt: Dict[str, Any]) -> Tuple[Set[int], Set[int], Set[int], Set[int]]:
    gt_subj = {int(x) for x in gt.get("gt_subject_index_ids", [])}
    gt_file = {int(x) for x in gt.get("gt_file_index_ids", [])}
    gt_net = {int(x) for x in gt.get("gt_netflow_index_ids", [])}
    gt_total = gt_subj | gt_file | gt_net
    return gt_subj, gt_file, gt_net, gt_total


def _flagged_ids(nodes_info: Iterable[Dict[str, Any]]) -> Set[int]:
    flagged: Set[int] = set()
    for nd in nodes_info:
        index_id = nd.get("node_index_id")
        if index_id is None:
            continue
        if int(nd.get("y_pred", 0)) == 1:
            flagged.add(int(index_id))
    return flagged


def _node_precision(tp: int, fp: int) -> Optional[float]:
    den = tp + fp
    return (tp / den) if den else None


def _mcc(tp: int, fp: int, tn: int, fn: int) -> Optional[float]:
    den = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return ((tp * tn - fp * fn) / math.sqrt(den)) if den else None


def _node_record(
    nodes_by_id: Dict[int, Dict[str, Any]],
    catalog: Dict[int, Dict[str, Any]],
    index_id: int,
) -> Dict[str, Any]:
    nd = nodes_by_id.get(index_id, {})
    meta = catalog.get(index_id, {})
    return {
        "node_index_id": index_id,
        "node_type": meta.get("node_type", "unknown"),
        "label": meta.get("label", nd.get("label", "")),
        "score": float(nd.get("score", 0.0)),
        "y_pred": int(nd.get("y_pred", 0)),
        "path": meta.get("path", ""),
        "cmd": meta.get("cmd", ""),
    }


def _sort_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        records,
        key=lambda r: (
            -float(r.get("score", 0.0)),
            r.get("node_type", ""),
            r.get("node_index_id", -1),
        ),
    )


def compute_metrics(
    nodes_info: List[Dict[str, Any]],
    gt: Dict[str, Any],
    node_catalog: Dict[int, Dict[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Compute Orthrus-style node-level GT-vs-flagged metrics.

    TP/FP/TN/FN are over node ids. Precision and MCC follow the
    Orthrus-style node-level table used for the E0 paper result.
    """
    nodes_by_id = {
        int(nd["node_index_id"]): nd
        for nd in nodes_info
        if nd.get("node_index_id") is not None
    }
    flagged_ids = _flagged_ids(nodes_info)
    _gt_subj, _gt_file, _gt_net, gt_total = _gt_sets(gt)

    gt_flagged = flagged_ids & gt_total
    gt_missed = gt_total - flagged_ids
    flagged_outside_gt = flagged_ids - gt_total
    all_nodes_count = int(gt.get("all_node_count", {}).get("total", 0) or 0)
    gt_count = len(gt_total)
    tp = len(gt_flagged)
    fp = len(flagged_outside_gt)
    fn = len(gt_missed)
    tn = max(0, all_nodes_count - tp - fp - fn)

    metrics = {
        "all_nodes_count": all_nodes_count,
        "flagged_count": len(flagged_ids),
        "gt_count": gt_count,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "node_precision": _node_precision(tp, fp),
        "mcc": _mcc(tp, fp, tn, fn),
    }

    evidence = {
        "gt_nodes": _sort_records([
            _node_record(nodes_by_id, node_catalog, i) for i in gt_total
        ]),
        "flagged_nodes": _sort_records([
            _node_record(nodes_by_id, node_catalog, i) for i in flagged_ids
        ]),
        "gt_flagged_nodes": _sort_records([
            _node_record(nodes_by_id, node_catalog, i) for i in gt_flagged
        ]),
        "gt_missed_nodes": _sort_records([
            _node_record(nodes_by_id, node_catalog, i) for i in gt_missed
        ]),
        "flagged_outside_gt_nodes": _sort_records([
            _node_record(nodes_by_id, node_catalog, i) for i in flagged_outside_gt
        ]),
    }

    return metrics, evidence


_SUMMARY_KEYS = [
    "scenario_id",
    "detector",
    "valid",
    "all_steps_passed",
    "final_attack_succeeded",
    "all_nodes_count",
    "flagged_count",
    "gt_count",
    "tp",
    "fp",
    "tn",
    "fn",
    "node_precision",
    "mcc",
    "wall_sec",
    "failed_step",
    "gt_source",
]

_ORTHRUS_SUMMARY_KEYS = [
    "Scenario",
    "System",
    "TP",
    "FP",
    "TN",
    "FN",
    "Precision",
    "MCC",
]


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_SUMMARY_KEYS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in _SUMMARY_KEYS})


def _write_orthrus_summary(path: Path, rows: List[Dict[str, Any]]) -> None:
    out_rows: List[Dict[str, Any]] = []
    for row in rows:
        scenario_id = str(row.get("scenario_id", ""))
        det = str(row.get("detector", ""))
        if not scenario_id or not det:
            continue
        tp = int(row.get("tp") or 0)
        fp = int(row.get("fp") or 0)
        tn = int(row.get("tn") or 0)
        fn = int(row.get("fn") or 0)
        precision = _node_precision(tp, fp)
        mcc = _mcc(tp, fp, tn, fn)
        out_rows.append({
            "Scenario": scenario_id,
            "System": det,
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
            "Precision": precision if precision is not None else "",
            "MCC": mcc if mcc is not None else "",
        })

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_ORTHRUS_SUMMARY_KEYS)
        writer.writeheader()
        for row in out_rows:
            writer.writerow({k: row.get(k) for k in _ORTHRUS_SUMMARY_KEYS})


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
    detectors: List[str] = list(args.detectors)
    for d in detectors:
        if d not in DETECTORS:
            raise SystemExit(f"[abort] unknown detector {d}; valid={DETECTORS}")
    assert_detector_artifacts_ready(detectors)
    scenarios = load_scenarios(args.scenarios)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    # Reuse detector objects across scenarios so each model loads once.
    oracle_pool: Dict[str, PIDSOracle] = {name: PIDSOracle(name) for name in detectors}

    summary_all_rows: List[Dict[str, Any]] = []

    for scenario in scenarios:
        sid = scenario["scenario_id"]
        scen_dir = RESULT_DIR / sid
        scen_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n=== scenario: {sid} ===", flush=True)

        t0 = time.time()
        try:
            attack_only_dir = scen_dir / "attack_only"
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
                scen_dir,
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

        (scen_dir / "detector_results.json").write_text(
            json.dumps(detector_results, indent=2, default=str)
        )
        (scen_dir / "node_evidence.json").write_text(
            json.dumps(node_evidence, indent=2, default=str)
        )
        _write_csv(scen_dir / "summary.csv", scen_rows)

    _write_csv(RESULT_DIR / "summary_all.csv", summary_all_rows)
    _write_orthrus_summary(RESULT_DIR / "summary_orthrus.csv", summary_all_rows)
    print(
        f"\n=== E0 done: {len(summary_all_rows)} rows -> "
        f"{RESULT_DIR / 'summary_all.csv'} ===",
        flush=True,
    )


if __name__ == "__main__":
    main()
