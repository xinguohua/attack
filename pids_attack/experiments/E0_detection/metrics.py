"""E0 node-level metric and summary helpers."""
from __future__ import annotations

import csv
import math
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

_INSERT_SUBJECT_RE = re.compile(
    r"INSERT INTO subject_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'((?:''|[^'\\]|\\.)*)',\s*'((?:''|[^'\\]|\\.)*)',\s*(\d+)\)",
    re.IGNORECASE,
)
_INSERT_FILE_RE = re.compile(
    r"INSERT INTO file_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'((?:''|[^'\\]|\\.)*)',\s*(\d+)\)",
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
    "Recall",
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
        recall = (tp / (tp + fn)) if (tp + fn) else None
        mcc = _mcc(tp, fp, tn, fn)
        out_rows.append({
            "Scenario": scenario_id,
            "System": det,
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
            "Precision": precision if precision is not None else "",
            "Recall": recall if recall is not None else "",
            "MCC": mcc if mcc is not None else "",
        })

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_ORTHRUS_SUMMARY_KEYS)
        writer.writeheader()
        for row in out_rows:
            writer.writerow({k: row.get(k) for k in _ORTHRUS_SUMMARY_KEYS})


