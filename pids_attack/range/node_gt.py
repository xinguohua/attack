"""Attack-only GT signatures for E0.

The E0 ground truth is the intersection of two independently observed facts:

1. a node's normalized signature appears in an attack-only run, and
2. the corresponding mixed-run node is touched inside the attack marker window.

This module intentionally does not filter runtime noise. It only normalizes the
run-specific `/tmp/e0_<run_id>` prefix and repeated whitespace so the same A0
execution can be matched across attack-only and mixed runs.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple


GT_SOURCE = "attack_only_signature_marker_window"
SIGNATURE_VERSION = 1
GT_VERSION = 1
TRACE_MODE = "batch_workload"

_RUN_DIR_RE = re.compile(r"/tmp/e0_[A-Za-z0-9]+")
_WS_RE = re.compile(r"\s+")

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
_INSERT_EVENT_RE = re.compile(
    r"INSERT INTO event_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*(\d+)\)",
    re.IGNORECASE,
)


def _unescape_sql_value(value: str) -> str:
    return value.replace("''", "'").replace("\\\\", "\\")


def normalize_signature_text(value: str) -> str:
    value = _RUN_DIR_RE.sub("/tmp/e0_RUN", value or "")
    return _WS_RE.sub(" ", value).strip()


def _node_signature(record: Dict[str, Any]) -> str:
    node_type = record["node_type"]
    if node_type == "subject":
        path = normalize_signature_text(record.get("path", ""))
        cmd = normalize_signature_text(record.get("cmd", ""))
        return f"subject|{path}|{cmd}"
    if node_type == "file":
        path = normalize_signature_text(record.get("path", ""))
        return f"file|{path}"
    if node_type == "netflow":
        src = normalize_signature_text(record.get("src_addr", ""))
        sport = normalize_signature_text(record.get("src_port", ""))
        dst = normalize_signature_text(record.get("dst_addr", ""))
        dport = normalize_signature_text(record.get("dst_port", ""))
        return f"netflow|{src}:{sport}->{dst}:{dport}"
    raise ValueError(f"unknown node_type={node_type!r}")


def _parse_sql_nodes(sql_path: Path) -> Tuple[Dict[int, Dict[str, Any]], Dict[str, int]]:
    text = Path(sql_path).read_text(errors="ignore")
    by_index: Dict[int, Dict[str, Any]] = {}
    hash_to_index: Dict[str, int] = {}

    for m in _INSERT_SUBJECT_RE.finditer(text):
        _uuid, hash_id, path, cmd, idx = m.groups()
        index_id = int(idx)
        record = {
            "node_index_id": index_id,
            "node_type": "subject",
            "hash_id": hash_id,
            "path": _unescape_sql_value(path),
            "cmd": _unescape_sql_value(cmd),
        }
        record["signature"] = _node_signature(record)
        by_index[index_id] = record
        hash_to_index[hash_id] = index_id

    for m in _INSERT_FILE_RE.finditer(text):
        _uuid, hash_id, path, idx = m.groups()
        index_id = int(idx)
        record = {
            "node_index_id": index_id,
            "node_type": "file",
            "hash_id": hash_id,
            "path": _unescape_sql_value(path),
            "cmd": "",
        }
        record["signature"] = _node_signature(record)
        by_index[index_id] = record
        hash_to_index[hash_id] = index_id

    for m in _INSERT_NETFLOW_RE.finditer(text):
        _uuid, hash_id, src_addr, src_port, dst_addr, dst_port, idx = m.groups()
        index_id = int(idx)
        record = {
            "node_index_id": index_id,
            "node_type": "netflow",
            "hash_id": hash_id,
            "path": "",
            "cmd": "",
            "src_addr": src_addr,
            "src_port": src_port,
            "dst_addr": dst_addr,
            "dst_port": dst_port,
        }
        record["signature"] = _node_signature(record)
        by_index[index_id] = record
        hash_to_index[hash_id] = index_id

    return by_index, hash_to_index


def _empty_signature_sets() -> Dict[str, Set[str]]:
    return {"subject": set(), "file": set(), "netflow": set()}


def build_attack_gt_signature(sql_path: Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Build attack-only node signatures from a SQL dump."""
    nodes, _hash_to_index = _parse_sql_nodes(sql_path)
    signature_sets = _empty_signature_sets()
    node_records: Dict[str, List[Dict[str, Any]]] = {
        "subject": [],
        "file": [],
        "netflow": [],
    }

    for record in sorted(nodes.values(), key=lambda r: int(r["node_index_id"])):
        node_type = record["node_type"]
        signature_sets[node_type].add(record["signature"])
        node_records[node_type].append({
            "node_index_id": record["node_index_id"],
            "node_type": node_type,
            "signature": record["signature"],
            "label": _record_label(record),
        })

    signature_doc = {
        "signature_version": SIGNATURE_VERSION,
        "trace_mode": TRACE_MODE,
        "gt_source": "attack_only_signature",
        "signatures": {
            k: sorted(v) for k, v in signature_sets.items()
        },
        "counts": {
            k: len(v) for k, v in signature_sets.items()
        },
    }
    nodes_doc = {
        "signature_version": SIGNATURE_VERSION,
        "trace_mode": TRACE_MODE,
        "gt_source": "attack_only_signature",
        "nodes": node_records,
    }
    return signature_doc, nodes_doc


def load_signature_sets(path: Path) -> Dict[str, Set[str]]:
    doc = json.loads(Path(path).read_text())
    signatures = doc.get("signatures", {})
    out = _empty_signature_sets()
    for node_type in out:
        out[node_type] = {str(x) for x in signatures.get(node_type, [])}
    return out


def collect_signature_window_gt_from_sql(
    *,
    sql_path: Path,
    t_begin_ns: int,
    t_end_ns: int,
    signature_sets: Dict[str, Set[str]],
    signature_path: Path | None = None,
) -> Dict[str, Any]:
    """Collect mixed-run GT nodes using signature match inside marker window."""
    nodes, hash_to_index = _parse_sql_nodes(sql_path)
    text = Path(sql_path).read_text(errors="ignore")
    candidate_ids: Set[int] = set()
    n_events_in_window = 0

    for m in _INSERT_EVENT_RE.finditer(text):
        src_hash, _src_index_hash, _op, dst_hash, _dst_index_hash, _evt, ts = m.groups()
        timestamp = int(ts)
        if not (t_begin_ns <= timestamp <= t_end_ns):
            continue
        n_events_in_window += 1
        for hash_id in (src_hash, dst_hash):
            index_id = hash_to_index.get(hash_id)
            if index_id is not None:
                candidate_ids.add(index_id)

    gt_subject: Set[int] = set()
    gt_file: Set[int] = set()
    gt_netflow: Set[int] = set()
    for index_id in candidate_ids:
        record = nodes.get(index_id)
        if not record:
            continue
        node_type = record["node_type"]
        if record["signature"] not in signature_sets.get(node_type, set()):
            continue
        if node_type == "subject":
            gt_subject.add(index_id)
        elif node_type == "file":
            gt_file.add(index_id)
        elif node_type == "netflow":
            gt_netflow.add(index_id)

    n_subject = sum(1 for n in nodes.values() if n["node_type"] == "subject")
    n_file = sum(1 for n in nodes.values() if n["node_type"] == "file")
    n_netflow = sum(1 for n in nodes.values() if n["node_type"] == "netflow")

    gt = {
        "t_begin_ns": int(t_begin_ns),
        "t_end_ns": int(t_end_ns),
        "duration_sec": (int(t_end_ns) - int(t_begin_ns)) / 1e9,
        "gt_version": GT_VERSION,
        "trace_mode": TRACE_MODE,
        "gt_source": GT_SOURCE,
        "gt_subject_index_ids": sorted(gt_subject),
        "gt_file_index_ids": sorted(gt_file),
        "gt_netflow_index_ids": sorted(gt_netflow),
        "gt_window_event_count": n_events_in_window,
        "gt_window_candidate_count": len(candidate_ids),
        "gt_signature_counts": {
            k: len(v) for k, v in signature_sets.items()
        },
        "all_node_count": {
            "n_subject": n_subject,
            "n_file": n_file,
            "n_netflow": n_netflow,
            "total": n_subject + n_file + n_netflow,
        },
    }
    if signature_path is not None:
        gt["gt_signature_path"] = str(signature_path)
    return gt


def _record_label(record: Dict[str, Any]) -> str:
    node_type = record["node_type"]
    if node_type == "subject":
        return f"{record.get('path', '')} | {record.get('cmd', '')}".strip()
    if node_type == "file":
        return record.get("path", "")
    if node_type == "netflow":
        local = (
            f"{record.get('src_addr', '')}:{record.get('src_port', '')}"
            if (record.get("src_addr") or record.get("src_port"))
            else ""
        )
        remote = f"{record.get('dst_addr', '')}:{record.get('dst_port', '')}"
        return f"{local}->{remote}" if local else remote
    return ""


def write_attack_gt_signature(sql_path: Path, signature_path: Path, nodes_path: Path) -> Dict[str, Any]:
    signature_doc, nodes_doc = build_attack_gt_signature(sql_path)
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    signature_path.write_text(json.dumps(signature_doc, indent=2))
    nodes_path.write_text(json.dumps(nodes_doc, indent=2))
    return signature_doc
