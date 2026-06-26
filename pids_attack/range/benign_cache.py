"""Cached benign background traces for attack-time mixed queries.

Attack queries execute only A0+delta in the range.  This module selects a
pre-collected benign provenance trace that is composed with the real attack
trace before detector inference.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENIGN_TRACE_DIR = PROJECT_ROOT / "detection" / "data" / "training_traces"


@dataclass(frozen=True)
class BenignTrace:
    trace_path: Path
    proc_snapshot_path: Optional[Path] = None
    sql_path: Optional[Path] = None

    def to_dict(self) -> dict:
        return {
            "trace_path": str(self.trace_path),
            "proc_snapshot_path": str(self.proc_snapshot_path) if self.proc_snapshot_path else None,
            "sql_path": str(self.sql_path) if self.sql_path else None,
        }


def resolve_benign_trace_dir(trace_dir: Optional[str | Path] = None) -> Path:
    if trace_dir is None:
        return DEFAULT_BENIGN_TRACE_DIR
    path = Path(trace_dir)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def _proc_snapshot_for(trace_path: Path) -> Optional[Path]:
    candidates = [
        Path(str(trace_path) + ".proc_snapshot"),
        trace_path.with_suffix(".proc_snapshot"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _sql_for(trace_path: Path) -> Optional[Path]:
    candidates = [
        trace_path.with_suffix(".sql"),
        Path(str(trace_path) + ".sql"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def list_cached_benign_traces(trace_dir: Optional[str | Path] = None) -> List[BenignTrace]:
    root = resolve_benign_trace_dir(trace_dir)
    if not root.exists():
        raise FileNotFoundError(f"benign trace dir not found: {root}")

    traces: List[BenignTrace] = []
    for path in sorted(root.glob("benign_*.strace")):
        if not path.is_file():
            continue
        traces.append(
            BenignTrace(
                trace_path=path,
                proc_snapshot_path=_proc_snapshot_for(path),
                sql_path=_sql_for(path),
            )
        )
    if not traces:
        raise FileNotFoundError(f"no benign_*.strace files found in {root}")
    return traces


def choose_cached_benign_trace(
    *,
    trace_dir: Optional[str | Path] = None,
    seed: int = 0,
    scenario_id: str = "",
    query_id: str = "",
) -> BenignTrace:
    traces = list_cached_benign_traces(trace_dir)
    key = f"{seed}:{scenario_id}:{query_id}".encode()
    idx = int(hashlib.sha256(key).hexdigest(), 16) % len(traces)
    return traces[idx]
