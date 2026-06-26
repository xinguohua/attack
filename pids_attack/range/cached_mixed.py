"""Cached-mixed trace construction for attack queries.

The attack oracle uses one execution path:
  1. run A0+delta in the victim container and collect a marker-preserving trace;
  2. prepend a cached benign background trace;
  3. strip markers, convert the composed trace to SQL, and build E0-style GT.

R1/R2 validity always comes from the fresh A0+delta execution.  The benign cache
only supplies detector background context.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from range.benign_cache import BenignTrace, choose_cached_benign_trace
from range.converter import build_cdm_graph_from_strace, graph_to_sql_with_mapping
from range.mixed_workload import collect_attack_query_trace
from range.node_gt import (
    GT_SOURCE,
    GT_VERSION,
    TRACE_MODE,
    collect_signature_window_gt_from_sql,
)
from range.trace_window import extract_window, strip_markers


MIXED_MODE = "cached_benign_attack_query"


def _concat_files(sources: List[Path], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as fout:
        for i, source in enumerate(sources):
            if i:
                fout.write(b"\n")
            with source.open("rb") as fin:
                shutil.copyfileobj(fin, fout)


def _write_proc_snapshot(
    *,
    benign_trace: BenignTrace,
    attack_proc_snapshot: Optional[Path],
    raw_strace: Path,
    clean_strace: Path,
) -> None:
    sources: List[Path] = []
    if benign_trace.proc_snapshot_path and benign_trace.proc_snapshot_path.exists():
        sources.append(benign_trace.proc_snapshot_path)
    if attack_proc_snapshot and Path(attack_proc_snapshot).exists():
        sources.append(Path(attack_proc_snapshot))
    if not sources:
        return

    raw_snapshot = Path(str(raw_strace) + ".proc_snapshot")
    clean_snapshot = Path(str(clean_strace) + ".proc_snapshot")
    _concat_files(sources, raw_snapshot)
    clean_snapshot.write_bytes(raw_snapshot.read_bytes())


def compose_cached_mixed_trace(
    *,
    benign_trace: BenignTrace,
    attack_raw_strace: Path,
    attack_proc_snapshot: Optional[Path],
    outdir: Path,
    attack_gt_signature_sets: Dict[str, Any],
    attack_gt_signature_path: Optional[Path],
) -> Dict[str, Any]:
    """Compose cached benign trace + fresh attack trace into one detector input."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    raw_strace = outdir / "raw.strace"
    clean_strace = outdir / "clean.strace"
    clean_sql = outdir / "clean.strace.sql"
    idx_map_path = outdir / "clean.strace.sql.idx_map.json"
    gt_path = outdir / "gt.json"

    _concat_files([benign_trace.trace_path, Path(attack_raw_strace)], raw_strace)
    _write_proc_snapshot(
        benign_trace=benign_trace,
        attack_proc_snapshot=attack_proc_snapshot,
        raw_strace=raw_strace,
        clean_strace=clean_strace,
    )

    t_begin_ns, t_end_ns = extract_window(raw_strace)
    n_dropped = strip_markers(raw_strace, clean_strace)

    graph = build_cdm_graph_from_strace(str(clean_strace))
    sql_text, uuid_to_index_id = graph_to_sql_with_mapping(graph)
    clean_sql.write_text(sql_text)
    idx_map_path.write_text(json.dumps(uuid_to_index_id, indent=2))

    gt = collect_signature_window_gt_from_sql(
        sql_path=clean_sql,
        t_begin_ns=t_begin_ns,
        t_end_ns=t_end_ns,
        signature_sets=attack_gt_signature_sets,
        signature_path=attack_gt_signature_path,
    )
    gt.update({
        "gt_version": GT_VERSION,
        "trace_mode": TRACE_MODE,
        "mixed_mode": MIXED_MODE,
        "window_source": "marker_strace",
        "gt_source": GT_SOURCE,
        "markers_stripped": n_dropped,
        "benign_trace_path": str(benign_trace.trace_path),
        "benign_proc_snapshot_path": (
            str(benign_trace.proc_snapshot_path) if benign_trace.proc_snapshot_path else None
        ),
        "attack_raw_strace": str(attack_raw_strace),
    })
    gt_path.write_text(json.dumps(gt, indent=2))

    return {
        "raw_strace": raw_strace,
        "clean_strace": clean_strace,
        "clean_sql": clean_sql,
        "idx_map_path": idx_map_path,
        "gt_json": gt_path,
        "gt": gt,
        "uuid_to_index_id": uuid_to_index_id,
        "all_node_count": gt["all_node_count"],
        "window_source": "marker_strace",
        "gt_source": GT_SOURCE,
        "markers_stripped": n_dropped,
        "mixed_mode": MIXED_MODE,
        "benign_trace": benign_trace.to_dict(),
    }


def collect_cached_mixed_workload(
    scenario: Dict[str, Any],
    outdir: Path,
    *,
    reset_container_before: bool = True,
    attack_gt_signature_sets: Optional[Dict[str, Any]] = None,
    attack_gt_signature_path: Optional[Path] = None,
    delta_commands: Optional[List[str]] = None,
    delta_positions: Optional[List[int]] = None,
    benign_trace_dir: Optional[str | Path] = None,
    benign_seed: int = 0,
    query_id: str = "",
) -> Dict[str, Any]:
    """Run A0+delta once and compose it with a cached benign trace."""
    if attack_gt_signature_sets is None:
        raise ValueError("attack_gt_signature_sets is required for cached mixed GT")

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    scenario_id = scenario["scenario_id"]

    attack_dir = outdir / "attack_query"
    attack_artifact = collect_attack_query_trace(
        scenario,
        attack_dir,
        reset_container_before=reset_container_before,
        delta_commands=delta_commands,
        delta_positions=delta_positions,
    )
    benign_trace = choose_cached_benign_trace(
        trace_dir=benign_trace_dir,
        seed=benign_seed,
        scenario_id=scenario_id,
        query_id=query_id,
    )
    composed = compose_cached_mixed_trace(
        benign_trace=benign_trace,
        attack_raw_strace=Path(attack_artifact["raw_strace"]),
        attack_proc_snapshot=Path(attack_artifact["raw_proc_snap"]),
        outdir=outdir,
        attack_gt_signature_sets=attack_gt_signature_sets,
        attack_gt_signature_path=attack_gt_signature_path,
    )

    gt = dict(composed["gt"])
    gt.update({
        "scenario_id": scenario_id,
        "run_id": attack_artifact["run_id"],
        "server_attached": False,
        "juice_pid": "",
        "workload_returncode": attack_artifact["workload_returncode"],
        "delta_command_success": attack_artifact["delta_command_success"],
        "delta_outputs": attack_artifact["delta_outputs"],
        "all_steps_passed": attack_artifact["all_steps_passed"],
        "final_attack_succeeded": attack_artifact["final_attack_succeeded"],
        "failed_step": attack_artifact["failed_step"],
    })
    Path(composed["gt_json"]).write_text(json.dumps(gt, indent=2))

    return {
        "scenario_id": scenario_id,
        "run_id": attack_artifact["run_id"],
        "raw_strace": composed["raw_strace"],
        "clean_strace": composed["clean_strace"],
        "clean_sql": composed["clean_sql"],
        "gt_json": composed["gt_json"],
        "gt": gt,
        "uuid_to_index_id": composed["uuid_to_index_id"],
        "all_node_count": composed["all_node_count"],
        "attack_raw_strace": attack_artifact["raw_strace"],
        "attack_clean_strace": attack_artifact["clean_strace"],
        "attack_step_results": attack_artifact["attack_step_results"],
        "final_check_result": attack_artifact["final_check_result"],
        "all_steps_passed": attack_artifact["all_steps_passed"],
        "final_attack_succeeded": attack_artifact["final_attack_succeeded"],
        "failed_step": attack_artifact["failed_step"],
        "window_source": "marker_strace",
        "gt_source": GT_SOURCE,
        "server_attached": False,
        "workload_returncode": attack_artifact["workload_returncode"],
        "delta_command_success": attack_artifact["delta_command_success"],
        "delta_outputs": attack_artifact["delta_outputs"],
        "mixed_mode": MIXED_MODE,
        "benign_trace": composed["benign_trace"],
    }
