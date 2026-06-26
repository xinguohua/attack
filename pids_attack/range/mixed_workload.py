"""Shared mixed-workload trace collection for E0/E1/E2.

This module owns the real detector context:
benign background + marker window + A0 (or A0⊕δ) + strace + SQL + GT.

Experiments should not reimplement this logic.  E0 calls it with no delta;
attack oracles call it with command-level perturbations.
"""
from __future__ import annotations

import json
import re
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from range.checker import run_checker
from range.converter import build_cdm_graph_from_strace, graph_to_sql_with_mapping
from range.execute import (
    CONTAINER_NAME,
    STRACE_SYSCALLS,
    CommandOutput,
    _docker_exec,
    reset_container,
)

from .node_gt import (
    GT_SOURCE,
    GT_VERSION,
    SIGNATURE_VERSION,
    TRACE_MODE,
    collect_signature_window_gt_from_sql,
    write_attack_gt_signature,
)
from .trace_window import extract_window, strip_markers


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENIGN_PLAN_PATH = PROJECT_ROOT / "detection" / "data" / "benign_collection_plan.yml"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def _write_container_file(container_path: str, text: str) -> None:
    cp = subprocess.run(
        ["docker", "exec", "-i", CONTAINER_NAME, "bash", "-c", f"cat > {container_path}"],
        input=text,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or f"failed to write {container_path}")


def _cp_from_container(container_path: str, host_path: Path) -> None:
    host_path.parent.mkdir(parents=True, exist_ok=True)
    cp = subprocess.run(
        ["docker", "cp", f"{CONTAINER_NAME}:{container_path}", str(host_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or f"docker cp failed: {container_path}")


def _dump_proc_snapshot(container_path: str) -> None:
    _docker_exec(
        'for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do '
        '  cmdline=$(tr "\\0" " " < /proc/$pid/cmdline 2>/dev/null); '
        '  exe=$(readlink /proc/$pid/exe 2>/dev/null); '
        '  echo "PID=$pid CMDLINE=\\"$cmdline\\" EXE=\\"$exe\\""; '
        f'done > {container_path}',
        timeout=15,
    )


def _load_benign_plan() -> Optional[Dict[str, Any]]:
    if not BENIGN_PLAN_PATH.exists():
        return None
    try:
        import yaml
        with open(BENIGN_PLAN_PATH) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _build_benign_block(stop_file: str, bg_pids_file: str) -> str:
    """Build fixed benign workload from the training collection plan."""
    plan = _load_benign_plan()
    if not plan:
        return f"""
(
  while [ ! -f {stop_file} ]; do
    curl -s -o /dev/null -m 2 http://localhost:3000/ 2>/dev/null
    curl -s -o /dev/null -m 2 'http://localhost:3000/rest/products/search?q=' 2>/dev/null
    sleep_until_stop 2
  done
) &
echo $! >> {bg_pids_file}
"""

    blocks: List[str] = []
    for daemon in plan.get("daemons", []):
        period = int(daemon.get("period_sec", 30))
        offset = int(daemon.get("phase_offset_sec", 0))
        commands = "\n    ".join(daemon.get("commands", [])) or "true"
        blocks.append(f"""
(
  sleep_until_stop {offset}
  while [ ! -f {stop_file} ]; do
    {commands}
    sleep_until_stop {period}
  done
) &
echo $! >> {bg_pids_file}
""")

    foreground_cmds: List[str] = []
    for scenario in plan.get("scenarios", {}).get("pool", []):
        for slot in scenario.get("slots", []):
            candidates = slot.get("candidates", [])
            if candidates:
                foreground_cmds.append(candidates[0])
    if foreground_cmds:
        body = "\n      sleep_until_stop 1\n      ".join(foreground_cmds)
        blocks.append(f"""
(
  while [ ! -f {stop_file} ]; do
      {body}
      sleep_until_stop 2
  done
) &
echo $! >> {bg_pids_file}
""")

    return "\n".join(blocks)


def _marker_line(tag: str, run_id: str, scenario_id: str) -> str:
    return f"__E0_ATTACK_{tag}__ run={run_id} scenario={scenario_id}"


_STEP_BEGIN_RE = re.compile(r"^__E0_STEP_BEGIN__ step=([^\s]+)\s*$")
_STEP_END_RE = re.compile(r"^__E0_STEP_END__ step=([^\s]+) rc=(-?\d+)\s*$")


def _step_id(spec: Dict[str, Any], fallback: int) -> str:
    return str(spec.get("step_id", fallback))


def _step_begin_line(step_id: str) -> str:
    return f"__E0_STEP_BEGIN__ step={step_id}"


def _step_end_prefix(step_id: str) -> str:
    return f"__E0_STEP_END__ step={step_id} rc="


def _build_step_block(steps: List[Dict[str, Any]]) -> str:
    blocks: List[str] = []
    for i, spec in enumerate(steps):
        step_id = _step_id(spec, i)
        command = str(spec["command"]).rstrip()
        blocks.append(f"""
printf '%s\\n' '{_step_begin_line(step_id)}'
(
{command}
)
__e0_step_rc=$?
printf '\\n%s%s\\n' '{_step_end_prefix(step_id)}' "$__e0_step_rc"
""")
    return "\n".join(blocks)


def _interleave_steps(
    steps: List[Dict[str, Any]],
    delta_commands: Optional[List[str]] = None,
    delta_positions: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """Return shell specs for A0⊕δ while preserving original A0 step ids.

    δ commands are marked as regular step records with ids `delta_<i>` so they
    execute inside the same marker window and their exit codes can be recorded.
    They are not used for A0 checker/final-check semantics.
    """
    delta_commands = list(delta_commands or [])
    delta_positions = list(delta_positions or [])
    if len(delta_positions) < len(delta_commands):
        delta_positions.extend([0] * (len(delta_commands) - len(delta_positions)))
    n = len(steps)
    buckets: List[List[Tuple[int, str]]] = [[] for _ in range(n + 1)]
    for i, cmd in enumerate(delta_commands):
        pos = int(delta_positions[i])
        pos = max(0, min(pos, n - 1 if n else 0))
        buckets[pos].append((i, cmd))

    out: List[Dict[str, Any]] = []
    for idx, cmd in buckets[0]:
        out.append({"step_id": f"delta_{idx}", "command": cmd, "_is_delta": True})
    for i, step in enumerate(steps):
        out.append(dict(step))
        for idx, cmd in buckets[i + 1] if i + 1 < len(buckets) else []:
            out.append({"step_id": f"delta_{idx}", "command": cmd, "_is_delta": True})
    return out


def _build_attack_only_workload(steps: List[Dict[str, Any]]) -> str:
    return f"""set +e
{_build_step_block(steps)}
exit 0
"""


def _build_attack_query_workload(
    *,
    run_id: str,
    scenario_id: str,
    executable_steps: List[Dict[str, Any]],
) -> str:
    begin = _marker_line("BEGIN", run_id, scenario_id)
    end = _marker_line("END", run_id, scenario_id)
    return f"""set +e
printf '%s\\n' '{begin}'

{_build_step_block(executable_steps)}

printf '%s\\n' '{end}'
exit 0
"""


def _build_mixed_workload(
    *,
    run_id: str,
    scenario_id: str,
    run_dir: str,
    executable_steps: List[Dict[str, Any]],
    warmup_sec: int,
    cooldown_sec: int,
) -> str:
    stop_file = f"{run_dir}/benign.stop"
    bg_pids_file = f"{run_dir}/bg.pids"
    benign_block = _build_benign_block(stop_file, bg_pids_file)
    begin = _marker_line("BEGIN", run_id, scenario_id)
    end = _marker_line("END", run_id, scenario_id)

    return f"""set +e
RUN_DIR={run_dir}
STOP_FILE={stop_file}
BG_PIDS={bg_pids_file}
rm -f "$STOP_FILE" "$BG_PIDS"

cleanup() {{
  touch "$STOP_FILE"
  if [ -f "$BG_PIDS" ]; then
    while read -r pid; do
      [ -n "$pid" ] && pkill -TERM -P "$pid" 2>/dev/null
      [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
    done < "$BG_PIDS"
    sleep 0.2
    while read -r pid; do
      [ -n "$pid" ] && pkill -KILL -P "$pid" 2>/dev/null
      [ -n "$pid" ] && kill -KILL "$pid" 2>/dev/null
    done < "$BG_PIDS"
  fi
}}
trap cleanup EXIT

sleep_until_stop() {{
  remaining="${{1:-0}}"
  while [ "$remaining" -gt 0 ] && [ ! -f "$STOP_FILE" ]; do
    sleep 1
    remaining=$((remaining - 1))
  done
}}

# Fixed benign workload from detection/data/benign_collection_plan.yml.
{benign_block}

sleep {warmup_sec}
printf '%s\\n' '{begin}'

{_build_step_block(executable_steps)}

printf '%s\\n' '{end}'
sleep {cooldown_sec}
cleanup
exit 0
"""


def _parse_step_outputs(
    stdout: str,
    stderr: str,
    steps: List[Dict[str, Any]],
) -> List[CommandOutput]:
    parsed: Dict[str, CommandOutput] = {}
    current_step: Optional[str] = None
    current_buf: List[str] = []

    for line in stdout.splitlines(keepends=True):
        line_stripped = line.strip()
        m_begin = _STEP_BEGIN_RE.match(line_stripped)
        if m_begin:
            current_step = m_begin.group(1)
            current_buf = []
            continue
        m_end = _STEP_END_RE.match(line_stripped)
        if m_end and current_step == m_end.group(1):
            step_id = current_step
            command = ""
            for i, spec in enumerate(steps):
                if _step_id(spec, i) == step_id:
                    command = str(spec.get("command", ""))
                    break
            parsed[step_id] = CommandOutput(
                command=command,
                stdout="".join(current_buf),
                stderr="",
                exit_code=int(m_end.group(2)),
                response_time_sec=0.0,
            )
            current_step = None
            current_buf = []
            continue
        if current_step is not None:
            current_buf.append(line)

    outputs: List[CommandOutput] = []
    for i, spec in enumerate(steps):
        step_id = _step_id(spec, i)
        outputs.append(
            parsed.get(
                step_id,
                CommandOutput(
                    command=str(spec.get("command", "")),
                    stdout="",
                    stderr=stderr,
                    exit_code=1,
                    response_time_sec=0.0,
                ),
            )
        )
    return outputs


def _command_output_dict(output: CommandOutput) -> Dict[str, Any]:
    return {
        "command": output.command,
        "stdout": output.stdout,
        "stderr": output.stderr,
        "exit_code": output.exit_code,
        "response_time_sec": output.response_time_sec,
    }


def _remove_obsolete_runner_artifacts(outdir: Path) -> None:
    for name in (
        "raw.orchestrator.strace",
        "raw.server.strace",
        "orchestrator.stdout",
        "orchestrator.stderr",
    ):
        (outdir / name).unlink(missing_ok=True)
    old_output_dir = outdir / "cmd_outputs"
    if old_output_dir.exists():
        import shutil
        shutil.rmtree(old_output_dir)


def _run_batch_workload(
    *,
    workload: str,
    outdir: Path,
    container_run_dir: str,
    max_runtime: int,
) -> Dict[str, Any]:
    container_trace = f"{container_run_dir}/raw.strace"
    container_proc_snap = f"{container_trace}.proc_snapshot"
    container_workload = f"{container_run_dir}/workload.sh"
    container_stdout = f"{container_run_dir}/workload.stdout"
    container_stderr = f"{container_run_dir}/workload.stderr"

    _docker_exec(f"rm -rf {container_run_dir} && mkdir -p {container_run_dir}", timeout=10)
    _docker_exec(f"touch {container_trace}", timeout=5)
    _write_container_file(container_workload, workload)
    _dump_proc_snapshot(container_proc_snap)

    run_cmd = (
        f"__e0_workload=$(cat {container_workload}); "
        f"strace -fA -ttt -s 256 -e trace={STRACE_SYSCALLS} "
        f"-o {container_trace} bash -lc \"$__e0_workload\" "
        f"> {container_stdout} 2> {container_stderr}"
    )
    cp = _docker_exec(run_cmd, timeout=max_runtime)

    raw_strace = outdir / "raw.strace"
    raw_proc_snap = outdir / "raw.strace.proc_snapshot"
    workload_stdout = outdir / "workload.stdout"
    workload_stderr = outdir / "workload.stderr"
    _cp_from_container(container_trace, raw_strace)
    _cp_from_container(container_proc_snap, raw_proc_snap)
    _cp_from_container(container_stdout, workload_stdout)
    _cp_from_container(container_stderr, workload_stderr)

    return {
        "returncode": cp.returncode,
        "raw_strace": raw_strace,
        "raw_proc_snap": raw_proc_snap,
        "workload_stdout": workload_stdout,
        "workload_stderr": workload_stderr,
        "stdout_text": _read_text(workload_stdout),
        "stderr_text": _read_text(workload_stderr),
    }


def _run_attack_checks(
    scenario: Dict[str, Any],
    step_outputs: List[CommandOutput],
) -> Dict[str, Any]:
    step_results: List[Dict[str, Any]] = []
    all_steps_passed = True
    failed_step: Optional[int] = None

    steps = list(scenario.get("steps", []))
    for i, (spec, output) in enumerate(zip(steps, step_outputs)):
        checker_spec = spec.get("checker") or {"type": "exit_code", "expected": 0}
        checker_spec = {**checker_spec, "step_id": spec.get("step_id", i)}
        res = run_checker(checker_spec, output)
        step_results.append({
            "step_id": res.step_id,
            "command": res.command,
            "success": bool(res.success),
            "actual": res.actual,
            "expected": res.expected,
            "error_message": res.error_message,
        })
        if not res.success:
            all_steps_passed = False
            if failed_step is None:
                failed_step = res.step_id

    if len(step_outputs) < len(steps):
        all_steps_passed = False
        if failed_step is None:
            failed_step = steps[len(step_outputs)].get("step_id", len(step_outputs)) if steps else -1

    final_result = None
    final_attack_succeeded = all_steps_passed
    final_check = scenario.get("final_attack_check")
    if all_steps_passed and final_check is not None:
        checker_spec = {**final_check, "step_id": -1}
        last_out = step_outputs[-1] if step_outputs else CommandOutput("", "", "", 1, 0.0)
        res = run_checker(checker_spec, last_out)
        final_result = {
            "step_id": res.step_id,
            "command": res.command,
            "success": bool(res.success),
            "actual": res.actual,
            "expected": res.expected,
            "error_message": res.error_message,
        }
        final_attack_succeeded = bool(res.success)
        if not final_attack_succeeded and failed_step is None:
            failed_step = -1

    return {
        "attack_step_results": step_results,
        "final_check_result": final_result,
        "all_steps_passed": all_steps_passed,
        "final_attack_succeeded": final_attack_succeeded,
        "failed_step": failed_step,
    }


def collect_attack_only_signature(
    scenario: Dict[str, Any],
    outdir: Path,
    *,
    reset_container_before: bool = True,
) -> Dict[str, Any]:
    """Collect an attack-only trace and generate GT signatures."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    scenario_id = scenario["scenario_id"]
    run_id = uuid.uuid4().hex[:12]

    if reset_container_before:
        reset_container()

    steps = list(scenario.get("steps", []))
    container_run_dir = f"/tmp/e0_{run_id}"
    _remove_obsolete_runner_artifacts(outdir)

    workload = _build_attack_only_workload(steps)
    max_runtime = max(60, 12 * len(steps)) + 120
    run_info = _run_batch_workload(
        workload=workload,
        outdir=outdir,
        container_run_dir=container_run_dir,
        max_runtime=max_runtime,
    )
    workload_returncode = run_info["returncode"]

    step_outputs = _parse_step_outputs(
        run_info["stdout_text"],
        run_info["stderr_text"],
        steps,
    )
    (outdir / "step_outputs.json").write_text(
        json.dumps([_command_output_dict(o) for o in step_outputs], indent=2)
    )
    check_info = _run_attack_checks(scenario, step_outputs)

    clean_strace = outdir / "clean.strace"
    clean_proc_snap = outdir / "clean.strace.proc_snapshot"
    n_dropped = strip_markers(run_info["raw_strace"], clean_strace)
    if run_info["raw_proc_snap"].exists():
        clean_proc_snap.write_bytes(run_info["raw_proc_snap"].read_bytes())

    graph = build_cdm_graph_from_strace(str(clean_strace))
    sql_text, uuid_to_index_id = graph_to_sql_with_mapping(graph)
    clean_sql = outdir / "clean.strace.sql"
    clean_sql.write_text(sql_text)
    idx_map_path = outdir / "clean.strace.sql.idx_map.json"
    idx_map_path.write_text(json.dumps(uuid_to_index_id, indent=2))

    signature_path = outdir / "attack_gt_signature.json"
    nodes_path = outdir / "attack_gt_nodes.json"
    signature_doc = write_attack_gt_signature(clean_sql, signature_path, nodes_path)
    signature_doc.update({
        "scenario_id": scenario_id,
        "run_id": run_id,
        "signature_version": SIGNATURE_VERSION,
        "trace_mode": TRACE_MODE,
        "markers_stripped": n_dropped,
        "workload_returncode": workload_returncode,
        **check_info,
    })
    signature_path.write_text(json.dumps(signature_doc, indent=2))

    try:
        _docker_exec(f"rm -rf {container_run_dir}", timeout=10)
    except Exception:
        pass

    return {
        "scenario_id": scenario_id,
        "run_id": run_id,
        "raw_strace": run_info["raw_strace"],
        "clean_strace": clean_strace,
        "clean_sql": clean_sql,
        "signature_path": signature_path,
        "nodes_path": nodes_path,
        "signature_doc": signature_doc,
        "signature_sets": {
            k: set(v) for k, v in signature_doc.get("signatures", {}).items()
        },
        "attack_step_results": check_info["attack_step_results"],
        "final_check_result": check_info["final_check_result"],
        "all_steps_passed": check_info["all_steps_passed"],
        "final_attack_succeeded": check_info["final_attack_succeeded"],
        "failed_step": check_info["failed_step"],
        "workload_returncode": workload_returncode,
    }


def collect_attack_query_trace(
    scenario: Dict[str, Any],
    outdir: Path,
    *,
    reset_container_before: bool = True,
    delta_commands: Optional[List[str]] = None,
    delta_positions: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Collect the real A0⊕δ execution trace for an attack query.

    This records only the attack workload in the victim container.  The raw
    strace keeps BEGIN/END markers so a later cached-mixed composer can recover
    the same marker-window GT used by E0.
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    scenario_id = scenario["scenario_id"]
    run_id = uuid.uuid4().hex[:12]

    if reset_container_before:
        reset_container()

    steps = list(scenario.get("steps", []))
    executable_steps = _interleave_steps(steps, delta_commands, delta_positions)
    container_run_dir = f"/tmp/e0_{run_id}"
    _remove_obsolete_runner_artifacts(outdir)

    workload = _build_attack_query_workload(
        run_id=run_id,
        scenario_id=scenario_id,
        executable_steps=executable_steps,
    )
    max_runtime = max(60, 12 * len(executable_steps)) + 120
    run_info = _run_batch_workload(
        workload=workload,
        outdir=outdir,
        container_run_dir=container_run_dir,
        max_runtime=max_runtime,
    )
    workload_returncode = run_info["returncode"]

    step_outputs = _parse_step_outputs(
        run_info["stdout_text"],
        run_info["stderr_text"],
        executable_steps,
    )
    a0_outputs = [o for spec, o in zip(executable_steps, step_outputs) if not spec.get("_is_delta")]
    delta_outputs = [o for spec, o in zip(executable_steps, step_outputs) if spec.get("_is_delta")]
    (outdir / "step_outputs.json").write_text(
        json.dumps([_command_output_dict(o) for o in step_outputs], indent=2)
    )
    (outdir / "delta_outputs.json").write_text(
        json.dumps([_command_output_dict(o) for o in delta_outputs], indent=2)
    )

    check_info = _run_attack_checks(scenario, a0_outputs)
    delta_command_success = (
        True if not delta_outputs else all(int(o.exit_code) == 0 for o in delta_outputs)
    )

    clean_strace = outdir / "attack.clean.strace"
    clean_proc_snap = outdir / "attack.clean.strace.proc_snapshot"
    n_dropped = strip_markers(run_info["raw_strace"], clean_strace)
    if run_info["raw_proc_snap"].exists():
        clean_proc_snap.write_bytes(run_info["raw_proc_snap"].read_bytes())

    try:
        _docker_exec(f"rm -rf {container_run_dir}", timeout=10)
    except Exception:
        pass

    return {
        "scenario_id": scenario_id,
        "run_id": run_id,
        "raw_strace": run_info["raw_strace"],
        "raw_proc_snap": run_info["raw_proc_snap"],
        "clean_strace": clean_strace,
        "clean_proc_snap": clean_proc_snap,
        "markers_stripped": n_dropped,
        "workload_returncode": workload_returncode,
        "delta_command_success": delta_command_success,
        "delta_outputs": [_command_output_dict(o) for o in delta_outputs],
        "attack_step_results": check_info["attack_step_results"],
        "final_check_result": check_info["final_check_result"],
        "all_steps_passed": check_info["all_steps_passed"],
        "final_attack_succeeded": check_info["final_attack_succeeded"],
        "failed_step": check_info["failed_step"],
    }


def collect_mixed_workload(
    scenario: Dict[str, Any],
    outdir: Path,
    *,
    warmup_sec: int = 10,
    cooldown_sec: int = 20,
    reset_container_before: bool = True,
    attack_gt_signature_sets: Optional[Dict[str, Any]] = None,
    attack_gt_signature_path: Optional[Path] = None,
    delta_commands: Optional[List[str]] = None,
    delta_positions: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Collect a mixed trace, SQL, and attack-signature-window GT.

    E0 calls this with no delta. E1/E2 call it with δ so the marker window
    executes A0⊕δ under the same benign background as E0.
    """
    if attack_gt_signature_sets is None:
        raise ValueError("attack_gt_signature_sets is required for E0 GT")

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    scenario_id = scenario["scenario_id"]
    run_id = uuid.uuid4().hex[:12]

    if reset_container_before:
        reset_container()

    steps = list(scenario.get("steps", []))
    executable_steps = _interleave_steps(steps, delta_commands, delta_positions)
    container_run_dir = f"/tmp/e0_{run_id}"
    _remove_obsolete_runner_artifacts(outdir)

    workload = _build_mixed_workload(
        run_id=run_id,
        scenario_id=scenario_id,
        run_dir=container_run_dir,
        executable_steps=executable_steps,
        warmup_sec=warmup_sec,
        cooldown_sec=cooldown_sec,
    )
    max_runtime = warmup_sec + cooldown_sec + max(60, 12 * len(executable_steps)) + 120
    run_info = _run_batch_workload(
        workload=workload,
        outdir=outdir,
        container_run_dir=container_run_dir,
        max_runtime=max_runtime,
    )
    workload_returncode = run_info["returncode"]

    step_outputs = _parse_step_outputs(
        run_info["stdout_text"],
        run_info["stderr_text"],
        executable_steps,
    )
    a0_outputs = [o for spec, o in zip(executable_steps, step_outputs) if not spec.get("_is_delta")]
    delta_outputs = [o for spec, o in zip(executable_steps, step_outputs) if spec.get("_is_delta")]
    (outdir / "step_outputs.json").write_text(
        json.dumps([_command_output_dict(o) for o in step_outputs], indent=2)
    )
    (outdir / "delta_outputs.json").write_text(
        json.dumps([_command_output_dict(o) for o in delta_outputs], indent=2)
    )
    check_info = _run_attack_checks(scenario, a0_outputs)
    delta_command_success = (
        True if not delta_outputs else all(int(o.exit_code) == 0 for o in delta_outputs)
    )

    clean_strace = outdir / "clean.strace"
    clean_proc_snap = outdir / "clean.strace.proc_snapshot"
    n_dropped = strip_markers(run_info["raw_strace"], clean_strace)
    if run_info["raw_proc_snap"].exists():
        clean_proc_snap.write_bytes(run_info["raw_proc_snap"].read_bytes())

    t_begin_ns, t_end_ns = extract_window(run_info["raw_strace"])

    graph = build_cdm_graph_from_strace(str(clean_strace))
    sql_text, uuid_to_index_id = graph_to_sql_with_mapping(graph)
    clean_sql = outdir / "clean.strace.sql"
    clean_sql.write_text(sql_text)
    idx_map_path = outdir / "clean.strace.sql.idx_map.json"
    idx_map_path.write_text(json.dumps(uuid_to_index_id, indent=2))

    gt = collect_signature_window_gt_from_sql(
        sql_path=clean_sql,
        t_begin_ns=t_begin_ns,
        t_end_ns=t_end_ns,
        signature_sets=attack_gt_signature_sets,
        signature_path=attack_gt_signature_path,
    )
    gt.update({
        "scenario_id": scenario_id,
        "run_id": run_id,
        "gt_version": GT_VERSION,
        "trace_mode": TRACE_MODE,
        "window_source": "marker_strace",
        "gt_source": GT_SOURCE,
        "markers_stripped": n_dropped,
        "server_attached": False,
        "juice_pid": "",
        "workload_returncode": workload_returncode,
        "delta_command_success": delta_command_success,
        "delta_outputs": [_command_output_dict(o) for o in delta_outputs],
        **check_info,
    })

    gt_path = outdir / "gt.json"
    gt_path.write_text(json.dumps(gt, indent=2))

    try:
        _docker_exec(f"rm -rf {container_run_dir}", timeout=10)
    except Exception:
        pass

    return {
        "scenario_id": scenario_id,
        "run_id": run_id,
        "raw_strace": run_info["raw_strace"],
        "clean_strace": clean_strace,
        "clean_sql": clean_sql,
        "gt_json": gt_path,
        "gt": gt,
        "uuid_to_index_id": uuid_to_index_id,
        "all_node_count": gt["all_node_count"],
        "attack_step_results": check_info["attack_step_results"],
        "final_check_result": check_info["final_check_result"],
        "all_steps_passed": check_info["all_steps_passed"],
        "final_attack_succeeded": check_info["final_attack_succeeded"],
        "failed_step": check_info["failed_step"],
        "window_source": "marker_strace",
        "gt_source": GT_SOURCE,
        "server_attached": False,
        "workload_returncode": workload_returncode,
        "delta_command_success": delta_command_success,
        "delta_outputs": [_command_output_dict(o) for o in delta_outputs],
    }


# Backward-compatible E0 names. New callers should use the public names above.
e0_collect_attack_only_scenario = collect_attack_only_signature
e0_collect_scenario = collect_mixed_workload
