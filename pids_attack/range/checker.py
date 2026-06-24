"""checker.py — 6 种 checker 类型 + execute_with_checks 主流程。"""
from __future__ import annotations
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .execute import (
    CONTAINER_NAME,
    CommandOutput,
    ExecutionResult,
    _docker_exec,
    reset_container,
)


# ------------------- Checker 数据类 -------------------

@dataclass
class StepCheckResult:
    step_id: int
    command: str
    success: bool
    actual: Any = None
    expected: Any = None
    error_message: Optional[str] = None


@dataclass
class AttackExecutionResult:
    scenario_id: str
    all_steps_passed: bool
    final_attack_succeeded: bool
    step_results: List[StepCheckResult] = field(default_factory=list)
    failed_step: Optional[int] = None
    trace_path: Optional[str] = None
    command_outputs: List[CommandOutput] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "all_steps_passed": self.all_steps_passed,
            "final_attack_succeeded": self.final_attack_succeeded,
            "failed_step": self.failed_step,
            "trace_path": self.trace_path,
            "step_results": [asdict(r) for r in self.step_results],
        }


# ------------------- 6 种 Checker 实施 -------------------


def _parse_http_response(stdout: str) -> Dict[str, Any]:
    """从 curl -i 风格的输出里粗略抽出 status / headers / body。"""
    out: Dict[str, Any] = {"status_code": None, "headers": "", "response_body": stdout}
    if "HTTP/" in stdout.split("\n")[0]:
        head, _, body = stdout.partition("\r\n\r\n")
        m = re.search(r"HTTP/\S+\s+(\d+)", head)
        if m:
            out["status_code"] = int(m.group(1))
        out["headers"] = head
        out["response_body"] = body or stdout
    return out


def check_http_response(spec: Dict[str, Any], output: CommandOutput) -> StepCheckResult:
    parsed = _parse_http_response(output.stdout)
    field = spec.get("field", "response_body")
    expected = spec.get("expected")
    typ = spec["type"]
    actual = parsed.get(field, "")
    success = False
    err = None
    if typ == "http_response_contains":
        success = expected in actual if isinstance(actual, str) else False
    elif typ == "http_status_code":
        success = parsed.get("status_code") == expected
        actual = parsed.get("status_code")
    elif typ == "http_header_present":
        success = expected in parsed.get("headers", "")
        actual = parsed.get("headers", "")[:200]
    else:
        err = f"unknown http checker type: {typ}"
    return StepCheckResult(
        step_id=spec.get("step_id", -1), command=output.command,
        success=success, actual=actual, expected=expected, error_message=err,
    )


def check_exit_code(spec: Dict[str, Any], output: CommandOutput) -> StepCheckResult:
    expected = spec.get("expected", 0)
    return StepCheckResult(
        step_id=spec.get("step_id", -1), command=output.command,
        success=output.exit_code == expected,
        actual=output.exit_code, expected=expected,
    )


def check_output(spec: Dict[str, Any], output: CommandOutput) -> StepCheckResult:
    typ = spec["type"]
    expected = spec.get("expected", "")
    text = output.stdout
    success = False
    if typ == "stdout_contains":
        success = expected in text
    elif typ == "stdout_not_contains":
        success = expected not in text
    elif typ == "stdout_regex_match":
        success = bool(re.search(expected, text))
    return StepCheckResult(
        step_id=spec.get("step_id", -1), command=output.command,
        success=success, actual=text[:200], expected=expected,
    )


def check_filesystem(spec: Dict[str, Any], output: CommandOutput) -> StepCheckResult:
    typ = spec["type"]
    path = spec["path"]
    expected = spec.get("expected")
    success = False
    actual = None
    if typ == "file_exists":
        cp = _docker_exec(f"test -e {path} && echo YES || echo NO")
        success = "YES" in cp.stdout
        actual = cp.stdout.strip()
    elif typ == "file_contains":
        cp = _docker_exec(f"cat {path} 2>/dev/null")
        success = expected in cp.stdout
        actual = cp.stdout[:200]
    elif typ == "file_size_min":
        cp = _docker_exec(f"stat -c %s {path} 2>/dev/null")
        try:
            size = int(cp.stdout.strip() or 0)
            success = size >= int(expected)
            actual = size
        except ValueError:
            success = False
    return StepCheckResult(
        step_id=spec.get("step_id", -1), command=output.command,
        success=success, actual=actual, expected=expected,
    )


def check_side_effect(spec: Dict[str, Any], output: CommandOutput) -> StepCheckResult:
    """攻击成功的最终验证（side effect）。"""
    typ = spec["type"]
    expected = spec.get("expected")
    success = False
    actual = None
    if typ == "exfiltrated_data_present":
        success = expected in output.stdout if expected else False
        actual = output.stdout[:200]
    elif typ == "privilege_escalated":
        cp = _docker_exec("id -u")
        success = cp.stdout.strip() == "0"
        actual = cp.stdout.strip()
    elif typ == "shell_obtained":
        success = "$" in output.stdout or "#" in output.stdout
        actual = output.stdout[:200]
    return StepCheckResult(
        step_id=spec.get("step_id", -1), command=output.command,
        success=success, actual=actual, expected=expected,
    )


def check_custom_script(spec: Dict[str, Any], output: CommandOutput) -> StepCheckResult:
    script_path = spec.get("script_path", "")
    success = False
    actual = None
    if script_path:
        try:
            cp = subprocess.run(
                ["bash", script_path],
                input=json.dumps({"command": output.command, "stdout": output.stdout, "stderr": output.stderr}),
                capture_output=True, text=True, timeout=10,
            )
            success = cp.returncode == 0
            actual = cp.stdout[:200]
        except Exception as e:
            actual = f"script error: {e}"
    return StepCheckResult(
        step_id=spec.get("step_id", -1), command=output.command,
        success=success, actual=actual, expected="exit_code=0",
    )


CHECKER_DISPATCH: Dict[str, Callable] = {
    "http_response_contains": check_http_response,
    "http_status_code": check_http_response,
    "http_header_present": check_http_response,
    "exit_code": check_exit_code,
    "stdout_contains": check_output,
    "stdout_not_contains": check_output,
    "stdout_regex_match": check_output,
    "file_exists": check_filesystem,
    "file_contains": check_filesystem,
    "file_size_min": check_filesystem,
    "exfiltrated_data_present": check_side_effect,
    "privilege_escalated": check_side_effect,
    "shell_obtained": check_side_effect,
    "custom": check_custom_script,
}


def run_checker(spec: Dict[str, Any], output: CommandOutput) -> StepCheckResult:
    fn = CHECKER_DISPATCH.get(spec["type"])
    if fn is None:
        return StepCheckResult(
            step_id=spec.get("step_id", -1), command=output.command,
            success=False, error_message=f"unknown checker type: {spec['type']}",
        )
    return fn(spec, output)


# ------------------- 主流程：execute_with_checks -------------------

def _interleave(A0: List[Dict[str, Any]], delta_commands: List[str], delta_positions: List[int]) -> List[Any]:
    """A0 步骤 dict 与 δ 命令字符串按 position 交错。返回 [(kind, item)] 序列。
    kind ∈ {"step", "delta"}
    """
    n = len(A0)
    buckets: List[List[str]] = [[] for _ in range(n + 1)]
    for cmd, pos in zip(delta_commands, delta_positions):
        p = max(0, min(pos, n))
        buckets[p].append(cmd)
    out: List[Any] = []
    for c in buckets[0]:
        out.append(("delta", c))
    for i, step in enumerate(A0):
        out.append(("step", step))
        for c in buckets[i + 1]:
            out.append(("delta", c))
    return out


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def _read_int(path: Path, default: int = 1) -> int:
    try:
        return int(path.read_text().strip())
    except Exception:
        return default


def _read_duration(path: Path) -> float:
    try:
        start_s, end_s = path.read_text().split()[:2]
        start = int(start_s)
        end = int(end_s)
        if end >= start:
            return (end - start) / 1e9
    except Exception:
        pass
    return 0.0


def _exec_traced_batch_safe(
    commands: List[str],
    trace_path_in_container: str,
    capture_trace: bool,
    per_cmd_timeout_sec: int = 8,
) -> List[CommandOutput]:
    """Execute a segment with one docker exec while tracing each command separately.

    Every real command is still wrapped by its own strace process and appends
    to the same trace. The optimization is removing per-command docker exec
    overhead.

    `per_cmd_timeout_sec` 同时控制 (a) runner.sh 里每条命令 `timeout ${N}s ...` 的 N,
    (b) 整个 batch 的 docker exec 上限 `max_runtime = max(30, N * len(commands) + 20)`。
    E0 collector 跑 warmup/cooldown sleep 60/120 时必须传一个 ≥ 最长命令的值,否则被杀。
    """
    if not commands:
        return []

    from .execute import STRACE_SYSCALLS

    batch_id = uuid.uuid4().hex[:12]
    container_dir = f"/tmp/pids_batch_{batch_id}"
    max_runtime = max(30, per_cmd_timeout_sec * len(commands) + 20)
    outputs: List[CommandOutput] = []

    _docker_exec(f"rm -rf {container_dir} && mkdir -p {container_dir}", timeout=10)
    try:
        with tempfile.TemporaryDirectory(prefix="pids_batch_") as td:
            root = Path(td)
            cmds_dir = root / "cmds"
            cmds_dir.mkdir()
            for i, cmd in enumerate(commands):
                cmd_path = cmds_dir / f"cmd_{i:04d}.sh"
                cmd_path.write_text(cmd + ("\n" if not cmd.endswith("\n") else ""))

            capture_flag = "1" if capture_trace else "0"
            runner = root / "runner.sh"
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set +e\n"
                f"CMD_DIR={container_dir}/cmds\n"
                f"OUT_DIR={container_dir}/out\n"
                f"TRACE_PATH={trace_path_in_container}\n"
                f"SYSCALLS={STRACE_SYSCALLS}\n"
                f"CAPTURE_TRACE={capture_flag}\n"
                f"PER_CMD_TIMEOUT={per_cmd_timeout_sec}\n"
                "mkdir -p \"$OUT_DIR\"\n"
                "i=0\n"
                "for cmd_file in \"$CMD_DIR\"/cmd_*.sh; do\n"
                "  [ -e \"$cmd_file\" ] || break\n"
                "  out=\"$OUT_DIR/out_${i}.stdout\"\n"
                "  err=\"$OUT_DIR/out_${i}.stderr\"\n"
                "  code=\"$OUT_DIR/out_${i}.code\"\n"
                "  timing=\"$OUT_DIR/out_${i}.time\"\n"
                "  start=$(date +%s%N 2>/dev/null || echo 0)\n"
                "  if [ \"$CAPTURE_TRACE\" = \"1\" ]; then\n"
                "    timeout ${PER_CMD_TIMEOUT}s strace -fA -ttt -s 256 -e \"trace=${SYSCALLS}\" "
                "-o \"$TRACE_PATH\" bash \"$cmd_file\" > \"$out\" 2> \"$err\"\n"
                "  else\n"
                "    timeout ${PER_CMD_TIMEOUT}s bash \"$cmd_file\" > \"$out\" 2> \"$err\"\n"
                "  fi\n"
                "  rc=$?\n"
                "  end=$(date +%s%N 2>/dev/null || echo 0)\n"
                "  printf '%s\\n' \"$rc\" > \"$code\"\n"
                "  printf '%s %s\\n' \"$start\" \"$end\" > \"$timing\"\n"
                "  i=$((i + 1))\n"
                "done\n"
            )

            cp_in = subprocess.run(
                ["docker", "cp", f"{td}/.", f"{CONTAINER_NAME}:{container_dir}/"],
                capture_output=True, text=True, timeout=30,
            )
            if cp_in.returncode != 0:
                raise RuntimeError(cp_in.stderr.strip() or "docker cp batch input failed")

            cp = _docker_exec(f"chmod +x {container_dir}/runner.sh && {container_dir}/runner.sh",
                              timeout=max_runtime)
            if cp.returncode != 0:
                # Individual command failures are recorded in per-command code
                # files. A non-zero runner code means setup/execution itself
                # failed, so expose it as stderr on missing outputs below.
                runner_error = cp.stderr or cp.stdout
            else:
                runner_error = ""

            out_local = root / "out"
            out_local.mkdir(exist_ok=True)
            cp_out = subprocess.run(
                ["docker", "cp", f"{CONTAINER_NAME}:{container_dir}/out/.", str(out_local)],
                capture_output=True, text=True, timeout=30,
            )
            if cp_out.returncode != 0 and not runner_error:
                runner_error = cp_out.stderr.strip() or "docker cp batch output failed"

            for i, cmd in enumerate(commands):
                stdout = _read_text(out_local / f"out_{i}.stdout")
                stderr = _read_text(out_local / f"out_{i}.stderr")
                code = _read_int(out_local / f"out_{i}.code", default=1)
                duration = _read_duration(out_local / f"out_{i}.time")
                if not stdout and not stderr and runner_error:
                    stderr = runner_error
                outputs.append(CommandOutput(cmd, stdout, stderr, code, duration))
    except subprocess.TimeoutExpired:
        return [
            CommandOutput(cmd, "", "[BATCH_TIMEOUT]", 124, 0.0)
            for cmd in commands
        ]
    except Exception as e:
        return [
            CommandOutput(cmd, "", f"[BATCH_ERROR] {e}", 1, 0.0)
            for cmd in commands
        ]
    finally:
        try:
            _docker_exec(f"rm -rf {container_dir}", timeout=10)
        except Exception:
            pass

    # If the runner produced fewer records than expected, keep positional
    # alignment with the input command list.
    while len(outputs) < len(commands):
        outputs.append(CommandOutput(commands[len(outputs)], "", "[BATCH_MISSING_OUTPUT]", 1, 0.0))
    return outputs


def apply_a0_mutation(
    A0_steps: List[Dict[str, Any]],
    mutated_a0: Optional[List[str]],
) -> List[Dict[str, Any]]:
    """v6 TODO #5 (C8) 纯函数:把 A0 各 step 的 command 替换成 mutated_a0[i]。

    返回**新列表**,不动原 list。每个 step 的其他字段(step_id / checker / final_check) 保留。
    None 或 等长 list 时:
      - None  → 返回原 A0(浅拷贝)
      - list  → 长度必须 = len(A0_steps),否则 ValueError
    """
    if mutated_a0 is None:
        return list(A0_steps)
    if len(mutated_a0) != len(A0_steps):
        raise ValueError(
            f"mutated_a0 length {len(mutated_a0)} != A0 length {len(A0_steps)}"
        )
    return [
        {**orig, "command": new_cmd}
        for orig, new_cmd in zip(A0_steps, mutated_a0)
    ]


def execute_with_checks(
    scenario: Dict[str, Any],
    delta_commands: List[str],
    delta_positions: List[int],
    capture_trace: bool = True,
    reset: bool = True,
    mutated_a0: Optional[List[str]] = None,
) -> AttackExecutionResult:
    """v6 TODO #5 (C8) 改造:支持 mutated_a0 参数 — 节点级 op 改 A0 自身。

    mutated_a0:
      - None  → 走 v5 老通路(δ append-only,A0 不动)
      - list[str] → 替换 scenario['steps'] 各 step 的 command 为这个列表对应位置的值
                    长度必须 = len(scenario['steps']) ;
                    checker 仍用原 scenario step 的 step_id / checker spec(只换 command 字符串)
    """
    if reset:
        reset_container()
    A0_steps_orig = scenario["steps"]
    A0_steps = apply_a0_mutation(A0_steps_orig, mutated_a0)
    final_check = scenario.get("final_attack_check")
    scenario_id = scenario["scenario_id"]

    SYSDIG_OUTPUT_DIR = os.environ.get("PIDS_RANGE_SYSDIG_DIR", "/tmp/pids_attack_traces")
    os.makedirs(SYSDIG_OUTPUT_DIR, exist_ok=True)
    trace_id = uuid.uuid4().hex[:12]
    container_trace = f"/tmp/pids_trace_{trace_id}.strace"
    container_proc_snapshot = f"/tmp/pids_trace_{trace_id}.strace.proc_snapshot"
    if capture_trace:
        _docker_exec(f"rm -f {container_trace} && touch {container_trace}", timeout=10)
        # Phase 3: dump /proc 快照(strace 起跑前已运行进程的 cmdline / exe)
        _docker_exec(
            'for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do '
            '  cmdline=$(tr "\\0" " " < /proc/$pid/cmdline 2>/dev/null); '
            '  exe=$(readlink /proc/$pid/exe 2>/dev/null); '
            '  echo "PID=$pid CMDLINE=\\"$cmdline\\" EXE=\\"$exe\\""; '
            f'done > {container_proc_snapshot}',
            timeout=15,
        )

    sequence = _interleave(A0_steps, delta_commands, delta_positions)
    step_results: List[StepCheckResult] = []
    cmd_outputs: List[CommandOutput] = []
    failed_step: Optional[int] = None
    all_steps_passed = True

    pending: List[Tuple[str, Any]] = []

    def flush_pending() -> bool:
        nonlocal all_steps_passed, failed_step, pending
        if not pending:
            return True
        commands = [
            item if kind == "delta" else item["command"]
            for kind, item in pending
        ]
        outputs = _exec_traced_batch_safe(commands, container_trace, capture_trace)
        for (kind, item), co in zip(pending, outputs):
            cmd_outputs.append(co)
            if kind != "step":
                continue
            spec = dict(item["checker"])
            spec["step_id"] = item.get("step_id", -1)
            result = run_checker(spec, co)
            step_results.append(result)
            if not result.success:
                all_steps_passed = False
                failed_step = result.step_id
                pending = []
                return False
        pending = []
        return True

    for kind, item in sequence:
        pending.append((kind, item))
        if kind == "step" and not flush_pending():
            break

    if all_steps_passed and pending:
        flush_pending()

    final_succeeded = False
    if all_steps_passed and final_check is not None:
        spec = dict(final_check)
        spec["step_id"] = -1
        last_out = cmd_outputs[-1] if cmd_outputs else CommandOutput("", "", "", 0, 0.0)
        fres = run_checker(spec, last_out)
        final_succeeded = fres.success
    elif all_steps_passed and final_check is None:
        final_succeeded = True

    # cp 到 host(trace 已经在容器内被 strace -A 合并到一个文件)+ /proc 快照
    trace_local = ""
    if capture_trace:
        trace_local = os.path.join(SYSDIG_OUTPUT_DIR, f"trace_{trace_id}.strace")
        try:
            subprocess.run(
                ["docker", "cp", f"{CONTAINER_NAME}:{container_trace}", trace_local],
                capture_output=True, timeout=30,
            )
            # Phase 3: /proc 快照跟 trace 一起 cp,parse_strace_text 自动加载
            subprocess.run(
                ["docker", "cp", f"{CONTAINER_NAME}:{container_proc_snapshot}",
                 trace_local + ".proc_snapshot"],
                capture_output=True, timeout=30,
            )
        except Exception:
            pass

    return AttackExecutionResult(
        scenario_id=scenario_id,
        all_steps_passed=all_steps_passed,
        final_attack_succeeded=final_succeeded,
        step_results=step_results,
        failed_step=failed_step,
        trace_path=trace_local if capture_trace else None,
        command_outputs=cmd_outputs,
    )
