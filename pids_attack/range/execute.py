"""execute_in_range — 在容器内执行命令并采集 syscall trace。

trace 后端：默认用 strace（Apple Silicon Docker Desktop 上 sysdig kernel module
不可加载）。strace 是 ptrace-based，零内核依赖，容器内 100% 工作。
"""
from __future__ import annotations
import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


CONTAINER_NAME = os.environ.get("PIDS_RANGE_CONTAINER", "pids_range")
SYSDIG_OUTPUT_DIR = os.environ.get("PIDS_RANGE_SYSDIG_DIR", "/tmp/pids_attack_traces")
TRACE_BACKEND = os.environ.get("PIDS_TRACE_BACKEND", "strace")  # strace | sysdig

# strace 跟踪的 syscall 集合（覆盖 PIDSMaker 的 10 种 EVENT_*）
STRACE_SYSCALLS = ",".join([
    "open", "openat", "creat",
    "read", "pread64", "readv",
    "write", "pwrite64", "writev",
    "execve", "execveat",
    "connect",
    "sendto", "sendmsg",
    "recvfrom", "recvmsg",
    "clone", "clone3", "fork", "vfork",
])


@dataclass
class CommandOutput:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    response_time_sec: float


@dataclass
class ExecutionResult:
    trace_path: str
    command_outputs: List[CommandOutput]
    sysdig_pid: Optional[int] = None  # 字段名保留兼容；strace 模式下为 strace 进程 pid

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["command_outputs"] = [asdict(c) for c in self.command_outputs]
        return d


def _docker_exec(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def reset_container() -> None:
    """重启容器内 juice-shop，清理临时状态。"""
    try:
        subprocess.run(["docker", "exec", CONTAINER_NAME, "pkill", "-f", "node"],
                       capture_output=True, timeout=10)
    except Exception:
        pass
    time.sleep(0.5)
    try:
        subprocess.Popen(
            ["docker", "exec", "-d", CONTAINER_NAME, "bash", "-c",
             "cd /opt/juice-shop && nohup node build/app.js > /var/log/juice-shop.log 2>&1 &"],
        )
    except Exception:
        pass
    # 等 juice-shop 起来
    for _ in range(30):
        try:
            cp = subprocess.run(
                ["docker", "exec", CONTAINER_NAME, "bash", "-c",
                 "timeout 4s curl --max-time 3 -sf -o /dev/null http://localhost:3000/"],
                capture_output=True, timeout=7,
            )
            if cp.returncode == 0:
                return
        except Exception:
            pass
        time.sleep(1)


# -------------------- trace 采集（strace 主，sysdig 兜底）--------------------

def execute_in_range(
    commands: List[str],
    reset: bool = True,
    capture_trace: bool = True,
) -> ExecutionResult:
    """
    1. （可选）reset 容器
    2. 容器内逐条执行 commands；每条命令用 strace 包裹（per-command trace 然后合并）
    3. 把每条命令的 trace 文件 cp 到宿主机
    4. 返回合并后的 trace_path（host 上）
    """
    if reset:
        reset_container()

    os.makedirs(SYSDIG_OUTPUT_DIR, exist_ok=True)
    trace_id = uuid.uuid4().hex[:12]

    if not capture_trace:
        outputs = _run_commands_no_trace(commands)
        return ExecutionResult(trace_path="", command_outputs=outputs)

    if TRACE_BACKEND == "sysdig":
        return _execute_sysdig(commands, trace_id)
    return _execute_strace(commands, trace_id)


def _run_commands_no_trace(commands: List[str]) -> List[CommandOutput]:
    outputs: List[CommandOutput] = []
    for cmd in commands:
        t0 = time.time()
        try:
            cp = _docker_exec(cmd, timeout=30)
            outputs.append(CommandOutput(cmd, cp.stdout, cp.stderr, cp.returncode, time.time() - t0))
        except subprocess.TimeoutExpired as e:
            outputs.append(CommandOutput(
                cmd, e.stdout.decode() if e.stdout else "",
                (e.stderr.decode() if e.stderr else "") + "[TIMEOUT]", 124, time.time() - t0,
            ))
    return outputs


# ---- strace 后端 ----

def _execute_strace(commands: List[str], trace_id: str) -> ExecutionResult:
    """每条 cmd 单独 strace，所有 trace 合并到一个文件。"""
    container_dir = "/tmp/pids_traces"
    _docker_exec(f"mkdir -p {container_dir} && rm -f {container_dir}/*", timeout=10)

    outputs: List[CommandOutput] = []
    for i, cmd in enumerate(commands):
        per_trace = f"{container_dir}/cmd_{i:03d}.strace"
        # 容器内 timeout 8s 硬限 + bash -c 让 strace -f 跟踪 shell pipeline 子进程
        traced_cmd = (
            f"timeout 8s strace -f -ttt -s 256 -e trace={STRACE_SYSCALLS} "
            f"-o {per_trace} bash -c {_shquote(cmd)}"
        )
        t0 = time.time()
        try:
            cp = _docker_exec(traced_cmd, timeout=12)
            outputs.append(CommandOutput(
                cmd, cp.stdout, cp.stderr, cp.returncode, time.time() - t0,
            ))
        except subprocess.TimeoutExpired as e:
            outputs.append(CommandOutput(
                cmd, e.stdout.decode() if e.stdout else "",
                (e.stderr.decode() if e.stderr else "") + "[TIMEOUT]", 124, time.time() - t0,
            ))

    # 合并所有 strace 输出到一个 file
    merged_in_container = f"{container_dir}/merged_{trace_id}.strace"
    _docker_exec(f"cat {container_dir}/cmd_*.strace > {merged_in_container} 2>/dev/null", timeout=10)

    # cp 到 host
    trace_path_local = os.path.join(SYSDIG_OUTPUT_DIR, f"trace_{trace_id}.strace")
    try:
        subprocess.run(
            ["docker", "cp", f"{CONTAINER_NAME}:{merged_in_container}", trace_path_local],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass

    return ExecutionResult(trace_path=trace_path_local, command_outputs=outputs)


def _shquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


# ---- sysdig 后端（保留作 fallback；Docker Desktop on Apple Silicon 不工作）----

def _start_sysdig(trace_path: str) -> subprocess.Popen:
    cmd = [
        "docker", "exec", "-d", CONTAINER_NAME, "bash", "-c",
        f"nohup sysdig -w {trace_path} -e 100000 > /tmp/sysdig.log 2>&1 &",
    ]
    return subprocess.Popen(cmd)


def _stop_sysdig() -> None:
    try:
        subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "pkill", "-f", "sysdig"],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def _execute_sysdig(commands: List[str], trace_id: str) -> ExecutionResult:
    container_path = f"/tmp/trace_{trace_id}.scap"
    host_path = os.path.join(SYSDIG_OUTPUT_DIR, f"trace_{trace_id}.scap")
    _start_sysdig(container_path)
    time.sleep(0.5)
    outputs = _run_commands_no_trace(commands)
    _stop_sysdig()
    try:
        subprocess.run(
            ["docker", "cp", f"{CONTAINER_NAME}:{container_path}", host_path],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass
    return ExecutionResult(trace_path=host_path, command_outputs=outputs)
