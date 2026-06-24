"""syscall trace → CDM (DARPA TC) → PostgreSQL 转换器。

支持两种 trace 输入：
- sysdig (.scap → JSONL via `sysdig -j`)
- strace (text format, `-f -ttt`)

实施重点（按需求文档 §4.2）：
- syscall→event 类型映射覆盖 10 种 EVENT_*
- 节点抽取覆盖 3 种类型（subject / file / netflow）
- 时间戳 CDM 标准 nanoseconds since epoch
- UUID 唯一
- 直接生成 PostgreSQL 填库 SQL，跳过 Avro 序列化（按文档建议）

参考：
- https://github.com/darpa-i2o/Transparent-Computing/blob/master/schema/TCCDMDatum.avsc
- PIDSMaker dataset_preprocessing/darpa_tc/create_database_e3.py
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# syscall → CDM EVENT_* 映射
SYSCALL_TO_EVENT: Dict[str, str] = {
    "read": "EVENT_READ", "pread": "EVENT_READ", "preadv": "EVENT_READ", "readv": "EVENT_READ",
    "write": "EVENT_WRITE", "pwrite": "EVENT_WRITE", "writev": "EVENT_WRITE", "pwritev": "EVENT_WRITE",
    "open": "EVENT_OPEN", "openat": "EVENT_OPEN", "creat": "EVENT_OPEN",
    "execve": "EVENT_EXECUTE", "execveat": "EVENT_EXECUTE",
    "connect": "EVENT_CONNECT",
    "recvfrom": "EVENT_RECVFROM",
    "recvmsg": "EVENT_RECVMSG",
    "sendto": "EVENT_SENDTO",
    "sendmsg": "EVENT_SENDMSG",
    "clone": "EVENT_CLONE", "fork": "EVENT_CLONE", "vfork": "EVENT_CLONE", "clone3": "EVENT_CLONE",
}

NODE_TYPES = ("subject", "file", "netflow")
EDGE_TYPES = (
    "EVENT_READ", "EVENT_WRITE", "EVENT_OPEN", "EVENT_EXECUTE",
    "EVENT_CONNECT", "EVENT_RECVFROM", "EVENT_RECVMSG",
    "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_CLONE",
)


@dataclass
class CDMNode:
    uuid: str
    node_type: str  # subject / file / netflow
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CDMEvent:
    uuid: str
    event_type: str  # EVENT_*
    timestamp_ns: int
    subject_uuid: str
    object_uuid: Optional[str]
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CDMGraph:
    nodes: Dict[str, CDMNode] = field(default_factory=dict)
    events: List[CDMEvent] = field(default_factory=list)
    node_key_to_uuid: Dict[str, str] = field(default_factory=dict)


# ------------------- sysdig parsing -------------------

def sysdig_export_json(scap_path: str, json_path: str) -> None:
    """sysdig -p ... 导出 JSON。需要 sysdig 在 PATH 上。"""
    fields = (
        "%evt.num %evt.time.ns %evt.type %proc.pid %proc.name %proc.exe "
        "%proc.cmdline %fd.name %fd.type %fd.sport %fd.cport %fd.sip %fd.cip %evt.args"
    )
    with open(json_path, "w") as f:
        subprocess.run(
            ["sysdig", "-r", scap_path, "-j", "-p", fields],
            stdout=f, check=False, timeout=600,
        )


def parse_sysdig_jsonl(json_path: str) -> List[Dict[str, Any]]:
    out = []
    with open(json_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


# ------------------- CDM 构造 -------------------

def _stable_node_uuid(key: str) -> str:
    """Deterministic node uuid from semantic node key.

    This keeps graph_to_sql mapping reproducible across repeated parses of the
    same trace, which is required for offline E0 GT recomputation.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"safemimic-cdm:{key}"))


def _ensure_node_by_key(
    graph: CDMGraph,
    *,
    key: str,
    node_type: str,
    properties: Dict[str, Any],
) -> str:
    u = graph.node_key_to_uuid.get(key)
    if u and u in graph.nodes:
        return u

    # Backward compatibility for tests or callers that manually populate
    # graph.nodes without node_key_to_uuid.
    for existing_u, n in graph.nodes.items():
        if n.node_type == node_type and n.properties.get("_key") == key:
            graph.node_key_to_uuid[key] = existing_u
            return existing_u

    u = _stable_node_uuid(key)
    graph.nodes[u] = CDMNode(uuid=u, node_type=node_type, properties=properties)
    graph.node_key_to_uuid[key] = u
    return u


def _ensure_subject_node(graph: CDMGraph, pid: int, exe: str, cmdline: str, name: str) -> str:
    key = f"subject:{pid}:{exe}"
    return _ensure_node_by_key(
        graph,
        key=key,
        node_type="subject",
        properties={
            "_key": key,
            "pid": pid,
            "exec_path": exe,
            "cmdline": cmdline,
            "comm": name,
        },
    )


def _ensure_file_node(graph: CDMGraph, path: str) -> str:
    key = f"file:{path}"
    return _ensure_node_by_key(
        graph,
        key=key,
        node_type="file",
        properties={"_key": key, "path": path},
    )


def _ensure_netflow_node(graph: CDMGraph, sip: str, sport: str, cip: str, cport: str) -> str:
    key = f"netflow:{sip}:{sport}:{cip}:{cport}"
    return _ensure_node_by_key(
        graph,
        key=key,
        node_type="netflow",
        properties={
            "_key": key,
            "src_ip": sip,
            "src_port": sport,
            "dst_ip": cip,
            "dst_port": cport,
        },
    )


def _evt_to_cdm(graph: CDMGraph, evt: Dict[str, Any]) -> Optional[CDMEvent]:
    syscall = (evt.get("evt.type") or "").lower()
    cdm_event = SYSCALL_TO_EVENT.get(syscall)
    if not cdm_event:
        return None
    pid = int(evt.get("proc.pid") or 0)
    name = evt.get("proc.name") or ""
    exe = evt.get("proc.exe") or name
    cmdline = evt.get("proc.cmdline") or ""
    subj = _ensure_subject_node(graph, pid, exe, cmdline, name)
    obj = None
    fd_name = evt.get("fd.name") or ""
    fd_type = evt.get("fd.type") or ""
    if cdm_event in {"EVENT_CONNECT", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_SENDTO", "EVENT_SENDMSG"}:
        obj = _ensure_netflow_node(
            graph,
            str(evt.get("fd.sip") or ""), str(evt.get("fd.sport") or ""),
            str(evt.get("fd.cip") or ""), str(evt.get("fd.cport") or ""),
        )
    elif cdm_event == "EVENT_CLONE":
        # CLONE 的 object 是新 child；这里没有现成字段 — 留 None，PIDSMaker 在 graph 构造时处理
        obj = None
    elif fd_name:
        obj = _ensure_file_node(graph, fd_name)
    ts_ns = int(evt.get("evt.time.ns") or 0)
    e = CDMEvent(
        uuid=str(uuid.uuid4()),
        event_type=cdm_event,
        timestamp_ns=ts_ns,
        subject_uuid=subj,
        object_uuid=obj,
        properties={"args": evt.get("evt.args", "")[:512]},
    )
    return e


def build_cdm_graph(events: List[Dict[str, Any]]) -> CDMGraph:
    g = CDMGraph()
    for evt in events:
        ce = _evt_to_cdm(g, evt)
        if ce:
            g.events.append(ce)
    return g


# ------------------- PostgreSQL 填库脚本(PIDSMaker 4.0 对齐) -------------------
# 参考 pids_attack/PIDSMaker/dataset_preprocessing/create_database.sh 的 DDL
# 参考 pids_attack/PIDSMaker/dataset_preprocessing/darpa_tc/create_database_e3.py 的 row format

DDL_SQL = """
CREATE TABLE IF NOT EXISTS subject_node_table (
    node_uuid VARCHAR,
    hash_id VARCHAR,
    path VARCHAR,
    cmd VARCHAR,
    index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE IF NOT EXISTS file_node_table (
    node_uuid VARCHAR NOT NULL,
    hash_id VARCHAR NOT NULL,
    path VARCHAR,
    index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE IF NOT EXISTS netflow_node_table (
    node_uuid VARCHAR NOT NULL,
    hash_id VARCHAR NOT NULL,
    src_addr VARCHAR,
    src_port VARCHAR,
    dst_addr VARCHAR,
    dst_port VARCHAR,
    index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE IF NOT EXISTS event_table (
    src_node VARCHAR,
    src_index_id VARCHAR,
    operation VARCHAR,
    dst_node VARCHAR,
    dst_index_id VARCHAR,
    event_uuid VARCHAR NOT NULL,
    timestamp_rec BIGINT,
    _id SERIAL PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS event_table_src_idx ON event_table (src_node);
CREATE INDEX IF NOT EXISTS event_table_dst_idx ON event_table (dst_node);
CREATE INDEX IF NOT EXISTS event_table_ts_idx ON event_table (timestamp_rec);
"""


def _esc(s: Any) -> str:
    if s is None:
        return "NULL"
    return "'" + str(s).replace("'", "''") + "'"


def _hash_id(uuid_str: str) -> str:
    """对应 PIDSMaker 的 stringtomd5(uuid),全 16 进制 32 字符。"""
    return hashlib.md5(uuid_str.encode()).hexdigest()


def _graph_to_sql_and_mapping(graph: CDMGraph) -> Tuple[str, Dict[str, int]]:
    """产 PIDSMaker 4.0 兼容 SQL(4 张 _table 表 + (node_uuid, hash_id) 复合主键 + index_id 全局自增)。

    Returns:
        sql_text: 完整 SQL dump 文本
        uuid_to_index_id: 三类节点 (netflow / subject / file) 的 uuid → 全局 index_id 映射,
            供 E0 marker-window GT 抽取做"event 触达 uuid → SQL index_id 集合"对齐。
    """
    lines: List[str] = [DDL_SQL.strip(), ""]
    # 全局 index_id 自增,对齐 PIDSMaker:net → subject → file 的灌库顺序
    index_id = 0
    # uuid → hash_id 映射,event_table 写入时复用
    uuid_to_hash: Dict[str, str] = {}
    # uuid → 全局 index_id 映射,供调用方对齐 SQL 节点
    uuid_to_index_id: Dict[str, int] = {}

    # 1. netflow 节点先写
    for u, n in graph.nodes.items():
        if n.node_type != "netflow":
            continue
        p = n.properties
        h = _hash_id(u)
        uuid_to_hash[u] = h
        uuid_to_index_id[u] = index_id
        lines.append(
            f"INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id) "
            f"VALUES ({_esc(u)}, {_esc(h)}, "
            f"{_esc(p.get('src_ip'))}, {_esc(p.get('src_port'))}, "
            f"{_esc(p.get('dst_ip'))}, {_esc(p.get('dst_port'))}, {index_id}) "
            f"ON CONFLICT DO NOTHING;"
        )
        index_id += 1

    # 2. subject 节点
    for u, n in graph.nodes.items():
        if n.node_type != "subject":
            continue
        p = n.properties
        h = _hash_id(u)
        uuid_to_hash[u] = h
        uuid_to_index_id[u] = index_id
        path_v = p.get("exec_path") or p.get("comm") or ""
        cmd_v = p.get("cmdline") or ""
        lines.append(
            f"INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) "
            f"VALUES ({_esc(u)}, {_esc(h)}, {_esc(path_v)}, {_esc(cmd_v)}, {index_id}) "
            f"ON CONFLICT DO NOTHING;"
        )
        index_id += 1

    # 3. file 节点
    for u, n in graph.nodes.items():
        if n.node_type != "file":
            continue
        h = _hash_id(u)
        uuid_to_hash[u] = h
        uuid_to_index_id[u] = index_id
        lines.append(
            f"INSERT INTO file_node_table (node_uuid, hash_id, path, index_id) "
            f"VALUES ({_esc(u)}, {_esc(h)}, "
            f"{_esc(n.properties.get('path'))}, {index_id}) "
            f"ON CONFLICT DO NOTHING;"
        )
        index_id += 1

    # 4. event_table 边
    for e in graph.events:
        src_h = uuid_to_hash.get(e.subject_uuid, _hash_id(e.subject_uuid))
        dst_h = uuid_to_hash.get(e.object_uuid, "") if e.object_uuid else ""
        # PIDSMaker 的 src_index_id / dst_index_id 是 nodeid2msg 索引(原版需要预扫一遍图);
        # 我们简化为 hash_id 字符串(VARCHAR 字段允许),PIDSMaker 训练时会按 hash_id join 节点表
        lines.append(
            f"INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec) "
            f"VALUES ({_esc(src_h)}, {_esc(src_h)}, {_esc(e.event_type)}, "
            f"{_esc(dst_h)}, {_esc(dst_h)}, {_esc(e.uuid)}, {e.timestamp_ns});"
        )
    return "\n".join(lines), uuid_to_index_id


def graph_to_sql(graph: CDMGraph) -> str:
    """产 PIDSMaker 4.0 兼容 SQL。

    保持历史 public API:调用方拿到 SQL 字符串。需要节点 uuid →
    SQL index_id 映射时用 `graph_to_sql_with_mapping`。
    """
    sql, _uuid_to_index_id = _graph_to_sql_and_mapping(graph)
    return sql


def graph_to_sql_with_mapping(graph: CDMGraph) -> Tuple[str, Dict[str, int]]:
    """产 SQL,同时返回 CDM node uuid → SQL global index_id 映射。"""
    return _graph_to_sql_and_mapping(graph)


def sysdig_to_pidsmaker(
    sysdig_trace_file: str,
    output_db_dump: str,
    json_intermediate: Optional[str] = None,
) -> CDMGraph:
    """端到端：sysdig .scap → CDM graph → PostgreSQL 填库 .sql。"""
    json_path = json_intermediate or sysdig_trace_file + ".jsonl"
    if not os.path.exists(json_path):
        sysdig_export_json(sysdig_trace_file, json_path)
    events = parse_sysdig_jsonl(json_path)
    graph = build_cdm_graph(events)
    sql = graph_to_sql(graph)
    with open(output_db_dump, "w") as f:
        f.write(sql)
    return graph


# =================================================================
# strace 后端 — Apple Silicon Docker Desktop 上 sysdig kernel module 不可用，
# 改用 strace（ptrace-based，零内核依赖）。本节实现 strace text → CDM。
# =================================================================

# 一行 strace -f -ttt 输出格式：
#   [pid] timestamp syscall(args) = retval
# 例：
#   375   1778167392.039223 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
_STRACE_LINE_RE = re.compile(
    r"^\s*(?:\[pid\s+)?(\d+)\]?\s+"        # pid
    r"(\d+\.\d+)\s+"                       # timestamp (epoch.fraction)
    r"(\w+)\("                             # syscall name
    r"(.*?)\)\s*=\s*"                      # args
    r"(-?\d+|0x[0-9a-fA-F]+|\?).*$"        # retval
)

# strace 在 syscall 被信号/上下文切换打断时,拆成两行写:
#   pid  ts1  syscall(partial_args <unfinished ...>
#   pid  ts2  <... syscall resumed>rest_args) = retval
# 必须把这两行重新拼成完整 syscall,否则 execve/clone 这类关键事件会丢。
_STRACE_UNFINISHED_RE = re.compile(
    r"^\s*(?:\[pid\s+)?(\d+)\]?\s+"
    r"(\d+\.\d+)\s+"
    r"(\w+)\("
    r"(.*?)\s*<unfinished \.\.\.>\s*$"
)

_STRACE_RESUMED_RE = re.compile(
    r"^\s*(?:\[pid\s+)?(\d+)\]?\s+"
    r"(\d+\.\d+)\s+"
    r"<\.\.\.\s+(\w+)\s+resumed>"
    r"(.*?)\)\s*=\s*"
    r"(-?\d+|0x[0-9a-fA-F]+|\?).*$"
)

_EMBEDDED_EXECVE_RE = re.compile(r"execve\(")
_EMBEDDED_SYSCALL_START_RE = re.compile(r"\d+\s+\d+\.\d+\s+\w+\(")


_PROC_SNAPSHOT_LINE_RE = re.compile(
    r'^PID=(\d+)\s+CMDLINE="([^"]*)"\s+EXE="([^"]*)"\s*$'
)


def _load_proc_snapshot(snapshot_path: str) -> Dict[int, Dict[str, str]]:
    """加载 strace 起跑前 dump 的 /proc 快照,返回 PID → {cmdline, exe}。
    格式:`PID=1234 CMDLINE="bash -c xxx" EXE="/bin/bash"`
    """
    pid_meta: Dict[int, Dict[str, str]] = {}
    if not os.path.exists(snapshot_path):
        return pid_meta
    with open(snapshot_path, errors="replace") as f:
        for line in f:
            m = _PROC_SNAPSHOT_LINE_RE.match(line.strip())
            if m:
                pid_meta[int(m.group(1))] = {
                    "cmdline": m.group(2).strip(),
                    "exe": m.group(3).strip(),
                }
    return pid_meta


def _parse_execve_args(args: str) -> Tuple[str, str]:
    """从 execve(...) args_str 抠 (exe_path, cmdline)。
    args 格式:`"/bin/bash", ["bash", "-c", "ls -la /tmp"], 0x...`
    """
    m_exe = re.match(r'^"([^"]*)"', args)
    exe = m_exe.group(1) if m_exe else ""
    m_argv = re.search(r'\[(.*?)\]', args)
    if m_argv:
        argv = re.findall(r'"([^"]*)"', m_argv.group(1))
        cmdline = " ".join(argv)
    else:
        cmdline = ""
    return exe, cmdline


def parse_strace_text(trace_path: str) -> List[Dict[str, Any]]:
    """把 strace text 文件解析成 sysdig-style event dict 列表。

    填充策略(Phase 3):
    1. 加载 `<trace>.proc_snapshot`(strace 起跑前 dump 的 /proc/*/cmdline 快照)
       → 已在跑的进程(juice-shop / daemon 父 bash)的 cmdline / exe 进 pid_meta
    2. 流式扫 strace,遇到 `execve(...)` 时从 args 抠 argv 更新 pid_meta
    3. 每条 syscall 用 pid_meta 填 proc.exe / proc.cmdline / proc.name
    """
    events: List[Dict[str, Any]] = []
    if not os.path.exists(trace_path):
        return events

    pid_meta = _load_proc_snapshot(trace_path + ".proc_snapshot")
    # (pid, syscall) → (ts_str, partial_args):buffer unfinished 行,等 resumed 行回填
    unfinished_buf: Dict[Tuple[int, str], Tuple[str, str]] = {}

    def _emit(pid: int, ts_str: str, syscall: str, args_str: str, retval: str):
        ts_ns = int(float(ts_str) * 1e9)
        # execve 时更新 PID → cmdline 映射(优先级高于 /proc 快照,因为更新)
        if syscall in ("execve", "execveat"):
            exe, cmdline = _parse_execve_args(args_str)
            if exe:
                pid_meta[pid] = {"cmdline": cmdline or exe, "exe": exe}
        # clone/fork 子进程继承父 meta(直到子自己 execve 才被覆盖)
        elif syscall in ("clone", "clone3", "fork", "vfork"):
            try:
                child_pid = int(retval)
            except (ValueError, TypeError):
                child_pid = 0
            if child_pid > 0 and pid in pid_meta:
                pid_meta[child_pid] = dict(pid_meta[pid])
        meta = pid_meta.get(pid, {"cmdline": "", "exe": ""})
        proc_name = os.path.basename(meta["exe"]) if meta["exe"] else ""
        events.append({
            "evt.type": syscall,
            "evt.time.ns": ts_ns,
            "proc.pid": pid,
            "proc.name": proc_name,
            "proc.exe": meta["exe"],
            "proc.cmdline": meta["cmdline"],
            "fd.name": _strace_extract_path(syscall, args_str),
            "fd.type": "",
            "fd.sport": "", "fd.cport": "", "fd.sip": "", "fd.cip": "",
            "evt.args": args_str[:512],
            "_retval": retval,
        })

    def _recover_embedded_execve(line: str):
        """Recover execve records pasted into another strace line.

        Under high concurrency, strace can occasionally interleave two process
        outputs into one physical line, e.g. `write(... = 8<PID> <ts> execve(...)`.
        The normal line regex then sees only the first syscall and loses the
        execve metadata, so later network events for that PID inherit the wrong
        subject. This best-effort pass extracts such embedded execve snippets
        before normal parsing.
        """
        for m_exec in _EMBEDDED_EXECVE_RE.finditer(line):
            prefix = line[:m_exec.start()]
            m_head = re.search(r"(\d+)\s+(\d+\.\d+)\s+$", prefix)
            if not m_head:
                continue
            pid_s, ts_str = m_head.groups()
            # If execve is already the syscall at the start of the line, normal
            # parsing will handle it. Only recover genuinely embedded records.
            if prefix.strip() == f"{pid_s} {ts_str}":
                continue
            # Common strace paste pattern: previous retval `8` sticks to pid
            # `55964`, producing `855964`. Keep the PID-looking suffix.
            if len(pid_s) > 5 and int(pid_s) > 100000:
                pid_s = pid_s[-5:]

            args = line[m_exec.end():]
            next_start = _EMBEDDED_SYSCALL_START_RE.search(args)
            if next_start:
                args = args[:next_start.start()]
            if " <unfinished ...>" in args:
                args = args.split(" <unfinished ...>", 1)[0]
            if ") = " in args:
                args = args.split(") = ", 1)[0]
            args = args.strip()
            if args:
                _emit(int(pid_s), ts_str, "execve", args, "0")

    with open(trace_path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("---") or line.startswith("+++"):
                continue

            _recover_embedded_execve(line)

            # 1. unfinished 行:先 buffer
            m_un = _STRACE_UNFINISHED_RE.match(line)
            if m_un:
                pid_s, ts_un, syscall, partial_args = m_un.groups()
                unfinished_buf[(int(pid_s), syscall)] = (ts_un, partial_args)
                continue

            # 2. resumed 行:跟 buffer 拼成完整 syscall
            m_re = _STRACE_RESUMED_RE.match(line)
            if m_re:
                pid_s, ts_re, syscall, rest_args, retval = m_re.groups()
                pid_n = int(pid_s)
                buf = unfinished_buf.pop((pid_n, syscall), None)
                if buf is not None:
                    ts_un, partial_args = buf
                    full_args = (partial_args + rest_args).strip()
                    _emit(pid_n, ts_un, syscall, full_args, retval)
                else:
                    # 没找到对应 unfinished,只能用 resumed 自己的 rest_args
                    _emit(pid_n, ts_re, syscall, rest_args.strip(), retval)
                continue

            # 3. 完整一行的 syscall:照常处理
            m = _STRACE_LINE_RE.match(line)
            if not m:
                continue
            pid_s, ts_str, syscall, args_str, retval = m.groups()
            _emit(int(pid_s), ts_str, syscall, args_str, retval)
    return events


def _strace_extract_path(syscall: str, args: str) -> str:
    """从 strace args 提取文件路径或 sockaddr。"""
    if syscall in ("open", "creat"):
        m = re.match(r'^"([^"]*)"', args)
        if m:
            return m.group(1)
    elif syscall in ("openat",):
        m = re.search(r',\s*"([^"]*)"', args)
        if m:
            return m.group(1)
    elif syscall in ("execve", "execveat"):
        m = re.match(r'^"([^"]+)"', args)
        if m:
            return m.group(1)
    elif syscall in ("connect", "sendto", "sendmsg", "recvfrom", "recvmsg"):
        # sockaddr_in: sin_port=htons(N), sin_addr=inet_addr("X.X.X.X")
        m = re.search(r'sin_port=htons\((\d+)\).*?inet_addr\("([\d\.]+)"\)', args)
        if m:
            return f"{m.group(2)}:{m.group(1)}"
        # AF_UNIX: sun_path="/var/run/..." 或 abstract "@/tmp/..."
        m_unix = re.search(r'sun_path="([^"]+)"', args)
        if m_unix:
            return f"unix:{m_unix.group(1)}:0"
        # AF_INET6: sin6_port=htons(N), inet_pton(AF_INET6, "X")
        m_v6 = re.search(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"', args)
        if m_v6:
            return f"{m_v6.group(2)}:{m_v6.group(1)}"
    return ""


def _extract_fd_arg(args: str):
    """strace args 第一个参数若是 fd 数字,返回 int,否则 None。"""
    m = re.match(r'^\s*(\d+)\s*,', args)
    return int(m.group(1)) if m else None


def build_cdm_graph_from_strace(trace_path: str) -> CDMGraph:
    """strace text → CDM graph。

    把 strace 输出的 fd path/sockaddr 转换成等价的 sysdig event dict 后复用 build_cdm_graph。
    socket-related events 走 netflow 节点路径。

    维护 (pid, fd) → netflow uuid 缓存:connect 时记下,connect-mode 的
    sendto/recvfrom (sockaddr=NULL) 通过 fd 反查,避免落到空 placeholder netflow。
    """
    events = parse_strace_text(trace_path)
    g = CDMGraph()
    pid_fd_to_netflow: Dict[Tuple[int, int], str] = {}
    for evt in events:
        syscall = evt["evt.type"]
        cdm_event = SYSCALL_TO_EVENT.get(syscall)
        if not cdm_event:
            continue
        pid = evt["proc.pid"]
        name = evt.get("proc.name") or ""
        exe = evt.get("proc.exe") or name
        cmdline = evt.get("proc.cmdline") or name
        subj = _ensure_subject_node(g, pid, exe, cmdline, name)
        obj = None
        fd_name = evt.get("fd.name") or ""
        args = evt.get("evt.args", "")
        if cdm_event in {"EVENT_CONNECT", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_SENDTO", "EVENT_SENDMSG"}:
            fd = _extract_fd_arg(args)
            if fd_name and ":" in fd_name:
                # 显式 sockaddr (AF_INET / AF_INET6 / AF_UNIX) 解析得到
                if fd_name.startswith("unix:"):
                    # unix:/path/to/sock:0 → dst_addr=unix:/path/..., dst_port=0
                    rest = fd_name[len("unix:"):]
                    sock_path, _, port = rest.rpartition(":")
                    obj = _ensure_netflow_node(g, "", "", f"unix:{sock_path}", port or "0")
                else:
                    ip, port = fd_name.rsplit(":", 1)
                    obj = _ensure_netflow_node(g, "", "", ip, port)
                if fd is not None:
                    pid_fd_to_netflow[(pid, fd)] = obj
            elif fd is not None and (pid, fd) in pid_fd_to_netflow:
                # connect-mode sendto/recvfrom (sockaddr=NULL) → 用 fd 反查
                obj = pid_fd_to_netflow[(pid, fd)]
            else:
                # 真的解析不到 → 不创建空 placeholder netflow
                obj = None
        elif cdm_event == "EVENT_CLONE":
            obj = None
        elif fd_name:
            obj = _ensure_file_node(g, fd_name)
        # close(fd) → 释放 fd 缓存(防止 fd 复用时拿到陈旧 netflow)
        if syscall == "close":
            fd = _extract_fd_arg(args)
            if fd is not None:
                pid_fd_to_netflow.pop((pid, fd), None)
        e = CDMEvent(
            uuid=str(uuid.uuid4()),
            event_type=cdm_event,
            timestamp_ns=int(evt["evt.time.ns"]),
            subject_uuid=subj, object_uuid=obj,
            properties={"args": evt.get("evt.args", "")[:512],
                        "retval": evt.get("_retval", "")},
        )
        g.events.append(e)
    return g


def strace_to_pidsmaker(trace_path: str, output_db_dump: str) -> CDMGraph:
    """端到端：strace text → CDM graph → PostgreSQL 填库 .sql。"""
    graph = build_cdm_graph_from_strace(trace_path)
    sql = graph_to_sql(graph)
    with open(output_db_dump, "w") as f:
        f.write(sql)
    return graph


# =================================================================
# 自动派发：根据 trace 文件后缀挑后端
# =================================================================
def trace_to_pidsmaker(trace_path: str, output_db_dump: str) -> CDMGraph:
    """主入口：自动选 sysdig / strace 后端。"""
    if trace_path.endswith(".scap"):
        return sysdig_to_pidsmaker(trace_path, output_db_dump)
    return strace_to_pidsmaker(trace_path, output_db_dump)
