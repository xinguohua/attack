"""G_benign builder — 从 attacker 公开 prior(命令源 + workflow 模板)构造 attacker-side reference。

承 p2_mcts.md §5.1 S1:
> Reference 由 attacker 端 prior G_benign(典型 benign 命令图)给出
> attacker 基于通用编程 / 系统知识构造的典型 benign 命令图

数据源(全公开,attacker 不需要 defender 同源 benign trace):
  1. shared/candidate_pool.txt:115 条 GTFOBins / Atomic Red Team / coreutils 公开命令
  2. BENIGN_WORKFLOWS:hardcoded 5-10 个典型 Linux sysadmin / web / file / network workflow
     每 workflow 是 cmd chain,代表 attacker 凭通用 Linux 经验知道的"benign 命令序列"
  3. WRAPPER_TEMPLATES:`bash -c`, `sudo`, `find -exec` 等 wrapper —
     这些命令同时连 file + netflow + spawn 多类型,是 type_pairs 共现统计的关键来源
"""
from __future__ import annotations
from pathlib import Path
from typing import Iterable, List, Optional

from .builder import _extract_resources, _parse_cmd_args
from .graph import CommandGraph


# ============================================================
# Attacker prior workflows (公开 Linux sysadmin / web 操作典型组合)
# ============================================================

BENIGN_WORKFLOWS: List[List[str]] = [
    # sysadmin daily check
    ["ps -ef", "df -h", "uptime", "free -m", "uname -a"],
    # file audit
    ["find /tmp -type f", "ls -la /tmp", "stat /etc/hostname", "cat /etc/hostname"],
    # network check
    ["ss -tln", "ip route show", "ip a", "curl http://localhost:3000/"],
    # process inspect
    ["ps -p 1", "cat /proc/1/status", "ls -la /proc/1/", "readlink /proc/1/exe"],
    # log query
    ["cat /var/log/syslog", "tail -100 /var/log/auth.log", "grep ERROR /var/log/messages"],
    # web check
    ["curl -s http://localhost:8080/health",
     "curl -s -i http://localhost:3000/api/status",
     "wget -q -O - http://localhost:80/"],
    # incident triage
    ["who -a", "last", "w", "users"],
    # disk usage
    ["du -sh /tmp", "df -h /", "ls -la /var/log"],
]


# Wrapper templates — 同时连 file + netflow + spawn 多类型,是 type_pairs 关键来源
WRAPPER_TEMPLATES: List[str] = [
    "bash -c 'ls /tmp && curl http://localhost:3000/'",
    "bash -c 'cat /etc/hostname; ps -ef'",
    "sh -c 'find /tmp -name *.log | xargs cat'",
    "sudo find / -name '*.conf' -exec cat {} \\;",
    "nohup curl http://localhost:8080/ > /tmp/out.log &",
    "setsid bash -c 'tail -f /var/log/syslog | grep ERROR'",
    "env LANG=C ls -la /etc/",
    "find /tmp -type f -exec stat {} \\;",
    "xargs -I {} curl http://{}:80/ < /tmp/hosts",
    "time bash -c 'curl localhost && cat /etc/hostname'",
]


# ============================================================
# Builder
# ============================================================

def _strip_pool_comment(line: str) -> str:
    """从 candidate_pool 行剥掉 inline source 注释(`# ART/T1082` 之类)。"""
    s = line.strip()
    if not s or s.startswith("#"):
        return ""
    # 去掉 inline 注释
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    return s


def _load_candidate_pool(path: Path) -> List[str]:
    """从 candidate_pool.txt 加载命令清单。"""
    out: List[str] = []
    for line in open(path):
        cmd = _strip_pool_comment(line)
        if cmd:
            out.append(cmd)
    return out


def _add_workflow_chain(G: CommandGraph, cmds: List[str]) -> List[int]:
    """把一条 cmd chain 加进 G,每条命令一个节点,顺序连 E_seq。

    返回:新加节点的 id 列表(用于上层调试)。
    """
    ids = []
    prev_id: Optional[int] = None
    for cmd in cmds:
        if not cmd.strip():
            continue
        args = _parse_cmd_args(cmd)
        r_in, r_out = _extract_resources(cmd)
        nid = G.add_node(
            raw_command=cmd,
            args=args,
            inputs=r_in,
            outputs=r_out,
            is_attack=False,                            # G_benign 全部 benign reference
        )
        ids.append(nid)
        if prev_id is not None:
            G.e_seq.append((prev_id, nid))
        prev_id = nid
    return ids


def build_g_benign_from_pool(
    candidate_pool_path: Optional[Path] = None,
    workflows: Optional[List[List[str]]] = None,
    wrappers: Optional[List[str]] = None,
) -> CommandGraph:
    """从 attacker prior(命令源)构 G_benign(承 p2_mcts.md §5.1 S1)。

    Args:
      candidate_pool_path:`shared/candidate_pool.txt`(115 条 GTFOBins/ART/coreutils 命令)
                          None 时默认走 `pids_attack/shared/candidate_pool.txt`
      workflows:典型 benign workflow 列表(每 workflow 一个 cmd chain),默认 BENIGN_WORKFLOWS
      wrappers:wrapper 命令列表(同时连多类型,为 type_pairs 共现作贡献),默认 WRAPPER_TEMPLATES

    输出 CommandGraph:
      节点 = candidate_pool 条目 + workflows 内命令 + wrappers
      E_seq:workflow 内顺序连接(workflow 间不连)
      E_res:自动 refresh
      E_spawn:wrapper 命令在 args 解析时不显式加(R3 不依赖 E_spawn,Phase 5 实测)

    跟旧 strace-based 版本的区别:
      - 不依赖 defender 训练数据(符合 attacker prior 威胁模型)
      - 节点数 ~140(115 + 30 workflow + 10 wrapper),远小于 strace 抽的 14430
      - 资源没系统库 noise(`/lib/libc.so` 等)
    """
    if candidate_pool_path is None:
        candidate_pool_path = Path(__file__).resolve().parent.parent / "shared" / "candidate_pool.txt"

    G = CommandGraph()

    # 1. candidate_pool — 每条命令一个节点(无 E_seq,因为 attacker 视它们为独立 benign 命令模板)
    pool = _load_candidate_pool(Path(candidate_pool_path))
    for cmd in pool:
        args = _parse_cmd_args(cmd)
        r_in, r_out = _extract_resources(cmd)
        G.add_node(
            raw_command=cmd,
            args=args,
            inputs=r_in,
            outputs=r_out,
            is_attack=False,
        )

    # 2. workflows — 每 workflow 内顺序 chain,提供 cmd-name 跨命令关联
    workflows = workflows if workflows is not None else BENIGN_WORKFLOWS
    for wf in workflows:
        _add_workflow_chain(G, wf)

    # 3. wrappers — 每个 wrapper 一个独立节点(同时连 file + netflow + spawn 等多类型)
    wrappers = wrappers if wrappers is not None else WRAPPER_TEMPLATES
    for wrap in wrappers:
        args = _parse_cmd_args(wrap)
        r_in, r_out = _extract_resources(wrap)
        G.add_node(
            raw_command=wrap,
            args=args,
            inputs=r_in,
            outputs=r_out,
            is_attack=False,
        )

    # 自动 refresh E_res(节点间资源共享)
    G.refresh_e_res()
    return G


# 旧 strace-based API 已删除(违反 attacker prior 威胁模型)
# 历史保留兼容性 — 调用即抛 deprecated
def build_g_benign(*args, **kwargs):  # pragma: no cover
    """DEPRECATED:旧 strace-based G_benign 违反 attacker prior 威胁模型(用 defender 同源 trace)。

    用 `build_g_benign_from_pool` 代替(从 candidate_pool + workflows 构造)。
    """
    raise NotImplementedError(
        "build_g_benign(strace) deprecated — 违反 p2_mcts.md §5.1 attacker prior 假设。"
        "用 build_g_benign_from_pool(candidate_pool_path, workflows) 代替。"
    )
