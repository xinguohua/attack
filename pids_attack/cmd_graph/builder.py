"""命令依赖图 builder。

build_g_from_a0(json) — 从 scenarios/juiceshop/*.json 构造初始 G_0(所有节点 is_attack=True)
                       每条 step 一个节点 + E_seq chain;资源 = URL / file path 正则抽

注:R3 reference G_benign 走 cmd_graph/benign.py:build_g_benign_from_pool(attacker prior 命令源),
    早期 build_g_from_strace 已删(违反 attacker prior 威胁模型)。
"""
from __future__ import annotations
import json
import re
import shlex
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union

from .graph import CommandGraph


# ============================================================
# A_0 JSON builder
# ============================================================

# 简单资源抽取正则(Phase 1 启发式 — Phase 1 设计修订点会反思要不要更精细)
_URL_PAT = re.compile(r"https?://([^/:\s]+)(?::(\d+))?", re.IGNORECASE)
_HOST_PORT_PAT = re.compile(r"\b([a-zA-Z0-9_.-]+):(\d{1,5})\b")
_FILE_PATH_PAT = re.compile(r"(?:^|\s|>|<)(/(?:etc|tmp|var|usr|home|root|opt|proc|sys|dev)/[\w./_-]+)")
_REDIRECT_OUT_PAT = re.compile(r">\s*(\S+)")


def _extract_resources(cmd_str: str) -> Tuple[Set[str], Set[str]]:
    """从 shell 命令字符串抽 (R_in, R_out) 资源集。

    Phase 1 启发式(给 Phase 1 设计修订留余地):
      - URL `http://host[:port]` → R_in 加 `host:port`(默认 80/443)
      - 字面 host:port → R_in
      - file path `/etc/...` `/tmp/...` → R_in(粗:不分读 / 写)
      - shell redirect `> file` → R_out
    """
    r_in: Set[str] = set()
    r_out: Set[str] = set()

    for m in _URL_PAT.finditer(cmd_str):
        host = m.group(1)
        port = m.group(2) or ("443" if m.group(0).startswith("https") else "80")
        r_in.add(f"{host}:{port}")

    for m in _HOST_PORT_PAT.finditer(cmd_str):
        host, port = m.group(1), m.group(2)
        # 滤掉看起来像版本号(1.2 / 3.0)
        if "." in host and host.replace(".", "").isdigit():
            pass  # 可能是 IP
        if host not in {"HTTP", "Content-Type"}:
            r_in.add(f"{host}:{port}")

    for m in _FILE_PATH_PAT.finditer(cmd_str):
        path = m.group(1)
        # 简单去 trailing `>` 等
        path = path.rstrip(">< ")
        r_in.add(path)

    for m in _REDIRECT_OUT_PAT.finditer(cmd_str):
        target = m.group(1)
        if target not in {"/dev/null", "/dev/stdout", "/dev/stderr"}:
            r_out.add(target)

    return r_in, r_out


def _parse_cmd_args(cmd_str: str) -> List[str]:
    """从 shell 命令抽 args tokens(Rewrite 算子用)。

    复杂 shell(`|`, `;`, `bash -c "..."`)只取首段。
    """
    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        tokens = cmd_str.split()
    return tokens[1:] if tokens else []


def build_g_from_a0(a0_json: Union[str, Path, Dict]) -> CommandGraph:
    """从 attack scenario JSON 构造初始 G_0。

    Input:
      a0_json:JSON 路径(str / Path)或已解析的 dict

    Output:
      CommandGraph,每条 step 一个 is_attack=True 节点,E_seq chain 按 step 顺序串起。
      E_res 自动 refresh(共享资源连边)。
      E_spawn 空(A_0 步骤间默认无 fork-exec 关系)。

    节点数 == len(scenario["steps"]),保证 ≥ A_0 step 数(承 p3 Validation #2)。
    """
    if isinstance(a0_json, (str, Path)):
        with open(a0_json) as f:
            data = json.load(f)
    else:
        data = a0_json

    g = CommandGraph()
    prev_id: Optional[int] = None
    for step in data.get("steps", []):
        cmd_str = step.get("command", "")
        args = _parse_cmd_args(cmd_str)
        r_in, r_out = _extract_resources(cmd_str)
        nid = g.add_node(
            raw_command=cmd_str,
            args=args,
            inputs=r_in,
            outputs=r_out,
            is_attack=True,                              # R1: A_0 节点不可动
        )
        if prev_id is not None:
            g.e_seq.append((prev_id, nid))
        prev_id = nid

    g.refresh_e_res()
    return g


# strace builder 已删除(2026-05-26):
#   早期 Phase 1 留的 strace → G builder,违反 attacker prior 威胁模型;
#   现在 G_benign 走 build_g_benign_from_pool(命令源),
#   build_g_from_a0 是 builder.py 唯一入口。
