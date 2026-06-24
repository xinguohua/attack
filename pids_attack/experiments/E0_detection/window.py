"""E0 marker 时间窗辅助。

Marker 字符串规范:
    __E0_ATTACK_BEGIN__ run=<run_id> scenario=<scenario_id>
    __E0_ATTACK_END__   run=<run_id> scenario=<scenario_id>

通过 echo 写到 stdout/stderr,strace 记录 `write(1, "__E0_ATTACK_BEGIN__ ...", N)`,
正则在 raw.strace 里抓 marker 行,取**行首 `-ttt` timestamp** 作 t_begin / t_end。

`strip_markers` 把 marker write 行从 raw 删掉,产 clean.strace 给后续 CDM 转换用,
避免 marker 字符串污染 detector 输入。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Tuple

# clean trace 不能残留 marker 字符串,所以任何包含 E0 marker 的 strace 行都删除。
_MARKER_PAT = re.compile(r"__E0_(?:ATTACK_(?:BEGIN|END)|STEP_(?:BEGIN|END))__")

# strace `-ttt` 行首格式有两种,都要支持:
#   - 单进程: "1234.567890 write(1, ...)"  → 行首直接是 ts
#   - 多进程 `-f`: "[pid 1234] 5678.901234 write(1, ...)" 或 "1234 5678.901234 write(1, ...)"
# 只有真正输出 marker 的 write(...) 才能定义窗口;bash 读取脚本的 read(255, "...marker...")
# 只是脚本文本,不能算 ATTACK_BEGIN / ATTACK_END。
_MARKER_TS = re.compile(
    r"^(?:(?:\[pid\s+\d+\])|\d+)?\s*"
    r"(\d+\.\d+)\s+write\(\d+,\s+\"__E0_ATTACK_(BEGIN|END)__"
)


def strip_markers(raw_path: Path, clean_path: Path) -> int:
    """从 raw.strace 删除所有 marker 行,写 clean.strace。

    Returns:
        删除的 marker 行数(诊断用)。
    """
    raw_path = Path(raw_path)
    clean_path = Path(clean_path)
    clean_path.parent.mkdir(parents=True, exist_ok=True)
    dropped = 0
    with open(raw_path, errors="replace") as fin, open(clean_path, "w") as fout:
        for line in fin:
            if _MARKER_PAT.search(line):
                dropped += 1
                continue
            fout.write(line)
    return dropped


def extract_window(raw_path: Path) -> Tuple[int, int]:
    """从 raw.strace 抠 ATTACK_BEGIN / ATTACK_END 时间戳(nanosecond)。

    多 BEGIN 取最早,多 END 取最晚(防 echo write syscall 被 strace 拆成多行)。

    Raises:
        RuntimeError: 若 BEGIN 或 END marker 找不到,或 END < BEGIN。
    """
    raw_path = Path(raw_path)
    t_begin_ns: Optional[int] = None
    t_end_ns: Optional[int] = None
    with open(raw_path, errors="replace") as f:
        for line in f:
            m = _MARKER_TS.search(line)
            if not m:
                continue
            ts_sec_str = m.group(1)
            tag = m.group(2)
            ts_ns = int(float(ts_sec_str) * 1e9)
            if tag == "BEGIN":
                if t_begin_ns is None or ts_ns < t_begin_ns:
                    t_begin_ns = ts_ns
            else:  # END
                if t_end_ns is None or ts_ns > t_end_ns:
                    t_end_ns = ts_ns
    if t_begin_ns is None or t_end_ns is None:
        raise RuntimeError(
            f"marker missing in {raw_path}: t_begin={t_begin_ns}, t_end={t_end_ns}"
        )
    if t_end_ns < t_begin_ns:
        raise RuntimeError(
            f"END earlier than BEGIN in {raw_path}: "
            f"begin={t_begin_ns}, end={t_end_ns}"
        )
    return t_begin_ns, t_end_ns
