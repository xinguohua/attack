"""test_strace_fields.py — Phase 3 Acceptance Gate 单测。

验证 parse_strace_text 正确填 proc.exe / proc.cmdline / proc.name(从 /proc 快照 + execve args)。
"""
import glob
import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from range.converter import (
    _load_proc_snapshot,
    _parse_execve_args,
    parse_strace_text,
    build_cdm_graph_from_strace,
    graph_to_sql,
)

DEMO_TRACE_DIR = os.path.join(PROJECT_ROOT, "results", "demo_traces")


class TestProcSnapshot(unittest.TestCase):
    def test_load_existing_snapshot(self):
        with tempfile.NamedTemporaryFile("w", suffix=".proc_snapshot", delete=False) as f:
            f.write('PID=1 CMDLINE="/bin/bash /entrypoint.sh " EXE="/usr/bin/bash"\n')
            f.write('PID=27 CMDLINE="tail -f /dev/null " EXE="/usr/bin/tail"\n')
            f.write('PID=99 CMDLINE="" EXE=""\n')
            path = f.name
        meta = _load_proc_snapshot(path)
        os.unlink(path)
        self.assertEqual(len(meta), 3)
        self.assertEqual(meta[1]["exe"], "/usr/bin/bash")
        self.assertEqual(meta[27]["cmdline"], "tail -f /dev/null")

    def test_missing_snapshot_returns_empty(self):
        meta = _load_proc_snapshot("/nonexistent/path.proc_snapshot")
        self.assertEqual(meta, {})


class TestExecveArgs(unittest.TestCase):
    def test_simple_execve(self):
        args = '"/bin/bash", ["bash", "-c", "ls -la /tmp"], 0x7fff...'
        exe, cmd = _parse_execve_args(args)
        self.assertEqual(exe, "/bin/bash")
        self.assertEqual(cmd, "bash -c ls -la /tmp")

    def test_execve_no_argv(self):
        args = '"/bin/false"'
        exe, cmd = _parse_execve_args(args)
        self.assertEqual(exe, "/bin/false")
        self.assertEqual(cmd, "")


class TestParseStrace(unittest.TestCase):
    def setUp(self):
        traces = sorted(glob.glob(os.path.join(DEMO_TRACE_DIR, "trace_*.strace")))
        # 找带 .proc_snapshot 的 trace(Phase 3 跑过 PART B 之后才有)
        self.trace_path = None
        for t in traces:
            if os.path.exists(t + ".proc_snapshot"):
                self.trace_path = t
                break
        if not self.trace_path:
            self.skipTest("no trace with .proc_snapshot found, run PART B first")

    def test_subject_cmdline_non_empty(self):
        """跑 demo trace,build_cdm_graph_from_strace 产 subject 节点 cmdline 大部分非空。"""
        g = build_cdm_graph_from_strace(self.trace_path)
        subjects = [n for n in g.nodes.values() if n.node_type == "subject"]
        self.assertGreater(len(subjects), 0)
        non_empty_cmd = sum(1 for s in subjects if s.properties.get("cmdline"))
        # 至少 30% subject 节点的 cmdline 非空(execve 跟踪到的 + /proc snapshot 命中的)
        ratio = non_empty_cmd / len(subjects)
        self.assertGreater(ratio, 0.3,
            f"only {non_empty_cmd}/{len(subjects)} ({ratio:.0%}) subjects have non-empty cmdline")

    def test_subject_exe_non_empty(self):
        """exec_path 大部分非空。"""
        g = build_cdm_graph_from_strace(self.trace_path)
        subjects = [n for n in g.nodes.values() if n.node_type == "subject"]
        non_empty = sum(1 for s in subjects if s.properties.get("exec_path"))
        ratio = non_empty / len(subjects)
        self.assertGreater(ratio, 0.3,
            f"only {non_empty}/{len(subjects)} subjects have exec_path")

    def test_sql_subject_path_cmd_non_empty(self):
        """落 SQL 后 subject_node_table 行的 path / cmd 大部分非空。"""
        g = build_cdm_graph_from_strace(self.trace_path)
        sql = graph_to_sql(g)
        subject_inserts = [l for l in sql.split("\n") if "INSERT INTO subject_node_table" in l]
        # 数 path / cmd 非空(不是 '', '')
        non_empty = sum(1 for l in subject_inserts if "'', ''" not in l)
        self.assertGreater(non_empty / max(1, len(subject_inserts)), 0.3,
            f"too many empty subject rows: {non_empty}/{len(subject_inserts)}")


if __name__ == "__main__":
    unittest.main()
