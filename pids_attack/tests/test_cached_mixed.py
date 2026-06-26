import tempfile
import unittest
from pathlib import Path

from range.benign_cache import choose_cached_benign_trace, list_cached_benign_traces
from range.cached_mixed import MIXED_MODE, compose_cached_mixed_trace


class TestBenignCache(unittest.TestCase):
    def test_lists_and_deterministically_selects_cached_trace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i in range(3):
                (root / f"benign_{i:02d}.strace").write_text(
                    f"10{i} 90.{i} openat(AT_FDCWD, \"/tmp/benign_{i}\", O_RDONLY) = 3\n"
                )
            (root / "benign_01.strace.proc_snapshot").write_text(
                'PID=101 CMDLINE="curl /" EXE="/usr/bin/curl"\n'
            )

            traces = list_cached_benign_traces(root)
            self.assertEqual(len(traces), 3)
            self.assertEqual(traces[1].proc_snapshot_path, root / "benign_01.strace.proc_snapshot")

            a = choose_cached_benign_trace(trace_dir=root, seed=7, scenario_id="01", query_id="q")
            b = choose_cached_benign_trace(trace_dir=root, seed=7, scenario_id="01", query_id="q")
            self.assertEqual(a.trace_path, b.trace_path)


class TestCachedMixedCompose(unittest.TestCase):
    def test_compose_preserves_marker_window_and_collects_gt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            benign = root / "benign_00.strace"
            benign.write_text(
                "111 90.000000 execve(\"/usr/bin/stat\", [\"stat\", \"/etc/hostname\"], 0x0) = 0\n"
                "111 90.100000 openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY) = 3\n"
            )
            attack = root / "attack.raw.strace"
            attack.write_text(
                "222 100.000000 write(1, \"__E0_ATTACK_BEGIN__ run=x scenario=01\", 40) = 40\n"
                "222 100.100000 execve(\"/usr/bin/curl\", [\"curl\", \"http://localhost:3000/rest\"], 0x0) = 0\n"
                "222 100.200000 openat(AT_FDCWD, \"/tmp/attack-proof\", O_RDONLY) = 3\n"
                "222 100.300000 write(1, \"__E0_ATTACK_END__ run=x scenario=01\", 38) = 38\n"
            )

            artifact = compose_cached_mixed_trace(
                benign_trace=list_cached_benign_traces(root)[0],
                attack_raw_strace=attack,
                attack_proc_snapshot=None,
                outdir=root / "mixed",
                attack_gt_signature_sets={
                    "subject": {"subject|/usr/bin/curl|curl http://localhost:3000/rest"},
                    "file": {"file|/tmp/attack-proof"},
                    "netflow": set(),
                },
                attack_gt_signature_path=None,
            )

            clean_text = Path(artifact["clean_strace"]).read_text()
            self.assertNotIn("__E0_ATTACK_BEGIN__", clean_text)
            self.assertEqual(artifact["gt"]["mixed_mode"], MIXED_MODE)
            self.assertGreaterEqual(len(artifact["gt"]["gt_subject_index_ids"]), 1)
            self.assertGreaterEqual(len(artifact["gt"]["gt_file_index_ids"]), 1)
            self.assertGreater(artifact["gt"]["gt_window_event_count"], 0)


if __name__ == "__main__":
    unittest.main()
