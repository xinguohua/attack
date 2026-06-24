"""Unit tests for experiments/E0_detection/window.py."""
import tempfile
import unittest
from pathlib import Path

from experiments.E0_detection.window import extract_window, strip_markers


def _write_strace(text: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".strace", mode="w", delete=False)
    f.write(text)
    f.flush()
    return Path(f.name)


class TestStripMarkers(unittest.TestCase):

    def test_strip_removes_marker_lines(self):
        raw = _write_strace(
            "1234 100.0 openat(AT_FDCWD, \"/etc/passwd\")\n"
            "1234 100.5 write(1, \"__E0_ATTACK_BEGIN__ run=abc scenario=01\", 40)\n"
            "1234 101.0 read(3, \"data\", 4096)\n"
            "1234 101.5 write(1, \"__E0_ATTACK_END__ run=abc scenario=01\", 38)\n"
            "1234 102.0 close(3)\n"
        )
        clean = Path(tempfile.NamedTemporaryFile(suffix=".strace", delete=False).name)
        try:
            dropped = strip_markers(raw, clean)
            self.assertEqual(dropped, 2)
            text = clean.read_text()
            self.assertNotIn("__E0_ATTACK_BEGIN__", text)
            self.assertNotIn("__E0_ATTACK_END__", text)
            self.assertIn("openat", text)
            self.assertEqual(text.count("\n"), 3)  # 5 行 - 2 marker = 3
        finally:
            raw.unlink(missing_ok=True)
            clean.unlink(missing_ok=True)

    def test_strip_removes_step_marker_lines(self):
        raw = _write_strace(
            "1234 100.0 write(1, \"__E0_STEP_BEGIN__ step=1\", 25)\n"
            "1234 100.5 openat(AT_FDCWD, \"/usr/bin/curl\")\n"
            "1234 101.0 write(1, \"__E0_STEP_END__ step=1 rc=0\", 30)\n"
        )
        clean = Path(tempfile.NamedTemporaryFile(suffix=".strace", delete=False).name)
        try:
            dropped = strip_markers(raw, clean)
            self.assertEqual(dropped, 2)
            text = clean.read_text()
            self.assertNotIn("__E0_STEP_BEGIN__", text)
            self.assertNotIn("__E0_STEP_END__", text)
            self.assertIn("openat", text)
        finally:
            raw.unlink(missing_ok=True)
            clean.unlink(missing_ok=True)

    def test_strip_empty_file(self):
        raw = _write_strace("")
        clean = Path(tempfile.NamedTemporaryFile(suffix=".strace", delete=False).name)
        try:
            self.assertEqual(strip_markers(raw, clean), 0)
            self.assertEqual(clean.read_text(), "")
        finally:
            raw.unlink(missing_ok=True)
            clean.unlink(missing_ok=True)


class TestExtractWindow(unittest.TestCase):

    def test_extract_single_pair(self):
        raw = _write_strace(
            "1234 100.0 openat(...)\n"
            "1234 100.5 write(1, \"__E0_ATTACK_BEGIN__ run=x scenario=01\", 40)\n"
            "1234 105.0 write(1, \"__E0_ATTACK_END__ run=x scenario=01\", 38)\n"
        )
        try:
            t_begin, t_end = extract_window(raw)
            self.assertEqual(t_begin, int(100.5 * 1e9))
            self.assertEqual(t_end, int(105.0 * 1e9))
        finally:
            raw.unlink(missing_ok=True)

    def test_extract_multi_begin_takes_earliest(self):
        """多 BEGIN 行(echo write 被 strace 拆 unfinished/resumed)取最早。"""
        raw = _write_strace(
            "1234 100.1 write(1, \"__E0_ATTACK_BEGIN__ run=x scenario=01\", 40)\n"
            "1234 100.5 write(1, \"__E0_ATTACK_BEGIN__ duplicate\", 30)\n"
            "1234 105.0 write(1, \"__E0_ATTACK_END__ x\", 20)\n"
        )
        try:
            t_begin, t_end = extract_window(raw)
            self.assertEqual(t_begin, int(100.1 * 1e9))
            self.assertEqual(t_end, int(105.0 * 1e9))
        finally:
            raw.unlink(missing_ok=True)

    def test_extract_multi_end_takes_latest(self):
        raw = _write_strace(
            "1234 100.0 write(1, \"__E0_ATTACK_BEGIN__ x\", 25)\n"
            "1234 104.0 write(1, \"__E0_ATTACK_END__ x\", 20)\n"
            "1234 106.0 write(1, \"__E0_ATTACK_END__ y\", 20)\n"
        )
        try:
            t_begin, t_end = extract_window(raw)
            self.assertEqual(t_begin, int(100.0 * 1e9))
            self.assertEqual(t_end, int(106.0 * 1e9))
        finally:
            raw.unlink(missing_ok=True)

    def test_extract_pid_bracket_format(self):
        """支持 `[pid 1234] ts ...` 这种 strace -f 多进程格式。"""
        raw = _write_strace(
            "[pid 5678] 100.5 write(1, \"__E0_ATTACK_BEGIN__ x\", 25)\n"
            "[pid 5678] 105.0 write(1, \"__E0_ATTACK_END__ x\", 20)\n"
        )
        try:
            t_begin, t_end = extract_window(raw)
            self.assertEqual(t_begin, int(100.5 * 1e9))
            self.assertEqual(t_end, int(105.0 * 1e9))
        finally:
            raw.unlink(missing_ok=True)

    def test_extract_ignores_bash_script_read_marker(self):
        """bash 读 workload block 的 read(255, "...marker...") 不是真 marker。"""
        raw = _write_strace(
            "1234 100.0 read(255, \"sleep 60\\nprintf '%s\\\\n' '__E0_ATTACK_BEGIN__ x'\", 8192) = 64\n"
            "1234 160.0 write(1, \"__E0_ATTACK_BEGIN__ x\", 25)\n"
            "1234 160.3 read(255, \"\\nprintf '%s\\\\n' '__E0_ATTACK_END__ x'\", 8192) = 42\n"
            "1234 160.4 write(1, \"__E0_ATTACK_END__ x\", 20)\n"
        )
        try:
            t_begin, t_end = extract_window(raw)
            self.assertEqual(t_begin, int(160.0 * 1e9))
            self.assertEqual(t_end, int(160.4 * 1e9))
        finally:
            raw.unlink(missing_ok=True)

    def test_extract_missing_marker_raises(self):
        raw = _write_strace("1234 100.0 openat(\"/etc/passwd\")\n")
        try:
            with self.assertRaises(RuntimeError):
                extract_window(raw)
        finally:
            raw.unlink(missing_ok=True)

    def test_extract_end_before_begin_raises(self):
        raw = _write_strace(
            "1234 105.0 write(1, \"__E0_ATTACK_END__ x\", 20)\n"
            "1234 110.0 write(1, \"__E0_ATTACK_BEGIN__ x\", 25)\n"
        )
        try:
            with self.assertRaises(RuntimeError):
                extract_window(raw)
        finally:
            raw.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
