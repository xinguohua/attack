"""oracle 单元测试 — _LocalDetector 是 in-A_Study_Stage PIDSMakerEngine wrapper(B 路径)。

无 daemon / 无 zerorpc / 无 RPC。第一次 predict 触发 lazy load。
"""
import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from detection.pidsmaker import (
    SUPPORTED_DETECTORS,
    _LocalDetector,
)


class TestSupportedDetectors(unittest.TestCase):
    def test_count_eq_8(self):
        self.assertEqual(len(SUPPORTED_DETECTORS), 8)

    def test_names(self):
        for name in ("orthrus", "kairos", "magic", "flash",
                     "threatrace", "nodlink", "rcaid", "velox"):
            self.assertIn(name, SUPPORTED_DETECTORS)


class TestLocalDetector(unittest.TestCase):
    def test_unknown_detector_rejected(self):
        with self.assertRaises(ValueError):
            _LocalDetector("not_a_detector")


class TestNoZerorpc(unittest.TestCase):
    """B 路径 —— pidsmaker_inference 不能 import zerorpc。"""

    def test_pidsmaker_inference_no_zerorpc(self):
        import inspect
        from detection import pidsmaker as pi
        src = inspect.getsource(pi)
        self.assertNotIn("zerorpc", src)

    def test_no_daemon_file(self):
        daemon_path = os.path.join(PROJECT_ROOT, "detection", "pidsmaker_daemon.py")
        self.assertFalse(os.path.exists(daemon_path),
                         f"daemon should be deleted: {daemon_path}")


if __name__ == "__main__":
    unittest.main()
