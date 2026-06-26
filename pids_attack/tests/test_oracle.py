"""oracle 单元测试 — _LocalDetector 是 in-A_Study_Stage PIDSMakerEngine wrapper(B 路径)。

无 daemon / 无 zerorpc / 无 RPC。第一次 predict 触发 lazy load。
"""
import os
import sys
import unittest
from unittest.mock import Mock, patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from detection.training.pidsmaker import (
    SUPPORTED_DETECTORS,
    _LocalDetector,
    default_system_resource_alert_filter_enabled,
    _runtime_use_kmeans,
    is_system_resource_alert_noise,
    suppress_system_resource_alerts,
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

    def test_threshold_override_disables_kmeans_runtime(self):
        self.assertTrue(
            _runtime_use_kmeans(True, threshold_override_active=False)
        )
        self.assertFalse(
            _runtime_use_kmeans(True, threshold_override_active=True)
        )
        self.assertFalse(
            _runtime_use_kmeans(False, threshold_override_active=True)
        )

    def test_local_detector_cache_key_includes_model_path(self):
        original = dict(_LocalDetector._engines)
        try:
            _LocalDetector._engines.clear()
            with patch("detection.training.pidsmaker.PIDSMakerEngine") as engine_cls:
                engine_cls.side_effect = [object(), object()]
                a = _LocalDetector("threatrace", model_path="/tmp/model_a")
                b = _LocalDetector("threatrace", model_path="/tmp/model_b")

                a._get_engine()
                b._get_engine()

            self.assertEqual(engine_cls.call_count, 2)
            self.assertEqual(engine_cls.call_args_list[0].kwargs["model_path"], "/tmp/model_a")
            self.assertEqual(engine_cls.call_args_list[1].kwargs["model_path"], "/tmp/model_b")
        finally:
            _LocalDetector._engines.clear()
            _LocalDetector._engines.update(original)

    def test_adapter_filter_only_removes_e0_controller_artifacts(self):
        nodes = suppress_system_resource_alerts([
            {
                "node_index_id": 1,
                "node_type": "file",
                "label": "file /proc/net/tcp",
                "y_pred": 1,
            },
            {
                "node_index_id": 2,
                "node_type": "netflow",
                "label": "netflow 192.168.65.7 53",
                "y_pred": 1,
            },
            {
                "node_index_id": 3,
                "node_type": "file",
                "label": "file /tmp/e0_abc123/benign.stop",
                "y_pred": 1,
            },
            {
                "node_index_id": 4,
                "node_type": "file",
                "label": "file /lib/aarch64-linux-gnu/libcurl.so.4",
                "y_pred": 1,
            },
            {
                "node_index_id": 5,
                "node_type": "netflow",
                "label": "netflow 127.0.0.1 3000",
                "y_pred": 1,
            },
            {
                "node_index_id": 6,
                "node_type": "subject",
                "label": "subject /usr/bin/touch | touch /tmp/e0_abc123/benign.stop",
                "y_pred": 1,
            },
            {
                "node_index_id": 7,
                "node_type": "subject",
                "label": "subject /usr/bin/curl | curl -s http://localhost:3000/",
                "y_pred": 1,
            },
        ])

        self.assertEqual([n["y_pred"] for n in nodes], [1, 1, 0, 1, 1, 0, 1])
        self.assertIsNone(is_system_resource_alert_noise(nodes[0]))
        self.assertIsNone(is_system_resource_alert_noise(nodes[1]))
        self.assertEqual(nodes[2]["post_filter_reason"], "e0_benign_stop_file")
        self.assertIsNone(is_system_resource_alert_noise(nodes[3]))
        self.assertIsNone(is_system_resource_alert_noise(nodes[4]))
        self.assertEqual(nodes[5]["post_filter_reason"], "e0_batch_controller_subject")
        self.assertIsNone(is_system_resource_alert_noise(nodes[6]))

    def test_system_resource_alert_filter_defaults_are_detector_specific(self):
        self.assertTrue(default_system_resource_alert_filter_enabled("magic"))
        self.assertTrue(default_system_resource_alert_filter_enabled("threatrace"))
        self.assertTrue(default_system_resource_alert_filter_enabled("orthrus"))


class TestNoZerorpc(unittest.TestCase):
    """B 路径 —— pidsmaker_inference 不能 import zerorpc。"""

    def test_pidsmaker_inference_no_zerorpc(self):
        import inspect
        from detection.training import pidsmaker as pi
        src = inspect.getsource(pi)
        self.assertNotIn("zerorpc", src)

    def test_no_daemon_file(self):
        daemon_path = os.path.join(PROJECT_ROOT, "detection", "pidsmaker_daemon.py")
        self.assertFalse(os.path.exists(daemon_path),
                         f"daemon should be deleted: {daemon_path}")


class TestPIDSOracleRuntimeConfig(unittest.TestCase):
    def test_prefers_e0_runtime_configured_detector(self):
        from attack.framework.oracle import PIDSOracle

        configured_detector = Mock()
        runtime = Mock()
        runtime._ensure_detector.return_value = configured_detector

        with patch("detection.inference.registry.load_e0_oracle", return_value=runtime) as load:
            oracle = PIDSOracle("threatrace_g1g2")
            detector = oracle._ensure_detector()

        load.assert_called_once_with("threatrace_g1g2")
        self.assertIs(detector, configured_detector)


if __name__ == "__main__":
    unittest.main()
