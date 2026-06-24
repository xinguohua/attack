"""v7 oracle GT 锚定指标 unit test(关键词驱动 + baseline-flagged 双锁定).

case 覆盖:
  - QueryResult 数据结构含 score_vec / gt_persistence / delta_gt_score / gt_n_dropped
  - _compute_node_metrics 无 gt_keywords → 没 GT 指标
  - _compute_node_metrics 给定 gt_keywords + baseline_gt_keys → 算正确持久率 + delta_score
  - _extract_path 抠 subject/file/netflow 的稳定 ID
  - reward() 连续值
"""
import unittest


class TestQueryResultSchema(unittest.TestCase):
    """v7 QueryResult 字段:score_vec / gt_persistence / delta_gt_score / gt_n_dropped。"""

    def test_valid_carries_gt_fields(self):
        from attack.framework.result import QueryResult
        qr = QueryResult.valid_(
            y=1,
            score_vec=[6.31, 6.31, 5.18, 3.62],
            gt_persistence=0.875,
            delta_gt_score=0.12,
            gt_n_dropped=1,
        )
        self.assertTrue(qr.valid)
        self.assertEqual(qr.y, 1)
        self.assertEqual(qr.score_vec, [6.31, 6.31, 5.18, 3.62])
        self.assertAlmostEqual(qr.gt_persistence, 0.875)
        self.assertAlmostEqual(qr.delta_gt_score, 0.12)
        self.assertEqual(qr.gt_n_dropped, 1)

    def test_valid_legacy_signature_still_works(self):
        from attack.framework.result import QueryResult
        qr = QueryResult.valid_(y=0)
        self.assertTrue(qr.valid)
        self.assertEqual(qr.y, 0)
        self.assertIsNone(qr.score_vec)
        self.assertIsNone(qr.gt_persistence)

    def test_invalid_no_score_fields(self):
        from attack.framework.result import QueryResult
        qr = QueryResult.invalid_(failed_step=3)
        self.assertFalse(qr.valid)
        self.assertEqual(qr.failed_step, 3)
        self.assertIsNone(qr.score_vec)


class TestExtractPath(unittest.TestCase):
    """_extract_path: 抠 subject / file / netflow 的稳定 ID."""

    def test_subject_path(self):
        from attack.oracle import _extract_path
        self.assertEqual(
            _extract_path("subject /usr/bin/curl curl -s -i http://localhost:3000/"),
            "/usr/bin/curl",
        )

    def test_file_path(self):
        from attack.oracle import _extract_path
        self.assertEqual(_extract_path("file /etc/passwd"), "/etc/passwd")

    def test_netflow(self):
        from attack.oracle import _extract_path
        self.assertEqual(_extract_path("netflow 127.0.0.1 3000"), "127.0.0.1:3000")

    def test_empty(self):
        from attack.oracle import _extract_path
        self.assertEqual(_extract_path(""), "")


class TestComputeNodeMetrics(unittest.TestCase):
    """v7 _compute_node_metrics:关键词驱动 + baseline_gt_keys 双锁定."""

    def test_no_gt_keywords_returns_none(self):
        from attack.oracle import _compute_node_metrics
        nodes = [
            {"node": 1, "label": "subject /usr/bin/curl curl ...", "y_pred": 1, "score": 5.0},
            {"node": 2, "label": "subject /usr/bin/bash bash ...", "y_pred": 0, "score": 1.0},
        ]
        m = _compute_node_metrics(nodes)
        self.assertEqual(m["score_vec"], [5.0, 1.0])
        self.assertIsNone(m["gt_persistence"])
        self.assertIsNone(m["delta_gt_score"])

    def test_keyword_match_no_baseline(self):
        """有 gt_keywords 但没 baseline_gt_keys → 当前 trace 即 baseline,持久率 1.0."""
        from attack.oracle import _compute_node_metrics
        nodes = [
            {"node": 1, "label": "subject /usr/bin/curl curl ... http://localhost:3000/", "y_pred": 1, "score": 6.0},
            {"node": 2, "label": "subject /usr/bin/head head -30", "y_pred": 1, "score": 6.0},
        ]
        m = _compute_node_metrics(nodes, gt_keywords=["http://localhost:3000/"])
        self.assertEqual(m["gt_n_matched"], 1)        # 只命中 curl,head 不含关键词
        self.assertAlmostEqual(m["gt_persistence"], 1.0)

    def test_keyword_no_flagged_match_is_zero_persistence(self):
        """有 gt_keywords 但当前没有 flagged GT node → attack-node oracle 已避开."""
        from attack.oracle import _compute_node_metrics
        nodes = [
            {"node": 1, "label": "subject /usr/bin/curl curl ... http://localhost:3000/", "y_pred": 0, "score": 0.1},
            {"node": 2, "label": "subject /usr/bin/head head -30", "y_pred": 1, "score": 6.0},
        ]
        m = _compute_node_metrics(nodes, gt_keywords=["http://localhost:3000/"])
        self.assertEqual(m["gt_n_matched"], 0)
        self.assertAlmostEqual(m["gt_persistence"], 0.0)

    def test_full_persistence_with_baseline(self):
        """baseline GT 节点全部仍命中 + flagged → 持久率 1.0,delta_score = 0."""
        from attack.oracle import _compute_node_metrics
        nodes = [
            {"node": 1, "label": "subject /usr/bin/curl curl ... http://localhost:3000/", "y_pred": 1, "score": 6.0},
            {"node": 2, "label": "subject /usr/bin/setsid setsid curl ... http://localhost:3000/", "y_pred": 1, "score": 6.0},  # 新加 wrapper
        ]
        base_keys = [("/usr/bin/curl", "http://localhost:3000/")]
        m = _compute_node_metrics(
            nodes,
            gt_keywords=["http://localhost:3000/"],
            baseline_gt_keys=base_keys,
            baseline_gt_avg_score=6.0,
        )
        self.assertAlmostEqual(m["gt_persistence"], 1.0)
        self.assertEqual(m["gt_n_dropped"], 0)
        self.assertAlmostEqual(m["delta_gt_score"], 0.0)

    def test_partial_persistence_baseline_node_dropped(self):
        """baseline 时 2 个 GT,变异后只剩 1 个(另一个 path 不再 flagged)→ 持久率 0.5."""
        from attack.oracle import _compute_node_metrics
        nodes = [
            {"node": 1, "label": "subject /usr/bin/curl curl ... http://localhost:3000/", "y_pred": 1, "score": 5.5},
            # /usr/bin/bash 节点不见了(或 y_pred=0)
        ]
        base_keys = [
            ("/usr/bin/curl", "http://localhost:3000/"),
            ("/usr/bin/bash", "http://localhost:3000/"),
        ]
        m = _compute_node_metrics(
            nodes,
            gt_keywords=["http://localhost:3000/"],
            baseline_gt_keys=base_keys,
            baseline_gt_avg_score=6.0,
        )
        self.assertAlmostEqual(m["gt_persistence"], 0.5)
        self.assertEqual(m["gt_n_dropped"], 1)
        self.assertAlmostEqual(m["delta_gt_score"], 6.0 - 5.5, places=3)

    def test_wrapper_does_not_break_match(self):
        """加 wrapper 改 cmd 不影响 (path, keyword) 命中 — 关键 bug fix 验证."""
        from attack.oracle import _compute_node_metrics
        nodes_before = [
            {"node": 1, "label": "subject /usr/bin/curl curl -s -i http://localhost:3000/", "y_pred": 1, "score": 6.0},
        ]
        nodes_after = [
            {"node": 1, "label": "subject /usr/bin/curl curl -s -i http://localhost:3000/", "y_pred": 1, "score": 6.0},
            {"node": 2, "label": "subject /usr/bin/setsid setsid curl -s -i http://localhost:3000/", "y_pred": 1, "score": 6.0},
            {"node": 3, "label": "subject /usr/bin/bash bash -c setsid curl -s -i http://localhost:3000/", "y_pred": 1, "score": 6.0},
        ]
        kw = ["http://localhost:3000/"]
        m_before = _compute_node_metrics(nodes_before, gt_keywords=kw)
        base_keys = [(nd["path"], nd["keyword"]) for nd in m_before["gt_nodes"]]
        m_after = _compute_node_metrics(
            nodes_after, gt_keywords=kw,
            baseline_gt_keys=base_keys, baseline_gt_avg_score=6.0)
        # /usr/bin/curl 这个 baseline GT 仍命中 → 持久 1.0(虽然加了 setsid/bash wrapper)
        self.assertAlmostEqual(m_after["gt_persistence"], 1.0)


class TestRewardContinuous(unittest.TestCase):
    """reward() 是 [0, 1] 连续值,基于 gt_persistence."""

    def test_reward_from_gt_persistence(self):
        from attack.framework.result import QueryResult
        qr = QueryResult.valid_(y=1, gt_persistence=0.3)
        self.assertAlmostEqual(qr.reward(), 0.7)  # 1 - 0.3

    def test_reward_raises_on_missing_gt_persistence(self):
        """valid=True 但 gt_persistence 缺失时 reward() 抛 ValueError(无 binary fallback)。"""
        from attack.framework.result import QueryResult
        qr = QueryResult.valid_(y=0)   # gt_persistence 默认 None
        with self.assertRaises(ValueError):
            qr.reward()

    def test_reward_invalid_zero(self):
        from attack.framework.result import QueryResult
        qr = QueryResult.invalid_(failed_step=2)
        self.assertAlmostEqual(qr.reward(), 0.0)


if __name__ == "__main__":
    unittest.main()
