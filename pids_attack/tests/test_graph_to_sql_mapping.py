"""Unit tests for range/converter.py::graph_to_sql_with_mapping."""
import re
import unittest

from range.converter import CDMEvent, CDMGraph, CDMNode, graph_to_sql_with_mapping


def _make_graph() -> CDMGraph:
    g = CDMGraph()
    # 2 netflow + 3 subject + 2 file = 7 节点;index_id 写入顺序应该是 net → subject → file
    g.nodes["uuid-net-1"] = CDMNode(
        uuid="uuid-net-1", node_type="netflow",
        properties={"src_ip": "127.0.0.1", "src_port": "1234", "dst_ip": "10.0.0.1", "dst_port": "80"},
    )
    g.nodes["uuid-net-2"] = CDMNode(
        uuid="uuid-net-2", node_type="netflow",
        properties={"src_ip": "127.0.0.1", "src_port": "5678", "dst_ip": "10.0.0.2", "dst_port": "443"},
    )
    g.nodes["uuid-subj-1"] = CDMNode(
        uuid="uuid-subj-1", node_type="subject",
        properties={"exec_path": "/usr/bin/bash", "cmdline": "bash -c 'curl http://x'"},
    )
    g.nodes["uuid-subj-2"] = CDMNode(
        uuid="uuid-subj-2", node_type="subject",
        properties={"exec_path": "/usr/bin/curl", "cmdline": "curl http://x"},
    )
    g.nodes["uuid-subj-3"] = CDMNode(
        uuid="uuid-subj-3", node_type="subject",
        properties={"exec_path": "/usr/bin/head", "cmdline": "head -30"},
    )
    g.nodes["uuid-file-1"] = CDMNode(
        uuid="uuid-file-1", node_type="file",
        properties={"path": "/etc/passwd"},
    )
    g.nodes["uuid-file-2"] = CDMNode(
        uuid="uuid-file-2", node_type="file",
        properties={"path": "/tmp/x.sh"},
    )
    g.events.append(CDMEvent(
        uuid="evt-1", event_type="EVENT_READ", timestamp_ns=1000,
        subject_uuid="uuid-subj-1", object_uuid="uuid-file-1",
    ))
    return g


class TestGraphToSqlMapping(unittest.TestCase):

    def test_returns_tuple(self):
        sql, mapping = graph_to_sql_with_mapping(_make_graph())
        self.assertIsInstance(sql, str)
        self.assertIsInstance(mapping, dict)

    def test_mapping_covers_all_nodes(self):
        """所有 subject / file / netflow uuid 都在 mapping 里。"""
        g = _make_graph()
        _sql, mapping = graph_to_sql_with_mapping(g)
        for uuid in g.nodes:
            self.assertIn(uuid, mapping, f"uuid {uuid} 缺失")

    def test_mapping_indices_unique_and_contiguous(self):
        """index_id 在 [0, n) 范围,每个 idx 唯一。"""
        g = _make_graph()
        _sql, mapping = graph_to_sql_with_mapping(g)
        idxs = list(mapping.values())
        self.assertEqual(len(idxs), len(set(idxs)), "index_id 重复")
        self.assertEqual(set(idxs), set(range(len(g.nodes))), "index_id 非 [0, n) 连续")

    def test_mapping_order_net_subject_file(self):
        """对齐 PIDSMaker 灌库顺序 net → subject → file。"""
        g = _make_graph()
        _sql, mapping = graph_to_sql_with_mapping(g)
        for uuid in ("uuid-net-1", "uuid-net-2"):
            self.assertLess(mapping[uuid], 2, f"{uuid} 应该在 net 段")
        for uuid in ("uuid-subj-1", "uuid-subj-2", "uuid-subj-3"):
            self.assertTrue(2 <= mapping[uuid] < 5, f"{uuid} 应该在 subject 段")
        for uuid in ("uuid-file-1", "uuid-file-2"):
            self.assertTrue(5 <= mapping[uuid] < 7, f"{uuid} 应该在 file 段")

    def test_mapping_matches_sql_index_id_column(self):
        """mapping 里的 index_id 必须等于 SQL INSERT 语句最后一个数字(VALUES … , <index_id>)。"""
        g = _make_graph()
        sql, mapping = graph_to_sql_with_mapping(g)
        # 从 SQL 抠 (uuid, index_id) 对,对齐 mapping
        # subject: VALUES ('uuid-subj-1', 'hash', 'path', 'cmd', 2)
        # file: VALUES ('uuid-file-1', 'hash', 'path', 5)
        # netflow: VALUES ('uuid-net-1', 'hash', '127...', ..., 0)
        pat = re.compile(
            r"VALUES \('([^']+)',.+,\s*(\d+)\) ON CONFLICT"
        )
        found = {m.group(1): int(m.group(2)) for m in pat.finditer(sql)}
        for uuid, idx in mapping.items():
            self.assertIn(uuid, found, f"SQL 缺 uuid {uuid}")
            self.assertEqual(found[uuid], idx,
                             f"uuid {uuid}: mapping={idx} vs SQL={found[uuid]}")

    def test_empty_graph(self):
        g = CDMGraph()
        sql, mapping = graph_to_sql_with_mapping(g)
        self.assertEqual(mapping, {})
        self.assertIn("CREATE TABLE", sql)  # DDL 仍然在


if __name__ == "__main__":
    unittest.main()
