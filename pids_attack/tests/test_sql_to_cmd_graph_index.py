"""Unit tests for sql_to_cmd_graph 写入 SQL index_id 到 CommandNode + G.resource_index_id(E0 Step 2)。"""
import tempfile
import unittest
from pathlib import Path

from detection.rules import sql_to_cmd_graph


def _make_sql() -> str:
    """合成一份最小 SQL CDM dump,2 subject + 1 file + 1 netflow。"""
    return """
CREATE TABLE IF NOT EXISTS subject_node_table (a INT);
CREATE TABLE IF NOT EXISTS file_node_table (a INT);
CREATE TABLE IF NOT EXISTS netflow_node_table (a INT);
CREATE TABLE IF NOT EXISTS event_table (a INT);

INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id)
VALUES ('net-uuid-1', 'hash-net-1', '', '', '127.0.0.1', '3000', 0) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-1', 'hash-subj-1', '/usr/bin/bash', 'bash -c x', 1) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-2', 'hash-subj-2', '/usr/bin/curl', 'curl http://x', 2) ON CONFLICT DO NOTHING;

INSERT INTO file_node_table (node_uuid, hash_id, path, index_id)
VALUES ('file-uuid-1', 'hash-file-1', '/etc/passwd', 3) ON CONFLICT DO NOTHING;
"""


class TestSqlToCmdGraphIndex(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sql", mode="w", delete=False)
        self.tmp.write(_make_sql())
        self.tmp.flush()
        self.sql_path = Path(self.tmp.name)

    def tearDown(self):
        self.sql_path.unlink(missing_ok=True)

    def test_command_node_has_index_id(self):
        G = sql_to_cmd_graph(str(self.sql_path))
        self.assertIsNotNone(G)
        # 2 subject 节点对应 SQL index_id = 1 跟 2
        indices = sorted(n.index_id for n in G.nodes.values())
        self.assertEqual(indices, [1, 2])

    def test_resource_index_id_for_file_and_netflow(self):
        G = sql_to_cmd_graph(str(self.sql_path))
        # /etc/passwd 是 file index_id=3
        self.assertEqual(G.resource_index_id["/etc/passwd"], 3)
        # 127.0.0.1:3000 是 netflow index_id=0(dst_port 非空 → addr=dst:port)
        self.assertEqual(G.resource_index_id["127.0.0.1:3000"], 0)

    def test_no_index_id_for_attack_side_construction(self):
        """attack-side 用 add_node 时 index_id 应该是 None。"""
        from cmd_graph.graph import CommandGraph
        G = CommandGraph()
        nid = G.add_node(raw_command="echo hi")
        self.assertIsNone(G.nodes[nid].index_id)
        self.assertEqual(G.resource_index_id, {})


if __name__ == "__main__":
    unittest.main()
