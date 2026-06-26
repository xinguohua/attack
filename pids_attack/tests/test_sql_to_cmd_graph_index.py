"""Unit tests for sql_to_cmd_graph 写入 SQL index_id 到 CommandNode + G.resource_index_id(E0 Step 2)。"""
import tempfile
import unittest
from pathlib import Path

from detection.training.rules import sql_to_cmd_graph


def _make_sql() -> str:
    """合成一份最小 SQL CDM dump,2 subject + 1 file + 1 netflow。"""
    return """
CREATE TABLE IF NOT EXISTS subject_node_table (a INT);
CREATE TABLE IF NOT EXISTS file_node_table (a INT);
CREATE TABLE IF NOT EXISTS netflow_node_table (a INT);
CREATE TABLE IF NOT EXISTS event_table (a INT);

INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id)
VALUES ('net-uuid-1', 'hash-net-1', '', '', '127.0.0.1', '3000', 0) ON CONFLICT DO NOTHING;

INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id)
VALUES ('net-uuid-2', 'hash-net-2', '', '', '192.168.65.7', '53', 7) ON CONFLICT DO NOTHING;

INSERT INTO netflow_node_table (node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id)
VALUES ('net-uuid-3', 'hash-net-3', '', '', 'unix:/var/run/nscd/socket', '0', 8) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-1', 'hash-subj-1', '/usr/bin/bash', 'bash -c x', 1) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-2', 'hash-subj-2', '/usr/bin/curl', 'curl http://x', 2) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-3', 'hash-subj-3', '/usr/bin/bash', 'bash -lc set +e
RUN_DIR=/tmp/e0_abc123
STOP_FILE=/tmp/e0_abc123/benign.stop
BG_PIDS=/tmp/e0_abc123/bg.pids', 5) ON CONFLICT DO NOTHING;

INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id)
VALUES ('subj-uuid-4', 'hash-subj-4', '/usr/bin/touch', 'touch /tmp/e0_abc123/benign.stop', 6) ON CONFLICT DO NOTHING;

INSERT INTO file_node_table (node_uuid, hash_id, path, index_id)
VALUES ('file-uuid-1', 'hash-file-1', '/etc/passwd', 3) ON CONFLICT DO NOTHING;

INSERT INTO file_node_table (node_uuid, hash_id, path, index_id)
VALUES ('file-uuid-2', 'hash-file-2', '/lib/aarch64-linux-gnu/libc.so.6', 4) ON CONFLICT DO NOTHING;

INSERT INTO file_node_table (node_uuid, hash_id, path, index_id)
VALUES ('file-uuid-3', 'hash-file-3', 'pids_traces_abc123', 9) ON CONFLICT DO NOTHING;

INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec)
VALUES ('hash-subj-1', 'hash-subj-1', 'EVENT_OPEN', 'hash-file-1', 'hash-file-1', 'evt-1', 1) ON CONFLICT DO NOTHING;

INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec)
VALUES ('hash-subj-1', 'hash-subj-1', 'EVENT_OPEN', 'hash-file-2', 'hash-file-2', 'evt-2', 2) ON CONFLICT DO NOTHING;

INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec)
VALUES ('hash-subj-1', 'hash-subj-1', 'EVENT_OPEN', 'hash-file-3', 'hash-file-3', 'evt-3', 3) ON CONFLICT DO NOTHING;

INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec)
VALUES ('hash-subj-1', 'hash-subj-1', 'EVENT_CONNECT', 'hash-net-2', 'hash-net-2', 'evt-4', 4) ON CONFLICT DO NOTHING;

INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec)
VALUES ('hash-subj-1', 'hash-subj-1', 'EVENT_CONNECT', 'hash-net-3', 'hash-net-3', 'evt-5', 5) ON CONFLICT DO NOTHING;

INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec)
VALUES ('hash-subj-2', 'hash-subj-2', 'EVENT_CONNECT', 'hash-net-1', 'hash-net-1', 'evt-6', 6) ON CONFLICT DO NOTHING;
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
        # 2 workload subject 节点对应 SQL index_id = 1 跟 2;
        # E0 batch controller shell 和 stop-signal touch 默认过滤。
        indices = sorted(n.index_id for n in G.nodes.values())
        self.assertEqual(indices, [1, 2])

    def test_can_disable_batch_controller_filter(self):
        G = sql_to_cmd_graph(str(self.sql_path), filter_batch_controller_subjects=False)
        self.assertIsNotNone(G)
        indices = sorted(n.index_id for n in G.nodes.values())
        self.assertEqual(indices, [1, 2, 5, 6])

    def test_resource_index_id_for_file_and_netflow(self):
        G = sql_to_cmd_graph(str(self.sql_path))
        # /etc/passwd 是 file index_id=3
        self.assertEqual(G.resource_index_id["/etc/passwd"], 3)
        self.assertEqual(G.resource_index_id["/lib/aarch64-linux-gnu/libc.so.6"], 4)
        # 127.0.0.1:3000 是 netflow index_id=0(dst_port 非空 → addr=dst:port)
        self.assertEqual(G.resource_index_id["127.0.0.1:3000"], 0)

    def test_default_filters_system_resources_before_e_res(self):
        G = sql_to_cmd_graph(str(self.sql_path))
        node = next(n for n in G.nodes.values() if n.index_id == 1)
        self.assertIn("/etc/passwd", node.inputs)
        self.assertNotIn("/lib/aarch64-linux-gnu/libc.so.6", node.inputs)

    def test_default_keeps_non_library_resources(self):
        G = sql_to_cmd_graph(str(self.sql_path))
        node = next(n for n in G.nodes.values() if n.index_id == 1)
        app = next(n for n in G.nodes.values() if n.index_id == 2)

        self.assertIn("pids_traces_abc123", node.inputs)
        self.assertIn("192.168.65.7:53", node.outputs)
        self.assertIn("unix:/var/run/nscd/socket:0", node.outputs)
        self.assertIn("127.0.0.1:3000", app.outputs)

    def test_can_disable_system_resource_filter(self):
        G = sql_to_cmd_graph(str(self.sql_path), filter_system_resources=False)
        node = next(n for n in G.nodes.values() if n.index_id == 1)
        self.assertIn("/etc/passwd", node.inputs)
        self.assertIn("/lib/aarch64-linux-gnu/libc.so.6", node.inputs)
        self.assertIn("pids_traces_abc123", node.inputs)
        self.assertIn("192.168.65.7:53", node.outputs)
        self.assertIn("unix:/var/run/nscd/socket:0", node.outputs)

    def test_no_index_id_for_attack_side_construction(self):
        """attack-side 用 add_node 时 index_id 应该是 None。"""
        from cmd_graph.graph import CommandGraph
        G = CommandGraph()
        nid = G.add_node(raw_command="echo hi")
        self.assertIsNone(G.nodes[nid].index_id)
        self.assertEqual(G.resource_index_id, {})


if __name__ == "__main__":
    unittest.main()
