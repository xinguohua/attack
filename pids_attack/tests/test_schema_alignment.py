"""test_schema_alignment.py — Phase 2 Acceptance Gate 单测。

验证 range/converter.py:graph_to_sql 输出的 SQL 跟 PIDSMaker 4.0 的 4 张表 schema 对齐。
"""
import glob
import hashlib
import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from range.converter import (
    DDL_SQL,
    build_cdm_graph_from_strace,
    graph_to_sql,
    _hash_id,
)

DEMO_TRACE_DIR = os.path.join(PROJECT_ROOT, "results", "demo_traces")


class TestSchemaAlignment(unittest.TestCase):
    def setUp(self):
        traces = sorted(glob.glob(os.path.join(DEMO_TRACE_DIR, "trace_*.strace")))
        if not traces:
            self.skipTest("no demo trace found in results/demo_traces/")
        self.trace_path = traces[0]

    def test_ddl_has_pidsmaker_tables(self):
        """DDL 含 4 张 _table 表(PIDSMaker 4.0 命名)。"""
        for tbl in ["subject_node_table", "file_node_table",
                    "netflow_node_table", "event_table"]:
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {tbl}", DDL_SQL,
                          f"{tbl} 缺失")

    def test_ddl_has_pidsmaker_columns(self):
        """关键列名跟 PIDSMaker 4.0 对齐。"""
        # subject_node_table: node_uuid / hash_id / path / cmd / index_id
        for col in ["node_uuid", "hash_id", "path", "cmd", "index_id"]:
            self.assertIn(col, DDL_SQL.split("subject_node_table")[1].split(");")[0],
                          f"subject_node_table 缺列 {col}")
        # netflow_node_table: src_addr / dst_addr(不是 src_ip / dst_ip)
        netflow_block = DDL_SQL.split("netflow_node_table")[1].split(");")[0]
        self.assertIn("src_addr", netflow_block)
        self.assertIn("dst_addr", netflow_block)
        self.assertNotIn("src_ip", netflow_block)
        # event_table: src_node / dst_node / operation / event_uuid / timestamp_rec
        event_block = DDL_SQL.split("event_table")[1].split(");")[0]
        for col in ["src_node", "dst_node", "operation", "event_uuid", "timestamp_rec"]:
            self.assertIn(col, event_block, f"event_table 缺列 {col}")

    def test_graph_to_sql_emits_inserts_into_correct_tables(self):
        """对 demo trace 跑 graph_to_sql,SQL 含 4 张 _table 的 INSERT。"""
        g = build_cdm_graph_from_strace(self.trace_path)
        sql = graph_to_sql(g)
        for tbl in ["subject_node_table", "file_node_table",
                    "netflow_node_table", "event_table"]:
            # 至少要么 DDL 要么 INSERT
            self.assertIn(tbl, sql, f"SQL 没提到 {tbl}")
        # event_table 必须有 INSERT(图至少有 1 条边)
        self.assertIn("INSERT INTO event_table", sql)

    def test_hash_id_md5(self):
        """_hash_id == md5(uuid) 跟 PIDSMaker stringtomd5 一致。"""
        u = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(_hash_id(u), hashlib.md5(u.encode()).hexdigest())

    def test_no_legacy_table_names(self):
        """旧表名 subject_node / cdm_event 已彻底删除。"""
        # DDL 不能有不带 _table 后缀的旧表名作为 CREATE TABLE 的目标
        for legacy in ["CREATE TABLE IF NOT EXISTS subject_node ",
                       "CREATE TABLE IF NOT EXISTS file_node ",
                       "CREATE TABLE IF NOT EXISTS netflow_node ",
                       "CREATE TABLE IF NOT EXISTS cdm_event"]:
            self.assertNotIn(legacy, DDL_SQL, f"旧表名残留: {legacy}")


if __name__ == "__main__":
    unittest.main()
