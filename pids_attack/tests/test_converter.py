"""CDM converter 单元测试 — 不依赖真实 sysdig，用合成的 sysdig JSONL 输入。"""
import json
import os
import tempfile
import unittest

from range.converter import (
    parse_strace_text, parse_sysdig_jsonl, build_cdm_graph, graph_to_sql, EDGE_TYPES,
)


SYNTHETIC_EVENTS = [
    {"evt.type": "open", "evt.time.ns": 1000, "proc.pid": 100, "proc.name": "bash",
     "proc.exe": "/bin/bash", "proc.cmdline": "bash", "fd.name": "/etc/hostname"},
    {"evt.type": "read", "evt.time.ns": 2000, "proc.pid": 100, "proc.name": "bash",
     "proc.exe": "/bin/bash", "proc.cmdline": "bash", "fd.name": "/etc/hostname"},
    {"evt.type": "execve", "evt.time.ns": 3000, "proc.pid": 200, "proc.name": "curl",
     "proc.exe": "/usr/bin/curl", "proc.cmdline": "curl localhost"},
    {"evt.type": "connect", "evt.time.ns": 4000, "proc.pid": 200, "proc.name": "curl",
     "proc.exe": "/usr/bin/curl", "proc.cmdline": "curl localhost",
     "fd.sip": "127.0.0.1", "fd.sport": "5555", "fd.cip": "127.0.0.1", "fd.cport": "3000"},
    {"evt.type": "clone", "evt.time.ns": 5000, "proc.pid": 100, "proc.name": "bash",
     "proc.exe": "/bin/bash", "proc.cmdline": "bash"},
]


class TestConverter(unittest.TestCase):

    def test_parse_synthetic_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sysdig.jsonl")
            with open(p, "w") as f:
                for e in SYNTHETIC_EVENTS:
                    f.write(json.dumps(e) + "\n")
            events = parse_sysdig_jsonl(p)
            self.assertEqual(len(events), len(SYNTHETIC_EVENTS))

    def test_cdm_graph_covers_3_node_types(self):
        graph = build_cdm_graph(SYNTHETIC_EVENTS)
        seen = {n.node_type for n in graph.nodes.values()}
        self.assertIn("subject", seen)
        self.assertIn("file", seen)
        self.assertIn("netflow", seen)

    def test_cdm_graph_edge_types(self):
        graph = build_cdm_graph(SYNTHETIC_EVENTS)
        types = {e.event_type for e in graph.events}
        self.assertIn("EVENT_OPEN", types)
        self.assertIn("EVENT_READ", types)
        self.assertIn("EVENT_EXECUTE", types)
        self.assertIn("EVENT_CONNECT", types)
        self.assertIn("EVENT_CLONE", types)

    def test_cdm_node_uuid_is_deterministic(self):
        g1 = build_cdm_graph(SYNTHETIC_EVENTS)
        g2 = build_cdm_graph(SYNTHETIC_EVENTS)
        k1 = {n.properties["_key"]: u for u, n in g1.nodes.items()}
        k2 = {n.properties["_key"]: u for u, n in g2.nodes.items()}
        self.assertEqual(k1, k2)

    def test_graph_to_sql_includes_ddl_and_inserts(self):
        """Phase 2 后 schema 对齐 PIDSMaker 4.0 → event_table 替代 cdm_event。"""
        graph = build_cdm_graph(SYNTHETIC_EVENTS)
        sql = graph_to_sql(graph)
        self.assertIn("CREATE TABLE IF NOT EXISTS event_table", sql)
        self.assertIn("INSERT INTO event_table", sql)

    def test_all_10_edge_types_in_dispatch(self):
        from range.converter import SYSCALL_TO_EVENT
        distinct = set(SYSCALL_TO_EVENT.values())
        for t in EDGE_TYPES:
            self.assertIn(t, distinct, msg=f"missing edge type {t}")

    def test_parse_strace_recovers_embedded_execve_subject(self):
        """Concurrent strace output can paste execve into another syscall line."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "raw.strace")
            with open(p, "w") as f:
                f.write(
                    '55280 1782224163.227371 write(16, "\\\\1", '
                    '855964 1782224163.227375 execve("/usr/bin/curl", '
                    '["curl", "-s", "-i", "-H", "Authorization: Bearer token", '
                    '"http://localhost:3000/rest/basket/2"], '
                    '0xaaa /* 8 vars */ <unfinished ...>) = 8\n'
                )
                f.write(
                    '55964 1782224163.265314 sendto(5, '
                    '"GET /rest/basket/2 HTTP/1.1\\r\\n", 33, '
                    'MSG_NOSIGNAL, NULL, 0) = 33\n'
                )

            events = parse_strace_text(p)
            sendto_events = [e for e in events if e["evt.type"] == "sendto"]
            self.assertEqual(len(sendto_events), 1)
            self.assertEqual(sendto_events[0]["proc.exe"], "/usr/bin/curl")
            self.assertIn("/rest/basket/2", sendto_events[0]["proc.cmdline"])


if __name__ == "__main__":
    unittest.main()
