"""wl_hash_benchmark — 测 wl_canonical_hash 在不同 |V| G 上的耗时。

Pass 标准:|V|=100 median ≤ 50ms;|V|=500 ≤ 200ms。
"""
from __future__ import annotations
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cmd_graph.graph import CommandGraph
from cmd_graph.wl_hash import wl_canonical_hash


def random_g(n_nodes: int, seed: int = 42) -> CommandGraph:
    rng = random.Random(seed)
    g = CommandGraph()
    ids = []
    cmds = ["ls", "cat", "stat", "grep", "echo", "head", "wc"]
    paths = ["/tmp", "/etc/passwd", "/var/log", "/proc/version", "/usr/bin"]
    for i in range(n_nodes):
        cmd = rng.choice(cmds)
        p = rng.choice(paths)
        nid = g.add_node(raw_command=f"{cmd} {p}_{i}", inputs={f"{p}_{i}"})
        ids.append(nid)
    # E_seq chain
    for i in range(len(ids) - 1):
        g.e_seq.append((ids[i], ids[i + 1]))
    # 随机 e_res 边(模拟资源共享)
    for _ in range(n_nodes // 3):
        a, b = rng.sample(ids, 2)
        g.e_res.add((min(a, b), max(a, b)))
    return g


def main():
    print(f"{'|V|':>6} {'median(ms)':>12} {'min(ms)':>10} {'max(ms)':>10} {'pass':>6}")
    print("-" * 50)
    for n in [10, 50, 100, 500]:
        g = random_g(n)
        times = []
        for _ in range(100):
            t0 = time.time()
            wl_canonical_hash(g, iters=3)
            times.append((time.time() - t0) * 1000)
        med = statistics.median(times)
        # Pass 标准:|V|=100 ≤ 50ms;|V|=500 ≤ 200ms
        thr = 50.0 if n <= 100 else 200.0
        ok = "✓" if med <= thr else "✗"
        print(f"{n:>6} {med:>12.2f} {min(times):>10.2f} {max(times):>10.2f} {ok:>6}")


if __name__ == "__main__":
    main()
