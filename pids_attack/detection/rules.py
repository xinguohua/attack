"""SQL CDM dump → CommandGraph 重建。

承 p3_implementation_plan.md Step 4.1。从 PIDSMaker 格式的 CDM SQL(含
subject_node_table / file_node_table / netflow_node_table / event_table)
重建一个 CommandGraph,用于:
  1. Reference.warm_start_from_benign(从 benign trace 起步填 R_unflagged)
  2. Rule detectors(G1/G2)在 detector 端把 SQL 转 CommandGraph 走 rule 检查

简化映射(只为 attacker-side 用):
  - subject 节点 → CommandNode(raw_command=cmd, is_attack=False)
  - file / netflow 节点 → 资源 ID(放入相关 subject 的 inputs/outputs)
  - 事件:
      READ/RECV → src is subject,dst is file/netflow → input of subject
      WRITE/SEND → src is subject,dst is file/netflow → output of subject
      FORK/CLONE → src is subject parent → spawn edge to dst subject
      EXECUTE → src is subject, dst is subject → seq edge
  - 时间顺序:用 event_table.timestamp_rec 排序 → 构造 e_seq chain

注:这是 best-effort,不保证 G_reconstructed 跟 attacker 原 G_t 完全等价 —
但对 R reference k-NN 距离 + G1/G2 rule 检查够用。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cmd_graph.graph import CommandGraph, CommandNode


# ============================================================
# SQL parsing
# ============================================================

_RE_SUBJECT = re.compile(
    r"INSERT INTO subject_node_table[^V]*VALUES\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(\d+)",
    re.IGNORECASE,
)
_RE_FILE = re.compile(
    r"INSERT INTO file_node_table[^V]*VALUES\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(\d+)",
    re.IGNORECASE,
)
_RE_NETFLOW = re.compile(
    r"INSERT INTO netflow_node_table[^V]*VALUES\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(\d+)",
    re.IGNORECASE,
)
_RE_EVENT = re.compile(
    r"INSERT INTO event_table[^V]*VALUES\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(\d+)",
)


def _parse_sql_dump(sql_text: str) -> Tuple[
    Dict[str, Dict],           # subject_by_uuid
    Dict[str, Dict],           # file_by_uuid
    Dict[str, Dict],           # netflow_by_uuid
    List[Tuple[str, str, str, str, str, int]],  # events: (src, src_idx, op, dst, dst_idx, ts)
]:
    """parse SQL dump 4 tables。"""
    subjects: Dict[str, Dict] = {}
    files: Dict[str, Dict] = {}
    netflows: Dict[str, Dict] = {}
    events: List[Tuple[str, str, str, str, str, int]] = []

    for m in _RE_SUBJECT.finditer(sql_text):
        node_uuid, hash_id, path, cmd, index_id = m.groups()
        subjects[node_uuid] = {
            "uuid": node_uuid, "hash": hash_id,
            "path": path, "cmd": cmd,
            "index_id": int(index_id),
        }

    for m in _RE_FILE.finditer(sql_text):
        node_uuid, hash_id, path, index_id = m.groups()
        files[node_uuid] = {
            "uuid": node_uuid, "hash": hash_id,
            "path": path, "index_id": int(index_id),
        }

    for m in _RE_NETFLOW.finditer(sql_text):
        node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id = m.groups()
        addr = f"{dst_addr}:{dst_port}" if dst_port else dst_addr
        netflows[node_uuid] = {
            "uuid": node_uuid, "hash": hash_id,
            "addr": addr, "index_id": int(index_id),
        }

    for m in _RE_EVENT.finditer(sql_text):
        src_node, src_idx, op, dst_node, dst_idx, evt_uuid, ts = m.groups()
        events.append((src_node, src_idx, op.upper(), dst_node, dst_idx, int(ts)))

    return subjects, files, netflows, events


# ============================================================
# Public API
# ============================================================

def sql_to_cmd_graph(sql_path: str) -> Optional[CommandGraph]:
    """SQL CDM dump → CommandGraph。

    Args:
        sql_path: 路径到 *.sql 文件

    Returns:
        CommandGraph,失败 / 空文件 / 无 subject 节点 → None
    """
    p = Path(sql_path)
    if not p.exists():
        return None
    sql_text = p.read_text(errors="ignore")
    subjects, files, netflows, events = _parse_sql_dump(sql_text)
    if not subjects:
        return None

    # 1. 创建 CommandNode per subject(CommandGraph.add_node 自动分配 nid)
    G = CommandGraph()
    hash_to_node_id: Dict[str, int] = {}        # event_table 用 hash_id 引用
    hash_to_file: Dict[str, Dict] = {info["hash"]: info for info in files.values()}
    hash_to_netflow: Dict[str, Dict] = {info["hash"]: info for info in netflows.values()}

    for uuid, info in sorted(subjects.items(), key=lambda kv: kv[1]["index_id"]):
        cmd = info["cmd"] or info["path"]
        nid = G.add_node(
            raw_command=cmd,
            args=cmd.split()[1:] if cmd else [],
            inputs=set(),
            outputs=set(),
            is_attack=False,                                  # benign trace 重建,都标 False
        )
        hash_to_node_id[info["hash"]] = nid
        # 保留 SQL CDM dump 的全局 index_id,让 rule detector 输出能跟 SQL 节点对齐
        G.nodes[nid].index_id = info["index_id"]

    # file / netflow 资源也保留 SQL index_id,rule detector 判 file/netflow flag 时用
    for info in files.values():
        if info.get("path"):
            G.resource_index_id[info["path"]] = info["index_id"]
    for info in netflows.values():
        if info.get("addr"):
            G.resource_index_id[info["addr"]] = info["index_id"]

    if not G.nodes:
        return None

    # 2. 走事件,加 inputs / outputs / edges(事件按 timestamp 排序)
    events_sorted = sorted(events, key=lambda e: e[5])
    for src_hash, _, op, dst_hash, _, _ in events_sorted:
        src_nid = hash_to_node_id.get(src_hash)
        if src_nid is None or src_nid not in G.nodes:
            continue
        src_obj = G.nodes[src_nid]

        # 读 / 接收
        if op in ("EVENT_READ", "READ", "EVENT_RECV", "RECV",
                  "EVENT_RECVFROM", "RECVFROM",
                  "EVENT_RECVMSG", "RECVMSG",
                  "EVENT_OPEN", "OPEN"):
            if dst_hash in hash_to_file:
                src_obj.inputs.add(hash_to_file[dst_hash]["path"])
            elif dst_hash in hash_to_netflow:
                src_obj.inputs.add(hash_to_netflow[dst_hash]["addr"])
        # 写 / 发送
        elif op in ("EVENT_WRITE", "WRITE", "EVENT_SEND", "SEND",
                    "EVENT_SENDTO", "SENDTO",
                    "EVENT_SENDMSG", "SENDMSG",
                    "EVENT_CREATE_OBJECT", "CREATE_OBJECT",
                    "EVENT_CONNECT", "CONNECT"):
            if dst_hash in hash_to_file:
                src_obj.outputs.add(hash_to_file[dst_hash]["path"])
            elif dst_hash in hash_to_netflow:
                src_obj.outputs.add(hash_to_netflow[dst_hash]["addr"])
        # FORK / CLONE → spawn 边
        elif op in ("EVENT_FORK", "FORK", "EVENT_CLONE", "CLONE"):
            dst_nid = hash_to_node_id.get(dst_hash)
            if dst_nid is not None and dst_nid in G.nodes and dst_nid != src_nid:
                G.e_spawn.add((src_nid, dst_nid))
        # EXECUTE → seq 边
        elif op in ("EVENT_EXECUTE", "EXECUTE"):
            dst_nid = hash_to_node_id.get(dst_hash)
            if dst_nid is not None and dst_nid in G.nodes and dst_nid != src_nid:
                edge = (src_nid, dst_nid)
                if edge not in G.e_seq:
                    G.e_seq.append(edge)

    # 3. 如果没生成任何 e_seq 边,按 index_id 顺序补一条 chain
    if not G.e_seq:
        node_ids_sorted = sorted(G.nodes.keys())
        for i in range(len(node_ids_sorted) - 1):
            G.e_seq.append((node_ids_sorted[i], node_ids_sorted[i + 1]))

    # 4. 从 inputs/outputs 算 e_res(共享资源 → 无向边)— G1/G2 规则检测器靠这个
    G.refresh_e_res()

    return G


# ============================================================
# Rule training
# ============================================================

"""离线训 G1/G2 规则参数(p3_implementation_plan.md Step 4.2)。

从 N 份 benign trace 重建 CommandGraph,union 出 G_benign,然后:
  1. precompute_power_law(G_benign) → α, l, degrees → 存 g1_rule.pkl
  2. precompute_co_occurrence(G_benign) → c_benign → 存 g2_rule.pkl
  3. 存 magic_g1g2.pkl 含 base GNN tag + 两 rule 路径

调用:
    PYTHONPATH=pids_attack conda run -n mimicattack python scripts/run.py detect train-rules \\
      --benign-dir detection/data/training_traces \\
      --out-dir detection/data/hybrid_rules \\
      --base-gnn magic \\
      --n-traces 31
"""

import argparse
import pickle
import sys
from pathlib import Path
from typing import Optional

from cmd_graph.graph import CommandGraph
from cmd_graph.nettack import (
    precompute_co_occurrence,
    precompute_power_law,
)


def union_graphs(graphs: list) -> CommandGraph:
    """Union 多个 CommandGraph 成一个大图(节点重 id-rebase,边合并)。"""
    G_union = CommandGraph()
    for G in graphs:
        node_map: dict = {}
        for old_nid, node in G.nodes.items():
            new_nid = G_union.add_node(
                raw_command=node.raw_command,
                args=list(node.args),
                inputs=set(node.inputs),
                outputs=set(node.outputs),
                is_attack=node.is_attack,
            )
            node_map[old_nid] = new_nid
        for a, b in G.e_seq:
            G_union.e_seq.append((node_map[a], node_map[b]))
        for a, b in G.e_res:
            G_union.e_res.add((node_map[a], node_map[b]))
        for a, b in G.e_spawn:
            G_union.e_spawn.add((node_map[a], node_map[b]))
    return G_union


def train_rules(
    benign_dir: Path,
    out_dir: Path,
    base_gnn: str = "magic",
    n_traces: int = 31,
    tau_lambda: float = 0.004,
    sigma: float = 0.05,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    sqls = sorted(benign_dir.glob("benign_*.sql"))[:n_traces]
    if not sqls:
        print(f"❌ no benign_*.sql in {benign_dir}")
        return

    print(f"=== Hybrid 规则训练 ===")
    print(f"benign trace count: {len(sqls)}")

    # 1. 重建每份 benign trace
    graphs = []
    for sql in sqls:
        G = sql_to_cmd_graph(str(sql))
        if G is not None and len(G.nodes) > 0:
            graphs.append(G)
            print(f"  ✓ {sql.name}: {len(G.nodes)} nodes")
        else:
            print(f"  ✗ {sql.name}: failed to parse")

    if not graphs:
        print("❌ no usable benign graphs")
        return

    # 2. Union
    G_benign = union_graphs(graphs)
    print(f"\nG_benign union: {len(G_benign.nodes)} nodes")

    # 3. precompute G1 (power-law)
    print("\nTraining G1 (degree power-law)...")
    power_law = precompute_power_law(G_benign)
    g1_rule = {
        "power_law": power_law,
        "tau_lambda": tau_lambda,
    }
    g1_path = out_dir / "g1_rule.pkl"
    with open(g1_path, "wb") as f:
        pickle.dump(g1_rule, f)
    print(f"  saved {g1_path}: alpha={power_law.get('alpha'):.4f}, l={power_law.get('l'):.4f}")

    # 4. precompute G2 (co-occurrence)
    print("\nTraining G2 (co-occurrence)...")
    c_benign = precompute_co_occurrence(G_benign)
    g2_rule = {
        "c_benign": c_benign,
        "sigma": sigma,
    }
    g2_path = out_dir / "g2_rule.pkl"
    with open(g2_path, "wb") as f:
        pickle.dump(g2_rule, f)
    print(f"  saved {g2_path}: |type_pairs|={len(c_benign.get('type_pairs', set()))}")

    # 5. 联合规则
    print(f"\nTraining hybrid {base_gnn} + G1 + G2...")
    hybrid_rule = {
        "base_gnn": base_gnn,
        "g1_rule_path": str(g1_path.relative_to(out_dir.parent.parent)) if "pids_attack" in str(g1_path) else str(g1_path),
        "g2_rule_path": str(g2_path.relative_to(out_dir.parent.parent)) if "pids_attack" in str(g2_path) else str(g2_path),
        "power_law": power_law,
        "c_benign": c_benign,
        "tau_lambda": tau_lambda,
        "sigma": sigma,
    }
    hybrid_path = out_dir / f"{base_gnn}_g1g2.pkl"
    with open(hybrid_path, "wb") as f:
        pickle.dump(hybrid_rule, f)
    print(f"  saved {hybrid_path}")

    print(f"\n✅ Done. Outputs: {out_dir}/")


def train_rules_main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--benign-dir", default="detection/data/training_traces")
    p.add_argument("--out-dir", default="detection/data/hybrid_rules")
    p.add_argument("--base-gnn", default="magic")
    p.add_argument("--n-traces", type=int, default=31)
    p.add_argument("--tau-lambda", type=float, default=0.004)
    p.add_argument("--sigma", type=float, default=0.05)
    args = p.parse_args(argv)

    # 路径根:相对于 pids_attack/ 目录
    base = Path(__file__).resolve().parent.parent
    benign_dir = base / args.benign_dir
    out_dir = base / args.out_dir
    train_rules(
        benign_dir=benign_dir,
        out_dir=out_dir,
        base_gnn=args.base_gnn,
        n_traces=args.n_traces,
        tau_lambda=args.tau_lambda,
        sigma=args.sigma,
    )




# ============================================================
# Rule detectors
# ============================================================

"""4 个新 detector — G1 / G2 / G1+G2(纯规则)+ G1+G2+GNN(混合)。

承 p3_implementation_plan.md Step 4.3。规则参数训自 31 份 benign trace
(via detection/rules.py),存于 detection/data/hybrid_rules/*.pkl。

合并方式:OR(任一标红即标红,strict 模式)— 用户拍板。

API 跟 detection/pidsmaker.py::_LocalDetector 完全兼容:
  - predict(sql_path) → int
  - predict_per_node(sql_path) → List[Dict]
  - predict_with_score(sql_path) → Dict
"""

import pickle
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cmd_graph.graph import CommandGraph
from cmd_graph.nettack import (
    eq10_incremental_lambda,
    eq12_check,
    resource_type,
)



# ============================================================
# helpers
# ============================================================

def _G_to_node_degrees(G: CommandGraph) -> Dict[int, int]:
    """每节点 e_res 度数。"""
    dg: Counter = Counter()
    for a, b in G.e_res:
        dg[a] += 1
        dg[b] += 1
    for nid in G.nodes:
        if nid not in dg:
            dg[nid] = 0
    return dict(dg)


def _node_neighbor_types(G: CommandGraph, nid: int) -> Set[str]:
    """v 在 G 上的邻居资源类型集。"""
    types: Set[str] = set()
    node = G.nodes.get(nid)
    if node is None:
        return types
    for r in node.inputs | node.outputs:
        types.add(resource_type(r))
    return types


def _load_rule(path: Path) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return pickle.load(f)


# ============================================================
# G1RuleDetector — 纯规则 G1
# ============================================================

class G1RuleDetector:
    """纯规则 G1 — 度分布 power-law 违反检测(Nettack §4.1 Eq 6-10)。

    流程:
      1. SQL → CommandGraph(via sql_to_cmd_graph)
      2. 每节点算 Λ = eq10_incremental_lambda(degrees_before=baseline, degrees_after=now)
      3. Λ > τ_Λ → 节点标红
    """

    def __init__(
        self,
        rule_path: Optional[str] = None,
        tau_lambda: Optional[float] = None,
    ) -> None:
        if rule_path is None:
            base = Path(__file__).resolve().parent.parent
            rule_path = str(base / "detection/data/hybrid_rules/g1_rule.pkl")
        self.rule = _load_rule(Path(rule_path))
        self.power_law = self.rule["power_law"]
        self.tau_lambda = tau_lambda if tau_lambda is not None else self.rule.get("tau_lambda", 0.004)
        # baseline degree list(power-law 用于评估新 degree 是否超出常规)
        self.baseline_degrees = self.power_law.get("degrees", [])

    def predict(self, sql_path: str) -> int:
        return int(any(n["y_pred"] == 1 for n in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        G = sql_to_cmd_graph(sql_path)
        if G is None or not G.nodes:
            return []
        degrees_now = _G_to_node_degrees(G)
        all_degree_list = list(degrees_now.values())

        out: List[Dict[str, Any]] = []
        for nid, node in G.nodes.items():
            # 模拟"加入 nid 这点的 degree"对全图 power-law 的扰动:
            #   degrees_before = baseline (without this node)
            #   degrees_after = baseline + [d_node]
            d_node = degrees_now[nid]
            degrees_after = self.baseline_degrees + [d_node]
            lam = eq10_incremental_lambda(
                degrees_before=self.baseline_degrees,
                degrees_after=degrees_after,
                power_law=self.power_law,
            )
            flag = lam > self.tau_lambda
            out.append({
                "node_index_id": node.index_id,
                "y_pred": int(flag),
                "score": float(lam),
                "raw_command": node.raw_command,
            })
        return out

    def predict_with_score(self, sql_path: str) -> Dict[str, Any]:
        nodes = self.predict_per_node(sql_path)
        y = int(any(n["y_pred"] == 1 for n in nodes))
        return {"y": y, "score": max((n["score"] for n in nodes), default=0.0),
                "nodes": nodes}


# ============================================================
# G2RuleDetector — 纯规则 G2
# ============================================================

class G2RuleDetector:
    """纯规则 G2 — 共现违反检测(Nettack §4.1 Eq 11-12)。

    流程:
      1. SQL → CommandGraph
      2. 每节点 v,算 v 的资源类型集 S_v
      3. eq12_check(before=∅, after=S_v, cmd_name=v.cmd, c_benign, σ) — 引入 G_benign 没共现过的类型对 → reject
      4. reject → 节点标红
    """

    def __init__(
        self,
        rule_path: Optional[str] = None,
        sigma: Optional[float] = None,
    ) -> None:
        if rule_path is None:
            base = Path(__file__).resolve().parent.parent
            rule_path = str(base / "detection/data/hybrid_rules/g2_rule.pkl")
        self.rule = _load_rule(Path(rule_path))
        self.c_benign = self.rule["c_benign"]
        self.sigma = sigma if sigma is not None else self.rule.get("sigma", 0.05)

    def predict(self, sql_path: str) -> int:
        return int(any(n["y_pred"] == 1 for n in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        G = sql_to_cmd_graph(sql_path)
        if G is None or not G.nodes:
            return []
        out: List[Dict[str, Any]] = []
        for nid, node in G.nodes.items():
            types_now = _node_neighbor_types(G, nid)
            cmd_name = node.raw_command.split()[0] if node.raw_command else ""
            # 假设 before 为空集(刚加入这个 node 时),after 为 types_now
            ok = eq12_check(
                op_affected_node_types_before=set(),
                op_affected_node_types_after=types_now,
                cmd_name=cmd_name,
                c_benign=self.c_benign,
                sigma=self.sigma,
            )
            flag = not ok                                                       # 违反 → 标红
            out.append({
                "node_index_id": node.index_id,
                "y_pred": int(flag),
                "score": 1.0 if flag else 0.0,
                "raw_command": node.raw_command,
            })
        return out

    def predict_with_score(self, sql_path: str) -> Dict[str, Any]:
        nodes = self.predict_per_node(sql_path)
        y = int(any(n["y_pred"] == 1 for n in nodes))
        return {"y": y, "score": max((n["score"] for n in nodes), default=0.0),
                "nodes": nodes}


# ============================================================
# G1G2RuleDetector — 纯规则 G1 + G2 OR 合并
# ============================================================

class G1G2RuleDetector:
    """纯规则 G1 + G2,OR 合并(任一标红即标红)。"""

    def __init__(self, g1_rule_path: Optional[str] = None, g2_rule_path: Optional[str] = None):
        self.g1 = G1RuleDetector(rule_path=g1_rule_path)
        self.g2 = G2RuleDetector(rule_path=g2_rule_path)

    def predict(self, sql_path: str) -> int:
        return int(any(n["y_pred"] == 1 for n in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        out_g1 = self.g1.predict_per_node(sql_path)
        out_g2 = self.g2.predict_per_node(sql_path)
        # SQL 解析两边走同一个 sql_to_cmd_graph,node_index_id 对齐
        g2_by_idx = {n["node_index_id"]: n for n in out_g2}
        merged = []
        for n1 in out_g1:
            idx = n1["node_index_id"]
            n2 = g2_by_idx.get(idx, {"y_pred": 0, "score": 0.0})
            merged.append({
                "node_index_id": idx,
                "y_pred": max(n1["y_pred"], n2["y_pred"]),
                "score": max(n1["score"], n2["score"]),
                "raw_command": n1.get("raw_command", ""),
            })
        return merged

    def predict_with_score(self, sql_path: str) -> Dict[str, Any]:
        nodes = self.predict_per_node(sql_path)
        y = int(any(n["y_pred"] == 1 for n in nodes))
        return {"y": y, "score": max((n["score"] for n in nodes), default=0.0),
                "nodes": nodes}


# ============================================================
# HybridGNNRuleDetector — GNN + G1 + G2 OR 合并
# ============================================================

class HybridGNNRuleDetector:
    """GNN + G1 + G2,OR 合并 — motivation 实验里这种 detector 最强。"""

    def __init__(self, base_gnn: str = "magic", rule_path: Optional[str] = None):
        # 延迟 import 避免循环 / GPU 启动
        from detection.pidsmaker import _LocalDetector
        self._base = _LocalDetector(detector_name=base_gnn)
        self._rule = G1G2RuleDetector()

    def predict(self, sql_path: str) -> int:
        return int(any(n["y_pred"] == 1 for n in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        gnn_out = self._base.predict_per_node(sql_path)
        rule_out = self._rule.predict_per_node(sql_path)
        # GNN 跟 Rule 现在都返 SQL `node_index_id`,真正 per-node OR
        gnn_by_idx = {nd["node_index_id"]: nd for nd in gnn_out
                      if nd.get("node_index_id") is not None}
        rule_by_idx = {nd["node_index_id"]: nd for nd in rule_out
                       if nd.get("node_index_id") is not None}
        all_idx = sorted(set(gnn_by_idx) | set(rule_by_idx))
        out: List[Dict[str, Any]] = []
        for idx in all_idx:
            g = gnn_by_idx.get(idx, {"y_pred": 0, "score": 0.0, "label": ""})
            r = rule_by_idx.get(idx, {"y_pred": 0, "score": 0.0, "raw_command": ""})
            out.append({
                "node_index_id": idx,
                "y_pred": max(int(g.get("y_pred", 0)), int(r.get("y_pred", 0))),
                "score": max(float(g.get("score", 0.0)), float(r.get("score", 0.0))),
                "label": g.get("label", ""),
                "raw_command": r.get("raw_command", ""),
            })
        return out

    def predict_with_score(self, sql_path: str) -> Dict[str, Any]:
        nodes = self.predict_per_node(sql_path)
        y = int(any(n.get("y_pred", 0) == 1 for n in nodes))
        return {"y": y,
                "score": max((float(n.get("score", 0.0)) for n in nodes), default=0.0),
                "nodes": nodes}


# ============================================================
# Factory
# ============================================================

SUPPORTED_RULE_DETECTORS = ("g1", "g2", "g1g2", "magic_g1g2",
                            "orthrus_g1g2", "threatrace_g1g2")


def make_rule_detector(name: str):
    """根据名字 dispatch 4 类 rule detector。"""
    if name == "g1":
        return G1RuleDetector()
    if name == "g2":
        return G2RuleDetector()
    if name == "g1g2":
        return G1G2RuleDetector()
    if name == "magic_g1g2":
        return HybridGNNRuleDetector(base_gnn="magic")
    if name == "orthrus_g1g2":
        return HybridGNNRuleDetector(base_gnn="orthrus")
    if name == "threatrace_g1g2":
        return HybridGNNRuleDetector(base_gnn="threatrace")
    raise ValueError(f"Unknown rule detector: {name}")



def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "train":
        return train_rules_main(argv[1:])
    print("usage: python -m detection.rules train ...")
    print("public: python scripts/run.py detect train-rules ...")
    return None


if __name__ == "__main__":
    main()
