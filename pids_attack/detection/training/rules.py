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
from cmd_graph.nettack import filter_resources


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

def _is_batch_controller_subject(cmd: str) -> bool:
    normalized = " ".join((cmd or "").split())
    return (
        "RUN_DIR=/tmp/e0_" in normalized
        or "STOP_FILE=/tmp/e0_" in normalized
        or "BG_PIDS=/tmp/e0_" in normalized
        or bool(re.search(r"(^|[;&|]\s*)touch\s+/tmp/e0_[^/\s]+/benign\.stop(\s|$)", normalized))
    )


_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def _is_rule_noise_resource(resource: str) -> bool:
    """Return True only for empty resources.

    Earlier E0 diagnostics tried to suppress DNS, nscd, and bare directory
    entries here. That improves FP, but it is a detector policy choice rather
    than an E0 controller-artifact cleanup, so it is not part of the clean E0
    baseline.
    """
    value = (resource or "").strip()
    return not value


def sql_to_cmd_graph(
    sql_path: str,
    filter_system_resources: bool = True,
    filter_batch_controller_subjects: bool = True,
) -> Optional[CommandGraph]:
    """SQL CDM dump → CommandGraph。

    Args:
        sql_path: 路径到 *.sql 文件
        filter_system_resources: 是否在重算 E_res 前剥掉系统库 / 公共配置资源。
            训练侧 co-occurrence 已经用同一过滤逻辑;推理侧保持一致可避免
            `/lib/*`、`/etc/ld.so.cache` 这类公共资源把 benign 命令连成高
            degree 节点,造成 rule detector 大量 FP。
        filter_batch_controller_subjects: 是否忽略 E0 batch collection 自己的
            controller shell。该 shell 只负责启动 benign background、sleep 和
            marker,不是 benign/attack workload 语义节点;detector 不应把它当作
            E0 评价对象。

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
        if filter_batch_controller_subjects and _is_batch_controller_subject(cmd):
            continue
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

    if filter_system_resources:
        for node in G.nodes.values():
            node.inputs = set(filter_resources(node.inputs))
            node.outputs = set(filter_resources(node.outputs))
            node.inputs = {r for r in node.inputs if not _is_rule_noise_resource(r)}
            node.outputs = {r for r in node.outputs if not _is_rule_noise_resource(r)}

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
      --out-dir detection/artifacts \\
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
    degree_profile = _command_degree_profile(G_benign)
    g1_rule = {
        "power_law": power_law,
        "tau_lambda": tau_lambda,
        "degree_profile": degree_profile,
        "degree_margin": 0,
        "unknown_cmd_policy": "global_max",
    }
    g1_path = out_dir / "g1" / "g1_rule.pkl"
    g1_path.parent.mkdir(parents=True, exist_ok=True)
    with open(g1_path, "wb") as f:
        pickle.dump(g1_rule, f)
    print(f"  saved {g1_path}: alpha={power_law.get('alpha'):.4f}, l={power_law.get('l'):.4f}")

    # 4. precompute G2 (co-occurrence)
    print("\nTraining G2 (co-occurrence)...")
    c_benign = precompute_co_occurrence(G_benign)
    g2_rule = {
        "c_benign": c_benign,
        "sigma": sigma,
        "flag_connected_netflows": True,
    }
    g2_path = out_dir / "g2" / "g2_rule.pkl"
    g2_path.parent.mkdir(parents=True, exist_ok=True)
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
    hybrid_dir = out_dir / f"{base_gnn}_g1g2"
    hybrid_dir.mkdir(parents=True, exist_ok=True)
    hybrid_path = hybrid_dir / f"{base_gnn}_g1g2.pkl"
    with open(hybrid_path, "wb") as f:
        pickle.dump(hybrid_rule, f)
    print(f"  saved {hybrid_path}")

    print(f"\n✅ Done. Outputs: {out_dir}/")


def train_rules_main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--benign-dir", default="detection/data/training_traces")
    p.add_argument("--out-dir", default="detection/artifacts")
    p.add_argument("--base-gnn", default="magic")
    p.add_argument("--n-traces", type=int, default=31)
    p.add_argument("--tau-lambda", type=float, default=0.004)
    p.add_argument("--sigma", type=float, default=0.05)
    args = p.parse_args(argv)

    # 路径根:相对于 pids_attack/ 目录
    base = Path(__file__).resolve().parents[2]
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
(via detection/training/rules.py),存于 detection/artifacts/<detector>/*.pkl。

合并方式:默认 OR(任一标红即标红)。Hybrid 支持 rule_components 配置,
便于 E0 外层优化在不重训的情况下选择更干净的 G1/G2 组合。

API 跟 detection/training/pidsmaker.py::_LocalDetector 完全兼容:
  - predict(sql_path) → int
  - predict_per_node(sql_path) → List[Dict]
  - predict_with_score(sql_path) → Dict
"""

import pickle
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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


def _cmd_name(raw_command: str) -> str:
    """Stable command key used by rule artifacts."""
    value = (raw_command or "").strip()
    return value.split()[0] if value else ""


def _command_degree_profile(G: CommandGraph) -> Dict[str, Any]:
    """Summarize benign degree ranges per command name for G1 inference."""
    degrees = _G_to_node_degrees(G)
    by_cmd: Dict[str, List[int]] = {}
    for nid, node in G.nodes.items():
        cmd = _cmd_name(node.raw_command)
        if not cmd:
            continue
        by_cmd.setdefault(cmd, []).append(int(degrees.get(nid, 0)))

    profile: Dict[str, Dict[str, Any]] = {}
    for cmd, values in by_cmd.items():
        sorted_values = sorted(values)
        profile[cmd] = {
            "count": len(sorted_values),
            "max_degree": int(sorted_values[-1]),
            "p95_degree": int(sorted_values[int(0.95 * (len(sorted_values) - 1))]),
        }
    all_values = sorted(int(v) for v in degrees.values())
    return {
        "by_cmd": profile,
        "global_max_degree": int(all_values[-1]) if all_values else 0,
        "global_p95_degree": int(all_values[int(0.95 * (len(all_values) - 1))])
        if all_values else 0,
    }


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


def _normalize_rule_components(components: Optional[Sequence[str]]) -> Tuple[str, ...]:
    if components is None:
        return ("g1", "g2")
    normalized: List[str] = []
    for item in components:
        name = str(item).strip().lower()
        if name not in {"g1", "g2"}:
            raise ValueError(f"unknown rule component {item!r}; expected g1 or g2")
        if name not in normalized:
            normalized.append(name)
    if not normalized:
        raise ValueError("rule_components must include at least one of g1/g2")
    return tuple(normalized)


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
            base = Path(__file__).resolve().parents[2]
            rule_path = str(base / "detection/artifacts/g1/g1_rule.pkl")
        self.rule = _load_rule(Path(rule_path))
        self.power_law = self.rule["power_law"]
        self.tau_lambda = tau_lambda if tau_lambda is not None else self.rule.get("tau_lambda", 0.004)
        self.degree_profile = self.rule.get("degree_profile") or {}
        self.degree_margin = int(self.rule.get("degree_margin", 0))
        self.unknown_cmd_policy = self.rule.get("unknown_cmd_policy", "legacy_power_law")
        # baseline degree list(power-law 用于评估新 degree 是否超出常规)
        self.baseline_degrees = self.power_law.get("degrees", [])

    def _degree_limit_for(self, cmd_name: str) -> Optional[int]:
        by_cmd = self.degree_profile.get("by_cmd") or {}
        if cmd_name in by_cmd:
            return int(by_cmd[cmd_name].get("max_degree", 0)) + self.degree_margin
        if self.unknown_cmd_policy == "global_max":
            return int(self.degree_profile.get("global_max_degree", 0)) + self.degree_margin
        return None

    def predict(self, sql_path: str) -> int:
        return int(any(n["y_pred"] == 1 for n in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        G = sql_to_cmd_graph(sql_path)
        if G is None or not G.nodes:
            return []
        degrees_now = _G_to_node_degrees(G)

        out: List[Dict[str, Any]] = []
        for nid, node in G.nodes.items():
            # 模拟"加入 nid 这点的 degree"对全图 power-law 的扰动:
            #   degrees_before = baseline (without this node)
            #   degrees_after = baseline + [d_node]
            d_node = degrees_now[nid]
            cmd_name = _cmd_name(node.raw_command)
            degrees_after = self.baseline_degrees + [d_node]
            lam = eq10_incremental_lambda(
                degrees_before=self.baseline_degrees,
                degrees_after=degrees_after,
                power_law=self.power_law,
            )
            degree_limit = self._degree_limit_for(cmd_name)
            if degree_limit is None:
                flag = lam > self.tau_lambda
            else:
                flag = d_node > degree_limit
            out.append({
                "node_index_id": node.index_id,
                "y_pred": int(flag),
                "score": float(lam),
                "raw_command": node.raw_command,
                "degree": int(d_node),
                "degree_limit": degree_limit,
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
            base = Path(__file__).resolve().parents[2]
            rule_path = str(base / "detection/artifacts/g2/g2_rule.pkl")
        self.rule = _load_rule(Path(rule_path))
        self.c_benign = self.rule["c_benign"]
        self.sigma = sigma if sigma is not None else self.rule.get("sigma", 0.05)
        self.flag_connected_netflows = bool(
            self.rule.get("flag_connected_netflows", True)
        )

    def predict(self, sql_path: str) -> int:
        return int(any(n["y_pred"] == 1 for n in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        G = sql_to_cmd_graph(sql_path)
        if G is None or not G.nodes:
            return []
        by_index: Dict[int, Dict[str, Any]] = {}
        for nid, node in G.nodes.items():
            types_now = _node_neighbor_types(G, nid)
            cmd_name = _cmd_name(node.raw_command)
            # 假设 before 为空集(刚加入这个 node 时),after 为 types_now
            ok = eq12_check(
                op_affected_node_types_before=set(),
                op_affected_node_types_after=types_now,
                cmd_name=cmd_name,
                c_benign=self.c_benign,
                sigma=self.sigma,
            )
            flag = not ok                                                       # 违反 → 标红
            if node.index_id is None:
                continue
            by_index[int(node.index_id)] = {
                "node_index_id": node.index_id,
                "node_type": "subject",
                "y_pred": int(flag),
                "score": 1.0 if flag else 0.0,
                "raw_command": node.raw_command,
            }
            if not (flag and self.flag_connected_netflows):
                continue
            for resource in node.inputs | node.outputs:
                if resource_type(resource) != "netflow":
                    continue
                resource_idx = G.resource_index_id.get(resource)
                if resource_idx is None:
                    continue
                by_index[int(resource_idx)] = {
                    "node_index_id": int(resource_idx),
                    "node_type": "netflow",
                    "y_pred": 1,
                    "score": 1.0,
                    "raw_command": node.raw_command,
                    "resource": resource,
                }
        return [by_index[idx] for idx in sorted(by_index)]

    def predict_with_score(self, sql_path: str) -> Dict[str, Any]:
        nodes = self.predict_per_node(sql_path)
        y = int(any(n["y_pred"] == 1 for n in nodes))
        return {"y": y, "score": max((n["score"] for n in nodes), default=0.0),
                "nodes": nodes}


# ============================================================
# G1G2RuleDetector — 纯规则 G1 + G2 OR 合并
# ============================================================

class G1G2RuleDetector:
    """纯规则 G1/G2 组件 OR 合并(任一启用组件标红即标红)。"""

    def __init__(
        self,
        g1_rule_path: Optional[str] = None,
        g2_rule_path: Optional[str] = None,
        *,
        components: Optional[Sequence[str]] = None,
    ):
        self.components = _normalize_rule_components(components)
        self.g1 = G1RuleDetector(rule_path=g1_rule_path) if "g1" in self.components else None
        self.g2 = G2RuleDetector(rule_path=g2_rule_path) if "g2" in self.components else None

    def predict(self, sql_path: str) -> int:
        return int(any(n["y_pred"] == 1 for n in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        outputs: Dict[str, List[Dict[str, Any]]] = {}
        if self.g1 is not None:
            outputs["g1"] = self.g1.predict_per_node(sql_path)
        if self.g2 is not None:
            outputs["g2"] = self.g2.predict_per_node(sql_path)
        by_component = {
            name: {
                n["node_index_id"]: n for n in nodes
                if n.get("node_index_id") is not None
            }
            for name, nodes in outputs.items()
        }
        all_idx = sorted({idx for by_idx in by_component.values() for idx in by_idx})
        merged = []
        for idx in all_idx:
            candidates = [
                by_component[name].get(idx, {"y_pred": 0, "score": 0.0, "raw_command": ""})
                for name in self.components
            ]
            raw_command = next(
                (n.get("raw_command", "") for n in candidates if n.get("raw_command")),
                "",
            )
            merged.append({
                "node_index_id": idx,
                "y_pred": max(int(n.get("y_pred", 0)) for n in candidates),
                "score": max(float(n.get("score", 0.0)) for n in candidates),
                "raw_command": raw_command,
            })
        return merged

    def predict_with_score(self, sql_path: str) -> Dict[str, Any]:
        nodes = self.predict_per_node(sql_path)
        y = int(any(n["y_pred"] == 1 for n in nodes))
        return {"y": y, "score": max((n["score"] for n in nodes), default=0.0),
                "nodes": nodes}


# ============================================================
# HybridGNNRuleDetector — GNN + enabled G1/G2 components OR 合并
# ============================================================

class HybridGNNRuleDetector:
    """GNN + rule components OR 合并。"""

    def __init__(
        self,
        base_gnn: str = "magic",
        rule_path: Optional[str] = None,
        g1_rule_path: Optional[str] = None,
        g2_rule_path: Optional[str] = None,
        gnn_model_path: Optional[str] = None,
        gnn_artifact_dir: Optional[str] = None,
        gnn_threshold_override: Optional[float] = None,
        gnn_suppress_system_resource_alerts_enabled: Optional[bool] = None,
        rule_components: Optional[Sequence[str]] = None,
    ):
        # 延迟 import 避免循环 / GPU 启动
        from detection.training.pidsmaker import _LocalDetector
        self.rule_components = _normalize_rule_components(rule_components)
        self._base = _LocalDetector(
            detector_name=base_gnn,
            model_path=gnn_model_path,
            artifact_dir=gnn_artifact_dir,
            threshold_override=gnn_threshold_override,
            suppress_system_resource_alerts_enabled=(
                gnn_suppress_system_resource_alerts_enabled
            ),
        )
        self._rule = G1G2RuleDetector(
            g1_rule_path=g1_rule_path,
            g2_rule_path=g2_rule_path,
            components=self.rule_components,
        )

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
                "node_type": g.get("node_type") or r.get("node_type", ""),
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
        return HybridGNNRuleDetector(base_gnn="orthrus", rule_components=("g2",))
    if name == "threatrace_g1g2":
        # E0 evidence shows G1 adds many FP to the useful GNN hybrids; keep
        # the cleaner G2 component while preserving the public detector ids.
        return HybridGNNRuleDetector(base_gnn="threatrace", rule_components=("g2",))
    raise ValueError(f"Unknown rule detector: {name}")



def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "train":
        return train_rules_main(argv[1:])
    print("usage: python -m detection.training.rules train ...")
    print("public: python scripts/run.py detect train-rules ...")
    return None


if __name__ == "__main__":
    main()
