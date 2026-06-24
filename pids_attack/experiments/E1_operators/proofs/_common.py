"""experiments/E1_operators/proofs/_common.py — 3 个 detector proof 脚本的共享工具.

被 magic.py / orthrus.py / threatrace.py 引用.
"""
from __future__ import annotations
import sys, json, re, os, uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from attack.oracle import PIDSOracle, query_with_validation_strict

EXP_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = EXP_DIR / "proofs_results"
RESULTS_DIR.mkdir(exist_ok=True)

SCENARIO_PATH = PROJECT_ROOT / "scenarios/juiceshop/01_juiceshop_login_admin_sqli.json"


def load_baseline(detector_name):
    """跑一次 attack,拿 baseline SQL + node info."""
    oracle = PIDSOracle(detector_name=detector_name)
    scn = json.load(open(SCENARIO_PATH))
    res = query_with_validation_strict(scn, [], [], oracle)
    assert res.valid, f"baseline attack failed on {detector_name}"
    sql = open(res.extra["dump"]).read()
    return oracle, sql, res


def find_attack_post(sql):
    """从 SQL dump 找 attack POST curl 节点 hash + idx."""
    m = re.search(
        r"subject_node_table[^;]+'([0-9a-f]{32})', '/usr/bin/curl', '([^']*POST[^']*)', (\d+)\)",
        sql,
    )
    if not m:
        return None, None
    return m.group(1), int(m.group(3))


def find_socket_3000(sql):
    """找 :3000 netflow hash."""
    m = re.search(
        r"netflow_node_table[^;]+'([0-9a-f]{32})', '', '', '127\.0\.0\.1', '3000'",
        sql,
    )
    return m.group(1) if m else None


def mk_subj_sql(idx, path="/usr/bin/curl", cmd=""):
    h = uuid.uuid4().hex
    return h, (
        f"INSERT INTO subject_node_table (node_uuid, hash_id, path, cmd, index_id) "
        f"VALUES ('{uuid.uuid4()}', '{h}', '{path}', '{cmd}', {idx}) ON CONFLICT DO NOTHING;"
    )


def mk_event_sql(src_hash, op, dst_hash, ts):
    return (
        f"INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec) "
        f"VALUES ('{src_hash}', '{src_hash}', '{op}', '{dst_hash}', '{dst_hash}', '{uuid.uuid4().hex}', {ts});"
    )


def shared_neighbor_dilution(sql, target_hash, n, ops,
                              proc_cmd="/usr/bin/cat", base_ts=200000,
                              proc_label_prefix="diluter"):
    """★ P1 原子扰动 — shared-neighbor dilution(共邻稀释).

    操作:加 N 个新 process 节点,每个发 outgoing ops edge 到目标已有节点。
    覆盖 magic add_contagion / orthrus dilution_nai / threatrace fp_removal 通用范式。

    Args:
        sql:        基线 SQL dump
        target_hash: 目标已有节点 hash(BL 自己 / BL 邻居)
        n:          新 process 节点数
        ops:        每个新节点对 target 发的 op 列表(file → ['EVENT_OPEN'];socket → ['EVENT_CONNECT','EVENT_SENDTO'])
        proc_cmd:   新 process binary
        base_ts:    timestamp 起点
        proc_label_prefix: 新节点 cmd 字段 prefix

    Returns:
        (perturbed_sql, list_of_new_node_indices)
    """
    next_idx = next_free_idx(sql)
    extras = []
    new_nodes = []
    for i in range(n):
        h, sj = mk_subj_sql(next_idx + i, proc_cmd, f"{proc_label_prefix}_{i}")
        extras.append(sj)
        new_nodes.append(next_idx + i)
        for j, op in enumerate(ops):
            ts = base_ts + i * len(ops) + j
            extras.append(mk_event_sql(h, op, target_hash, ts))
    return sql + "\n" + "\n".join(extras), new_nodes


def edge_rerouting(sql, src_hash, dst_hash, midway_path="/usr/bin/socat",
                   midway_cmd="socat nat", n=3, ts_base=60000):
    """★ P2 原子扰动 — edge rerouting(边改路由).

    操作:删 src↔dst 原 edge + 加中转节点 + 加 N 条绕道 edge。
    N 条 edge 在 3 种 op 模式间循环分配:
      - src → mid (EVENT_CONNECT)
      - mid → dst (EVENT_CONNECT)
      - dst → mid (EVENT_RECVFROM)

    Args:
        sql:         基线 SQL dump
        src_hash:    源节点 hash(attack POST)
        dst_hash:    原终点 hash(:3000 socket)
        midway_path: 中转 process binary
        midway_cmd:  中转 process cmd 字段
        n:           中转加 N 条绕道 edge(默认 3 = 一个完整 NAT round)
        ts_base:     timestamp 起点

    Returns:
        (perturbed_sql, midway_node_idx)
    """
    s = re.sub(
        rf"INSERT INTO event_table[^;]+'{src_hash}', '[0-9a-f]+', '[A-Z_]+', '{dst_hash}'[^;]+;\s*",
        "", sql,
    )
    s = re.sub(
        rf"INSERT INTO event_table[^;]+'{dst_hash}', '[0-9a-f]+', '[A-Z_]+', '{src_hash}'[^;]+;\s*",
        "", s,
    )
    next_idx = next_free_idx(s)
    midway_h, midway_sj = mk_subj_sql(next_idx, midway_path, midway_cmd)
    edge_patterns = [
        (src_hash, "EVENT_CONNECT", midway_h),
        (midway_h, "EVENT_CONNECT", dst_hash),
        (dst_hash, "EVENT_RECVFROM", midway_h),
    ]
    extras = [midway_sj]
    for i in range(n):
        src, op, dst = edge_patterns[i % len(edge_patterns)]
        extras.append(mk_event_sql(src, op, dst, ts_base + i))
    return s + "\n" + "\n".join(extras), next_idx


def find_incoming_edge_source(sql, target_hash):
    """从 SQL 找一个对 target 发 edge 的源节点 hash(用于 P2 rerouting 找 src)."""
    m = re.search(
        rf"INSERT INTO event_table[^;]+'([0-9a-f]{{32}})', '[0-9a-f]+', '[A-Z_]+', '{target_hash}'",
        sql,
    )
    return m.group(1) if m else None


def predict_all_nodes(oracle, sql):
    """跑 inference,返回 {node_id: {y_pred, score, correct_pred, pred_type, declared_type}}."""
    tmp = f"/tmp/proofs_eval_{os.getpid()}.sql"
    open(tmp, "w").write(sql)
    det = oracle._ensure_detector()
    nodes = det.predict_per_node(tmp)
    os.remove(tmp)
    return {n["node"]: {
        "y_pred": n["y_pred"],
        "score": n["score"],
        "correct_pred": n.get("correct_pred", -1),
        "pred_type": n.get("pred_type", -1),
        "declared_type": n.get("declared_type", -1),
    } for n in nodes}


def eval_attack_node(oracle, sql, attack_idx):
    """跑 inference,返回 attack 节点的 score / y / cor / pred_type."""
    return predict_all_nodes(oracle, sql).get(attack_idx)


_QSTR = r"'(?:[^']|'')*'"   # SQL 单引号字符串(支持 '' 转义,匹配 'foo''bar' 这种)


def _unesc(s):
    """去掉 SQL 字符串两端单引号 + 还原 '' → '."""
    return s[1:-1].replace("''", "'")


def parse_nodes_canonical(sql):
    """从 SQL 抽出 {index_id: canonical_id} 映射,canonical 跨 run 稳定.

    canonical_id 形式:
      ("file",    path)                          ← file_node_table 用 path
      ("netflow", "<dst_ip>:<dst_port>")        ← netflow 用远端 addr
      ("subject", path, cmd)                     ← subject 用 (exec_path, cmdline)

    跟 node_uuid / hash_id / index_id 的随机性脱钩 — 只用节点固有内容做身份。
    支持 SQL 单引号转义('foo''bar' = foo'bar)— 处理 cmd 字段里有引号的情况。
    """
    canonical = {}

    # subject: VALUES ('uuid', 'hash', 'path', 'cmd', idx)
    for m in re.finditer(
        rf"INSERT INTO subject_node_table[^;]*?VALUES "
        rf"\({_QSTR}, {_QSTR}, ({_QSTR}), ({_QSTR}), (\d+)\) ON CONFLICT",
        sql,
    ):
        path = _unesc(m.group(1))
        cmd = _unesc(m.group(2))
        idx = int(m.group(3))
        canonical[idx] = ("subject", path, cmd)

    # file: VALUES ('uuid', 'hash', 'path', idx)
    for m in re.finditer(
        rf"INSERT INTO file_node_table[^;]*?VALUES "
        rf"\({_QSTR}, {_QSTR}, ({_QSTR}), (\d+)\) ON CONFLICT",
        sql,
    ):
        path = _unesc(m.group(1))
        idx = int(m.group(2))
        canonical[idx] = ("file", path)

    # netflow: VALUES ('uuid', 'hash', src_ip, src_port, dst_ip, dst_port, idx)
    for m in re.finditer(
        rf"INSERT INTO netflow_node_table[^;]*?VALUES "
        rf"\({_QSTR}, {_QSTR}, ({_QSTR}), ({_QSTR}), ({_QSTR}), ({_QSTR}), (\d+)\) ON CONFLICT",
        sql,
    ):
        dst_ip = _unesc(m.group(3))
        dst_port = _unesc(m.group(4))
        idx = int(m.group(5))
        canonical[idx] = ("netflow", f"{dst_ip}:{dst_port}")

    return canonical


def build_canonical_index(sql):
    """反向映射:canonical_id → index_id."""
    return {canon: idx for idx, canon in parse_nodes_canonical(sql).items()}


def compute_evade_rate(baseline_sql, baseline_pred, af_sql, af_pred):
    """统一 evade 指标(canonical-id 跨 run 匹配,不依赖 index_id).

    BL_canon = {canonical_id | baseline 里 y_pred==1}
    evade_rate = |{c ∈ BL_canon : af 里同 canonical_id 节点 y == 0}| / |BL_canon|

    Args:
        baseline_sql:   baseline SQL dump 字符串(用于建 idx→canonical 映射)
        baseline_pred:  predict_all_nodes(oracle, baseline_sql) 输出
        af_sql:         扰动后 SQL dump 字符串(用于反查 canonical→new idx)
        af_pred:        predict_all_nodes(oracle, af_sql) 输出

    Returns:
        dict: {baseline_flagged_count, evaded_count, still_flagged_count, evade_rate,
               bl_canonical, evaded_canonical}
    """
    bl_idx_to_canon = parse_nodes_canonical(baseline_sql)
    af_canon_to_idx = build_canonical_index(af_sql)

    bl_flagged_canon = {
        bl_idx_to_canon[idx] for idx, pred in baseline_pred.items()
        if pred["y_pred"] == 1 and idx in bl_idx_to_canon
    }
    if not bl_flagged_canon:
        return {
            "baseline_flagged_count": 0,
            "evaded_count": 0,
            "still_flagged_count": 0,
            "evade_rate": None,
            "bl_canonical": [],
            "evaded_canonical": [],
        }

    evaded = set()
    for canon in bl_flagged_canon:
        af_idx = af_canon_to_idx.get(canon)
        if af_idx is None:
            # 节点在 af dump 里完全不存在 → 视为 evade(detector 见不到 = 没 flag)
            evaded.add(canon)
            continue
        if af_pred.get(af_idx, {"y_pred": 1})["y_pred"] == 0:
            evaded.add(canon)

    return {
        "baseline_flagged_count": len(bl_flagged_canon),
        "evaded_count": len(evaded),
        "still_flagged_count": len(bl_flagged_canon) - len(evaded),
        "evade_rate": len(evaded) / len(bl_flagged_canon),
        "bl_canonical": sorted([str(c) for c in bl_flagged_canon]),
        "evaded_canonical": sorted([str(c) for c in evaded]),
    }


def next_free_idx(sql):
    """SQL 里下一个可用 index_id."""
    indices = [int(i) for i in re.findall(r", (\d+)\) ON CONFLICT", sql)]
    return max(indices) + 1


def save_result(detector_name, results):
    """保存 detector 全部 variant 结果到 proofs_results/<detector>.json."""
    p = RESULTS_DIR / f"{detector_name}.json"
    p.write_text(json.dumps(results, indent=2, default=str))
    return p


def _fmt(label, v):
    """格式化 baseline / after — dict 抽 score+y,string 显示 ref。"""
    if isinstance(v, dict):
        s = v.get("score")
        y = v.get("y_pred")
        parts = []
        if isinstance(s, (int, float)):
            parts.append(f"score={s:.3f}")
        if y is not None:
            parts.append(f"y={y}")
        return f"{label}({', '.join(parts)})" if parts else f"{label}=ref"
    if isinstance(v, str):
        return f"{label}=ref"
    return f"{label}=—"


def print_table(detector_name, results):
    """打印 detector 全部 variant 结果表."""
    print(f"\n{'='*72}")
    print(f"§ {detector_name.upper()} — {len(results)} variant(s)")
    print('='*72)
    for r in results:
        v = r.get("variant", "?")
        finding = r.get("finding", "—")
        bl_s = _fmt("baseline", r.get("baseline"))
        af_s = _fmt("after", r.get("after"))
        evade = r.get("evade", "—")
        print(f"  [{v}] {finding}")
        print(f"     {bl_s} → {af_s}  evade={evade}")
