"""pidsmaker_inference.py — 真 forward inference (v2, 2026-05-09).

每个 detector 一个 PIDSMakerEngine 实例,Lazy load:
- 第一次构造:只记 detector_name
- 第一次 predict:
  * 加载 PIDSMaker 训练时落盘的 state_dict + memory + neighbor_loader + threshold
  * 加载 indexid2vec / etype2oh / ntype2oh / GraphReindexer
  * 缓存 train/val/test sample(供 schema 比对)

每次 predict(sql_path):
  1. SQL → events + indexid2msg(直接解析 INSERT 语句,不灌 DB)
  2. cdm_to_nx_graph:复制 PIDSMaker gen_edge_fused_tw 节点/边构建逻辑(去 IO)
  3. apply_graph_transformations(graph, methods, cfg):PIDSMaker 直接调
  4. single_graph_to_temporal_data:复制 PIDSMaker feat_inference 转换 + OOV 处理
  5. extract_msg_from_data([data], cfg):PIDSMaker 直接调
  6. (TGN-based) compute_tgn_graphs(deepcopy(neighbor_loader)):隔离 query 间状态
  7. self._model(batch, inference=True):真 forward
  8. compute_detector_score:复制 inference_loop.test_node_level 4 个 detector 分支
  9. _apply_threshold:5 种 threshold method 分发

**关键**:每次 predict **真按 SQL 内容跑模型**;δ 改了 → events 不同 → graph 不同 →
forward 输出不同 → score 不同 → y 可能 0/1 翻转。**没有任何固化查表**。

**任意 SQL 进来都过同一个模型** —— 不再按文件名做 scenario 路由。
"""
from __future__ import annotations
import argparse
import copy
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PIDSMAKER_DIR = os.environ.get(
    "PIDSMAKER_DIR",
    os.path.join(PROJECT_ROOT, "PIDSMaker"),
)
ARTIFACT_DIR = os.environ.get(
    "PIDSMAKER_ARTIFACT_DIR",
    os.path.join(PROJECT_ROOT, "detection", "data", "pidsmaker_artifacts"),
)
DB_HOST = os.environ.get("PIDS_DB_HOST", "localhost")
DB_USER = os.environ.get("PIDS_DB_USER", "pids")
DB_PASSWORD = os.environ.get("PIDS_DB_PASSWORD", "pids")
DB_PORT = os.environ.get("PIDS_DB_PORT", "5432")


def _build_args(detector_name: str) -> argparse.Namespace:
    """模拟 argparse.Namespace 给 get_yml_cfg。"""
    if PIDSMAKER_DIR not in sys.path:
        sys.path.insert(0, PIDSMAKER_DIR)
    from pidsmaker.config.pipeline import get_runtime_required_args  # noqa: E402

    fake_argv = [
        detector_name, "JUICESHOP",
        "--cpu",
        "--database_host", DB_HOST,
        "--database_user", DB_USER,
        "--database_password", DB_PASSWORD,
        "--database_port", str(DB_PORT),
        "--artifact_dir", str(ARTIFACT_DIR),
    ]
    return get_runtime_required_args(args=fake_argv)


def _get_yml_cfg_safe(args):
    """Call PIDSMaker get_yml_cfg without leaking our CLI argv into upstream argparse."""
    from pidsmaker.config.pipeline import get_yml_cfg  # noqa: E402

    old_argv = sys.argv[:]
    try:
        sys.argv = [old_argv[0] if old_argv else "pidsmaker"]
        return get_yml_cfg(args)
    finally:
        sys.argv = old_argv


# ============================================================================
# SQL → events + indexid2msg(in-memory,绕过 DB)
# ============================================================================

_INSERT_NETFLOW_RE = re.compile(
    r"INSERT INTO netflow_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*(\d+)\)",
    re.IGNORECASE,
)
_INSERT_SUBJECT_RE = re.compile(
    r"INSERT INTO subject_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'((?:[^'\\]|\\.)*)',\s*'((?:[^'\\]|\\.)*)',\s*(\d+)\)",
    re.IGNORECASE,
)
_INSERT_FILE_RE = re.compile(
    r"INSERT INTO file_node_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'((?:[^'\\]|\\.)*)',\s*(\d+)\)",
    re.IGNORECASE,
)
_INSERT_EVENT_RE = re.compile(
    r"INSERT INTO event_table\s*\([^)]+\)\s*VALUES\s*"
    r"\('([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*(\d+)\)",
    re.IGNORECASE,
)


def parse_sql_to_events_and_nodes(sql_text: str, cfg) -> Tuple[List[tuple], Dict[str, list]]:
    """解析 PIDSMaker INSERT SQL → (events_list, indexid2msg)。

    输出 events_list 字段对齐 build_default_graphs.gen_edge_fused_tw 的 events_list:
        (src_node_hash, src_index_id, operation, dst_node_hash, dst_index_id,
         event_uuid, timestamp_rec, _id)

    indexid2msg: {index_id_str: [node_type, label_string]}
        和 build_default_graphs.compute_indexid2msg 输出一致。

    与上游差别:
      - 我们不灌 DB,直接 regex 抽 INSERT
      - hash_id 直接当 src_node / dst_node;index_id 直接来自 SQL,不重排
      - label 拼接逻辑跟 compute_indexid2msg 一致,字段顺序对齐
        get_darpa_tc_node_feats_from_cfg(cfg).
    """
    if PIDSMAKER_DIR not in sys.path:
        sys.path.insert(0, PIDSMAKER_DIR)
    from pidsmaker.config import get_darpa_tc_node_feats_from_cfg
    from pidsmaker.utils.utils import stringtomd5

    use_hashed = cfg.construction.use_hashed_label
    feats = get_darpa_tc_node_feats_from_cfg(cfg)

    indexid2msg: Dict[str, list] = {}
    hash_to_index_id: Dict[str, str] = {}

    def _label(attrs: Dict[str, str], ntype: str) -> str:
        s = " ".join(attrs[k] for k in feats[ntype])
        return stringtomd5(s) if use_hashed else s

    # netflow
    for m in _INSERT_NETFLOW_RE.finditer(sql_text):
        node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, idx_id = m.groups()
        attrs = {
            "type": "netflow",
            "local_ip": src_addr, "local_port": src_port,
            "remote_ip": dst_addr, "remote_port": dst_port,
        }
        idx_id = str(idx_id)
        indexid2msg[idx_id] = ["netflow", _label(attrs, "netflow")]
        hash_to_index_id[hash_id] = idx_id

    # subject
    for m in _INSERT_SUBJECT_RE.finditer(sql_text):
        node_uuid, hash_id, path, cmd_line, idx_id = m.groups()
        # SQL escape '' → ' ;  我们目前不需要双 ' 的复杂还原
        attrs = {"type": "subject", "path": path, "cmd_line": cmd_line.replace("''", "'")}
        idx_id = str(idx_id)
        indexid2msg[idx_id] = ["subject", _label(attrs, "subject")]
        hash_to_index_id[hash_id] = idx_id

    # file
    for m in _INSERT_FILE_RE.finditer(sql_text):
        node_uuid, hash_id, path, idx_id = m.groups()
        attrs = {"type": "file", "path": path}
        idx_id = str(idx_id)
        indexid2msg[idx_id] = ["file", _label(attrs, "file")]
        hash_to_index_id[hash_id] = idx_id

    # events
    events: List[tuple] = []
    eid = 0
    skipped = 0
    for m in _INSERT_EVENT_RE.finditer(sql_text):
        src_hash, src_idx, op, dst_hash, dst_idx, evt_uuid, ts = m.groups()
        # gen_edge_fused_tw 用 src_index_id 当节点 key。SQL 里 src_index_id 实际是 hash;
        # 我们的 indexid2msg key 是数字 index_id, 因此 lookup 用 hash → index_id 表。
        sidx = hash_to_index_id.get(src_idx)
        didx = hash_to_index_id.get(dst_idx)
        if sidx is None or didx is None:
            # 引用了未声明的节点(orphan event):跳过(对齐上游 indexid2msg 缺失会 KeyError 的安全行为)
            skipped += 1
            continue
        events.append((
            src_hash,    # src_node (hash)
            sidx,        # src_index_id (整数字符串)
            op,          # operation
            dst_hash,    # dst_node (hash)
            didx,        # dst_index_id (整数字符串)
            evt_uuid,
            int(ts),
            eid,
        ))
        eid += 1

    return events, indexid2msg


# ============================================================================
# 自写 ① cdm_to_nx_graph
# from pids_attack/PIDSMaker/pidsmaker/preprocessing/build_graph_methods/build_default_graphs.py:290-447
# 删除:DB 查询 / cfg.dataset.dates 遍历 / BATCH=1024 切图 / torch.save 落盘
# 保留:include_edge_type 过滤 / fuse_edge 逻辑 / nx.MultiDiGraph 组装
# ============================================================================

def cdm_to_nx_graph(events: List[tuple], indexid2msg: Dict[str, list], cfg):
    """events + indexid2msg → 单张 nx.MultiDiGraph。

    跟 PIDSMaker `gen_edge_fused_tw` 等价(单图、单时间窗、不切 BATCH、不落盘)。
    """
    if PIDSMAKER_DIR not in sys.path:
        sys.path.insert(0, PIDSMAKER_DIR)
    import networkx as nx
    from pidsmaker.utils.dataset_utils import get_rel2id

    rel2id = get_rel2id(cfg)
    include_edge_type = rel2id

    # 过滤 events
    events_list: List[tuple] = []
    for ev in events:
        op = ev[2]
        if op in include_edge_type:
            events_list.append(ev)

    if not events_list:
        return nx.MultiDiGraph()

    node_info: Dict[str, Dict[str, str]] = {}
    edge_list: List[Dict[str, Any]] = []

    if cfg.construction.fuse_edge:
        edge_info: Dict[Tuple[str, str], list] = {}
        for (
            src_node, src_index_id, operation, dst_node, dst_index_id,
            event_uuid, timestamp_rec, _id,
        ) in events_list:
            if src_index_id not in node_info:
                node_type, label = indexid2msg.get(src_index_id, ["subject", ""])
                node_info[src_index_id] = {"label": label, "node_type": node_type}
            if dst_index_id not in node_info:
                node_type, label = indexid2msg.get(dst_index_id, ["file", ""])
                node_info[dst_index_id] = {"label": label, "node_type": node_type}

            edge_info.setdefault((src_index_id, dst_index_id), []).append(
                (timestamp_rec, operation, event_uuid)
            )

        # fuse: 同 (src, dst) 同 op 连续的折成一条边,取最早 timestamp(对齐上游)
        for (src, dst), data in edge_info.items():
            sorted_data = sorted(data, key=lambda x: x[0])
            cur_op = None
            cur_start_idx = None
            for idx, (ts, op, uuid) in enumerate(sorted_data):
                if op == cur_op:
                    continue
                if cur_start_idx is not None:
                    # flush 前一段
                    s_ts, s_op, s_uuid = sorted_data[cur_start_idx]
                    edge_list.append({
                        "src": src, "dst": dst, "time": s_ts,
                        "label": s_op, "event_uuid": s_uuid,
                    })
                cur_op = op
                cur_start_idx = idx
            if cur_start_idx is not None:
                s_ts, s_op, s_uuid = sorted_data[cur_start_idx]
                edge_list.append({
                    "src": src, "dst": dst, "time": s_ts,
                    "label": s_op, "event_uuid": s_uuid,
                })
    else:
        for (
            src_node, src_index_id, operation, dst_node, dst_index_id,
            event_uuid, timestamp_rec, _id,
        ) in events_list:
            if src_index_id not in node_info:
                node_type, label = indexid2msg.get(src_index_id, ["subject", ""])
                node_info[src_index_id] = {"label": label, "node_type": node_type}
            if dst_index_id not in node_info:
                node_type, label = indexid2msg.get(dst_index_id, ["file", ""])
                node_info[dst_index_id] = {"label": label, "node_type": node_type}
            edge_list.append({
                "src": src_index_id, "dst": dst_index_id,
                "time": timestamp_rec, "label": operation, "event_uuid": event_uuid,
            })

    graph = nx.MultiDiGraph()
    for node, info in node_info.items():
        graph.add_node(node, node_type=info["node_type"], label=info["label"])
    for edge in edge_list:
        graph.add_edge(
            edge["src"], edge["dst"],
            event_uuid=edge["event_uuid"],
            time=edge["time"],
            label=edge["label"],
            y=0,
        )
    return graph


# ============================================================================
# 自写 ② single_graph_to_temporal_data
# from pids_attack/PIDSMaker/pidsmaker/tasks/feat_inference.py:25-84 (核心循环) +
#      pids_attack/PIDSMaker/pidsmaker/featurization/feat_inference_methods/feat_inference_word2vec.py:28-41 (OOV)
# 删除:读盘循环 / 写盘 / 全量 indexid2msg 遍历
# ============================================================================

def _emb_for_label_word2vec(label: str, node_type: str, w2v_model, emb_dim: int,
                            decline_percentage: float):
    """复制 feat_inference_word2vec.main line 28-41 单节点的处理。"""
    if PIDSMAKER_DIR not in sys.path:
        sys.path.insert(0, PIDSMAKER_DIR)
    import numpy as np
    from pidsmaker.utils.utils import tokenize_label

    tokens = tokenize_label(label, node_type)
    n = len(tokens)
    zeros = np.zeros((emb_dim,))
    if n == 0:
        return zeros

    # cal_word_weight (decline_percentage)
    d = -1 / n * decline_percentage / 100
    a_1 = 1 / n - 0.5 * (n - 1) * d
    weights = [a_1 + i * d for i in range(n)]

    word_vecs = [w2v_model.wv[w] if w in w2v_model.wv else zeros for w in tokens]
    weighted = [w * v for w, v in zip(weights, word_vecs)]
    sentence = np.mean(weighted, axis=0)
    return sentence / (np.linalg.norm(sentence) + 1e-12)


def single_graph_to_temporal_data(graph, indexid2vec, etype2oh, ntype2oh,
                                   oov_emb_fn, cfg):
    """nx 图 → CollatableTemporalData.

    indexid2vec: 训练时全量 emb 字典 (str index_id → np.array)
    etype2oh / ntype2oh: 训练时计算的 one-hot 字典(str → tensor)
    oov_emb_fn: 单节点 OOV → emb 的 callable(label, node_type) → np.array
    """
    if PIDSMAKER_DIR not in sys.path:
        sys.path.insert(0, PIDSMAKER_DIR)
    import numpy as np
    import torch
    from pidsmaker.utils.data_utils import CollatableTemporalData

    sorted_edges = list(graph.edges(data=True, keys=True))

    src_l, dst_l, msg_l, t_l, y_l = [], [], [], [], []
    for u, v, k, attr in sorted_edges:
        src_l.append(int(u))
        dst_l.append(int(v))
        t_l.append(int(attr["time"]))
        y_l.append(int(attr.get("y", 0)))

        if "label" in attr:
            edge_label = etype2oh[attr["label"]]
        else:
            edge_label = torch.zeros_like(etype2oh[next(iter(etype2oh))])

        u_node = graph.nodes[u]
        v_node = graph.nodes[v]
        u_type = u_node["node_type"]
        v_type = v_node["node_type"]

        # node embedding(训练时表 + OOV fallback)
        if indexid2vec is None:
            msg_l.append(torch.cat([
                ntype2oh[u_type],
                edge_label,
                ntype2oh[v_type],
            ]))
        else:
            u_vec = indexid2vec.get(str(u))
            if u_vec is None:
                u_vec = oov_emb_fn(u_node.get("label", ""), u_type)
            v_vec = indexid2vec.get(str(v))
            if v_vec is None:
                v_vec = oov_emb_fn(v_node.get("label", ""), v_type)
            msg_l.append(torch.cat([
                ntype2oh[u_type],
                torch.from_numpy(np.asarray(u_vec, dtype=np.float32)),
                edge_label,
                ntype2oh[v_type],
                torch.from_numpy(np.asarray(v_vec, dtype=np.float32)),
            ]))

    if not msg_l:
        return None

    return CollatableTemporalData(
        src=torch.tensor(src_l, dtype=torch.long),
        dst=torch.tensor(dst_l, dtype=torch.long),
        t=torch.tensor(t_l, dtype=torch.long),
        msg=torch.vstack(msg_l).to(torch.float),
        y=torch.tensor(y_l, dtype=torch.long),
    )


# ============================================================================
# 自写 ③ compute_detector_score
# from pids_attack/PIDSMaker/pidsmaker/detection/training_methods/inference_loop.py:99-244
# 删除:CSV 落盘 / time_interval 命名
# ============================================================================

def compute_detector_score(out: Dict[str, Any], data, cfg,
                           magic_train_distance: Optional[float] = None,
                           model=None) -> List[Dict[str, Any]]:
    """复制 inference_loop.test_node_level 的 4 个 detector 分支。

    严格按上游公式实现,不简化。magic 分支需要 model 参数以便调 model.embed(...) 取嵌入。
    """
    if PIDSMAKER_DIR not in sys.path:
        sys.path.insert(0, PIDSMAKER_DIR)
    import numpy as np
    import torch
    import torch.nn.functional as F

    loss = out["loss"]
    n_id = getattr(data, "original_n_id_tgn", None)
    if n_id is None:
        n_id = getattr(data, "original_n_id", None)
    if n_id is None:
        n_id = torch.arange(loss.numel(), dtype=torch.long)

    method = cfg.evaluation.node_evaluation.threshold_method
    node_list: List[Dict[str, Any]] = []

    if method == "threatrace":
        # 上游 inference_loop.py:104-132 — 严格复刻
        out_t = out["out"]
        pred = out_t.max(1)[1]
        pro = F.softmax(out_t, dim=1)
        pro1 = pro.max(1)
        for i in range(len(out_t)):
            pro[i][pro1[1][i]] = -1
        pro2 = pro.max(1)
        node_type_num = data.node_type.argmax(1)
        for i in range(len(out_t)):
            denom = pro2[0][i] if pro2[0][i] != 0 else 1e-5
            score = pro1[0][i] / denom
            score = torch.log(score + 1e-12)
            score = max(score.item(), 0)
            node_list.append({
                "node": int(n_id[i].item()),
                "loss": float(loss[i].item()),
                "threatrace_score": float(score),
                "correct_pred": int((node_type_num[i] == pred[i]).item()),
                "pred_type": int(pred[i].item()),
                "declared_type": int(node_type_num[i].item()),
            })

    elif method == "flash":
        # 上游 inference_loop.py:134-156 — 严格复刻(包括 batch normalize)
        out_t = out["out"]
        sorted_, _ = out_t.sort(dim=1, descending=True)
        eps = 1e-6
        conf = (sorted_[:, 0] - sorted_[:, 1]) / (sorted_[:, 0] + eps)
        if conf.max() > 0:
            conf = (conf - conf.min()) / conf.max()
        node_type_num = data.node_type.argmax(1)
        pred = out_t.max(1)[1]
        for i in range(len(out_t)):
            score = max(conf[i].item(), 0)
            node_list.append({
                "node": int(n_id[i].item()),
                "loss": float(loss[i].item()),
                "flash_score": float(score),
                "correct_pred": int((node_type_num[i] == pred[i]).item()),
            })

    elif method == "magic":
        # 上游 inference_loop.py:203-236 (test 分支) — 严格复刻 NearestNeighbors 流程
        if model is None:
            # 没传 model:fallback 到 raw loss / train_distance(精度有损,但不会崩)
            mtd = magic_train_distance if magic_train_distance else 1e-9
            for i in range(loss.numel()):
                node_id = int(n_id[i].item()) if i < len(n_id) else i
                node_list.append({
                    "node": node_id,
                    "loss": float(loss[i].item()),
                    "magic_score": float(loss[i].item()) / float(mtd),
                })
        else:
            from sklearn.neighbors import NearestNeighbors
            import pandas as pd
            mean_distance_train = magic_train_distance if magic_train_distance else 1e-9

            with torch.no_grad():
                x_emb, _, _ = model.embed(data, inference=True)
            x_test = x_emb.cpu().numpy()
            num_nodes = x_test.shape[0]
            sample_size = 5000 if num_nodes > 5000 else num_nodes
            sample_indices = np.random.choice(num_nodes, sample_size, replace=False)
            x_test_sampled = x_test[sample_indices]
            x_test_mean = x_test_sampled.mean(axis=0)
            x_test_std = x_test_sampled.std(axis=0)  # 跟 PIDSMaker 严格对齐(无 +1e-12 saneness guard)
            x_test_sampled = (x_test_sampled - x_test_mean) / x_test_std

            x_test_sampled_df = pd.DataFrame.from_records(x_test_sampled)
            n_neighbors = 10  # 跟 PIDSMaker line 220 一致(原来用了 min 兜底)
            nbrs = NearestNeighbors(n_neighbors=n_neighbors)
            nbrs.fit(x_test_sampled_df)

            # 全部 query 节点对照(没 sample 减少)
            distances, _ = nbrs.kneighbors(x_test, n_neighbors=n_neighbors)
            distances = distances.mean(axis=1)
            scores = (distances / float(mean_distance_train)).tolist()

            for i in range(loss.numel()):
                node_id = int(n_id[i].item()) if i < len(n_id) else i
                node_list.append({
                    "node": node_id,
                    "loss": float(loss[i].item()),
                    "magic_score": float(scores[i]) if i < len(scores) else 0.0,
                })

    else:
        # max_val_loss / nodlink / 默认:只看 loss
        # 判定 edge-level 还是 node-level:
        #   edge-level(orthrus/kairos predict_edge_type):loss.shape[0] == data.src.shape[0]
        #     → 镜像 PIDSMaker test_edge_level + get_node_predictions_edge_level:
        #       每个 edge 把 loss 分给 src(+ dst if use_dst_node_loss),per-node 聚合
        #   node-level(threatrace/flash/nodlink/rcaid/velox):loss.shape[0] == len(n_id)
        #     → 原 loop 直接 i 取 n_id[i] 和 loss[i]
        is_edge_level = (
            hasattr(data, "src")
            and data.src is not None
            and loss.numel() == data.src.shape[0]
            and loss.numel() != len(n_id)
        )
        if is_edge_level:
            # 用 original_edge_index(全局 ID) 而不是 data.src/dst(local reindex)
            edge_index = getattr(data, "original_edge_index", None)
            if edge_index is None:
                # fallback:用 data.src/dst + n_id 反查
                src_idx = data.src.cpu().tolist()
                dst_idx = data.dst.cpu().tolist()
                src_globals = [int(n_id[i].item()) for i in src_idx]
                dst_globals = [int(n_id[i].item()) for i in dst_idx]
            else:
                src_globals = edge_index[0, :].cpu().tolist()
                dst_globals = edge_index[1, :].cpu().tolist()

            use_dst = bool(getattr(
                cfg.evaluation.node_evaluation, "use_dst_node_loss", False
            ))
            node_max_loss: Dict[int, float] = {}
            for i in range(loss.numel()):
                edge_loss = float(loss[i].item())
                s = int(src_globals[i]); d = int(dst_globals[i])
                if s not in node_max_loss or edge_loss > node_max_loss[s]:
                    node_max_loss[s] = edge_loss
                if use_dst:
                    if d not in node_max_loss or edge_loss > node_max_loss[d]:
                        node_max_loss[d] = edge_loss
            for nid, ml in node_max_loss.items():
                node_list.append({"node": nid, "loss": ml})
        else:
            for i in range(loss.numel()):
                node_id = int(n_id[i].item()) if i < len(n_id) else i
                node_list.append({
                    "node": node_id,
                    "loss": float(loss[i].item()),
                })

    return node_list


# ============================================================================
# 自写 ④ apply_threshold
# 5 种 threshold method:max_val_loss / magic / flash / threatrace / nodlink
# ============================================================================

def _kmeans_top_k_labels(node_list: List[Dict[str, Any]], topk_K: int,
                         threshold_method: str) -> List[bool]:
    """镜像 PIDSMaker evaluation_utils.compute_kmeans_labels(单 SQL 版)。
    取每个 node 的 score → 排序拿后 topk_K → KMeans 2 簇 → 高均值簇标 1。"""
    import numpy as np
    from sklearn.cluster import KMeans

    def _score_of(nd):
        if threshold_method == "threatrace":
            return float(nd.get("threatrace_score", 0.0))
        if threshold_method == "flash":
            return float(nd.get("flash_score", 0.0))
        if threshold_method == "magic":
            return float(nd.get("magic_score", 0.0))
        return float(nd.get("loss", 0.0))

    scores = [_score_of(nd) for nd in node_list]
    n = len(node_list)
    k = min(topk_K, n)
    order = sorted(range(n), key=lambda i: scores[i])
    top_idx = order[-k:]
    top_scores = np.array([scores[i] for i in top_idx], dtype=float).reshape(-1, 1)
    out = [False] * n
    if k < 2:
        out[top_idx[-1]] = True
        return out
    km = KMeans(n_clusters=2, random_state=0, n_init=10).fit(top_scores)
    high_cluster = int(np.argmax(km.cluster_centers_.flatten()))
    for j, i in enumerate(top_idx):
        if km.labels_[j] == high_cluster:
            out[i] = True
    return out


def apply_threshold(node_list: List[Dict[str, Any]], threshold: float,
                    threshold_method: str) -> List[bool]:
    """node_list → list[bool] (y_pred per node)。

    严格按上游 node_evaluation.py:185-247 的判定逻辑:
      - threatrace / flash: score > thr AND correct_pred(预测的 node 类型 == 真实类型)
      - magic              : score > thr
      - max_val_loss/nodlink: loss > thr

    threshold 由训练侧 get_threshold(method) 算出,统一从 best_dir/threshold.pkl 读。
    threatrace 写死 1.5,flash 写死 0.53,magic = mean(val magic_scores),
    max_val_loss = max(val losses),nodlink = percentile_90(val losses)。
    """
    out: List[bool] = []
    if threshold_method == "threatrace":
        # Original ThreaTrace (IEEE TIFS'22): anomaly <=> (score < thr) OR (predicted_type != true_type)
        # i.e. low confidence OR wrong type-prediction => anomaly.
        for nd in node_list:
            score = nd.get("threatrace_score", 0.0)
            correct = nd.get("correct_pred", 0)
            out.append(bool(score < threshold or correct != 1))
    elif threshold_method == "flash":
        # Same confidence-based logic as threatrace.
        for nd in node_list:
            score = nd.get("flash_score", 0.0)
            correct = nd.get("correct_pred", 0)
            out.append(bool(score < threshold or correct != 1))
    elif threshold_method == "magic":
        for nd in node_list:
            out.append(bool(nd.get("magic_score", 0.0) > threshold))
    else:
        # max_val_loss / nodlink:loss > threshold
        for nd in node_list:
            out.append(bool(nd.get("loss", 0.0) > threshold))
    return out


# ============================================================================
# Engine
# ============================================================================

class PIDSMakerEngine:
    """单 detector 一个实例,真 forward inference。"""

    def __init__(self, detector_name: str, model_path: Optional[str] = None):
        self.detector_name = detector_name
        self.model_path = model_path
        self._loaded = False

    # -- internal: lazy load --

    def _ensure_loaded(self):
        if self._loaded:
            return
        if PIDSMAKER_DIR not in sys.path:
            sys.path.insert(0, PIDSMAKER_DIR)
        import torch
        import numpy as np
        from pidsmaker.factory import build_model
        from pidsmaker.tasks.batching import get_preprocessed_graphs
        from pidsmaker.utils.data_utils import (
            load_model,
            GraphReindexer,
        )
        from pidsmaker.utils.dataset_utils import get_node_map, get_rel2id
        from pidsmaker.utils.utils import gen_relation_onehot, get_device

        args = _build_args(self.detector_name)
        cfg = _get_yml_cfg_safe(args)
        device = get_device(cfg)

        train_data, val_data, test_data, max_node, neighbor_loader = (
            get_preprocessed_graphs(cfg)
        )

        sample = train_data[0][0]
        model = build_model(sample, device, cfg, max_node)
        best_dir = os.path.join(cfg.training._trained_models_dir, "best_model")
        load_model(model, best_dir, cfg)
        model.eval()

        # threshold(detector-specific)
        # 训练侧用 get_threshold(method) 算出来后存成 dict {"method": ..., "threshold": ...}
        # 同时兼容老 patch 存的 plain float / int。
        threshold_method = cfg.evaluation.node_evaluation.threshold_method
        thr_path = os.path.join(best_dir, "threshold.pkl")
        threshold = 0.0
        if os.path.exists(thr_path):
            loaded_thr = torch.load(thr_path)
            if isinstance(loaded_thr, dict):
                threshold = float(loaded_thr.get("threshold", 0.0))
                # method 以训练侧存的为准(更可信),但跟 cfg 不一致就 warn
                saved_method = loaded_thr.get("method")
                if saved_method and saved_method != threshold_method:
                    print(f"[pidsmaker_inference] WARN: threshold.pkl method "
                          f"{saved_method} != cfg method {threshold_method}; "
                          f"using cfg method")
            else:
                threshold = float(loaded_thr)

        # featurization 产物(query 间共享)
        rel2id = get_rel2id(cfg)
        ntype2id = get_node_map()
        etype2oh = gen_relation_onehot(rel2id=rel2id)
        ntype2oh = gen_relation_onehot(rel2id=ntype2id)

        indexid2vec = self._load_indexid2vec(cfg)

        # OOV emb function(method-dependent)
        oov_emb_fn = self._build_oov_emb_fn(cfg)

        # Magic 需要 train_distance —— training_loop 训完会拷一份到 best_dir,
        # 优先从 best_dir 读(独立于 PIDSMaker 工作目录),fallback 到上游写入位置。
        magic_train_distance = None
        if threshold_method == "magic":
            train_dist_candidates = [
                os.path.join(best_dir, "train_distance.txt"),  # mimicattack copy
            ]
            magic_dir = getattr(cfg.training, "_magic_dir", None)
            if magic_dir:
                train_dist_candidates.append(os.path.join(magic_dir, "train_distance.txt"))
            for cand in train_dist_candidates:
                if os.path.exists(cand):
                    with open(cand) as f:
                        vals = [float(x) for x in f.read().split() if x.strip()]
                    magic_train_distance = sum(vals) / len(vals) if vals else None
                    if magic_train_distance:
                        break

        # Reindexer + max_node 用训练时的
        reindexer = GraphReindexer(
            device=device,
            num_nodes=max_node,
            fix_buggy_graph_reindexer=cfg.batching.fix_buggy_graph_reindexer,
        )

        self._cfg = cfg
        self._device = device
        self._max_node = max_node
        self._neighbor_loader = neighbor_loader
        self._reindexer = reindexer
        self._model = model
        self._threshold = threshold
        self._threshold_method = threshold_method
        # orthrus 用 use_kmeans=True 在 eval 阶段把 threshold compare 覆盖 ——
        # 推理这边也得镜像同样逻辑,否则 orthrus 永远报 0(eval 上 F1=0.29 vs 推理 0)。
        self._use_kmeans = bool(getattr(cfg.evaluation.node_evaluation, "use_kmeans", False) or False)
        _topk = getattr(cfg.evaluation.node_evaluation, "kmeans_top_K", None)
        self._kmeans_top_K = int(_topk) if _topk else 30
        self._etype2oh = etype2oh
        self._ntype2oh = ntype2oh
        self._indexid2vec = indexid2vec
        self._oov_emb_fn = oov_emb_fn
        self._magic_train_distance = magic_train_distance
        self._cached_test_sample = (
            test_data[0][0] if test_data and test_data[0] else sample
        )
        self._cached_val_sample = (
            val_data[0][0] if val_data and val_data[0] else sample
        )

        self._loaded = True

    @staticmethod
    def _load_indexid2vec(cfg):
        """method-specific:加载训练时的 indexid2vec。"""
        if PIDSMAKER_DIR not in sys.path:
            sys.path.insert(0, PIDSMAKER_DIR)
        method = cfg.featurization.used_method.strip()
        if method in ("only_type", "only_ones", "magic"):
            return None
        if method == "word2vec":
            from pidsmaker.featurization.feat_inference_methods import feat_inference_word2vec
            return feat_inference_word2vec.main(cfg)
        if method == "fasttext":
            from pidsmaker.featurization.feat_inference_methods import feat_inference_fasttext
            return feat_inference_fasttext.main(cfg)
        if method == "alacarte":
            from pidsmaker.featurization.feat_inference_methods import feat_inference_alacarte
            return feat_inference_alacarte.main(cfg)
        if method == "doc2vec":
            from pidsmaker.featurization.feat_inference_methods import feat_inference_doc2vec
            return feat_inference_doc2vec.main(cfg)
        if method == "hierarchical_hashing":
            from pidsmaker.featurization.feat_inference_methods import feat_inference_HFH
            return feat_inference_HFH.main(cfg)
        if method == "temporal_rw":
            from pidsmaker.featurization.feat_inference_methods import feat_inference_TRW
            return feat_inference_TRW.main(cfg)
        if method == "flash":
            from pidsmaker.featurization.feat_inference_methods import feat_inference_flash
            return feat_inference_flash.main(cfg)
        return None

    @staticmethod
    def _build_oov_emb_fn(cfg):
        """method-specific:OOV 节点的 label → emb。"""
        if PIDSMAKER_DIR not in sys.path:
            sys.path.insert(0, PIDSMAKER_DIR)
        import numpy as np
        method = cfg.featurization.used_method.strip()
        emb_dim = cfg.featurization.emb_dim or 0

        if method == "word2vec":
            from gensim.models import Word2Vec
            model_path = cfg.featurization._model_dir + "word2vec.model"
            try:
                w2v = Word2Vec.load(model_path)
                decline = cfg.featurization.word2vec.decline_rate
                return lambda label, ntype: _emb_for_label_word2vec(
                    label, ntype, w2v, emb_dim, decline
                )
            except FileNotFoundError:
                return lambda label, ntype: np.zeros((emb_dim,))
        if method == "fasttext":
            try:
                from gensim.models.fasttext import load_facebook_model
                ft_path = cfg.featurization._model_dir + "fasttext.bin"
                if os.path.exists(ft_path):
                    ft = load_facebook_model(ft_path)
                    return lambda label, ntype: ft.wv[label] if label else np.zeros((emb_dim,))
            except Exception:
                pass
            return lambda label, ntype: np.zeros((emb_dim,))
        # default OOV: zero
        return lambda label, ntype: np.zeros((emb_dim,))

    # -- public --

    def predict(self, sql_path: str) -> int:
        """真 forward predict:δ 改 → events 改 → forward 输出改 → y 可能翻转。

        Raw graph-summary helper:整条对齐 PIDSMaker eval 的 pipeline 全部在 predict_per_node。
        Attack/E0/E3 的论文口径不直接用这个函数,而是在 pidsmaker_wrapper
        里用 scenario.gt_keywords 过滤 GT/attack nodes。
        any(y_pred==1) → y=1,否则 0。
        """
        nodes = self.predict_per_node(sql_path)
        return 1 if any(nd["y_pred"] == 1 for nd in nodes) else 0

    def predict_with_score(self, sql_path: str):
        y = self.predict(sql_path)
        return y, float(y)

    def predict_per_node(self, sql_path: str) -> List[Dict[str, Any]]:
        """跟 predict() 走同一条 forward,但暴露每个 node 的 (label, y_pred, score).

        返回: [{"node": int_index_id, "label": str, "y_pred": 0|1, "score": float}, ...]
        node 是 SQL 原始 index_id(eval 那侧是 DB 全局 index_id,跟这里不同),
        对齐时请用 label 而不是 node ID。
        """
        self._ensure_loaded()
        try:
            with open(sql_path, "r", encoding="utf-8", errors="ignore") as f:
                sql_text = f.read()
        except Exception:
            return []
        if not sql_text.strip():
            return []

        events, indexid2msg = parse_sql_to_events_and_nodes(sql_text, self._cfg)
        if not events:
            return []

        graph = cdm_to_nx_graph(events, indexid2msg, self._cfg)
        if graph.number_of_edges() == 0:
            return []

        if PIDSMAKER_DIR not in sys.path:
            sys.path.insert(0, PIDSMAKER_DIR)
        from pidsmaker.tasks.transformation import apply_graph_transformations
        methods = [m.strip() for m in self._cfg.transformation.used_methods.split(",")]
        graph = apply_graph_transformations(graph, methods, self._cfg)

        data = single_graph_to_temporal_data(
            graph, self._indexid2vec, self._etype2oh, self._ntype2oh,
            self._oov_emb_fn, self._cfg,
        )
        if data is None:
            return []

        from pidsmaker.utils.data_utils import (
            extract_msg_from_data, compute_tgn_graphs, get_full_data, reindex_graphs,
        )
        data_list = extract_msg_from_data([data], self._cfg)
        data = data_list[0]

        if not self._is_tgn():
            reindex_graphs(
                [[[data]]],
                self._reindexer,
                self._device,
                use_tgn=False,
                x_is_tuple=self._cfg.training.encoder.x_is_tuple,
            )

        if self._is_tgn():
            full_data = get_full_data([[[data]]])
            tgn_cfg = self._cfg.batching.intra_graph_batching.tgn_last_neighbor
            query_max = max(int(max(data.src.tolist() + data.dst.tolist())) + 1, 16)
            datasets, _ = compute_tgn_graphs(
                datasets=[[[data]]],
                full_data=full_data,
                graph_reindexer=self._reindexer,
                device=self._device,
                max_node=query_max,
                tgn_loader_cfg=tgn_cfg,
                node_feat_dim=data.x_src.shape[1],
                node_type_dim=data.node_type_src.shape[1],
            )
            data = datasets[0][0][0]

        import torch
        data = data.to(self._device)
        if hasattr(self._model, "reset_state"):
            self._model.reset_state()
        with torch.no_grad():
            out = self._model(data, inference=True, validation=False)

        node_list = compute_detector_score(
            out, data, self._cfg,
            magic_train_distance=self._magic_train_distance,
            model=self._model,
        )
        if not node_list:
            return []

        thr = float(self._threshold) if self._threshold is not None else 0.0
        y_preds = apply_threshold(node_list, thr, self._threshold_method)
        if self._use_kmeans and len(node_list) >= 2:
            y_preds = _kmeans_top_k_labels(node_list, self._kmeans_top_K, self._threshold_method)

        def _score_field(nd):
            if self._threshold_method == "threatrace":
                return float(nd.get("threatrace_score", 0.0))
            if self._threshold_method == "flash":
                return float(nd.get("flash_score", 0.0))
            if self._threshold_method == "magic":
                return float(nd.get("magic_score", 0.0))
            return float(nd.get("loss", 0.0))

        out_list = []
        for nd, yp in zip(node_list, y_preds):
            nid = int(nd["node"])
            label_pair = indexid2msg.get(str(nid))
            label = label_pair[1] if label_pair else ""
            out_list.append({
                "node_index_id": nid,
                "label": label,
                "y_pred": int(bool(yp)),
                "score": _score_field(nd),
                "correct_pred": int(nd.get("correct_pred", -1)),
                "pred_type": int(nd.get("pred_type", -1)),
                "declared_type": int(nd.get("declared_type", -1)),
            })
        return out_list

    # -- helpers --

    def _is_tgn(self) -> bool:
        if PIDSMAKER_DIR not in sys.path:
            sys.path.insert(0, PIDSMAKER_DIR)
        from pidsmaker.encoders import TGNEncoder
        return isinstance(getattr(self._model, "encoder", None), TGNEncoder)


# ============================================================================
# Public API:_LocalDetector + SUPPORTED_DETECTORS
# (从 train_pidsmaker.py 挪过来 —— 这俩是 STAGE 6 推理用的)
# ============================================================================

SUPPORTED_DETECTORS = (
    "orthrus", "kairos", "magic", "flash",
    "threatrace", "nodlink", "rcaid", "velox",
)


class _LocalDetector:
    """In-A_Study_Stage detector wrapper(无 daemon / 无 RPC)。

    每个 detector 只起一个 PIDSMakerEngine,跨 _LocalDetector 实例共享(class-level cache)。
    第一次 predict 触发 lazy load,后续复用 in-memory model。
    """
    _engines: Dict[str, "PIDSMakerEngine"] = {}  # detector_name -> PIDSMakerEngine

    def __init__(self, detector_name: str, model_path: Optional[str] = None):
        if detector_name not in SUPPORTED_DETECTORS:
            raise ValueError(
                f"unknown detector {detector_name}, "
                f"supported: {SUPPORTED_DETECTORS}"
            )
        self.detector_name = detector_name
        self.model_path = model_path  # 兼容老接口

    def _get_engine(self) -> "PIDSMakerEngine":
        if self.detector_name not in self._engines:
            self._engines[self.detector_name] = PIDSMakerEngine(
                detector_name=self.detector_name,
                model_path=self.model_path,
            )
        return self._engines[self.detector_name]

    def predict(self, cdm_dump_sql: str) -> int:
        return int(self._get_engine().predict(cdm_dump_sql))

    def predict_with_score(self, cdm_dump_sql: str):
        """兼容老接口,返回 (y, score)。score 用 y 占位(B 路径只暴露 0/1)。"""
        y = self.predict(cdm_dump_sql)
        return y, float(y)

    def predict_per_node(self, cdm_dump_sql: str) -> List[Dict[str, Any]]:
        return self._get_engine().predict_per_node(cdm_dump_sql)


# ============================================================================
# PIDSMaker eval adapter
# ============================================================================

"""eval_pidsmaker.py — 看 PIDSMaker 自己原始 evaluation 真实检测结果。

跟 `train_pidsmaker.py` 对称:
- train_pidsmaker.py train_all     → 训 8 detector
- eval_pidsmaker.py(此文件)        → 读 PIDSMaker 自己 evaluation pkl,看真实 metrics

所有数字都是 **PIDSMaker 训练 + evaluation 阶段自己计算并落盘的**,
跟 mimicattack 的 query SQL / 路由 / detection 规则 0 关系。

用法:
    python scripts/run.py detect eval-gnn                          # 8 detector 全测
    python scripts/run.py detect eval-gnn orthrus                  # 单 detector
    python scripts/run.py detect eval-gnn flash rcaid velox        # 多 detector
"""
import glob
import os
import re
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)


PIDSMAKER_DIR = os.environ.get(
    "PIDSMAKER_DIR",
    os.path.join(PROJECT_ROOT, "PIDSMaker"),
)
ARTIFACT_DIR = os.environ.get(
    "PIDSMAKER_ARTIFACT_DIR",
    os.path.join(PROJECT_ROOT, "detection", "data", "pidsmaker_artifacts"),
)

if PIDSMAKER_DIR not in sys.path:
    sys.path.insert(0, PIDSMAKER_DIR)

# JUICESHOP attack scenario 顺序(对齐 PIDSMaker config.py:DATASET_DEFAULT_CONFIG['JUICESHOP'])
SCENARIO_LIST = (
    "juiceshop_basket_idor",
    "juiceshop_db_schema_union_sqli",
    "juiceshop_directory_listing_ftp",
    "juiceshop_exposed_metrics",
    "juiceshop_login_admin_sqli",
    "juiceshop_login_bender_sqli",
    "juiceshop_login_jim_sqli",
    "juiceshop_redirect_open",
    "juiceshop_register_admin_mass_assignment",
    "juiceshop_weak_password_admin",
)


def _build_args(detector_name: str):
    from pidsmaker.config.pipeline import get_runtime_required_args
    return get_runtime_required_args(args=[
        detector_name, "JUICESHOP", "--cpu",
        "--database_host", DB_HOST,
        "--database_user", DB_USER, "--database_password", DB_PASSWORD,
        "--database_port", str(DB_PORT),
        "--artifact_dir", str(ARTIFACT_DIR),
    ])


def load_eval_pkl(detector_name: str):
    """读 PIDSMaker 训练时落盘的 evaluation pkl(最后一个 epoch)。"""
    import torch
    cfg = _get_yml_cfg_safe(_build_args(detector_name))
    pr_dir = cfg.evaluation._precision_recall_dir
    if not os.path.isdir(pr_dir):
        return None, None
    pkls = sorted(
        glob.glob(os.path.join(pr_dir, "scores_model_epoch_*.pkl")),
        key=lambda p: int(re.search(r"_epoch_(\d+)", p).group(1)),
    )
    if not pkls:
        return None, None
    latest_pkl = pkls[-1]
    return torch.load(latest_pkl), latest_pkl


def compute_metrics(eval_data: dict) -> dict:
    """从 PIDSMaker 落盘的 eval pkl 算 TP / FP / FN / TN / precision / recall / f1。"""
    yp = list(eval_data.get("y_preds", []))
    yt = list(eval_data.get("y_truth", []))
    n2a = eval_data.get("node2attacks", {}) or {}
    nodes = eval_data.get("nodes", [])

    tp = sum(1 for p, t in zip(yp, yt) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(yp, yt) if p == 1 and t == 0)
    fn = sum(1 for p, t in zip(yp, yt) if p == 0 and t == 1)
    tn = sum(1 for p, t in zip(yp, yt) if p == 0 and t == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # per-scenario 4 项拆:
    #   GT  = 该 scenario 下真实 attack 节点数(y_truth=1 且节点属于该 scenario)
    #   TP  = 该 scenario 下被 PIDSMaker 命中的(y_truth=1 且 y_pred=1 且属于该 scenario)
    #   FN  = 该 scenario 下漏报的(y_truth=1 且 y_pred=0 且属于该 scenario)= GT - TP
    #   FP  = 跟这个 scenario "无关" 的节点被错报(y_truth=0 且 y_pred=1)。
    #         注:FP 节点不属于任何 attack scenario,所以 per-scenario 的 FP 拆不出来,
    #         统一作整体 FP(放在汇总行)。
    sc_tp = {}
    sc_gt = {}
    for i, node_id in enumerate(nodes):
        attacks = n2a.get(node_id, set()) or set()
        if not attacks:
            continue
        is_pred_pos = i < len(yp) and yp[i]
        is_truth_pos = i < len(yt) and yt[i]
        for sc in attacks:
            if is_truth_pos:
                sc_gt[sc] = sc_gt.get(sc, 0) + 1
            if is_pred_pos and is_truth_pos:
                sc_tp[sc] = sc_tp.get(sc, 0) + 1

    return {
        "n_nodes": len(yp),
        "yp_sum": sum(yp),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "gt_attack": tp + fn,
        "precision": precision, "recall": recall, "f1": f1,
        "scenario_tp": sc_tp,
        "scenario_gt": sc_gt,
    }


def print_detector(detector_name: str, all_results: dict = None):
    """打印一个 detector 的完整 detail;若 all_results 提供,顺手把指标存进去给汇总表用。"""
    eval_data, pkl_path = load_eval_pkl(detector_name)

    print()
    print(f"┌{'─'*78}┐")
    print(f"│ {detector_name:<76} │")
    print(f"└{'─'*78}┘")

    if eval_data is None:
        print(f"  ✗ 没找到 evaluation pkl")
        print(f"    先训:python scripts/run.py detect train-gnn")
        print(f"    或:  python pids_attack/PIDSMaker/pidsmaker/main.py {detector_name} JUICESHOP --cpu ...")
        if all_results is not None:
            all_results[detector_name] = None
        return

    m = compute_metrics(eval_data)
    n_detected = len(m["scenario_tp"])
    # 全局 precision 当作 per-scenario precision 近似(FP 不能拆 scenario,所以共用)
    P = m["precision"]

    print(f"  pkl       {pkl_path}")
    print()
    print(f"  整体指标")
    print(f"    总节点          {m['n_nodes']:>8}")
    print(f"    GT attack 节点  {m['gt_attack']:>8}")
    print(f"    PIDSMaker 标 attack(yp_sum)  {m['yp_sum']:>8}")
    print(f"    TP / FP / FN / TN   {m['tp']:>5} / {m['fp']:>5} / {m['fn']:>5} / {m['tn']:>5}")
    print(f"    Precision       {m['precision']:>8.4f}")
    print(f"    Recall          {m['recall']:>8.4f}")
    print(f"    F1              {m['f1']:>8.4f}")
    print()
    print(f"  10 个 scenario 各自(TP / FN / GT / recall / F1*)")
    print(f"    * F1 用 per-scenario recall × 全局 Precision = {P:.4f} 算(FP 跨 scenario 无法拆)")
    sum_tp = 0
    sum_fn = 0
    sum_gt = 0
    for idx, sid in enumerate(SCENARIO_LIST):
        n_tp = m["scenario_tp"].get(idx, 0)
        n_gt = m["scenario_gt"].get(idx, 0)
        n_fn = n_gt - n_tp
        sc_recall = (n_tp / n_gt) if n_gt > 0 else 0.0
        sc_f1 = (2 * P * sc_recall / (P + sc_recall)) if (P + sc_recall) > 0 else 0.0
        mark = "✓" if n_tp > 0 else "✗"
        print(f"    {mark} [{idx}] {sid:<42} "
              f"TP={n_tp:>5}  FN={n_fn:>5}  GT={n_gt:>5}  "
              f"recall={sc_recall:>6.3f}  F1={sc_f1:>6.3f}")
        sum_tp += n_tp
        sum_fn += n_fn
        sum_gt += n_gt
    print(f"    {'─'*102}")
    sum_recall = (sum_tp / sum_gt) if sum_gt > 0 else 0.0
    sum_f1 = (2 * P * sum_recall / (P + sum_recall)) if (P + sum_recall) > 0 else 0.0
    print(f"      合计(各 scenario 累加,跨 scenario 节点重复计数):")
    print(f"        TP_sum={sum_tp:>5}  FN_sum={sum_fn:>5}  GT_sum={sum_gt:>5}  "
          f"recall={sum_recall:>6.3f}  F1={sum_f1:>6.3f}")
    print(f"      整体(节点级,跨 scenario 去重):")
    print(f"        TP={m['tp']:>5}  FP={m['fp']:>5}  FN={m['fn']:>5}  TN={m['tn']:>5}    "
          f"FP 是 PIDSMaker 误报的 benign 节点(不归任何 attack scenario)")
    print()
    summary_mark = "✓" if n_detected == 10 and m["tp"] > 0 else "✗"
    print(f"  汇总  {summary_mark}  {n_detected}/10 个 scenario 被 PIDSMaker 检测到")

    if all_results is not None:
        all_results[detector_name] = {
            **m,
            "n_detected_scenarios": n_detected,
        }


def print_comparison_table(all_results: dict, detector_order: list):
    """横向对比表:每行一个 detector,列出关键指标。"""
    print()
    print(f"━{'━'*108}")
    print(f"  汇总对比表({len([d for d, m in all_results.items() if m]) }/{len(detector_order)} 个 detector 有结果)")
    print(f"━{'━'*108}")
    header = f"  {'detector':<12} {'n_node':>7} {'GT':>5} {'yp_sum':>7} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5} {'Prec':>7} {'Recall':>7} {'F1':>7} {'sc/10':>6}"
    print(header)
    print(f"  {'─'*108}")
    # 按 F1 降序,F1 都 0 时按 recall 降序
    rows = []
    for d in detector_order:
        m = all_results.get(d)
        if m is None:
            rows.append((d, None))
        else:
            rows.append((d, m))
    rows.sort(key=lambda r: (
        r[1]["f1"] if r[1] else -1,
        r[1]["recall"] if r[1] else -1,
    ), reverse=True)
    for d, m in rows:
        if m is None:
            print(f"  {d:<12} {'(no eval pkl)':<60}")
            continue
        mark = ""
        if m["f1"] >= 0.5:
            mark = "✓"
        elif m["f1"] > 0:
            mark = "△"
        else:
            mark = "✗"
        print(
            f"  {d:<12} "
            f"{m['n_nodes']:>7} {m['gt_attack']:>5} {m['yp_sum']:>7} "
            f"{m['tp']:>5} {m['fp']:>5} {m['fn']:>5} {m['tn']:>5} "
            f"{m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f} "
            f"{m['n_detected_scenarios']:>2}/10 {mark}"
        )
    print(f"  {'─'*108}")
    print(f"  排序按 F1 降序;✓ F1≥0.5  △ F1>0  ✗ F1=0")


def eval_main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        targets = list(SUPPORTED_DETECTORS)
    else:
        bad = [d for d in args if d not in SUPPORTED_DETECTORS]
        if bad:
            print(f"unknown detector(s): {bad}")
            print(f"supported: {list(SUPPORTED_DETECTORS)}")
            sys.exit(1)
        targets = args

    print()
    print(f"━{'━'*78}")
    print(f"  PIDSMaker 原始 evaluation 真实检测结果({len(targets)} detector × JUICESHOP)")
    print(f"  数据来源: cfg.evaluation._precision_recall_dir/scores_model_epoch_<N>.pkl")
    print(f"━{'━'*78}")

    all_results: dict = {}
    for d in targets:
        print_detector(d, all_results=all_results)
    print()

    # 多 detector 时打横向对比表
    if len(targets) >= 2:
        print_comparison_table(all_results, targets)
        print()




# ============================================================================
# PIDSMaker train adapter
# ============================================================================

#!/usr/bin/env python3
"""train_pidsmaker.py — 一键训练 8 个 PIDSMaker detector(灌库 + 清 cache + 训 + eval)。

流程:
  Step 1.  打印 dataset 划分(train_dates / val_dates / test_dates / GT 来源)
  Step 2.  (可选)灌库 — 调 `python -m data_prep.juiceshop`
  Step 3.  (可选)清训练 cache(construction / transformation / ... / evaluation 全清)
  Step 4.  N detector 全训(每个走 PIDSMaker 完整 pipeline)
  Step 5.  (可选)跑 scripts/run.py detect eval-gnn 出真实指标矩阵

用法:
  python scripts/run.py detect train-gnn                          # 全套(默认 8 detector)
  python scripts/run.py detect train-gnn --skip-ingest            # 跳过灌库,只重训
  python scripts/run.py detect train-gnn --skip-clean             # 跳过清 cache(增量训练)
  python scripts/run.py detect train-gnn --skip-eval              # 训完不跑 eval 报告
  python scripts/run.py detect train-gnn -d orthrus kairos        # 只训指定 detector

跟推理代码解耦 ——
  推理类 `_LocalDetector` / `SUPPORTED_DETECTORS` 在 detection/pidsmaker.py
"""
import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PIDSMAKER_DIR = Path(os.environ.get(
    "PIDSMAKER_DIR",
    str(PROJECT_ROOT / "PIDSMaker"),
))
ARTIFACT_DIR = Path(os.environ.get(
    "PIDSMAKER_ARTIFACT_DIR",
    str(PROJECT_ROOT / "detection" / "data" / "pidsmaker_artifacts"),
))

ALL_DETECTORS = [
    "orthrus", "kairos", "magic", "flash",
    "threatrace", "nodlink", "rcaid", "velox",
]

# 跟 detection/data_prep.py 对齐
TRAIN_DATES = ["2026-01-01", "2026-01-02", "2026-01-03"]
VAL_DATES = ["2026-01-04"]
TEST_DATES = ["2026-01-05", "2026-01-06"]
ATTACK_TO_DATE = [
    ("juiceshop_basket_idor", "2026-01-05"),
    ("juiceshop_db_schema_union_sqli", "2026-01-06"),
    ("juiceshop_directory_listing_ftp", "2026-01-05"),
    ("juiceshop_exposed_metrics", "2026-01-06"),
    ("juiceshop_login_admin_sqli", "2026-01-05"),
    ("juiceshop_login_bender_sqli", "2026-01-06"),
    ("juiceshop_login_jim_sqli", "2026-01-05"),
    ("juiceshop_redirect_open", "2026-01-06"),
    ("juiceshop_register_admin_mass_assignment", "2026-01-05"),
    ("juiceshop_weak_password_admin", "2026-01-06"),
]


def banner(title: str, char: str = "═") -> None:
    print()
    print(char * 80)
    print(f"  {title}")
    print(char * 80)


# ============================================================================
# Step 1:数据集划分概览
# ============================================================================

def step_print_dataset_overview(args):
    banner("Step 1/5 · 数据集划分(JUICESHOP)")
    traces_dir = PROJECT_ROOT / "detection" / "data" / "training_traces"
    benign_files = sorted(traces_dir.glob("benign_*.sql")) or [traces_dir / "benign.sql"]
    attack_dir = traces_dir / "attack"
    gt_dir = PIDSMAKER_DIR / "Ground_Truth/orthrus/JUICESHOP"

    print(f"  原始数据源:")
    print(f"    benign:    {len(benign_files)} 份 SQL ({benign_files[0].parent}/benign*.sql)")
    print(f"    attack:    {attack_dir}/*.strace.sql ({len(list(attack_dir.glob('*.strace.sql')))} 个 scenario)")
    print(f"    ground_truth: {gt_dir}/*.csv")
    print()
    print(f"  Fake-date 切片:")
    print(f"    train_dates  ({len(TRAIN_DATES)} 天):     {TRAIN_DATES}   ← 模型训练数据,纯 benign")
    print(f"    val_dates    ({len(VAL_DATES)} 天):       {VAL_DATES}      ← 验证 + 计算 threshold,纯 benign")
    print(f"    test_dates   ({len(TEST_DATES)} 天):      {TEST_DATES}   ← attack scenario 全在这")
    print()
    print(f"  10 个 attack scenario 在 test 集的分布:")
    for sid, date in ATTACK_TO_DATE:
        print(f"    {sid:<48} → {date}")
    print()
    print(f"  ⚠ 训练 = train_dates(纯 benign),用 self-supervised 学 benign 长啥样")
    print(f"  ⚠ 阈值 = max(val_dates 的 loss)(还是纯 benign,这是 benign 上限)")
    print(f"  ⚠ 检测 = test_dates 中谁 loss 超阈值就报 attack(无监督)")


# ============================================================================
# Step 2:灌库(调 data_prep.juiceshop)
# ============================================================================

def step_ingest(args):
    if args.skip_ingest:
        banner("Step 2/5 · 灌库(--skip-ingest 跳过)")
        return
    banner("Step 2/5 · 灌库 + 写 ground truth(调 data_prep.juiceshop)")

    # 前置检查:benign SQL 必须存在(否则灌进去是空 DB,训练全废)
    traces_dir = PROJECT_ROOT / "detection" / "data" / "training_traces"
    benign_files = sorted(traces_dir.glob("benign_*.sql"))
    if not benign_files:
        single = traces_dir / "benign.sql"
        benign_files = [single] if single.exists() else []
    if not benign_files:
        print(f"  [FAIL] 找不到任何 benign SQL(检查路径 {traces_dir}/benign*.sql)")
        print(f"  先跑:python scripts/run.py detect collect-benign --num-collections 30 --parallel 4")
        sys.exit(1)
    print(f"  [check] {len(benign_files)} 份 benign SQL OK")

    cmd = ["python", "-m", "detection.data_prep",
           "--user", "pids", "--password", "pids"]
    cp = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if cp.returncode != 0:
        print(f"  [FAIL] ingest 失败 returncode={cp.returncode}")
        sys.exit(1)
    print(f"  [done]")


# ============================================================================
# Step 3:清 cache
# ============================================================================

def step_clean_cache(args):
    if args.skip_clean:
        banner("Step 3/5 · 清 cache(--skip-clean 跳过)")
        return
    banner("Step 3/5 · 清 PIDSMaker cache(forces re-construction + re-training)")
    targets = ["construction", "transformation", "featurization",
               "feat_inference", "batching", "training", "evaluation"]
    for t in targets:
        path = ARTIFACT_DIR / t
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            print(f"  rm  {path}")
    print(f"  [done]")


# ============================================================================
# Step 4:训练 N detector
# ============================================================================

def _load_metrics_for(detector_name):
    """训完立即从 eval pkl 抽 P/R/F1 给一行汇总。"""
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        eval_data, _ = load_eval_pkl(detector_name)
        if eval_data is None:
            return None
        return compute_metrics(eval_data)
    except Exception:
        return None


def step_train(args, detectors):
    banner(f"Step 4/5 · 训练 detectors ({len(detectors)} 个,sequential)")
    failed = []
    summaries = {}  # detector → metrics dict(给末尾对比表用)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PIDSMAKER_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    for d in detectors:
        print()
        print(f"  ──── {d} ────")
        t0 = time.time()
        cp = subprocess.run(
            ["python", "-u", "pidsmaker/main.py", d, "JUICESHOP", "--cpu",
             "--database_host", "localhost",
             "--database_user", "pids", "--database_password", "pids",
             "--database_port", "5432",
             "--artifact_dir", str(ARTIFACT_DIR)],
            cwd=str(PIDSMAKER_DIR),
            env=env,
            capture_output=True, text=True,
        )
        elapsed = int(time.time() - t0)
        out = cp.stdout + cp.stderr
        for line in out.splitlines():
            if any(kw in line for kw in (
                "Train num graphs", "Val num graphs", "Test num graphs",
                "Run finished", "Traceback", "Error",
            )):
                print(f"    {line.strip()}")
        ok = "Run finished" in out and cp.returncode == 0
        status = "✓" if ok else "✗"
        # 训完立刻抽 eval pkl 出一行带指标(失败的不抽)
        metrics_line = ""
        if ok:
            m = _load_metrics_for(d)
            if m is not None:
                summaries[d] = m
                metrics_line = (
                    f"  TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}"
                    f"  P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f}"
                )
        print(f"  [{status}] {d} 耗时 {elapsed}s{metrics_line}")
        if not ok:
            failed.append(d)

    if failed:
        print()
        print(f"  ⚠ 失败 detector:{failed}")

    # 不在 step_train 末尾打汇总对比表(step_eval 会调 eval_pidsmaker.py 出完整版)。
    # 如果跑了 --skip-eval,想看汇总:`python scripts/run.py detect eval-gnn`
    return failed


# ============================================================================
# Step 5:eval 报告(可选)
# ============================================================================

def step_eval(args, detectors):
    if args.skip_eval:
        banner("Step 5/5 · eval 报告(--skip-eval 跳过)")
        return
    banner("Step 5/5 · PIDSMaker 真实指标报告(scripts/run.py detect eval-gnn)")
    try:
        eval_main(list(detectors))
    except Exception as exc:
        print(f"  [warn] eval failed: {exc}")


# ============================================================================
# Main
# ============================================================================

def train_main(argv=None):
    p = argparse.ArgumentParser(
        description="一键训练 8 detector(灌库 + 清 cache + 训 + eval)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--skip-ingest", action="store_true", help="跳过灌库步骤(用现有 db)")
    p.add_argument("--skip-clean", action="store_true", help="跳过清 cache(增量训练)")
    p.add_argument("--skip-eval", action="store_true", help="跳过最后的 eval 报告")
    p.add_argument("-d", "--detectors", nargs="+", default=ALL_DETECTORS,
                   choices=ALL_DETECTORS, metavar="DETECTOR",
                   help=f"只训这几个 detector(默认全 8 个;可选 {ALL_DETECTORS})")
    args = p.parse_args(argv)

    banner("train_pidsmaker.py", char="━")
    print(f"  PROJECT_ROOT     = {PROJECT_ROOT}")
    print(f"  PIDSMAKER_DIR    = {PIDSMAKER_DIR}")
    print(f"  ARTIFACT_DIR     = {ARTIFACT_DIR}")
    print(f"  detectors        = {args.detectors}")
    print(f"  skip_ingest      = {args.skip_ingest}")
    print(f"  skip_clean       = {args.skip_clean}")
    print(f"  skip_eval        = {args.skip_eval}")

    step_print_dataset_overview(args)
    step_ingest(args)
    step_clean_cache(args)
    failed = step_train(args, args.detectors)
    success = [d for d in args.detectors if d not in failed]
    if success:
        step_eval(args, success)

    banner("✓ train_pidsmaker.py 完成", char="━")





def main(argv=None):
    """Debug dispatcher. Public entry is scripts/run.py detect ..."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "train":
        return train_main(argv[1:])
    if argv and argv[0] == "eval":
        return eval_main(argv[1:])
    print("usage: python -m detection.pidsmaker [train|eval] ...")
    print("public: python scripts/run.py detect [train-gnn|eval-gnn] ...")
    return None


if __name__ == "__main__":
    main()
