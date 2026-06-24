"""
Evaluate D2 (LOLBin single-responsibility violation) as a standalone
anomaly detector against the full test set + 191 adversarial graphs.

D2 rule:
  exists ProcessNode p in graph such that:
    name(p) in LOLBin pool
    AND f(p) >= 1   # at least one outgoing edge to FileNode
    AND s(p) >= 1   # at least one outgoing edge to SocketChannelNode

LOLBin pool = the 16 A_Study_Stage names ProvNinja's gadget-chain.json uses.

Two evaluation tasks:
  Task A: ProvNinja-modification detection
    positive = 191 adversarial graphs
    negative = 636 benign + 215 original anomaly
    Goal: tell if a graph has been modified by ProvNinja

  Task B: anomaly classification (parallel to GAT)
    positive = 215 original anomaly + 191 adversarial = 406 anomaly
    negative = 636 benign
    Goal: classify each graph as anomaly vs benign
    (Same task GAT was trained for)

Outputs eval_d2_full.json (alongside this script) + stdout summary.
"""

import os
import sys
import json
import pickle
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GBROOT    = REPO_ROOT / "baselines/provninja/intrusion-detection-system/graph-based"
ADVDIR    = GBROOT / "adversarial_examples"
DATADIR   = GBROOT / "sample-supply-chain-data"

sys.path.insert(0, str(GBROOT))
sys.path.insert(0, str(GBROOT / "dataloaders"))

import dgl
import dgl.heterograph
sys.modules['dgl.heterograph'].DGLHeteroGraph = dgl.DGLGraph

from gnnUtils import get_binary_train_val_test_datasets

# 16 LOLBins from gadget-chain.json
LOLBIN = {
    '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/dockerd', '/usr/bin/dpkg',
    '/usr/bin/env', '/usr/bin/fiberlamp', '/usr/bin/git', '/usr/bin/mandb',
    '/usr/bin/perl', '/usr/bin/python3.8', '/usr/bin/run-parts',
    '/usr/bin/start-stop-daemon', '/usr/bin/thunderbird',
    '/usr/bin/xfce-terminal', '/usr/bin/anacron',
}

FORWARD = {
    ("ProcessNode", "PROC_CREATE",        "ProcessNode"),
    ("ProcessNode", "READ",               "FileNode"),
    ("ProcessNode", "WRITE",              "FileNode"),
    ("ProcessNode", "FILE_EXEC",          "FileNode"),
    ("ProcessNode", "READ",               "SocketChannelNode"),
    ("ProcessNode", "WRITE",              "SocketChannelNode"),
    ("ProcessNode", "IP_CONNECTION_EDGE", "ProcessNode"),
    ("ProcessNode", "IP_CONNECTION_EDGE", "FileNode"),
}


def d2_predict(g):
    """Returns True if graph has any LOLBin A_Study_Stage with both file IO and socket IO."""
    if "ProcessNode" not in g.ntypes:
        return False
    n_proc = g.num_nodes("ProcessNode")
    if n_proc == 0:
        return False
    arr = g.additional_node_data.get("ProcessNode", []) if hasattr(g, "additional_node_data") else []

    file_count = [0] * n_proc
    sock_count = [0] * n_proc
    for ce in g.canonical_etypes:
        if ce not in FORWARD or ce[0] != "ProcessNode":
            continue
        src, _ = g.edges(etype=ce)
        for s in src.tolist():
            if ce[2] == "FileNode":
                file_count[s] += 1
            elif ce[2] == "SocketChannelNode":
                sock_count[s] += 1

    for i in range(n_proc):
        name = arr[i].get("EXE_NAME", "") if i < len(arr) else ""
        if name in LOLBIN and file_count[i] >= 1 and sock_count[i] >= 1:
            return True
    return False


def metrics(tp, fn, fp, tn):
    P = tp / (tp + fp) if (tp + fp) else 0
    R = tp / (tp + fn) if (tp + fn) else 0
    F1 = 2 * P * R / (P + R) if (P + R) else 0
    Acc = (tp + tn) / (tp + fn + fp + tn) if (tp + fn + fp + tn) else 0
    return {"precision": round(P, 4), "recall": round(R, 4), "f1": round(F1, 4), "accuracy": round(Acc, 4),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn}


def main():
    os.chdir(str(GBROOT))

    print("Loading test dataset...")
    node_attrs = {"ProcessNode": ["EXE_NAME"], "SocketChannelNode": ["LOCAL_INET_ADDR"], "FileNode": ["FILENAME_SET"]}
    rel_attrs = {("ProcessNode", "PROC_CREATE", "ProcessNode"): [], ("ProcessNode", "READ", "FileNode"): [], ("ProcessNode", "WRITE", "FileNode"): [], ("ProcessNode", "FILE_EXEC", "FileNode"): [], ("ProcessNode", "READ", "SocketChannelNode"): [], ("ProcessNode", "WRITE", "SocketChannelNode"): [], ("ProcessNode", "IP_CONNECTION_EDGE", "ProcessNode"): [], ("ProcessNode", "IP_CONNECTION_EDGE", "FileNode"): []}
    for r in list(rel_attrs.keys()):
        f = r[::-1]
        if f not in rel_attrs:
            rel_attrs[f] = rel_attrs[r]
    _, _, test_ds = get_binary_train_val_test_datasets(
        str(DATADIR), "benign", "anomaly", node_attrs, rel_attrs,
        bidirection=True, force_reload=False, verbose=False,
    )

    # Per-graph D2 predictions on benign / orig anomaly
    benign_preds   = []
    orig_ano_preds = []
    benign_total = 0; orig_ano_total = 0
    for g, label in test_ds:
        pred = d2_predict(g)
        if int(label) == 0:
            benign_total += 1
            benign_preds.append(pred)
        else:
            orig_ano_total += 1
            orig_ano_preds.append(pred)

    # Adversarial
    adv_preds = []
    adv_total = 0
    for d in sorted(os.listdir(str(ADVDIR))):
        try:
            g = pickle.load(open(f"{ADVDIR}/{d}/adversarial_graph.pkl", "rb"))
        except Exception:
            continue
        adv_total += 1
        adv_preds.append(d2_predict(g))

    print(f"\nLoaded: {benign_total} benign + {orig_ano_total} original anomaly + {adv_total} adversarial")

    # ===== Task A: ProvNinja-modification detection =====
    # positive = adv, negative = benign + orig_anomaly
    A_tp = sum(adv_preds)
    A_fn = adv_total - A_tp
    A_fp = sum(benign_preds) + sum(orig_ano_preds)
    A_tn = (benign_total + orig_ano_total) - A_fp
    A = metrics(A_tp, A_fn, A_fp, A_tn)

    # ===== Task B: anomaly classification (parallel to GAT) =====
    # positive = orig_ano + adv, negative = benign
    B_tp = sum(orig_ano_preds) + sum(adv_preds)
    B_fn = (orig_ano_total + adv_total) - B_tp
    B_fp = sum(benign_preds)
    B_tn = benign_total - B_fp
    B = metrics(B_tp, B_fn, B_fp, B_tn)

    out = {
        "rule": "D2: any LOLBin ProcessNode with file_edges>=1 AND socket_edges>=1",
        "lolbin_size": len(LOLBIN),
        "totals": {"benign": benign_total, "orig_anomaly": orig_ano_total, "adversarial": adv_total},
        "task_A_modification_detection": A,
        "task_B_anomaly_classification": B,
    }

    print()
    print("=" * 70)
    print("Task A: ProvNinja-modification detection")
    print(f"  positive = 191 adv (改造图);  negative = {benign_total} benign + {orig_ano_total} orig anomaly")
    print(f"  TP={A['tp']}  FN={A['fn']}  FP={A['fp']}  TN={A['tn']}")
    print(f"  Precision: {A['precision']}    Recall: {A['recall']}    F1: {A['f1']}    Acc: {A['accuracy']}")
    print()
    print("Task B: anomaly classification (跟 GAT 同任务)")
    print(f"  positive = {orig_ano_total} orig + {adv_total} adv = {orig_ano_total+adv_total} anomaly;")
    print(f"  negative = {benign_total} benign")
    print(f"  TP={B['tp']}  FN={B['fn']}  FP={B['fp']}  TN={B['tn']}")
    print(f"  Precision: {B['precision']}    Recall: {B['recall']}    F1: {B['f1']}    Acc: {B['accuracy']}")
    print()
    print("Comparison: GAT 在 Task B 上(replay README §2.6 的 851 张):")
    print(f"  TP=7  FN=208  FP=23  TN=613   P=0.233  R=0.033  F1=0.057")

    out_path = Path(__file__).with_suffix(".json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"\nWrote: {out_path}")


if __name__ == "__main__":
    main()
