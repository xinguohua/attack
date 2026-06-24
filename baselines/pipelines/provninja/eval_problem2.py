"""
Problem 2 unified evaluation — three-step pipeline on 191 (orig, adv) pairs.

  Step 0: original_graph.pkl  -> Prov-GAT   (expect ~100%)
  Step 1: adversarial_graph.pkl -> Prov-GAT (expect ~0%)
  Step 2: adversarial_graph.pkl -> D2 rule  (expect >=90%)

D2 rule: any ProcessNode p where
   name(p) in LOLBin set
   AND f(p) >= 1   (at least one outgoing edge to FileNode)
   AND s(p) >= 1   (at least one outgoing edge to SocketChannelNode)

Outputs eval_problem2.json (alongside this script) + a single comparison table to stdout.
"""

import os
import sys
import json
import copy
import pickle
import torch
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GBROOT    = REPO_ROOT / "baselines/provninja/intrusion-detection-system/graph-based"
ADVDIR    = GBROOT / "adversarial_examples"
MODEL_BIN = GBROOT / "models/gat_768_10_0.001_20_5_128_bidirection.bin"

sys.path.insert(0, str(GBROOT))
sys.path.insert(0, str(GBROOT / "dataloaders"))

import dgl
import dgl.heterograph
sys.modules['dgl.heterograph'].DGLHeteroGraph = dgl.DGLGraph

from gnnDriver import BinaryHeteroClassifier

LOLBIN = {
    "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dockerd", "/usr/bin/dpkg",
    "/usr/bin/env", "/usr/bin/fiberlamp", "/usr/bin/git", "/usr/bin/mandb",
    "/usr/bin/perl", "/usr/bin/python3.8", "/usr/bin/run-parts",
    "/usr/bin/start-stop-daemon", "/usr/bin/thunderbird",
    "/usr/bin/xfce-terminal", "/usr/bin/anacron",
}

FORWARD = {
    ("ProcessNode", "PROC_CREATE",        "ProcessNode"),
    ("ProcessNode", "READ",               "FileNode"),
    ("ProcessNode", "WRITE",              "FileNode"),
    ("ProcessNode", "FILE_EXEC",          "FileNode"),
    ("ProcessNode", "READ",               "SocketChannelNode"),
    ("ProcessNode", "WRITE",               "SocketChannelNode"),
    ("ProcessNode", "IP_CONNECTION_EDGE", "ProcessNode"),
    ("ProcessNode", "IP_CONNECTION_EDGE", "FileNode"),
}

node_attrs = {"ProcessNode": ["EXE_NAME"], "SocketChannelNode": ["LOCAL_INET_ADDR"], "FileNode": ["FILENAME_SET"]}
rel_attrs  = {("ProcessNode","PROC_CREATE","ProcessNode"):[], ("ProcessNode","READ","FileNode"):[], ("ProcessNode","WRITE","FileNode"):[], ("ProcessNode","FILE_EXEC","FileNode"):[], ("ProcessNode","READ","SocketChannelNode"):[], ("ProcessNode","WRITE","SocketChannelNode"):[], ("ProcessNode","IP_CONNECTION_EDGE","ProcessNode"):[], ("ProcessNode","IP_CONNECTION_EDGE","FileNode"):[]}
for r in list(rel_attrs.keys()):
    f = r[::-1]
    if f not in rel_attrs:
        rel_attrs[f] = rel_attrs[r]


def feature_aggregation_function(graph):
    return {
        "FileNode":          graph.nodes["FileNode"].data["FILENAME_SET"]          if graph.num_nodes("FileNode")          else torch.empty(0),
        "ProcessNode":       graph.nodes["ProcessNode"].data["EXE_NAME"]           if graph.num_nodes("ProcessNode")       else torch.empty(0),
        "SocketChannelNode": graph.nodes["SocketChannelNode"].data["LOCAL_INET_ADDR"] if graph.num_nodes("SocketChannelNode") else torch.empty(0),
    }

THRESHOLD = 0.5
device = torch.device("cpu")


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


def main():
    os.chdir(str(GBROOT))

    print("Loading Prov-GAT model...")
    model = BinaryHeteroClassifier(
        "gat", 5, 768, 10,
        list(rel_attrs.keys()),
        list(node_attrs.keys()),
        structural=False,
    )
    model.load_state_dict(torch.load(str(MODEL_BIN), map_location=device))
    model.eval()
    model = model.to(device)

    pair_names = sorted(d.name for d in ADVDIR.iterdir() if d.is_dir())
    print(f"Found {len(pair_names)} pairs")

    # Step counters
    step0_detected = 0   # GAT on orig: anomaly?
    step1_detected = 0   # GAT on adv: anomaly?
    step2_detected = 0   # D2 on adv: trigger?

    per_pair = []
    for i, name in enumerate(pair_names, 1):
        d = ADVDIR / name
        try:
            with open(d / "original_graph.pkl",    "rb") as f: orig = pickle.load(f)
            with open(d / "adversarial_graph.pkl", "rb") as f: adv  = pickle.load(f)
        except Exception as e:
            print(f"  load fail {name}: {e}")
            continue

        with torch.no_grad():
            g_orig = copy.deepcopy(orig).to(device)
            g_adv  = copy.deepcopy(adv).to(device)
            orig_pred = float(model(g_orig, feature_aggregation_function(g_orig)))
            adv_pred  = float(model(g_adv,  feature_aggregation_function(g_adv)))

        s0 = orig_pred > THRESHOLD
        s1 = adv_pred  > THRESHOLD
        s2 = d2_predict(adv)

        if s0: step0_detected += 1
        if s1: step1_detected += 1
        if s2: step2_detected += 1

        per_pair.append({
            "graph": name,
            "orig_pred": round(orig_pred, 6),
            "adv_pred":  round(adv_pred,  6),
            "step0_gat_on_orig":   s0,
            "step1_gat_on_adv":    s1,
            "step2_d2_on_adv":     s2,
        })

        if i % 20 == 0 or i == len(pair_names):
            print(f"  [{i}/{len(pair_names)}] s0={step0_detected} s1={step1_detected} s2={step2_detected}")

    n = len(per_pair)
    summary = {
        "n_pairs":              n,
        "step0_gat_on_orig":    {"detected": step0_detected, "rate": round(step0_detected/n, 4)},
        "step1_gat_on_adv":     {"detected": step1_detected, "rate": round(step1_detected/n, 4)},
        "step2_d2_on_adv":      {"detected": step2_detected, "rate": round(step2_detected/n, 4)},
    }

    out_path = Path(__file__).with_suffix(".json")
    with open(out_path, "w") as f:
        json.dump({"summary": summary, "per_pair": per_pair}, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 70)
    print(f"Total pairs: {n}")
    print(f"{'Step':<8} {'输入':<10} {'Detector':<12} {'detected':<12} {'rate':<8}")
    print("-" * 60)
    print(f"Step 0  {'原图':<10} {'Prov-GAT':<12} {step0_detected}/{n}{'':<3}  {100*step0_detected/n:>5.1f}%")
    print(f"Step 1  {'改造图':<10} {'Prov-GAT':<12} {step1_detected}/{n}{'':<3}  {100*step1_detected/n:>5.1f}%")
    print(f"Step 2  {'改造图':<10} {'D2 rule':<12} {step2_detected}/{n}{'':<3}  {100*step2_detected/n:>5.1f}%")
    print()
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
