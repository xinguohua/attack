"""
Apply the trained Prov-GAT model (768-feature, 5 layers, bidirectional) to
each pair (original_graph.pkl, adversarial_graph.pkl) under
adversarial_examples/<name>/, record predictions, count detection results.

Goal: get the empirical detection rate of GAT on the 191 saved adversarial
examples. The save logic in provninjaGraph.py (line 483) only writes when
attack_pred < THRESHOLD=0.5 at attack time, so we expect detection rate
near 0% if we use the same model. But the user wants empirical verification
rather than relying on save-logic-by-construction.

Output: eval_gat_on_adv.json (alongside this script) with per-graph predictions + summary.
"""

import os
import sys
import json
import pickle
import torch
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GBROOT    = REPO_ROOT / "baselines/provninja/intrusion-detection-system/graph-based"
ADVDIR    = GBROOT / "adversarial_examples"
MODEL_BIN = GBROOT / "models/gat_768_10_0.001_20_5_128_bidirection.bin"

sys.path.insert(0, str(GBROOT))
sys.path.insert(0, str(GBROOT / "dataloaders"))

# dgl alias for old pickled graphs
import dgl
import dgl.heterograph
sys.modules['dgl.heterograph'].DGLHeteroGraph = dgl.DGLGraph

from gnnDriver import BinaryHeteroClassifier

# These match provninjaGraph.py exactly
node_attributes = {
    "ProcessNode": ["EXE_NAME"],
    "SocketChannelNode": ["LOCAL_INET_ADDR"],
    "FileNode": ["FILENAME_SET"],
}

relation_attributes = {
    ("ProcessNode", "PROC_CREATE", "ProcessNode"): [],
    ("ProcessNode", "READ", "FileNode"): [],
    ("ProcessNode", "WRITE", "FileNode"): [],
    ("ProcessNode", "FILE_EXEC", "FileNode"): [],
    ("ProcessNode", "WRITE", "SocketChannelNode"): [],
    ("ProcessNode", "READ", "SocketChannelNode"): [],
    ("ProcessNode", "IP_CONNECTION_EDGE", "ProcessNode"): [],
    ("ProcessNode", "IP_CONNECTION_EDGE", "FileNode"): [],
}

# Bidirectional duplication (-bi flag in README command)
for r in list(relation_attributes.keys()):
    flipped = r[::-1]
    if flipped not in relation_attributes:
        relation_attributes[flipped] = relation_attributes[r]


def feature_aggregation_function(graph):
    return {
        "FileNode": graph.nodes["FileNode"].data["FILENAME_SET"]
        if graph.num_nodes("FileNode") else torch.empty(0),
        "ProcessNode": graph.nodes["ProcessNode"].data["EXE_NAME"]
        if graph.num_nodes("ProcessNode") else torch.empty(0),
        "SocketChannelNode": graph.nodes["SocketChannelNode"].data["LOCAL_INET_ADDR"]
        if graph.num_nodes("SocketChannelNode") else torch.empty(0),
    }


THRESHOLD = 0.5

device = torch.device("cpu")


def main():
    # Build same architecture as README command:
    #   gat -if 768 -hf 10 -lr 0.001 -e 20 -n 5 -bs 128 -bi
    model = BinaryHeteroClassifier(
        "gat",
        5,           # num_layers
        768,         # input_feature_size
        10,          # hidden_feature_size
        list(relation_attributes.keys()),
        list(node_attributes.keys()),
        structural=False,
    )
    state = torch.load(str(MODEL_BIN), map_location=device)
    model.load_state_dict(state)
    model.eval()
    model = model.to(device)

    pair_names = sorted(d.name for d in ADVDIR.iterdir() if d.is_dir())
    print(f"Found {len(pair_names)} pairs in {ADVDIR}")
    print(f"THRESHOLD = {THRESHOLD} (pred > THRESHOLD => detected as anomaly)")
    print()

    out = {
        "threshold": THRESHOLD,
        "model": str(MODEL_BIN.name),
        "results": [],
        "loaded": 0,
        "failures": [],
    }

    detected_count = 0
    evaded_count   = 0
    for i, name in enumerate(pair_names, 1):
        d = ADVDIR / name
        try:
            with open(d / "original_graph.pkl",    "rb") as f: orig = pickle.load(f)
            with open(d / "adversarial_graph.pkl", "rb") as f: adv  = pickle.load(f)
        except Exception as e:
            out["failures"].append({"graph": name, "error": str(e)[:200]})
            print(f"[{i}/{len(pair_names)}] {name} LOAD FAIL: {e}")
            continue

        # If pickled with extra wrappers, get the underlying dgl graph
        orig_g = orig.graph if hasattr(orig, "graph") else orig
        adv_g  = adv.graph  if hasattr(adv, "graph")  else adv

        with torch.no_grad():
            try:
                orig_pred = float(model(orig_g, feature_aggregation_function(orig_g)))
                adv_pred  = float(model(adv_g,  feature_aggregation_function(adv_g)))
            except Exception as e:
                out["failures"].append({"graph": name, "error": f"forward: {str(e)[:200]}"})
                print(f"[{i}/{len(pair_names)}] {name} FWD FAIL: {e}")
                continue

        orig_detected = orig_pred > THRESHOLD
        adv_detected  = adv_pred  > THRESHOLD

        if adv_detected:
            detected_count += 1
        else:
            evaded_count += 1

        out["results"].append({
            "graph": name,
            "orig_pred": round(orig_pred, 6),
            "adv_pred":  round(adv_pred,  6),
            "orig_detected": orig_detected,
            "adv_detected":  adv_detected,
            "evaded": (not adv_detected),
        })
        out["loaded"] += 1

        if i % 20 == 0 or i == len(pair_names):
            print(f"[{i}/{len(pair_names)}] {name} orig={orig_pred:.3f} adv={adv_pred:.3f}"
                  f" {'DETECTED' if adv_detected else 'EVADED'}")

    total = out["loaded"]
    out["summary"] = {
        "total":         total,
        "detected":      detected_count,
        "evaded":        evaded_count,
        "detection_rate":  round(detected_count / total, 4) if total else 0,
        "evasion_rate":    round(evaded_count   / total, 4) if total else 0,
        "failures":      len(out["failures"]),
    }

    out_path = Path(__file__).with_suffix(".json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 60)
    print(f"Total pairs evaluated: {total}")
    print(f"Adversarial graphs DETECTED by GAT (pred > 0.5): {detected_count} ({100*detected_count/max(total,1):.1f}%)")
    print(f"Adversarial graphs EVADED  GAT (pred <= 0.5):    {evaded_count} ({100*evaded_count/max(total,1):.1f}%)")
    print(f"Failed to load/forward: {len(out['failures'])}")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
