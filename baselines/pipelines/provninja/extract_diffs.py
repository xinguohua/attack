"""
Step 1 of PROBLEM_JUSTIFICATION §2.1.

For each pair (original_graph.pkl, adversarial_graph.pkl) in
baselines/provninja/intrusion-detection-system/graph-based/adversarial_examples/<name>/,
compute a diff and write pair_<name>.json into baselines/pipelines/provninja/diffs/.

DIFF METHOD: per-node alignment (node-level identity matching by full
additional_node_data dict equality), then graph traversal for chain detection.

Why not multiset diff: ProvNinja may insert a gadget whose EXE_NAME matches
an existing original node (e.g., insert python3.8 gadget while original also
has python3.8). Multiset count diff = 0 → gadget missed. Per-node alignment
catches this because gadget nodes have only EXE_NAME (or FILENAME_SET) field
while original nodes have CMD / VOL_ID / DATA_ID populated.

Output schema per pair:

{
  "graph": "<name>",
  "original_attack": {
    "attack_processes": {label: count, ...},
    "attack_files":     {label: count, ...},
    "attack_ips":       {label: count, ...}
  },
  "inserted": {
    "gadgets":     {label: count, ...},                # ProcessNode gadgets only
    "pc_edges":    [{"src": ..., "dst": ...,
                     "src_is_gadget": bool, "dst_is_gadget": bool}, ...],
    "chains":      [{"anchor_src": ..., "anchor_dst": ..., "gadgets": [...]}, ...],
    "camouflage_edges_per_gadget": {
      gadget_label: [{"edge": "READ", "target": "/path", "target_nt": "..."}]
    }
  },
  "removed": {
    "pc_edges":     [...],
    "non_pc_edges": [...]
  },
  "diffs_extra": {
    "all_inserted_edges": [...],
    "all_removed_edges":  [...]
  },
  "stats": {...}
}
"""

import json
import os
import pickle
import subprocess
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path

REPO_ROOT       = Path(__file__).resolve().parents[3]
ADVDIR          = REPO_ROOT / "baselines/provninja/intrusion-detection-system/graph-based/adversarial_examples"
OUT_DIR         = REPO_ROOT / "baselines/pipelines/provninja/diffs"

sys.path.insert(0, str(REPO_ROOT / "baselines/provninja/intrusion-detection-system/graph-based"))
sys.path.insert(0, str(REPO_ROOT / "baselines/provninja/intrusion-detection-system/graph-based/dataloaders"))

# Alias DGLHeteroGraph (old class name, dgl <=0.7) → DGLGraph (current).
# Some pkls in adversarial_examples/ were written by an older dgl version and
# pickle resolves dgl.heterograph.DGLHeteroGraph at load time. Without this 5
# pairs fail with: AttributeError: Can't get attribute 'DGLHeteroGraph'.
import dgl
import dgl.heterograph
sys.modules['dgl.heterograph'].DGLHeteroGraph = dgl.DGLGraph

FORWARD_ETYPES = {
    ("ProcessNode", "PROC_CREATE",         "ProcessNode"),
    ("ProcessNode", "READ",                "FileNode"),
    ("ProcessNode", "WRITE",               "FileNode"),
    ("ProcessNode", "FILE_EXEC",           "FileNode"),
    ("ProcessNode", "READ",                "SocketChannelNode"),
    ("ProcessNode", "WRITE",               "SocketChannelNode"),
    ("ProcessNode", "IP_CONNECTION_EDGE",  "ProcessNode"),
    ("ProcessNode", "IP_CONNECTION_EDGE",  "FileNode"),
}

NTYPE_KEY = {
    "ProcessNode":       "EXE_NAME",
    "FileNode":          "FILENAME_SET",
    "SocketChannelNode": "LOCAL_INET_ADDR",
}


# ──────────────── Step A: per-node alignment ────────────────

def node_label(addit_data, ntype, idx):
    """Display string for a node."""
    key = NTYPE_KEY[ntype]
    if ntype not in addit_data or idx >= len(addit_data[ntype]):
        return f"<{ntype}_anonymized_{idx}>"
    return addit_data[ntype][idx].get(key, f"<unknown_{ntype}_{idx}>")


def node_signature(addit_data, ntype, idx):
    """Hashable full-content signature of a node, for cross-graph alignment."""
    if ntype not in addit_data or idx >= len(addit_data[ntype]):
        # No record → can't align; treat each such node as unique
        return ("__no_record__", ntype, idx)
    entry = addit_data[ntype][idx]
    return frozenset(entry.items())


def align_nodes(orig, adv, ntype, num_orig, num_adv):
    """Greedy 1-1 match adv nodes to orig nodes by full addit_data dict equality.
    Returns (adv_to_orig, unmatched_orig_idxs).
      adv_to_orig[adv_idx] = orig_idx if matched else None (gadget)
    """
    orig_addit = orig.additional_node_data
    adv_addit  = adv.additional_node_data

    # Group orig nodes by signature
    sig_to_orig_idxs = defaultdict(list)
    for i in range(num_orig):
        sig_to_orig_idxs[node_signature(orig_addit, ntype, i)].append(i)

    adv_to_orig = {}
    used_orig = set()
    for adv_idx in range(num_adv):
        adv_sig = node_signature(adv_addit, ntype, adv_idx)
        cands = sig_to_orig_idxs.get(adv_sig, [])
        match = next((o for o in cands if o not in used_orig), None)
        if match is not None:
            adv_to_orig[adv_idx] = match
            used_orig.add(match)
        else:
            adv_to_orig[adv_idx] = None  # gadget

    unmatched_orig = [i for i in range(num_orig) if i not in used_orig]
    return adv_to_orig, unmatched_orig


# ──────────────── Step B: edge diff via canonical identity ────────────────

def canonical_node_id(adv_to_orig_per_ntype, ntype, adv_idx, label):
    """Return a hashable id usable across orig/adv:
    - matched: ('orig', orig_idx, ntype)
    - gadget:  ('gadget', label, adv_idx, ntype)
    """
    o = adv_to_orig_per_ntype[ntype].get(adv_idx)
    if o is not None:
        return ("orig", o, ntype)
    return ("gadget", label, adv_idx, ntype)


def orig_node_id(orig_idx, ntype):
    return ("orig", orig_idx, ntype)


def collect_orig_edges(orig, orig_labels):
    """orig edge tuples in canonical form (all 'orig' ids since orig has no gadgets).
    Returns list of (canonical_src_id, etype, canonical_dst_id, src_label, dst_label, src_nt, dst_nt).
    """
    out = []
    for ce in orig.canonical_etypes:
        if ce not in FORWARD_ETYPES:
            continue
        src_nt, etype, dst_nt = ce
        u, v = orig.edges(etype=ce)
        for s, d in zip(u.tolist(), v.tolist()):
            out.append((
                orig_node_id(s, src_nt),
                etype,
                orig_node_id(d, dst_nt),
                orig_labels[src_nt][s],
                orig_labels[dst_nt][d],
                src_nt, dst_nt,
            ))
    return out


def collect_adv_edges(adv, adv_labels, adv_to_orig_per_ntype):
    """adv edge tuples in canonical form (orig ids when matched, gadget ids when not)."""
    out = []
    for ce in adv.canonical_etypes:
        if ce not in FORWARD_ETYPES:
            continue
        src_nt, etype, dst_nt = ce
        u, v = adv.edges(etype=ce)
        for s, d in zip(u.tolist(), v.tolist()):
            sl = adv_labels[src_nt][s]
            dl = adv_labels[dst_nt][d]
            out.append((
                canonical_node_id(adv_to_orig_per_ntype, src_nt, s, sl),
                etype,
                canonical_node_id(adv_to_orig_per_ntype, dst_nt, d, dl),
                sl, dl, src_nt, dst_nt,
            ))
    return out


def diff_edges_canonical(orig_edges, adv_edges):
    """Multiset diff using canonical ids (first 3 elements of each tuple)."""
    def key(e): return (e[0], e[1], e[2])
    orig_c = Counter(key(e) for e in orig_edges)
    adv_c  = Counter(key(e) for e in adv_edges)
    inserted_keys = adv_c  - orig_c
    removed_keys  = orig_c - adv_c

    # Recover full tuples (with labels) for inserted/removed
    inserted = []
    for k, count in inserted_keys.items():
        for e in adv_edges:
            if key(e) == k:
                inserted.append(e); count -= 1
                if count == 0: break
    removed = []
    for k, count in removed_keys.items():
        for e in orig_edges:
            if key(e) == k:
                removed.append(e); count -= 1
                if count == 0: break
    return removed, inserted


# ──────────────── Step C: chain reconstruction via BFS ────────────────

def reconstruct_chains(inserted_pc_edges):
    """Enumerate every directed path in inserted PC edges that starts and ends at
    non-gadget anchors with gadget-only intermediates. Differs from a greedy walker
    that stops at the first orig node it sees: that strategy collapses bidirectional
    structures like  python ↔ sh ↔ env ↔ run-parts ↔ bash ↔ git  into 2 spurious
    self-loops (python→sh→python and git→bash→git) and silently loses the cross-anchor
    chains that actually carry the rerouted operation.

    Returns list of {anchor_src, anchor_dst, gadgets: [labels in order]}.
    Path uniqueness is keyed on (anchor_src, anchor_dst, tuple(gadget labels)) so
    duplicate gadget-instance paths collapse but distinct topologies don't.
    """
    adj = defaultdict(list)
    for (sid, etype, did, sl, dl, snt, dnt) in inserted_pc_edges:
        if etype != "PROC_CREATE":
            continue
        adj[sid].append((did, sl, dl))

    def is_gadget_id(nid):
        return isinstance(nid, tuple) and nid[0] == "gadget"

    seen = set()
    chains = []
    for sid, neighbors in list(adj.items()):
        if is_gadget_id(sid):
            continue
        for (did, sl, dl) in neighbors:
            if not is_gadget_id(did):
                # Direct orig → orig restoration (empty gadget chain)
                key = (sl, dl, ())
                if key in seen:
                    continue
                seen.add(key)
                chains.append({"anchor_src": sl, "anchor_dst": dl, "gadgets": []})
                continue
            # DFS from gadget did, ending at any non-gadget node. Visited set is
            # per-path so different paths through the same gadget can both be reported.
            stack = [(did, [dl], {sid, did})]
            while stack:
                cur, path_labels, visited = stack.pop()
                for (nxt, _slx, nxt_label) in adj.get(cur, []):
                    if not is_gadget_id(nxt):
                        # Path complete: anchor_src → gadgets → anchor_dst
                        anchor_dst_label = nxt_label
                        key = (sl, anchor_dst_label, tuple(path_labels))
                        if key in seen:
                            continue
                        seen.add(key)
                        chains.append({
                            "anchor_src": sl,
                            "anchor_dst": anchor_dst_label,
                            "gadgets":    list(path_labels),
                        })
                    elif nxt not in visited:
                        stack.append((nxt, path_labels + [nxt_label], visited | {nxt}))
    return chains


def compute_replacements(removed_pc_edges, adv_pc_label_edges):
    """For each removed cross-name PC edge (parent, child), find the shortest path
    parent → g1 → g2 → ... → child in the **modified graph's** PC adjacency (label
    space). Adjacency must include ALL adversarial PC edges — preserved-from-original
    edges and newly inserted alike — because a removed edge instance does not imply
    the (parent, child) relationship is gone from modified: original may have had
    multiple instances and some can survive. Building adjacency from inserted edges
    only would miss those preserved direct edges and produce false-positive long
    chains (e.g., 0524_36 dash → python3.8 has a preserved direct edge that the
    inserted-only BFS misses, falsely reporting a 3-hop bash → sh chain).

    adv_pc_label_edges: list of (src_label, dst_label) tuples covering all
                        ProcessNode→ProcessNode PROC_CREATE edges in adversarial.

    Returns list of dicts:
      {
        "removed_src": str, "removed_dst": str,
        "replacement_chain": [intermediate_label, ...] | None,
        "path_length": int (1 = direct edge in modified graph),
      }
    """
    adj = defaultdict(set)
    for src_lbl, dst_lbl in adv_pc_label_edges:
        adj[src_lbl].add(dst_lbl)

    out = []
    for re in removed_pc_edges:
        parent, child = re["src"], re["dst"]
        if parent == child:
            continue  # self-loop deletion — not a routing operation
        # BFS shortest path parent → child in label space
        q = deque([(parent, [parent])])
        seen = {parent}
        path = None
        while q:
            cur, p = q.popleft()
            for nxt in adj.get(cur, []):
                if nxt == child:
                    path = p + [child]; break
                if nxt in seen:
                    continue
                seen.add(nxt)
                q.append((nxt, p + [nxt]))
            if path:
                break
        if path is None:
            out.append({
                "removed_src": parent, "removed_dst": child,
                "replacement_chain": None, "path_length": 0,
            })
        else:
            out.append({
                "removed_src": parent, "removed_dst": child,
                "replacement_chain": path[1:-1],
                "path_length": len(path) - 1,
            })
    return out


# ──────────────── Step D: orchestration ────────────────

def process_pair(name):
    advdir = ADVDIR / name
    orig_pkl = advdir / "original_graph.pkl"
    adv_pkl  = advdir / "adversarial_graph.pkl"
    if not orig_pkl.exists() or not adv_pkl.exists():
        return None

    with open(orig_pkl, "rb") as f: orig = pickle.load(f)
    with open(adv_pkl,  "rb") as f: adv  = pickle.load(f)

    # Build label tables for display purposes
    def build_labels(g):
        return {nt: [node_label(g.additional_node_data, nt, i) for i in range(g.num_nodes(nt))]
                for nt in g.ntypes}
    orig_labels = build_labels(orig)
    adv_labels  = build_labels(adv)

    # Per-ntype alignment: adv idx → orig idx | None
    adv_to_orig_per_ntype = {}
    unmatched_orig_per_ntype = {}
    for nt in adv.ntypes:
        a2o, unmatched = align_nodes(
            orig, adv, nt,
            num_orig=orig.num_nodes(nt) if nt in orig.ntypes else 0,
            num_adv=adv.num_nodes(nt),
        )
        adv_to_orig_per_ntype[nt] = a2o
        unmatched_orig_per_ntype[nt] = unmatched

    # Collect edges in canonical form
    orig_edges_can = collect_orig_edges(orig, orig_labels)
    adv_edges_can  = collect_adv_edges(adv, adv_labels, adv_to_orig_per_ntype)

    # Diff
    removed_edges, inserted_edges = diff_edges_canonical(orig_edges_can, adv_edges_can)

    # ── identify gadget nodes ──
    gadget_proc_labels = []
    for adv_idx, orig_idx in adv_to_orig_per_ntype.get("ProcessNode", {}).items():
        if orig_idx is None:
            gadget_proc_labels.append(adv_labels["ProcessNode"][adv_idx])
    gadget_proc_counter = Counter(gadget_proc_labels)
    gadget_proc_set_canonical_ids = {
        canonical_node_id(adv_to_orig_per_ntype, "ProcessNode", adv_idx,
                          adv_labels["ProcessNode"][adv_idx])
        for adv_idx, orig_idx in adv_to_orig_per_ntype.get("ProcessNode", {}).items()
        if orig_idx is None
    }

    # ── classify inserted PC edges + reconstruct chains ──
    inserted_pc = [e for e in inserted_edges if e[1] == "PROC_CREATE"]
    pc_edges_annotated = []
    for (sid, etype, did, sl, dl, snt, dnt) in inserted_pc:
        pc_edges_annotated.append({
            "src": sl, "dst": dl,
            "src_is_gadget": isinstance(sid, tuple) and sid[0] == "gadget",
            "dst_is_gadget": isinstance(did, tuple) and did[0] == "gadget",
        })
    chains = reconstruct_chains(inserted_pc)

    # ── camouflage: inserted non-PC edges where src is a gadget ──
    camouflage = defaultdict(list)
    for (sid, etype, did, sl, dl, snt, dnt) in inserted_edges:
        if etype == "PROC_CREATE":
            continue
        if isinstance(sid, tuple) and sid[0] == "gadget" and snt == "ProcessNode":
            camouflage[sl].append({"edge": etype, "target": dl, "target_nt": dnt})

    # ── original_attack summary ──
    orig_proc_counter = Counter(orig_labels.get("ProcessNode", []))
    orig_file_counter = Counter(orig_labels.get("FileNode", []))
    orig_sock_counter = Counter(orig_labels.get("SocketChannelNode", []))

    # ── pretty output ──
    def edge_to_dict(t):
        sid, etype, did, sl, dl, snt, dnt = t
        return {"src": sl, "edge": etype, "dst": dl, "src_nt": snt, "dst_nt": dnt}

    removed_pc     = [edge_to_dict(e) for e in removed_edges if e[1] == "PROC_CREATE"]
    removed_non_pc = [edge_to_dict(e) for e in removed_edges if e[1] != "PROC_CREATE"]

    # ── replacements: BFS shortest path in modified graph for each removed cross-name edge ──
    # Adjacency built from the full adversarial PC edge set (label space) so preserved
    # direct edges (original edges that survived the deletion of other instances) are visible.
    pc_etype_local = ("ProcessNode", "PROC_CREATE", "ProcessNode")
    adv_pc_u, adv_pc_v = adv.edges(etype=pc_etype_local)
    adv_pc_label_edges = [
        (adv_labels["ProcessNode"][s], adv_labels["ProcessNode"][d])
        for s, d in zip(adv_pc_u.tolist(), adv_pc_v.tolist())
    ]
    replacements = compute_replacements(removed_pc, adv_pc_label_edges)

    pc_etype = ("ProcessNode", "PROC_CREATE", "ProcessNode")
    return {
        "graph": name,
        "original_attack": {
            "attack_processes": dict(orig_proc_counter),
            "attack_files":     dict(orig_file_counter),
            "attack_ips":       dict(orig_sock_counter),
        },
        "inserted": {
            "gadgets":   dict(gadget_proc_counter),
            "pc_edges":  pc_edges_annotated,
            "chains":    chains,
            "camouflage_edges_per_gadget": dict(camouflage),
        },
        "removed": {
            "pc_edges":     removed_pc,
            "non_pc_edges": removed_non_pc,
        },
        "replacements": replacements,
        "diffs_extra": {
            "all_inserted_edges": [edge_to_dict(e) for e in inserted_edges],
            "all_removed_edges":  [edge_to_dict(e) for e in removed_edges],
            "unmatched_orig_processes": [orig_labels["ProcessNode"][i]
                                         for i in unmatched_orig_per_ntype.get("ProcessNode", [])],
        },
        "stats": {
            "orig_num_processes":   orig.num_nodes("ProcessNode")  if "ProcessNode" in orig.ntypes else 0,
            "adv_num_processes":    adv.num_nodes("ProcessNode")   if "ProcessNode" in adv.ntypes  else 0,
            "orig_num_files":       orig.num_nodes("FileNode")     if "FileNode" in orig.ntypes else 0,
            "adv_num_files":        adv.num_nodes("FileNode")      if "FileNode" in adv.ntypes  else 0,
            "orig_num_sockets":     orig.num_nodes("SocketChannelNode") if "SocketChannelNode" in orig.ntypes else 0,
            "adv_num_sockets":      adv.num_nodes("SocketChannelNode")  if "SocketChannelNode" in adv.ntypes else 0,
            "orig_num_proc_create": orig.num_edges(pc_etype),
            "adv_num_proc_create":  adv.num_edges(pc_etype),
            "num_inserted_edges":   len(inserted_edges),
            "num_removed_edges":    len(removed_edges),
            "num_inserted_pc":      len(inserted_pc),
            "num_inserted_gadgets": sum(gadget_proc_counter.values()),
            "num_chains":           len(chains),
        },
    }


def _worker_one_pair(name):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    d = process_pair(name)
    if d is None:
        sys.exit(2)
    out = OUT_DIR / f"pair_{name}.json"
    with open(out, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    sys.exit(0)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pair_names = sorted(d.name for d in ADVDIR.iterdir() if d.is_dir())
    summary = {"total_dirs": len(pair_names), "with_both_pkls": 0,
               "with_inserted_gadgets": 0, "failures": []}

    print(f"Found {len(pair_names)} directories under {ADVDIR}", flush=True)
    PER_PAIR_TIMEOUT = 20
    script = Path(__file__).resolve()

    for i, name in enumerate(pair_names, 1):
        out_file = OUT_DIR / f"pair_{name}.json"
        if out_file.exists():
            print(f"[{i}/{len(pair_names)}] {name} (skip)", flush=True)
            try:
                d = json.load(open(out_file))
                summary["with_both_pkls"] += 1
                if d["stats"]["num_inserted_gadgets"] > 0:
                    summary["with_inserted_gadgets"] += 1
            except Exception:
                pass
            continue
        print(f"[{i}/{len(pair_names)}] {name} ...", flush=True, end=" ")
        try:
            r = subprocess.run(
                [sys.executable, "-B", str(script), "--worker", name],
                capture_output=True, text=True, timeout=PER_PAIR_TIMEOUT,
            )
            if r.returncode == 0:
                summary["with_both_pkls"] += 1
                try:
                    d = json.load(open(out_file))
                    if d["stats"]["num_inserted_gadgets"] > 0:
                        summary["with_inserted_gadgets"] += 1
                except Exception:
                    pass
                print("OK", flush=True)
            elif r.returncode == 2:
                print("no pkls", flush=True)
            else:
                summary["failures"].append({"graph": name, "error": f"rc={r.returncode}: {r.stderr.strip()[:200]}"})
                print(f"FAIL rc={r.returncode}", flush=True)
        except subprocess.TimeoutExpired:
            summary["failures"].append({"graph": name, "error": f"timeout >{PER_PAIR_TIMEOUT}s"})
            print("TIMEOUT", flush=True)
        except Exception as e:
            summary["failures"].append({"graph": name, "error": str(e)})
            print(f"FAIL {e}", flush=True)

    with open(OUT_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print()
    print(f"Wrote {summary['with_both_pkls']} pair_*.json files → {OUT_DIR}")
    print(f"  with inserted gadgets:   {summary['with_inserted_gadgets']}/{summary['with_both_pkls']}")
    print(f"  failures:                {len(summary['failures'])}")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--worker":
        _worker_one_pair(sys.argv[2])
    else:
        main()