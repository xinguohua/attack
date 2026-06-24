"""§3 threatrace — 命令空间 P1 dilution(对每个 BL 节点真跑 N 命令).

跟 threatrace.py(图空间)对照:
  图空间:对每个 BL 节点 type-typical incoming op,加 N=100 个 cat process 节点
  命令空间:
    file BL    → cat <path> × N 命令
    netflow BL → curl <addr> × N 命令(socket op via 真 socket connect)

USAGE:
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/threatrace_cmd.py
"""
from __future__ import annotations
import sys, re, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    load_baseline, save_result, SCENARIO_PATH,
    predict_all_nodes, compute_evade_rate,
)
from attack.oracle import query_with_validation_strict


def get_node_info(sql, idx):
    """返回 (node_type, path_or_addr)."""
    m = re.search(rf"INSERT INTO file_node_table[^;]+, '([^']+)', {idx}\) ON CONFLICT", sql)
    if m:
        return "file", m.group(1)
    m = re.search(rf"INSERT INTO netflow_node_table[^;]+'([^']*)', '([^']*)', '([^']+)', '(\d+)', {idx}\) ON CONFLICT", sql)
    if m:
        # local_ip, local_port, remote_ip, remote_port
        local_ip, local_port, remote_ip, remote_port = m.group(1), m.group(2), m.group(3), m.group(4)
        return "netflow", f"{remote_ip}:{remote_port}"
    return None, None


def variant_baseline():
    oracle, sql, _ = load_baseline("threatrace")
    bl = predict_all_nodes(oracle, sql)
    flagged = sorted({nid for nid, info in bl.items() if info["y_pred"] == 1})
    return {
        "variant": "baseline",
        "total_nodes": len(bl),
        "baseline_flagged_count": len(flagged),
        "baseline_flagged_nodes": flagged[:20],
    }


def variant_p1_dilution_universal_cmd(n_per_target=100):
    """★ 命令空间 P1 — 对每个 BL 节点按 type 加 N 个命令."""
    oracle, baseline_sql, _ = load_baseline("threatrace")
    bl_pred = predict_all_nodes(oracle, baseline_sql)
    bl_flagged = sorted({nid for nid, info in bl_pred.items() if info["y_pred"] == 1})

    delta_commands = []
    per_target = []
    skipped = []
    for idx in bl_flagged:
        ntype, addr = get_node_info(baseline_sql, idx)
        if ntype == "file":
            if addr.startswith("/dev/"):
                skipped.append({"node_idx": idx, "type": ntype, "addr": addr, "reason": "/dev/* skipped"})
                continue
            cmds = [f"cat {addr} > /dev/null 2>&1"] * n_per_target
            per_target.append({"node_idx": idx, "type": ntype, "addr": addr,
                               "cmd_template": f"cat {addr}"})
            delta_commands.extend(cmds)
        elif ntype == "netflow":
            if addr.startswith("127.0.0.1:") or addr.startswith("localhost:"):
                # 用 curl 连这个 socket
                port = addr.split(":")[-1]
                cmds = [f"curl -s http://localhost:{port}/ -o /dev/null 2>&1"] * n_per_target
                per_target.append({"node_idx": idx, "type": ntype, "addr": addr,
                                   "cmd_template": f"curl http://localhost:{port}/"})
                delta_commands.extend(cmds)
            else:
                skipped.append({"node_idx": idx, "type": ntype, "addr": addr,
                                "reason": "non-local netflow,无法命令空间复现"})
                continue
        else:
            skipped.append({"node_idx": idx, "type": "unknown", "reason": "no node_info match"})
            continue

    delta_positions = [0] * len(delta_commands)
    scn = json.load(open(SCENARIO_PATH))
    print(f"  → 执行 {len(delta_commands)} 条命令(skip {len(skipped)} 个 BL)+ A0 attack(等 docker)...")
    result = query_with_validation_strict(scn, delta_commands, delta_positions, oracle)
    if not result.valid:
        return {
            "variant": f"p1_dilution_universal_cmd_n{n_per_target}",
            "failed": True,
            "failed_step": result.failed_step,
            "extra": result.extra,
            "per_target": per_target,
            "skipped": skipped,
        }

    af_sql = open(result.extra["dump"]).read()
    af_pred = predict_all_nodes(oracle, af_sql)
    er = compute_evade_rate(baseline_sql, bl_pred, af_sql, af_pred)

    sweep = []
    for info in per_target + skipped:
        idx = info["node_idx"]
        b = bl_pred.get(idx, {})
        a = af_pred.get(idx, {})
        sweep.append({
            **info,
            "baseline": {"score": b.get("score"), "cor": b.get("correct_pred"), "y": b.get("y_pred")},
            "after":    {"score": a.get("score"), "cor": a.get("correct_pred"), "y": a.get("y_pred")},
            "evaded": b.get("y_pred") == 1 and a.get("y_pred") == 0,
        })

    return {
        "variant": f"p1_dilution_universal_cmd_n{n_per_target}",
        "atomic_mode": "P1 cmd-space shared-neighbor dilution",
        "target_class": "每个 BL 节点(file → cat;netflow → curl)",
        "params": {"n_per_target": n_per_target, "targets": len(per_target), "skipped": len(skipped)},
        "n_commands": len(delta_commands),
        "sweep": sweep,
        "perturbed_n_nodes": result.extra.get("n_nodes"),
        "perturbed_n_flagged": result.extra.get("n_flagged"),
        **er,
    }


def _fmt_rate(r):
    return f"{r*100:.1f}%" if r is not None else "N/A"


def main():
    print("\n=== §3 threatrace — 命令空间 P1 dilution(真跑 docker)===")
    print("\n--- variant_baseline ---")
    bl = variant_baseline()
    print(f"  BL = {bl['baseline_flagged_nodes']}  size={bl['baseline_flagged_count']}")

    print("\n--- ★ variant_p1_dilution_universal_cmd ---")
    r = variant_p1_dilution_universal_cmd(100)
    if r.get("failed"):
        print(f"  ✗ 命令空间执行失败:failed_step={r['failed_step']}")
        print(f"    extra: {r['extra']}")
    else:
        print(f"  atomic mode:       {r['atomic_mode']}")
        print(f"  n_commands:        {r['n_commands']}  (targets={r['params']['targets']}, skipped={r['params']['skipped']})")
        print(f"  perturbed graph:   {r['perturbed_n_nodes']} 节点 / {r['perturbed_n_flagged']} flagged")
        for s in r["sweep"]:
            mark = " ★" if s.get("evaded") else " ✗"
            if "reason" in s:
                print(f"  node {s['node_idx']:>3d} ({s.get('type', '?'):8s}) {s.get('addr', ''):30s}  SKIPPED ({s['reason']})")
                continue
            bl_info = s["baseline"]; af_info = s["after"]
            print(f"  node {s['node_idx']:>3d} ({s['type']:8s}) {s['addr'][:30]:30s}  "
                  f"score {bl_info['score']:.3f}→{af_info['score']:>7.3f}  "
                  f"cor {bl_info['cor']}→{af_info['cor']}  "
                  f"y {bl_info['y']}→{af_info['y']}{mark}")
        print(f"  ▸ evade_rate: {_fmt_rate(r['evade_rate'])}  ({r['evaded_count']}/{r['baseline_flagged_count']})")

    p = save_result("threatrace_cmd", [bl, r])
    print(f"\n→ {p}")


if __name__ == "__main__":
    main()
