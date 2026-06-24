"""§2 orthrus — 命令空间 P1 dilution(curl × N 真跑 docker).

跟 orthrus.py(图空间)对照:
  图空间:直接 INSERT 50 个 curl process 节点 + CONNECT/SENDTO edge 到 :3000 socket
  命令空间:在 attack 场景前注入 50 个 `curl http://localhost:3000 -o /dev/null` 命令,
            真跑 docker,strace 抓 syscall → CDM 节点+边

USAGE:
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/orthrus_cmd.py
"""
from __future__ import annotations
import sys, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    load_baseline, save_result, SCENARIO_PATH,
    predict_all_nodes, compute_evade_rate, find_attack_post,
)
from attack.oracle import query_with_validation_strict


def variant_baseline():
    oracle, sql, _ = load_baseline("orthrus")
    bl = predict_all_nodes(oracle, sql)
    flagged = sorted({nid for nid, info in bl.items() if info["y_pred"] == 1})
    return {
        "variant": "baseline",
        "total_nodes": len(bl),
        "baseline_flagged_count": len(flagged),
        "baseline_flagged_nodes": flagged[:20],
    }


def variant_p1_dilution_nai_cmd(n=50):
    """★ 命令空间 P1 — 注入 N 个 curl :3000 命令到 attack 场景前."""
    oracle, baseline_sql, _ = load_baseline("orthrus")
    bl_pred = predict_all_nodes(oracle, baseline_sql)
    _, attack_idx = find_attack_post(baseline_sql)

    delta_commands = [
        f"curl -s http://localhost:3000/ -o /dev/null 2>&1"
    ] * n
    delta_positions = [0] * n

    scn = json.load(open(SCENARIO_PATH))
    print(f"  → 执行 {n} 条 curl 命令 + A0 attack(等 docker)...")
    result = query_with_validation_strict(scn, delta_commands, delta_positions, oracle)
    if not result.valid:
        return {
            "variant": f"p1_dilution_nai_cmd_n{n}",
            "failed": True,
            "failed_step": result.failed_step,
            "extra": result.extra,
        }

    af_sql = open(result.extra["dump"]).read()
    af_pred = predict_all_nodes(oracle, af_sql)
    er = compute_evade_rate(baseline_sql, bl_pred, af_sql, af_pred)

    bl_at = bl_pred.get(attack_idx, {})
    af_at = af_pred.get(attack_idx, {})

    return {
        "variant": f"p1_dilution_nai_cmd_n{n}",
        "atomic_mode": "P1 cmd-space shared-neighbor dilution",
        "target_class": "attack POST 邻居 :3000 socket",
        "params": {"n_per_target": n, "cmd_template": "curl -s http://localhost:3000/ -o /dev/null 2>&1"},
        "n_commands": len(delta_commands),
        "attack_baseline_score": bl_at.get("score"),
        "attack_after_score": af_at.get("score"),
        "perturbed_n_nodes": result.extra.get("n_nodes"),
        "perturbed_n_flagged": result.extra.get("n_flagged"),
        **er,
    }


def _fmt_rate(r):
    return f"{r*100:.1f}%" if r is not None else "N/A"


def main():
    print("\n=== §2 orthrus — 命令空间 P1 dilution(真跑 docker)===")
    print("\n--- variant_baseline ---")
    bl = variant_baseline()
    print(f"  BL = {bl['baseline_flagged_nodes']}  size={bl['baseline_flagged_count']}")

    print("\n--- ★ variant_p1_dilution_nai_cmd ---")
    r = variant_p1_dilution_nai_cmd(50)
    if r.get("failed"):
        print(f"  ✗ 命令空间执行失败:failed_step={r['failed_step']}")
        print(f"    extra: {r['extra']}")
    else:
        print(f"  atomic mode:       {r['atomic_mode']}")
        print(f"  target_class:      {r['target_class']}")
        print(f"  n_commands:        {r['n_commands']}")
        print(f"  perturbed graph:   {r['perturbed_n_nodes']} 节点 / {r['perturbed_n_flagged']} flagged")
        print(f"  attack POST:       score {r['attack_baseline_score']}→{r['attack_after_score']}")
        print(f"  evade_rate:        {_fmt_rate(r['evade_rate'])}  ({r['evaded_count']}/{r['baseline_flagged_count']})")

    p = save_result("orthrus_cmd", [bl, r])
    print(f"\n→ {p}")


if __name__ == "__main__":
    main()
