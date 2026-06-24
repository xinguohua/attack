"""§1 magic — 命令空间 P1 dilution(cat × N 真跑 docker).

跟 magic.py(图空间)对照:
  图空间:在 SQL dump 直接 INSERT 500 cat process 节点 + EVENT_OPEN edge
  命令空间:在 attack 场景前注入 500 个 `cat <file_path>` shell 命令,真跑 docker,
            strace 抓 syscall → range/converter.py 转 CDM 节点+边

USAGE:
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/magic_cmd.py
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


def find_baseline_file_paths(baseline_sql, n=5, exclude_dev=True):
    """从 baseline SQL 抽 N 个已存在 file 节点的 path."""
    paths = re.findall(
        r"INSERT INTO file_node_table[^;]+, '([^']+)', \d+\) ON CONFLICT",
        baseline_sql,
    )
    if exclude_dev:
        paths = [p for p in paths if not p.startswith("/dev/")]
    return paths[:n]


def variant_baseline():
    oracle, sql, _ = load_baseline("magic")
    bl = predict_all_nodes(oracle, sql)
    flagged = sorted({nid for nid, info in bl.items() if info["y_pred"] == 1})
    return {
        "variant": "baseline",
        "total_nodes": len(bl),
        "baseline_flagged_count": len(flagged),
        "baseline_flagged_nodes": flagged[:20],
    }


def variant_p1_dilution_cmd(n_per_target=100, n_targets=5):
    """★ 命令空间 P1 — 注入 N×T 个 cat <path> 命令到 attack 场景前."""
    oracle, baseline_sql, _ = load_baseline("magic")
    bl_pred = predict_all_nodes(oracle, baseline_sql)

    paths = find_baseline_file_paths(baseline_sql, n_targets)
    if len(paths) < n_targets:
        raise RuntimeError(f"only {len(paths)} non-dev file paths in baseline; need {n_targets}")

    delta_commands = []
    for p in paths:
        delta_commands.extend([f"cat {p} > /dev/null 2>&1"] * n_per_target)
    delta_positions = [0] * len(delta_commands)

    scn = json.load(open(SCENARIO_PATH))
    print(f"  → 执行 {len(delta_commands)} 条 cat 命令 + A0 attack(等 docker)...")
    result = query_with_validation_strict(scn, delta_commands, delta_positions, oracle)
    if not result.valid:
        return {
            "variant": f"p1_dilution_cmd_n{n_per_target}_t{n_targets}",
            "failed": True,
            "failed_step": result.failed_step,
            "extra": result.extra,
        }

    af_sql = open(result.extra["dump"]).read()
    af_pred = predict_all_nodes(oracle, af_sql)
    er = compute_evade_rate(baseline_sql, bl_pred, af_sql, af_pred)

    bl_flagged = {nid for nid, i in bl_pred.items() if i["y_pred"] == 1}
    bl_scores_before = sorted(set(round(bl_pred[n]["score"], 2) for n in bl_flagged))

    return {
        "variant": f"p1_dilution_cmd_n{n_per_target}_t{n_targets}",
        "atomic_mode": "P1 cmd-space shared-neighbor dilution",
        "target_class": "BL 邻居 file 节点的 path",
        "params": {"target_count": n_targets, "n_per_target": n_per_target,
                   "cmd_template": "cat <path> > /dev/null 2>&1"},
        "target_paths": paths,
        "n_commands": len(delta_commands),
        "BL_scores_before": bl_scores_before,
        "perturbed_n_nodes": result.extra.get("n_nodes"),
        "perturbed_n_flagged": result.extra.get("n_flagged"),
        **er,
    }


def _fmt_rate(r):
    return f"{r*100:.1f}%" if r is not None else "N/A"


def main():
    print("\n=== §1 magic — 命令空间 P1 dilution(真跑 docker)===")
    print("\n--- variant_baseline ---")
    bl = variant_baseline()
    print(f"  BL = {bl['baseline_flagged_nodes']}  size={bl['baseline_flagged_count']}")

    print("\n--- ★ variant_p1_dilution_cmd ---")
    r = variant_p1_dilution_cmd(100, 5)
    if r.get("failed"):
        print(f"  ✗ 命令空间执行失败:failed_step={r['failed_step']}")
        print(f"    extra: {r['extra']}")
    else:
        print(f"  atomic mode:       {r['atomic_mode']}")
        print(f"  target_paths:      {r['target_paths']}")
        print(f"  n_commands:        {r['n_commands']}")
        print(f"  perturbed graph:   {r['perturbed_n_nodes']} 节点 / {r['perturbed_n_flagged']} flagged")
        print(f"  BL scores before:  {r['BL_scores_before']}")
        print(f"  evade_rate:        {_fmt_rate(r['evade_rate'])}  ({r['evaded_count']}/{r['baseline_flagged_count']})")

    p = save_result("magic_cmd", [bl, r])
    print(f"\n→ {p}")


if __name__ == "__main__":
    main()
