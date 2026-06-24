"""聚合实验结果 → CSV + 简单统计。

Usage:
    python aggregate.py --root pids_attack/experiments/E3_attack --out figures/E3_attack_summary.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List


def collect_results(root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for exp_dir in sorted(root.iterdir()):
        if not exp_dir.is_dir() or not exp_dir.name.startswith("E"):
            continue
        results_dir = exp_dir / "results"
        if not results_dir.exists():
            continue
        for json_path in sorted(results_dir.glob("*.json")):
            try:
                with open(json_path) as f:
                    data = json.load(f)
            except Exception as e:
                print(f"  ⚠️  failed to load {json_path}: {e}")
                continue
            # 提取关键字段
            row = {
                "experiment": exp_dir.name,
                "result_file": json_path.name,
                "scenario_id": data.get("scenario_id"),
                "detector": data.get("detector"),
                "converged": data.get("converged"),
                "q_used": data.get("q_used"),
                "delta_len": data.get("delta_len"),
                "best_F_count": data.get("best_F_count"),
                "wall_clock_sec": data.get("wall_clock_sec"),
                "n_unflagged_in_R": data.get("n_unflagged_in_R"),
                "n_flagged_in_R": data.get("n_flagged_in_R"),
                "blr_n_active": data.get("blr_n_active_features"),
                "ga_variant": _ga_variant_from_file(json_path.name),
            }
            # config 字段
            cfg = data.get("config", {})
            for key in ("seed", "B_max", "T_GA", "m_pop", "H", "D_cap",
                         "beta", "beta_lcb", "k_nn",
                         "feature_method", "surrogate", "f2_metric",
                         "scalarize", "commit_mode", "acquisition"):
                row[f"cfg_{key}"] = cfg.get(key)
            rows.append(row)
    return rows


def write_csv(rows: List[Dict[str, Any]], out_path: Path) -> None:
    if not rows:
        print("⚠️  no rows to write")
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(rows[0].keys())
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"✅ wrote {len(rows)} rows → {out_path}")


def _stat(rows):
    n = len(rows)
    if n == 0:
        return None
    n_conv = sum(1 for r in rows if r.get("converged"))
    sr = n_conv / n
    q_avg_all = sum(r.get("q_used") or 0 for r in rows) / n
    q_star = (sum(r.get("q_used") or 0 for r in rows if r.get("converged")) / n_conv) if n_conv else 0
    delta_avg = (sum(r.get("delta_len") or 0 for r in rows if r.get("converged")) / n_conv) if n_conv else 0
    wall_avg = sum(r.get("wall_clock_sec") or 0 for r in rows) / n
    return {"n": n, "n_conv": n_conv, "SR": sr, "q_avg_all": q_avg_all,
            "q_star": q_star, "delta_star": delta_avg, "wall_avg": wall_avg}


def _algo_from_file(fname: str) -> str:
    parts = fname.replace(".json", "").split("_")
    return parts[0] if parts else "?"


def _ga_variant_from_file(fname: str) -> str:
    stem = fname.replace(".json", "")
    marker = "_ga-"
    return stem.split(marker, 1)[1] if marker in stem else ""


def print_summary(rows: List[Dict[str, Any]]) -> None:
    by_exp: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_exp.setdefault(r["experiment"], []).append(r)
    print("\n=== Summary by experiment ===")
    for exp, exp_rows in sorted(by_exp.items()):
        s = _stat(exp_rows)
        if s:
            print(f"  {exp}: n={s['n']}, SR={s['SR']:.1%}, q★={s['q_star']:.1f}, "
                  f"|Δ★|={s['delta_star']:.1f}, wall={s['wall_avg']:.1f}s")

    # E3.0 per (detector, algo)
    e30 = [r for r in rows if r["experiment"].startswith("E3.0")]
    if e30:
        print("\n=== E3.0 by (detector, algorithm) ===")
        dets = sorted(set(r["detector"] for r in e30 if r.get("detector")))
        algos = sorted(set(_algo_from_file(r["result_file"]) for r in e30))
        print(f"  {'detector':<16} {'algo':<10} {'n':>4} {'SR':>7} {'q★':>5} {'|Δ★|':>5} {'wall(s)':>7}")
        for det in dets:
            for algo in algos:
                sub = [r for r in e30 if r["detector"] == det
                       and _algo_from_file(r["result_file"]) == algo]
                if not sub:
                    continue
                s = _stat(sub)
                print(f"  {det:<16} {algo:<10} {s['n']:>4} {s['SR']:>6.1%} "
                      f"{s['q_star']:>5.1f} {s['delta_star']:>5.1f} {s['wall_avg']:>7.2f}")

    # ablation per-variant
    variant_key_map = {
        "E2.1_features": "cfg_feature_method",
        "E2.2_surrogate": "cfg_surrogate",
        "E2.3_f2_metric": "cfg_f2_metric",
        "E2.4_scalarize": "cfg_scalarize",
        "E2.5_commit": "cfg_commit_mode",
        "E2.6_acquisition": "cfg_acquisition",
        "E2.7_ga_cmd": "ga_variant",
    }
    for exp_name, key in variant_key_map.items():
        sub = [r for r in rows if r["experiment"] == exp_name]
        if not sub:
            continue
        variants = sorted(set(str(r.get(key)) for r in sub))
        if len(variants) <= 1:
            continue
        print(f"\n=== {exp_name} by variant ({key}) ===")
        print(f"  {'variant':<28} {'n':>4} {'SR':>7} {'q★':>5} {'|Δ★|':>5}")
        for v in variants:
            v_rows = [r for r in sub if str(r.get(key)) == v]
            s = _stat(v_rows)
            print(f"  {v:<28} {s['n']:>4} {s['SR']:>6.1%} {s['q_star']:>5.1f} {s['delta_star']:>5.1f}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", required=True)
    p.add_argument("--out", default="figures/E3_attack_summary.csv")
    args = p.parse_args()

    root = Path(args.root).resolve()
    out_path = Path(args.out) if Path(args.out).is_absolute() else (root / args.out)

    rows = collect_results(root)
    write_csv(rows, out_path)
    print_summary(rows)


if __name__ == "__main__":
    main()
