"""聚合实验结果 → CSV + 简单统计。

Usage:
    python aggregate.py --root pids_attack/experiments/E1_ablation --out figures/E1_ablation_summary.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List


PREFERRED_COLUMNS = [
    "experiment",
    "result_file",
    "schema_version",
    "scenario_id",
    "detector",
    "variant",
    "e1_0_passed",
    "query_ok",
    "r1_valid",
    "r2_valid",
    "delta_command_success",
    "e0_gt_loaded",
    "e0_gt_count",
    "mutation_produced",
    "mutation_expected_types",
    "mutation_observed_types",
    "mutation_missing_types",
    "mutation_effective",
    "asr",
    "q_used",
    "delta_len",
    "active_delta_len",
    "r1_valid_rate",
    "r2_valid_rate",
    "attack_impact_rate",
    "recall",
    "mcc",
    "e0_mcc",
    "delta_mcc",
    "tp",
    "fp",
    "tn",
    "fn",
    "gt_flagged_nodes",
    "n_flagged",
    "n_nodes",
    "best_F_count",
    "converged",
    "wall_clock_sec",
    "trace_path",
    "sql_path",
    "cfg_seed",
    "cfg_B_max",
    "cfg_T_GA",
    "cfg_m_pop",
    "cfg_feature_method",
    "cfg_surrogate",
    "cfg_f2_metric",
    "cfg_scalarize",
    "cfg_commit_mode",
    "cfg_acquisition",
    "ga_variant",
]


def _legacy_row(exp_name: str, json_path: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    row = {
        "experiment": exp_name,
        "result_file": json_path.name,
        "schema_version": data.get("schema_version"),
        "scenario_id": data.get("scenario_id"),
        "detector": data.get("detector"),
        "variant": data.get("variant"),
        "converged": data.get("converged"),
        "asr": data.get("asr"),
        "q_used": data.get("q_used"),
        "delta_len": data.get("delta_len"),
        "active_delta_len": data.get("active_delta_len"),
        "best_F_count": data.get("best_F_count"),
        "wall_clock_sec": data.get("wall_clock_sec"),
        "mutation_produced": data.get("mutation_produced"),
        "mutation_expected_types": ",".join(data.get("mutation_expected_types") or []),
        "mutation_observed_types": ",".join(data.get("mutation_observed_types") or []),
        "mutation_missing_types": ",".join(data.get("mutation_missing_types") or []),
        "mutation_effective": data.get("mutation_effective"),
        "r1_valid_rate": data.get("r1_valid_rate"),
        "r2_valid_rate": data.get("r2_valid_rate"),
        "attack_impact_rate": data.get("attack_impact_rate"),
        "recall": data.get("recall"),
        "mcc": data.get("mcc"),
        "tp": data.get("tp"),
        "fp": data.get("fp"),
        "tn": data.get("tn"),
        "fn": data.get("fn"),
        "gt_flagged_nodes": data.get("gt_flagged_nodes"),
        "n_flagged": data.get("n_flagged"),
        "n_nodes": data.get("n_nodes"),
        "n_unflagged_in_R": data.get("n_unflagged_in_R"),
        "n_flagged_in_R": data.get("n_flagged_in_R"),
        "blr_n_active": data.get("blr_n_active_features"),
        "ga_variant": _ga_variant_from_file(json_path.name),
    }
    cfg = data.get("config", {})
    for key in ("seed", "B_max", "T_GA", "m_pop", "H", "D_cap",
                "beta", "beta_lcb", "k_nn",
                "feature_method", "surrogate", "f2_metric",
                "scalarize", "commit_mode", "acquisition"):
        row[f"cfg_{key}"] = cfg.get(key)
    return row


def _e1_0_row(exp_name: str, json_path: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    metrics = data.get("metrics") or {}
    e0_gt = data.get("e0_gt") or {}
    detector_query = data.get("detector_query") or {}
    legacy = data.get("legacy") or {}
    delta = data.get("delta") or {}
    return {
        "experiment": exp_name,
        "result_file": json_path.name,
        "schema_version": data.get("schema_version"),
        "scenario_id": data.get("scenario_id"),
        "detector": data.get("detector"),
        "variant": data.get("variant"),
        "e1_0_passed": metrics.get("e1_0_passed"),
        "query_ok": metrics.get("query_ok"),
        "r1_valid": metrics.get("r1_valid"),
        "r2_valid": metrics.get("r2_valid"),
        "delta_command_success": metrics.get("delta_command_success"),
        "e0_gt_loaded": e0_gt.get("loaded"),
        "e0_gt_count": e0_gt.get("gt_count"),
        "asr": metrics.get("asr"),
        "q_used": metrics.get("q_used"),
        "delta_len": metrics.get("delta_len"),
        "gt_flagged_nodes": metrics.get("gt_flagged_nodes"),
        "n_flagged": metrics.get("n_flagged"),
        "n_nodes": metrics.get("n_nodes"),
        "best_F_count": legacy.get("best_F_count"),
        "converged": legacy.get("converged"),
        "wall_clock_sec": metrics.get("wall_clock_sec"),
        "trace_path": detector_query.get("trace_path"),
        "sql_path": detector_query.get("sql_path"),
        "delta_position": (delta.get("positions") or [None])[0],
        "delta_command": (delta.get("commands") or [None])[0],
        "delta_source": delta.get("source"),
        "position_valid": delta.get("position_valid"),
        "cfg_seed": data.get("seed"),
        "aggregate_ok": True,
    }


def _load_e0_mcc(root: Path) -> Dict[tuple, float]:
    path = root.parent / "E0_detection" / "results" / "summary_orthrus.csv"
    if not path.exists():
        return {}
    out: Dict[tuple, float] = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                out[(row.get("Scenario"), row.get("System"))] = float(row.get("MCC"))
            except (TypeError, ValueError):
                continue
    return out


def _attach_e0_delta_mcc(rows: List[Dict[str, Any]], e0_mcc: Dict[tuple, float]) -> None:
    for row in rows:
        key = (row.get("scenario_id"), row.get("detector"))
        baseline = e0_mcc.get(key)
        if baseline is None:
            continue
        row["e0_mcc"] = baseline
        try:
            row["delta_mcc"] = float(row.get("mcc")) - baseline
        except (TypeError, ValueError):
            row["delta_mcc"] = None


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
            if str(data.get("schema_version", "")).startswith("safemimic.e1_0_framework"):
                row = _e1_0_row(exp_dir.name, json_path, data)
            else:
                row = _legacy_row(exp_dir.name, json_path, data)
            rows.append(row)
    _attach_e0_delta_mcc(rows, _load_e0_mcc(root))
    return rows


def write_csv(rows: List[Dict[str, Any]], out_path: Path) -> None:
    if not rows:
        print("⚠️  no rows to write")
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    keys: List[str] = []
    for key in PREFERRED_COLUMNS:
        if any(key in row for row in rows):
            keys.append(key)
            seen.add(key)
    for row in rows:
        for key in row.keys():
            if key not in seen:
                keys.append(key)
                seen.add(key)
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
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
    produced = sum(1 for r in rows if r.get("mutation_produced")) / n
    r1_vals = [float(r["r1_valid_rate"]) for r in rows if r.get("r1_valid_rate") is not None]
    r2_vals = [float(r["r2_valid_rate"]) for r in rows if r.get("r2_valid_rate") is not None]
    impact_vals = [float(r["attack_impact_rate"]) for r in rows if r.get("attack_impact_rate") is not None]
    return {"n": n, "n_conv": n_conv, "SR": sr, "q_avg_all": q_avg_all,
            "q_star": q_star, "delta_star": delta_avg, "wall_avg": wall_avg,
            "produced": produced,
            "r1_rate": (sum(r1_vals) / len(r1_vals)) if r1_vals else None,
            "r2_rate": (sum(r2_vals) / len(r2_vals)) if r2_vals else None,
            "impact_rate": (sum(impact_vals) / len(impact_vals)) if impact_vals else None}


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
        if exp.startswith("E1.0"):
            n = len(exp_rows)
            pass_rate = sum(1 for r in exp_rows if r.get("e1_0_passed")) / n if n else 0
            query_rate = sum(1 for r in exp_rows if r.get("query_ok")) / n if n else 0
            r1_rate = sum(1 for r in exp_rows if r.get("r1_valid")) / n if n else 0
            r2_rate = sum(1 for r in exp_rows if r.get("r2_valid")) / n if n else 0
            print(f"  {exp}: n={n}, pass={pass_rate:.1%}, query={query_rate:.1%}, "
                  f"R1={r1_rate:.1%}, R2={r2_rate:.1%}")
            continue
        s = _stat(exp_rows)
        if s:
            print(f"  {exp}: n={s['n']}, SR={s['SR']:.1%}, q★={s['q_star']:.1f}, "
                  f"|Δ★|={s['delta_star']:.1f}, wall={s['wall_avg']:.1f}s")

    # E1.0 framework gate.
    e30 = [r for r in rows if r["experiment"].startswith("E1.0")]
    if e30:
        print("\n=== E1.0 framework bootstrap ===")
        dets = sorted(set(r["detector"] for r in e30 if r.get("detector")))
        variants = sorted(set(r.get("variant") or _algo_from_file(r["result_file"]) for r in e30))
        print(f"  {'detector':<16} {'variant':<12} {'n':>4} {'pass':>7} {'query':>7} {'R1':>7} {'R2':>7} {'ASR':>7}")
        for det in dets:
            for variant in variants:
                sub = [r for r in e30 if r["detector"] == det
                       and (r.get("variant") or _algo_from_file(r["result_file"])) == variant]
                if not sub:
                    continue
                n = len(sub)
                pass_rate = sum(1 for r in sub if r.get("e1_0_passed")) / n
                query_rate = sum(1 for r in sub if r.get("query_ok")) / n
                r1_rate = sum(1 for r in sub if r.get("r1_valid")) / n
                r2_rate = sum(1 for r in sub if r.get("r2_valid")) / n
                asr = sum(1 for r in sub if r.get("asr")) / n
                print(f"  {det:<16} {variant:<12} {n:>4} {pass_rate:>6.1%} "
                      f"{query_rate:>6.1%} {r1_rate:>6.1%} {r2_rate:>6.1%} {asr:>6.1%}")

    # ablation per-variant
    variant_key_map = {
        "E1.1_mutation": "variant",
        "E1.2_fitness": "variant",
        "E1.3_search": "variant",
        "E1.4_surrogate": "variant",
        "E1.5_acquisition": "variant",
    }
    for exp_name, key in variant_key_map.items():
        sub = [r for r in rows if r["experiment"] == exp_name]
        if not sub:
            continue
        variants = sorted(set(str(r.get(key)) for r in sub))
        if len(variants) <= 1:
            continue
        print(f"\n=== {exp_name} by variant ({key}) ===")
        print(f"  {'variant':<28} {'n':>4} {'prod':>7} {'SR':>7} {'q★':>5} {'|Δ★|':>5} {'R1':>7} {'R2':>7}")
        for v in variants:
            v_rows = [r for r in sub if str(r.get(key)) == v]
            s = _stat(v_rows)
            r1 = f"{s['r1_rate']:.1%}" if s["r1_rate"] is not None else "NA"
            r2 = f"{s['r2_rate']:.1%}" if s["r2_rate"] is not None else "NA"
            print(f"  {v:<28} {s['n']:>4} {s['produced']:>6.1%} {s['SR']:>6.1%} "
                  f"{s['q_star']:>5.1f} {s['delta_star']:>5.1f} {r1:>7} {r2:>7}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", required=True)
    p.add_argument("--out", default="figures/E2_summary.csv")
    args = p.parse_args()

    root = Path(args.root).resolve()
    out_path = Path(args.out) if Path(args.out).is_absolute() else (root / args.out)

    rows = collect_results(root)
    write_csv(rows, out_path)
    print_summary(rows)


if __name__ == "__main__":
    main()
