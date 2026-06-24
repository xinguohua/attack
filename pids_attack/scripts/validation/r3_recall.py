"""r3_recall — Phase 5 核心 motivation 复现验证。

把 ProvNinja P2 191 case + Contorter P2 15 case 喂 R3,
看 R3 能 reject 的比例是否 ≥ 90%(p2_mcts.md §5.1 motivation finding 复现)。

ProvNinja 测 Eq. 12 (co-occurrence):
  - 每个 case 的 inserted_edges 提取 src node 在扰动加入了哪些 dst 节点类型
  - 看 G_benign C_benign 中该 cmd_name 是否同时连过这些类型
  - 若任一 case 引入 G_benign 未共现过的类型组合 → R3 reject

Contorter 测 Eq. 10 (degree distribution):
  - 每个 case 的 (orig_count, adv_count) 表示 degree 从 X → Y
  - 模拟把这个 degree 变化加到 G_benign,看 Λ 是否 ≥ τ_Λ
  - 若 Λ ≥ τ_Λ → R3 reject
"""
from __future__ import annotations
import argparse
import json
import pickle
import sys
from collections import defaultdict
from pathlib import Path
from typing import Set

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from cmd_graph.nettack import (
    eq10_incremental_lambda, eq12_check, resource_type, _fit_power_law_alpha,
)


def classify_provenance_node(nt: str, dst: str) -> str:
    """ProvNinja edge dst:`ProcessNode` / `FileNode` / `IpNode` → 我们的资源类型映射。"""
    if nt == "FileNode":
        return "file"
    if nt in ("IpNode", "SocketNode"):
        return "netflow"
    if nt == "ProcessNode":
        return "process"
    return "other"


def validate_provninja(diff_dir: Path, c_benign: dict, sigma: float = 0.05) -> dict:
    """对每个 ProvNinja P2 pair 跑 eq12_check,统计 reject 数。"""
    rejected = 0
    total = 0
    details = []
    for f in sorted(diff_dir.glob("*.json")):
        total += 1
        d = json.load(open(f))
        inserted = d.get("diffs_extra", {}).get("all_inserted_edges", [])
        # 按 src 聚合 dst types
        src_to_dst_types = defaultdict(set)
        src_to_cmd = {}
        for e in inserted:
            src = e.get("src", "")
            dst_nt = e.get("dst_nt", "")
            dst_type = classify_provenance_node(dst_nt, e.get("dst", ""))
            src_to_dst_types[src].add(dst_type)
            # cmd_name 从 src path 抽 basename
            src_to_cmd[src] = src.rsplit("/", 1)[-1] if "/" in src else src
        # 对每个 src 跑 Eq. 12:before = ∅(扰动是 net new edges),after = inserted types
        case_rejected = False
        for src, dst_types in src_to_dst_types.items():
            # before assumed empty(扰动是新加邻居)— 引入任意 G_benign 未共现的 dst_type 组合就 reject
            if len(dst_types) >= 2:
                # 检查 G_benign 中是否有 cmd_name 节点共现过这些类型
                cmd_name = src_to_cmd[src]
                passed = eq12_check(
                    op_affected_node_types_before=set(),
                    op_affected_node_types_after=dst_types,
                    cmd_name=cmd_name,
                    c_benign=c_benign,
                    sigma=sigma,
                )
                if not passed:
                    case_rejected = True
                    break
            elif len(dst_types) == 1:
                # 单一类型加入,先检查 G_benign 是否该 cmd_name 见过这个类型
                cmd_name = src_to_cmd[src]
                nbr_seen = c_benign.get("neighbor_types_by_cmd", {}).get(cmd_name, set())
                t = next(iter(dst_types))
                if t not in nbr_seen and nbr_seen:
                    # 该 cmd_name 见过其他类型但没见过 t → 引入未见类型
                    passed = eq12_check(
                        op_affected_node_types_before=nbr_seen,
                        op_affected_node_types_after=nbr_seen | dst_types,
                        cmd_name=cmd_name,
                        c_benign=c_benign,
                        sigma=sigma,
                    )
                    if not passed:
                        case_rejected = True
                        break
        if case_rejected:
            rejected += 1
        details.append({"file": f.name, "rejected": case_rejected,
                         "n_inserted_edges": len(inserted)})
    return {"total": total, "rejected": rejected,
            "recall": rejected / max(1, total),
            "details": details}


def validate_contorter(diff_dir: Path, power_law: dict, baseline_degrees: list,
                        tau_lambda: float = 0.004) -> dict:
    """对每个 Contorter pair 跑 eq10_incremental_lambda,统计 reject 数。"""
    rejected = 0
    total = 0
    details = []
    for f in sorted(diff_dir.glob("pair_*.json")):
        total += 1
        d = json.load(open(f))
        orig = d.get("orig_count", 0)
        adv = d.get("adv_count", 0)
        if orig == 0 or adv == 0:
            continue
        # 模拟扰动:从 baseline_degrees 池替换一个 degree=orig 为 degree=adv
        deg_before = list(baseline_degrees) + [orig]
        deg_after = list(baseline_degrees) + [adv]
        lam = eq10_incremental_lambda(deg_before, deg_after, power_law)
        case_rejected = lam >= tau_lambda
        if case_rejected:
            rejected += 1
        details.append({"file": f.name, "rejected": case_rejected,
                         "orig_count": orig, "adv_count": adv,
                         "inflation": d.get("count_inflation_factor", 0),
                         "lambda": lam})
    return {"total": total, "rejected": rejected,
            "recall": rejected / max(1, total),
            "details": details}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--g-benign", default="shared/g_benign.pkl")
    ap.add_argument("--provninja-dir", default="../baselines/pipelines/provninja/diffs")
    ap.add_argument("--contorter-dir", default="../baselines/pipelines/contorter/diffs")
    ap.add_argument("--tau-lambda", type=float, default=0.004)
    ap.add_argument("--sigma", type=float, default=0.05)
    ap.add_argument("--output", default="results/r3_recall.json")
    args = ap.parse_args()

    g_benign = Path(args.g_benign)
    if not g_benign.is_absolute():
        g_benign = PROJECT_ROOT / g_benign
    provninja_dir = Path(args.provninja_dir)
    if not provninja_dir.is_absolute():
        provninja_dir = (PROJECT_ROOT / provninja_dir).resolve()
    contorter_dir = Path(args.contorter_dir)
    if not contorter_dir.is_absolute():
        contorter_dir = (PROJECT_ROOT / contorter_dir).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = PROJECT_ROOT / output

    with open(g_benign, "rb") as f:
        pre = pickle.load(f)
    c_benign = pre["c_benign"]
    power_law = pre["power_law"]
    baseline_degrees = power_law["degrees"]

    print(f"[r3_recall] G_benign: |type_pairs|={len(c_benign['type_pairs'])}  "
          f"α={power_law['alpha']:.3f}  |baseline_degrees|={len(baseline_degrees)}")

    print(f"\n=== ProvNinja P2 (Eq. 12 co-occurrence,σ={args.sigma}) ===")
    pn = validate_provninja(provninja_dir, c_benign, args.sigma)
    print(f"  total={pn['total']}  rejected={pn['rejected']}  recall={pn['recall']:.1%}")
    print(f"  Pass 标准 ≥ 90%:{'✓' if pn['recall'] >= 0.9 else '✗'}")

    print(f"\n=== Contorter P2 (Eq. 10 degree preservation,τ_Λ={args.tau_lambda}) ===")
    ct = validate_contorter(contorter_dir, power_law, baseline_degrees,
                            args.tau_lambda)
    print(f"  total={ct['total']}  rejected={ct['rejected']}  recall={ct['recall']:.1%}")
    print(f"  Pass 标准 ≥ 90%:{'✓' if ct['recall'] >= 0.9 else '✗'}")

    out = {
        "provninja": {k: v for k, v in pn.items() if k != "details"},
        "provninja_details": pn["details"],
        "contorter": {k: v for k, v in ct.items() if k != "details"},
        "contorter_details": ct["details"],
        "config": {"tau_lambda": args.tau_lambda, "sigma": args.sigma,
                    "alpha_benign": power_law["alpha"],
                    "n_baseline_degrees": len(baseline_degrees),
                    "n_type_pairs": len(c_benign["type_pairs"])},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(out, f, indent=2, default=lambda x: list(x) if isinstance(x, set) else str(x))
    print(f"\n→ {output}")


if __name__ == "__main__":
    main()
