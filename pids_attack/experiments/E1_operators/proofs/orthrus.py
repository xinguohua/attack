"""§2 orthrus — 图空间扰动(P1 + P2 原子).

orthrus 用 per-edge MLP → per-node max edge loss → kmeans top-30 划 anomaly 簇.
2 个 variant:
  - variant_p1_dilution_nai(50):  P1 — 加 50 curl 共享 BL 节点邻居 :3000 socket
  - variant_p2_rerouting:         P2 — socat 中转,改 BL 节点关联 edge endpoint

统一 evade 指标:BL = {y=1},evade_rate = |evaded ∈ BL| / |BL|.

USAGE:
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/orthrus.py
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (
    load_baseline, find_attack_post, find_socket_3000,
    save_result, predict_all_nodes, compute_evade_rate,
    shared_neighbor_dilution, edge_rerouting,
)


def _attack_info(predictions, attack_idx):
    info = predictions.get(attack_idx)
    return {"score": info["score"], "y_pred": info["y_pred"]} if info else None


def variant_p1_dilution_nai(n=50):
    """P1 shared-neighbor dilution 作用于 attack 邻居 :3000 socket."""
    oracle, sql, _ = load_baseline("orthrus")
    _attack_hash, attack_idx = find_attack_post(sql)
    sock_hash = find_socket_3000(sql)

    bl_pred = predict_all_nodes(oracle, sql)

    perturbed_sql, _ = shared_neighbor_dilution(
        sql, sock_hash, n=n,
        ops=["EVENT_CONNECT", "EVENT_SENDTO"], proc_cmd="/usr/bin/curl",
        base_ts=50000, proc_label_prefix="curl_dilute",
    )
    af_pred = predict_all_nodes(oracle, perturbed_sql)
    return {
        "variant": f"p1_dilution_nai_n{n}",
        "atomic_mode": "P1 shared-neighbor dilution",
        "target_class": "attack POST 的邻居 :3000 socket",
        "params": {"target_count": 1, "n_per_target": n,
                   "ops": ["EVENT_CONNECT", "EVENT_SENDTO"], "proc_cmd": "/usr/bin/curl"},
        "finding": "F-orth-1 ★",
        "mechanism": (
            f"加 {n} 个良性 curl 连 :3000,orthrus 给它们同样高分,"
            "占满 kmeans top-30 阈值簇,把 attack score 挤出 anomaly 簇"
        ),
        "attack_baseline": _attack_info(bl_pred, attack_idx),
        "attack_after": _attack_info(af_pred, attack_idx),
        **compute_evade_rate(sql, bl_pred, perturbed_sql, af_pred),
    }


def variant_p2_rerouting():
    """P2 edge rerouting — socat 中转改 attack endpoint."""
    oracle, sql, _ = load_baseline("orthrus")
    attack_hash, attack_idx = find_attack_post(sql)
    sock_hash = find_socket_3000(sql)

    bl_pred = predict_all_nodes(oracle, sql)
    perturbed_sql, _ = edge_rerouting(
        sql, attack_hash, sock_hash,
        midway_path="/usr/bin/socat",
        midway_cmd="socat tcp-listen:3001 fork tcp:localhost:3000",
        ts_base=60000,
    )
    af_pred = predict_all_nodes(oracle, perturbed_sql)
    bl_at = _attack_info(bl_pred, attack_idx)
    af_at = _attack_info(af_pred, attack_idx)
    return {
        "variant": "p2_rerouting_socat",
        "atomic_mode": "P2 edge rerouting",
        "target_class": "attack POST 关联 edge",
        "params": {"midway": "socat", "ops": "del attack↔:3000 + add 3 detour"},
        "finding": "F-orth-2(单独不够)",
        "mechanism": (
            "iptables REDIRECT 把 connect(:3000) 重定向到 :3001(socat listener),"
            "attack 关联 edge dst 从 :3000 → socat 进程,max-loss 来源被改 → score 降"
        ),
        "attack_baseline": bl_at,
        "attack_after": af_at,
        "score_delta": af_at["score"] - bl_at["score"],
        **compute_evade_rate(sql, bl_pred, perturbed_sql, af_pred),
        "note": "score 真降,但 kmeans 阈值仍在 top-30 簇内 → 单独不够",
    }


def _fmt_rate(r):
    return f"{r*100:.1f}%" if r is not None else "N/A"


def main():
    print("\n=== §2 orthrus 图空间扰动(P1 + P2 原子)===")
    results = [variant_p1_dilution_nai(50), variant_p2_rerouting()]
    print(f"\n{'='*72}\n§ ORTHRUS — {len(results)} variant(s)\n{'='*72}")
    for r in results:
        bl, af = r["attack_baseline"], r["attack_after"]
        print(f"  [{r['variant']}] {r['finding']}  ({r['atomic_mode']})")
        print(f"     attack POST: score {bl['score']:.3f}→{af['score']:.3f}  y {bl['y_pred']}→{af['y_pred']}")
        print(f"     BL flagged: {r['baseline_flagged_count']}  "
              f"evaded: {r['evaded_count']}  evade_rate: {_fmt_rate(r['evade_rate'])}")
    p = save_result("orthrus", results)
    print(f"\n→ {p}")


if __name__ == "__main__":
    main()
