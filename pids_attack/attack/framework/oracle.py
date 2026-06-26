"""pidsmaker_wrapper.py — pids_query / query_with_validation 整合。

v6 TODO #1 (C6) 改造:
  - 返 score_vec / gt_persistence / delta_gt_score(连续输出)
  - v7 GT:关键词驱动(scenario.steps[].gt_keywords)+ baseline-flagged 锁定
    稳定 ID = (exec_path, 命中的关键词)元组,跨 trace 不变(替代字符串求交)
  - 加 mutated_a0 参数支持 TODO #5 节点级 op 改 A0 自身

y 字段现在是 attack-node oracle:
  y=1 表示至少一个 GT/attack node 仍被 detector flagged;
  y=0 表示 GT/attack node 已全部避开检测。
"""
from __future__ import annotations
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from range.checker import execute_with_checks, AttackExecutionResult
from range.converter import trace_to_pidsmaker

from detection.training.pidsmaker import _LocalDetector, SUPPORTED_DETECTORS
from detection.training.rules import SUPPORTED_RULE_DETECTORS, make_rule_detector

WARMUP_GT_KEYWORDS = {"http://localhost:3000/"}
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class PIDSOracle:
    def __init__(self, detector_name: str = "orthrus"):
        # v3:支持 GNN base detector 跟 rule-based(G1/G2/G1G2)+ hybrid 混合
        if detector_name not in SUPPORTED_DETECTORS and detector_name not in SUPPORTED_RULE_DETECTORS:
            print(f"[oracle] unknown detector {detector_name}, fallback orthrus")
            detector_name = "orthrus"
        self.detector_name = detector_name
        self._detector = None
        self._is_rule_detector = detector_name in SUPPORTED_RULE_DETECTORS

    def _ensure_detector(self):
        if self._detector is None:
            try:
                from detection.inference.registry import load_e0_oracle

                self._detector = load_e0_oracle(self.detector_name)._ensure_detector()
                return self._detector
            except FileNotFoundError:
                pass

            if self._is_rule_detector:
                self._detector = make_rule_detector(self.detector_name)
            else:
                self._detector = _LocalDetector(detector_name=self.detector_name)
        return self._detector

    def pids_query(self, command_sequence: List[str]) -> int:
        """简单查询 — 不验证 checker(不推荐用于攻击算法主循环)。"""
        from range.execute import execute_in_range
        res = execute_in_range(command_sequence, capture_trace=True)
        if not res.trace_path:
            return 1
        dump = res.trace_path + ".sql"
        try:
            trace_to_pidsmaker(res.trace_path, dump)
        except Exception:
            return 1
        det = self._ensure_detector()
        return int(det.predict(dump))

    def predict_per_node_from_sql(self, sql_path: str) -> List[Dict[str, Any]]:
        """Public 接口:给定已经写好的 SQL CDM dump,直接拿 detector 节点级输出。

        E0 collector 用这个让 7 detector 复用同一份 clean.strace.sql,不再每个
        detector 重跑 docker / strace / convert。GNN 跟 rule detector 都返
        `{"node_index_id": int, "y_pred": int, "score": float, ...}`(Step 3 统一)。
        """
        det = self._ensure_detector()
        return det.predict_per_node(sql_path)


def _extract_path(label: str) -> str:
    """从 PIDSMaker label 抠 exec_path(或 file path / netflow id)当稳定 ID 一部分.

    label 三类:
      "subject /usr/bin/curl curl ..."  → "/usr/bin/curl"
      "file /etc/passwd"                 → "/etc/passwd"
      "netflow 127.0.0.1 3000"          → "127.0.0.1:3000"
    """
    if not label:
        return ""
    parts = label.split(" ", 3)
    if not parts:
        return ""
    ntype = parts[0]
    if ntype == "subject" and len(parts) >= 2:
        return parts[1]
    if ntype == "file" and len(parts) >= 2:
        return parts[1]
    if ntype == "netflow" and len(parts) >= 3:
        return f"{parts[1]}:{parts[2]}"
    return parts[1] if len(parts) >= 2 else ""


def _node_label(nd: Dict[str, Any]) -> str:
    """Return the detector node label, falling back for rule detectors."""
    return nd.get("label") or nd.get("raw_command") or ""


def _gt_keyed_match(nodes_info: List[Dict[str, Any]],
                     gt_keywords: List[str],
                     flagged_only: bool = False) -> List[Dict[str, Any]]:
    """v7 GT 节点提取 — 用 (path, 命中关键词) 当稳定 ID.

    返回每个匹配 = {path, keyword, node_id, label, score, y_pred}.
    flagged_only=True 时只留 y_pred==1 的节点。
    一个节点可命中多个 keyword,各算一行。
    """
    if not gt_keywords:
        return []
    out = []
    for nd in nodes_info:
        if flagged_only and nd.get("y_pred", 0) != 1:
            continue
        label = _node_label(nd)
        path = _extract_path(label)
        for kw in gt_keywords:
            if kw in label:
                out.append({
                    "path": path,
                    "keyword": kw,
                    "node_id": nd.get("node_index_id"),
                    "label": label,
                    "score": float(nd.get("score", 0.0)),
                    "y_pred": int(nd.get("y_pred", 0)),
                })
    return out


def _compute_node_metrics(
    nodes_info: List[Dict[str, Any]],
    gt_keywords: Optional[List[str]] = None,
    baseline_gt_keys: Optional[List[tuple]] = None,
    baseline_gt_avg_score: Optional[float] = None,
):
    """v7 GT 锚定指标(关键词驱动 + baseline-flagged 锁定).

    GT 节点 = (label 含关键词) AND (baseline 时被 detector flagged)。
    稳定 ID = (exec_path, 命中的 keyword) 元组,跨 trace 稳定。

    输入:
      gt_keywords:                scenario.steps[].gt_keywords union
      baseline_gt_keys:           Phase 0 baseline 锁定的 GT ID 列表(每项是 (path, keyword) 元组)
      baseline_gt_avg_score:      baseline 时 GT 节点的平均 score
    输出:gt_persistence + delta_gt_score。传入 baseline_gt_keys 时按 baseline GT
    持久率计算;未传时按当前 GT/attack-node 是否仍 flagged 计算 1.0/0.0。
    """
    flagged = [nd for nd in nodes_info if nd.get("y_pred", 0) == 1]
    flagged_sorted = sorted(flagged, key=lambda nd: -nd.get("score", 0.0))
    score_vec = [float(nd.get("score", 0.0)) for nd in nodes_info]

    top_flagged = [
        {"node": nd.get("node_index_id"), "label": _node_label(nd), "score": float(nd.get("score", 0.0))}
        for nd in flagged_sorted[:5]
    ]
    all_flagged = [
        {"node": nd.get("node_index_id"), "label": _node_label(nd), "score": float(nd.get("score", 0.0))}
        for nd in flagged_sorted
    ]
    max_score = max(score_vec, default=0.0)

    gt_persistence = None
    delta_gt_score = None
    gt_n_matched = None
    gt_n_dropped = None
    gt_nodes_info: List[Dict[str, Any]] = []
    if gt_keywords:
        # 当前 trace 里 (path, keyword) 命中且 flagged 的节点(候选 GT)
        curr_matched = _gt_keyed_match(nodes_info, gt_keywords, flagged_only=True)
        curr_keys = {(m["path"], m["keyword"]) for m in curr_matched}
        gt_nodes_info = curr_matched

        if baseline_gt_keys is not None:
            # 持久率 = baseline GT 中当前还能匹配上的比例
            base_keys = {tuple(k) if not isinstance(k, tuple) else k for k in baseline_gt_keys}
            still = base_keys & curr_keys
            dropped = base_keys - curr_keys
            gt_n_matched = len(curr_matched)
            gt_n_dropped = len(dropped)
            gt_persistence = (len(still) / float(len(base_keys))) if base_keys else None
            if baseline_gt_avg_score is not None and curr_matched:
                curr_avg = sum(m["score"] for m in curr_matched) / len(curr_matched)
                delta_gt_score = baseline_gt_avg_score - curr_avg
        else:
            # 没传 baseline → 用当前 trace 的 GT/attack-node 检测状态作为目标。
            # 有命中即 persistence=1.0;无命中即 0.0,让 reward/early-stop 都是 attack-node 口径。
            gt_n_matched = len(curr_matched)
            gt_n_dropped = 0
            gt_persistence = 1.0 if curr_matched else 0.0

    return {
        "score_vec": score_vec,
        "flagged": flagged,
        "top_flagged": top_flagged,
        "all_flagged": all_flagged,
        "max_score": max_score,
        "gt_persistence": gt_persistence,
        "delta_gt_score": delta_gt_score,
        "gt_n_matched": gt_n_matched,
        "gt_n_dropped": gt_n_dropped,
        "gt_nodes": gt_nodes_info,
    }


def collect_gt_keywords_from_scenario(scenario: Dict[str, Any]) -> List[str]:
    """Collect attack-specific GT markers from scenario steps.

    Generic warmup/homepage markers are deliberately excluded; the attack oracle
    must target attack-bearing nodes rather than common setup traffic.
    """
    kws: List[str] = []
    for st in scenario.get("steps", []):
        for keyword in st.get("gt_keywords", []) or []:
            if keyword not in WARMUP_GT_KEYWORDS:
                kws.append(keyword)
    return kws


def query_with_validation_strict(
    scenario: Dict[str, Any],
    delta_commands: List[str],
    delta_positions: List[int],
    oracle: PIDSOracle,
    baseline_gt_keys: Optional[List[tuple]] = None,
    baseline_gt_avg_score: Optional[float] = None,
    mutated_a0: Optional[List[str]] = None,
    reset: bool = True,
):
    """严格通路:先跑 checker,pass 才送 PIDS。

    v7 GT(关键词 + baseline-flagged 双约束):
      - GT 节点 = scenario.gt_keywords 命中 AND baseline 时被 detector flagged
      - 稳定 ID = (exec_path, 命中的关键词)元组,跨 trace 稳定
      - baseline_gt_keys 从 Phase 0 baseline 拿到(只含 baseline 时 flagged 的)
    """
    from attack.framework.result import QueryResult
    res: AttackExecutionResult = execute_with_checks(
        scenario, delta_commands, delta_positions, capture_trace=True,
        reset=reset,
        mutated_a0=mutated_a0,
    )
    if not res.all_steps_passed or not res.final_attack_succeeded:
        return QueryResult.invalid_(
            failed_step=res.failed_step,
            extra={"trace_path": res.trace_path,
                   "step_results": [r.__dict__ for r in res.step_results]},
        )
    if not res.trace_path or not os.path.exists(res.trace_path):
        return QueryResult.invalid_(failed_step=-1, extra={"reason": "no_trace"})
    dump = res.trace_path + ".sql"
    try:
        trace_to_pidsmaker(res.trace_path, dump)
    except Exception as e:
        return QueryResult.invalid_(failed_step=-1, extra={"reason": f"convert_fail: {e}"})
    det = oracle._ensure_detector()
    nodes_info = det.predict_per_node(dump)
    gt_keywords = collect_gt_keywords_from_scenario(scenario)
    if not gt_keywords:
        return QueryResult.invalid_(
            failed_step=-1,
            extra={"reason": "missing_gt_keywords", "trace_path": res.trace_path, "dump": dump},
        )
    metrics = _compute_node_metrics(nodes_info,
                                     gt_keywords=gt_keywords,
                                     baseline_gt_keys=baseline_gt_keys,
                                     baseline_gt_avg_score=baseline_gt_avg_score)
    gt_flagged_nodes = len({m.get("node_id") for m in metrics["gt_nodes"] if m.get("node_id") is not None})
    y = 1 if gt_flagged_nodes > 0 else 0
    return QueryResult.valid_(
        y=y,
        score_vec=metrics["score_vec"],
        gt_persistence=metrics["gt_persistence"],
        delta_gt_score=metrics["delta_gt_score"],
        gt_n_dropped=metrics["gt_n_dropped"],
        extra={
            "trace_path": res.trace_path,
            "dump": dump,
            "n_nodes": len(nodes_info),
            "n_flagged": len(metrics["flagged"]),
            "max_score": metrics["max_score"],
            "top_flagged": metrics["top_flagged"],
            "all_flagged": metrics["all_flagged"],
            "gt_n_matched": metrics["gt_n_matched"],
            "gt_flagged_nodes": gt_flagged_nodes,
            "gt_nodes": metrics["gt_nodes"],
            "attack_detected": bool(gt_flagged_nodes > 0),
            "oracle_target": "gt_attack_node",
        },
    )


def _scenario_raw(scenario: Any) -> Dict[str, Any]:
    if isinstance(scenario, dict):
        return scenario
    raw = getattr(scenario, "raw", None)
    if isinstance(raw, dict):
        return raw
    raise TypeError(f"expected scenario dict or AttackScenario, got {type(scenario)!r}")


def _load_or_collect_signature(
    scenario: Dict[str, Any],
    *,
    signature_root: Optional[Path],
    reset: bool,
) -> Dict[str, Any]:
    from range.mixed_workload import collect_attack_only_signature
    from range.node_gt import load_signature_sets

    scenario_id = scenario["scenario_id"]
    root = Path(signature_root or (PROJECT_ROOT / "experiments/E0_detection/test_data"))
    attack_only_dir = root / scenario_id / "attack_only"
    signature_path = attack_only_dir / "attack_gt_signature.json"
    if signature_path.exists():
        return {
            "signature_path": signature_path,
            "signature_sets": load_signature_sets(signature_path),
            "reused": True,
        }
    collected = collect_attack_only_signature(
        scenario,
        attack_only_dir,
        reset_container_before=reset,
    )
    return {
        "signature_path": collected["signature_path"],
        "signature_sets": collected["signature_sets"],
        "reused": False,
    }


def query_with_validation_mixed(
    scenario: Any,
    delta_commands: List[str],
    delta_positions: List[int],
    *,
    detector_name: str = "threatrace_g1g2",
    oracle: Optional[PIDSOracle] = None,
    out_root: Optional[Path] = None,
    signature_root: Optional[Path] = None,
    warmup_sec: int = 10,
    cooldown_sec: int = 20,
    benign_trace_dir: Optional[str | Path] = None,
    benign_seed: int = 0,
    reset: bool = True,
):
    """E0-compatible mixed-workload attack oracle.

    This is the paper-facing query path for E1/E2:
    cached benign background + freshly executed marker(A0⊕δ) + strace + SQL +
    detector + E0-style node-level GT/metrics.  δ is evaluated as part of the
    same full SQL graph; if it is flagged outside attack GT, it naturally
    contributes to FP/MCC.
    """
    from attack.framework.result import QueryResult
    from range.cached_mixed import collect_cached_mixed_workload
    from range.node_metrics import _sql_node_catalog, compute_metrics

    scenario_raw = _scenario_raw(scenario)
    scenario_id = scenario_raw["scenario_id"]
    query_id = uuid.uuid4().hex[:12]
    outdir = Path(out_root or "/tmp/pids_attack_queries") / f"{scenario_id}_{query_id}"

    try:
        signature = _load_or_collect_signature(
            scenario_raw,
            signature_root=signature_root,
            reset=reset,
        )
        artifact = collect_cached_mixed_workload(
            scenario_raw,
            outdir,
            reset_container_before=reset,
            attack_gt_signature_sets=signature["signature_sets"],
            attack_gt_signature_path=signature["signature_path"],
            delta_commands=list(delta_commands or []),
            delta_positions=list(delta_positions or []),
            benign_trace_dir=benign_trace_dir,
            benign_seed=benign_seed,
        )
    except Exception as exc:
        return QueryResult.invalid_(
            failed_step=-1,
            extra={
                "reason": f"mixed_collect_fail: {exc}",
                "oracle_target": "mixed_node_level",
                "outdir": str(outdir),
            },
        )

    if not artifact.get("all_steps_passed") or not artifact.get("final_attack_succeeded"):
        return QueryResult.invalid_(
            failed_step=artifact.get("failed_step"),
            extra={
                "reason": "checker_or_final_attack_failed",
                "oracle_target": "mixed_node_level",
                "outdir": str(outdir),
                "trace_path": str(artifact.get("clean_strace")),
                "sql_path": str(artifact.get("clean_sql")),
                "gt_json": str(artifact.get("gt_json")),
                "all_steps_passed": artifact.get("all_steps_passed"),
                "final_attack_succeeded": artifact.get("final_attack_succeeded"),
                "delta_command_success": artifact.get("delta_command_success"),
                "delta_outputs": artifact.get("delta_outputs"),
                "attack_step_results": artifact.get("attack_step_results") or [],
            },
        )

    det_oracle = oracle or PIDSOracle(detector_name=detector_name)
    sql_path = Path(artifact["clean_sql"])
    nodes_info = det_oracle.predict_per_node_from_sql(str(sql_path))
    node_catalog = _sql_node_catalog(sql_path)
    node_metrics, evidence = compute_metrics(nodes_info, artifact["gt"], node_catalog)
    tp = int(node_metrics.get("tp") or 0)
    gt_count = int(node_metrics.get("gt_count") or 0)
    y = 1 if tp > 0 else 0
    gt_persistence = (tp / gt_count) if gt_count else 0.0
    score_vec = [
        float(nd.get("score", 0.0))
        for nd in nodes_info
        if nd.get("score") is not None
    ]

    return QueryResult.valid_(
        y=y,
        score_vec=score_vec,
        gt_persistence=gt_persistence,
        delta_gt_score=None,
        gt_n_dropped=max(0, gt_count - tp),
        extra={
            "oracle_target": "mixed_node_level",
            "outdir": str(outdir),
            "raw_strace": str(artifact.get("raw_strace")),
            "attack_raw_strace": str(artifact.get("attack_raw_strace")),
            "trace_path": str(artifact.get("clean_strace")),
            "dump": str(sql_path),
            "sql_path": str(sql_path),
            "gt_json": str(artifact.get("gt_json")),
            "signature_path": str(signature["signature_path"]),
            "signature_reused": bool(signature.get("reused")),
            "mixed_mode": artifact.get("mixed_mode"),
            "benign_trace": artifact.get("benign_trace"),
            "gt": artifact["gt"],
            "node_metrics": node_metrics,
            "evidence": evidence,
            "n_nodes": node_metrics.get("all_nodes_count"),
            "n_flagged": node_metrics.get("flagged_count"),
            "gt_count": gt_count,
            "gt_flagged_nodes": tp,
            "attack_detected": bool(tp > 0),
            "delta_command_success": artifact.get("delta_command_success"),
            "delta_outputs": artifact.get("delta_outputs"),
            "all_steps_passed": artifact.get("all_steps_passed"),
            "final_attack_succeeded": artifact.get("final_attack_succeeded"),
            "failed_step": artifact.get("failed_step"),
            "attack_step_results": artifact.get("attack_step_results") or [],
        },
    )
