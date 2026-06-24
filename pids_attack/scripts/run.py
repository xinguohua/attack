#!/usr/bin/env python3
"""run.py — SafeMimic canonical CLI.

Two public modules:
    detect  detector data collection, training, diagnostics, and E0
    attack  attack-time smoke query and GRABNEL attack runs

Examples:
    python pids_attack/scripts/run.py detect e0
    python pids_attack/scripts/run.py attack run --scenario 01 --detector magic
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CONTAINER = os.environ.get("PIDS_RANGE_CONTAINER", "pids_range")
PG_CONTAINER = os.environ.get("PIDS_PG_CONTAINER", "pids_postgres")
TRACE_DIR = ROOT / "results" / "demo_traces"


def configure_trace_dir() -> None:
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    os.environ["PIDS_RANGE_SYSDIG_DIR"] = str(TRACE_DIR)


def banner(stage: str, title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {stage} · {title}")
    print("=" * 70)


def short(s: str, n: int = 90) -> str:
    s = s.replace("\n", "  ")
    return s if len(s) <= n else s[:n] + "..."


# =====================================================================
# PART A · 环境 + 容器
# =====================================================================

def stage_0_preflight() -> None:
    """检查 docker daemon、镜像、scenario 数据是否齐全。失败立刻 abort。"""
    banner("STAGE 0", "preflight: docker / images / scenario JSON")

    r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
    if r.returncode != 0:
        sys.exit("[abort] docker daemon 不可达 → 启动 Docker Desktop")
    print("  docker daemon ✅")

    r = subprocess.run(["docker", "image", "inspect", "pids_range:latest"],
                       capture_output=True, timeout=10)
    if r.returncode != 0:
        print("  pids_range image 不存在 → 自动 build(5–15 min)...")
        rb = subprocess.run(["docker", "build", "-t", "pids_range:latest", str(ROOT / "range")],
                            timeout=1800)
        if rb.returncode != 0:
            sys.exit("[abort] docker build 失败")
    print("  pids_range image ✅")

    sc_dir = ROOT / "scenarios" / "juiceshop"
    sc_files = sorted(sc_dir.glob("*.json"))
    if len(sc_files) == 0:
        sys.exit(f"[abort] 没找到 scenario:{sc_dir}")
    print(f"  scenario JSON ✅  ({len(sc_files)} 个)")


def stage_1_containers(skip_setup: bool) -> None:
    """启动 pids_postgres 和 pids_range 容器(idempotent),等 juice-shop 200。"""
    banner("STAGE 1", "bring up containers (postgres + pids_range)")

    if skip_setup:
        print("  --skip-setup,跳过容器启动")
    else:
        for name, image, args in [
            (PG_CONTAINER, "postgres:14",
             ["-e", "POSTGRES_USER=pids", "-e", "POSTGRES_PASSWORD=pids",
              "-e", "POSTGRES_DB=pids_attack", "-p", "5432:5432"]),
            (CONTAINER, "pids_range:latest",
             ["--privileged", "-p", "3000:3000"]),
        ]:
            r = subprocess.run(["docker", "ps", "-a", "--filter", f"name=^{name}$",
                                "--format", "{{.Status}}"], capture_output=True, text=True)
            status = r.stdout.strip()
            if status.startswith("Up"):
                print(f"  {name}: 已在运行")
                continue
            if status:
                print(f"  {name}: {status} → docker start")
                subprocess.run(["docker", "start", name], capture_output=True, timeout=30)
            else:
                print(f"  {name}: 不存在 → docker run")
                subprocess.run(
                    ["docker", "run", "-d", "--name", name, *args, image],
                    capture_output=True, timeout=60,
                )

    # 等 juice-shop 起来
    for i in range(60):
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "http://localhost:3000/"], capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "200":
            print(f"  juice-shop ✅  (HTTP 200 after {i}s)")
            break
        time.sleep(1)
    else:
        sys.exit("[abort] juice-shop 60s 内没起来 → docker exec pids_range cat /var/log/juice-shop.log")

    # 容器内 strace 自检(strace 是采日志的核心,镜像里必须装好)
    r = subprocess.run(["docker", "exec", CONTAINER, "strace", "--version"],
                       capture_output=True, text=True, timeout=10)
    ver = (r.stdout or r.stderr).strip().split("\n")[0]
    if r.returncode != 0 or "strace" not in ver:
        sys.exit("[abort] strace 不在容器内可用 → 重 build:docker build -t pids_range:latest range/")
    print(f"  strace in container ✅  ({ver})")


# =====================================================================
# PART B · 单次 pipeline 走查(固定 δ,纯粹看 5 层 pipeline)
# =====================================================================

def stage_2_load_scenario() -> dict:
    """从 JSON 读 A0 攻击场景(取目录里第一个,文件名按字典序排)。"""
    banner("STAGE 2", "load scenario JSON (A0)")
    sc_dir = ROOT / "scenarios" / "juiceshop"
    sc_files = sorted(sc_dir.glob("*.json"))
    if not sc_files:
        sys.exit(f"[abort] {sc_dir} 下没找到 JSON")
    sc_path = sc_files[0]
    print(f"  loading: {sc_path.name}")
    with open(sc_path) as f:
        scenario = json.load(f)
    print(f"  scenario_id = {scenario['scenario_id']}")
    print(f"  attack_type = {scenario.get('attack_type')}")
    for s in scenario["steps"]:
        print(f"    [{s['step_id']}] {short(s['command'], 100)}")
        print(f"        checker = {s['checker']}")
    return scenario


def stage_3_execute_and_trace(scenario: dict):
    """range 层:容器执行 A0(纯原始攻击,无 δ)+ strace 采集 + checker 验证。
    ★ δ 扰动是 attack mode 的事;pipeline 只看 PIDS 对原始攻击的判定。
    """
    banner("STAGE 3", "execute_with_checks: 容器跑原始攻击 A0 + strace + checker")
    from range.checker import execute_with_checks
    t0 = time.time()
    res = execute_with_checks(
        scenario=scenario, delta_commands=[], delta_positions=[],
        capture_trace=True, reset=True,
    )
    dt = time.time() - t0
    print(f"  耗时              = {dt:.1f}s")
    print(f"  all_steps_passed  = {res.all_steps_passed}")
    print(f"  final_attack_succeeded = {res.final_attack_succeeded}")
    print(f"  trace_path        = {res.trace_path}")
    if res.trace_path and os.path.exists(res.trace_path):
        print(f"  trace 大小        = {os.path.getsize(res.trace_path)} bytes")
    print(f"  step_results:")
    for r in res.step_results:
        ok = "✅" if r.success else "❌"
        print(f"    {ok} step {r.step_id}  expected={r.expected!r}  actual={short(str(r.actual), 60)!r}")
    if not (res.all_steps_passed and res.final_attack_succeeded):
        sys.exit("[abort] checker 没全过,后续 STAGE 跳过(检查容器是否 up)")
    return res


def stage_5_convert_to_cdm(trace_path: str):
    """strace text → CDM 节点边 → SQL dump。"""
    banner("STAGE 5", "trace_to_pidsmaker: strace → CDM 图 → SQL dump")
    from range.converter import trace_to_pidsmaker, build_cdm_graph_from_strace
    sql_path = trace_path + ".sql"
    trace_to_pidsmaker(trace_path, sql_path)
    g = build_cdm_graph_from_strace(trace_path)
    node_types: dict[str, int] = {}
    for n in g.nodes.values():
        node_types[n.node_type] = node_types.get(n.node_type, 0) + 1
    edge_types: dict[str, int] = {}
    for e in g.events:
        edge_types[e.event_type] = edge_types.get(e.event_type, 0) + 1
    print(f"  sql_path  = {sql_path}")
    print(f"  SQL 行数  = {sum(1 for _ in open(sql_path))}")
    print(f"  CDM 节点  = {node_types}")
    print(f"  CDM 边    = {edge_types}")
    return sql_path


def stage_6_detector_predict(sql_path: str, detector_name: str = "orthrus") -> int:
    """detector 拿 CDM SQL 推 y(攻击前的初始推理)."""
    banner("STAGE 6", "_LocalDetector.predict → y ∈ {0,1}  (初始状态,攻击前)")
    from detection.pidsmaker import _LocalDetector
    detector = _LocalDetector(detector_name=detector_name, model_path=None)

    nodes = detector.predict_per_node(sql_path)
    flagged_nodes = [nd for nd in nodes if nd["y_pred"] == 1]
    y = 1 if flagged_nodes else 0

    print(f"  detector_name = {detector_name}")
    print(f"  graph         = {len(nodes)} nodes,  flagged = {len(flagged_nodes)}")
    print(f"  y (初始)      = {y}  ({'benign' if y == 0 else 'malicious'})")
    if flagged_nodes:
        # 按 score 降序列出被标 attack 的 node(label / score)
        flagged_nodes.sort(key=lambda nd: nd["score"], reverse=True)
        print(f"  被检测到的 {len(flagged_nodes)} 个 node(按 score 降序):")
        for i, nd in enumerate(flagged_nodes, 1):
            print(f"    [{i:>2}] score={nd['score']:8.3f}  label={nd['label']!r}")
    return y


# =====================================================================
# attack smoke-query mode
# =====================================================================

def smoke_query_main(argv: Optional[Sequence[str]] = None):
    configure_trace_dir()
    ap = argparse.ArgumentParser(
        prog="scripts/run.py attack smoke-query",
        description="Run the 5-layer A0 pipeline smoke path.",
    )
    ap.add_argument("--skip-setup", action="store_true",
                    help="跳过 STAGE 1 容器启动(确定容器已 up 时用)")
    ap.add_argument("--detector", default="orthrus",
                    choices=("orthrus", "kairos", "magic", "flash",
                             "threatrace", "nodlink", "rcaid", "velox"),
                    help="STAGE 6 用哪个 detector(默认 orthrus)")
    args = ap.parse_args(argv)

    # PART A
    stage_0_preflight()
    stage_1_containers(skip_setup=args.skip_setup)

    # PART B — 跑原始攻击 + 看 PIDS 初始判定
    scenario = stage_2_load_scenario()
    res = stage_3_execute_and_trace(scenario)
    sql_path = stage_5_convert_to_cdm(res.trace_path)
    y = stage_6_detector_predict(sql_path, detector_name=args.detector)

    print("\n" + "=" * 70)
    print("  ✓ 全部完成")
    print("=" * 70)
    print(f"  trace 文件:   {res.trace_path}")
    print(f"  CDM SQL:     {sql_path}")
    print(f"  y(初始):    {y}")
    print(f"\n  下一步 debug:")
    print(f"    less {res.trace_path}        # 看 syscall 流")
    print(f"    less {sql_path}              # 看 CDM 节点边")
    print(f"  在 STAGE 3/5/6 行号设断点,F7 进入函数单步")
    return {
        "trace_path": res.trace_path,
        "sql_path": sql_path,
        "y": y,
    }


# =====================================================================
# main dispatch
# =====================================================================

def detect_main(argv: Optional[Sequence[str]] = None):
    raw = list([] if argv is None else argv)
    if not raw or raw[0] in {"-h", "--help"}:
        print("usage: scripts/run.py detect <command> ...\n")
        print("Commands:")
        print("  collect-benign      collect benign training traces")
        print("  collect-attack      collect attack traces")
        print("  train-gnn           train PIDSMaker GNN detectors")
        print("  train-rules         train G1/G2/G1G2 rule detectors")
        print("  eval-gnn            evaluate PIDSMaker GNN detectors")
        print("  e0                  run E0 detection baseline")
        print("  audit               run detection pipeline audit")
        print("  threshold-sweep     sweep detector thresholds")
        return None

    cmd, rest = raw[0], raw[1:]
    if cmd == "collect-benign":
        from detection.collect import collect_benign_main

        return collect_benign_main(rest)
    if cmd == "collect-attack":
        from detection.collect import collect_attack_main

        return collect_attack_main(rest)
    if cmd == "train-gnn":
        from detection.pidsmaker import train_main

        return train_main(rest)
    if cmd == "train-rules":
        from detection.rules import train_rules_main

        return train_rules_main(rest)
    if cmd == "eval-gnn":
        from detection.pidsmaker import eval_main

        return eval_main(rest)
    if cmd == "e0":
        from experiments.E0_detection.run import main as e0_main

        return e0_main(rest)
    if cmd == "audit":
        from detection.diagnostics import audit_main

        return audit_main(rest)
    if cmd == "threshold-sweep":
        from detection.diagnostics import threshold_sweep_main

        return threshold_sweep_main(rest)
    sys.exit(f"[abort] unknown detect command: {cmd}")


def attack_main(argv: Optional[Sequence[str]] = None):
    raw = list([] if argv is None else argv)
    if not raw or raw[0] in {"-h", "--help"}:
        print("usage: scripts/run.py attack <command> ...\n")
        print("Commands:")
        print("  smoke-query         run one real A0 query through range -> detector")
        print("  run                 run GRABNEL attack")
        return None

    cmd, rest = raw[0], raw[1:]
    if cmd == "smoke-query":
        return smoke_query_main(rest)
    if cmd == "run":
        configure_trace_dir()
        from attack.grabnel_cmd.runner import main as run_attack

        return run_attack(rest, prog="scripts/run.py attack run")
    sys.exit(f"[abort] unknown attack command: {cmd}")


def main(argv: Optional[Sequence[str]] = None):
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "detect":
        return detect_main(raw[1:])
    if raw and raw[0] == "attack":
        return attack_main(raw[1:])
    if raw and raw[0] in {"-h", "--help"}:
        print("usage: scripts/run.py [detect|attack] ...\n")
        print("Common:")
        print("  scripts/run.py detect e0")
        print("  scripts/run.py attack smoke-query")
        print("  scripts/run.py attack run --scenario 01 --detector magic")
        print("\nFor mode-specific options:")
        print("  scripts/run.py detect --help")
        print("  scripts/run.py attack --help")
        return None
    sys.exit("[abort] explicit mode required: scripts/run.py detect|attack ...")


if __name__ == "__main__":
    main()
