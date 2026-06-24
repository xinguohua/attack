"""graph_semantics — Phase 1 关键端到端验证。

链路:
  build_g_from_a0(scenario.json) → graph_to_shell(G_0) → docker exec
  → execute_with_checks → final_attack_succeeded ?

Pass 标准:`final_attack_succeeded=True` 证明 G_0 → shell 翻译没丢攻击语义(R1 严守)。
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from cmd_graph.builder import build_g_from_a0
from cmd_graph.translator import graph_to_shell
from range.checker import execute_with_checks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    help="scenarios/juiceshop/XX.json 路径")
    args = ap.parse_args()

    scenario_path = Path(args.scenario)
    if not scenario_path.is_absolute():
        scenario_path = PROJECT_ROOT / scenario_path
    with open(scenario_path) as f:
        scenario = json.load(f)

    print(f"[1/3] build_g_from_a0({scenario_path.name})")
    g = build_g_from_a0(scenario_path)
    print(f"      → {g}")

    print(f"[2/3] graph_to_shell(G_0)")
    shell_seq = graph_to_shell(g)
    print(f"      → {len(shell_seq)} 条命令:")
    for i, c in enumerate(shell_seq):
        c_short = c if len(c) <= 80 else c[:77] + "..."
        print(f"        [{i}] {c_short}")

    # 对比 raw scenario.steps[*].command
    raw_cmds = [s["command"] for s in scenario["steps"]]
    if shell_seq != raw_cmds:
        print("\n✗ shell_seq != raw steps[*].command,builder/translator round-trip 不忠实")
        print(f"  shell_seq: {shell_seq}")
        print(f"  raw:       {raw_cmds}")
        sys.exit(1)
    print(f"      ✓ shell_seq == raw scenario steps(byte-identical)")

    print(f"[3/3] execute_with_checks(scenario)  # 无 δ 扰动,投 docker 跑")
    # 不带 δ 跑 — execute_with_checks 默认就是跑 A_0
    result = execute_with_checks(scenario, delta_commands=[], delta_positions=[],
                                  capture_trace=False)
    print(f"      all_steps_passed     = {result.all_steps_passed}")
    print(f"      final_attack_succeeded = {result.final_attack_succeeded}")
    if result.failed_step is not None:
        print(f"      failed_step          = {result.failed_step}")

    if result.all_steps_passed and result.final_attack_succeeded:
        print(f"\n✓ Phase 1 Validation (4): G_0 → shell → docker → checker pass 证明 G 语义忠实")
        sys.exit(0)
    else:
        print(f"\n✗ Phase 1 Validation (4) FAIL")
        sys.exit(2)


if __name__ == "__main__":
    main()
