"""validation.py — 干净环境（无 δ）跑 A0，验证所有 checker 通过。"""
from __future__ import annotations
import json
import os
from typing import Any, Dict

from .checker import execute_with_checks


def validate_scenario_checkers(scenario: Dict[str, Any], capture_trace: bool = False) -> bool:
    """在干净环境执行 A0（无 δ），验证所有 checker + final_attack_check 都通过。"""
    res = execute_with_checks(scenario, delta_commands=[], delta_positions=[], capture_trace=capture_trace)
    return res.all_steps_passed and res.final_attack_succeeded


def validate_scenario_file(path: str) -> bool:
    with open(path) as f:
        scenario = json.load(f)
    return validate_scenario_checkers(scenario)


def validate_all_scenarios(scenarios_dir: str) -> Dict[str, bool]:
    out: Dict[str, bool] = {}
    for fn in sorted(os.listdir(scenarios_dir)):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(scenarios_dir, fn)
        try:
            ok = validate_scenario_file(path)
        except Exception as e:
            print(f"[validate] {fn}: error {e}")
            ok = False
        out[fn] = ok
        print(f"[validate] {fn}: {'PASS' if ok else 'FAIL'}")
    return out


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scenarios/juiceshop"
    validate_all_scenarios(target)
