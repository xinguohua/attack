#!/usr/bin/env python3
"""attack_scenarios.py — 验证 attack_sequences/*.json 真的解开了对应 Juice-Shop challenge。

权威验证(不靠"响应里 grep 字符串"):
  1. 重启 pids_range 容器,所有 challenge.solved 回到 false
  2. 对每个 JSON 顺序跑全部 steps(docker exec bash -c)
  3. 跑完后查 GET /api/Challenges,检查目标 challenge 的 solved 字段
  4. 报告:每个 JSON 的目标 challenge 是否真被 server 标记为 solved

跑法:  conda run -n mimicattack python scripts/validation/attack_scenarios.py
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ATTACK_DIR = ROOT / "data" / "attack_sequences"
CONTAINER = "pids_range"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Verify Juice Shop A0 scenario JSON files really solve their target challenges."
    )
    return ap.parse_args()


def docker_curl_api(path: str, timeout: int = 10) -> dict | None:
    """在容器内查 Juice-Shop API,返回解析的 JSON。"""
    r = subprocess.run(
        ["docker", "exec", CONTAINER, "curl", "-s", f"http://localhost:3000{path}"],
        capture_output=True, text=True, timeout=timeout,
    )
    if r.returncode != 0 or not r.stdout:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def get_challenges_status() -> dict[str, dict]:
    """返回 {key: {name, solved}}。"""
    d = docker_curl_api("/api/Challenges/")
    if not d:
        return {}
    return {ch["key"]: {"name": ch["name"], "solved": ch.get("solved")}
            for ch in d.get("data", [])}


def restart_juiceshop_in_container() -> bool:
    """容器内 pkill node + nohup 重启,等 200。比 docker restart 快。"""
    print("[reset] 容器内 pkill node 重启 juice-shop...")
    subprocess.run(["docker", "exec", CONTAINER, "pkill", "-9", "-f", "node"],
                   capture_output=True, timeout=10)
    time.sleep(1)
    subprocess.Popen(["docker", "exec", "-d", CONTAINER, "bash", "-c",
                      "cd /opt/juice-shop && nohup node build/app.js > /var/log/juice-shop.log 2>&1 &"])
    for i in range(60):
        r = subprocess.run(
            ["docker", "exec", CONTAINER, "curl", "-sf", "-o", "/dev/null",
             "-w", "%{http_code}", "http://localhost:3000/"],
            capture_output=True, text=True, timeout=5,
        )
        if r.stdout.strip() == "200":
            print(f"[reset] juice-shop ✅ 200 after {i}s")
            return True
        time.sleep(1)
    print("[reset] ❌ juice-shop 60s 没起来")
    return False


def run_steps(scenario: dict) -> list[tuple[int, str, bool]]:
    """顺序跑所有 steps,返回 [(step_id, command_short, ok), ...]。"""
    out = []
    for step in scenario["steps"]:
        cmd = step["command"]
        sid = step["step_id"]
        try:
            r = subprocess.run(
                ["docker", "exec", CONTAINER, "bash", "-c", cmd],
                capture_output=True, text=True, timeout=15,
            )
            ok = r.returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
        out.append((sid, cmd[:60], ok))
    return out


def main():
    parse_args()

    # 容器探活
    r = subprocess.run(["docker", "ps", "--filter", f"name={CONTAINER}", "--format", "{{.Status}}"],
                       capture_output=True, text=True, timeout=10)
    if not r.stdout.strip().startswith("Up"):
        sys.exit(f"[abort] {CONTAINER} 容器没在跑")

    # 全局重启 juice-shop,所有 challenge state 归零
    if not restart_juiceshop_in_container():
        sys.exit("[abort] juice-shop 重启失败")

    # 拿 baseline solved 状态
    print("\n[baseline] 拿初始 challenge 状态...")
    baseline = get_challenges_status()
    if not baseline:
        sys.exit("[abort] 拿不到 /api/Challenges")
    n_solved_init = sum(1 for c in baseline.values() if c["solved"])
    print(f"  baseline: {n_solved_init}/{len(baseline)} 已 solved (理想应该 0)")

    # 加载所有 JSON
    json_files = sorted(ATTACK_DIR.glob("*.json"))
    print(f"\n[攻击] 顺序跑 {len(json_files)} 个 scenario\n")

    results = []
    for jf in json_files:
        with open(jf) as f:
            scenario = json.load(f)
        scenario_id = scenario["scenario_id"]
        # scenario_id → Juice-Shop challenge key 映射(source 字段精简后从 scenario_id 推)
        SCENARIO_TO_KEY = {
            "juiceshop_login_admin_sqli": "loginAdminChallenge",
            "juiceshop_login_bender_sqli": "loginBenderChallenge",
            "juiceshop_login_jim_sqli": "loginJimChallenge",
            "juiceshop_db_schema_union_sqli": "dbSchemaChallenge",
            "juiceshop_directory_listing_ftp": "directoryListingChallenge",
            "juiceshop_register_admin_mass_assignment": "registerAdminChallenge",
            "juiceshop_redirect_open": "redirectCryptoCurrencyChallenge",
            "juiceshop_basket_idor": "basketAccessChallenge",
            "juiceshop_exposed_metrics": "exposedMetricsChallenge",
            "juiceshop_weak_password_admin": "weakPasswordChallenge",
        }
        key = SCENARIO_TO_KEY.get(scenario_id)

        print(f"━━━ {jf.name} ━━━")
        print(f"  target challenge key: {key or '(none)'}")
        if key and key in baseline:
            print(f"  before attack: solved={baseline[key]['solved']}")

        # 跑 steps
        step_results = run_steps(scenario)
        for sid, cmd_short, ok in step_results:
            sym = "✅" if ok else "❌"
            print(f"    {sym} step {sid}: {cmd_short}...")

        # 跑完查 challenge 状态
        time.sleep(0.5)  # 给 server 一点时间标记
        post = get_challenges_status()
        if key and key in post:
            now_solved = post[key]["solved"]
            was_solved = baseline.get(key, {}).get("solved", False)
            flipped = now_solved and not was_solved
            print(f"  after attack: solved={now_solved}  {'  (flipped false→true ✅ 真解开了)' if flipped else '  (没翻 ❌)' if not now_solved else '  (本来就 solved,无变化)'}")
            results.append({
                "scenario": scenario_id, "key": key, "name": post[key]["name"],
                "solved_before": was_solved, "solved_after": now_solved, "flipped": flipped,
                "all_steps_ok": all(ok for _, _, ok in step_results),
            })
        elif key is None:
            print(f"  (无 target key,跳过 solved 验证)")
            results.append({"scenario": scenario_id, "key": None, "all_steps_ok": all(ok for _, _, ok in step_results)})
        else:
            print(f"  ⚠️  key {key!r} 不在 /api/Challenges,只能看响应")
            results.append({"scenario": scenario_id, "key": key, "name": None,
                           "solved_before": None, "solved_after": None, "flipped": None,
                           "all_steps_ok": all(ok for _, _, ok in step_results)})
        print()

    # 总结
    print("=" * 70)
    print("  汇总")
    print("=" * 70)
    print(f"{'scenario_id':45s}  {'key':35s}  flipped  steps_ok")
    flipped_count = 0
    for r in results:
        flipped_str = "✅" if r.get("flipped") else ("(已solved)" if r.get("solved_before") else "❌") if r.get("key") else "-"
        steps_ok_str = "✅" if r.get("all_steps_ok") else "❌"
        print(f"{r['scenario']:45s}  {(r.get('key') or '-')[:35]:35s}  {flipped_str:9s}  {steps_ok_str}")
        if r.get("flipped"):
            flipped_count += 1
    print(f"\n真解开 challenge: {flipped_count} / {len(results)}")


if __name__ == "__main__":
    main()
