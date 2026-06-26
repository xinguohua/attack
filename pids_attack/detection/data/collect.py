"""collect_benign.py — yml-driven 单容器 30min benign trace 采集。

读 detection/data/benign_collection_plan.yml,按 plan 编排:
  1. 校验 plan 中所有命令 from candidate_pool.txt
  2. 起 pids_benign 容器
  3. 启 N 个 daemon(yml.daemons,后台 while-loop)
  4. dump /proc 快照(yml.proc_snapshot.before_strace)
  5. 起 strace(yml.strace)
  6. 30min 内按 yml.scenarios.trigger 策略随机触发 scenario
  7. 停 strace + daemon
  8. docker cp 出来 + STAGE 5 转 SQL
"""
import argparse
import os
import random
import re
import subprocess
import sys
import time
import uuid

import yaml

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

from range.converter import trace_to_pidsmaker

PLAN_PATH = os.path.join(PROJECT_ROOT, "detection", "data", "benign_collection_plan.yml")


# --------- 1. 加载 + 校验 plan ---------

def load_plan(plan_path: str) -> dict:
    with open(plan_path) as f:
        plan = yaml.safe_load(f)
    validate_plan_against_pool(plan)
    return plan


def validate_plan_against_pool(plan: dict) -> None:
    """yml.validation 规则:所有 daemon / scenario 命令必须 from candidate_pool。"""
    pool_path = os.path.join(PROJECT_ROOT, plan["validation"]["command_pool_file"].lstrip("/"))
    # benign_collection_plan.yml 用相对路径 "shared/candidate_pool.txt",我们要加 PROJECT_ROOT
    if not os.path.exists(pool_path):
        # try literal path from yml
        pool_path = plan["validation"]["command_pool_file"]
    pool_cmds = set()
    with open(pool_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cmd = re.split(r'\s+#', line)[0].strip()
            pool_cmds.add(cmd)
    fails = []
    for d in plan["daemons"]:
        for c in d["commands"]:
            if c not in pool_cmds:
                fails.append(f"daemon {d['id']}: {c}")
    for s in plan["scenarios"]["pool"]:
        for slot in s["slots"]:
            for c in slot["candidates"]:
                if c not in pool_cmds:
                    fails.append(f"scenario {s['id']}.{slot['name']}: {c}")
    if fails:
        raise RuntimeError(f"plan 命令不在 pool({len(fails)} 条):\n  " + "\n  ".join(fails[:20]))
    if len(plan["daemons"]) != 7:
        raise RuntimeError(f"daemon count {len(plan['daemons'])} != 7")
    if len(plan["scenarios"]["pool"]) != 10:
        raise RuntimeError(f"scenario count {len(plan['scenarios']['pool'])} != 10")
    print(f"[validate] OK: {len(plan['daemons'])} daemons, "
          f"{len(plan['scenarios']['pool'])} scenarios, all cmds in pool ({len(pool_cmds)} entries)")


# --------- 2. 容器 / daemon / strace 编排 ---------

def start_container(plan: dict, name_override: str = None) -> str:
    c = plan["container"]
    name = name_override or c["name"]
    # 复用现有 image(pids_range:latest);如已有同名容器先删
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    cmd = ["docker", "run", "-d", "--name", name]
    for cap in c.get("cap_add", []):
        cmd += [f"--cap-add={cap}"]
    cmd += [c["image"]]
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.returncode != 0:
        raise RuntimeError(f"docker run failed: {cp.stderr}")
    # 等 juice-shop ready
    timeout = c.get("juice_shop_ready_timeout_sec", 60)
    for _ in range(timeout):
        cp = subprocess.run(
            ["docker", "exec", name, "curl", "-sf", "-o", "/dev/null",
             "http://localhost:3000/"],
            capture_output=True, timeout=5,
        )
        if cp.returncode == 0:
            print(f"[container] {name} juice-shop ready")
            return name
        time.sleep(1)
    raise RuntimeError(f"juice-shop in {name} not ready in {timeout}s")


def build_orchestrator_script(plan: dict) -> str:
    """生成容器内执行的 orchestrator.sh,strace 直接 fork 这个脚本所有 daemon + scenario 都在 strace 子树下。"""
    cfg = plan["scenarios"]["trigger"]
    total = plan["collection"]["total_duration_sec"]
    end_buf = cfg["end_buffer_sec"]
    daemons_block = []
    for d in plan["daemons"]:
        cmds = "; ".join(d["commands"])
        daemons_block.append(
            f'(sleep {d["phase_offset_sec"]}; '
            f'while true; do {cmds}; sleep {d["period_sec"]}; done) &'
        )
    daemons_block.append('DAEMONS=$!')
    # scenario 触发循环 — bash 内随机选 scenario + slot
    # 我们把 scenario 池作为 bash here-docs,按 trigger 策略随机
    scenarios_json = []
    for s in plan["scenarios"]["pool"]:
        slots_cmds = []
        for slot in s["slots"]:
            # 用 |||| 分隔候选,bash 里 split 后随机
            slots_cmds.append("||||".join(slot["candidates"]))
        # 一个 scenario 是若干 slot 用 ||SLOT|| 分隔
        scenarios_json.append("||SLOT||".join(slots_cmds))
    # 用 bash array 存 scenario,每条 || 分隔 slot
    scen_array = "(\n  " + "\n  ".join(f"'{s}'" for s in scenarios_json) + "\n)"

    return f"""#!/bin/bash
set +e
# === Layer 2: 7 daemons (background while-loops) ===
{chr(10).join(daemons_block)}

# === Layer 3: scenario trigger loop ===
SCENARIOS={scen_array}
T0=$(date +%s)
NEXT_AT=$((T0 + RANDOM % {cfg['first_at_sec_max'] - cfg['first_at_sec_min']} + {cfg['first_at_sec_min']}))
END={total}
END_BUF={end_buf}
TRIGGERED=0
while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - T0))
    if [ $ELAPSED -ge $((END - END_BUF)) ]; then break; fi
    if [ $NOW -ge $NEXT_AT ]; then
        # 随机选 scenario
        IDX=$((RANDOM % ${{#SCENARIOS[@]}}))
        SCEN="${{SCENARIOS[$IDX]}}"
        # split slots by ||SLOT||
        echo "[t=${{ELAPSED}}s] scenario_idx=$IDX"
        IFS='||SLOT||' read -ra SLOTS <<< "$SCEN"
        for SLOT in "${{SLOTS[@]}}"; do
            [ -z "$SLOT" ] && continue
            # split candidates by ||||
            IFS='||||' read -ra CANDS <<< "$SLOT"
            CIDX=$((RANDOM % ${{#CANDS[@]}}))
            eval "${{CANDS[$CIDX]}}"
            sleep $(({cfg['inter_command_sleep_min_sec']} + RANDOM % {cfg['inter_command_sleep_max_sec'] - cfg['inter_command_sleep_min_sec'] + 1}))
        done
        TRIGGERED=$((TRIGGERED + 1))
        NEXT_AT=$((NOW + {cfg['interval_min_sec']} + RANDOM % {cfg['interval_max_sec'] - cfg['interval_min_sec']}))
    fi
    sleep 2
done
# 跑满剩余时间
NOW=$(date +%s)
REMAIN=$((END - (NOW - T0)))
if [ $REMAIN -gt 0 ]; then sleep $REMAIN; fi
echo "[orchestrator] triggered=$TRIGGERED done"
# 杀所有后台 daemon
pkill -P $$ 2>/dev/null
wait
"""


def start_daemons(name: str, plan: dict) -> None:
    """在新模式下不再单独起 daemon,daemon 跟 scenario 都在 orchestrator 里,由 strace 直接包裹。"""
    pass  # noop


def stop_daemons(name: str) -> None:
    """orchestrator 退出时自动 pkill 所有后台 daemon。"""
    pass  # noop


def dump_proc_snapshot(name: str, plan: dict) -> None:
    snap = plan["proc_snapshot"]
    if not snap.get("enabled"):
        return
    out = snap["output_in_container"]
    cmd = (
        'for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do '
        '  cmdline=$(tr "\\0" " " < /proc/$pid/cmdline 2>/dev/null); '
        '  exe=$(readlink /proc/$pid/exe 2>/dev/null); '
        '  echo "PID=$pid CMDLINE=\\"$cmdline\\" EXE=\\"$exe\\""; '
        f'done > {out}'
    )
    subprocess.run(["docker", "exec", name, "bash", "-c", cmd], timeout=15)
    print(f"[snapshot] dumped to {out}")


def start_strace_with_orchestrator(name: str, plan: dict) -> None:
    """新模式:strace 直接 fork orchestrator.sh,所有 daemon + scenario 都在 strace 子树下。
    同时 attach 到现有 juice-shop PID 拿应用层 syscall。
    """
    s = plan["strace"]
    syscalls = ",".join(s["syscalls"])

    # 1. 写 orchestrator.sh 到容器
    orch = build_orchestrator_script(plan)
    container_orch = "/tmp/benign_orchestrator.sh"
    # 用 stdin 把 orchestrator 喂进去,避免 shell 引号转义复杂
    cp = subprocess.run(
        ["docker", "exec", "-i", name, "bash", "-c", f"cat > {container_orch}"],
        input=orch, text=True, capture_output=True, timeout=10,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"orchestrator write failed: {cp.stderr}")
    subprocess.run(["docker", "exec", name, "chmod", "+x", container_orch],
                   capture_output=True, timeout=5)

    # 2. 找 juice-shop PID(node build/app.js)
    cp = subprocess.run(
        ["docker", "exec", name, "pgrep", "-f", "node build/app.js"],
        capture_output=True, text=True, timeout=5,
    )
    juice_pid = cp.stdout.strip().split("\n")[0] if cp.stdout.strip() else ""

    # 3. 起两个 strace:
    #   strace_a: orchestrator 子树(daemon + scenario 命令)
    #   strace_b: juice-shop attach(应用层 syscall)
    # 都 -A append 到同一文件,出来一条合并 trace
    out = s["output_in_container"]
    subprocess.run(["docker", "exec", name, "bash", "-c", f"rm -f {out} && touch {out}"],
                   timeout=5)

    # strace_a:用 bash 把 orchestrator 包起来
    strace_a = (
        f"strace {s['flags']} -e trace={syscalls} -o {out} bash {container_orch} "
        f"> /tmp/orch.stdout 2> /tmp/orch.stderr"
    )
    subprocess.Popen(["docker", "exec", "-d", name, "bash", "-c", strace_a])
    print(f"[strace_a] started → orchestrator")

    # strace_b:attach juice-shop(若有)
    if juice_pid:
        strace_b = (
            f"strace {s['flags']} -e trace={syscalls} -o {out} -p {juice_pid} -f "
            f"2> /tmp/juice.strace_err"
        )
        subprocess.Popen(["docker", "exec", "-d", name, "bash", "-c", strace_b])
        print(f"[strace_b] started → attach juice-shop pid={juice_pid}")
    else:
        print("[strace_b] juice-shop pid not found, skip")


def stop_strace(name: str) -> None:
    subprocess.run(["docker", "exec", name, "pkill", "-f", "strace"],
                   capture_output=True, timeout=5)
    subprocess.run(["docker", "exec", name, "pkill", "-f", "benign_orchestrator"],
                   capture_output=True, timeout=5)


# --------- 3. scenario 触发 ---------

def sample_scenario(plan: dict) -> tuple:
    s = random.choice(plan["scenarios"]["pool"])
    cmds = [random.choice(slot["candidates"]) for slot in s["slots"]]
    return s["id"], cmds


def run_scenario_loop(name: str, plan: dict) -> None:
    cfg = plan["scenarios"]["trigger"]
    total = plan["collection"]["total_duration_sec"]
    end_buf = cfg["end_buffer_sec"]
    t0 = time.time()
    next_at = t0 + random.uniform(cfg["first_at_sec_min"], cfg["first_at_sec_max"])
    triggered = 0
    while time.time() - t0 < total - end_buf:
        if time.time() >= next_at:
            sid, cmds = sample_scenario(plan)
            print(f"[t={int(time.time()-t0)}s] scenario {sid} ({len(cmds)} cmds)", flush=True)
            for c in cmds:
                subprocess.run(["docker", "exec", name, "bash", "-c", c],
                               capture_output=True, timeout=12)
                time.sleep(random.uniform(
                    cfg["inter_command_sleep_min_sec"],
                    cfg["inter_command_sleep_max_sec"],
                ))
            triggered += 1
            next_at = time.time() + random.uniform(
                cfg["interval_min_sec"], cfg["interval_max_sec"],
            )
        time.sleep(2)
    remaining = total - (time.time() - t0)
    if remaining > 0:
        time.sleep(remaining)
    print(f"[scenario] triggered {triggered} scenarios across {total}s window")


# --------- 4. 主流程 ---------

def _output_paths(plan: dict, idx: int = None) -> tuple:
    """计算 host 输出路径(strace / proc_snapshot / sql)。
    idx=None → benign.{strace,proc_snapshot,sql}(单次采集,跟旧路径兼容)
    idx=N    → benign_{N:02d}.{...}(多次采集,N=0..29)
    """
    out = plan["output"]["benign"]
    base_strace = os.path.join(PROJECT_ROOT, out["strace"])
    base_snap   = os.path.join(PROJECT_ROOT, out["proc_snapshot"])
    base_sql    = os.path.join(PROJECT_ROOT, out["sql"])
    if idx is None:
        return base_strace, base_snap, base_sql
    # 把 benign.* 改成 benign_<idx:02d>.*
    def _suffix(path):
        d, fname = os.path.split(path)
        if fname.startswith("benign."):
            return os.path.join(d, f"benign_{idx:02d}." + fname[len("benign."):])
        # 通用 fallback:在扩展名前插 _<idx>
        root, ext = os.path.splitext(path)
        return f"{root}_{idx:02d}{ext}"
    return _suffix(base_strace), _suffix(base_snap), _suffix(base_sql)


def run_one_collection(plan: dict, container_name: str, idx: int = None) -> bool:
    """跑一个独立的 docker 容器,产 benign_<idx>.{strace,proc_snapshot,sql}。

    container_name:docker 容器名(并行时各容器需要唯一)
    idx:输出文件后缀;None 则走旧路径(benign.*)
    返回 True 成功,False 失败。
    """
    label = f"[col {idx:02d}]" if idx is not None else "[col --]"
    print(f"{label} starting container {container_name}", flush=True)
    name = start_container(plan, name_override=container_name)
    try:
        time.sleep(plan["collection"]["warmup_sec"])
        dump_proc_snapshot(name, plan)
        start_strace_with_orchestrator(name, plan)

        total = plan["collection"]["total_duration_sec"]
        wait_sec = total + plan["collection"]["strace_settle_sec"] + 10
        print(f"{label} waiting {wait_sec}s for orchestrator", flush=True)
        elapsed = 0
        while elapsed < wait_sec:
            time.sleep(min(30, wait_sec - elapsed))
            elapsed = min(elapsed + 30, wait_sec)
            cp = subprocess.run(
                ["docker", "exec", name, "stat", "-c", "%s",
                 plan["strace"]["output_in_container"]],
                capture_output=True, text=True, timeout=5,
            )
            sz = cp.stdout.strip() or "0"
            print(f"{label} t={elapsed}s trace_size={sz}B", flush=True)
        stop_strace(name)
        time.sleep(2)

        host_strace, host_snap, host_sql = _output_paths(plan, idx)
        for p in [host_strace, host_snap, host_sql]:
            os.makedirs(os.path.dirname(p), exist_ok=True)

        subprocess.run(["docker", "cp",
            f"{name}:{plan['strace']['output_in_container']}", host_strace],
            check=True, timeout=120)
        subprocess.run(["docker", "cp",
            f"{name}:{plan['proc_snapshot']['output_in_container']}", host_snap],
            check=True, timeout=30)
        compat_snap = host_strace + ".proc_snapshot"
        if compat_snap != host_snap:
            subprocess.run(["cp", host_snap, compat_snap], check=False)

        trace_to_pidsmaker(host_strace, host_sql)
        print(f"{label} ✓ done strace={os.path.getsize(host_strace)}B "
              f"sql={os.path.getsize(host_sql)}B", flush=True)
        return True
    except Exception as e:
        print(f"{label} ✗ FAIL: {e}", flush=True)
        return False
    finally:
        if plan["container"].get("remove_on_finish"):
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def run_parallel_collections(plan: dict, n: int, parallel: int) -> tuple:
    """并发跑 n 次独立 collection,最多 K 个同时跑。返回 (success_count, failed_count)。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    print(f"\n[parallel] {n} collections, max {parallel} concurrent\n", flush=True)
    success = 0
    failed = 0
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {
            pool.submit(run_one_collection, plan, f"pids_benign_{i:02d}", i): i
            for i in range(n)
        }
        for f in as_completed(futures):
            i = futures[f]
            try:
                ok = f.result()
            except Exception as e:
                print(f"[col {i:02d}] crashed: {e}", flush=True)
                ok = False
            if ok:
                success += 1
            else:
                failed += 1
    return success, failed


def collect_benign_main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", default=PLAN_PATH)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--duration-override", type=int, default=None,
                        help="覆盖 yml 中 total_duration_sec(autonomous smoke 用)")
    parser.add_argument("--num-collections", type=int, default=1,
                        help="跑 N 次独立采集,产 N 份 benign_<i>.sql(默认 1 = 单次,兼容旧路径)")
    parser.add_argument("--parallel", type=int, default=4,
                        help="并发跑几个 docker 容器(默认 4)")
    args = parser.parse_args(argv)

    random.seed(args.seed)
    plan = load_plan(args.plan)
    if args.duration_override:
        plan["collection"]["total_duration_sec"] = args.duration_override
        print(f"[override] total_duration → {args.duration_override}s")
    print(f"[start] total_duration={plan['collection']['total_duration_sec']}s "
          f"warmup={plan['collection']['warmup_sec']}s "
          f"num_collections={args.num_collections} parallel={args.parallel}")

    if args.num_collections == 1:
        # 单次:保持旧路径 detection/data/training_traces/benign.{strace,proc_snapshot,sql}
        ok = run_one_collection(plan, plan["container"]["name"], idx=None)
        sys.exit(0 if ok else 1)
    else:
        # 多次并行:产 benign_00..benign_<n-1>.{...}
        parallel = min(args.parallel, args.num_collections)
        success, failed = run_parallel_collections(plan, args.num_collections, parallel)
        print(f"\n[summary] {success} succeeded, {failed} failed (of {args.num_collections})")
        sys.exit(0 if failed == 0 else 1)




# ============================================================================
# Attack trace collection
# ============================================================================

"""collect_attack.py — 跑每个 A_0 scenario 1 次(δ=[]),采纯 attack trace。"""
import glob
import json
import os
import shutil
import sys
import yaml

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

from range.checker import execute_with_checks
from range.converter import trace_to_pidsmaker

PLAN_PATH = os.path.join(PROJECT_ROOT, "detection", "data", "benign_collection_plan.yml")


def collect_attack_main(argv=None):
    plan = yaml.safe_load(open(PLAN_PATH))
    scenarios_dir = os.path.join(PROJECT_ROOT, plan["attack_collection"]["scenarios_dir"])
    output_dir = os.path.join(PROJECT_ROOT, plan["attack_collection"]["output_dir"])
    os.makedirs(output_dir, exist_ok=True)

    files = sorted(glob.glob(f"{scenarios_dir}/*.json"))
    print(f"[attack] {len(files)} scenarios in {scenarios_dir}")

    succeeded = []
    failed = []
    for fn in files:
        scenario = json.load(open(fn))
        sid = scenario["scenario_id"]
        try:
            res = execute_with_checks(
                scenario,
                delta_commands=plan["attack_collection"]["delta_commands"],
                delta_positions=plan["attack_collection"]["delta_positions"],
                capture_trace=True,
            )
        except Exception as e:
            print(f"  [error] {sid}: {e}")
            failed.append((sid, str(e)[:80]))
            continue
        if not res.trace_path or not res.all_steps_passed:
            print(f"  [skip] {sid}: pass={res.all_steps_passed} trace={res.trace_path}")
            failed.append((sid, "checker_fail"))
            continue
        target_strace = os.path.join(output_dir, f"{sid}.strace")
        target_snap = target_strace + ".proc_snapshot"
        target_sql = target_strace + ".sql"
        # mv trace + proc_snapshot
        shutil.move(res.trace_path, target_strace)
        snap_src = res.trace_path + ".proc_snapshot"
        if os.path.exists(snap_src):
            shutil.move(snap_src, target_snap)
        trace_to_pidsmaker(target_strace, target_sql)
        succeeded.append(sid)
        print(f"  [done] {sid}: {os.path.getsize(target_strace)} bytes "
              f"sql={os.path.getsize(target_sql)} bytes")

    print(f"\n[summary] succeeded={len(succeeded)}/{len(files)} failed={len(failed)}")
    if failed:
        print("  failures:")
        for sid, reason in failed:
            print(f"    {sid}: {reason}")





def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "benign":
        return collect_benign_main(argv[1:])
    if argv and argv[0] == "attack":
        return collect_attack_main(argv[1:])
    print("usage: python -m detection.data.collect [benign|attack] ...")
    print("public: python scripts/run.py detect collect ...")
    return None


if __name__ == "__main__":
    main()
