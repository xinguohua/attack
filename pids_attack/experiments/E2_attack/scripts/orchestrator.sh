#!/bin/bash
# Stage-by-stage main attack orchestrator
# - 跑完一个 stage → aggregate → snapshot CSV + summary → 下一个
# - 后台运行,不会停
#
# Usage:
#   bash orchestrator.sh 2>&1 | tee logs/orchestrator.log

set -euo pipefail
cd /Users/xinguohua/mimicattack

ROOT=/Users/xinguohua/mimicattack/pids_attack/experiments/E2_attack
LOG_DIR=$ROOT/logs
SNAP_DIR=$ROOT/snapshots
PROG=$ROOT/progress.md
mkdir -p "$LOG_DIR" "$SNAP_DIR"

PY="conda run -n mimicattack python"
# 用 env 保证 PYTHONPATH= 当作环境变量赋值
RUN_PREFIX="env PYTHONPATH=/Users/xinguohua/mimicattack $PY /Users/xinguohua/mimicattack/pids_attack/scripts/run.py attack run"
SCENARIOS=(01 02 03 04 05 06 07 08 09 10)
SEEDS=(1 2 3 4 5)
COMMON="--B-max 20 --T-GA 20 --m 10 --H 3 --D-cap 200"

# ─── 实时进度写到 progress.md ──────────────────────
log_stage() {
  local stage=$1 status=$2 note=${3:-}
  local ts=$(date "+%Y-%m-%d %H:%M:%S")
  echo "| $ts | $stage | $status | $note |" >> "$PROG"
}

# ─── snapshot:CSV + 分析摘要 + 源码 tar ─────────────
snapshot() {
  local stage=$1
  local outdir=$SNAP_DIR/$stage
  mkdir -p "$outdir"
  # 1. 全量 CSV + stdout 摘要
  PYTHONPATH=pids_attack $PY $ROOT/scripts/aggregate.py \
    --root $ROOT --out "$outdir/summary.csv" > "$outdir/summary.txt" 2>&1
  # 2. 源码 tar(可复现):SafeMimic-CMD + shared runtime + unified run.py + orchestrator
  tar czf "$outdir/code_snapshot.tgz" \
    pids_attack/attack/safemimic_cmd \
    pids_attack/attack/framework \
    pids_attack/range \
    pids_attack/detection \
    pids_attack/cmd_graph \
    pids_attack/scripts/run.py \
    pids_attack/experiments/E2_attack/scripts \
    pids_attack/p3_implementation_plan.md \
    2>/dev/null
  # 3. git diff(若是 repo)
  git -C /Users/xinguohua/mimicattack diff > "$outdir/git.diff" 2>/dev/null || true
  git -C /Users/xinguohua/mimicattack log -1 --format="%H %s" > "$outdir/git.head" 2>/dev/null || true
  # 4. 复制到 progress.md
  echo "📊 snapshot $stage at $(date)" >> "$PROG"
  echo "" >> "$PROG"
  echo '```' >> "$PROG"
  tail -80 "$outdir/summary.txt" >> "$PROG"
  echo '```' >> "$PROG"
  echo "" >> "$PROG"
}

# ─── run one cell(若已存在跳过)──────────────────
run_cell() {
  local algo=$1 det=$2 scn=$3 seed=$4 outdir=$5 extra=${6:-}
  local fname=${algo}_${det}_${scn}_s${seed}.json
  local path=$outdir/$fname
  [[ -f "$path" ]] && return 0
  $RUN_PREFIX --scenario $scn --detector $det --algo $algo \
    --seed $seed $COMMON $extra \
    --output "$path" > /dev/null 2>&1
}

# ─── STAGE A.2:rule × random(150)─────────────────
stage_a2() {
  log_stage "A.2" "🔄" "rule detectors × random"
  for det in g1 g2 g1g2; do
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        run_cell random $det $scn $seed $ROOT/E2.0_main_attack/results
      done
    done
  done
  log_stage "A.2" "✅" "done"
  snapshot "A.2"
}

# ─── STAGE A.3:GNN × full(150)─────────────────
stage_a3() {
  log_stage "A.3" "🔄" "GNN × full"
  for det in magic orthrus threatrace; do
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        run_cell full $det $scn $seed $ROOT/E2.0_main_attack/results
      done
    done
  done
  log_stage "A.3" "✅" "done"
  snapshot "A.3"
}

# ─── STAGE A.4:GNN × random(150)──────────────────
stage_a4() {
  log_stage "A.4" "🔄" "GNN × random"
  for det in magic orthrus threatrace; do
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        run_cell random $det $scn $seed $ROOT/E2.0_main_attack/results
      done
    done
  done
  log_stage "A.4" "✅" "done"
  snapshot "A.4"
}

# ─── STAGE A.5:hybrid magic_g1g2 × 2 algos(100)──
stage_a5() {
  log_stage "A.5" "🔄" "hybrid magic_g1g2 × 2 algos"
  for algo in full random; do
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        run_cell $algo magic_g1g2 $scn $seed $ROOT/E2.0_main_attack/results
      done
    done
  done
  log_stage "A.5" "✅" "done"
  snapshot "A.5"
}

# ─── STAGE I:最终聚合 ────────────────────────────
stage_i() {
  log_stage "I" "🔄" "final aggregate"
  PYTHONPATH=pids_attack $PY $ROOT/scripts/aggregate.py \
    --root $ROOT --out $ROOT/figures/E2_attack_summary_final.csv > $ROOT/logs/final_summary.txt 2>&1
  log_stage "I" "✅" "done — see figures/E2_attack_summary_final.csv"
  echo "" >> "$PROG"
  echo "## final main attack summary" >> "$PROG"
  echo '```' >> "$PROG"
  cat $ROOT/logs/final_summary.txt >> "$PROG"
  echo '```' >> "$PROG"
}

# ─── 入口:顺序跑所有 stage(不会停)──────────────
main() {
  echo "▶ orchestrator start $(date)" | tee -a "$LOG_DIR/orchestrator.log"
  stage_a2 2>&1 | tee -a "$LOG_DIR/stage_a2.log"
  stage_a3 2>&1 | tee -a "$LOG_DIR/stage_a3.log"
  stage_a4 2>&1 | tee -a "$LOG_DIR/stage_a4.log"
  stage_a5 2>&1 | tee -a "$LOG_DIR/stage_a5.log"
  stage_i  2>&1 | tee -a "$LOG_DIR/stage_i.log"
  echo "✅ orchestrator done $(date)" | tee -a "$LOG_DIR/orchestrator.log"
}

main
