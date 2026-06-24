#!/bin/bash
# Stage-by-stage ablation orchestrator
# - 跑完一个 stage → aggregate → snapshot CSV + summary → 下一个
# - 后台运行,不会停
#
# Usage:
#   bash orchestrator.sh 2>&1 | tee logs/orchestrator.log

set -u
cd /Users/xinguohua/mimicattack

ROOT=/Users/xinguohua/mimicattack/pids_attack/experiments/E2_ablation
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
  # 2. 源码 tar(可复现):grabnel_cmd + detection + attack oracle + unified run.py + orchestrator
  tar czf "$outdir/code_snapshot.tgz" \
    pids_attack/attack/grabnel_cmd \
    pids_attack/attack/framework \
    pids_attack/detection \
    pids_attack/attack/oracle.py \
    pids_attack/cmd_graph \
    pids_attack/scripts/run.py \
    pids_attack/experiments/E2_ablation/scripts \
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

# ─── STAGE B:E2.4 scalarize(250)──────────────────
stage_b() {
  log_stage "B" "🔄" "E2.4 scalarize"
  mkdir -p $ROOT/E2.4_scalarize/results
  for variant in "tcheby:1" "tcheby:5" "tcheby:20" "weighted:5" "lex:5"; do
    IFS=":" read sc bt <<< "$variant"
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        local fname=grabnel_magic_${scn}_s${seed}_${sc}_b${bt}.json
        local path=$ROOT/E2.4_scalarize/results/$fname
        [[ -f "$path" ]] && continue
        $RUN_PREFIX --scenario $scn --detector magic --algo grabnel --seed $seed $COMMON \
          --scalarize $sc --beta $bt --output "$path" > /dev/null 2>&1
      done
    done
  done
  log_stage "B" "✅" "done"
  snapshot "B"
}

# ─── STAGE C:E2.3 f2_metric(300)──────────────────
stage_c() {
  log_stage "C" "🔄" "E2.3 f2_metric"
  mkdir -p $ROOT/E2.3_f2_metric/results
  for variant in "knn:3" "knn:5" "knn:10" "dist_weighted:5" "kde:5" "gmm:5"; do
    IFS=":" read m k <<< "$variant"
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        local fname=grabnel_magic_${scn}_s${seed}_${m}_k${k}.json
        local path=$ROOT/E2.3_f2_metric/results/$fname
        [[ -f "$path" ]] && continue
        $RUN_PREFIX --scenario $scn --detector magic --algo grabnel --seed $seed $COMMON \
          --f2 $m --k-nn $k --output "$path" > /dev/null 2>&1
      done
    done
  done
  log_stage "C" "✅" "done"
  snapshot "C"
}

# ─── STAGE D:E2.6 acquisition(300)────────────────
stage_d() {
  log_stage "D" "🔄" "E2.6 acquisition"
  mkdir -p $ROOT/E2.6_acquisition/results
  for variant in "lcb:0.1" "lcb:0.5" "lcb:1" "lcb:2" "ei:0.5" "thompson:0.5"; do
    IFS=":" read a b <<< "$variant"
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        local fname=grabnel_magic_${scn}_s${seed}_${a}_b${b}.json
        local path=$ROOT/E2.6_acquisition/results/$fname
        [[ -f "$path" ]] && continue
        $RUN_PREFIX --scenario $scn --detector magic --algo grabnel --seed $seed $COMMON \
          --acquisition $a --beta-lcb $b --output "$path" > /dev/null 2>&1
      done
    done
  done
  log_stage "D" "✅" "done"
  snapshot "D"
}

# ─── STAGE E:E2.1 features stub(250)─────────────
stage_e() {
  log_stage "E" "🔄" "E2.1 features (stub)"
  mkdir -p $ROOT/E2.1_features/results
  for ft in wl gnn random_walk graph2vec domain; do
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        local fname=grabnel_magic_${scn}_s${seed}_ft-${ft}.json
        local path=$ROOT/E2.1_features/results/$fname
        [[ -f "$path" ]] && continue
        $RUN_PREFIX --scenario $scn --detector magic --algo grabnel --seed $seed $COMMON \
          --feature $ft --output "$path" > /dev/null 2>&1
      done
    done
  done
  log_stage "E" "✅" "done"
  snapshot "E"
}

# ─── STAGE F:E2.2 surrogate stub(250)────────────
stage_f() {
  log_stage "F" "🔄" "E2.2 surrogate (stub)"
  mkdir -p $ROOT/E2.2_surrogate/results
  for sg in blr gp_wl gp_rbf rf ensemble; do
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        local fname=grabnel_magic_${scn}_s${seed}_sg-${sg}.json
        local path=$ROOT/E2.2_surrogate/results/$fname
        [[ -f "$path" ]] && continue
        $RUN_PREFIX --scenario $scn --detector magic --algo grabnel --seed $seed $COMMON \
          --surrogate $sg --output "$path" > /dev/null 2>&1
      done
    done
  done
  log_stage "F" "✅" "done"
  snapshot "F"
}

# ─── STAGE G:E2.5 commit stub(200)───────────────
stage_g() {
  log_stage "G" "🔄" "E2.5 commit (stub)"
  mkdir -p $ROOT/E2.5_commit/results
  for cm in single batch_2 beam_3 lookahead_2; do
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        local fname=grabnel_magic_${scn}_s${seed}_cm-${cm}.json
        local path=$ROOT/E2.5_commit/results/$fname
        [[ -f "$path" ]] && continue
        $RUN_PREFIX --scenario $scn --detector magic --algo grabnel --seed $seed $COMMON \
          --commit $cm --output "$path" > /dev/null 2>&1
      done
    done
  done
  log_stage "G" "✅" "done"
  snapshot "G"
}

# ─── STAGE H:E2.7 ga_cmd stub(200)───────────────
stage_h() {
  log_stage "H" "🔄" "E2.7 ga_cmd (stub)"
  mkdir -p $ROOT/E2.7_ga_cmd/results
  for cfg in "default" "mut_weighted" "constrained" "both"; do
    local flags=""
    case $cfg in
      default) flags="" ;;
      mut_weighted) flags="--ga-mut-weighted" ;;
      constrained) flags="--ga-constrained-mut" ;;
      both) flags="--ga-mut-weighted --ga-constrained-mut" ;;
    esac
    for scn in "${SCENARIOS[@]}"; do
      for seed in "${SEEDS[@]}"; do
        local fname=grabnel_magic_${scn}_s${seed}_ga-${cfg}.json
        local path=$ROOT/E2.7_ga_cmd/results/$fname
        [[ -f "$path" ]] && continue
        $RUN_PREFIX --scenario $scn --detector magic --algo grabnel --seed $seed $COMMON \
          $flags --output "$path" > /dev/null 2>&1
      done
    done
  done
  log_stage "H" "✅" "done"
  snapshot "H"
}

# ─── STAGE I:最终聚合 ────────────────────────────
stage_i() {
  log_stage "I" "🔄" "final aggregate"
  PYTHONPATH=pids_attack $PY $ROOT/scripts/aggregate.py \
    --root $ROOT --out $ROOT/figures/E2_ablation_summary_final.csv > $ROOT/logs/final_summary.txt 2>&1
  log_stage "I" "✅" "done — see figures/E2_ablation_summary_final.csv"
  echo "" >> "$PROG"
  echo "## final ablation summary" >> "$PROG"
  echo '```' >> "$PROG"
  cat $ROOT/logs/final_summary.txt >> "$PROG"
  echo '```' >> "$PROG"
}

# ─── 入口:顺序跑所有 stage(不会停)──────────────
main() {
  echo "▶ orchestrator start $(date)" | tee -a "$LOG_DIR/orchestrator.log"
  stage_b  2>&1 | tee -a "$LOG_DIR/stage_b.log"
  stage_c  2>&1 | tee -a "$LOG_DIR/stage_c.log"
  stage_d  2>&1 | tee -a "$LOG_DIR/stage_d.log"
  stage_e  2>&1 | tee -a "$LOG_DIR/stage_e.log"
  stage_f  2>&1 | tee -a "$LOG_DIR/stage_f.log"
  stage_g  2>&1 | tee -a "$LOG_DIR/stage_g.log"
  stage_h  2>&1 | tee -a "$LOG_DIR/stage_h.log"
  stage_i  2>&1 | tee -a "$LOG_DIR/stage_i.log"
  echo "✅ orchestrator done $(date)" | tee -a "$LOG_DIR/orchestrator.log"
}

main
