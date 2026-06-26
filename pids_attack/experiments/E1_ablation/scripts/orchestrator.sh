#!/bin/bash
# E1 finding-driven stage orchestrator.
#
# This script contains no attack logic.  It runs the current E1 stage wrappers
# in order, aggregates after each stage, and snapshots enough metadata for
# reproducibility.
#
# Usage:
#   bash orchestrator.sh [--dry-run] [E1.0_framework E1.1_mutation ...]

set -euo pipefail

REPO_ROOT=/Users/xinguohua/mimicattack
ROOT=$REPO_ROOT/pids_attack/experiments/E1_ablation
LOG_DIR=$ROOT/logs
SNAP_DIR=$ROOT/snapshots
PROG=$ROOT/progress.md
RUN_GRID=$ROOT/scripts/run_grid.sh
PY="conda run -n mimicattack python"

mkdir -p "$LOG_DIR" "$SNAP_DIR"
cd "$REPO_ROOT"

DRY_RUN=0
STAGES=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) STAGES+=("$arg") ;;
  esac
done

if [ ${#STAGES[@]} -eq 0 ]; then
  STAGES=(
    E1.0_framework
    E1.1_mutation
    E1.2_fitness
    E1.3_search
    E1.4_surrogate
    E1.5_acquisition
  )
fi

log_stage() {
  local stage=$1 status=$2 note=${3:-}
  local ts
  ts=$(date "+%Y-%m-%d %H:%M:%S")
  echo "| $ts | $stage | $status | $note |" >> "$PROG"
}

snapshot() {
  local stage=$1
  local outdir=$SNAP_DIR/$stage
  mkdir -p "$outdir"

  PYTHONPATH=pids_attack $PY "$ROOT/scripts/aggregate.py" \
    --root "$ROOT" --out "$outdir/summary.csv" > "$outdir/summary.txt" 2>&1

  tar czf "$outdir/code_snapshot.tgz" \
    pids_attack/attack/safemimic_cmd \
    pids_attack/attack/framework \
    pids_attack/range \
    pids_attack/cmd_graph \
    pids_attack/scripts/run.py \
    pids_attack/experiments/E1_ablation/scripts \
    pids_attack/p3_results.md \
    2>/dev/null

  git -C "$REPO_ROOT" diff > "$outdir/git.diff" 2>/dev/null || true
  git -C "$REPO_ROOT" log -1 --format="%H %s" > "$outdir/git.head" 2>/dev/null || true

  echo "snapshot $stage at $(date)" >> "$PROG"
  echo "" >> "$PROG"
  echo '```' >> "$PROG"
  tail -80 "$outdir/summary.txt" >> "$PROG"
  echo '```' >> "$PROG"
  echo "" >> "$PROG"
}

main() {
  echo "orchestrator start $(date)" | tee -a "$LOG_DIR/orchestrator.log"
  for stage in "${STAGES[@]}"; do
    log_stage "$stage" "running" ""
    if [ "$DRY_RUN" -eq 1 ]; then
      bash "$RUN_GRID" "$stage" --dry-run 2>&1 | tee "$LOG_DIR/${stage}.dry_run.log"
      log_stage "$stage" "dry-run" "not executed"
      continue
    fi
    bash "$RUN_GRID" "$stage" 2>&1 | tee "$LOG_DIR/${stage}.log"
    log_stage "$stage" "done" ""
    snapshot "$stage"
  done
  echo "orchestrator done $(date)" | tee -a "$LOG_DIR/orchestrator.log"
}

main
