#!/bin/bash
# 单 cell:跑一个 (experiment, algo, detector, scenario, seed) 组合
# Usage: bash run_one.sh <experiment> <algo> <detector> <scenario> <seed> [extra_flags...]

set -e

EXP=${1:?usage: run_one.sh <experiment> <algo> <detector> <scenario> <seed>}
ALGO=${2:-grabnel}
DETECTOR=${3:-magic}
SCN=${4:-01}
SEED=${5:-1}
shift 5 || true
EXTRA="$@"

PROJ_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT_DIR="${PROJ_ROOT}/experiments/E3_attack/${EXP}/results"
mkdir -p "$OUT_DIR"
OUT_PATH="${OUT_DIR}/${ALGO}_${DETECTOR}_${SCN}_s${SEED}.json"

cd "$PROJ_ROOT/.."   # project root

if [ "$ALGO" == "grabnel" ]; then
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack run \
      --scenario "$SCN" --detector "$DETECTOR" --algo grabnel --seed "$SEED" \
      --output "$OUT_PATH" \
      $EXTRA
elif [ "$ALGO" == "random" ]; then
    # Random baseline:GA T_GA=1, m=1,基本就是随机 mutation 起步
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack run \
      --scenario "$SCN" --detector "$DETECTOR" --algo random --seed "$SEED" \
      --T-GA 1 --m 1 \
      --output "$OUT_PATH" \
      $EXTRA
else
    echo "Unknown algo: $ALGO (expect grabnel|random)"
    exit 1
fi
echo "✅ wrote $OUT_PATH"
