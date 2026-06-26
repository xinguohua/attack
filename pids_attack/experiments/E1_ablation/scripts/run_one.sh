#!/bin/bash
# 单 cell:跑一个 (experiment, variant, detector, scenario, seed) 组合
# Usage: bash run_one.sh <experiment> <variant> <detector> <scenario> <seed> [extra_flags...]

set -e

EXP=${1:?usage: run_one.sh <experiment> <variant> <detector> <scenario> <seed>}
VARIANT=${2:-minimal_add}
DETECTOR=${3:-magic}
SCN=${4:-01}
SEED=${5:-1}
shift 5 || true
EXTRA="$@"

PROJ_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT_DIR="${PROJ_ROOT}/experiments/E1_ablation/${EXP}/results"
mkdir -p "$OUT_DIR"
OUT_PATH="${OUT_DIR}/${VARIANT}_${DETECTOR}_${SCN}_s${SEED}.json"

cd "$PROJ_ROOT/.."   # project root

if [ "$EXP" == "E1.0_framework" ]; then
    PYTHONPATH=pids_attack conda run -n mimicattack python \
      pids_attack/experiments/E1_ablation/scripts/e1_0_bootstrap.py \
      --scenario "$SCN" --detector "$DETECTOR" --variant "$VARIANT" --seed "$SEED" \
      --output "$OUT_PATH" \
      $EXTRA
elif [ "$EXP" == "E1.1_mutation" ]; then
    PYTHONPATH=pids_attack conda run -n mimicattack python \
      pids_attack/experiments/E1_ablation/scripts/e1_1_mutation.py \
      --scenario "$SCN" --detector "$DETECTOR" --variant "$VARIANT" --seed "$SEED" \
      --output "$OUT_PATH" \
      $EXTRA
elif [ "$EXP" == "E1.2_fitness" ]; then
    PYTHONPATH=pids_attack conda run -n mimicattack python \
      pids_attack/experiments/E1_ablation/scripts/e1_2_fitness.py \
      --scenario "$SCN" --detector "$DETECTOR" --variant "$VARIANT" --seed "$SEED" \
      --output "$OUT_PATH" \
      $EXTRA
elif [ "$EXP" == "E1.3_search" ]; then
    PYTHONPATH=pids_attack conda run -n mimicattack python \
      pids_attack/experiments/E1_ablation/scripts/e1_3_search.py \
      --scenario "$SCN" --detector "$DETECTOR" --variant "$VARIANT" --seed "$SEED" \
      --output "$OUT_PATH" \
      $EXTRA
elif [ "$EXP" == "E1.4_surrogate" ]; then
    PYTHONPATH=pids_attack conda run -n mimicattack python \
      pids_attack/experiments/E1_ablation/scripts/e1_4_surrogate.py \
      --scenario "$SCN" --detector "$DETECTOR" --variant "$VARIANT" --seed "$SEED" \
      --output "$OUT_PATH" \
      $EXTRA
elif [ "$EXP" == "E1.5_acquisition" ]; then
    PYTHONPATH=pids_attack conda run -n mimicattack python \
      pids_attack/experiments/E1_ablation/scripts/e1_5_acquisition.py \
      --scenario "$SCN" --detector "$DETECTOR" --variant "$VARIANT" --seed "$SEED" \
      --output "$OUT_PATH" \
      $EXTRA
else
    echo "Unknown E1 experiment: $EXP"
    exit 1
fi
echo "✅ wrote $OUT_PATH"
