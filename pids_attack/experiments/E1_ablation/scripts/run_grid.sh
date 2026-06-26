#!/bin/bash
# 全 grid 跑一个 experiment
# Usage: bash run_grid.sh <experiment> [--dry-run] [extra_flags...]

set -e

EXP=${1:?usage: run_grid.sh <experiment> [--dry-run] [extra_flags...]}
shift
DRY_RUN=0
EXTRA_FLAGS=()
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1;;
        --mock)
            echo "[abort] --mock is retired for E1 finding-driven runs; use unit tests for algorithm smoke."
            exit 2
            ;;
        *) EXTRA_FLAGS+=("$arg");;
    esac
done

PROJ_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
RUN_ONE="${PROJ_ROOT}/experiments/E1_ablation/scripts/run_one.sh"

# 共享配置
SCENARIOS=(01 02 03 04 05 06 07 08 09 10)
SEEDS=(1 2 3 4 5)
DETECTORS=(threatrace_g1g2)
VARIANTS=()

case "$EXP" in
    "E1.0_framework")
        VARIANTS=(minimal_add)
        SCENARIOS=(01 08)
        SEEDS=(1)
        ;;
    "E1.1_mutation")
        VARIANTS=(add_only add_rewrite add_rewrite_move all4)
        DETECTORS=(threatrace_g1g2)
        SCENARIOS=(01)
        SEEDS=(1)
        ;;
    "E1.2_fitness")
        VARIANTS=(f1_only f1_f2)
        ;;
    "E1.3_search")
        VARIANTS=(full random)
        ;;
    "E1.4_surrogate")
        VARIANTS=(blr_ard blr_noard no_posterior)
        ;;
    "E1.5_acquisition")
        VARIANTS=(lcb ei thompson)
        ;;
    *)
        echo "Unknown E1 ablation experiment: $EXP"
        exit 1
        ;;
esac

# 计算总 cell 数
total=$((${#VARIANTS[@]} * ${#DETECTORS[@]} * ${#SCENARIOS[@]} * ${#SEEDS[@]}))
echo "=== $EXP grid ==="
echo "Variants:  ${#VARIANTS[@]} (${VARIANTS[@]})"
echo "Detectors: ${#DETECTORS[@]} (${DETECTORS[@]})"
echo "Scenarios: ${#SCENARIOS[@]}"
echo "Seeds:     ${#SEEDS[@]}"
echo "Total cells: $total"
if [ $DRY_RUN -eq 1 ]; then
    echo "[dry-run] not executing"
    exit 0
fi

cell=0
for variant in "${VARIANTS[@]}"; do
    for detector in "${DETECTORS[@]}"; do
        for scn in "${SCENARIOS[@]}"; do
            for seed in "${SEEDS[@]}"; do
                cell=$((cell + 1))
                echo "[$cell/$total] $variant / $detector / $scn / $seed"
                bash "$RUN_ONE" "$EXP" "$variant" "$detector" "$scn" "$seed" "${EXTRA_FLAGS[@]}"
            done
        done
    done
done

echo "✅ $EXP grid done ($total cells)"
