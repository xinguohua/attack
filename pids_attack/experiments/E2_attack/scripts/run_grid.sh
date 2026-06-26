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
            echo "[abort] --mock is retired for E2 real attack runs; use unit tests for algorithm smoke."
            exit 2
            ;;
        *) EXTRA_FLAGS+=("$arg");;
    esac
done

PROJ_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
RUN_ONE="${PROJ_ROOT}/experiments/E2_attack/scripts/run_one.sh"

# 共享配置
SCENARIOS=(01 02 03 04 05 06 07 08 09 10)
SEEDS=(1 2 3 4 5)

case "$EXP" in
    "E2.0_main_attack")
        ALGOS=(full random)
        DETECTORS=(magic orthrus threatrace g1 g2 g1g2 magic_g1g2)
        ;;
    *)
        echo "Unknown E2 attack experiment: $EXP"
        exit 1
        ;;
esac

# 计算总 cell 数
total=$((${#ALGOS[@]} * ${#DETECTORS[@]} * ${#SCENARIOS[@]} * ${#SEEDS[@]}))
echo "=== $EXP grid ==="
echo "Algos:     ${#ALGOS[@]} (${ALGOS[@]})"
echo "Detectors: ${#DETECTORS[@]} (${DETECTORS[@]})"
echo "Scenarios: ${#SCENARIOS[@]}"
echo "Seeds:     ${#SEEDS[@]}"
echo "Total cells: $total"
if [ $DRY_RUN -eq 1 ]; then
    echo "[dry-run] not executing"
    exit 0
fi

cell=0
for algo in "${ALGOS[@]}"; do
    for detector in "${DETECTORS[@]}"; do
        for scn in "${SCENARIOS[@]}"; do
            for seed in "${SEEDS[@]}"; do
                cell=$((cell + 1))
                echo "[$cell/$total] $algo / $detector / $scn / $seed"
                bash "$RUN_ONE" "$EXP" "$algo" "$detector" "$scn" "$seed" "${EXTRA_FLAGS[@]}"
            done
        done
    done
done

echo "✅ $EXP grid done ($total cells)"
