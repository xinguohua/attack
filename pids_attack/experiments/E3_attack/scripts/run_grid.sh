#!/bin/bash
# 全 grid 跑一个 experiment
# Usage: bash run_grid.sh <experiment> [--mock] [--dry-run]

set -e

EXP=${1:?usage: run_grid.sh <experiment> [--mock]}
shift
MOCK_FLAG=""
DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --mock) MOCK_FLAG="--mock";;
        --dry-run) DRY_RUN=1;;
    esac
done

PROJ_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
RUN_ONE="${PROJ_ROOT}/experiments/E3_attack/scripts/run_one.sh"

# 共享配置
SCENARIOS=(01 02 03 04 05 06 07 08 09 10)
SEEDS=(1 2 3 4 5)

case "$EXP" in
    "E3.0_main_attack")
        ALGOS=(grabnel random)
        DETECTORS=(magic orthrus threatrace g1 g2 g1g2 magic_g1g2)
        VARIANTS=("")
        ;;
    *)
        echo "Unknown E3 attack experiment: $EXP"
        exit 1
        ;;
esac

# 计算总 cell 数
total=$((${#ALGOS[@]} * ${#DETECTORS[@]} * ${#VARIANTS[@]} * ${#SCENARIOS[@]} * ${#SEEDS[@]}))
echo "=== $EXP grid ==="
echo "Algos:     ${#ALGOS[@]} (${ALGOS[@]})"
echo "Detectors: ${#DETECTORS[@]} (${DETECTORS[@]})"
echo "Variants:  ${#VARIANTS[@]}"
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
        for variant in "${VARIANTS[@]}"; do
            for scn in "${SCENARIOS[@]}"; do
                for seed in "${SEEDS[@]}"; do
                    cell=$((cell + 1))
                    echo "[$cell/$total] $algo / $detector / $variant / $scn / $seed"
                    # 把 variant 切成单独 token,加 mock flag
                    bash "$RUN_ONE" "$EXP" "$algo" "$detector" "$scn" "$seed" $variant $MOCK_FLAG || {
                        echo "  ⚠️  failed cell $cell"
                    }
                done
            done
        done
    done
done

echo "✅ $EXP grid done ($total cells)"
