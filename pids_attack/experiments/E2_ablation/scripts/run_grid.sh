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
RUN_ONE="${PROJ_ROOT}/experiments/E2_ablation/scripts/run_one.sh"

# 共享配置
SCENARIOS=(01 02 03 04 05 06 07 08 09 10)
SEEDS=(1 2 3 4 5)

case "$EXP" in
    "E2.1_features")
        ALGOS=(grabnel)
        DETECTORS=(magic)
        VARIANTS=("--feature wl" "--feature gnn" "--feature random_walk" "--feature graph2vec" "--feature domain")
        ;;
    "E2.2_surrogate")
        ALGOS=(grabnel)
        DETECTORS=(magic)
        VARIANTS=("--surrogate blr" "--surrogate gp_wl" "--surrogate gp_rbf" "--surrogate rf" "--surrogate ensemble")
        ;;
    "E2.3_f2_metric")
        ALGOS=(grabnel)
        DETECTORS=(magic)
        VARIANTS=("--f2 knn --k-nn 3" "--f2 knn --k-nn 5" "--f2 knn --k-nn 10" "--f2 dist_weighted" "--f2 kde" "--f2 gmm")
        ;;
    "E2.4_scalarize")
        ALGOS=(grabnel)
        DETECTORS=(magic)
        VARIANTS=("--scalarize tcheby --beta 1" "--scalarize tcheby --beta 5" "--scalarize tcheby --beta 20" "--scalarize weighted" "--scalarize lex")
        ;;
    "E2.5_commit")
        ALGOS=(grabnel)
        DETECTORS=(magic)
        VARIANTS=("--commit single" "--commit batch_2" "--commit beam_3" "--commit lookahead_2")
        ;;
    "E2.6_acquisition")
        ALGOS=(grabnel)
        DETECTORS=(magic)
        VARIANTS=("--acquisition lcb --beta-lcb 0.1" "--acquisition lcb --beta-lcb 0.5" "--acquisition lcb --beta-lcb 1" "--acquisition lcb --beta-lcb 2" "--acquisition ei" "--acquisition thompson")
        ;;
    "E2.7_ga_cmd")
        ALGOS=(grabnel)
        DETECTORS=(magic)
        VARIANTS=("" "--ga-mut-weighted" "--ga-constrained-mut" "--ga-mut-weighted --ga-constrained-mut")
        ;;
    *)
        echo "Unknown E2 ablation experiment: $EXP"
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
