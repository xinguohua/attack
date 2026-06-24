# E2 Ablation

Purpose: component ablation and sensitivity studies for SafeMimic-CMD.

E2 is not the final attack table. It tests whether individual GRABNEL design
choices change the outcome before running the complete attack in E3.

## Structure

```text
E2_ablation/
├── E2.1_features/
├── E2.2_surrogate/
├── E2.3_f2_metric/
├── E2.4_scalarize/
├── E2.5_commit/
├── E2.6_acquisition/
├── E2.7_ga_cmd/
├── scripts/
├── figures/
├── logs/
└── snapshots/
```

## Current Result

Raw result count: 1749 JSON files.

All completed E2 ablations currently have 0% SR. This has limited paper value
because the base detector is mostly `magic`, where the complete attack also has
0% SR.

## Commands

```bash
bash pids_attack/experiments/E2_ablation/scripts/run_grid.sh E2.1_features --dry-run
PYTHONPATH=pids_attack conda run -n mimicattack python \
  pids_attack/experiments/E2_ablation/scripts/aggregate.py \
  --root pids_attack/experiments/E2_ablation \
  --out figures/E2_ablation_summary_final.csv
```
