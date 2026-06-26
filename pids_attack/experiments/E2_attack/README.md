# E2 Attack

Purpose: complete SafeMimic-CMD end-to-end attack experiment.

E2 is the full attack table after E1 validates and stabilizes the attack
framework components.

## Structure

```text
E2_attack/
├── E2.0_main_attack/
│   └── results/
├── scripts/
├── figures/
├── logs/
└── snapshots/
```

## Current Result

Raw result count: 700 JSON files.

Current E2.0 result is legacy and must be rerun after the mixed-workload
attack oracle migration:

- `g1`: legacy full-pipeline 100% SR, random 96% SR.
- `g2`, `g1g2`, `magic`, `orthrus`, `threatrace`, `magic_g1g2`: 0% SR.

## Commands

```bash
bash pids_attack/experiments/E2_attack/scripts/run_grid.sh E2.0_main_attack --dry-run
PYTHONPATH=pids_attack conda run -n mimicattack python \
  pids_attack/experiments/E2_attack/scripts/aggregate.py \
  --root pids_attack/experiments/E2_attack \
  --out figures/E2_attack_summary_final.csv
```
