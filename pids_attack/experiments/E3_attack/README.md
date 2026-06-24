# E3 Attack

Purpose: complete GRABNEL attack experiment.

E3 is the final end-to-end attack table after E1 validates the atomic operators
and E2 studies component choices.

## Structure

```text
E3_attack/
├── E3.0_main_attack/
│   └── results/
├── scripts/
├── figures/
├── logs/
└── snapshots/
```

## Current Result

Raw result count: 700 JSON files.

Current E3.0 result:

- `g1`: GRABNEL 100% SR, random 96% SR.
- `g2`, `g1g2`, `magic`, `orthrus`, `threatrace`, `magic_g1g2`: 0% SR.

## Commands

```bash
bash pids_attack/experiments/E3_attack/scripts/run_grid.sh E3.0_main_attack --dry-run
PYTHONPATH=pids_attack conda run -n mimicattack python \
  pids_attack/experiments/E3_attack/scripts/aggregate.py \
  --root pids_attack/experiments/E3_attack \
  --out figures/E3_attack_summary_final.csv
```
