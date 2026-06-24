# SafeMimic — Project Context

## What this project is
Black-box command-level adversarial mimicry attack on Provenance-based IDS (PIDS). Target venue: USENIX Security 2026. Attacker injects benign camouflage commands `δ` into attack scenario `A_0`, real-runs in docker, reads detector reply (`flagged_nodes`), iterates until `v_attack ∉ F` while preserving attack semantics.

Core thesis: existing methods (ProvNinja, Contorter) have a dual failure — they break attacks (safety) AND their camouflage backfires on detectors (stealthiness). SafeMimic formalizes both via dependency-respecting perturbation operators + Nettack-style unnoticeable constraints on attacker-side `G_benign`.

## Where we are right now

Research workflow lives in `A_Study_Stage/`:
- `0_Motivation_FINDINGS.md` — failure analysis of ProvNinja / Contorter.
- `1_p1_formulation.md` — formal mutation definitions (P1 shared-neighbor dilution / P2 edge rerouting, plus §3 problem formulation and §4 atomic operators).

Current experiment tracks aligned to the workflow:

1. **Motivation experiments (done).** `baselines/pipelines/` reproduces ProvNinja and Contorter on their own published data to quantify their failure modes. Results in `baselines/pipelines/{provninja,contorter}/FINDINGS.md` + `PROBLEM_JUSTIFICATION.md`.

2. **E0 detection (done under detection-side node-level baseline).** `pids_attack/experiments/E0_detection/` runs original `A_0` in benign background, builds attack-only-signature + marker-window GT, and reports Orthrus-style node-level TP/FP/TN/FN, Precision, and MCC. It is a detection experiment invoked by `scripts/run.py detect e0`, not the attack oracle.

3. **E1 mutation-definition validation (done).** `pids_attack/experiments/E1_operators/` takes the P1 / P2 atomic ops from `1_p1_formulation.md` and runs them against magic / orthrus / threatrace on real PIDSMaker artifacts. Evade-rate numbers in `pids_attack/experiments/E1_operators/FINDINGS.md` — **real runtime, not synthetic**.

4. **E2 ablation / sensitivity (wired, old results retained).** `pids_attack/experiments/E2_ablation/` contains feature / surrogate / f2 / scalarization / commit / acquisition / GA-command ablations.

5. **E3 full attack (code updated, rerun needed).** `pids_attack/experiments/E3_attack/` contains the GRABNEL main attack grid. Existing JSON/CSV results are old graph-summary oracle artifacts; current code uses GT/attack-node oracle and must be rerun before paper claims.

## Key files (read in this order when returning)

1. `ORIGINAL_MAIN_THREAD.pdf` — original paper main thread, written by user before any code. High-level vision.
2. `PIDS_Adversarial_Attack_Requirements.md` — implementation requirements (BlackboxBench-aligned interfaces, threat model).
3. `0_Problem Statement & Motivation Experiment.md` — H1 (safety) / H2 (stealthiness) hypotheses + motivation design.
4. `A_Study_Stage/0_Motivation_FINDINGS.md` — ProvNinja / Contorter failure analysis (drives the motivation experiments in `baselines/pipelines/`).
5. `A_Study_Stage/1_p1_formulation.md` — §3 problem formulation + §4 mutation operator (P1/P2) definitions; predecessor to `p2_mcts.md` §5. Validated by `pids_attack/experiments/E1_operators/`.
6. `pids_attack/p3_results.md` — current experiment ledger and paper-facing result notes.
7. `pids_attack/p2_mcts.md` — §5 method draft / algorithm notes.
8. `baselines/pipelines/{provninja,contorter}/FINDINGS.md` + `PROBLEM_JUSTIFICATION.md` — motivation experiment results (ProvNinja / Contorter failure reproduction).
9. `pids_attack/experiments/E1_operators/FINDINGS.md` + `README.md` — P1/P2 mutation validation against 3 detectors (magic / orthrus / threatrace).
10. `pids_attack/README.md` — code entry point; `scripts/run.py` is the single command to run the pipeline / attack.
11. `paper/main.tex` + `paper/sections/` — LaTeX paper draft (compiled to `main.pdf`).
12. `baselines/{provninja,contorter,goyal}/` — upstream pristine clones. `baselines/pipelines/{provninja,contorter}/` wraps them with reproduction scripts + FINDINGS. Don't modify the pristine clones.

## Codebase layout (under `pids_attack/`)

### 5-layer runtime pipeline (one query)

```
attack/ (algorithm) → attack/oracle.py (query_with_validation_strict)
  → range/checker.py (execute_with_checks: docker exec + strace + 6 checker types)
    → range/converter.py (strace text → CDM graph → SQL dump)
      → detection/pidsmaker.py or detection/rules.py (per-node detector scores)
        → wrapper filters GT/attack nodes → y ∈ {0,1}
        → back to attack/ for state update
```

### Single entry

`scripts/run.py` is the only public CLI:
- `scripts/run.py detect ...` runs detection-side collection, training, diagnostics, and E0.
- `scripts/run.py attack smoke-query` runs one real A0 query through docker, strace, CDM conversion, and detector prediction.
- `scripts/run.py attack run` runs the current GRABNEL command-level search. `--mock` is only for algorithm smoke tests; real runs call `attack/oracle.py`.

### `attack/` — current method code

- `attack/framework/` — shared contracts: `AttackScenario`, `QueryResult`, `QueryHistory`, `AttackResult`.
- `attack/grabnel_cmd/runner.py` — attack mode runner imported by `scripts/run.py`.
- `attack/grabnel_cmd/algorithm.py` — outer GRABNEL loop.
- `attack/grabnel_cmd/inner_ga.py` — candidate delta generation.
- `attack/grabnel_cmd/commit.py` — sequential commit policy.
- `attack/grabnel_cmd/fitness/` — attack/stealth objectives and scalarization.
- `attack/grabnel_cmd/surrogate/` — WL features and sparse BLR.
- `attack/grabnel_cmd/acquisition/` — LCB / EI / Thompson acquisition.
- `attack/oracle.py` — attack-time black-box oracle; calls `range/` for real execution and `detection/` for detector inference.

### `range/` — docker execution + strace + CDM conversion

- `Dockerfile` — `pids_range` image: Juice-Shop v15 + strace + Kali tools.
- `execute.py` — `_docker_exec`, `_execute_strace`, `STRACE_SYSCALLS` (19 syscalls covering CDM's 10 EVENT_* types).
- `checker.py` — `execute_with_checks` (fail-fast per step), `_interleave` (A_0 ⊕ δ ordering), batch-safe strace execution with append mode. 6 checker types: http_response_contains / http_status_code / exit_code / stdout_contains / file_exists / privilege_escalated / custom.
- `converter.py` — `parse_strace_text` (regex per line) → `build_cdm_graph_from_strace` (3 node types: subject/file/netflow, 10 EVENT_* edges) → `graph_to_sql` (DDL + INSERTs, PostgreSQL).
- `validation.py` — offline scenario sanity checks.

### `detection/` — training + detection framework

- **Collect** (`scripts/run.py detect collect-benign` + `detection/data/benign_collection_plan.yml`): runs 7 daemons + 10 scenarios in docker, strace records → `detection/data/training_traces/benign_<i>.{strace,sql}`. **Don't reintroduce `replicate_sql`** (assigned to bin 2026-05-11; real samples only).
- **Train GNN** (`scripts/run.py detect train-gnn`): 5 steps — overview / ingest (`detection/data_prep.py`) / clean cache / train PIDSMaker detectors / eval. Artifacts in `detection/data/pidsmaker_artifacts/`.
- **Train rules** (`scripts/run.py detect train-rules`): trains G1/G2 artifacts into `detection/data/hybrid_rules/`.
- **Infer GNN** (`detection/pidsmaker.py:_LocalDetector.predict_per_node(sql)`): runs forward pass and returns per-node labels/scores. `_LocalDetector.predict(sql)` is only a raw graph-summary helper (`any(y_pred==1)`), not the attack success oracle.
- **Infer rules** (`detection/rules.py`): SQL → CommandGraph + G1/G2/G1G2/hybrid detector inference.
- **Diagnostics** (`scripts/run.py detect audit` / `threshold-sweep`): read-only detection health checks and threshold sweeps.

### Shared data

- `scenarios/juiceshop/*.json` — 10 Juice-Shop A_0 scenarios, payloads 1:1 translated from `routes/*.ts solveIf(...)`; verified by `scripts/validation/attack_scenarios.py`.
- `shared/candidate_pool.txt` — δ candidate command pool with traceable source tags.
- `attack/data/command_templates.json` — templates for command-space search.
- `shared/g_benign.pkl` — attacker-side benign prior generated from public command prior.

### `PIDSMaker/` — vendored upstream

Fork of [ubc-provenance/PIDSMaker](https://github.com/ubc-provenance/PIDSMaker) (docker compose, configs, 8 detectors integrated). **Not first-party code; don't restructure.** Four upstream patches we keep applied:
- `data_utils.py:compute_tgn_graphs` + chain → return `neighbor_loader` (fixes save_model AttributeError on TGN models).
- `training_loop.py:main` → bind `model.encoder.neighbor_loader` post-build_model.
- `data_utils.py:save_model/load_model` → strict logic (no `getattr` fallback).
- New threshold methods `p90/p98/p99_val_loss` in `utils.py` + `evaluation_methods/evaluation_utils.py` + `config/config.py` — fixes `max_val_loss` outlier on JUICESHOP (rcaid/kairos/velox F1 0 → 0.49/0.81/0.66).

### `experiments/E1_operators/` — P1/P2 mutation validation

- `proofs/_common.py` — shared `load_baseline / eval_attack_node / SQL 改写`, plus the 2 atomic perturbations (`shared_neighbor_dilution` = P1, `edge_rerouting` = P2).
- `proofs/{magic,orthrus,threatrace}.py` — graph-space variants per detector; results in `proofs_results/<det>.json`.
- `proofs/{magic,orthrus,threatrace}_cmd.py` — cmd-space variants.
- `FINDINGS.md` reports per-variant evade_rate, e.g. magic P1=5/5, orthrus P1=8/9, threatrace P1=4/6 (file 4/4, netflow 0/2).

### `experiments/E0_detection/` — A0 baseline detection

- `run.py` — detection-side E0 baseline. It runs all A0 scenarios in a mixed benign+attack trace, builds GT as attack-only normalized signatures intersected with the mixed-run BEGIN/END marker window, then runs detector node-level inference on the same `clean.strace.sql`.
- Default E0 detector set is 9 systems: `magic / orthrus / threatrace / g1 / g2 / g1g2 / magic_g1g2 / orthrus_g1g2 / threatrace_g1g2`.
- E0 summary columns are Orthrus-style node-level `TP / FP / TN / FN / Precision / MCC`, plus validity and artifact metadata. It no longer reports only `gt_recall` / `flagged_rate`.
- Results are recorded in `pids_attack/p3_results.md`.

### `tests/` — unittest suite (24 files)

Component-level unit tests. Run via `PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.<name> -v`.

### Cross-cutting traps

- **fake-date alignment**: `detection/data_prep.py:TRAIN_DATES/VAL_DATES/TEST_DATES/ATTACK_TO_DATE` must match `PIDSMaker/pidsmaker/config/config.py:JUICESHOP.{train,val,test}_dates/attack_to_time_window`. Changing one without the other silently breaks ingestion.
- **STAGE 3 positions constraint**: δ positions in `_interleave` must satisfy `positions[i] < n_steps` — otherwise δ lands after A_0's last step and `final_attack_check` misjudges `final_attack_succeeded=False`.
- **Per-query trace files**: each query produces `results/demo_traces/trace_<uuid>.{strace,strace.sql}`. Don't reuse UUIDs across queries.

### `baselines/` (project root, not under `pids_attack/`)

- `baselines/{provninja,contorter,goyal}/` — upstream pristine clones. Don't modify.
- `baselines/pipelines/{provninja,contorter}/` — our reproduction wrappers + `FINDINGS.md` + `PROBLEM_JUSTIFICATION.md` motivating SafeMimic. Run `extract_diffs.py` / `eval_*.py` scripts here, not in the pristine clones.

## Detector & paper anchors (hard fixings)

- **E1 detector subset = magic / orthrus / threatrace** (PIDSMaker node-level detectors used for operator validation).
- **E0 detector set = magic / orthrus / threatrace / g1 / g2 / g1g2 / magic_g1g2 / orthrus_g1g2 / threatrace_g1g2**. E0 is a detection-side baseline over 9 systems.
- **E3 detector set follows the current attack-grid scripts/results, not E0 by assumption.** Check `pids_attack/experiments/E3_attack/scripts/` before claiming the active E3 grid. PIDSMaker also integrates velox / kairos / flash / rcaid / nodlink, but those are not in scope unless explicitly requested.
- **Writing anchor = BagAmmo [USENIX'23]** — `method_design/pids_writing_thread.md` mirrors BagAmmo §3-§5.5 paragraph by paragraph. Sole reference for paper structure.
- **§5 algorithm anchor = MalGuise [USENIX'24]** — cross-domain transfer (PE → provenance, problem-space real-exec). Double-layer MCTS structure inherits from MalGuise.
- **Substitute-free design (decided 2026-05-21)**: leaf eval directly queries `D_target` via docker exec. **Do not reintroduce substitute/surrogate models** unless the user explicitly asks. Rationale: leaf cost dominated by docker exec, not detector inference; substitute adds train-test gap with negligible savings.

## Conventions

- When editing `p2_mcts.md`, don't restructure unilaterally; propose changes and wait for approval. Prefer terse academic phrasing, positive framing (no "无 X / 不依赖 X"), and only cite papers genuinely used in body text.

## Python environment

- **Use the `mimicattack` conda env for everything.** Path: `/opt/anaconda3/envs/mimicattack`, Python 3.10.20.
- Run code with `conda run -n mimicattack python ...` or `source activate mimicattack` first.
- Already installed: numpy 1.24, scikit-learn 1.7, PyYAML 6, torch 2.1 + torch-geometric, requests, plus baselines extras (gensim 4.3.3 / gdown 6.0.0 for Contorter; tensorflow 2.13 / keras 2.13 for ProvNinja's Prov-GAT). **No pytest** — use Python's built-in `unittest` (already importable).
- Don't `pip install` new packages without asking — work with what's there.

## Running pieces of the pipeline

- Detection audit: `PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py detect audit`
- Pipeline smoke: `conda run -n mimicattack python pids_attack/scripts/run.py attack smoke-query` (needs Docker Desktop open)
- Attack run: `PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack run --scenario 01 --detector magic`
- Motivation proofs: `PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/{magic,orthrus,threatrace}.py`
- Unittests: `PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.<name> -v`
