# SafeMimic — Project Context

## What this project is
Black-box command-level adversarial mimicry attack on Provenance-based IDS (PIDS). Target venue: USENIX Security 2026. Attacker injects benign camouflage commands `δ` into attack scenario `A_0`, real-runs in docker, reads detector reply (`flagged_nodes`), iterates until `v_attack ∉ F` while preserving attack semantics.

Core thesis: existing methods (ProvNinja, Contorter) have a dual failure — they break attacks (safety) AND their camouflage backfires on detectors (stealthiness). SafeMimic formalizes both via dependency-respecting perturbation operators + Nettack-style unnoticeable constraints on attacker-side `G_benign`.

## Where we are right now

Research workflow lives in `A_Study_Stage/`:
- `0_Motivation_FINDINGS.md` — failure analysis of ProvNinja / Contorter.
- `1_p1_formulation.md` — formal mutation definitions (P1 shared-neighbor dilution / P2 edge rerouting, plus §3 problem formulation and §4 atomic operators).

Three completed / active tracks aligned to the workflow:

1. **Motivation experiments (done).** `baselines/pipelines/` reproduces ProvNinja and Contorter on their own published data to quantify their failure modes. Results in `baselines/pipelines/{provninja,contorter}/FINDINGS.md` + `PROBLEM_JUSTIFICATION.md`.

2. **Mutation-definition validation (done).** `pids_attack/experiments/E1/` takes the P1 / P2 atomic ops from `1_p1_formulation.md` and runs them against 3 detectors (magic / orthrus / threatrace from PIDSMaker) on real PIDSMaker artifacts. Evade-rate numbers in `pids_attack/experiments/E1/FINDINGS.md` — **real runtime, not synthetic**.

3. **Search algorithm (active).** `pids_attack/p2_mcts.md` is the active §5 draft — MCTS-CMD combining the validated P1/P2 atomic ops into adversarial sequences. Uses R3 (Nettack §4.1 unnoticeable filter on attacker prior `G_benign`) + soft-min Tchebycheff reward (multi-target evasion) + WL canonical-hash query caching. Refined paragraph-by-paragraph with user confirmation gates.

## Key files (read in this order when returning)

1. `ORIGINAL_MAIN_THREAD.pdf` — original paper main thread, written by user before any code. High-level vision.
2. `PIDS_Adversarial_Attack_Requirements.md` — implementation requirements (BlackboxBench-aligned interfaces, threat model).
3. `0_Problem Statement & Motivation Experiment.md` — H1 (safety) / H2 (stealthiness) hypotheses + motivation design.
4. `A_Study_Stage/0_Motivation_FINDINGS.md` — ProvNinja / Contorter failure analysis (drives the motivation experiments in `baselines/pipelines/`).
5. `A_Study_Stage/1_p1_formulation.md` — §3 problem formulation + §4 mutation operator (P1/P2) definitions; predecessor to `p2_mcts.md` §5. Validated by `pids_attack/experiments/E1/`.
6. `pids_attack/p2_mcts.md` — **active §5 draft** (MCTS-CMD search algorithm).
7. `baselines/pipelines/{provninja,contorter}/FINDINGS.md` + `PROBLEM_JUSTIFICATION.md` — motivation experiment results (ProvNinja / Contorter failure reproduction).
8. `pids_attack/experiments/E1/FINDINGS.md` + `README.md` — P1/P2 mutation validation against 3 detectors (magic / orthrus / threatrace).
9. `pids_attack/README.md` — code entry point; `scripts/run.py` is the single command to run the full pipeline.
10. `paper/main.tex` + `paper/sections/` — LaTeX paper draft (compiled to `main.pdf`).
11. `baselines/{provninja,contorter,goyal}/` — upstream pristine clones. `baselines/pipelines/{provninja,contorter}/` wraps them with reproduction scripts + FINDINGS. Don't modify the pristine clones.

## Codebase layout (under `pids_attack/`)

### 5-layer runtime pipeline (one query)

```
attack/ (algorithm) → oracle/pidsmaker_wrapper.py (query_with_validation_strict)
  → range/checker.py (execute_with_checks: docker exec + strace + 6 checker types)
    → range/converter.py (strace text → CDM graph → SQL dump)
      → oracle/pidsmaker_inference.py (_LocalDetector.predict → y ∈ {0,1})
        → back to attack/ for state update
```

### Single entry + 8 STAGE

`scripts/run.py` drives end-to-end:
- STAGE 0 preflight / 1 docker (`pids_range` Juice-Shop target + `pids_postgres`) / 2 load scenario JSON / 3 execute A_0 + strace + checker / 5 strace → CDM SQL / 6 detector predict / 7 `BlackboxAttack.run` loop. STAGE 4 is intentionally absent.
- Flags: `--skip-attack` (pipeline-only, ~10s), `--skip-setup` (containers already up), `--budget N` (query cap).

### `attack/` — 9 components, dependency-injected by name

`BlackboxAttack` in `attack/algorithm.py` composes named candidates from these dirs (see `attack/builder.py`):

| Component | Candidates |
|---|---|
| `search_space/` | set / sequence / positioned / templated (4) |
| `initialization/` | random / history / prior / multi_start (4) |
| `perturbation/` | random / importance / history / gradient_estimation + combined / order_swap / position_shift / parameter_swap (8) |
| `acceptance/` | greedy / annealing / threshold / uncertainty (4) |
| `guidance/` | importance / bandit / bayesian / boundary / leave_one_out / surrogate (6) |
| `state_update/` | single_point / population / multi_population / elite_archive (4) |
| `termination/` | first_success / consecutive / budget / combined (4) |
| `fitness/` | guidance / similarity / diversity / size / population_pref / combined (6) |

`config.py` parameterises all hyperparams; `history.py` tracks `QueryHistory` (incl. invalid queries that don't burn budget).

### `range/` — docker execution + strace + CDM conversion

- `Dockerfile` — `pids_range` image: Juice-Shop v15 + strace + Kali tools.
- `execute.py` — `_docker_exec`, `_execute_strace`, `STRACE_SYSCALLS` (19 syscalls covering CDM's 10 EVENT_* types).
- `checker.py` — `execute_with_checks` (fail-fast per step), `_interleave` (A_0 ⊕ δ ordering), `_exec_traced` (strace -fA -ttt with append mode). 6 checker types: http_response_contains / http_status_code / exit_code / stdout_contains / file_exists / privilege_escalated / custom.
- `converter.py` — `parse_strace_text` (regex per line) → `build_cdm_graph_from_strace` (3 node types: subject/file/netflow, 10 EVENT_* edges) → `graph_to_sql` (DDL + INSERTs, PostgreSQL).
- `validation.py` — offline scenario sanity checks.

### `oracle/` — PIDS oracle (3 phases: collect → train → infer)

- **Collect** (`scripts/collect_benign.py` + `data/benign_collection_plan.yml`): `--num-collections 30 --parallel 4` runs 7 daemons + 10 scenarios in docker, strace records → `data/training_traces/benign_<i>.{strace,sql}`. **Don't reintroduce `replicate_sql`** (assigned to bin 2026-05-11; real samples only).
- **Train** (`oracle/train_pidsmaker.py`): 5 steps — overview / ingest (`data_prep/juiceshop.py`) / clean cache / train 8 detectors via `subprocess.run([python pidsmaker/main.py <d> JUICESHOP ...])` / eval. Artifacts in `data/pidsmaker_artifacts/{construction,transformation,featurization,feat_inference,batching,training,evaluation,triage}/`.
- **Infer** (`oracle/pidsmaker_inference.py:_LocalDetector.predict(sql)`): runs forward pass, returns `y∈{0,1}` from `any(y_pred==1)`. `PIDSMakerEngine._ensure_loaded()` loads model + threshold + featurizer once (~3-5min); class-level cache reused across instances.
- **Wrap** (`oracle/pidsmaker_wrapper.py:query_with_validation_strict`): single entry for STAGE 7 attack loop — runs checker, builds trace, predicts; invalid checker → `QueryResult.invalid_` doesn't burn budget.

### `data/` — attack scenarios + candidate pool + training data

- `attack_sequences/*.json` — 10 Juice-Shop A_0 scenarios, payloads 1:1 translated from `routes/*.ts solveIf(...)` server-side conditions; verified by `scripts/verify_attack_solves.py` (10/10 server `solved=true`).
- `candidate_pool.txt` — 106 δ candidates with traceable source tags: ART/T1xxx (18 entries from Atomic Red Team Discovery YAMLs), gtfobins/ (8 file-read entries), coreutils/procps/util-linux/iproute2/bash (80 from official man pages).
- `command_templates.json` — templates for `search_space=templated`.
- `training_traces/benign_<i>.{strace,proc_snapshot,sql}` — collected by `collect_benign.py`.
- `pidsmaker_artifacts/` — trained model artifacts (~4.6 GB, models ~80 MB).

### `PIDSMaker/` — vendored upstream

Fork of [ubc-provenance/PIDSMaker](https://github.com/ubc-provenance/PIDSMaker) (docker compose, configs, 8 detectors integrated). **Not first-party code; don't restructure.** Four upstream patches we keep applied:
- `data_utils.py:compute_tgn_graphs` + chain → return `neighbor_loader` (fixes save_model AttributeError on TGN models).
- `training_loop.py:main` → bind `model.encoder.neighbor_loader` post-build_model.
- `data_utils.py:save_model/load_model` → strict logic (no `getattr` fallback).
- New threshold methods `p90/p98/p99_val_loss` in `utils.py` + `evaluation_methods/evaluation_utils.py` + `config/config.py` — fixes `max_val_loss` outlier on JUICESHOP (rcaid/kairos/velox F1 0 → 0.49/0.81/0.66).

### `experiments/E1/` — P1/P2 mutation validation

- `proofs/_common.py` — shared `load_baseline / eval_attack_node / SQL 改写`, plus the 2 atomic perturbations (`shared_neighbor_dilution` = P1, `edge_rerouting` = P2).
- `proofs/{magic,orthrus,threatrace}.py` — graph-space variants per detector; results in `proofs_results/<det>.json`.
- `proofs/{magic,orthrus,threatrace}_cmd.py` — cmd-space variants.
- `FINDINGS.md` reports per-variant evade_rate, e.g. magic P1=5/5, orthrus P1=8/9, threatrace P1=4/6 (file 4/4, netflow 0/2).

### `tests/` — unittest suite (24 files)

Component-level unit tests. Run via `PYTHONPATH=. conda run -n mimicattack python -m unittest tests.<name> -v`.

### Cross-cutting traps

- **fake-date alignment**: `data_prep/juiceshop.py:TRAIN_DATES/VAL_DATES/TEST_DATES/ATTACK_TO_DATE` must match `PIDSMaker/pidsmaker/config/config.py:JUICESHOP.{train,val,test}_dates/attack_to_time_window`. Changing one without the other silently breaks ingestion.
- **STAGE 3 positions constraint**: δ positions in `_interleave` must satisfy `positions[i] < n_steps` — otherwise δ lands after A_0's last step and `final_attack_check` misjudges `final_attack_succeeded=False`.
- **Per-query trace files**: each query produces `results/demo_traces/trace_<uuid>.{strace,strace.sql}`. Don't reuse UUIDs across queries.

### `baselines/` (project root, not under `pids_attack/`)

- `baselines/{provninja,contorter,goyal}/` — upstream pristine clones. Don't modify.
- `baselines/pipelines/{provninja,contorter}/` — our reproduction wrappers + `FINDINGS.md` + `PROBLEM_JUSTIFICATION.md` motivating SafeMimic. Run `extract_diffs.py` / `eval_*.py` scripts here, not in the pristine clones.

## Detector & paper anchors (hard fixings)

- **Detector subset used = magic / orthrus / threatrace** (all from PIDSMaker). PIDSMaker also integrates velox / kairos / flash / rcaid / nodlink, but those are **not in scope** for this paper. Don't add evaluations against them without asking.
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

- Full pipeline: `conda run -n mimicattack python pids_attack/scripts/run.py` (needs Docker Desktop open)
- Skip attack loop, only the 5-layer pipeline: `python pids_attack/scripts/run.py --skip-attack` (~10s)
- Motivation proofs: `PYTHONPATH=. conda run -n mimicattack python pids_attack/experiments/E1/proofs/{magic,orthrus,threatrace}.py`
- Unittests: `PYTHONPATH=. conda run -n mimicattack python -m unittest tests.<name> -v`