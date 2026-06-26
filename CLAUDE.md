# SafeMimic — Project Context

## What this project is
Black-box command-level adversarial mimicry attack on Provenance-based IDS (PIDS). Target venue: USENIX Security 2026. Attacker injects benign camouflage commands `δ` into attack scenario `A_0`, real-runs in docker, reads detector reply (`flagged_nodes`), iterates until `v_attack ∉ F` while preserving attack semantics.

Core thesis: existing methods (ProvNinja, Contorter) have a dual failure — they break attacks (safety) AND their camouflage backfires on detectors (stealthiness). SafeMimic formalizes both via dependency-respecting perturbation operators + Nettack-style unnoticeable constraints on attacker-side `G_benign`.

## Where we are right now

Research workflow lives in `A_Study_Stage/`:
- `0_Motivation_FINDINGS.md` — paper motivation: ProvNinja / Contorter expose two failure axes, P1 = OS-level safety/executability failure and P2 = stealthiness/backfire on ignored detector dimensions.
- `1_p1_formulation.md` — paper §3-§4: command-space problem formulation and manipulation operators. The paper-facing command-space actions are `Add / Edit / Move / Remove`, not SQL graph rewriting. `Edit` means command-relationship editing, not arbitrary shell-parameter rewriting.
- `pids_attack/p2_mcts_v3.md` — paper §5: SafeMimic-CMD black-box command-level search over the §4 command-space actions (anchored on GRABNEL §2 structure for writing, but the framework name is SafeMimic-CMD).
- `pids_attack/p3_results.md` — experiment ledger and paper-facing result notes.

Current experiment tracks aligned to the workflow:

1. **Motivation experiments (done; project root `baselines/pipelines/`).** These experiments reproduce ProvNinja and Contorter on their own published data and quantify the two motivation failures: P1 safety/executability failure and P2 stealthiness/backfire. `A_Study_Stage/0_Motivation_FINDINGS.md` is the paper-facing synthesis. Per-baseline writeups are `baselines/pipelines/{provninja,contorter}/FINDINGS.md` + `PROBLEM_JUSTIFICATION.md`; scripts and JSON results live under the same two pipeline directories (`extract_diffs.py` / `diffs*.json` for P1, `eval_*.py` / results JSON for P2).

2. **E0 detection (done under detection-side node-level baseline).** `pids_attack/experiments/E0_detection/` runs original `A_0` in benign background, builds attack-only-signature + marker-window GT, and reports Orthrus-style node-level TP/FP/TN/FN, Precision, and MCC. It is a detection experiment invoked by `scripts/run.py detect e0`, not the attack oracle.

3. **E1 = finding-driven 6-stage loop, NOT a pre-baked ablation table.** Canonical attack framework lives in `pids_attack/attack/safemimic_cmd/` (single paper-facing implementation). `experiments/E1_ablation/` is an **experiment track**: it only configures `SafeMimicConfig` variants, invokes `attack/safemimic_cmd/`, and collects JSON — **0 lines of attack logic**. The dependency direction is one-way: `experiments/E1_ablation/` may call the framework, but `attack/safemimic_cmd/` must never import, read, or depend on E1 result folders, grids, or aggregate scripts. E1 findings can drive later framework revisions, but the runtime implementation remains in `attack/`, not in `experiments/`. Stage order matches both paper §-progression and code dependency:
   - **E1.0 Bootstrap (§3 closure + §4 minimal Add)** — verify min closed loop: A0 + 1 Add δ → docker/strace → CDM/SQL → detector → R1/R2/ASR/JSON
   - **E1.1 Mutation primitive (§4)** — actions/{add, edit, move, remove}; legacy `rewrite` is being redefined as relationship-level `Edit`
   - **E1.2 Fitness design (§5.3)** — objectives/{f1_hinge, f2_endogenous_r, scalarize}
   - **E1.3 Search structure (§5.3/§5.4)** — search/{sequential, inner_ga, commit}
   - **E1.4 Surrogate (§5.2)** — surrogate/{wl_features, sparse_blr, ard}
   - **E1.5 Acquisition (§5.4)** — acquisition/{lcb, ei, thompson}
   
   Each stage = pilot run → finding → framework revision → re-pilot → gate pass → next stage. Stage X's pilot validates and revises the corresponding `safemimic_cmd/<layer>/` implementation. After all 6 stages pass + designs stabilize, scale to main grid. §4 TODO-1 (R1/R2) is folded into E1.0 closure check; §4 TODO-2 (operator independence) is folded into E1.1.

4. **E2 full attack (code updated, rerun needed).** `pids_attack/experiments/E2_attack/` contains the SafeMimic-CMD main attack grid. Existing JSON/CSV results are old graph-summary oracle artifacts; current code uses mixed-workload node-level GT oracle and must be rerun before paper claims.

## Key files (read in this order when returning)

1. `ORIGINAL_MAIN_THREAD.pdf` — original paper main thread, written by user before any code. High-level vision.
2. `PIDS_Adversarial_Attack_Requirements.md` — implementation requirements (BlackboxBench-aligned interfaces, threat model).
3. `0_Problem Statement & Motivation Experiment.md` — H1 (safety) / H2 (stealthiness) hypotheses + motivation design.
4. `A_Study_Stage/0_Motivation_FINDINGS.md` — ProvNinja / Contorter failure analysis (drives the motivation experiments in `baselines/pipelines/`).
5. `A_Study_Stage/1_p1_formulation.md` — §3 problem formulation + §4 command-space manipulation. Command-space actions are `Add / Edit / Move / Remove`; `Add` selects a full command from a finite command pool, and `Edit(delta_id,target_id)` searches command-to-command relations, not unbounded command parameters. Do not reinterpret them as graph-space P1/P2 SQL rewrites.
6. `pids_attack/p2_mcts_v3.md` — §5 method draft / algorithm notes for **SafeMimic-CMD** (framework name). GRABNEL/BagAmmo/FCGHunter/MOS-Attack are structural/fitness/scalarization references only, not framework names.
7. `pids_attack/p3_results.md` — current experiment ledger and paper-facing result notes.
8. `baselines/pipelines/{provninja,contorter}/FINDINGS.md` + `PROBLEM_JUSTIFICATION.md` — motivation experiment results (ProvNinja / Contorter failure reproduction).
9. `pids_attack/README.md` — code entry point; `scripts/run.py` is the single command to run the pipeline / attack.
10. `baselines/{provninja,contorter,goyal}/` — upstream pristine clones. `baselines/pipelines/{provninja,contorter}/` wraps them with reproduction scripts + FINDINGS. Don't modify the pristine clones.

## Codebase layout (under `pids_attack/`)

### 5-layer runtime pipeline (one query)

```
attack/ (algorithm) → attack/framework/oracle.py (query_with_validation_mixed)
  → range/mixed_workload.py (E0-style benign+A0+δ mixed trace)
    → range/checker.py + range/converter.py (docker exec + strace → CDM SQL)
      → detection/inference/registry.py (GNN/rule/hybrid per-node detector scores)
        → range/node_gt.py + range/node_metrics.py (E0-style node GT/metrics)
        → back to attack/ for state update
```

### Single entry

`scripts/run.py` is the only public CLI:
- `scripts/run.py detect ...` runs detection-side collection, training, diagnostics, and E0.
- `scripts/run.py attack smoke-query` runs one real A0 query through docker, strace, CDM conversion, and detector prediction.
- `scripts/run.py attack run` runs the SafeMimic-CMD attack framework via `attack/safemimic_cmd/runner.py` (by-config dispatch). `--mock` is only for algorithm smoke tests; real runs call `attack/framework/oracle.py`.

### `attack/` — single paper-facing framework: SafeMimic-CMD

- `attack/framework/` — shared contracts: `AttackScenario`, `QueryResult`, `QueryHistory`, `AttackResult`, and **`SafeMimicConfig`** (single config class — covers all E1.x variants).
- `attack/framework/oracle.py` — attack-time black-box oracle; calls `range/` for real mixed-workload execution and `detection/inference/` for detector inference.
- `attack/safemimic_cmd/` — **唯一 paper-facing 攻击框架**(SafeMimic-CMD)。Target structure (built layer-by-layer through E1.0 → E1.5):
  - `runner.py` — single CLI entry; by-config dispatch over operator / objective / search / surrogate / acquisition variants.
  - `search/one_shot.py` — E1.0 minimal Add profile (one-shot Add δ × 1 real query × R1/R2/GT/JSON).
  - `operators/{add, edit, move, remove}.py` — §4 mutation primitives (built in E1.1). Existing `rewrite.py` is legacy code until migrated to relationship-level `Edit`.
  - `constraints/{r1_attack_integrity, r2_delta_executable}.py` — §3 validity gates (built in E1.0).
  - `objectives/{f1_hinge, f2_endogenous_r, scalarize}.py` — §5.3 fitness (built in E1.2; **renamed** from `fitness/` to `objectives/` to match paper §5.3 terminology).
  - `search/{sequential, inner_ga, commit, one_shot}.py` — §5.3/§5.4 search (built in E1.3; one_shot is E1.0 bootstrap).
  - `surrogate/{wl_features, sparse_blr, ard}.py` — §5.2 surrogate (built in E1.4).
  - `acquisition/{lcb, ei, thompson}.py` — §5.4 acquisition (built in E1.5).
- `attack/grabnel_cmd/` + `attack/minimal_cmd/` — removed/archived legacy names; never recreate or reference them in new code or docs.

### `range/` — docker execution + strace + CDM conversion

- `Dockerfile` — `pids_range` image: Juice-Shop v15 + strace + Kali tools.
- `execute.py` — `_docker_exec`, `_execute_strace`, `STRACE_SYSCALLS` (19 syscalls covering CDM's 10 EVENT_* types).
- `checker.py` — `execute_with_checks` (fail-fast per step), `_interleave` (A_0 ⊕ δ ordering), batch-safe strace execution with append mode. 6 checker types: http_response_contains / http_status_code / exit_code / stdout_contains / file_exists / privilege_escalated / custom.
- `converter.py` — `parse_strace_text` (regex per line) → `build_cdm_graph_from_strace` (3 node types: subject/file/netflow, 10 EVENT_* edges) → `graph_to_sql` (DDL + INSERTs, PostgreSQL).
- `validation.py` — offline scenario sanity checks.

### `detection/` — training + detection framework

- **Collect** (`scripts/run.py detect collect` + `detection/data/benign_collection_plan.yml`): runs benign workloads in docker, strace records → `detection/data/training_traces/benign_<i>.{strace,sql}`. **Don't reintroduce `replicate_sql`** (assigned to bin 2026-05-11; real samples only).
- **Attack/test traces**: A0 attack traces live separately under `detection/data/test_traces/attack/` and are mapped only to PIDSMaker test dates; they must not be placed under `training_traces/`.
- **Train GNN** (`scripts/run.py detect train-gnn`): 5 steps — overview / ingest (`detection/data/data_prep.py`) / clean cache / train PIDSMaker detectors / eval. Artifacts in `detection/training/artifacts/`.
- **Train rules** (`scripts/run.py detect train-rules`): trains G1/G2 artifacts into `detection/artifacts/{g1,g2,g1g2}/`.
- **Infer GNN** (`detection/training/pidsmaker.py:_LocalDetector.predict_per_node(sql)` via `detection/inference/registry.py`): runs forward pass and returns per-node labels/scores. `_LocalDetector.predict(sql)` is only a raw graph-summary helper (`any(y_pred==1)`), not the attack success oracle.
- **Infer rules** (`detection/training/rules.py` via `detection/inference/registry.py`): SQL → CommandGraph + G1/G2/G1G2/hybrid detector inference.
- **Diagnostics** (`detection/diagnostics.py`): internal read-only detection health checks and threshold sweeps; not a public CLI contract.

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

### `experiments/E0_detection/` — A0 baseline detection

- `run.py` — detection-side E0 baseline. It runs all A0 scenarios in a mixed benign+attack trace, builds GT as attack-only normalized signatures intersected with the mixed-run BEGIN/END marker window, then runs detector node-level inference on the same `clean.strace.sql`.
- Default E0 detector set is 9 systems: `magic / orthrus / threatrace / g1 / g2 / g1g2 / magic_g1g2 / orthrus_g1g2 / threatrace_g1g2`.
- E0 summary columns are Orthrus-style node-level `TP / FP / TN / FN / Precision / MCC`, plus validity and artifact metadata. It no longer reports only `gt_recall` / `flagged_rate`.
- Results are recorded in `pids_attack/p3_results.md`.

### `tests/` — unittest suite (24 files)

Component-level unit tests. Run via `PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.<name> -v`.

### Cross-cutting traps

- **fake-date alignment**: `detection/data/data_prep.py:TRAIN_DATES/VAL_DATES/TEST_DATES/ATTACK_TO_DATE` must match `PIDSMaker/pidsmaker/config/config.py:JUICESHOP.{train,val,test}_dates/attack_to_time_window`. Changing one without the other silently breaks ingestion.
- **STAGE 3 positions constraint**: δ positions in `_interleave` must satisfy `positions[i] < n_steps` — otherwise δ lands after A_0's last step and `final_attack_check` misjudges `final_attack_succeeded=False`.
- **Per-query trace files**: each query produces `results/demo_traces/trace_<uuid>.{strace,strace.sql}`. Don't reuse UUIDs across queries.

### `baselines/` (project root, not under `pids_attack/`)

- `baselines/{provninja,contorter,goyal}/` — upstream pristine clones. Don't modify.
- `baselines/pipelines/{provninja,contorter}/` — our reproduction wrappers + `FINDINGS.md` + `PROBLEM_JUSTIFICATION.md` motivating SafeMimic. Run `extract_diffs.py` / `eval_*.py` scripts here, not in the pristine clones.

## Detector & paper anchors (hard fixings)

- **Motivation P1/P2 = failure axes, not mutation names.** In the motivation experiments (`baselines/pipelines/{provninja,contorter}/`), P1 = safety/executability failure axis and P2 = stealthiness/backfire failure axis. These are the two axes ProvNinja/Contorter fail on, not graph-space mutation operators.
- **SafeMimic primitive = command-space manipulation.** Do not treat SQL/CDM graph-space mutations as the paper mainline. The paper-facing actions are `Add / Edit / Move / Remove` over shell-command sequences from `1_p1_formulation.md`, executed in Docker and observed through strace. `Add(command_id,position)` chooses a full command, not a bare binary. `Edit(delta_id,target_id)` edits command-to-command provenance relations; the concrete file/process/network footprint is derived from the target command, not selected as an unbounded parameter.
- **E0 detector set = magic / orthrus / threatrace / g1 / g2 / g1g2 / magic_g1g2 / orthrus_g1g2 / threatrace_g1g2**. E0 is a detection-side baseline over 9 systems.
- **E2 detector set follows the current attack-grid scripts/results, not E0 by assumption.** Check `pids_attack/experiments/E2_attack/scripts/` before claiming the active E2 grid. PIDSMaker also integrates velox / kairos / flash / rcaid / nodlink, but those are not in scope unless explicitly requested.
- **Framework name = SafeMimic-CMD.** Paper §5 introduces "SafeMimic-CMD"; GRABNEL/BagAmmo/FCGHunter/MOS-Attack are cited as structural / fitness / scalarization references only. **Never write "GRABNEL-CMD" in paper, code, or docs as a framework name.**
- **Writing anchor (structure) = BagAmmo [USENIX'23] + GRABNEL [NeurIPS'21]** — §5 follows GRABNEL §2 paragraph structure (Problem Setup → Surrogate → Sequential perturbation selection → Optimisation via GA) and BagAmmo §5 paragraph order. See `p2_mcts_v3.md` for the active V3 draft.
- **§5 algorithm structural reference = GRABNEL [Wan et al. NeurIPS'21]** — double-layer BO: outer Sequential perturbation selection (K stages, 1 atomic op + 1 real query per stage) + inner GA on acquisition. Surrogate is **WL features + Sparse Bayesian Linear Regression with ARD prior** (GRABNEL 原汁), LCB / EI / Thompson acquisition. SafeMimic-CMD adopts the same skeleton but pairs it with §5.3 two-objective fitness.
- **§5 objectives reference = FCGHunter [Sen Chen et al. TSE'25] + MOS-Attack [arXiv 2501.07251, 2025]** — extends single-scalar fitness to **two-objective `(f_1, f_2)`** (FCGHunter Eq 4) composed via **soft-min Tchebycheff scalarization** (MOS-Attack). `f_1` = flagged-node hinge sum, `f_2` = k-NN similarity to **endogenous reference** `R = (R_unflagged, R_flagged)` accumulated during search (no preset `G_benign`). Code lives under `safemimic_cmd/objectives/` (not `fitness/` — paper §5.3 terminology is "objectives").
- **Substitute-free design (decided 2026-05-21)**: leaf eval directly queries `D_target` via docker exec. **Do not reintroduce substitute/surrogate models for the detector** unless the user explicitly asks. (The WL+BLR surrogate above is for the **fitness landscape**, not for emulating the detector.) Rationale: leaf cost dominated by docker exec, not detector inference; detector-side substitute adds train-test gap with negligible savings.

## Conventions

- **`attack/` vs `experiments/` 边界:** any mutation / objective / search / oracle / surrogate / acquisition logic lives in `attack/safemimic_cmd/` or `attack/framework/`. `experiments/E1_ablation/scripts/` only chooses `SafeMimicConfig` variants, invokes the public framework entry, and collects JSON/CSV/figures. This is a one-way dependency: `experiments/` may call `attack/`; `attack/` must not import `experiments/`, read experiment result folders, or hard-code E1 cell names. **0 attack logic in `experiments/`** — if you find yourself writing `apply_delta` / `compute_f1` / `query_oracle` / `inner_ga` / `acquisition` inside an experiment script, stop and move it under `attack/safemimic_cmd/`.
- **E1 finding-driven loop:** each E1.x cell = (pilot run → finding → framework revision → re-pilot → gate pass). Cell is NOT done until its finding section in `p3_results.md` §3.x is filled with `observed X → revised attack/Y → re-pilot Z`. Don't scale to main grid until all 6 stages pass their gates.
- **`SafeMimicConfig` is the single config class.** Legacy config names are retired; don't introduce new config classes.
- **Terminology:** code dir is `objectives/` (matching paper §5.3), not `fitness/`. Variant key in config is `objective`, not `fitness`. Old `fitness/` paths are shims being removed.
- When editing `p2_mcts_v3.md`, don't restructure unilaterally; propose changes and wait for approval. Prefer terse academic phrasing, positive framing (no "无 X / 不依赖 X"), and only cite papers genuinely used in body text.

## Python environment

- **Use the `mimicattack` conda env for everything.** Path: `/opt/anaconda3/envs/mimicattack`, Python 3.10.20.
- Run code with `conda run -n mimicattack python ...` or `source activate mimicattack` first.
- Already installed: numpy 1.24, scikit-learn 1.7, PyYAML 6, torch 2.1 + torch-geometric, requests, plus baselines extras (gensim 4.3.3 / gdown 6.0.0 for Contorter; tensorflow 2.13 / keras 2.13 for ProvNinja's Prov-GAT). **No pytest** — use Python's built-in `unittest` (already importable).
- Don't `pip install` new packages without asking — work with what's there.

## Running pieces of the pipeline

- Detection baseline: `PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py detect e0`
- Pipeline smoke: `conda run -n mimicattack python pids_attack/scripts/run.py attack smoke-query` (needs Docker Desktop open)
- Attack run: `PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack run --scenario 01 --detector magic`
- Unittests: `PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.<name> -v`
