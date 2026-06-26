# SafeMimic-CMD v3 — 实验结果

> 此文件跟 `p3_implementation_plan.md` 同目录。
> **每个 stage 跑完必须立刻更新这个文件** — 这是 paper writing 的唯一数据源。

最近更新: 2026-06-25

口径更新:

- E0 当前使用 **two-run batch workload** node-level 口径:Run 1 只跑完整 A0 block 生成 attack-only normalized node signatures;Run 2 跑 benign background + 同一个 A0 block,detector 只看 mixed SQL。
- E0 GT 定义为 `mixed marker window touched nodes ∩ attack-only signatures`。不使用 scenario `gt_keywords`,也不做噪音过滤;主结果只采用 Orthrus-style node-level evaluation:`TP / FP / TN / FN / Precision / Recall / overall MCC / macro MCC`。
- E1/E2 attack oracle 当前使用 **cached-mixed** 口径:每个候选 δ 仍真实执行 `A0⊕δ` 并验证 R1/R2;detector 输入由 cached benign trace + 本次 attack trace 组合得到,再用同一 marker-window GT 计算 node-level metrics。
- E0 当前主结果覆盖完整 9 个 detector:`magic / orthrus / threatrace / g1 / g2 / g1g2 / magic_g1g2 / orthrus_g1g2 / threatrace_g1g2`。
- E0 当前外层 detector adapter 不改 PIDSMaker upstream;只保留 E0 controller artifact cleanup。旧 generic system-noise filtering 与 executable-file post-filter 已撤回,不计入 clean baseline。
- E0 v1 batch artifact 已去掉 runner 污染:`orchestrator.sh / step_000*.sh / timeout / /tmp/e0_*/out/* / date +%s%N` 不再进入 fresh GT evidence。`curl / head / python3 / 127.0.0.1:3000 / runtime libraries` 属于真实攻击执行 footprint,按本轮 GT 定义保留。
- 已有 E2 JSON/CSV 是旧 graph-summary oracle 口径下生成的历史产物,保留作原始结果,但不能再作为 paper 主结论;E2 需要按新 oracle 重跑。

原始数据:

- E0: `experiments/E0_detection/results/summary_orthrus.csv`
- E0 per-scenario diagnostics: `experiments/E0_detection/results/summary_all.csv`
- E0 detector artifacts: `detection/artifacts/<detector>/manifest.json`
- E0 detector artifact summary: `detection/artifacts/manifest.json`
- E1: `experiments/E1_ablation/E1.*/*/results/*.json`
- E2: `experiments/E2_attack/E2.0_main_attack/results/*.json`
- E1 聚合: `experiments/E1_ablation/figures/E1_ablation_summary_final.csv`
- E2 聚合: `experiments/E2_attack/figures/E2_attack_summary_final.csv`
- E1 snapshots: `experiments/E1_ablation/snapshots/<stage>/summary.csv`
- E2 snapshots: `experiments/E2_attack/snapshots/<stage>/summary.csv`

---

## 1. 总览

### 实验进度

| Experiment | Variants | wired 状态 | 目标 | 已完成 | 进度 |
|---|---|---|---:|---:|---|
| **E0** A0 detection | 10 scenarios × 9 detectors | ✅ v1 two-run batch node-level GT | 90 | **90** | **✅ 100%** |
| **E1.0** Attack framework bootstrap | minimal_add × threatrace_g1g2 × 2 scenarios | ✅ done(2026-06-25) | 2 | **2** | **✅ 100%** |
| **E1.1** Mutation primitive(§4) | add_only / add_edit / add_edit_move / all4 = 4 | ⚠️ legacy pilot done, new Edit design pending | 4 pilot | 4 legacy pilot | **⚠️ 设计验证未完成** |
| **E1.2** Fitness(§5.3) | f1_only / f1_f2 = 2 | ⏳ 待跑 | 100 | 0 | **⏳ 0%** |
| **E1.3** Search structure(§5.3/§5.4) | full / random = 2 | ⏳ 待跑 | 100 | 0 | **⏳ 0%** |
| **E1.4** Surrogate(§5.2) | blr_ard / blr_noard / no_posterior = 3 | ⏳ 待跑 | 150 | 0 | **⏳ 0%** |
| **E1.5** Acquisition(§5.4) | lcb / ei / thompson = 3 | ⏳ 待跑 | 150 | 0 | **⏳ 0%** |
| **E2.0** main attack | 2 algos × 7 detectors = 14 | ⚠️ 旧 graph-summary 结果保留;新 attack-node oracle 待重跑 | 700 | **700 old / 0 new** | **⚠️ 待重跑** |
| **E0+E1+E2 cell 总计** | | | **1582** | **96 current + 700 old E2** | **⚠️ E1.2-E1.5/E2 待跑或重跑** |

### 当前结论

1. **E0 two-run batch pipeline 跑通,训练数据清理后已重刷并完成 Phase 4 第 2 次 calibration 优化。** fresh E0 90/90 valid。当前 overall/global best 是 `threatrace_g1g2`(TP=426,FP=692,FN=81,Precision=0.381,Recall=0.840,overall MCC=0.544,macro MCC=0.536);GNN best 是 `threatrace`(TP=403,FP=648,FN=104,Precision=0.383,Recall=0.795,MCC=0.530);Rule best 是 `g2`/`g1g2`(MCC=0.182)。`threatrace` 使用 validation-only score-floor threshold(`inference_threshold=0.0`),不使用 E0 GT 选阈值。9 个 detector 的可运行模型/规则和参数均保存到 `pids_attack/detection/artifacts/<detector>/`,全局选择记录在 `pids_attack/detection/artifacts/manifest.json`。detector 不使用 marker/GT 作为输入。
2. **E1.0 ✅ done(2026-06-25,2 cells)— 攻击模块 × 检测模块 6 个 hand-off 全部串通。** 真正的攻击框架实现在 `pids_attack/attack/safemimic_cmd/`;`experiments/E1_ablation/` 只做实验配置、调用、记录和聚合。E1.0 跑 `minimal_add(true)` × `threatrace_g1g2` × scenarios 01/08(cached-mixed oracle),两格均 `query_ok=True ∧ r1_valid=True ∧ r2_valid=True ∧ e0_gt_loaded=True ∧ e1_0_passed=True`;节点级指标分别为 scenario 01:TP=39/FP=242/TN=1297/FN=9/MCC=0.294,scenario 08:TP=85/FP=236/TN=1299/FN=13/MCC=0.426。真实 detector 信号传回攻击侧,平均 wall≈11.9s/cell。详见 §3.7。E1.1 的目标仍是验证 §4 mutation primitive 的产生、安全性与攻击有效性;当前 4-cell 只是一轮 pilot/diagnostic,结果不足以证明 operator 有效性,因此 E1.1 设计验证仍未完成。E1.2-E1.5 待跑。每个 cell 的 finding 必须反向驱动 `attack/safemimic_cmd/` 框架迭代。指标除 E0 node-level TP/FP/TN/FN/Precision/Recall/MCC 外,必须补 ASR / q★ / |Δ★| / R1-R2 validity / 攻击影响率。详见 §3。
3. **E2.0 完整攻击结果需要重跑。** 现有 700 个 E2 结果是旧 graph-summary oracle 口径,只能作为历史产物;新代码已改为 GT/attack-node oracle。
4. **必须修正的技术问题。** random baseline 的 cumulative edge bug 会让 random 偏弱。检测侧阶段 2(rule implementation)已完成 3 次尝试;阶段 3(model/inference bug check)已完成 3 次尝试;阶段 4 threshold/calibration 已完成 3 次尝试,其中 validation-only threatrace score-floor policy 将 global MCC 0.455 → 0.544。按阶段门槛,下一步需要确认是否结束模块 1 检测优化,或进入新的训练/模型问题专项。

### 口径说明

- PIDSMaker 原始输出是 **node-level**。
- E0 当前 GT 是 mixed trace 中同时满足 attack-only normalized signature 命中和 marker 时间窗触达的 subject/file/netflow 节点 union;它表示真实 A0 execution footprint,不是只取语义攻击 subject。
- E0 当前主指标是 detector flagged nodes 与 GT nodes 的节点级交集形成的 TP/FP/TN/FN;整图任意节点报警不进入 E0 主结论。

---

## 2. E0 Detection — A0 原始检测实验

### Orthrus-style node-level 结果表

| System | Family | TP | FP | TN | FN | Flagged | GT | Precision | Recall | Overall MCC | Macro MCC | Wall(s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| magic | GNN | 293 | 9319 | 4237 | 214 | 9612 | 507 | 0.030 | 0.578 | -0.044 | -0.020 | 5.90 |
| orthrus | GNN | 32 | 24 | 13532 | 475 | 56 | 507 | 0.571 | 0.063 | 0.182 | 0.183 | 6.10 |
| threatrace | GNN | 403 | 648 | 12908 | 104 | 1051 | 507 | 0.383 | 0.795 | 0.530 | 0.523 | 2.73 |
| g1 | Rule | 0 | 14 | 13542 | 507 | 14 | 507 | 0.000 | 0.000 | -0.006 | -0.006 | 4.88 |
| g2 | Rule | 43 | 54 | 13502 | 464 | 97 | 507 | 0.443 | 0.085 | 0.182 | 0.182 | 1.65 |
| g1g2 | Rule | 43 | 54 | 13502 | 464 | 97 | 507 | 0.443 | 0.085 | 0.182 | 0.182 | 6.71 |
| magic_g1g2 | Hybrid | 301 | 9323 | 4233 | 206 | 9624 | 507 | 0.031 | 0.594 | -0.038 | -0.014 | 9.71 |
| orthrus_g1g2 | Hybrid | 43 | 54 | 13502 | 464 | 97 | 507 | 0.443 | 0.085 | 0.182 | 0.182 | 7.47 |
| threatrace_g1g2 | Hybrid | 426 | 692 | 12864 | 81 | 1118 | 507 | 0.381 | 0.840 | 0.544 | 0.536 | 4.38 |

### Scenario-level 结果

| Scenario (GT/all) | Family | System | TP | FP | TN | FN | Precision | Recall | MCC |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| juiceshop_basket_idor (94/1463) | GNN | magic | 8 | 322 | 1047 | 86 | 0.024 | 0.085 | -0.088 |
|      | GNN | orthrus | 5 | 2 | 1367 | 89 | 0.714 | 0.053 | 0.184 |
|      | GNN | threatrace | 79 | 58 | 1311 | 15 | 0.577 | 0.840 | 0.672 |
|      | Rule | g1 | 0 | 1 | 1368 | 94 | 0.000 | 0.000 | -0.007 |
|      | Rule | g2 | 7 | 5 | 1364 | 87 | 0.583 | 0.074 | 0.193 |
|      | Rule | g1g2 | 7 | 5 | 1364 | 87 | 0.583 | 0.074 | 0.193 |
|      | Hybrid | magic_g1g2 | 10 | 323 | 1046 | 84 | 0.030 | 0.106 | -0.076 |
|      | Hybrid | orthrus_g1g2 | 7 | 5 | 1364 | 87 | 0.583 | 0.074 | 0.193 |
|      | Hybrid | threatrace_g1g2 | 84 | 62 | 1307 | 10 | 0.575 | 0.894 | 0.694 |
| juiceshop_db_schema_union_sqli (47/1410) | GNN | magic | 4 | 324 | 1039 | 43 | 0.012 | 0.085 | -0.065 |
|      | GNN | orthrus | 3 | 2 | 1361 | 44 | 0.600 | 0.064 | 0.188 |
|      | GNN | threatrace | 36 | 59 | 1304 | 11 | 0.379 | 0.766 | 0.518 |
|      | Rule | g1 | 0 | 1 | 1362 | 47 | 0.000 | 0.000 | -0.005 |
|      | Rule | g2 | 4 | 5 | 1358 | 43 | 0.444 | 0.085 | 0.184 |
|      | Rule | g1g2 | 4 | 5 | 1358 | 43 | 0.444 | 0.085 | 0.184 |
|      | Hybrid | magic_g1g2 | 6 | 325 | 1038 | 41 | 0.018 | 0.128 | -0.047 |
|      | Hybrid | orthrus_g1g2 | 4 | 5 | 1358 | 43 | 0.444 | 0.085 | 0.184 |
|      | Hybrid | threatrace_g1g2 | 38 | 63 | 1300 | 9 | 0.376 | 0.809 | 0.531 |
| juiceshop_directory_listing_ftp (46/1418) | GNN | magic | 46 | 1358 | 14 | 0 | 0.033 | 1.000 | 0.018 |
|      | GNN | orthrus | 3 | 3 | 1369 | 43 | 0.500 | 0.065 | 0.172 |
|      | GNN | threatrace | 36 | 72 | 1300 | 10 | 0.333 | 0.783 | 0.488 |
|      | Rule | g1 | 0 | 2 | 1370 | 46 | 0.000 | 0.000 | -0.007 |
|      | Rule | g2 | 4 | 6 | 1366 | 42 | 0.400 | 0.087 | 0.175 |
|      | Rule | g1g2 | 4 | 6 | 1366 | 42 | 0.400 | 0.087 | 0.175 |
|      | Hybrid | magic_g1g2 | 46 | 1358 | 14 | 0 | 0.033 | 1.000 | 0.018 |
|      | Hybrid | orthrus_g1g2 | 4 | 6 | 1366 | 42 | 0.400 | 0.087 | 0.175 |
|      | Hybrid | threatrace_g1g2 | 38 | 77 | 1295 | 8 | 0.330 | 0.826 | 0.500 |
| juiceshop_exposed_metrics (46/1384) | GNN | magic | 46 | 1324 | 14 | 0 | 0.034 | 1.000 | 0.019 |
|      | GNN | orthrus | 3 | 2 | 1336 | 43 | 0.600 | 0.065 | 0.190 |
|      | GNN | threatrace | 36 | 64 | 1274 | 10 | 0.360 | 0.783 | 0.509 |
|      | Rule | g1 | 0 | 1 | 1337 | 46 | 0.000 | 0.000 | -0.005 |
|      | Rule | g2 | 4 | 5 | 1333 | 42 | 0.444 | 0.087 | 0.186 |
|      | Rule | g1g2 | 4 | 5 | 1333 | 42 | 0.444 | 0.087 | 0.186 |
|      | Hybrid | magic_g1g2 | 46 | 1324 | 14 | 0 | 0.034 | 1.000 | 0.019 |
|      | Hybrid | orthrus_g1g2 | 4 | 5 | 1333 | 42 | 0.444 | 0.087 | 0.186 |
|      | Hybrid | threatrace_g1g2 | 38 | 68 | 1270 | 8 | 0.358 | 0.826 | 0.523 |
| juiceshop_login_admin_sqli (46/1397) | GNN | magic | 4 | 313 | 1038 | 42 | 0.013 | 0.087 | -0.062 |
|      | GNN | orthrus | 3 | 2 | 1349 | 43 | 0.600 | 0.065 | 0.190 |
|      | GNN | threatrace | 36 | 58 | 1293 | 10 | 0.383 | 0.783 | 0.527 |
|      | Rule | g1 | 0 | 1 | 1350 | 46 | 0.000 | 0.000 | -0.005 |
|      | Rule | g2 | 4 | 5 | 1346 | 42 | 0.444 | 0.087 | 0.186 |
|      | Rule | g1g2 | 4 | 5 | 1346 | 42 | 0.444 | 0.087 | 0.186 |
|      | Hybrid | magic_g1g2 | 6 | 314 | 1037 | 40 | 0.019 | 0.130 | -0.043 |
|      | Hybrid | orthrus_g1g2 | 4 | 5 | 1346 | 42 | 0.444 | 0.087 | 0.186 |
|      | Hybrid | threatrace_g1g2 | 38 | 62 | 1289 | 8 | 0.380 | 0.826 | 0.540 |
| juiceshop_login_bender_sqli (45/1392) | GNN | magic | 45 | 1333 | 14 | 0 | 0.033 | 1.000 | 0.018 |
|      | GNN | orthrus | 3 | 2 | 1345 | 42 | 0.600 | 0.067 | 0.193 |
|      | GNN | threatrace | 36 | 66 | 1281 | 9 | 0.353 | 0.800 | 0.510 |
|      | Rule | g1 | 0 | 1 | 1346 | 45 | 0.000 | 0.000 | -0.005 |
|      | Rule | g2 | 4 | 5 | 1342 | 41 | 0.444 | 0.089 | 0.188 |
|      | Rule | g1g2 | 4 | 5 | 1342 | 41 | 0.444 | 0.089 | 0.188 |
|      | Hybrid | magic_g1g2 | 45 | 1333 | 14 | 0 | 0.033 | 1.000 | 0.018 |
|      | Hybrid | orthrus_g1g2 | 4 | 5 | 1342 | 41 | 0.444 | 0.089 | 0.188 |
|      | Hybrid | threatrace_g1g2 | 38 | 70 | 1277 | 7 | 0.352 | 0.844 | 0.524 |
| juiceshop_login_jim_sqli (46/1388) | GNN | magic | 4 | 313 | 1029 | 42 | 0.013 | 0.087 | -0.062 |
|      | GNN | orthrus | 3 | 2 | 1340 | 43 | 0.600 | 0.065 | 0.190 |
|      | GNN | threatrace | 36 | 58 | 1284 | 10 | 0.383 | 0.783 | 0.527 |
|      | Rule | g1 | 0 | 1 | 1341 | 46 | 0.000 | 0.000 | -0.005 |
|      | Rule | g2 | 4 | 5 | 1337 | 42 | 0.444 | 0.087 | 0.186 |
|      | Rule | g1g2 | 4 | 5 | 1337 | 42 | 0.444 | 0.087 | 0.186 |
|      | Hybrid | magic_g1g2 | 6 | 314 | 1028 | 40 | 0.019 | 0.130 | -0.044 |
|      | Hybrid | orthrus_g1g2 | 4 | 5 | 1337 | 42 | 0.444 | 0.087 | 0.186 |
|      | Hybrid | threatrace_g1g2 | 38 | 62 | 1280 | 8 | 0.380 | 0.826 | 0.540 |
| juiceshop_redirect_open (47/1385) | GNN | magic | 46 | 1324 | 14 | 1 | 0.034 | 0.979 | -0.019 |
|      | GNN | orthrus | 3 | 3 | 1335 | 44 | 0.500 | 0.064 | 0.170 |
|      | GNN | threatrace | 36 | 71 | 1267 | 11 | 0.336 | 0.766 | 0.483 |
|      | Rule | g1 | 0 | 2 | 1336 | 47 | 0.000 | 0.000 | -0.007 |
|      | Rule | g2 | 4 | 6 | 1332 | 43 | 0.400 | 0.085 | 0.172 |
|      | Rule | g1g2 | 4 | 6 | 1332 | 43 | 0.400 | 0.085 | 0.172 |
|      | Hybrid | magic_g1g2 | 46 | 1324 | 14 | 1 | 0.034 | 0.979 | -0.019 |
|      | Hybrid | orthrus_g1g2 | 4 | 6 | 1332 | 43 | 0.400 | 0.085 | 0.172 |
|      | Hybrid | threatrace_g1g2 | 38 | 76 | 1262 | 9 | 0.333 | 0.809 | 0.495 |
| juiceshop_register_admin_mass_assignment (45/1414) | GNN | magic | 45 | 1355 | 14 | 0 | 0.032 | 1.000 | 0.018 |
|      | GNN | orthrus | 3 | 3 | 1366 | 42 | 0.500 | 0.067 | 0.174 |
|      | GNN | threatrace | 36 | 71 | 1298 | 9 | 0.336 | 0.800 | 0.497 |
|      | Rule | g1 | 0 | 2 | 1367 | 45 | 0.000 | 0.000 | -0.007 |
|      | Rule | g2 | 4 | 6 | 1363 | 41 | 0.400 | 0.089 | 0.177 |
|      | Rule | g1g2 | 4 | 6 | 1363 | 41 | 0.400 | 0.089 | 0.177 |
|      | Hybrid | magic_g1g2 | 45 | 1355 | 14 | 0 | 0.032 | 1.000 | 0.018 |
|      | Hybrid | orthrus_g1g2 | 4 | 6 | 1363 | 41 | 0.400 | 0.089 | 0.177 |
|      | Hybrid | threatrace_g1g2 | 38 | 76 | 1293 | 7 | 0.333 | 0.844 | 0.509 |
| juiceshop_weak_password_admin (45/1412) | GNN | magic | 45 | 1353 | 14 | 0 | 0.032 | 1.000 | 0.018 |
|      | GNN | orthrus | 3 | 3 | 1364 | 42 | 0.500 | 0.067 | 0.174 |
|      | GNN | threatrace | 36 | 71 | 1296 | 9 | 0.336 | 0.800 | 0.497 |
|      | Rule | g1 | 0 | 2 | 1365 | 45 | 0.000 | 0.000 | -0.007 |
|      | Rule | g2 | 4 | 6 | 1361 | 41 | 0.400 | 0.089 | 0.177 |
|      | Rule | g1g2 | 4 | 6 | 1361 | 41 | 0.400 | 0.089 | 0.177 |
|      | Hybrid | magic_g1g2 | 45 | 1353 | 14 | 0 | 0.032 | 1.000 | 0.018 |
|      | Hybrid | orthrus_g1g2 | 4 | 6 | 1361 | 41 | 0.400 | 0.089 | 0.177 |
|      | Hybrid | threatrace_g1g2 | 38 | 76 | 1291 | 7 | 0.333 | 0.844 | 0.509 |


## 3. E1 Ablation — 组件消融/敏感性实验

> 对应 paper §6.1,锚定 `A_Study_Stage/1_p1_formulation.md` §4 与 `pids_attack/p2_mcts_v3.md` §5 V3 设计。E1 是实验轨道,不是攻击框架本体:真正的方法实现放在 `pids_attack/attack/`,E1 只负责配置 variants、调用攻击框架、记录 finding 和聚合证据。两者是单向依赖: `experiments/E1_ablation/` 可以调用 `attack/safemimic_cmd/`,但 `attack/` 不能 import `experiments/`,不能读取 E1 结果目录,也不能 hard-code E1 cell 名称。E1 不是参数扫表,而是 claim-driven ablation:每个 cell 对应一个会被 reviewer 质疑的方法设计选择。

### 3.0 Finding-driven 6 阶段 gate

E1 顺序 = paper 方法 §-进度 = `attack/safemimic_cmd/` 子层迁移顺序。每个 stage 必须过 gate 才能进入下一阶段。

```
[E1.0 Bootstrap]              ← §3 closure + §4 minimal Add
    │  build:   safemimic_cmd/runner.py + search/one_shot.py + framework/config.py + framework/oracle.py + constraints/
    │  pilot:   minimal_add × threatrace_g1g2 × 2 scenarios
    │  gate:    real query OK + R1/R2 valid + JSON schema + aggregate OK
    │  finding → framework revision → re-pilot until pass
    ▼
[E1.1 Mutation primitive]     ← §4 command-space actions
    │  build:   safemimic_cmd/operators/{add,edit,move,remove}.py
    │  simple:  add_only/add_edit/add_edit_move/all4 × threatrace_g1g2 × scenario 01
    │  gate:    Add/Edit/Move/Remove 真进入 query history + R1/R2 不退化
    ▼
[E1.2 Fitness design]         ← §5.3 objectives
    │  build:   safemimic_cmd/objectives/{f1_hinge,f2_endogenous_r,scalarize}.py
    │  pilot:   f1_only vs f1_f2 × threatrace_g1g2 × 1-2 scenarios
    │  gate:    f_2 真降低 post-attack FP 或提升稳定性,否则回头改 stealth term 定义
    ▼
[E1.3 Search structure]       ← §5.3 sequential + §5.4 inner GA
    │  build:   safemimic_cmd/search/{policy,sequential,inner_ga,commit}.py
    │  pilot:   full vs random × threatrace_g1g2 × 1-2 scenarios
    │  gate:    full 在同 B_max 下 ASR > random
    ▼
[E1.4 Surrogate]              ← §5.2 WL + Sparse BLR + ARD
    │  build:   safemimic_cmd/surrogate/{wl_features,sparse_blr,ard}.py
    │  pilot:   blr_ard vs blr_noard vs no_posterior × threatrace_g1g2 × 1-2 scenarios
    │  gate:    blr_ard 在同 B_max 下 q★ 更低或 ASR 更高
    ▼
[E1.5 Acquisition]            ← §5.4 LCB / EI / Thompson
    │  build:   safemimic_cmd/acquisition/{lcb,ei,thompson}.py
    │  pilot:   lcb vs ei vs thompson × threatrace_g1g2 × 1-2 scenarios
    │  gate:    若区分不明显,主文写默认实现选择 + appendix 完整对比
    ▼
[设计稳定 → 扩 main grid]     ← 9-detector × 10-scenario × seeds {1,2,3} 主表
```

**每个 stage 两条产出:**
- 数据(JSON 结果 + 聚合表) → 回填 §3.7-§3.12 结果表
- finding 报告(observed X → revised attack/Y → re-pilot Z)→ 回填 §3.7-§3.12 `Finding` / `Framework revision` 槽位

**红线:** finding / revision 槽位为空 → 该 cell 不算 done,不能进下一阶段;不得直接跳过 gate 扩 main grid。

**代码边界 contract:** `attack/safemimic_cmd/` 持有 operator/objective/search/surrogate/acquisition/oracle 适配等方法逻辑;`experiments/E1_ablation/` 只持有 cell 定义、CLI wrapper、grid、结果 JSON、aggregate 和 paper 表。Finding 可以提出“修改框架”的需求,但修改必须落回 `attack/`;实验目录不得实现或复制攻击算法。

### 3.1 目的

验证 SafeMimic-CMD V3 的核心设计链条是否成立。先用 `attack/safemimic_cmd` 的 bootstrap/minimal profile 提供最小可跑攻击闭环,E1.0 只作为实验 gate 去调用它;只有这个闭环能稳定产出真实 oracle JSON,后面的 E1.1-E1.5 才进入方法设计验证。

1. E1.0 通过调用 `attack/safemimic_cmd` 是否能完成 scenario loading、δ generation、real execution、strace/CDM conversion、detector inference、GT/metric aggregation。
2. §4 定义的 mutation primitives 是否真的能生成可执行的 command-level perturbation。
3. §5 的 fitness / search / surrogate / acquisition 是否在同一 mutation space 上带来独立收益。
4. 攻击收益是否来自 attack-node evasion,而不是只靠制造大量额外 alert 拉低 MCC。

因此 E1 的执行顺序必须是 **E1.0 framework gate → E1.1 mutation primitive → E1.2-E1.5 method ablation**。若 E1.0 不通过,说明攻击实验基础设施还没有闭环;若 operator space 实际只覆盖 Add,后续 fitness / search / surrogate / acquisition 的结论都只能说明 Add-only attack,不能支撑 §4 的方法设计。

**Finding-driven design loop:** E1 的结果不是单纯填表。每个 finding 都要回写到 `pids_attack/attack/`,决定 operator pool、R1/R2 precondition、fitness term、search policy、surrogate/acquisition 默认值是否保留、弱化或重写。这里的“回写”是设计反馈,不是运行时耦合:框架不依赖 E1 目录,实验目录也不承载攻击逻辑。框架修改后必须重跑对应 gate/pilot,再进入更大规模 ablation;实验表只是设计迭代稳定后的证据产物。

**Base detector = 每类 best** 3 个(GNN / Rule / Hybrid),配 E0 同款 node-level 指标和攻击侧指标。连续指标用于区分未完全收敛的 runs,攻击侧指标用于防止把 noisy perturbation 误判为有效 evasion。

### 3.2 设计概览

| Cell | 设计锚点 | 实验逻辑 | Variants |
|---|---|---|---:|
| **E1.0 Attack framework bootstrap** | `attack/safemimic_cmd/search/one_shot.py` + `attack/framework/oracle.py` + E0-style GT | E1.0 不实现攻击逻辑,只调用同一 SafeMimic 框架的最小 Add-based profile:固定 Add policy、一次 cached-mixed query、checker/CDM/detector/GT/metric JSON 全闭环;不要求成功 evade,只验证实验 harness 可用。 | 1 |
| **E1.1 Mutation primitive** | §4 command-space manipulation | 先确认搜索空间成立:action 能落到 shell、保持 A0 成功、产生预期 footprint,并观察 Edit/Move/Remove 是否提供 Add-only 无法覆盖的搜索路径。 | 4 |
| **E1.2 Fitness design** | §5.3 two-objective fitness | 比较只优化 attack-node evasion 与同时约束 stealth/reference 的差别;若 f2 降低 post-attack FP 或提高稳定性,说明 stealth objective 有独立作用。 | 2 |
| **E1.3 Search structure** | §5.3 sequential + §5.4 inner GA | 在相同 query budget 下比较 full search 与弱搜索;若 full 有更高 ASR / 更低 q★,说明 sequential + GA 更有效利用反馈。 | 2 |
| **E1.4 Surrogate** | §5.2 WL + BLR + ARD | 比较 posterior-guided 与 no-posterior;若同预算下更快找到有效 δ,说明 surrogate 提升 sample efficiency。 | 3 |
| **E1.5 Acquisition** | §5.4 acquisition | 比较 LCB / EI / Thompson;若差异明显,支撑默认 acquisition;若差异不明显,写成实现选择而非核心贡献。 | 3 |

### 3.3 Base Detector(3 个,每类 best)

| 类别 | Detector | E0 baseline MCC | 选择理由 |
|---|---|---:|---|
| GNN | `threatrace` | **0.530** | GNN best |
| Rule | `g2` | **0.182** | Rule best |
| Hybrid | `threatrace_g1g2` | **0.544** | Hybrid best,也是 global best |

**选择理由:**
- 覆盖 3 种检测哲学,各取最强 baseline 给攻击
- 攻击若能压制 best detector,paper claim 自然成立
- 跟 E0 直接对应(MCC_pre vs MCC_post 同口径可比)

### 3.4 统一指标

每个 cell × variant × detector 报告两类指标。

**Node-level detector metrics**(跟 §2 E0 表一致):

```
Variant | Detector | n | TP | FP | TN | FN | Precision | Recall | MCC | ΔRecall | ΔMCC | wall(s)
```

**指标定义:**

```text
TP = flagged_nodes ∩ GT_nodes              (post-attack)
FP = flagged_nodes - GT_nodes
FN = GT_nodes - flagged_nodes
TN = all_nodes - TP - FP - FN

Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
MCC       = (TP·TN - FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
ΔRecall   = Recall_post - Recall_E0
ΔMCC      = MCC_post - MCC_E0
```

**Attack-side metrics**(E1 必报):

| Metric | 含义 | 用途 |
|---|---|---|
| ASR | `attack/GT nodes evade` 的成功率 | 主攻击成功指标 |
| q★ | 成功样本平均 query 数 | sample efficiency |
| \|Δ★\| | 成功样本平均扰动长度 | 扰动成本 |
| R1 valid | `all_steps_passed` 与 `final_attack_succeeded` | 攻击功能保持 |
| R2 valid | δ success / timeout / blocking / resource conflict | 可执行性 |
| 攻击影响率 | `1 - R1 valid rate` | 衡量变异破坏原攻击的比例 |
| FP control | post-attack FP / Precision / MCC | 防止靠制造噪声降低 MCC |

判定逻辑:一个 variant 只有同时降低 attack-node detection、保持 R1/R2、且没有明显 FP 爆炸,才算有效。MCC drop 只是连续辅助信号,不能单独当攻击成功。

### 3.5 Cell 数预算

| Cell | Variants | Detectors | Scenarios | Seeds | Cells |
|---|---:|---:|---:|---:|---:|
| E1.0 Attack framework bootstrap | 1 | 1 | 2 | 1 | **2** |
| E1.1 Mutation primitive(pilot) | 4 | 1 | 1 | 1 | **4 pilot** |
| E1.2 Fitness design | 2 | 3 | 10 | 1 | **60** |
| E1.3 Search structure | 3 | 3 | 10 | 1 | **90** |
| E1.4 Surrogate | 3 | 3 | 10 | 1 | **90** |
| E1.5 Acquisition | 3 | 3 | 10 | 1 | **90** |
| **E1.0 + 当前 E1 计划** | | | | | **336 cells** |

**策略:**
- 先跑 **E1.0 bootstrap**:`minimal_add` × `threatrace_g1g2` × 2 scenarios × seed=1。确认最小攻击闭环能生成 JSON,并包含 query history、δ、flagged nodes、GT nodes、R1/R2。
- 再跑 **E1.1 pilot**:`add_only / add_edit / add_edit_move / all4` × `threatrace_g1g2` × scenario 01 × seed=1。先检查四类 command-space action 是否真的产生对应 mutation、R1/R2 是否退化、以及相对 A0-only 的 TP/FP/TN/FN 是否出现 attack-node evasion 信号。
- 每轮 gate/pilot 后先写 finding,再决定是否修改 `pids_attack/attack/` 中的框架代码;若 finding 暴露框架问题,先修框架并重跑对应 gate/pilot,不得直接扩大 grid。
- E1.1 不降级为工程 gate;当前 pilot 若没有 attack-node TP/Recall 下降,就说明 E1.1 尚未完成证明,需要继续改攻击框架或实验设置后重跑。
- β sensitivity、kNN-k、KDE/GMM、MCTS 等放入后续扩展或 appendix,不进入第一轮主表。

### 3.6 TODO-1 / TODO-2 的归宿

| Source | 归宿 |
|---|---|
| §4 **TODO-1**(依赖图建模 R1+R2) | 不单独做 graph-space 实验;并入所有 E1 runs 的 R1/R2 validity 与攻击影响率。若某 variant 牺牲 R1/R2 换 detector drop,不能算有效攻击。 |
| §4 **TODO-2**(4 算子独立性) | **E1.1 Mutation primitive** 负责。Add-only → Add+Edit → Add+Edit+Move → all4 必须相对 A0-only 报告 ASR、q★、\|Δ★\|、R1/R2、攻击影响率、TP/FP/TN/FN、Recall/MCC 边际变化。当前 4-cell pilot 仍是 legacy Rewrite 口径,未证明新 Edit 定义下的独立贡献,所以 TODO-2 仍 open。 |

---

### 3.7 E1.0 Attack framework bootstrap — ✅ done(2 cells,2026-06-25)

**研究问题:** 在进入 operator / objective / search ablation 之前,SafeMimic-CMD 是否已经具备一个可复用的真实黑盒 query 闭环。

**本节只做 gate,不评价攻击效果。** E1.0 固定使用最小 `Add` 扰动 `δ=true`,目标是验证框架链路、oracle 口径和结果 schema;不要求绕过 detector。因此 ASR=0 不构成方法失败,只说明这个 trivial δ 没有攻击收益。

**Gate 必须同时满足:**

| 环节 | 验收条件 |
|---|---|
| Scenario + δ | 加载真实 Juice-Shop A0;插入 1 条 Add δ;插入位置满足 `positions[i] < n_steps` |
| R1 attack integrity | fresh `A0⊕δ` 在 Docker 中真实执行;A0 step checker 与 final attack check 全部通过 |
| R2 δ executability | δ 命令真实执行且 exit code 为 0;无 timeout / blocking / resource conflict |
| Cached-mixed oracle | 将本次 fresh attack trace 与 cached benign trace 组合成 detector 输入 |
| CDM + detector | composed trace 可转 SQL;`threatrace_g1g2` 返回 per-node prediction |
| GT + metrics | 使用 E0 同款 attack-only signature ∩ marker-window GT,输出 TP/FP/TN/FN/Precision/MCC |
| Result schema | 每个 cell 写 JSON;`aggregate.py` 能聚合 pass/query/R1/R2/ASR |

**运行配置:**

| Field | Value |
|---|---|
| Variant | `minimal_add` |
| Detector | `threatrace_g1g2` |
| Scenarios | `01` login admin SQLi;`08` basket IDOR |
| δ | `true` |
| Query budget | 1 real query per cell |
| Oracle mode | `cached_benign_attack_query` |

**Gate 结果:**

| Scenario | query ok | R1 valid | R2 valid | JSON ok | Gate | wall(s) |
|---|---:|---:|---:|---:|---:|---:|
| `01` login admin SQLi | ✅ | ✅ | ✅ | ✅ | **pass** | 12.3 |
| `08` basket IDOR | ✅ | ✅ | ✅ | ✅ | **pass** | 11.4 |

**Detector 反馈(记录,不作为 E1.0 攻击效果结论):**

| Scenario | n_nodes | GT | TP | FP | TN | FN | Precision | Recall | MCC | ASR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `01` | 1587 | 48 | 39 | 242 | 1297 | 9 | 0.139 | 0.812 | 0.294 | 0 |
| `08` | 1633 | 98 | 85 | 236 | 1299 | 13 | 0.265 | 0.867 | 0.426 | 0 |

**Finding:** E1.0 证明当前攻击框架已经完成真实 query 闭环:攻击侧生成 `A0⊕δ`,range 侧真实执行并验证 R1/R2,oracle 侧组合 cached benign background,detector 侧给出 node-level prediction,最后按 E0 同款 GT 产出 attack-side JSON 和 aggregate summary。两格都保留了 `mixed_mode`,`benign_trace`,`attack_raw_strace`,`delta_outputs`,`attack_step_results` 和 `node_metrics`,足以支撑后续 E1.1-E1.5 的 finding-driven 迭代。

**Framework revision:** 本轮将 attack oracle 从 realtime mixed workload 改为单一 cached-mixed 路径。`range/benign_cache.py` 负责选择预采集 benign trace;`range/mixed_workload.py::collect_attack_query_trace` 只负责 fresh `A0⊕δ` 执行和 R1/R2;`range/cached_mixed.py` 负责 benign+attack trace 组合、marker-window GT 和 SQL 生成;`attack/framework/oracle.py::query_with_validation_mixed` 统一调用该路径。该 revision 将单 cell wall 从约 40s 降到约 12s,同时保持 detector 输入处于真实 mixed-background 图规模(约 1.6k nodes)。

**Decision:** E1.0 gate 通过后进入 E1.1。当前 E1.1 pilot 证明了 legacy operator 能产生且 R1/R2 不坏,但没有证明 attack-node evasion 或 operator 独立贡献;更重要的是 legacy `Rewrite` 被重新定义为命令间关系层面的 `Edit`,因此 E1.1 仍需按新 action space 继续设计/重跑,不能直接宣称完成。

---

### 3.8 E1.1 Mutation primitive(§4)— legacy Rewrite pilot inconclusive; Edit 待重跑(4 cells)

**研究问题:** §4 的命令空间变异是否被定义成搜索器可操作的有限 action space。当前定义为:

```text
Add(command_id, position)
Move(delta_id, position)
Remove(delta_id)
Edit(delta_id, target_id)
```

其中 `command_id` 指向一条完整可执行命令,不是裸命令名;`Edit` 不是任意 shell 参数编辑,也不让搜索器选择资源类型,而是让一条 δ 命令和某条已有命令产生 provenance 关联。关联具体落到 file / process / network 哪一类,由 `target_id` 对应命令已经观察到的 footprint 决定。E1.1 必须同时回答三件事:第一,这些 action 能否被真实产生;第二,进入真实 query 后是否保持 R1/R2;第三,相对扰动前 A0-only 是否带来 attack-node evasion 或搜索效率收益。当前 4-cell 只是 legacy Rewrite pilot,不能替代完整 E1.1 证明。

**当前完整定义:**

| Action | 搜索对象 | 候选集合为什么有限 | 命令空间含义 |
|---|---|---|---|
| `Add(command_id, position)` | 从候选命令池选一条完整 δ 命令,再选插入位置 | `command_id` 来自有限 full-command pool;`position` 来自当前命令序列插入点 | 增加一条扰动命令 |
| `Move(delta_id, position)` | 选已有 δ,再选新位置 | `delta_id` 来自当前 Δ;`position` 来自当前命令序列插入点 | 改变 δ 与 A0/δ 的时序关系 |
| `Remove(delta_id)` | 选已有 δ 删除 | `delta_id` 来自当前 Δ | 回退坏扰动,控制扰动长度 |
| `Edit(delta_id, target_id)` | 选已有 δ、选目标命令 | `delta_id` 来自当前 Δ;`target_id` 来自当前 A0+Δ | 改变 δ 与目标命令的命令间关联 |

`Add` 的参数规则:`command_id` 对应的是命令库中的完整命令,例如 `ls /tmp`、`stat /etc/hosts`、`curl -s http://127.0.0.1:3000/`,不是先选 `ls/stat/curl` 再搜索任意参数。

`Edit` 的落地规则:搜索器只搜索 `(delta_id,target_id)`,不搜索资源类型或任意参数字符串。具体命令参数由目标命令的已观察 footprint 派生:target 有 file footprint 就生成文件/目录关联,target 有 process footprint 就生成进程/执行上下文关联,target 有 network footprint 就生成网络端点关联。这样 Edit 仍然是命令空间/关系空间搜索,不会退化成无限参数空间搜索。

| 验证点 | E1.1 要回答什么 | 判断方式 |
|---|---|---|
| 变异能否产生 | `add_only / add_edit / add_edit_move / all4` 是否真的产生各自声称允许的 action | query history 中必须出现对应 action |
| 变异是否安全 | primitive 进入真实 query 后是否破坏 A0 或 δ 执行 | R1/R2 必须保持 100%,攻击影响率必须为 0 |
| 变异是否有效 | 相对 A0-only 是否减少 attack-node detection 或提高成功效率 | ASR、q★、\|Δ★\|、TP/Recall drop、MCC/FP 诊断 |

**Variants:**

| Variant | 含义 |
|---|---|
| `add_only` | 只允许插入新 δ 命令,最小 mutation space |
| `add_edit` | 允许插入 δ,并让 δ 与已有命令在 file/process/network 资源上建立关联 |
| `add_edit_move` | 加入位置调整,测试执行顺序关系是否有用 |
| `all4`(default) | Add / Edit / Move / Remove 全开,允许建立关联、调整位置并撤销坏 perturbation |

**实验逻辑:** E1.1 以 `A0_only` 为扰动前参照,比较 Add-only → Add+Edit → Add+Edit+Move → all4。一个 variant 只有同时满足 action 真实产生、R1/R2 不退化、且相对 A0-only 降低 attack-node TP/Recall 或提升 ASR/q★,才能支持该 action-space 设计。若只产生 action 但 TP 不降,只能算 pilot finding,不能算 E1.1 证明。

**结果(2026-06-26 pilot run):**

配置:`scenario=01`, `detector=threatrace_g1g2`, `seed=1`, `B_max=3`, `T_GA=6`, `m=8`, `n_init_random=3`。第一行为同一 cached-mixed oracle 下的 A0-only/no-δ baseline。4 个 perturbation variant 均未成功绕过,因此本轮 E1.1 未完成有效性证明。注意:下表是 legacy `rewrite` 口径,不是新定义的关系型 `Edit` 口径。TP/FP/TN/FN 用于说明 Recall/MCC 变化来源。

| Variant | n | primitive | R1 | R2 | 影响率 | TP | FP | TN | FN | Recall | MCC | 判定 |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `A0_only`(扰动前) | 1 | none | 1.00 | — | 0.00 | 40 | 218 | 1321 | 8 | 0.833 | 0.321 | baseline |
| `add_only` | 1 | add | 1.00 | 1.00 | 0.00 | 40 | 258 | 1322 | 18 | 0.690 | 0.252 | inconclusive |
| `add_rewrite` | 1 | add,rewrite | 1.00 | 1.00 | 0.00 | 40 | 323 | 1320 | 16 | 0.714 | 0.225 | inconclusive |
| `add_rewrite_move` | 1 | add,rewrite,move | 1.00 | 1.00 | 0.00 | 40 | 221 | 1323 | 13 | 0.755 | 0.296 | inconclusive |
| `all4`(default) | 1 | add,rewrite,move,remove | 1.00 | 1.00 | 0.00 | 40 | 219 | 1323 | 12 | 0.769 | 0.302 | inconclusive |

**Finding:** 当前 pilot 没有完成 E1.1 证明。四个 variant 的声明 primitive 都出现在真实 query history 中,R1/R2 均为 100%,攻击影响率为 0,说明实现层可用;但相对 `A0_only`,四个 perturbation variant 的 TP 都没有下降(TP=40),所以没有 attack-node evasion 证据;`add_only` 和 legacy `add_rewrite` 还带来更高 FP。结论是:E1.1 目标不变,但当前 pilot 不足以支持任何 action 有效性或独立贡献 claim。下一轮必须把 `Rewrite` 改成 `Edit(delta_id,target_id)` 后重跑。

**Framework revision:** 下一轮 E1.1 要把 mutation primitive 实现留在攻击框架内,实验脚本只配置 variant。具体方向:将 legacy Rewrite 替换为关系型 Edit;在 `attack/safemimic_cmd/operators/` 中实现 `Edit(delta_id,target_id)`;在 search 中按 `cfg.operator_set` 做状态化 Add/Edit/Move/Remove 采样;在 summary 中记录 `edit_target_id`、derived footprint type(file/process/network) 和 action usage,用于证明 action-space 被真实搜索。

---

### 3.9 E1.2 Fitness design(§5.3)— 待跑(目标 60 cells)

**研究问题:** `f_2` endogenous reference 是否减少 stealth backfire,还是 `f_1` attack-node objective 已足够。

**Variants:**

| Variant | 含义 |
|---|---|
| `f1_only` | 只优化 attack-node flagged score |
| `f1_f2`(default) | attack-node objective + endogenous reference stealth objective |

**实验逻辑:** `f_1` 可能降低目标攻击节点告警,但同时扩大非 GT FP。若 `f1_f2` 在 ASR 接近或更高的同时提高 Precision/MCC、提高 R1/R2 稳定性或减少 post-attack FP,说明 stealth objective 不是装饰项。若 `f1_only` 同样好,则 §5 应弱化 `f_2` claim,把它写成 detector-dependent regularizer。

**结果(待跑):**

| Variant | Detector | n | ASR | q★ | \|Δ★\| | FP_post | Precision | Recall | MCC | ΔMCC |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `f1_only` | × 1 | ⏳ | — | — | — | — | — | — | — | — |
| `f1_f2`(default) | × 1 | ⏳ | — | — | — | — | — | — | — | — |

**Finding(跑完回填):** —

**Framework revision(回填:回 `attack/safemimic_cmd/objectives/` 改了什么):** —

---

### 3.10 E1.3 Search structure(§5.3/§5.4)— 待跑(目标 100 cells)

**研究问题:** sequential + inner GA 是否比弱搜索更有效利用黑盒反馈。

**Variants:**

| Variant | 含义 |
|---|---|
| `full`(default) | sequential commit + inner GA + surrogate acquisition |
| `random` | 同样 B_max 下随机采样合法 Δ,不使用反馈排序 |

**实验逻辑:** 若 `full` 在相同 B_max 下取得更高 ASR、更低 q★或更短 |Δ★|,说明 sequential + GA 不是普通随机搜索,而是在 command mutation space 中更有效地组合反馈。第一轮只保留已经接入真实 oracle 且预算公平的 `full/random`。

**结果(待跑):**

| Variant | Detector | n | ASR | q★ | \|Δ★\| | R1 valid | R2 valid | Recall | MCC | ΔMCC |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `full`(default) | × 1 | ⏳ | — | — | — | — | — | — | — | — |
| `random` | × 1 | ⏳ | — | — | — | — | — | — | — | — |

**Finding(跑完回填):** —

**Framework revision(回填:回 `attack/safemimic_cmd/search/` 改了什么):** —

---

### 3.11 E1.4 Surrogate(§5.2)— 待跑(目标 90 cells)

**研究问题:** WL + BLR + ARD posterior 是否提高小预算黑盒搜索的 sample efficiency。

**Variants:**

| Variant | 含义 |
|---|---|
| `blr_ard`(default) | WL features + Sparse BLR + ARD |
| `blr_noard` | WL features + Bayesian linear regression,无 ARD 稀疏化 |
| `no_posterior` | 不使用 posterior 排序;同样 B_max 下用 random/no-posterior acquisition |

**实验逻辑:** `no_posterior` 不能用更多真 query 评估 candidate,否则 query budget 不公平。三者都必须使用同样 B_max,只比较候选排序信号。若 `blr_ard` 的 ASR 更高、q★ 更低或 invalid exploration 更少,说明 surrogate 的作用是提高 sample efficiency,不是改变 detector 或 checker。

**结果(待跑):**

| Variant | Detector | n | ASR | q★ | \|Δ★\| | posterior active dims | Recall | MCC | ΔMCC |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `blr_ard`(default) | × 3 | ⏳ | — | — | — | — | — | — | — |
| `blr_noard` | × 3 | ⏳ | — | — | — | — | — | — | — |
| `no_posterior` | × 3 | ⏳ | — | — | — | — | — | — | — |

**Finding(跑完回填):** —

**Framework revision(回填:回 `attack/safemimic_cmd/surrogate/` 改了什么):** —

---

### 3.12 E1.5 Acquisition(§5.4)— 待跑(目标 90 cells)

**研究问题:** LCB 是否是当前离散、小预算、高噪声攻击搜索中的合理默认 acquisition。

**Variants:**

| Variant | 含义 |
|---|---|
| `lcb`(default) | Lower Confidence Bound |
| `ei` | Expected Improvement |
| `thompson` | Thompson sampling |

**实验逻辑:** acquisition 是候选排序策略,不是方法本身的主要贡献。若 `lcb` 明显更稳定,主文保留;若三者差异小,主文只说明采用 LCB 作为默认实现,把细节放 appendix。β sweep 不进入第一轮主表,避免把 E1 写成 hyperparameter tuning。

**结果(待跑):**

| Variant | Detector | n | ASR | q★ | \|Δ★\| | early-stage valid rate | Recall | MCC | ΔMCC |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `lcb`(default) | × 3 | ⏳ | — | — | — | — | — | — | — |
| `ei` | × 3 | ⏳ | — | — | — | — | — | — | — |
| `thompson` | × 3 | ⏳ | — | — | — | — | — | — | — |

**Finding(跑完回填):** —

**Framework revision(回填:回 `attack/safemimic_cmd/acquisition/` 改了什么):** —

---

### 3.13 数据物理位置

攻击框架实现不放在本目录。本目录只保存 E1 的实验入口、grid、结果和聚合脚本;核心方法代码固定在 `pids_attack/attack/` 下。关系是“实验 harness → 调用攻击框架”的单向依赖,不是两个框架互相耦合。

| 位置 | 职责 | 禁止事项 |
|---|---|---|
| `pids_attack/attack/safemimic_cmd/` | SafeMimic-CMD 方法实现:operator/objective/search/surrogate/acquisition/runner | 不 import `experiments/`,不读取 E1 results,不写死 E1 cell 名 |
| `pids_attack/attack/framework/` | 公共 contract、config、oracle adapter、query result schema | 不绑定具体 E1 stage 或实验目录 |
| `pids_attack/experiments/E1_ablation/` | cell 配置、CLI wrapper、grid、结果、aggregate、paper table | 不实现 `apply_delta` / objective / search / oracle / acquisition 逻辑 |

```
pids_attack/experiments/E1_ablation/
├── E1.0_framework/
│   └── results/*.json                 # 最小 attack loop gate
├── E1.1_mutation/
│   ├── results/*.json                 # 每个 cell 一个 JSON
│   └── scripts/run_grid.sh            # variant × detector × scenario × seed
├── E1.2_fitness/
├── E1.3_search/
├── E1.4_surrogate/
├── E1.5_acquisition/
├── scripts/
│   ├── e1_0_bootstrap.py              # E1.0 CLI wrapper; calls attack/safemimic_cmd
│   ├── aggregate.py                   # 算 E0-aligned node metrics + attack-side metrics
│   ├── run_grid.sh                    # 当前 E1.0-E1.5 stage grids
│   ├── run_one.sh
│   └── orchestrator.sh                # 串行 E1.0 + E1 stage experiments
├── figures/
│   └── E1_ablation_summary_final.csv  # 最终汇总
└── archive_old_7cell/                 # 旧 7-cell 结果 1749 cells / 全 0% SR,保留以备复算
```

**GT 共享 E0:** attack-only signature 默认复用 `pids_attack/experiments/E0_detection/test_data/<scenario>/attack_only/attack_gt_signature.json`;每次 E1/E2 cached-mixed query 在自己的 outdir 生成当前 `gt.json`。

### 3.14 实施步骤

1. **E1.0 bootstrap profile 已 wired 并通过** — 核心实现位于 `pids_attack/attack/safemimic_cmd/search/one_shot.py`;最小 Add δ、cached-mixed oracle、E0-style GT/metrics、JSON schema、aggregate row 已闭环。E1.0 实验脚本只做 CLI/grid/output 包装。
2. **`aggregate.py` 已支持 E1.0 schema** — 支持 E1.0 pass/query/R1/R2/ASR/|Δ|,并兼容旧 7-cell JSON。
3. **E1.0 bootstrap 已跑通** — `minimal_add × threatrace_g1g2 × 2 scenarios × seed=1`,query、R1/R2、JSON、aggregate 全部通过。
4. **wire action variants** — `InnerGA` 必须能按 action set 真实执行 Add / Edit / Move / Remove 对应的搜索分支。
5. **建 E1 子目录** — `E1.1_mutation` / `E1.2_fitness` / `E1.3_search` / `E1.4_surrogate` / `E1.5_acquisition`。
6. **跑 E1.1 mutation pilot** — `add_only/add_edit/add_edit_move/all4 × threatrace_g1g2 × scenario 01 × seed=1`,同时检查 action 是否真实产生、R1/R2 是否保持、以及相对 A0-only 是否出现 attack-node evasion 信号。
7. **finding 回写 attack framework** — 每个 gate/pilot 后先判断 finding 是否要求修改 `pids_attack/attack/safemimic_cmd/`;`experiments/E1_ablation/` 只改 config/grid/aggregate,不写攻击逻辑。若修改框架,必须重跑触发该修改的 gate/pilot。
8. **批量跑第一轮** — orchestrator 按当前 stage 顺序调用 `run_grid.sh`:E1.0 先跑 2-cell gate;后续 E1.1-E1.5 只有在前一 stage gate 通过后再扩展。

### 3.15 关键风险

| 风险 | 应对 |
|---|---|
| E1.0 最小闭环不稳定 | 先修 attack framework / oracle / aggregate schema;不得直接跑 E1.1-E1.5 |
| `all4` 实际仍是 Add-only | E1.1 pilot 已确认四个 variant 的搜索分支不同,但还未证明有效性;后续若改 search/commit,必须重跑 E1.1 |
| MCC drop 来自 FP 爆炸,不是 evasion | 每个表同时报 ASR、Precision/MCC、FP、R1/R2;δ 产生的非 GT 报警按统一 node-level FP 计入,不单独设 GT |
| no-posterior / random baseline query budget 不公平 | 所有 variants 固定同一 B_max;不得让某 variant 用真 query 评估更多 candidates |
| MCTS 实现成本高且口径不稳 | 不进入第一轮主实验;等真实实现后再作为 appendix 扩展 |
| 变体未真实 wire,结果 tied | 每个 variant 在 JSON 中记录 config hash 与对应 branch name |

### 3.16 命令

```bash
# Dry-run E1.0 minimal attack framework gate
bash pids_attack/experiments/E1_ablation/scripts/run_grid.sh E1.0_framework --dry-run

# Run E1.0 real 2-cell bootstrap
bash pids_attack/experiments/E1_ablation/scripts/run_grid.sh E1.0_framework

# Dry-run E1.1 operator grid
bash pids_attack/experiments/E1_ablation/scripts/run_grid.sh E1.1_mutation --dry-run

# Aggregate after run
PYTHONPATH=pids_attack conda run -n mimicattack python \
  pids_attack/experiments/E1_ablation/scripts/aggregate.py \
  --root pids_attack/experiments/E1_ablation \
  --out figures/E1_ablation_summary_final.csv
```

### 3.17 当前状态

✅ **E1.0 cached-mixed bootstrap 已通过;E1.1 mutation pilot 证据不足** —— E0 GT 已就绪。攻击框架实现位于 `pids_attack/attack/`,E1 只做实验封装与证据记录。E1.1 当前定义为 Add/Edit/Move/Remove,其中 Edit 是 `Edit(delta_id,target_id)` 的命令间关联编辑;旧 4-cell pilot 只确认 legacy Add/Rewrite/Move/Remove 能进入真实 query history 并保持 R1/R2,但没有降低 attack-node TP,也不能证明新 Edit 定义下的有效性或独立贡献。下一步仍在 E1.1 内修改攻击框架/搜索设置并重跑,不能直接进入 E1.2 作为完成态。旧脚本/旧结果仍是旧 7-cell sweep 结构,不能直接作为新 E1 paper 数据源。

(旧 7-cell ablation 结果 1749 cells / 全 0% SR 在 `archive_old_7cell/` 保留以备复算,不再作为 paper 数据源)

---

## 4. E2 Attack — 完整主攻击实验

> **Archived old-oracle result.** 本节数字来自 2026-06-04 的旧 graph-summary oracle。原始结果保留,但当前 attack-node oracle 已更新,这些 SR / q★ / 关键发现不能直接写入 paper 主结论。

### 指标含义

| 列 | 含义 | 方向 |
|---|---|---|
| **Detector** | 被攻击的 PIDS 检测器(g1/g2/g1g2/magic/orthrus/threatrace/magic_g1g2) | — |
| **Algo** | 攻击算法。`full` = SafeMimic-CMD full pipeline;`random` = 纯随机 δ baseline。旧 JSON 曾用 legacy full-pipeline label,当前重跑统一写 `full` | — |
| **n** | cell 数 = scenarios × seeds。50 = 10 scenarios × 5 seeds | — |
| **SR** | Success Rate = evade 成功的 cell 数 / n | 越高越好 |
| **q★** | 成功 cell 上平均真 query 次数(失败 cell 不算) | 越低越好 |
| **\|Δ★\|** | 成功 cell 上平均扰动 op 数 | 越低越好 |
| **wall/cell** | 平均每个 cell 跑了多久 | — |

### E2.0 Main Attack — old graph-summary oracle(700 / 700 cells,2026-06-04 11:08)

| Detector | Algo | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| g1 | full | 50/50 | **100%** | 1.0 | 1.0 | 4.9s |
| g1 | random | 50/50 | **96%** | 1.2 | 1.0 | 11.0s |
| g2 | full | 50/50 | **0%** | — | — | 859s |
| g2 | random | 50/50 | **0%** | — | — | 234s |
| g1g2 | full | 50/50 | **0%** | — | — | 384s |
| g1g2 | random | 50/50 | **0%** | — | — | 239s |
| **magic** | full | 50/50 | **0%** | — | — | 902s |
| magic | random | 50/50 | **0%** | — | — | 7.8s¹ |
| **orthrus** | full | 50/50 | **0%** | — | — | 389s |
| orthrus | random | 50/50 | **0%** | — | — | 11.8s¹ |
| **threatrace** | full | 50/50 | **0%** | — | — | 321s |
| threatrace | random | 50/50 | **0%** | — | — | 81.6s¹ |
| **magic_g1g2** | full | 50/50 | **0%** | — | — | 680s |
| magic_g1g2 | random | 50/50 | **0%** | — | — | 8.4s¹ |

¹ random baseline 有实现 bug:所有 add op 用同 `edge=(0,1)`,第 2 个 stage 起 apply_delta precondition 失败 → 实际 q_used=1 而非 B_max=20。1 个随机扰动就让 GNN 标 55 flagged 节点(magic),0% SR 结论仍成立但 random 偏弱。TODO:修 random 让每 stage 用累积 G 的不同 edge,重跑 random 才公平对比。

### E2.0 旧口径汇总

| 类别 | n | SR | 说明 |
|---|---:|---:|---|
| **g1 (太弱)** | 100 | 98% | full 100% + random 96% — 唯一击破的 detector |
| **GNN (强)** | 300 | 0% | magic / orthrus / threatrace × {full, random} 全 0% |
| **G2 / G1G2 / Hybrid** | 300 | 0% | G2 + G1G2 + magic_g1g2 — G2 主导整个 hybrid |
| **总计** | 700 | 14% | 14% = 98/700,全部来自 g1 |

### E2.0 旧口径关键观察

1. **G1 (power-law degree distribution) 太宽松。** random 96% SR,full 100% SR。G1 单独不能防御命令空间扰动。
2. **G2 (feature co-occurrence) 极严格,无 evade 可能。** 不论 full/random,SR=0%。这也意味着 G2 可能有高 benign false positive 风险,需要单独测 benign-test FP rate。
3. **G1G2 OR 合并 → G2 主导。** SR=0% 与 G2 单独一致,OR 合并退化为最严规则。
4. **GNN 检测器当前设计下不可击穿。** magic / orthrus / threatrace × {full, random} 全 0% SR。
5. **full 在 g1 上 q 效率优于 random。** q★ 1.0 vs 1.2。
6. **full 在不收敛 detector 上 4-8× 慢于 random。** magic 902s vs 7.8s,需要 early-stop。

旧口径历史观察,新 paper 主结论需等 attack-node oracle 重跑后再写:

> Across 7 detectors and 700 attack cells, the current SafeMimic-CMD v3 succeeds only against the G1 power-law rule (100% SR for SafeMimic-CMD, 96% for random). For G2, G1G2, all three GNN detectors, and the magic+G1G2 hybrid, both SafeMimic-CMD and random achieve 0% SR within B_max=20 queries.

---

## 5. 进度日志

| 时间 | 事件 | 备注 |
|---|---|---|
| 2026-06-02 启动 | A.1 后台启动 | rule × full,150 cells |
| 2026-06-02 23:42 | Orchestrator 启动 | A.2 → I 串行 |
| 2026-06-03 00:48 | A.2 ✅ done | rule × random 全部 150 cells |
| 2026-06-03 10:01 | A.1 卡在 g2/08 | 88/300,~1100s/cell(g2 不收敛) |
| 2026-06-03 10:01 | A.3 进行中 | full × magic,24/150 cells |
| 2026-06-03 23:45 | **A.1 ✅ done** | 300 cells,24h 总耗时 87766s |
| 2026-06-03 23:49 | **A.3 ✅ done** | orchestrator 跳过已跑 cells,补 threatrace × 2 → 50/50。E2.0 总计 450 cells |
| 2026-06-03 23:49 | A.4 🔄 启动 | GNN × random,150 cells |
| 2026-06-04 01:18 | **A.4 ✅ done** | GNN random SR=0%,但 baseline 偏弱 — 见 footnote 1 |
| 2026-06-04 11:08 | **A.5 ✅ done** | hybrid magic_g1g2 × {full,random} 全 0% SR。E2.0 主表 700/700 完成 |
| 2026-06-04 20:30 | **B ✅ done** | E1.4 scalarize 250 cells,全 0% SR |
| 2026-06-05 14:44 | **C ✅ done** | E1.3 f2_metric 250 cells,kde 50 cells crash |
| 2026-06-05 22:11 | kde refill ✅ done | 50 cells 跑回,SR 0% |
| 2026-06-06 17:38 | **D ✅ done** | E1.6 acquisition 300 cells,全 0% SR |
| 2026-06-07 14:48 | **E ✅ done** | E1.1 features stub 250 cells,全 0% |
| 2026-06-07 23:43 | **F ✅ done** | E1.2 surrogate stub 250 cells,全 0% |
| 2026-06-08 15:33 | **G ✅ done** | E1.5 commit stub 200 cells,全 0% |
| 2026-06-08 23:03 | **H ✅ done** | E1.7 ga_cmd stub 199 cells,全 0% |
| 2026-06-08 23:03 | **I ✅ done** | 原 combined orchestrator 全部跑完。新结构已拆成 E1_ablation 与 E2_attack |
| 2026-06-24 | **E0 ⚠️ attack-only GT + marker window rerun** | 30 cells;artifact valid,但 GT audit 发现 footprint 偏宽 |
| 2026-06-24 | **E0 threshold LOSO diagnostic ✅ done** | threatrace LOSO MCC 0.436 → 0.455;Precision 0.276 → 0.359;Recall 0.790 → 0.643 |
| 2026-06-24 | **E0 fresh rerun + per-detector runtime ✅ done** | 90/90 valid;global/GNN=threatrace MCC 0.436;Rule=g2 MCC -0.067;Hybrid=threatrace_g1g2 MCC 0.184 |
| 2026-06-24 | **E0 runtime loader ✅ done** | `load_e0_oracle(global_best/best_by_class.*/<detector>)` 可从 per-detector config 构造 lazy config-backed oracle |
| 2026-06-24 | **E0 all-detector runtime preservation ✅ done** | 旧 runtime bundle 已重构为 `detection/artifacts/<detector>/manifest.json` |
| 2026-06-24 | **E0 config-backed oracle loader ✅ done** | GNN 使用 config artifact root;rule/hybrid 使用 copied runtime rule artifact |
| 2026-06-24 | **E0 runtime threshold injection ✅ done** | config threshold=1.5 与默认 threatrace 节点级输出一致;可接独立 calibration threshold |
| 2026-06-24 | **E0 independent calibration diagnostic ✅ done** | 内部 calibration split 诊断支持选阈值再测 results |
| 2026-06-24 | **E0 threatrace independent calibration ✅ done** | threshold=0.905967;test MCC 0.436 → 0.510,Precision 0.276 → 0.361,Recall 0.790 保持 |
| 2026-06-24 | **E0 orthrus calibration initial diagnostic** | threshold=3.967562;早期诊断 MCC 0.18094 → 0.18119,当时因 runtime 复现问题未进主表;后续已由 2026-06-25 MCC-first policy 覆盖 |
| 2026-06-24 | **E0 rule resource-filter optimization ✅ done** | 推理侧过滤系统库/公共配置资源;g2 MCC -0.067 → 0.095,FP 2426 → 66;threatrace_g1g2 MCC 0.184 → 0.274,FP 5284 → 2889 |
| 2026-06-25 | **E0 hybrid merge policy optimization ✅ done** | `threatrace_g1g2` 改为 `threatrace OR g2`;FP 2889 → 779,Precision 0.129 → 0.354,MCC 0.274 → 0.519,成为 global best |
| 2026-06-25 | **E0 batch controller filter ✅ done** | rule detector 不再把 E0 collector 的 `RUN_DIR=/tmp/e0_*` controller shell 当 workload 节点;unknown flagged 995 → 0,global MCC 0.519 → 0.520 |
| 2026-06-25 | **E0 magic calibration + dependent hybrid refresh ✅ done** | threshold=103.063195;magic MCC -0.068 → 0.008,Recall 0.996 但 FP=13358;`magic_g1g2` 自动按 `magic OR g1 OR g2` 重算并刷新 runtime |
| 2026-06-25 | **E0 orthrus hybrid merge optimization ✅ done** | `orthrus_g1g2` 改为 `orthrus OR g2`;FP 847 → 74,Precision 0.037 → 0.308,MCC 0.001 → 0.127 |
| 2026-06-25 | **E0 orthrus threshold runtime reproducibility ✅ done** | `threshold_override` 时禁用 KMeans 覆盖;`orthrus` MCC 0.18094 → 0.18119,`orthrus_g1g2` MCC 0.127 → 0.145 |
| 2026-06-25 | **E0 threshold calibration policy optimization ✅ done** | 内部 threshold calibration 改为严格 MCC-first;`orthrus` threshold=3.968229,FP 51 → 34,Precision 0.452 → 0.553,MCC 0.181 → 0.204;`orthrus_g1g2` MCC 0.145 → 0.154 |
| 2026-06-25 | **E0 controller stop-signal filter ✅ done** | 过滤 `touch /tmp/e0_*/benign.stop` collector 控制节点;g2 FP 64 → 44,MCC 0.096 → 0.114;global `threatrace_g1g2` FP 777 → 757,MCC 0.520 → 0.525 |
| 2026-06-25 | **E0 rule resource-noise filter withdrawn** | 裸目录项、DNS resolver `*:53`、nscd socket 过滤被撤回;这些 FP 计入 clean baseline。 |
| 2026-06-25 | **E0 GNN system-resource post-filter withdrawn** | `/proc/*`、`/etc/hostname`、DNS `:53`、nscd resolver socket 过滤被撤回;这些 FP 计入 clean baseline。 |
| 2026-06-25 | **E0 artifact manifest sync ✅ done** | 当前检测结果同步到 `detection/artifacts/<detector>/manifest.json` 与 `detection/artifacts/manifest.json`。 |
| 2026-06-25 | **E0 executable-file post-filter withdrawn** | executable-file requires flagged subject 过滤被撤回;该规则属于 detector policy,不是 E0 GT cleanup。 |
| 2026-06-25 | **E0 clean controller-only baseline ✅ done** | 只保留 E0 controller cleanup 后重刷 9 个 detector;global `threatrace_g1g2` TP=426,FP=747,FN=84,Precision=0.363,Recall=0.835,MCC=0.527。 |
| 2026-06-25 | **E0 training-data phase-1 rerun ✅ done** | 删除污染 benign training traces,重采 30 份 benign,重训 magic/orthrus/threatrace 与 G1/G2;fresh E0 90/90 valid,global `threatrace_g1g2` TP=426,FP=1102,FN=81,Precision=0.279,Recall=0.840,MCC=0.455。 |
| 2026-06-25 | **E0 rule G1 per-command degree fix ✅ done** | G1 改为使用 benign per-command degree profile,不再用全局 power-law lambda 直接逐点报警;g1 FP 825 → 14,MCC -0.012 → -0.006;g1g2 FP 825 → 44,MCC -0.012 → 0.114;global best 仍为 `threatrace_g1g2` MCC=0.455。 |
| 2026-06-25 | **E0 rule G2 netflow propagation ✅ done** | G2 标红 subject 时同步输出其触达的 netflow 节点,不传播 file;g2/g1g2 TP 23 → 43,FP 44 → 54,MCC 0.114 → 0.182;global best 仍为 `threatrace_g1g2` MCC=0.455。 |
| 2026-06-25 | **E0 rule phase attempt 3 no-save** | 只读模拟两种候选:flagged subject → executable-file basename 传播使 g2 FP 54 → 64,MCC 0.182 → 0.172;full-command G2 使 FP 54 → 394,MCC 0.182 → 0.060。二者均降低 MCC,且当前图没有真实 spawn 边可做 process-child 传播,因此规则阶段第 3 次不保存代码/artifact。 |
| 2026-06-25 | **E0 inference runtime artifact loader fix ✅ done** | 第三阶段第 1 次:发现 `load_e0_oracle()` 保存了 per-detector runtime artifact,但 GNN runtime 仍从 `detection/training/artifacts` 的 best_model 加载;同时 `_LocalDetector` cache key 未包含 `model_path`。已改为 `model_path=detection/artifacts/<detector>/`,训练 cache root 仍保留为 `detection/training/artifacts`;hybrid 同步传递 `gnn_model_path`。重算 6 个 GNN/hybrid detector 后 TP/FP/TN/FN/MCC 与当前 E0 完全一致,所以不刷新 detector best;该修复保证后续攻击框架使用最终保存模型和参数。 |
| 2026-06-26 | **PIDSMaker Magic KNN normalization finding — review needed** | 第三阶段第 2 次:对照 upstream `inference_loop.py` 发现 Magic 分支用标准化后的 `x_test_sampled` 拟合 KNN,但用未标准化的 `x_test` 查询距离。adapter 当前严格复刻该逻辑。只读模拟“查询向量也标准化”后,在当前 threshold 下 Magic 从 TP=293/FP=9319/MCC=-0.044 变成 TP=0/FP=0/MCC undefined,说明公式与 threshold/calibration 强耦合;这属于 PIDSMaker upstream 逻辑问题候选,本轮不擅自改 `PIDSMaker/`,等待 review。 |
| 2026-06-26 | **E0 runtime threshold override fix ✅ done** | 第三阶段第 3 次:发现 `detection/artifacts/<detector>/manifest.json` 中的普通训练阈值 `threshold` 被 registry 当作 `threshold_override` 传入 runtime,导致 Orthrus 的 upstream KMeans 后处理被关闭。已改为只有显式 `inference_threshold` 才覆盖 runtime threshold;普通 `threshold` 仅作训练产物说明。重算 E0 后 `orthrus` TP/FP/FN=85/3579/422,MCC=-0.041 → 32/24/475,MCC=0.182;`orthrus_g1g2` MCC=-0.041 → 0.182。global best 仍为 `threatrace_g1g2` MCC=0.455。 |
| 2026-06-26 | **E0 calibration runtime plumbing fix ✅ done** | 第四阶段第 1 次:发现 calibration 应用代码仍写旧 `config.json/metrics.json`,而当前 runtime artifact 是 `manifest.json`;同时 threshold diagnostics 仍假设 SQL/GT 在 `results/<scenario>/`,与 E0 重构后的 `test_data/<scenario>/` 分离结构不一致。已改为写 `manifest.threshold.inference_threshold`,diagnostics 从 sibling `test_data/` 读取 SQL/GT,并让 hybrid manifest 继承 base GNN 的显式阈值。该尝试修复可复现性,本身不改变 MCC。 |
| 2026-06-26 | **E0 threatrace validation-floor calibration ✅ done** | 第四阶段第 2 次:用 benign validation score-floor policy 设置 `threatrace` `inference_threshold=0.0`。选择依据是 validation threatrace score 非负且 observed min score > 0,不使用 E0 GT 选阈值;E0 只作为最终评估。`threatrace` FP 1058 → 648,Precision 0.276 → 0.383,MCC 0.438 → 0.530;dependent hybrid `threatrace_g1g2` FP 1102 → 692,Precision 0.279 → 0.381,MCC 0.455 → 0.544,刷新 global best。 |
| 2026-06-26 | **E0 calibration phase attempt 3 no-save** | 第四阶段第 3 次:复查 `threshold_sweep_summary.csv` 与 LOSO 诊断。magic 的 LOSO MCC -0.044 → -0.060,orthrus 0.182 → 0.176,均退化;g1 虽从 -0.006 → 0.001,但仍接近无效且需要 E0 GT 才能选该阈值,不满足 validation-only 保存条件。因此第 3 次不保存新的阈值/artifact。 |

---

## 6. 数据物理位置

```text
/Users/xinguohua/mimicattack/pids_attack/experiments/
├── E0_detection/
│   ├── run.py
│   ├── results/
│   │   ├── summary_all.csv
│   │   └── <scenario>/{raw.strace,clean.strace,clean.strace.sql,gt.json,summary.csv,node_evidence.json}
│   └── results/
│       ├── summary_all.csv
│       └── <scenario>/{raw.strace,clean.strace,clean.strace.sql,gt.json,summary.csv,node_evidence.json}
├── E1_ablation/                           # E1.0 done; E1.1 pilot inconclusive; 后续 E1 ablation 待跑
│   ├── figures/E1_ablation_summary_final.csv
│   ├── E1.0_framework/results/*.json      # done(2 cells)
│   ├── E1.1_mutation/results/*.json       # legacy Rewrite pilot inconclusive; Edit 待重跑(4 cells)
│   ├── E1.2_fitness/results/*.json        # 待跑(当前 grid 100 cells)
│   ├── E1.3_search/results/*.json         # 待跑(当前 grid 100 cells)
│   ├── E1.4_surrogate/results/*.json      # 待跑(当前 grid 150 cells)
│   ├── E1.5_acquisition/results/*.json    # 待跑(当前 grid 150 cells)
│   ├── scripts/
│   ├── snapshots/
│   ├── logs/
│   └── archive_old_7cell/                 # 老 7-cell 结果 1749 cells,全 0% SR,保留以备复算
│       ├── E1.1_features/ E1.2_surrogate/ E1.3_f2_metric/ E1.4_scalarize/
│       ├── E1.5_commit/ E1.6_acquisition/ E1.7_ga_cmd/
└── E2_attack/
    ├── figures/E2_attack_summary_final.csv
    ├── E2.0_main_attack/results/*.json  # 700 cells
    ├── scripts/
    ├── snapshots/
	    └── logs/
```

```text
/Users/xinguohua/mimicattack/pids_attack/detection/artifacts/
├── manifest.json
├── magic/{manifest.json,state_dict.pkl,threshold.pkl,train_distance.txt}
├── orthrus/{manifest.json,state_dict.pkl,threshold.pkl,neighbor_loader.pkl}
├── threatrace/{manifest.json,state_dict.pkl,threshold.pkl}
├── g1/{manifest.json,g1_rule.pkl}
├── g2/{manifest.json,g2_rule.pkl}
├── g1g2/{manifest.json,g1_rule.pkl,g2_rule.pkl}
├── magic_g1g2/{manifest.json,state_dict.pkl,threshold.pkl,train_distance.txt,g1_rule.pkl,g2_rule.pkl}
├── orthrus_g1g2/{manifest.json,state_dict.pkl,threshold.pkl,neighbor_loader.pkl,g2_rule.pkl}
└── threatrace_g1g2/{manifest.json,state_dict.pkl,threshold.pkl,g2_rule.pkl}
```

---

## 7. 写作判断与下一步

### Paper 可用产出

| 类别 | n | SR / detection | 价值 |
|---|---:|---:|---|
| **E0 A0 detection** | 90 rows | TP/FP/TN/FN + Precision/Recall + overall/macro MCC | ✅ Orthrus-style node-level baseline 可用 |
| **E1.0 + E1 ablation** | E1.0 done(2 cells),E1.1 legacy pilot inconclusive(4 cells),Edit 待重跑,其余 ablation 待定 | E0-aligned node metrics + ASR/q★/\|Δ★\|/R1-R2/攻击影响率 | ⏳ E1.1 需重跑,E1.2-E1.5 待跑,详见 §3 |
| **E2.0 主表** | 700 | 旧口径历史结果 | ⚠️ graph-summary oracle 产物,新 attack-node oracle 下需重跑 |

### Negative result 的写作选项

**A. 改 motivation,paper 写成 negative result:** command-level black-box full-pipeline attack cannot evade modern GNN PIDS within B_max=20,反过来证明 GNN-based PIDS 的 query-bounded robustness。

**B. 加强算法重新跑:** 优先 pilot:

- B_max 100 + early stop
- 引入 edit/move/remove 操作;legacy rewrite 迁移为关系型 Edit
- WL feature → 真 GNN embedding
- f_2 reference 用 attack-similar benign

**C. 改 base detector + 主投规则 detector:** 当前 g1 100% SR 是 strong evidence,可以把论文重心改成“规则 detector 易被 black-box command-space mimicry 击破”。

### 立即要修

1. E2.0 需要按新的 GT/attack-node oracle 重跑,旧 graph-summary 结果只保留为原始历史产物。
2. `random` baseline cumulative edge bug 需要修,否则 E2.0 random 对比偏弱。
3. G1 在 benign trace 上 100% 标红,说明当前 G1 rule detector 的 FP 风险必须补实验确认。
