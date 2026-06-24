# SafeMimic-CMD v3 — 实验结果

> 此文件跟 `p3_implementation_plan.md` 同目录。
> **每个 stage 跑完必须立刻更新这个文件** — 这是 paper writing 的唯一数据源。

最近更新: 2026-06-24

口径更新:

- E0 当前使用 **two-run batch workload** node-level 口径:Run 1 只跑完整 A0 block 生成 attack-only normalized node signatures;Run 2 跑 benign background + 同一个 A0 block,detector 只看 mixed SQL。
- E0 GT 定义为 `mixed marker window touched nodes ∩ attack-only signatures`。不使用 scenario `gt_keywords`,也不做噪音过滤;主结果只采用 Orthrus-style node-level evaluation:`TP / FP / TN / FN / Precision / MCC`。
- E0 当前主结果覆盖完整 9 个 detector:`magic / orthrus / threatrace / g1 / g2 / g1g2 / magic_g1g2 / orthrus_g1g2 / threatrace_g1g2`。
- E0 v1 batch artifact 已去掉 runner 污染:`orchestrator.sh / step_000*.sh / timeout / /tmp/e0_*/out/* / date +%s%N` 不再进入 fresh GT evidence。`curl / head / python3 / 127.0.0.1:3000 / runtime libraries` 属于真实攻击执行 footprint,按本轮 GT 定义保留。
- 已有 E3 JSON/CSV 是旧 graph-summary oracle 口径下生成的历史产物,保留作原始结果,但不能再作为 paper 主结论;E3 需要按新 oracle 重跑。

原始数据:

- E0: `experiments/E0_detection/results_window/summary_orthrus.csv`
- E0 per-scenario diagnostics: `experiments/E0_detection/results_window/summary_all.csv`
- E0 threshold diagnostics: `experiments/E0_detection/results_window/threshold_diagnostics/{threshold_sweep_summary.csv,threshold_loso_summary.csv,summary_orthrus_threshold_loso.csv}`
- E1: `experiments/E1_operators/proofs_results/*.json`
- E2: `experiments/E2_ablation/E2.*/*/results/*.json`
- E3: `experiments/E3_attack/E3.0_main_attack/results/*.json`
- E2 聚合: `experiments/E2_ablation/figures/E2_ablation_summary_final.csv`
- E3 聚合: `experiments/E3_attack/figures/E3_attack_summary_final.csv`
- E2 snapshots: `experiments/E2_ablation/snapshots/<stage>/summary.csv`
- E3 snapshots: `experiments/E3_attack/snapshots/<stage>/summary.csv`

---

## 1. 总览

### 实验进度

| Experiment | Variants | wired 状态 | 目标 | 已完成 | 进度 |
|---|---|---|---:|---:|---|
| **E0** A0 detection | 10 scenarios × 9 detectors | ✅ v1 two-run batch node-level GT | 90 | **90** | **✅ 100%** |
| **E1** operators | 3 detectors × P1/P2 + cmd P1 | ✅ graph/cmd proof done | 6 scripts | **6 scripts** | **✅ 100%** |
| **E2.1** features | wl / gnn / random_walk / graph2vec / domain = 5 | ⚠️ 只 wl wired,其他=wl(stub) | 250 | **250** | **✅ 100%** |
| **E2.2** surrogate | blr / gp_wl / gp_rbf / rf / ensemble = 5 | ⚠️ 只 blr wired,其他=blr(stub) | 250 | **250** | **✅ 100%** |
| **E2.3** f2_metric | knn(k=3/5/10) / dist_weighted / kde / gmm = 6 | ✅ 全 wired | 300 | **300** | **✅ 100%** |
| **E2.4** scalarize | tcheby(β=1/5/20) / weighted / lex = 5 | ✅ 全 wired | 250 | **250** | **✅ 100%** |
| **E2.5** commit | single / batch_2 / beam_3 / lookahead_2 = 4 | ⚠️ 只 single wired,其他=single(stub) | 200 | **200** | **✅ 100%** |
| **E2.6** acquisition | lcb(β=0.1/0.5/1/2) / ei / thompson = 6 | ✅ 全 wired | 300 | **300** | **✅ 100%** |
| **E2.7** ga_cmd | 4 flag 组合 | ⚠️ flag 存在但 GA 不消费(stub) | 200 | **199** | **✅ 99.5%** |
| **E3.0** main attack | 2 algos × 7 detectors = 14 | ⚠️ 旧 graph-summary 结果保留;新 attack-node oracle 待重跑 | 700 | **700 old / 0 new** | **⚠️ 待重跑** |
| **E0+E2+E3 cell 总计** | | | **2540** | **1839 current + 700 old E3** | **⚠️ E3 新口径待重跑** |

### 当前结论

1. **E0 two-run batch pipeline 跑通。** fresh E0 90/90 valid。GNN 中 threatrace 综合最好(TP=403,Precision=0.277,MCC=0.438),orthrus 最精确但漏报多(TP=32,Precision=0.593,MCC=0.185),magic 报警量大且质量差(MCC=-0.067)。规则与混合 detector 已纳入 E0,但 g1/g2/g1g2 与 magic_g1g2/orthrus_g1g2 Precision≈0.009-0.013,MCC 为负,说明它们主要暴露的是过度报警问题;threatrace_g1g2 TP=447,但 FP=5261,Precision=0.078,MCC=0.186。第一轮 threshold 优化诊断显示,threatrace 的 leave-one-scenario-out 校准可把 MCC 从 0.438 提到 0.491,Precision 从 0.277 提到 0.410,代价是 Recall 从 0.790 降到 0.643。
2. **E1 证明 P1/P2 原子 operator 有效。** P1 在 magic / orthrus / threatrace 上都有有效信号,且命令空间 P1 与图空间 P1 基本对齐。
3. **E2.1-E2.7 ablation 暂无 paper-grade 区分度。** 这些实验大多以 magic 为 base,而 magic 本身 0% SR,导致所有 variant tied;部分 variant 仍是 stub。
4. **E3.0 完整攻击结果需要重跑。** 现有 700 个 E3 结果是旧 graph-summary oracle 口径,只能作为历史产物;新代码已改为 GT/attack-node oracle。
5. **必须修正的技术问题。** random baseline 的 cumulative edge bug 会让 random 偏弱;G1 rule detector 在 benign trace 上 100% 标红,说明 G1 当前规则很噪。

### 口径说明

- PIDSMaker 原始输出是 **node-level**。
- E0 当前 GT 是 mixed trace 中同时满足 attack-only normalized signature 命中和 marker 时间窗触达的 subject/file/netflow 节点 union;它表示真实 A0 execution footprint,不是只取语义攻击 subject。
- E0 当前主指标是 detector flagged nodes 与 GT nodes 的节点级交集形成的 TP/FP/TN/FN;整图任意节点报警不进入 E0 主结论。

---

## 2. E0 Detection — A0 原始检测实验

### Orthrus-style node-level 结果表

目的:按 Orthrus 的 node-level detection performance 口径,量化 detector 报警节点与 E0 GT nodes 的 TP/FP/TN/FN、Precision 和 MCC。

指标定义:

```text
TP = flagged_nodes ∩ GT_nodes
FP = flagged_nodes - GT_nodes
FN = GT_nodes - flagged_nodes
TN = all_nodes - TP - FP - FN

Precision = TP / (TP + FP)
MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
```

表中每个 scenario 合并展示 9 行 detector:GNN / Rule / Hybrid 三组。原始 CSV 保留 `scenario × detector` 的 90 行长表,方便程序读取。

状态:当前表是 v1 two-run batch workload 的 fresh 结果。10 个 scenario 均为 `all_steps_passed=True`,`final_attack_succeeded=True`,`gt_source=attack_only_signature_marker_window`。

数据源:`experiments/E0_detection/results_window/summary_orthrus.csv`。

聚合结果:

| System | TP | FP | TN | FN | Precision | MCC |
|---|---:|---:|---:|---:|---:|---:|
| magic | 44 | 3227 | 10306 | 466 | 0.013 | -0.067 |
| orthrus | 32 | 22 | 13511 | 478 | 0.593 | 0.185 |
| threatrace | 403 | 1050 | 12483 | 107 | 0.277 | 0.438 |
| g1 | 44 | 4209 | 9324 | 466 | 0.010 | -0.092 |
| g2 | 23 | 2435 | 11098 | 487 | 0.009 | -0.066 |
| g1g2 | 44 | 4211 | 9322 | 466 | 0.010 | -0.092 |
| magic_g1g2 | 44 | 4211 | 9322 | 466 | 0.010 | -0.092 |
| orthrus_g1g2 | 54 | 4221 | 9312 | 456 | 0.013 | -0.084 |
| threatrace_g1g2 | 447 | 5261 | 8272 | 63 | 0.078 | 0.186 |

Threshold diagnostic(pooled upper bound):

数据源:`experiments/E0_detection/results_window/threshold_diagnostics/threshold_sweep_summary.csv`。

这个表不覆盖 E0 主结果;它只回答“在不改 PIDSMaker 原生代码、不重新采 trace 的前提下,单独调 detector threshold 能否改善当前 operating point”。注意:pooled sweep 在同一批 E0 GT 上选阈值和评价,只能作为上界诊断,不能当最终 paper 主性能。

| System | Current Precision | Current Recall | Current MCC | Best-threshold Precision | Best-threshold Recall | Best-threshold MCC | Best threshold |
|---|---:|---:|---:|---:|---:|---:|---:|
| magic | 0.013 | 0.086 | -0.067 | 0.036 | 0.996 | 0.008 | 103.252026 |
| orthrus | 0.593 | 0.063 | 0.185 | 0.568 | 0.082 | 0.207 | 3.968611 |
| threatrace | 0.277 | 0.790 | 0.438 | 0.451 | 0.788 | 0.577 | 0.522226 |
| g1 | 0.010 | 0.086 | -0.092 | 0.000 | 0.000 | -0.003 | 12.200637 |

结论:当前最有调优价值的是 `threatrace` threshold。它在 Recall 基本不变的情况下把 FP 从 1050 降到 489,MCC 从 0.438 提到 0.577。`g1` 的问题不是简单 threshold 能解决,它需要回到规则定义或训练数据覆盖分析。

Threshold LOSO calibration:

数据源:`experiments/E0_detection/results_window/threshold_diagnostics/threshold_loso_summary.csv` 与 `summary_orthrus_threshold_loso.csv`。

这个表按 leave-one-scenario-out 口径评估:每个 held-out scenario 的 threshold 只由另外 9 个 scenario 选择,再在当前 scenario 上评价。因此它比 pooled sweep 更接近“可泛化调参”证据,但仍是 E0 内部诊断,不覆盖原始 detector baseline。

| System | Current Precision | Current Recall | Current MCC | LOSO Precision | LOSO Recall | LOSO MCC | ΔMCC | Median threshold |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| magic | 0.013 | 0.086 | -0.067 | 0.036 | 0.914 | -0.002 | +0.065 | 103.252035 |
| orthrus | 0.593 | 0.063 | 0.185 | 0.568 | 0.082 | 0.207 | +0.022 | 3.968611 |
| threatrace | 0.277 | 0.790 | 0.438 | 0.410 | 0.643 | 0.491 | +0.053 | 0.522226 |
| g1 | 0.010 | 0.086 | -0.092 | 0.000 | 0.000 | -0.003 | +0.088 | 12.200637 |

结论:`threatrace` 是唯一同时保持正 MCC 且有实质校准收益的 detector。LOSO 校准后 FP 从 1050 降到 472,Precision 从 0.277 提到 0.410,MCC 从 0.438 提到 0.491;代价是 TP 从 403 降到 328,Recall 从 0.790 降到 0.643。`magic` 和 `g1` 虽然 delta 为正,但校准后 MCC 仍接近 0 或为负,不能作为最终优化方向。

Scenario-level 结果:

| Scenario (GT/all) | Family | System | TP | FP | TN | FN | Precision | MCC |
|---|---|---|---:|---:|---:|---:|---:|---:|
| juiceshop_login_admin_sqli (46/1400) | GNN | magic | 4 | 324 | 1030 | 42 | 0.012 | -0.064 |
|  | GNN | orthrus | 3 | 2 | 1352 | 43 | 0.600 | 0.190 |
|  | GNN | threatrace | 36 | 106 | 1248 | 10 | 0.254 | 0.416 |
|  | Rule | g1 | 4 | 424 | 930 | 42 | 0.009 | -0.088 |
|  | Rule | g2 | 2 | 244 | 1110 | 44 | 0.008 | -0.064 |
|  | Rule | g1g2 | 4 | 424 | 930 | 42 | 0.009 | -0.088 |
|  | Hybrid | magic_g1g2 | 4 | 424 | 930 | 42 | 0.009 | -0.088 |
|  | Hybrid | orthrus_g1g2 | 5 | 425 | 929 | 41 | 0.012 | -0.079 |
|  | Hybrid | threatrace_g1g2 | 40 | 530 | 824 | 6 | 0.070 | 0.173 |
| juiceshop_login_bender_sqli (46/1424) | GNN | magic | 4 | 334 | 1044 | 42 | 0.012 | -0.065 |
|  | GNN | orthrus | 3 | 3 | 1375 | 43 | 0.500 | 0.172 |
|  | GNN | threatrace | 36 | 114 | 1264 | 10 | 0.240 | 0.403 |
|  | Rule | g1 | 4 | 443 | 935 | 42 | 0.009 | -0.089 |
|  | Rule | g2 | 2 | 247 | 1131 | 44 | 0.008 | -0.063 |
|  | Rule | g1g2 | 4 | 443 | 935 | 42 | 0.009 | -0.089 |
|  | Hybrid | magic_g1g2 | 4 | 443 | 935 | 42 | 0.009 | -0.089 |
|  | Hybrid | orthrus_g1g2 | 5 | 444 | 934 | 41 | 0.011 | -0.081 |
|  | Hybrid | threatrace_g1g2 | 40 | 557 | 821 | 6 | 0.067 | 0.167 |
| juiceshop_login_jim_sqli (46/1393) | GNN | magic | 4 | 322 | 1025 | 42 | 0.012 | -0.064 |
|  | GNN | orthrus | 3 | 2 | 1345 | 43 | 0.600 | 0.190 |
|  | GNN | threatrace | 36 | 105 | 1242 | 10 | 0.255 | 0.417 |
|  | Rule | g1 | 4 | 420 | 927 | 42 | 0.009 | -0.087 |
|  | Rule | g2 | 2 | 244 | 1103 | 44 | 0.008 | -0.065 |
|  | Rule | g1g2 | 4 | 420 | 927 | 42 | 0.009 | -0.087 |
|  | Hybrid | magic_g1g2 | 4 | 420 | 927 | 42 | 0.009 | -0.087 |
|  | Hybrid | orthrus_g1g2 | 5 | 421 | 926 | 41 | 0.012 | -0.079 |
|  | Hybrid | threatrace_g1g2 | 40 | 525 | 822 | 6 | 0.071 | 0.175 |
| juiceshop_db_schema_union_sqli (47/1392) | GNN | magic | 4 | 321 | 1024 | 43 | 0.012 | -0.066 |
|  | GNN | orthrus | 3 | 2 | 1343 | 44 | 0.600 | 0.188 |
|  | GNN | threatrace | 36 | 104 | 1241 | 11 | 0.257 | 0.414 |
|  | Rule | g1 | 4 | 418 | 927 | 43 | 0.009 | -0.089 |
|  | Rule | g2 | 2 | 244 | 1101 | 45 | 0.008 | -0.066 |
|  | Rule | g1g2 | 4 | 419 | 926 | 43 | 0.009 | -0.089 |
|  | Hybrid | magic_g1g2 | 4 | 419 | 926 | 43 | 0.009 | -0.089 |
|  | Hybrid | orthrus_g1g2 | 5 | 420 | 925 | 42 | 0.012 | -0.081 |
|  | Hybrid | threatrace_g1g2 | 40 | 523 | 822 | 7 | 0.071 | 0.170 |
| juiceshop_directory_listing_ftp (46/1400) | GNN | magic | 4 | 318 | 1036 | 42 | 0.012 | -0.063 |
|  | GNN | orthrus | 3 | 2 | 1352 | 43 | 0.600 | 0.190 |
|  | GNN | threatrace | 36 | 101 | 1253 | 10 | 0.263 | 0.425 |
|  | Rule | g1 | 4 | 412 | 942 | 42 | 0.010 | -0.085 |
|  | Rule | g2 | 2 | 243 | 1111 | 44 | 0.008 | -0.064 |
|  | Rule | g1g2 | 4 | 412 | 942 | 42 | 0.010 | -0.085 |
|  | Hybrid | magic_g1g2 | 4 | 412 | 942 | 42 | 0.010 | -0.085 |
|  | Hybrid | orthrus_g1g2 | 5 | 413 | 941 | 41 | 0.012 | -0.076 |
|  | Hybrid | threatrace_g1g2 | 40 | 513 | 841 | 6 | 0.072 | 0.179 |
| juiceshop_register_admin_mass_assignment (46/1380) | GNN | magic | 4 | 314 | 1020 | 42 | 0.013 | -0.063 |
|  | GNN | orthrus | 3 | 2 | 1332 | 43 | 0.600 | 0.190 |
|  | GNN | threatrace | 36 | 100 | 1234 | 10 | 0.265 | 0.426 |
|  | Rule | g1 | 4 | 404 | 930 | 42 | 0.010 | -0.085 |
|  | Rule | g2 | 2 | 239 | 1095 | 44 | 0.008 | -0.064 |
|  | Rule | g1g2 | 4 | 404 | 930 | 42 | 0.010 | -0.085 |
|  | Hybrid | magic_g1g2 | 4 | 404 | 930 | 42 | 0.010 | -0.085 |
|  | Hybrid | orthrus_g1g2 | 5 | 405 | 929 | 41 | 0.012 | -0.077 |
|  | Hybrid | threatrace_g1g2 | 40 | 504 | 830 | 6 | 0.074 | 0.181 |
| juiceshop_redirect_open (47/1410) | GNN | magic | 4 | 333 | 1030 | 43 | 0.012 | -0.067 |
|  | GNN | orthrus | 3 | 3 | 1360 | 44 | 0.500 | 0.170 |
|  | GNN | threatrace | 36 | 114 | 1249 | 11 | 0.240 | 0.397 |
|  | Rule | g1 | 4 | 442 | 921 | 43 | 0.009 | -0.092 |
|  | Rule | g2 | 2 | 247 | 1116 | 45 | 0.008 | -0.065 |
|  | Rule | g1g2 | 4 | 443 | 920 | 43 | 0.009 | -0.093 |
|  | Hybrid | magic_g1g2 | 4 | 443 | 920 | 43 | 0.009 | -0.093 |
|  | Hybrid | orthrus_g1g2 | 5 | 444 | 919 | 42 | 0.011 | -0.085 |
|  | Hybrid | threatrace_g1g2 | 40 | 557 | 806 | 7 | 0.067 | 0.161 |
| juiceshop_basket_idor (94/1468) | GNN | magic | 8 | 333 | 1041 | 86 | 0.023 | -0.091 |
|  | GNN | orthrus | 5 | 2 | 1372 | 89 | 0.714 | 0.184 |
|  | GNN | threatrace | 79 | 106 | 1268 | 15 | 0.427 | 0.563 |
|  | Rule | g1 | 8 | 438 | 936 | 86 | 0.018 | -0.124 |
|  | Rule | g2 | 5 | 249 | 1125 | 89 | 0.020 | -0.083 |
|  | Rule | g1g2 | 8 | 438 | 936 | 86 | 0.018 | -0.124 |
|  | Hybrid | magic_g1g2 | 8 | 438 | 936 | 86 | 0.018 | -0.124 |
|  | Hybrid | orthrus_g1g2 | 9 | 439 | 935 | 85 | 0.020 | -0.119 |
|  | Hybrid | threatrace_g1g2 | 87 | 544 | 830 | 7 | 0.138 | 0.262 |
| juiceshop_exposed_metrics (46/1386) | GNN | magic | 4 | 314 | 1026 | 42 | 0.013 | -0.063 |
|  | GNN | orthrus | 3 | 2 | 1338 | 43 | 0.600 | 0.190 |
|  | GNN | threatrace | 36 | 100 | 1240 | 10 | 0.265 | 0.426 |
|  | Rule | g1 | 4 | 404 | 936 | 42 | 0.010 | -0.084 |
|  | Rule | g2 | 2 | 239 | 1101 | 44 | 0.008 | -0.064 |
|  | Rule | g1g2 | 4 | 404 | 936 | 42 | 0.010 | -0.084 |
|  | Hybrid | magic_g1g2 | 4 | 404 | 936 | 42 | 0.010 | -0.084 |
|  | Hybrid | orthrus_g1g2 | 5 | 405 | 935 | 41 | 0.012 | -0.076 |
|  | Hybrid | threatrace_g1g2 | 40 | 504 | 836 | 6 | 0.074 | 0.181 |
| juiceshop_weak_password_admin (46/1390) | GNN | magic | 4 | 314 | 1030 | 42 | 0.013 | -0.062 |
|  | GNN | orthrus | 3 | 2 | 1342 | 43 | 0.600 | 0.190 |
|  | GNN | threatrace | 36 | 100 | 1244 | 10 | 0.265 | 0.426 |
|  | Rule | g1 | 4 | 404 | 940 | 42 | 0.010 | -0.084 |
|  | Rule | g2 | 2 | 239 | 1105 | 44 | 0.008 | -0.063 |
|  | Rule | g1g2 | 4 | 404 | 940 | 42 | 0.010 | -0.084 |
|  | Hybrid | magic_g1g2 | 4 | 404 | 940 | 42 | 0.010 | -0.084 |
|  | Hybrid | orthrus_g1g2 | 5 | 405 | 939 | 41 | 0.012 | -0.076 |
|  | Hybrid | threatrace_g1g2 | 40 | 504 | 840 | 6 | 0.074 | 0.181 |

### 解释

这轮 E0 的直接结论:

- GNN 组:threatrace 综合最好(TP=403,Precision=0.277,MCC=0.438);orthrus 最精确但漏报多(TP=32,FN=478,Precision=0.593,MCC=0.185);magic 报警量大但质量低(Precision=0.013,MCC=-0.067)。
- Rule 组:g1/g1g2 的 TP 与 magic 相同(44),但 FP 超过 4200,MCC=-0.092;g2 TP 更低(23),Precision=0.009,MCC=-0.066。规则 detector 能碰到部分 GT,但当前主要问题是过度报警。
- Hybrid 组:magic_g1g2 与 g1g2 基本一致;orthrus_g1g2 因规则 OR 合并后 FP 激增,MCC 从 orthrus 的 0.185 降到 -0.084;threatrace_g1g2 TP 提升到 447,但 FP=5261,Precision=0.078,MCC=0.186。
- Threshold 组:pooled sweep 给出 threatrace MCC=0.577 的上界;LOSO 校准给出 threatrace MCC=0.491 的更可信提升。下一轮优化应围绕 threatrace 的 threshold/validation calibration 做成可复现实验,而不是继续扩大 G1/G2 OR hybrid。

本轮结果使用 fresh E0 v1 batch 重新采集。节点级排查信息保留在每个 scenario 的 `node_evidence.json` 中,包含 `gt_nodes / flagged_nodes / gt_flagged_nodes / gt_missed_nodes / flagged_outside_gt_nodes`。artifact audit 确认 fresh GT evidence 中不再包含 `orchestrator.sh / step_000*.sh / timeout / /tmp/e0_*/out/* / date +%s%N`。

---

## 3. E1 Operators — P1/P2 原子扰动验证

目的:先证明方法里的原子扰动确实能改变 detector 对攻击节点的 node-level 判定,再进入 E2 的组合搜索。

### 图空间 operator 结果

| Detector | P1 shared-neighbor dilution | P2 edge rerouting | 结论 |
|---|---:|---:|---|
| **magic** | **4/4 = 100%** | **4/4 = 100%** | P1/P2 都有效 |
| **orthrus** | **8/9 = 88.9%** | 0/9 = 0% | P1 有效,P2 单独不够 |
| **threatrace** | **4/6 = 66.7%** | 0/6 = 0% | P1 对 file 节点有效,netflow 失败 |

### 命令空间 P1 结果

| Detector | Graph-space P1 | Command-space P1 | 对齐 |
|---|---:|---:|---|
| **magic** | 4/4 = 100% | **4/4 = 100%** | 完全一致 |
| **orthrus** | 8/9 = 88.9% | **7/9 = 77.8%** | 接近 |
| **threatrace** | 4/6 = 66.7% | **4/6 = 66.7%** | 完全一致 |

数据源:

- `experiments/E1_operators/FINDINGS.md`
- `experiments/E1_operators/FINDINGS_CMD.md`
- `experiments/E1_operators/proofs_results/*.json`

---

## 4. E2 Ablation — 组件消融/敏感性实验

### E2.1 Features(250 / 250 cells,2026-06-07 14:48)

| Variant | wired | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| wl(default) | ✅ | 50/50 | **0%** | — | — | ~298s |
| gnn | ⚠️ stub | 50/50 | **0%** | — | — | ~298s |
| random_walk | ⚠️ stub | 50/50 | **0%** | — | — | ~298s |
| graph2vec | ⚠️ stub | 50/50 | **0%** | — | — | ~298s |
| domain | ⚠️ stub | 50/50 | **0%** | — | — | ~298s |

关键发现:stub variant 等价于 wl default;base = magic 不可击破,所以全 0% SR,无法体现 feature 差异。

### E2.2 Surrogate(250 / 250 cells,2026-06-07 23:43)

| Variant | wired | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| blr(default) | ✅ | 50/50 | **0%** | — | — | ~127s |
| gp_wl | ⚠️ stub | 50/50 | **0%** | — | — | ~127s |
| gp_rbf | ⚠️ stub | 50/50 | **0%** | — | — | ~127s |
| rf | ⚠️ stub | 50/50 | **0%** | — | — | ~127s |
| ensemble | ⚠️ stub | 50/50 | **0%** | — | — | ~127s |

关键发现:全 0% 零区分度。wall/cell=127s 比 E2.6(317s) 快,可能是部分 stub 路径 short-circuit。

### E2.3 F2 Metric(300 / 300 cells,2026-06-05 22:11)

| Variant | wired | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| knn k=3 | ✅ | 50/50 | **0%** | — | — | ~257s |
| knn k=5(default) | ✅ | 50/50 | **0%** | — | — | ~257s |
| knn k=10 | ✅ | 50/50 | **0%** | — | — | ~257s |
| dist_weighted | ✅ | 50/50 | **0%** | — | — | ~257s |
| kde | ✅ | 50/50 | **0%** | — | — | ~257s |
| gmm | ✅ | 50/50 | **0%** | — | — | ~257s |

补充:kde 最初 50 cells crash(`f2_kde(phi_G, reference, bandwidth=0.5)` 不接受 `k` 参数),已加 `k` 占位参数并 refill 完成。最终 SR 仍为 0%。

### E2.4 Scalarize(250 / 250 cells,2026-06-04 20:30)

| Variant | wired | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| tcheby β=1 | ✅ | 50/50 | **0%** | — | — | ~133s |
| tcheby β=5(default) | ✅ | 50/50 | **0%** | — | — | ~133s |
| tcheby β=20 | ✅ | 50/50 | **0%** | — | — | ~133s |
| weighted_sum | ✅ | 50/50 | **0%** | — | — | ~133s |
| lex | ✅ | 50/50 | **0%** | — | — | ~133s |

关键发现:全 0% SR。若要看 scalarize 差异,base detector 应换成 g1 或先解决 GNN 0% 问题。

### E2.5 Commit(200 / 200 cells,2026-06-08 15:33)

| Variant | wired | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| single(default) | ✅ | 50/50 | **0%** | — | — | ~283s |
| batch_2 | ⚠️ stub | 50/50 | **0%** | — | — | ~283s |
| beam_3 | ⚠️ stub | 50/50 | **0%** | — | — | ~283s |
| lookahead_2 | ⚠️ stub | 50/50 | **0%** | — | — | ~283s |

关键发现:stub 同 E2.1/E2.2。commit ablation 需要实际 wire batch/beam/lookahead 后重跑。

### E2.6 Acquisition(300 / 300 cells,2026-06-06 17:38)

| Variant | wired | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| lcb β=0.1 | ✅ | 50/50 | **0%** | — | — | ~317s |
| lcb β=0.5(default) | ✅ | 50/50 | **0%** | — | — | ~317s |
| lcb β=1 | ✅ | 50/50 | **0%** | — | — | ~317s |
| lcb β=2 | ✅ | 50/50 | **0%** | — | — | ~317s |
| ei | ✅ | 50/50 | **0%** | — | — | ~317s |
| thompson | ✅ | 50/50 | **0%** | — | — | ~317s |

关键发现:全 0% SR。lcb / ei / thompson 在不收敛 detector 上无法区分。

### E2.7 GA-CMD(199 / 200 cells,2026-06-08 23:03)

| Variant | wired | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| default | ⚠️ flag stub | 50/50 | **0%** | — | — | ~131s |
| mut_weighted | ⚠️ flag stub | 50/50 | **0%** | — | — | ~131s |
| constrained | ⚠️ flag stub | 50/50 | **0%** | — | — | ~131s |
| both | ⚠️ flag stub | 49/50 | **0%** | — | — | ~131s |

关键发现:全 0% SR。GA 命令空间 ablation 待实际 wire flag 后再跑。缺失 1 cell 不影响 0% 结论。

---

## 5. E3 Attack — 完整主攻击实验

> **Archived old-oracle result.** 本节数字来自 2026-06-04 的旧 graph-summary oracle。原始结果保留,但当前 attack-node oracle 已更新,这些 SR / q★ / 关键发现不能直接写入 paper 主结论。

### 指标含义

| 列 | 含义 | 方向 |
|---|---|---|
| **Detector** | 被攻击的 PIDS 检测器(g1/g2/g1g2/magic/orthrus/threatrace/magic_g1g2) | — |
| **Algo** | 攻击算法。`grabnel` = BO + Inner GA 主算法;`random` = 纯随机 δ baseline | — |
| **n** | cell 数 = scenarios × seeds。50 = 10 scenarios × 5 seeds | — |
| **SR** | Success Rate = evade 成功的 cell 数 / n | 越高越好 |
| **q★** | 成功 cell 上平均真 query 次数(失败 cell 不算) | 越低越好 |
| **\|Δ★\|** | 成功 cell 上平均扰动 op 数 | 越低越好 |
| **wall/cell** | 平均每个 cell 跑了多久 | — |

### E3.0 Main Attack — old graph-summary oracle(700 / 700 cells,2026-06-04 11:08)

| Detector | Algo | n | SR | q★ | \|Δ★\| | wall/cell |
|---|---|---:|---:|---:|---:|---:|
| g1 | grabnel | 50/50 | **100%** | 1.0 | 1.0 | 4.9s |
| g1 | random | 50/50 | **96%** | 1.2 | 1.0 | 11.0s |
| g2 | grabnel | 50/50 | **0%** | — | — | 859s |
| g2 | random | 50/50 | **0%** | — | — | 234s |
| g1g2 | grabnel | 50/50 | **0%** | — | — | 384s |
| g1g2 | random | 50/50 | **0%** | — | — | 239s |
| **magic** | grabnel | 50/50 | **0%** | — | — | 902s |
| magic | random | 50/50 | **0%** | — | — | 7.8s¹ |
| **orthrus** | grabnel | 50/50 | **0%** | — | — | 389s |
| orthrus | random | 50/50 | **0%** | — | — | 11.8s¹ |
| **threatrace** | grabnel | 50/50 | **0%** | — | — | 321s |
| threatrace | random | 50/50 | **0%** | — | — | 81.6s¹ |
| **magic_g1g2** | grabnel | 50/50 | **0%** | — | — | 680s |
| magic_g1g2 | random | 50/50 | **0%** | — | — | 8.4s¹ |

¹ random baseline 有实现 bug:所有 add op 用同 `edge=(0,1)`,第 2 个 stage 起 apply_delta precondition 失败 → 实际 q_used=1 而非 B_max=20。1 个随机扰动就让 GNN 标 55 flagged 节点(magic),0% SR 结论仍成立但 random 偏弱。TODO:修 random 让每 stage 用累积 G 的不同 edge,重跑 random 才公平对比。

### E3.0 旧口径汇总

| 类别 | n | SR | 说明 |
|---|---:|---:|---|
| **g1 (太弱)** | 100 | 98% | grabnel 100% + random 96% — 唯一击破的 detector |
| **GNN (强)** | 300 | 0% | magic / orthrus / threatrace × {grabnel, random} 全 0% |
| **G2 / G1G2 / Hybrid** | 300 | 0% | G2 + G1G2 + magic_g1g2 — G2 主导整个 hybrid |
| **总计** | 700 | 14% | 14% = 98/700,全部来自 g1 |

### E3.0 旧口径关键观察

1. **G1 (power-law degree distribution) 太宽松。** random 96% SR,grabnel 100% SR。G1 单独不能防御命令空间扰动。
2. **G2 (feature co-occurrence) 极严格,无 evade 可能。** 不论 grabnel/random,SR=0%。这也意味着 G2 可能有高 benign false positive 风险,需要单独测 benign-test FP rate。
3. **G1G2 OR 合并 → G2 主导。** SR=0% 与 G2 单独一致,OR 合并退化为最严规则。
4. **GNN 检测器当前设计下不可击穿。** magic / orthrus / threatrace × {grabnel, random} 全 0% SR。
5. **grabnel 在 g1 上 q 效率优于 random。** q★ 1.0 vs 1.2。
6. **grabnel 在不收敛 detector 上 4-8× 慢于 random。** magic 902s vs 7.8s,需要 early-stop。

旧口径历史观察,新 paper 主结论需等 attack-node oracle 重跑后再写:

> Across 7 detectors and 700 attack cells, the current SafeMimic-CMD v3 succeeds only against the G1 power-law rule (100% SR for GRABNEL, 96% for random). For G2, G1G2, all three GNN detectors, and the magic+G1G2 hybrid, both GRABNEL-CMD and random achieve 0% SR within B_max=20 queries.

---

## 6. 进度日志

| 时间 | 事件 | 备注 |
|---|---|---|
| 2026-06-02 启动 | A.1 后台启动 | rule × grabnel,150 cells |
| 2026-06-02 23:42 | Orchestrator 启动 | A.2 → I 串行 |
| 2026-06-03 00:48 | A.2 ✅ done | rule × random 全部 150 cells |
| 2026-06-03 10:01 | A.1 卡在 g2/08 | 88/300,~1100s/cell(g2 不收敛) |
| 2026-06-03 10:01 | A.3 进行中 | grabnel × magic,24/150 cells |
| 2026-06-03 23:45 | **A.1 ✅ done** | 300 cells,24h 总耗时 87766s |
| 2026-06-03 23:49 | **A.3 ✅ done** | orchestrator 跳过已跑 cells,补 threatrace × 2 → 50/50。E3.0 总计 450 cells |
| 2026-06-03 23:49 | A.4 🔄 启动 | GNN × random,150 cells |
| 2026-06-04 01:18 | **A.4 ✅ done** | GNN random SR=0%,但 baseline 偏弱 — 见 footnote 1 |
| 2026-06-04 11:08 | **A.5 ✅ done** | hybrid magic_g1g2 × {grabnel,random} 全 0% SR。E3.0 主表 700/700 完成 |
| 2026-06-04 20:30 | **B ✅ done** | E2.4 scalarize 250 cells,全 0% SR |
| 2026-06-05 14:44 | **C ✅ done** | E2.3 f2_metric 250 cells,kde 50 cells crash |
| 2026-06-05 22:11 | kde refill ✅ done | 50 cells 跑回,SR 0% |
| 2026-06-06 17:38 | **D ✅ done** | E2.6 acquisition 300 cells,全 0% SR |
| 2026-06-07 14:48 | **E ✅ done** | E2.1 features stub 250 cells,全 0% |
| 2026-06-07 23:43 | **F ✅ done** | E2.2 surrogate stub 250 cells,全 0% |
| 2026-06-08 15:33 | **G ✅ done** | E2.5 commit stub 200 cells,全 0% |
| 2026-06-08 23:03 | **H ✅ done** | E2.7 ga_cmd stub 199 cells,全 0% |
| 2026-06-08 23:03 | **I ✅ done** | 原 combined orchestrator 全部跑完。新结构已拆成 E2_ablation 与 E3_attack |
| 2026-06-24 | **E0 ⚠️ attack-only GT + marker window rerun** | 30 cells;artifact valid,但 GT audit 发现 footprint 偏宽 |
| 2026-06-24 | **E0 threshold LOSO diagnostic ✅ done** | threatrace LOSO MCC 0.438 → 0.491;Precision 0.277 → 0.410;Recall 0.790 → 0.643 |

---

## 7. 数据物理位置

```text
/Users/xinguohua/mimicattack/pids_attack/experiments/
├── E0_detection/
│   ├── run.py
│   └── results_window/
│       ├── summary_all.csv
│       └── <scenario>/{raw.strace,clean.strace,clean.strace.sql,gt.json,summary.csv,node_evidence.json}
├── E1_operators/
│   ├── FINDINGS.md
│   ├── FINDINGS_CMD.md
│   ├── proofs/
│   └── proofs_results/
├── E2_ablation/
│   ├── figures/E2_ablation_summary_final.csv
│   ├── E2.1_features/results/*.json     # 250
│   ├── E2.2_surrogate/results/*.json    # 250
│   ├── E2.3_f2_metric/results/*.json    # 300
│   ├── E2.4_scalarize/results/*.json    # 250
│   ├── E2.5_commit/results/*.json       # 200
│   ├── E2.6_acquisition/results/*.json  # 300
│   ├── E2.7_ga_cmd/results/*.json       # 199
│   ├── scripts/
│   ├── snapshots/
│   └── logs/
└── E3_attack/
    ├── figures/E3_attack_summary_final.csv
    ├── E3.0_main_attack/results/*.json  # 700 cells
    ├── scripts/
    ├── snapshots/
    └── logs/
```

---

## 8. 写作判断与下一步

### Paper 可用产出

| 类别 | n | SR / detection | 价值 |
|---|---:|---:|---|
| **E0 A0 detection** | 30 | TP/FP/TN/FN + precision/MCC | ✅ Orthrus-style node-level baseline 可用 |
| **E1 operators** | 6 proof scripts | P1 graph/cmd 有效 | ✅ 支撑 P1/P2 原子扰动设计 |
| **E2.1-E2.7 ablation** | 1749 | 0% SR | ❌ 全部零区分度;base = magic 0% 且部分 variant 为 stub |
| **E3.0 主表** | 700 | 旧口径历史结果 | ⚠️ graph-summary oracle 产物,新 attack-node oracle 下需重跑 |

### Negative result 的写作选项

**A. 改 motivation,paper 写成 negative result:** Command-level black-box GRABNEL adaptation cannot evade modern GNN PIDS within B_max=20,反过来证明 GNN-based PIDS 的 query-bounded robustness。

**B. 加强算法重新跑:** 优先 pilot:

- B_max 100 + early stop
- 引入 rewrite/move/remove 操作
- WL feature → 真 GNN embedding
- f_2 reference 用 attack-similar benign

**C. 改 base detector + 主投规则 detector:** 当前 g1 100% SR 是 strong evidence,可以把论文重心改成“规则 detector 易被 black-box command-space mimicry 击破”。

### 立即要修

1. E3.0 需要按新的 GT/attack-node oracle 重跑,旧 graph-summary 结果只保留为原始历史产物。
2. `random` baseline cumulative edge bug 需要修,否则 E3.0 random 对比偏弱。
3. G1 在 benign trace 上 100% 标红,说明当前 G1 rule detector 的 FP 风险必须补实验确认。
