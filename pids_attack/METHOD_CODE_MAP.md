# SafeMimic 方法代码地图

当前代码按两大模块组织：

```text
pids_attack/
├── detection/        # 模块 1：训练 + 检测能力
├── attack/           # 模块 2：攻击算法能力
├── experiments/      # E0/E1/E2 论文实验
├── scenarios/        # 共享 A0 场景
├── shared/           # 共享候选命令池 / attacker prior
├── range/            # 共享真实执行层
├── cmd_graph/        # 共享命令图、命令空间算子、WL/R3
├── PIDSMaker/        # 上游代码，不重构
└── scripts/run.py    # 唯一公开入口
```

核心原则：

- `detection` 回答 detector 怎么采数据、训练、推理、诊断。
- `attack` 回答怎么利用 detector 反馈做 SafeMimic-CMD 搜索。
- `experiments` 只放论文实验，不混进 runtime 模块。
- 顶层 oracle 目录已删除；攻击时黑盒反馈入口位于 `attack/framework/oracle.py`。

## 唯一入口

```bash
python pids_attack/scripts/run.py detect collect
python pids_attack/scripts/run.py detect train-gnn
python pids_attack/scripts/run.py detect train-rules
python pids_attack/scripts/run.py detect e0

python pids_attack/scripts/run.py attack smoke-query
python pids_attack/scripts/run.py attack run
```

旧脚本不再作为公开入口。实验或调试时可以直接跑模块文件，但 README 和论文实验说明只写 `scripts/run.py`。

## 模块 1：训练 + 检测框架

这部分回答：**detector 怎么训练、怎么推理、原始 A0 是否能被检测到。**

### 数据和采集

- `detection/data/benign_collection_plan.yml`
  - 良性 workload、attack collection、输出路径配置。
- `detection/data/training_traces/`
  - 真实采集的 benign SQL 和 strace，只用于 train / val。
- `detection/data/test_traces/attack/`
  - 真实采集的 A0 attack SQL 和 strace，只映射到 test dates。
- `detection/training/artifacts/`
  - PIDSMaker GNN 训练 artifact。
- `detection/artifacts/`
  - 9 个 detector 的当前可运行模型/规则/参数。
  - 每个 detector 一个目录，统一由 `manifest.json` 描述。
- `detection/data/archive/`
  - 旧训练 trace 备份，不参与当前 runtime。
- `detection/data/collect.py`
  - `detect collect` 的实现。

### 训练和推理

- `detection/training/pidsmaker.py`
  - PIDSMaker GNN 的 train / eval / inference adapter。
  - 输入 PIDSMaker SQL，输出节点级 `node_index_id / y_pred / score`。
- `detection/training/rules.py`
  - SQL → command graph。
  - G1 / G2 / G1G2 规则 detector。
  - `magic_g1g2 / orthrus_g1g2 / threatrace_g1g2` hybrid detector。
- `detection/inference/registry.py`
  - 读取 `detection/artifacts/<detector>/manifest.json`。
  - 支持 `global_best`、`best_by_class.*` 和具体 detector 名称。
  - 这是 detection framework 对 attack framework 暴露 detector 的唯一加载层。
- `detection/diagnostics.py`
  - 内部诊断脚本：检查训练数据、artifact、PIDSMaker eval、E0 当前结果。
  - 不作为公开 CLI；公开检测入口只保留 `collect / train-gnn / train-rules / e0`。
- `detection/data/data_prep.py`
  - 原 `data_prep` 灌库逻辑，供 `detect train-gnn` 使用。

### E0 检测基线

- `experiments/E0_detection/`
  - 属于 detection-side experiment。
  - E0 不训练 detector，只消费已经训练好的 detector artifact。
  - detector 输入是 mixed run 的 `clean.strace.sql`。
  - GT 口径是：
    ```text
    GT nodes = attack-only signature ∩ mixed marker window
    ```
  - 主指标是节点级 TP / FP / TN / FN / Precision / Recall / overall MCC / macro MCC。
  - 默认覆盖 9 个 detector：
    ```text
    magic / orthrus / threatrace
    g1 / g2 / g1g2
    magic_g1g2 / orthrus_g1g2 / threatrace_g1g2
    ```
  - fresh E0 后同步当前 detector artifact manifest：
    ```text
    detection/artifacts/<detector>/
    detection/artifacts/manifest.json
    ```
  - 每个 detector 目录保存当前可运行文件和最小参数说明，例如：
    ```text
    state_dict.pkl
    threshold.pkl
    g1_rule.pkl / g2_rule.pkl
    neighbor_loader.pkl / train_distance.txt
    manifest.json
    ```
  - `detection/artifacts/manifest.json` 保存当前 `global_best` 和 `best_by_class`。

## 模块 2：攻击框架

这部分回答：**在 detector 已经存在的前提下，如何通过命令级扰动逃避检测。**

一次真实攻击 query 链路：

```text
scripts/run.py attack run
  -> attack/safemimic_cmd/runner.py            # 唯一 CLI 入口,by-config dispatch
  -> attack/safemimic_cmd/search/sequential.py # 外层 K-stage commit
  -> attack/safemimic_cmd/search/inner_ga.py   # 内层 GA
  -> attack/framework/oracle.py::query_with_validation_mixed
  -> range/cached_mixed.py::collect_cached_mixed_workload
  -> range/mixed_workload.py::collect_attack_query_trace
  -> range/converter.py::build_cdm_graph_from_strace
  -> detection/training/pidsmaker.py 或 detection/training/rules.py
  -> 返回节点级 detector 反馈
```

### 攻击算法

- `attack/framework/`
  - `AttackScenario`、`AttackResult`、`QueryResult`、`QueryHistory`、**`SafeMimicConfig`**(单一 config 类,覆盖所有 E1.x variants)。
- `attack/framework/oracle.py`
  - 攻击时黑盒 oracle。
  - 负责真实执行 query、跑 checker、调用 detector、返回攻击算法需要的反馈。
- `attack/safemimic_cmd/`
  - **唯一 paper-facing 攻击框架(SafeMimic-CMD)**。按 paper §5 子层逐步迁移搭建,顺序对齐 `p3_results.md` §3.0 6-stage gate(E1.0 → E1.5):
  - `runner.py`:唯一 CLI 入口,by-config dispatch。
  - `search/one_shot.py`:E1.0 minimal Add profile,一次 cached-mixed query 完成最小闭环。
  - `operators/{add,rewrite,move,remove}.py`:§4 mutation primitives(E1.1 阶段建出)。
  - `constraints/{r1_attack_integrity,r2_delta_executable}.py`:§3 validity gates(E1.0 内建)。
  - `objectives/{f1_hinge,f2_endogenous_r,scalarize}.py`:§5.3 双目标 fitness(E1.2 建出;**改名 fitness → objectives** 对齐 paper §5.3 术语)。
  - `search/{sequential,inner_ga,commit,one_shot}.py`:§5.3/§5.4 search(E1.3; `one_shot` supports E1.0)。
  - `surrogate/{wl_features,sparse_blr,ard}.py`:§5.2 surrogate(E1.4)。
  - `acquisition/{lcb,ei,thompson}.py`:§5.4 acquisition(E1.5)。
- `attack/data/command_templates.json`
  - attack search space 使用的命令模板。

### 共享命令图和执行层

- `cmd_graph/`
  - A0 JSON → command graph。
  - 论文主线的命令空间 atomic operators：`Add / Rewrite / Move / Remove`。
  - R3 unnoticeability 约束。
  - WL hash / WL feature。
  - `build_g_benign.py` 和 `benign.py` 构造 attacker-side `G_benign`。
- `range/`
  - Docker / Juice Shop / strace / checker / SQL converter。
  - detection 和 attack 都复用这一层。
- `scenarios/juiceshop/*.json`
  - 10 个共享 A0 场景。
- `shared/candidate_pool.txt`
  - detection benign workload 和 attack mutation 共用的候选命令池。
- `shared/g_benign.pkl`
  - attacker-side benign prior 预计算结果。

## 论文实验位置

- `experiments/E0_detection/`
  - detection baseline：原始 A0 在良性背景里能否被节点级 detector 检到。
- `experiments/E1_ablation/`
  - attack-side 6-stage finding-driven loop(E1.0 bootstrap → E1.5 acquisition)。详见 `p3_results.md` §3.0。
- `experiments/E2_attack/`
  - attack-side SafeMimic-CMD 完整主实验。

## 不重构的内容

- `PIDSMaker/`
  - vendored upstream，只保留必要 patch，不做结构重构。
- `experiments/*/results*`
  - 已有实验结果保留，不批量改历史 JSON/CSV 内部路径。
- `experiments/*/logs`、`experiments/*/snapshots`、`results/`
  - 运行产物保留，不作为方法主入口。
