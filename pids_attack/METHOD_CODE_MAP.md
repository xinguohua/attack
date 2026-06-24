# SafeMimic 方法代码地图

当前代码按两大模块组织：

```text
pids_attack/
├── detection/        # 模块 1：训练 + 检测能力
├── attack/           # 模块 2：攻击算法能力
├── experiments/      # E0/E1/E2/E3 论文实验
├── scenarios/        # 共享 A0 场景
├── shared/           # 共享候选命令池 / attacker prior
├── range/            # 共享真实执行层
├── cmd_graph/        # 共享命令图、算子、WL/R3
├── PIDSMaker/        # 上游代码，不重构
└── scripts/run.py    # 唯一公开入口
```

核心原则：

- `detection` 回答 detector 怎么采数据、训练、推理、诊断。
- `attack` 回答怎么利用 detector 反馈做 GRABNEL 搜索。
- `experiments` 只放论文实验，不混进 runtime 模块。
- 顶层 oracle 目录已删除；`oracle` 这个词只保留在 `attack/oracle.py`，表示攻击时的黑盒反馈。

## 唯一入口

```bash
python pids_attack/scripts/run.py detect collect-benign
python pids_attack/scripts/run.py detect collect-attack
python pids_attack/scripts/run.py detect train-gnn
python pids_attack/scripts/run.py detect train-rules
python pids_attack/scripts/run.py detect eval-gnn
python pids_attack/scripts/run.py detect e0
python pids_attack/scripts/run.py detect audit
python pids_attack/scripts/run.py detect threshold-sweep

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
  - 真实采集的 benign / attack SQL 和 strace。
- `detection/data/pidsmaker_artifacts/`
  - PIDSMaker GNN 训练 artifact。
- `detection/data/hybrid_rules/`
  - G1 / G2 规则 detector artifact。
- `detection/data/archive/`
  - 旧训练 trace 备份，不参与当前 runtime。
- `detection/collect.py`
  - `collect-benign` 和 `collect-attack` 的实现。

### 训练和推理

- `detection/pidsmaker.py`
  - PIDSMaker GNN 的 train / eval / inference adapter。
  - 输入 PIDSMaker SQL，输出节点级 `node_index_id / y_pred / score`。
- `detection/rules.py`
  - SQL → command graph。
  - G1 / G2 / G1G2 规则 detector。
  - `magic_g1g2 / orthrus_g1g2 / threatrace_g1g2` hybrid detector。
- `detection/diagnostics.py`
  - `detect audit`：检查训练数据、artifact、PIDSMaker eval、E0 当前结果。
  - `detect threshold-sweep`：只读 E0 结果，离线扫描 detector threshold。
- `detection/data_prep.py`
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
  - 主指标是节点级 TP / FP / TN / FN / Precision / MCC。
  - 默认覆盖 9 个 detector：
    ```text
    magic / orthrus / threatrace
    g1 / g2 / g1g2
    magic_g1g2 / orthrus_g1g2 / threatrace_g1g2
    ```

## 模块 2：攻击框架

这部分回答：**在 detector 已经存在的前提下，如何通过命令级扰动逃避检测。**

一次真实攻击 query 链路：

```text
scripts/run.py attack run
  -> attack/grabnel_cmd/runner.py
  -> attack/grabnel_cmd/algorithm.py
  -> attack/oracle.py::query_with_validation_strict
  -> range/checker.py::execute_with_checks
  -> range/converter.py::trace_to_pidsmaker
  -> detection/pidsmaker.py 或 detection/rules.py
  -> 返回节点级 detector 反馈
```

### 攻击算法

- `attack/framework/`
  - `AttackScenario`、`AttackResult`、`QueryResult`、`QueryHistory`。
- `attack/grabnel_cmd/`
  - GRABNEL-CMD 主实现。
  - `runner.py`：`scripts/run.py attack run` 调用的 runner。
  - `algorithm.py`：外层搜索。
  - `inner_ga.py`：候选扰动生成。
  - `fitness/`：攻击成功、隐蔽性、多目标标量化。
  - `surrogate/`：WL 特征和稀疏 BLR。
  - `acquisition/`：LCB / EI / Thompson。
- `attack/oracle.py`
  - 攻击时黑盒 oracle。
  - 负责真实执行 query、跑 checker、调用 detector、返回攻击算法需要的反馈。
- `attack/data/command_templates.json`
  - attack search space 使用的命令模板。

### 共享命令图和执行层

- `cmd_graph/`
  - A0 JSON → command graph。
  - P1/P2 mutation operators。
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
- `experiments/E1_operators/`
  - detection-side operator validation：P1/P2 mutation validation。
- `experiments/E2_ablation/`
  - attack-side ablation / sensitivity。
- `experiments/E3_attack/`
  - attack-side 完整 GRABNEL 主实验。

## 不重构的内容

- `PIDSMaker/`
  - vendored upstream，只保留必要 patch，不做结构重构。
- `experiments/*/results*`
  - 已有实验结果保留，不批量改历史 JSON/CSV 内部路径。
- `experiments/*/logs`、`experiments/*/snapshots`、`results/`
  - 运行产物保留，不作为方法主入口。
