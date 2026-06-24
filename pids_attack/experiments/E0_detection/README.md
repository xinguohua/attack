# E0 检测基线实验

E0 属于 **训练 + 检测框架**，不是攻击框架。

它不训练 detector，只消费已经训练好的 artifact，回答一个基础问题：

```text
原始 A0 攻击在真实良性背景里执行时，
节点级 detector 能不能检测到真实攻击节点？
```

E0 的前置条件：

```text
GNN detector artifact 已由 scripts/run.py detect train-gnn 训练好
规则 detector artifact 已由 scripts/run.py detect train-rules 训练好
```

## 当前 GT 口径

E0 的 GT nodes 只有一个定义：

```text
GT nodes =
  mixed trace 中的节点
  且该节点 normalized signature 出现在 attack-only trace
  且该节点在 ATTACK_BEGIN / ATTACK_END marker 时间窗内被事件触达
```

简写就是：

```text
GT = attack-only signature ∩ mixed marker window
```

含义：

- `attack-only signature` 决定这个节点是否来自真实攻击执行 footprint。
- `mixed marker window` 决定这个节点是否出现在 mixed run 的攻击时间段里。
- 不使用 scenario keyword。
- 不做人为噪音过滤。
- 不再使用旧的 marker-only GT。

## 两次真实运行

每个 scenario 跑两次。

第一次：attack-only

```text
只执行完整 A0 攻击 block
一个 strace 包住整段攻击
生成 attack_gt_signature.json
```

输出：

```text
attack_only/raw.strace
attack_only/clean.strace
attack_only/clean.strace.sql
attack_only/workload.stdout
attack_only/workload.stderr
attack_only/step_outputs.json
attack_only/attack_gt_signature.json
attack_only/attack_gt_nodes.json
```

第二次：mixed

```text
启动良性背景 workload
warmup
打 ATTACK_BEGIN marker
执行完整 A0 攻击 block
打 ATTACK_END marker
cooldown
停止良性背景 workload
```

输出：

```text
raw.strace
clean.strace
clean.strace.sql
gt.json
detector_results.json
node_evidence.json
summary.csv
```

Detector 只看 mixed run 的 `clean.strace.sql`。

## 为什么 marker 不污染检测

marker 是为了定位 mixed run 里的攻击时间窗。

流程是：

```text
raw.strace 里保留 marker
extract_window(raw.strace) 提取 ATTACK_BEGIN / ATTACK_END 时间
strip_markers(raw.strace) 生成 clean.strace
clean.strace 转 clean.strace.sql
detector 只读取 clean.strace.sql
```

所以 detector 看不到 marker 字符串。

## 当前入口参数

```bash
PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py detect e0
```

直接跑 `experiments/E0_detection/run.py` 只作为调试入口，公开入口统一走 `scripts/run.py`。

只保留必要参数：

```text
--scenarios          只跑指定 scenario；默认跑全部
--detectors          指定 detector；默认跑完整 9 个 detector
--warmup-sec         mixed run 中攻击前良性背景运行时间；默认 10s
--cooldown-sec       mixed run 中攻击后良性背景运行时间；默认 20s
--refresh-signature  强制重跑 attack-only signature
```

默认 detector：

```text
GNN:     magic / orthrus / threatrace
规则:    g1 / g2 / g1g2
混合:    magic_g1g2 / orthrus_g1g2 / threatrace_g1g2
```

E0 启动前会做 artifact preflight：

```text
缺 GNN model artifact     → 直接报错，提示先跑 scripts/run.py detect train-gnn
缺 g1_rule.pkl/g2_rule.pkl → 直接报错，提示先跑 scripts/run.py detect train-rules
```

E0 不会自动训练 detector。

入口约束：

- mixed run 每次都应该 fresh 跑，避免拿旧 GT 或旧 detector 结果混用。
- container reset 固定打开，不再暴露成参数。
- attack-only signature 可以复用；只有攻击命令、converter、signature normalization 改了，才需要 `--refresh-signature`。

## 主要结果文件

统一结果目录：

```text
experiments/E0_detection/results_window/
```

顶层结果：

```text
summary_all.csv
summary_orthrus.csv
```

`summary_orthrus.csv` 里的 `orthrus` 指的是 Orthrus-style node-level
评价格式，不是只包含 orthrus detector。默认完整运行后：

```text
summary_all.csv      = 10 scenarios × 9 detectors = 90 rows
summary_orthrus.csv  = 同一批结果的论文表格式
```

每个 scenario：

```text
raw.strace
clean.strace
clean.strace.sql
gt.json
detector_results.json
node_evidence.json
summary.csv
```

## 主指标

节点级评价只看 detector flagged nodes 和 GT nodes 的交集。

```text
TP = flagged_nodes ∩ GT_nodes
FP = flagged_nodes - GT_nodes
FN = GT_nodes - flagged_nodes
TN = all_nodes - TP - FP - FN

Precision = TP / (TP + FP)
MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
```

主表用 Orthrus-style node-level 表：

```text
Scenario
System
TP
FP
TN
FN
Precision
MCC
```

其中：

- `Scenario` 写成 `scenario_id (GT nodes / all nodes)`。
- `System` 是 detector 名。
- 同一个 scenario 下默认有 9 行，对应 3 个 GNN、3 个规则、3 个混合 detector。

## Node Evidence

`node_evidence.json` 用来排查 detector 到底打中了哪些节点。

每个 detector 保留：

```text
gt_nodes
flagged_nodes
gt_flagged_nodes
gt_missed_nodes
flagged_outside_gt_nodes
```

每个节点记录包含：

```text
node_index_id
node_type
label
score
y_pred
path
cmd
```

## 当前代码职责

```text
collector.py      跑 attack-only / mixed 两次真实 trace
gt_signature.py   生成 attack-only signature，并计算 signature ∩ marker-window GT
window.py         只负责 marker 时间提取和 marker 清理
run.py            统一入口、调用 detector、计算节点级指标、写结果
```

当前 GT 只有 `attack-only signature ∩ mixed marker window` 这一条路径。
