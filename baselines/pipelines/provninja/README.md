# ProvNinja — 复现

本文档记录 `baselines/provninja/` 这份上游 `syssec-utd/provninja` 忠实复刻在它自带 sample 数据上的复现 + 代码分析。

---

## 1. 原始代码的复现和分析

代码位置:`baselines/provninja`(上游 `syssec-utd/provninja` 的 pristine clone)。

运行环境:conda env `mimicattack`(从 `provng.yml` 创建 + 加 `torch_geometric` / `jupyter` / `tensorflow==2.13.0` / `keras==2.13.1`)。**§2.x 所有命令运行前先激活 env**:

```bash
conda activate mimicattack
```

### 1.0 代码依赖的输入数据和模型

这一节是上游代码运行时从外部 read/load 的所有资源清单 —— 数据集、查表 JSON、预训模型,以及网络下载的预训模型,统称"输入"。给 §2.1-§2.6 兜底:后面任何入口跑出来的数字都能回到这里查它吃了哪些输入。代码自己产出的缓存 / 中间文件不算。

#### A. Windows 进程频次 DB(给 §2.1 gadget-finder)

- **路径**:`gadget-finder/FrequencyDB/SAMPLE_WINDOWS_FREQUENCY_DB.csv`
- **来源**:仓库自带,只是 sample(543 行)。论文里用的全量(54 Win + 32 Linux,13 个月,17TB 原始事件聚合)未公开。
- **配套输入**:`gadget-finder/input.csv` —— 单行 `entry,target`(默认 `winword.exe,notepad.exe`)。

- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 转移概率矩阵的源数据 | CSV 里有这么一行:`winword.exe,firefox.exe,250` |
| **操作** | `read_csv` → `groupby+pivot` 转成 src×dst 矩阵 → DFS 反复查表 | `winword.exe` 总 count = 1000,变换后 `transition_matrix.loc['winword.exe', 'firefox.exe'] = 25.0`(% 概率)。DFS 走到 winword 时问"firefox 行不行?",查到 25 > 0.003 → 允许往这边走 |
| **任务** | 输出多步伪装链 | `output.txt` 第一行:`winword.exe -> firefox.exe -> sshd.exe -> ssh-shellhost.exe -> cmd.exe -> ... -> notepad.exe : 1.00e+01` |

#### B. Enterprise APT path-based 特征向量(给 §2.2 SIGL, §2.3 ProvDetector)

- **路径**:`intrusion-detection-system/path-based/sample-enterprise-data/`
- **来源**:仓库自带。论文 Enterprise APT testbed(4 Win + 3 Linux,1779 graphs)的处理后 fv 三段(benign 15650 / anomaly 266 / gadget 268 行)。`*-paragraph.csv` 三个文件代码不读,只是人工对照(`gadget-paragraph.csv` 173 行还跟 fv 268 行对不上,上游本身不一致)。

- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 50 维 path fv 训练 / 评测集 | `benign-fv.csv` 第 1 行:`-0.1132, 0.0181, 0.0377, ..., -0.0698`(50 个 float)。对应 paragraph(代码不读)是:`BACKGROUNDTASKHOST.EXE READ_WRITE E71E1300...` |
| **操作** | `read_csv` → numpy 数组 → 模型 predict | 加载后变成 `x_benign: shape=(15650, 50)`,`x_anomaly: shape=(266, 50)`,`x_gadget: shape=(268, 50)`。SIGL 跑 `autoencoder.predict(x_anomaly)` 算重构误差;ProvDetector 跑 `lof.predict(x_anomaly)` 出 -1/+1 标签 |
| **任务** | 三组打分对比,看 evasion 效果 | ProvDetector 实测:anomaly F1 = 0.885,gadget F1 = 0.213 → 改造后 F1 掉 0.67,evasion 成功 |

#### C. Supply-Chain APT 图数据(给 §2.4 S-GAT, §2.5 Prov-GAT, §2.6 ProvNinja-Graph)

- **路径**:`intrusion-detection-system/graph-based/sample-supply-chain-data/` (23GB)
- **来源**:不在仓库里,通过 `download_sample_supply_chain_data.sh` 从 Google Drive 下(`1Jz0ZuiZlUEZdAgqlnfmpN2_X0Cms6Sl8`,4.5GB → 23GB)。是论文 Supply-Chain testbed(5 Linux,1091 graphs)处理后子集,共 4302 图(train 2248B+764A / validation 321B+109A / test 642B+218A)。dataloader 只接 8 种 relation 边类型(`ProcessNode~{PROC_CREATE,READ,WRITE,FILE_EXEC,IP_CONNECTION_EDGE}~{ProcessNode,FileNode,SocketChannelNode}`),其他 skip(`BaseDataloader.py:66-72`)。

- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 异构图的样本集(每图一个目录) | 一个目录 `test/anomaly/nd_220323_0105_24/` 含 `ProcessNode.csv`(EXE_NAME 列是 768 维 codebert 嵌入的 base64 字符串 `k05VTVBZAQB2AHsn...`)+ `FileNode.csv` + `ProcessNode~PROC_CREATE~ProcessNode.csv`(边 `,u,v,...`)+ 各类 `.pickle` |
| **操作** | scandir 遍历 → read_csv 节点+边 + pickle.load → dgl.heterograph 组装 | 加载后 `graph` 对象:`graph.nodes('ProcessNode').data['EXE_NAME']: shape=(N, 768)`。喂模型 `model(graph, agg_func(graph)) → 0.9952`(预测 anomaly) |
| **任务** | GNN 分类 + evasion 后再分类 | §2.5 Prov-GAT 实测 `nd_220323_0105_24` 原始预测 `0.9952`(被识别);§2.6 ProvNinja-Graph 改完图后预测 `3.69e-05`(漏报)→ evasion 成功 |

#### D. gadget_files/ 16 JSON(给 §2.6 ProvNinja-Graph)

- **路径**:`intrusion-detection-system/graph-based/gadget_files/`(16 个 JSON)
- **来源**:仓库自带。`gadget-chain.json` 是作者用 §2.1 gadget-finder 跑 + 人工筛选 + 转格式得到(转格式那段代码不在 repo,ship 的是 Linux `/usr/bin/...` 路径,跟 §2.1 用的 Windows freq DB 不同源);`<process>.json`(15 个)是从 benign 数据聚合"该进程通常读 / 写什么 / 连哪些 IP"得到。

- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 运行时查表(2 类字典) | `gadget-chain.json` 装着 `{"('/usr/bin/sudo', '/usr/bin/docker')": [["/usr/bin/sh", "/usr/bin/bash"], ...]}`;`bash.json` 装着 `{"files": [[["Read_Content","/etc/ld.so.cache"], 10], ...], "ips": [...]}` |
| **操作** | json.load → 字典查表 | evasion 主循环走到一条 PROC_CREATE 边 `sudo→docker`,`gadget_chains = gadget_dict[str(('/usr/bin/sudo', '/usr/bin/docker'))]` 拿到候选链。再决定插 bash 时 `json.load('gadget_files/bash.json')` 给 bash 节点配 `Read /etc/ld.so.cache` 等"伪装边" |
| **任务** | 选 chain + 配伪装边 | 把原图 `sudo →PROC_CREATE→ docker` 边换成 `sudo→sh→bash→docker`,再给 sh、bash 各连一堆"自然的"读文件 / 网络边 |

#### E. 自带预训模型(全部自带,不重训)

- **路径**:4 个模型文件:
  - `graph-based/models/gat_768_10_0.001_20_5_128_bidirection.bin` —— Prov-GAT 768 维 GAT(`gnnDriver.py:359`,`provninjaGraph.py:241-242` 加载,给 §2.5 Prov-GAT、§2.6 ProvNinja-Graph 用)
  - `graph-based/models/gat_5_10_0.001_20_5_128_bidirection.bin` —— S-GAT 5 维 GAT 纯结构(`gnnDriver.py:359` 加载,给 §2.4 S-GAT 用)
  - `path-based/models/enterprise_apt_autoencoder.h5` —— Autoencoder Keras `.h5`(`sigl.py:205` 加载,给 §2.2 SIGL 用)
  - `path-based/models/enterprise_apt_lof.pkl` —— LOF sklearn 0.24 训的 pickle(`provdetector.py:67` 加载,给 §2.3 ProvDetector 用)
- **来源**:论文作者自训后 ship 进 repo。`gnnDriver.py:336-357` 的训练 + `torch.save` 整段被注释,`sigl.py:286` 也把 `autoencoder.run`(从头训)注释掉、只留 `runWithModel`(load .h5)。**训练代码不在 repo,我们这边无法重训出同一份**。
- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | detector / autoencoder 的预训权重 | `gat_768_10_0.001_20_5_128_bidirection.bin` 是 torch state_dict,装 768 维 GAT 的 115231 个参数;`enterprise_apt_lof.pkl` 是 sklearn pickle 出来的 LOF estimator |
| **操作** | load 一次,只跑 forward / predict | `model = BinaryHeteroClassifier(...); model.load_state_dict(torch.load('models/gat_768_..._bidirection.bin'))` → `model.eval(); pred = model(graph, ...)`。`gnnDriver.py:336-357` 的 train 整段被注释,**没有重训路径** |
| **任务** | 给 detector 直接打分 | §2.5 跑出来 weighted F1=0.95,这个 0.95 完全是这个 .bin 决定的 |

#### F. HuggingFace `microsoft/codebert-base`(给 §2.6 ProvNinja-Graph)

- **路径**:HuggingFace model id `microsoft/codebert-base`(不在仓库里,运行时缓存到 `~/.cache/huggingface/hub/`,~480MB,第一次跑下完后离线可用)。
- **来源**:`provninjaGraph.py:22-23` 在 module 顶层(import 即触发)从 HuggingFace 网络下载。
- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 768 维字符串嵌入器 | 输入字符串 `"bash"` 或 `"/etc/passwd"`,输出 768 维 float32 向量 `[0.123, -0.456, ...]` |
| **操作** | from_pretrained 加载,每个新节点算一次 | evasion 决定插一个 bash 伪装节点 → `tokens = tokenizer.tokenize("bash"); ids = tokenizer.convert_tokens_to_ids(tokens); emb = model(torch.tensor(ids)[None,:])[0][0].sum(0)` 拿到 768 维向量,赋给新节点的 `EXE_NAME` 字段 |
| **任务** | 让新插入节点跟原图节点用同种嵌入 | §1.0.C 里原节点的 EXE_NAME 也是 768 维 codebert(以 base64 形式存盘),新节点直接拼进 dgl.heterograph 跑 GNN forward,GNN 不会因维度 / 嵌入空间不一致出错 |

---

### 2.0 组件分析

6 个脚本的输入 / 输出 / 作用一览:

```
脚本                          输入                                                                                                输出                                                                作用
────────────────────────────  ────────────────────────────────────────────────────────────────────────────────────────────────  ──────────────────────────────────────────────────────────────────  ─────────────────────────────────────────────────────────
①  gadget-finder.py           input.csv  [§1.0.A] —— (entry, target) 一行起止进程对(默认 winword→notepad)                          output.txt —— 99 条按"概率连乘 × 4^长度"排序的伪装链候选          在 freq_db 上 DFS 找从 entry 到 target 的
                              freq_db.csv [§1.0.A] —— 父→子进程频次表 543 行                                                                                                                          所有路径,每跳概率 > 0.003,按可信度排序

②  sigl.py                    benign-fv.csv  [§1.0.B] —— 15650 条 benign path 的 50 维 fv                                          stdout —— anomaly fv 一组 F1 + gadget fv 一组 F1                  用 Autoencoder 给 path fv 算重建误差,
                              anomaly-fv.csv [§1.0.B] —— 266 条原始攻击 path 的 50 维 fv                                                                                                              对比 anomaly fv vs gadget fv 看 evasion
                              gadget-fv.csv  [§1.0.B] —— 268 条 ProvNinja 改造后 path 的 50 维 fv                                                                                                      效果(F1 0.945 → 0.349)
                              autoencoder.h5 [§1.0.E] —— 训好的 Keras Autoencoder 架构 + 权重

③  provdetector.py            benign-fv.csv  [§1.0.B] —— 同 ②                                                                      stdout —— anomaly fv 一组 F1 + gadget fv 一组 F1                  同 ②,但用 LOF(密度异常)替代
                              anomaly-fv.csv [§1.0.B] —— 同 ②                                                                                                                                         Autoencoder(F1 0.885 → 0.213)
                              gadget-fv.csv  [§1.0.B] —— 同 ②
                              lof.pkl        [§1.0.E] —— sklearn 0.24 训好的 LOF estimator pickle

④  gnnDriver.py (S-GAT)       sample-supply-chain-data/   [§1.0.C] —— 4302 图(test 851 个),节点 5 维结构特征                       stdout —— test 851 图二分类的 weighted F1 = 0.88                  用 5 维结构特征 GNN(只看图拓扑,不看
                              gat_5_..._bidirection.bin   [§1.0.E] —— 训好的 S-GAT 5 维输入 GAT 权重                                                                                                  字符串语义)给整张图二分类 —— ⑤ 的
                                                                                                                                                                                                      ablation 基线

⑤  gnnDriver.py (Prov-GAT)    sample-supply-chain-data/   [§1.0.C] —— 同 ④,但节点 EXE_NAME 是 768 维 codebert                      stdout —— test 851 图二分类的 weighted F1 = 0.95                  用 768 维 codebert + 结构特征 GNN
                              gat_768_..._bidirection.bin [§1.0.E] —— 训好的 Prov-GAT 11.5 万参数 GAT 权重                                                                                            给整张图二分类 —— ⑥ 的攻击目标

⑥  provninjaGraph.py          sample-supply-chain-data/        [§1.0.C] —— 同 ⑤                                                    adversarial_examples/<图名>/                                      对每张被 ⑤ 抓住的 anomaly 图,
                              gat_768_..._bidirection.bin      [§1.0.E] —— 跟 ⑤ 共享同一份,它就是攻击目标                            original_graph.pkl + adversarial_graph.pkl                       REMOVE 原 PROC_CREATE 边 + 用 §1.0.D
                              gadget_files/gadget-chain.json   [§1.0.D] —— (src,tgt) → 候选伪装链字典                                 —— 每张被攻击图存原图 + 改造图各一份                              选 chain + 给新节点算 codebert 嵌入
                              gadget_files/<process>.json(×15) [§1.0.D] —— 每个伪装进程的"通常读/写/连什么"模板                                                                                        并配伪装边,改完再喂回 ⑤ 看能否漏报
                              microsoft/codebert-base          [§1.0.F] —— 768 维字符串嵌入器(给新插入节点用)                       stdout —— 改造后的 P/R/F1 + "evaded 168/198" 摘要                 (实测 168/198 成功)
```

**脚本之间的连接关系**(代码层面):

- **6 条运行路径在代码层面零数据流** —— 每个脚本独立 runner,各读各的输入、各写各的输出,没有谁把谁的输出当输入。
- **唯一的"配合"是文件层共享**:
  - ② / ③ 共享 **path-based 的 3 个 fv csv**(benign / anomaly / gadget,§1.0.B)
  - ④ / ⑤ / ⑥ 共享 **Supply-Chain APT 整个图目录**(§1.0.C)
  - **⑤ / ⑥ 共享同一个 Prov-GAT 768 维模型 `gat_768_..._bidirection.bin`**(§1.0.E)—— 最关键的共享:⑥ 改完图后喂回去打分用的就是 ⑤ 测出 weighted F1=0.95 的那个模型,evasion 数字 168/198 才有可比性
- **概念层面的攻击-检测对照**(② vs ③ 比 anomaly/gadget fv F1;⑤ vs ⑥ 比原图/改造图 recall)**不在代码自动连接里**,要靠人对比两组运行的输出数字才能看到。
- **① 是孤岛**:`output.txt` 在 upstream 没人读;⑥ 用的 `gadget-chain.json` 是仓库直接 ship 的固定文件,从 ① 输出转 JSON 那段代码不在 repo。

### 2.1 Gadget Finder

#### 1. 执行的命令

```bash
cd baselines/provninja/gadget-finder
python gadget-finder.py -i input.csv -p FrequencyDB/SAMPLE_WINDOWS_FREQUENCY_DB.csv -o output/gadgets.txt
```

#### 2. 输入和输出

- **输入**:
  - `input.csv` (§1.0.A) —— 单行 `entry,target`(默认 `winword.exe,notepad.exe`),指明伪装的起止进程对
  - `FrequencyDB/SAMPLE_WINDOWS_FREQUENCY_DB.csv` (§1.0.A) —— 543 行 `src,dst,count`,父→子进程频次表
- **输出**:
  - `output.txt` —— 99 条按可信度排序的伪装链,每行 `proc1 -> proc2 -> ... -> procN : score`

#### 3. 代码逻辑

`gadget-finder.py`(189 行)4 步:

1. **读 freq DB**(`line 124`,`pd.read_csv`)→ 3 列 DataFrame
2. **构造转移概率矩阵**(`get_transition_matrix`,`line 70-83`)
   - groupby src 算每个 src 的总 count
   - 每行 count / src 总 count → 概率(%)
   - pivot 成 src×dst 二维矩阵,缺失填 0
3. **DFS 从 entry 到 target**(`find_all_paths`,`line 43-67`)
   - 每跳查 `transition_matrix.loc[当前进程, 候选下一跳]`
   - 概率 > 阈值 0.003(`rare_edge`,`line 33-40`)才允许递归
   - 递归遍历所有路径
4. **打分排序**(`get_regularity_score`,`line 86-93`;`postprocessing_result`,`line 96-117`)
   - 路径原始分 = 路径上每跳概率连乘
   - `final_score = raw × 4^path_length`(指数奖励长链)
   - min-max 归一到 0-10 后按分降序写到 `output.txt`

#### 4. 作用

在 freq DB 这张图上,搜出从 entry 进程到 target 进程的所有"每跳都常见"的多步路径,作为伪装链候选。

它在 upstream 仓库里的真实角色 = **"§2.6 evasion 用的 `gadget-chain.json` 产生机制的可重复 demo"**:

```
完整生成流程(只一部分在 repo 里):
   freq DB                                            gadget-chain.json (§1.0.D)
       │                                                       ▲
       │  ① gadget-finder.py (本节,repo 里有)                 │
       ▼                                                       │
   output.txt ─── ② 转格式 + 人工筛选 (repo 里没这段代码) ─────┘
```

- **第 ① 步**(算法本身):repo 里跑得出 99 条候选 byte-identical with ship 的 sample,证明 DFS + 评分逻辑工作正常
- **第 ② 步**(转 JSON + 挑哪些 (src,tgt) 对 + 留哪些链):**代码不在 repo**
- **§2.6 用的 `gadget-chain.json`**:第 ① + ② 步走完后的成品,以 ship 文件形式保存(直接是 Linux `/usr/bin/...` 路径,所以跟 §2.1 用的 Windows freq DB **不同源**)

所以它 **≠ §2.6 evasion 的 live producer**,而是**让读者能复现"gadget-chain.json 怎么从频次数据生出来"算法部分**的演示工具。

#### 5. 复现结果

`output.txt` 共 99 条 gadget chain,score 从 1.00e+01 衰减到接近 0。与上游自带的 `gadget-finder/output/gadgets.txt` byte-for-byte 完全一致(`diff` 输出空)。

### 2.2 Path-based — SIGL

#### 1. 执行的命令

```bash
cd baselines/provninja/intrusion-detection-system/path-based
python sigl.py
```

#### 2. 输入和输出

- **输入**:
  - `sample-enterprise-data/benign-fv.csv` (§1.0.B) —— 15650 条 benign path 的 50 维 fv(用来定阈值)
  - `sample-enterprise-data/anomaly-fv.csv` (§1.0.B) —— 266 条原始攻击 path 的 50 维 fv
  - `sample-enterprise-data/gadget-fv.csv` (§1.0.B) —— 268 条 ProvNinja 改造后 path 的 50 维 fv
  - `models/enterprise_apt_autoencoder.h5` (§1.0.E) —— 训好的 Keras Autoencoder
- **输出**:
  - stdout —— 两组 P/R/F1(`Enterprise APT` = anomaly fv 跑;`Gadget Enterprise APT` = gadget fv 跑)

#### 3. 代码逻辑

`sigl.py`(295 行)主流程:

1. **加载 fv**(`line 56-57`):`pd.read_csv` 三组 fv → numpy 数组
2. **加载 autoencoder**(`line 205`):`load_model('models/enterprise_apt_autoencoder.h5')` 装预训权重
3. **算重建误差 + 打分**(AutoencoderUtils.evaluate):
   - `autoencoder.predict(x)` → 重建版本
   - `mse = mean((x - x_reconstructed)^2)` 沿样本维
   - `y_pred = (mse > threshold).astype(int)` —— 误差超阈值就判为 anomaly
4. **跑两次 + 输出指标**(`line 287-291`):
   - 第一次:anomaly fv → 对照 Enterprise APT
   - 第二次:gadget fv → 对照 Gadget Enterprise APT(被 ProvNinja 改造的)
   - 各自 `confusion_matrix → P/R/F1` 打印

注意:`autoencoder.run`(从头训)在 `line 286` 已被注释,默认只跑 `runWithModel`(load .h5)。

#### 4. 作用

**用 autoencoder 重建误差判断 path 是不是攻击**。重建得好(误差小)= 像 benign;重建得烂(误差大)= 像 anomaly。跑两次对比 anomaly fv vs gadget fv,看 ProvNinja 改造后的 path 能不能逃过 SIGL。

#### 5. 复现结果

| 数据集 | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Enterprise APT(原始 anomaly) | 0.944 | 0.921 | 0.970 | **0.945** |
| Gadget Enterprise APT(改造后) | 0.569 | 0.713 | 0.231 | **0.349** |

→ Evasion 把 F1 从 0.945 → 0.349,降幅 **−0.60**。SIGL 几乎抓不住改造后的 path。

---

### 2.3 Path-based — ProvDetector

#### 1. 执行的命令

```bash
cd baselines/provninja/intrusion-detection-system/path-based
python provdetector.py
```

#### 2. 输入和输出

- **输入**:
  - `sample-enterprise-data/benign-fv.csv` (§1.0.B) —— 同 §2.2(用来 sanity check)
  - `sample-enterprise-data/anomaly-fv.csv` (§1.0.B) —— 同 §2.2
  - `sample-enterprise-data/gadget-fv.csv` (§1.0.B) —— 同 §2.2
  - `models/enterprise_apt_lof.pkl` (§1.0.E) —— 训好的 sklearn LOF estimator
- **输出**:
  - stdout —— 两组 P/R/F1(同 §2.2 套路)

#### 3. 代码逻辑

`provdetector.py`(114 行)主流程:

1. **加载 fv**(`line 78-80`):`pd.read_csv` 三组 fv
2. **加载 LOF**(`line 67, 93`):`pickle.load(open('models/enterprise_apt_lof.pkl'))` 拿到训好的 estimator
3. **打分**:
   - `model.predict(df_anomaly)` → -1(outlier)/+1(inlier)
   - `model.predict(df_gadget)` → 同上
4. **算指标**(`printStat`,`line 33-46`):confusion_matrix → P/R/F1 打印

注意:训练那段(`fit_predict` + `save_model`)在 `line 86-90` 已被注释,默认只跑 load + predict。

#### 4. 作用

**用 LOF(密度异常)判断 path 是不是攻击**。LOF 在训练时学了 benign fv 的密度分布,测试 fv 跟 benign 邻居距离正常 → inlier;距离反常远 → outlier。跑两次对比 anomaly fv vs gadget fv,看 ProvNinja 改造后能否逃过。

⚠️ **caveat**:sklearn 1.7.2 反序列化 0.24.2 训的 LOF 触发 `InconsistentVersionWarning`,精确分数可能轻微受影响。

#### 5. 复现结果

| 数据集 | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Enterprise APT(原始 anomaly) | 0.793 | 1.000 | 0.793 | **0.885** |
| Gadget Enterprise APT(改造后) | 0.119 | 1.000 | 0.119 | **0.213** |

→ Evasion 把 F1 从 0.885 → 0.213,降幅 **−0.67**。

---

### 2.4 Graph-based — S-GAT

#### 1. 执行的命令

```bash
cd baselines/provninja/intrusion-detection-system/graph-based
python gnnDriver.py gat -if 5 -hf 10 -lr 0.001 -e 20 -n 5 -bs 128 -bi -s
```

参数:`-if 5` 输入维度 5,`-bi` 双向边,`-s` structural-only(只用图结构特征,不用字符串嵌入)。

#### 2. 输入和输出

- **输入**:
  - `sample-supply-chain-data/` (§1.0.C) —— 4302 图,其中 test 集 851 个(636 benign + 215 anomaly)
  - `models/gat_5_10_0.001_20_5_128_bidirection.bin` (§1.0.E) —— 训好的 S-GAT 5 维输入 GAT 权重
- **输出**:
  - stdout —— test 851 图的 P/R/F1 + confusion matrix

#### 3. 代码逻辑

`gnnDriver.py`(382 行)主流程:

1. **argparse**(`line 36-211`):解析 `gat -if 5 ... -s` 等命令行参数;`log_name = f"gat_{if}_{hf}_{lr}_{e}_{n}_{bs}{'_bidirection' if bi else ''}"` → `gat_5_10_0.001_20_5_128_bidirection`
2. **加载图数据集**(`get_binary_train_val_test_datasets`,`gnnUtils.py:37`):`os.scandir` 扫 `sample-supply-chain-data/{train,val,test}/{benign,anomaly}/` 的 4302 个目录,对每个目录 `BaseDataloader` 用 `read_csv` 读节点+边 + `pickle.load` 读 .pickle → 拼成 dgl.heterograph 列表
3. **建空模型架子**(`BinaryHeteroClassifier`,`gnnDriver.py:23-...`):8 种 relation × 5 维输入特征的异构 GAT
4. **加载权重**(`line 359-360`):`model.load_state_dict(torch.load(f'models/{log_name}.bin'))`,文件名严格依赖 argparse 参数
5. **eval 模式 + evaluate**(`evaluate_binary_graph_classification`):对 test 851 图逐个 forward,confusion_matrix → P/R/F1

`-s` flag 让节点不用字符串嵌入,只用 5 维结构特征(类型 one-hot + 度数等)。训练代码(`line 336-357`)整段被注释,只跑 evaluate。

#### 4. 作用

**用纯结构 GNN 给图二分类**(只看节点类型 + 图拓扑,不看字符串语义)。

它的角色 = **§2.5 Prov-GAT 的 ablation 基线**。同样的 GAT 架构,砍掉字符串嵌入,F1 从 §2.5 的 0.95 掉到 0.88 → 证明 768 维 codebert 嵌入贡献了 +0.07 F1。

#### 5. 复现结果

测试集:851 个图(636 benign + 215 anomaly),总参数量 8426。

| 类别 | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Benign | 0.99 | 0.83 | 0.91 | 636 |
| Anomaly | 0.67 | 0.99 | 0.80 | 215 |
| **weighted avg** | **0.91** | **0.87** | **0.88** | 851 |

混淆矩阵 `[[530, 106], [3, 212]]`,accuracy 0.872。

→ weighted F1 = **0.88**,跟 README 声称的 0.88 精确吻合。

---

### 2.5 Graph-based — Prov-GAT

#### 1. 执行的命令

```bash
cd baselines/provninja/intrusion-detection-system/graph-based
python gnnDriver.py gat -if 768 -hf 10 -lr 0.001 -e 20 -n 5 -bs 128 -bi
```

参数:`-if 768` 输入维度 768,`-bi` 双向,**没有 `-s`**(用字符串嵌入)。

#### 2. 输入和输出

- **输入**:
  - `sample-supply-chain-data/` (§1.0.C) —— 同 §2.4,但节点 EXE_NAME / FILENAME / IP 字段是 768 维 codebert 嵌入(b64 解码后)
  - `models/gat_768_10_0.001_20_5_128_bidirection.bin` (§1.0.E) —— 训好的 Prov-GAT 768 维 GAT 权重(11.5 万参数)
- **输出**:
  - stdout —— test 851 图的 P/R/F1 + confusion matrix

#### 3. 代码逻辑

跟 §2.4 共用同一份 `gnnDriver.py`,只是 argparse 参数不同导致两点变化:

1. **没有 `-s`** → 节点特征不只是 5 维结构,还包括从 b64 解码出的 768 维 codebert 嵌入(`feature_aggregation_function`,`gnnDriver.py:188`)
2. **`-if 768`** → `log_name = "gat_768_10_0.001_20_5_128_bidirection"` → 加载 `gat_768_..._bidirection.bin`

其他流程同 §2.4:加载 dgl.heterograph 列表 → load_state_dict → eval → evaluate_binary_graph_classification。

#### 4. 作用

**用结构 + 字符串语义混合 GNN 给图二分类**。是 ProvNinja 论文的最强 detector 基线。

它的角色:**§2.6 evasion 攻击的目标** —— §2.6 改完图后喂回去打分用的就是这个模型,所以 evasion 数字 168/198 才有可比性(攻同一个 .bin 数字才说明问题)。

#### 5. 复现结果

测试集:851 个图(636 benign + 215 anomaly),总参数量 115231。

| 类别 | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Benign | 0.97 | 0.96 | 0.97 | 636 |
| Anomaly | 0.90 | 0.92 | 0.91 | 215 |
| **weighted avg** | **0.95** | **0.95** | **0.95** | 851 |

混淆矩阵 `[[613, 23], [17, 198]]`,accuracy 0.953。

→ weighted F1 = **0.95**,跟 README 声称的 0.95 精确吻合。

---

### 2.6 Graph-based — ProvNinja-Graph(adversarial evasion)

#### 1. 执行的命令

```bash
cd baselines/provninja/intrusion-detection-system/graph-based
python provninjaGraph.py
```

#### 2. 输入和输出

- **输入**:
  - `sample-supply-chain-data/` (§1.0.C) —— 同 §2.5
  - `models/gat_768_10_0.001_20_5_128_bidirection.bin` (§1.0.E) —— 跟 §2.5 共享同一份,作为攻击目标
  - `gadget_files/gadget-chain.json` (§1.0.D) —— (src,tgt) 进程对 → 候选伪装链字典
  - `gadget_files/<process>.json` × 15 (§1.0.D) —— 每个伪装进程的"通常读/写/连什么"边模板
  - `microsoft/codebert-base` (§1.0.F) —— 768 维字符串嵌入器,给新插入节点算 EXE_NAME
- **输出**:
  - `adversarial_examples/<图名>/{original,adversarial}_graph.pkl` —— 每张被攻击图存原图 + 改造图各一份
  - stdout —— 改造后整体 P/R/F1 + "Detection evaded for X / Y true positive samples"

#### 3. 代码逻辑

`provninjaGraph.py`(558 行)主流程:

1. **import 时下载 codebert**(`line 22-23`):`AutoTokenizer / AutoModel.from_pretrained("microsoft/codebert-base")` → 第一次跑联网下 ~480MB
2. **加载 gadget-chain.json**(`line 161-162`):全局字典 `{ "(src,tgt)": [候选链, ...] }`
3. **加载图数据集 + Prov-GAT 模型**(同 §2.5 的流程,共用 `gnnUtils` + `BaseDataloader`)
4. **跑 baseline**(`line 520-538`):对 test 851 图逐个 `model(graph)`,挑出 198 个被抓住的 anomaly 图作为攻击对象
5. **对每张被抓的图调用 `provninja_attack`**(`line 284-513`):
   - 遍历图里每条 PROC_CREATE 边 (`(src→dst)`),对每条边 try:
     - 查 `gadget_chains = gadget_dict[str((src_name, dst_name))]` 拿候选链
     - 对每条候选链 `["sh", "bash", ...]` 试一次:
       - **REMOVE** 原 PROC_CREATE 边 + 中间节点(`remove_node`)
       - **INSERT** 链上每个新节点(`add_process_node`):每个新进程名调 codebert 算 768 维嵌入,塞进 EXE_NAME
       - **CAMOUFLAGE**:`json.load('gadget_files/<process>.json')` 拿伪装边模板,给新节点 `apply_camoflauge` 配上 read 文件 / connect IP 等真实读写边
     - 改完图 `model(改图)` → 看新预测分能否 < 阈值 0.5
     - 任一候选链成功 → 记一次 evasion + break
6. **统计**(`line 540-557`):成功 evasion 数 / 攻击对象数 → 168/198,加上整体 P/R/F1 打印

#### 4. 作用

**ProvNinja 论文的核心 evasion 攻击算法**。把"REMOVE 原 PROC_CREATE 边 + REPLACE 成多步 chain + 给中间节点配伪装边"这套机制实现出来,在 §2.5 同一个 Prov-GAT 上验证 evasion 效果。

#### 5. 复现结果

完整跑完 198 个被 §2.5 抓住的 anomaly 图:

| 指标 | 数值 |
|---|---|
| 攻击对象 | 198 个 anomaly 图 |
| Evasion 成功 | **168 / 198**(85%) |
| 改造后 Precision | 0.671 |
| 改造后 Recall | 0.219 |
| 改造后 F1 | 0.330 |

→ **168/198 evasion**,跟 README 声称的 ~168/198 精确吻合。anomaly recall 从 §2.5 的 0.92 被打到 0.22。

---




