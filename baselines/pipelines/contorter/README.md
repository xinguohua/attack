# Contorter — 复现

本文档记录 `baselines/contorter/` 这份上游 `focusResearchLab/Contorter` 忠实复刻在它自带 sample 数据上的复现 + 代码分析。

---

## 1. 原始代码的复现和分析

代码位置:`baselines/contorter/`(上游 `focusResearchLab/Contorter` 的 pristine clone,HEAD `035f0247`)。

运行环境:统一用 conda env `mimicattack`(Python 3.10.20,`torch 2.1.0` / `torch_geometric 2.7.0` / `scikit-learn 1.7.2` / `gdown 6.0.0` / `gensim 4.3.3` / `pandas 2.3.3` / `numpy 1.24.3`,跟上游 `requirements.txt` 略有版本差,实测兼容)。**§2.x 所有命令运行前先激活 env**:

```bash
conda activate mimicattack
```

上游仓库结构:**4 个 PIDS 子目录 × 多个数据集**(每个 PIDS-数据集组合一个 `*_Contorter.ipynb` 自包含 notebook)。

```
contorter/
├── Flash/         (4 datasets: Cadets / Theia / Trace / OpTC)
├── ThreaTrace/    (4 datasets: Cadets / Theia / Trace / OpTC × 3 variants)
├── NodLink/       (1 dataset: Cadets,带 download.ipynb + models_train.ipynb)
└── Magic/         (placeholder,只有 README,无代码)
```

`Magic/` 是空 placeholder(README 里 `Workflow Overview` 字段全空),**本文档 §2 不覆盖**。

**本仓库实跑范围(per project decision: 仅以 NodLink/Cadets 为主复现入口)**:

| PIDS-数据集 | 数据状态 | 实跑状态 |
|---|---|---|
| **NodLink/Cadets** | 完整(`dependancies/` 30 项) | ✅ **主复现**(§2.2.5,R 1.0 → 0.33,evasion 有效) |
| Flash/Theia | 完整 | ⏭️ 已下不算入(§2.1.5 留作反向失效记录,baseline R 99.76% 已饱和、改后反升 0.07pp) |
| Flash/Cadets / Trace / OpTC | raw 已下,GCN/W2V 已下 | ⏭️ 已下不跑 |
| ThreaTrace × 4 datasets(含 OpTC × 3 变种) | **Drive 全 404** | ❌ 不跑(§2.3.5 数据列留空) |
| Magic | 上游空 placeholder | — 不覆盖 |

### 1.0 代码依赖的输入数据和模型

这一节是上游代码运行时从外部 read/load 的所有资源清单 —— 数据集、查表 JSON、预训模型,以及网络下载的预训模型,统称"输入"。给 §2.1-§2.4 兜底。代码自己产出的缓存 / 中间文件不算。

#### A. DARPA TC 处理后子集 + ground truth(给 §2.1 / §2.2 / §2.3)

- **路径**:每个 notebook 第一次运行时通过 `gdown.download_folder()` 拉到 notebook 所在目录的子文件夹(典型为 `<dataset>_resources/`),并把 ground truth 拉到 `groundtruth/<dataset>/`
- **来源**:作者放在 Google Drive 的 sample 数据(每个 PIDS-数据集组合一个 folder,文件夹 ID 写死在 notebook 里):
  - Flash: `1IdWTDMxo88_ysUo1oNEbze63M8914_rD` 之类的 file IDs,raw json 日志
  - ThreaTrace: `1e7vCDnqk42N2CZzrtNVwWWF1OlShL54X`(GT)+ `1SRgE1BZEdAqkfA7yZ_xrABwqXsd0mQHk`(features)+ `1h8pTHuXGvtfmNJkw3yNPEJPgXrm9bZUg`(models)
  - NodLink: 单独 `download.ipynb` 拉所有依赖(数据 + 模型 + utils)到 `dependencies/`
- **配套输入**:每个数据集自带的 `for_<dataset>.pkl`(预处理好的 6-tuple `(df, phrases, labels, edges, mapp, NODES, all_ids, GT_mal, indices_of_malicious_nodes)`),notebook 用 `pickle.load(...)` 读
- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 攻击图 + 节点级 ground truth(谁是恶意节点)| Flash/Theia: gdown 拉 1.5GB `flash_theia_data.bin` (实为 `ta1-theia-e3-official-6r.json.tar.gz`),解压出 13 个 raw JSON,Ground_Truth_mal 25359 entries |
| **操作** | `gdown` 下载 → tar 解 → 处理为 dataframe → 根据 GT 找 attack 节点 | NodLink: `df, phrases, labels = pickle.load(...)` 解出 `for_<dataset>.pkl`(ThreaTrace 同款,但本仓库未实跑) |
| **任务** | baseline detection + Contorter evasion 的输入图 | Flash/Theia 本仓库实跑:25359 攻击节点,baseline 检出 25297,recall = 0.998(§2.1.5) |

#### B. 预训 detector 模型(给 §2.1 / §2.2 / §2.3)

- **路径**:每个 PIDS-数据集组合配自家预训 detector,notebook 内通过 gdown 下载到 `<repo>/models/<dataset>/`
  - **Flash**:`models/<dataset>/`下 22 个 GCN ensemble `.pth` —— `gnn_<i>.pth`(`i=1..22`),notebook 加载后做 ensemble inference
  - **ThreaTrace**:`models/<dataset>/<dataset>_model_weights.pth`(单个 SAGENet 权重),`feature.txt` + `label.txt`(节点类型 / 标签词表)
  - **NodLink**:`AE.model`(VAE 模型),阈值 cutoff = 130
- **来源**:论文作者 ship 的预训模型,跟原 PIDS 论文 (FLASH / MAGIC / NodLink / ThreaTrace) 复用同一组权重
- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 4 个目标 PIDS 的预训 detector,Contorter 攻击对象 | Flash 22-GCN ensemble(每个权重 11KB);ThreaTrace SAGENet(SAGEConv + linear,36 维输入 + 5 类输出);NodLink VAE(`AE.model`,cutoff=130) |
| **操作** | `model.load_state_dict(torch.load(.pth))` → `model.eval()` → 在测试图上 forward | NodLink:`vae(x_tensor)` 输出 reconstruction → 跟 cutoff=130 比较 → 阈值化为 anomaly 标签 |
| **任务** | 算 baseline R/F1 (evasion 前)+ 改造图上重新算 R/F1(evasion 后)| 本仓库实跑:Flash/Theia R 1.0 → 1.0(evasion 无效,§2.1.5);NodLink/Cadets R 1.0 → 0.33(evasion 有效,§2.2.5);ThreaTrace 4 数据集数据 Drive 404,本仓库未跑 |

#### C. 字符串 / 路径嵌入器(给 §2.1 Flash / §2.2 NodLink)

- **路径**:notebook 第一次运行时下载或现训
  - **Flash** 用 **Word2Vec + Positional Encoder** 生成 30 维节点 embedding,模型在 notebook 内加载预训权重(从 Google Drive)
  - **NodLink** 用 **FastText**(`gensim.models.fasttext.load_facebook_model`)给 process / file path 算嵌入,加 TF-IDF + Stability Norm 加权
- **来源**:Flash 的 Word2Vec + GCN ensemble 跟 FLASH (S&P'24) 同源;NodLink 的 FastText 跟 NodLink (arXiv'23) 同源,作者 ship 进 dependencies
- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | 给 Contorter 的 CSMax 步算 cosine similarity 用的节点向量化器 | Flash/Theia:30 维 Word2Vec embedding;NodLink:`load_facebook_model(...).get_sentence_vector("process /usr/bin/sudo")` 返回 100 维 |
| **操作** | `.bin` / `.model` 文件 load → encode_node(name) → 向量 | `fasttext_model.get_sentence_vector(path)` 返回 100-d numpy array |
| **任务** | 找跟 attack node 上下文最相似的 benign 候选(CSMax 第 3 步)| ThreaTrace/Theia 选 top-10 cosine 相似 benign 节点配对每个 attack 节点 |

#### D. 各 PIDS-数据集组合的 utility 模块(给 §2.3 ThreaTrace / §2.2 NodLink)

- **路径**:
  - `ThreaTrace/<dataset>/utils_<dataset>/`(`Cadets` / `Theia` / `Trace` / `OpTC`)—— 每个目录里有 `data_process_train.py` / `data_process_test.py` / `evaluate_<dataset>.py` 等
  - `NodLink/Cadets/utils/` —— VAE 模型类、辅助 process/file embedding 函数
- **来源**:从原 PIDS 仓库(`threaTrace-detector/threaTrace`、`PKU-ASAL/Simulated-Data`)修改而来的本地副本
- **作用**:

| 层次 | 内容 | 例子 |
|---|---|---|
| **角色** | notebook import 的支持模块 | `from utils_theia.data_process_test import MyDatasetA, TestDatasetA` |
| **操作** | `MyDatasetA(path, 'theia')` 把 csv 转成 `torch_geometric.data.Data`,`evaluate_<dataset>` 算 P/R/F1 | `data, feature_num, label_num, adj, adj2, nodeA = MyDatasetA(path, 'theia')` |
| **任务** | 解耦数据集解析 / 评测代码,让 notebook 的 main flow 干净 | utils_theia 解出 36 维 feature + 5 个 label class |

### 2.0 组件分析

3 个 PIDS family 的 notebook 输入 / 输出 / 作用一览(**Magic 略**,placeholder 无代码):

```
Notebook                                            输入                                                                              输出                                            作用
①  Flash/<dataset>/Flash_<dataset>_Contorter.ipynb  raw JSON 日志 [§1.0.A]                                                            stdout —— baseline P/R/F1 + 改后 P/R/F1     在 Flash GCN ensemble (22 GCN) 上跑 Contorter
   (4 datasets: Cadets / Theia / Trace / OpTC)      Flash 22-GCN ensemble [§1.0.B]                                                                                                    evasion(节点级,30 维 W2V embed)
                                                    Word2Vec + Positional Encoder [§1.0.C]
②  ThreaTrace/<dataset>/Threatrace_<dataset>_       for_<dataset>.pkl + GT [§1.0.A]                                                   stdout —— baseline P/R/F1 + 改后 P/R/F1     在 ThreaTrace SAGENet 上跑 Contorter
   Contorter.ipynb (4 datasets,OpTC 含 3 variants) ThreaTrace SAGENet 权重 [§1.0.B]                                                                                                  evasion(节点级,36 维 type embed)
                                                    utils_<dataset>/ [§1.0.D]
③  NodLink/Cadets/NodLink_Cadets_Contorter.ipynb    process-event txt [§1.0.A]                                                       stdout —— baseline R + 改后 R                   在 NodLink VAE 上跑 Contorter
                                                    NodLink VAE (AE.model) [§1.0.B]                                                                                                  evasion(进程级,FastText embed)
                                                    FastText embedding [§1.0.C]
                                                    utils/ [§1.0.D]
   NodLink/Cadets/download.ipynb                    Google Drive folder ID                                                            dependencies/ 目录                              一次性把 NodLink 所需所有数据 + 模型拉下来
   NodLink/Cadets/models_train.ipynb                process-event txt [§1.0.A]                                                        AE.model + FastText weights                     从头训 NodLink VAE + FastText
                                                    raw process logs
```

**脚本之间的连接关系**(代码层面):

- **三个 PIDS family 的 notebook 在代码层面零数据流** —— 每个 `*_Contorter.ipynb` 是独立 runner,各自下载自己的数据 / 模型,各写各的输出,没有谁把谁的输出当输入
- **唯一的"配合"是文件层共享**:
  - 同一 PIDS 在不同数据集上的 notebook **共享同一个 detector 架构定义**(SAGENet 类、VAE 类、Flash GCN 类),但 weights 各自一份
  - **NodLink 的 `download.ipynb` 必须在 `NodLink_Cadets_Contorter.ipynb` 之前跑**(它准备 `dependencies/` 目录),其他 PIDS 的 notebook 自带 download cell,没这个依赖
  - `models_train.ipynb` 是 NodLink VAE 从头训的可选 alternative;主流程默认用 ship 的 `AE.model`,`models_train.ipynb` **在主流程里不被引用**
- **概念层面的攻击-检测对照**(Contorter 7 步 evasion vs 4 个 PIDS 的 detection 反应)**不在代码自动连接里**,要靠人对比同一 PIDS 在不同数据集 / 不同 PIDS 之间的 baseline-vs-改后数字才能看到
- **Magic/ 是孤岛 placeholder**,README 字段全空,没代码可跑

### 2.1 Flash family — 在 22-GCN ensemble 上的 Contorter evasion

#### 1. 执行的命令

```bash
cd baselines/contorter/Flash/<dataset>           # dataset ∈ {Cadets, Theia, Trace, OpTC}
jupyter nbconvert --to notebook --execute Flash_<dataset>_Contorter.ipynb --inplace
# 或 Jupyter 里逐 cell 跑
```

#### 2. 输入和输出

- **输入**:
  - raw JSON 日志(§1.0.A)—— gdown 下载到当前目录子文件夹
  - 22-GCN ensemble `.pth` × 22(§1.0.B)—— gdown 下载到 `models/<dataset>/`
  - Word2Vec + Positional Encoder(§1.0.C)—— 同 GCN ensemble 一起下
- **输出**:
  - stdout —— baseline (evasion 前) P/R/F1 + 改后 (evasion 后) P/R/F1
  - 中间产物 —— 改造后的 `<dataset>_test_curated.txt`、`processed/` 缓存

#### 3. 代码逻辑

`Flash_<dataset>_Contorter.ipynb`(34 cells)主流程,以 Theia 为例:

1. **下载 + 预处理**(`cell 4-12`):`gdown.download_folder(...)` 拉 raw JSON → `cell 7-10` 用 FLASH 上游的 parser 解 UUID / node type / edge / attribute → 整成 dataframe + edge index
2. **特征化**(`cell 11-14`):用 Word2Vec + Positional Encoder 把节点交互(读 / 写 / 执行 / 连接)编成 30 维 vector,组成 `Data(x, y, edge_index)` 的 PyG 格式
3. **baseline 评测**(`cell 19-22`):加载 22 个 GCN 权重 → ensemble inference → `printStat` 算 P/R/F1
4. **Contorter 7 步 evasion**(`cell 23-31`):
   - **TypeSel + FOpt**(cell 23-25):按 label 分组 benign 节点 + 过滤交互数 [FMin, FMax] 之间的
   - **CSMax**(cell 26-27):用 W2V embedding 算 cosine similarity,选 top-similar benign 候选
   - **ImpMax**(cell 28-29,**仅 Cadets / Trace**):跑 GCN ensemble 测每个 candidate 被预测为 benign 的置信度,选最高的
   - **Gadget Insertion**(cell 30):把 selected benign 节点的边复制到 attack 节点,形成"接的更像 benign"的图
   - **OccVer**(cell 31):drop_duplicates 看是否引入了原图里不存在的边
5. **再评测**(`cell 32-33`):同 Step 3 流程,在改后图上重新跑 GCN ensemble

注意:Flash 的 4 个 notebook 都没存输出 cell(原作者 commit 前清掉了),所以本地必须实际跑过才有 §2.x.5 数字。

#### 4. 作用

**针对 Flash PIDS(GCN ensemble)的 Contorter 节点级 evasion**。把 attack node 的边 footprint 改造成最像某个 benign node(based on Word2Vec context similarity),让 22-GCN ensemble vote 把 attack 误判为 benign。

它在 upstream 仓库里的角色 = **Contorter 评估 PIDS 之一(Flash 是 4 个之一)**,4 个数据集 × 1 个 PIDS = 4 个 notebook,跑下来看 Contorter 在 Flash 上对不同 DARPA TC engagement 的 evasion 效果差异。

#### 5. 复现结果

**本地 `mimicattack` env 实测 Theia**(本项目决定每方法只跑一个数据集,Theia 数据已解 + 22 GCN 全到位,其余 3 个仅下载 raw,未实跑):

| Dataset | 阶段 | TP | TN | FP | FN | Precision | Recall(精确) | F1 |
|---|---|---|---|---|---|---|---|---|
| **Theia** | baseline | 25297 | 307983 | 11424 | 62 | 0.6889 | **0.99756** | 0.8156 |
| **Theia** | 改后 | 25315 | 308002 | 11423 | 44 | 0.6890 | **0.99826** | 0.8158 |
| Cadets | baseline / 改后 | (raw 已下,未实跑)| | | | | | |
| Trace  | baseline / 改后 | (raw 已下,未实跑)| | | | | | |
| OpTC   | baseline / 改后 | (raw 已下,未实跑)| | | | | | |

**evasion 真改了图**(cell 31 print):17 万条新边加入,`df_curated` 9.6M 行 vs `df` 9.4M 行;25319 个攻击节点全部被 graph_modification 处理。FOpt 候选数充足(Label 0/2/3 各 1226/10223/6540 候选 benign)。

**Recall 反而上升 0.0007**:18 个原本被 GCN 自信分对的 attack 节点(算 FN)被推到"不自信"区(算 TP),FN 从 62 → 44。

→ 关键洞察:Flash 的 flag 逻辑不是 "predict as anomaly",而是 **"20 个 GCN 都没能自信归对类"**(`flag` 初值 True,只有当某个 GCN `pred==y AND conf>0.53` 时才清掉 flag)。Contorter 把 benign 边复制给 attack 节点 → W2V 节点 embedding 漂移 → GCN 分类自信度**下降** → flag 留得更多 → **更多 attack 被 detect**。这是**反向自杀式失效** —— 不是 evasion 不够强,是算法设计跟 Flash 的检测机制方向相反。

注:论文 Table 5 报告的 "Flash 平均 evasion drop" 我们无法在 Theia 上复现到。可能 Cadets/Trace/OpTC 上结果不同(待跑),或者论文的平均值掩盖了数据集间差异。

实跑过程中需要的 patches:
- `gdown.download(..., fuzzy=True)` 在 gdown 6.0.0 中不支持 → 用 `_patch_nbs.py` 把这调用替换成"文件已存在则 skip"的 no-op(raw `.tar.gz` 已通过我们自己的 driver 下到位)
- gdown 下来的 sample 文件名是 `flash_theia_data.bin`,但 notebook `os.system('tar -zxvf ta1-theia-e3-official-6r.json.tar.gz')` 期望规范名 → 重命名 `mv flash_theia_data.bin ta1-theia-e3-official-6r.json.tar.gz` 后才能解
- 第一次跑 wall clock ~58 min(tar 解压 + 90M 行 regex 抽节点 + 7M 行 pandas merge + 22 GCN ensemble forward),瓶颈是 Python 单线程的 JSON parse + DataFrame.merge,不是 GCN;复跑用缓存的 `theia_test.txt` + `.json.8` 可缩到 ~10 min

---

### 2.2 NodLink family — 在 VAE 上的 Contorter evasion

#### 1. 执行的命令

```bash
cd baselines/contorter/NodLink/Cadets
# 第一次:跑 download.ipynb 拉 dependencies/
jupyter nbconvert --to notebook --execute download.ipynb --inplace
# 主流程:
jupyter nbconvert --to notebook --execute NodLink_Cadets_Contorter.ipynb --inplace
# (可选,从头训而不是用 ship 的 AE.model)
jupyter nbconvert --to notebook --execute models_train.ipynb --inplace
```

#### 2. 输入和输出

- **输入**:
  - process-event 文本(§1.0.A,在 `dependencies/` 里,benign + anomaly 各一份 txt)
  - VAE 预训模型 `AE.model`(§1.0.B)
  - FastText 嵌入器(§1.0.C)
  - utils/(§1.0.D)
- **输出**:
  - stdout —— baseline R + 改后 R(在 cutoff=130 上)
  - 中间产物 —— `process-event-benign.txt` / `process-event-anomaly.txt` / `final-augmented-malicious-processes.txt`

#### 3. 代码逻辑

`NodLink_Cadets_Contorter.ipynb`(28 cells)主流程:

1. **数据载入**(`cell 2-4`):读 benign/anomaly dataframe,过滤出 ground truth 的 15 个 malicious process UUID(notebook 注释:三个原本 GT 中的 attack process 因为没记录到任何交互被人工排除)
2. **process-event txt 生成**(`cell 5-8`):每个进程映射到它的 file path 集合,写成 `process-event-{benign,anomaly}.txt`
3. **embedding**(`cell 9-11`):FastText 加载 + TF-IDF 加权 + Stability Norm
4. **baseline 评测**(`cell 12-15`):VAE forward + reconstruction loss → `cutoff=130` 阈值化 → 输出 R/F1。Notebook 存 cell 15 输出:**TP=15, FP=17, FN=0, TN=28590, Precision=0.4688, Recall=1.0000, F1=0.6383**
5. **Contorter evasion**(`cell 16-24`):
   - cell 17:Group benign by labels(进程类型 / 命令行)
   - cell 19:FOpt 过滤 [FMin, FMax] 内的
   - cell 21:CSMax 用 FastText cosine 选 top-10% similar
   - cell 23:ImpMax,run VAE 在 candidates 上 → 选 reconstruction loss 最低的
6. **改后再评测**(`cell 25-27`):重组 augmented txt → re-run VAE → 输出新 R(notebook 没存这个 cell 输出)

注意:`models_train.ipynb` 是 alternative 训练 entry,**主流程不依赖它**(用 ship 的 `AE.model`)。`download.ipynb` 是必跑前置依赖。

#### 4. 作用

**针对 NodLink PIDS(VAE)的 Contorter 进程级 evasion**。NodLink 是 process-level detector,Contorter 把 attack process 的 file-path footprint 改造成最像某个 benign process(by FastText similarity + lowest VAE reconstruction loss)。

它在 upstream 仓库里的角色 = **Contorter 评估 4 个 PIDS 之一**(只有 Cadets 一个数据集,因为 NodLink 上游只支持 Cadets)。

#### 5. 复现结果

**本地 `mimicattack` env 实测**(`jupyter nbconvert --execute NodLink_Cadets_Contorter.run.ipynb`,28 cells 全跑,0 errors):

| 阶段 | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| baseline (cutoff=130) | 15 | 19 | 0 | 27517 | 0.4412 | **1.0000** | 0.6122 |
| Contorter 改后 | 5 | 24 | **10** | 27512 | 0.1724 | **0.3333** | 0.2273 |

→ **Contorter evasion 在 NodLink/Cadets 上: Recall 1.0 → 0.33 = -67%**。15 个 attack process,10 个被 Contorter 改造后成功 evade VAE,只剩 5 个仍被检测到。FP/TN 数字会在 sampling 上略有抖动(benign 集合 ~27.5K),但 TP/FN 在两次重跑里完全一致。

实跑过程中需要的 patches(为了在 mimicattack env / Mac CPU 上跑通):
- 注释掉 `from scipy.sparse.construct import random` 死 import(scipy 1.13+ 已移除该 namespace)
- `utils/model.py` 里 `.cuda()` → `.to("cuda" if torch.cuda.is_available() else "cpu")`(Mac 无 CUDA)
- `torch.load(...)` 加 `map_location='cpu'`(模型在 CUDA 上保存,跨 device 加载需显式)
- 通过 curl + Drive 二次确认 token 替代 gdown 拉 9 个被 Drive 限流的文件

---

### 2.3 ThreaTrace family — 在 SAGENet 上的 Contorter evasion

#### 1. 执行的命令

```bash
cd baselines/contorter/ThreaTrace/<dataset>      # dataset ∈ {Cadets, Theia, Trace, OpTC}
jupyter nbconvert --to notebook --execute Threatrace_<dataset>_Contorter.ipynb --inplace
# OpTC 有 3 个变种:
jupyter nbconvert --to notebook --execute Threatrace_optc_plain_powershell.ipynb --inplace
jupyter nbconvert --to notebook --execute Threatrace_optc_custom_powershell.ipynb --inplace
jupyter nbconvert --to notebook --execute Threatrace_optc_malicious_upgrade.ipynb --inplace
```

#### 2. 输入和输出

- **输入**:
  - `for_<dataset>.pkl`(§1.0.A)—— `pickle.load` 解出 9-tuple `(df, phrases, labels, edges, mapp, NODES, all_ids, GT_mal, indices_of_malicious_nodes)`
  - SAGENet 权重 `<dataset>_model_weights.pth`(§1.0.B)—— `model.load_state_dict(torch.load(...))`
  - utils_<dataset>/(§1.0.D)—— `MyDatasetA` / `TestDatasetA` / `evaluate_<dataset>` 等
- **输出**:
  - stdout —— baseline P/R/F1 + 改后 P/R/F1(在 thre=1.5 阈值)
  - 中间产物 —— `<dataset>_test_curated.txt`(改造后的图作为下次评测输入)

#### 3. 代码逻辑

`Threatrace_<dataset>_Contorter.ipynb`(36 cells)主流程,以 Theia 为例:

1. **import + 模型类**(`cell 0-4`):`SAGENet = SAGEConv(in_ch, 32) → SAGEConv(32, out_ch)`,2 层 GraphSAGE
2. **下载数据 + GT + 模型**(`cell 5-10`):`gdown` 拉 3 个 Google Drive folder
3. **加载测试数据 + baseline 评测**(`cell 11-17`):pickle.load `for_theia.pkl` → `MyDatasetA` 解成 PyG `Data` → SAGENet forward → `test_one_model` 算 P/R/F1
4. **Contorter evasion**(`cell 19-31`):
   - cell 23:`split_malicious_nodes_by_label` —— 把 attack node 按 label 分组
   - cell 25:`split_nodes_by_label_exclude_malicious` —— benign 节点按 label 分组
   - cell 27:`filter_nodes_by_phrase_length(min_len=5, max_len=20)` —— FOpt
   - cell 29:`compute_top_similar_nodes` —— CSMax(基于 phrase context 的 cosine similarity)
   - cell 31:`graph_modification` —— Gadget Insertion(把 selected benign 的边 copy 给 attack node)
5. **改后再评测**(`cell 32-35`):curated txt → MyDatasetA → SAGENet forward → 算 P/R/F1

OpTC 的 3 个变种(custom_powershell / plain_powershell / malicious_upgrade)对应 OpTC 不同 attack 子集,代码结构跟 Cadets/Theia/Trace 一致。

#### 4. 作用

**针对 ThreaTrace PIDS(SAGENet,GraphSAGE 节点分类)的 Contorter 节点级 evasion**。SAGENet 通过 K-hop 邻居聚合判定节点恶意度,Contorter 把 attack node 的 1-hop 邻居改造成跟某 benign node 邻居最相似(by phrase / context cosine),让 SAGENet 把 attack 节点 embedding 推到 benign manifold 内。

它在 upstream 仓库里的角色 = **Contorter 评估 4 个 PIDS 中数据集覆盖最广的(4 datasets,OpTC 含 3 子变种,共 6 个 notebook)**,数据点最多。

#### 5. 复现结果

ThreaTrace 4 数据集 + OpTC 3 变种总共 34 个 Drive folder/file ID **全部 HTTP 404**(2026-05 链路探测,改 UA 无效)—— contorter 上游已下架/转私有。

| Dataset | 阶段 | 状态 |
|---|---|---|
| Theia | baseline / 改后 | (数据 Drive 404,无法实跑) |
| Trace | baseline / 改后 | (数据 Drive 404,无法实跑) |
| Cadets | baseline / 改后 | (数据 Drive 404,无法实跑) |
| OpTC × 3 | baseline / 改后 | (数据 Drive 404,无法实跑) |

→ 本仓库**无 ThreaTrace family 复现数字**。后续若要跑只能(a)联系 contorter 作者要新链接,或(b)绕开 contorter sample,直接走 ThreaTrace 上游 (`threaTrace-detector/threaTrace`) 自己重训 + 准备 `for_<dataset>.pkl`。

---

### 2.4 关于 Magic/

`Magic/` 目录在上游 commit 时是 **placeholder** —— `README.md` 的 `Workflow Overview` 字段全空,目录里没任何 `.ipynb` 或 `.py`。论文 §6 报告 Contorter 在 Magic (USENIX Security'24) 上的实验结果,但**实现代码未 ship**,所以本文档不覆盖 Magic 的复现。
