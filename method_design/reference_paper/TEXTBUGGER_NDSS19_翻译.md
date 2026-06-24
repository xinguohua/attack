# TEXTBUGGER:针对真实应用的对抗文本生成

**原文**:Jinfeng Li, Shouling Ji, Tianyu Du, Bo Li, Ting Wang
**会议**:Network and Distributed Systems Security Symposium (NDSS) 2019,2 月 24–27 日,圣地亚哥
**ISBN**:1-891562-55-X
**DOI**:https://dx.doi.org/10.14722/ndss.2019.23138
**通讯作者**:Shouling Ji (sji@zju.edu.cn)
**机构**:浙江大学网络空间研究院 + 计算机科学与技术学院、阿里巴巴-浙大前沿技术联合研究所;UIUC;Lehigh University

---

## 摘要(Abstract)

基于深度学习的文本理解(**DLTU**)已成为问答、机器翻译、文本分类等应用的核心,但其在情感分析、毒性内容检测等安全敏感场景下的**对抗脆弱性**仍未被充分研究。本文提出 **TEXTBUGGER**,一个生成对抗文本的通用攻击框架,在三方面区别于先前工作:

* **有效(effective)** — 攻击成功率超越 SOTA
* **隐蔽(evasive)** — 保持良性文本的可用性,**94.9%** 的对抗文本仍能被人类正确识别
* **高效(efficient)** — 计算复杂度**亚线性**于文本长度

在情感分析、毒性内容检测的真实 DLTU 系统上验证。例如:在 IMDB 数据集上,对 **Amazon AWS Comprehend** 的攻击 **100% 成功率**,平均耗时 **4.61 秒**,保留 **97% 语义相似度**。论文还讨论两种防御机制以启发后续研究。

**索引词**:对抗文本、文本分类、DLTU 安全、字符级/词级扰动。

---

## I. 引言(Introduction)

**第 1 段**:深度神经网络在分类、回归、决策任务上取得显著成功,但在安全敏感场景下被对抗样本欺骗的脆弱性引发严重关切 [8]、[13]、[20]、[25]、[36]、[37]。

**第 2 段**:DNN 在文本理解中的应用日益重要——例如线上推荐基于评论情感分析做排序 [22];文本分类也用于自动检测线上有害内容(讽刺、侮辱、骚扰、滥用)[26]。

**第 3 段**:机器学习安全已被多方面研究,包括因果型攻击与探索型攻击 [2]、[3]、[15]。已有研究在图像分类任务上展示对抗样本可达高成功率 [6],并对自动驾驶等智能设备构成实际威胁 [10]。

**第 4 段(为什么文本对抗特别难)**:相比图像,文本是**离散**的,难以优化;扰动在图像上可以做到肉眼不可见,但在文本上**单词替换会显著改变语义**。已有面向图像的算法**不能直接迁移**到文本,需要新的攻击与防御方法。

**第 5 段(现有文本对抗方法的局限)**:已有工作 [19]、[33] 提出用**词表外(out-of-vocabulary)单词替换**来生成对抗文本 [4]、[11]、[14]。这些尝试虽然开创性,但实际可行性受四点限制:(i) 计算效率低;(ii) 主要为白盒设置设计;(iii) 需要人工介入;(iv) 仅在特定 NLP 模型上验证,无全面评估。**因此需要进一步研究当前对抗文本生成的效率/有效性,以及流行文本分类模型的鲁棒性**。

**第 6 段(本文方法概览)**:提出 **TEXTBUGGER**,在**白盒**与**黑盒**两种场景下生成**可用性保留(utility-preserving)**的对抗文本:

* **白盒**:计算分类器 $\mathcal{F}$ 的 Jacobian 矩阵找重要词,然后从五种扰动中选**最优的"bug"**改变置信度
* **黑盒**:先找重要句子,然后用打分函数找重要词,最后改

实验显示对 Google Cloud NLP、Microsoft Azure Text Analytics、IBM Watson NLU、Amazon AWS Comprehend 等真实在线 DLTU 系统均能欺骗¹。

> 脚注 ¹:发现已通报相关厂商,他们答复将在下一版本修复 bugs。

**第 7 段(主要贡献)**:
1. 提出 **TEXTBUGGER** 框架,能在白盒/黑盒下高效生成可用性保留的对抗文本
2. 在 10 个 SOTA 模型/平台上评估(Google Cloud NLP、IBM Watson NLU、Microsoft Azure、Amazon AWS、Facebook fastText、ParallelDots、TheySay、Aylien、TextProcessing、Mashape)
3. **跨模型迁移性**:在离线模型生成的对抗文本可成功迁移到多个在线 DLTU 系统
4. **用户研究**:TEXTBUGGER 对人类理解几乎无影响
5. 讨论两种潜在防御策略 + 初步评估

---

## II. 攻击设计(Attack Design)

### A. 问题形式化

给定预训练文本分类模型 $\mathcal{F}:\mathcal{X}\to\mathcal{Y}$,把特征空间 $\mathcal{X}$ 映射到类别集合 $\mathcal{Y}$。攻击者要从一个合法文档 $\boldsymbol{x}\in\mathcal{X}$(真实标签 $y\in\mathcal{Y}$)生成对抗文档 $\boldsymbol{x}_{adv}$,使

$$
\mathcal{F}(\boldsymbol{x}_{adv}) = t \quad (t\ne y)
$$

同时要求一个**领域专属相似度函数** $S:\mathcal{X}\times\mathcal{X}\to\mathbb{R}_+$ 满足 $S(\boldsymbol{x},\boldsymbol{x}_{adv})\ge\epsilon$,其中 $\epsilon\in\mathbb{R}$ 是可用性保留的下界。本文中 $S$ 用文本的**语义相似度**实现。

### B. 威胁模型(Threat Model)

* **白盒**:攻击者完全知道目标模型(架构、参数)。按 Kerckhoff 原则 [35],白盒攻击可暴露模型最坏情况的脆弱性
* **黑盒**:目标模型部署在 MLaaS 平台(如 ParallelDots²),只能通过 API 查询,获取预测或置信度分数。考虑到免费 API 通常有调用限制,黑盒攻击必须把**调用次数与时间成本**纳入设计

> 脚注 ²:https://www.parallelDots.com/

### C. TEXTBUGGER

#### 1) 白盒攻击(Algorithm 1)

> 思想:先找**重要词**,再为每个重要词生成 5 种 bugs,选最优 bug 替换。

**Algorithm 1:White-box TEXTBUGGER**

```
输入:合法文档 x、真实标签 y、分类器 F、阈值 ε
输出:对抗文档 x_adv
1:  x' ← x
2:  for word x_i in x:
3:      Compute C_{x_i}  (Eq. 2)
4:  end for
5:  W_ordered ← Sort(x_1,...,x_m) according to C_{x_i}
6:  for x_i in W_ordered:
7:      bug ← SelectBug(x_i, x', y, F)
8:      x' ← replace x_i with bug in x'
9:      if S(x, x') ≤ ε: return None
10:     elif F_l(x') ≠ y: return x'  (Solution found)
11: end for
12: return None
```

##### Step 1:找重要词(line 2–5)

对输入 $\boldsymbol{x}=(x_1, x_2, \dots, x_N)$ 计算分类器的 Jacobian 矩阵:

$$
J_{\mathcal{F}}(\boldsymbol{x}) = \frac{\partial \mathcal{F}(\boldsymbol{x})}{\partial\boldsymbol{x}} = \left[\frac{\partial \mathcal{F}_j(\boldsymbol{x})}{\partial x_i}\right]_{i\in 1..N,\ j\in 1..K} \qquad (1)
$$

其中 $K$ 是 $\mathcal{Y}$ 中类别数。每个词 $x_i$ 的**重要度**定义为

$$
C_{x_i} = J_{\mathcal{F}(i,y)} = \frac{\partial \mathcal{F}_y(\boldsymbol{x})}{\partial x_i} \qquad (2)
$$

即关于预测类 $y$ 的置信度对输入词 $x_i$ 的偏导,按 $C_{x_i}$ 降序排列。

##### Step 2:生成 bug(line 6–14)

要求生成的对抗句子在视觉上与语义上接近原句。两类扰动:

**字符级扰动(character-level)**:DLTU 系统通常用字典表示有限词集——字典大小(例如英语 ~26ⁿ)远小于字符组合数。**故意拼错重要词** → 词表外(unknown),映射到 unknown embedding → 大幅误导分类。

**词级扰动(word-level)**:在嵌入空间最近邻替换。但 word2vec 等模型中 "worst" 和 "better" 这种语义对立词在句法上很相似 → 直接最近邻会改变情感。**改用语义保留的 context-aware 词向量空间**(预训练 GloVe [30]),取 $top_k=5$ 最近邻,保证语义相似。

**五种 bug 生成方法(Table I)**:

| 方法 | 操作 | 示例:foolish → ? |
|---|---|---|
| **Insert** | 在词中**插入空格**³ | "f oolish" |
| **Delete** | 删除随机字符(不动首末) | "folish" |
| **Swap** | 随机交换两个相邻字符(不动首末)⁴ | "fooilsh" |
| **Sub-C** | 用视觉近似字符替换("o"→"0","l"→"1","a"→"@") | "fo0lish" |
| **Sub-W** | 在 context-aware 词向量空间取 top-k 最近邻替换 | "silly" |

> 脚注 ³:仅在词长 < 6 时使用(长词可能被拆为两个合法词)。
> 脚注 ⁴:只用于 4 字以上词。

##### Algorithm 2:Bug 选择(SelectBug)

```
function SelectBug(w, x, y, F):
    bugs = BugGenerator(w)             # 生成 5 个 bugs
    for b_k in bugs:
        candidate(k) = replace w with b_k in x
        score(k) = F_y(x) - F_y(candidate(k))
    end for
    bug_best = argmax_{b_k} score(k)    # 置信度下降最多的 bug
    return bug_best
end function
```

替换 $x_i$ 后:若分类标签翻转($\mathcal{F}_l(\boldsymbol{x}')\ne y$)且语义相似度 $S(\boldsymbol{x},\boldsymbol{x}')\ge\epsilon$ → 找到对抗样本;否则继续下一个重要词。

#### 2) 黑盒攻击(Algorithm 3)

> 思想:黑盒下无法用梯度,改用三步——**找重要句子 → 找重要词 → 生成 bug**。

**Algorithm 3:Black-box TEXTBUGGER**

```
输入:合法文档 x、真实标签 y、分类器 F、阈值 ε
输出:对抗文档 x_adv
1:  x' ← x
2:  for s_i in document x:
3:      C_{sentence}(i) = F_y(s_i)
4:  end for
5:  S_ordered ← Sort(sentences) by C_{sentence}(i)
6:  Delete s_i in S_ordered if F_l(s_i) ≠ y
7:  for s_i in S_ordered:
8:      for w_j in s_i:
9:          Compute C_{w_j}  (Eq. 3)
10:     end for
11:     W_ordered ← Sort(words) by C_{w_j}
12:     for w_j in W_ordered:
13:         bug = SelectBug(w_j, x', y, F)
14:         x' ← replace w_j with bug
15:         if S(x, x') ≤ ε: return None
16:         elif F_l(x') ≠ y: return x'
17:     end for
18: end for
19: return None
```

##### Step 1:找重要句子(line 2–6)

用 spaCy⁵ 把文档拆为句子;过滤掉**与文档标签不同**的句子;按句子被分类为 $y$ 的置信度 $C_{s_i}=\mathcal{F}_y(s_i)$ 降序排列。

> 脚注 ⁵:http://spacy.io

##### Step 2:找重要词(line 8–11)

第 $j^{th}$ 词的重要度:

$$
C_{w_j} = \mathcal{F}_y(w_1, \dots, w_m) - \mathcal{F}_y(w_1, \dots, w_{j-1}, w_{j+1}, \dots, w_m) \qquad (3)
$$

即**删除 $w_j$ 前后的置信度变化**。此打分函数三个优点:
1. 能正确反映词对预测的重要性
2. 无需知模型参数与结构
3. 计算高效

##### Step 3:生成 bug(line 12–20)

与白盒同步骤,SelectBug 选 5 种 bug 中使 $y$ 置信度下降最多的那个。

---

## III. 攻击评估:情感分析

### A. 数据集

* **IMDB** [21]:50,000 条电影评论,平均 215.63 词,二分类(正/负);25,000 训练 + 25,000 测试,训练集 20% 划为 val
* **Rotten Tomatoes Movie Reviews (MR)** [27]:5,331 正 + 5,331 负 评论,平均 32 词,80/10/10 划分

### B. 目标模型

* **白盒**:LR、Kim's CNN [17]、LSTM [38]。hold-out 训练,val 调参
* **黑盒**:10 个真实平台/模型 — **Google Cloud NLP、IBM Watson NLU、Microsoft Azure、Amazon AWS、Facebook fastText、ParallelDots、TheySay、Aylien、TextProcessing、Mashape**。fastText 用预训练版(在 Amazon Review Polarity 上训练)

### C. 基线算法

* **Random**:每句随机选 10% 词修改
* **FGSM+NNS** [13]:FGSM 加 embedding 噪声 + 最近邻搜索
* **DeepFool+NNS** [24]:DeepFool 找最小跨边界距离 + 最近邻

### D. 评估指标(4 项)

* **Edit Distance**:Levenshtein 距离(增/删/改字符)
* **Jaccard 相似系数**:
  $$
  J(A,B) = \frac{|A\cap B|}{|A\cup B|} \qquad (4)
  $$
* **Euclidean 距离**(词向量空间):
  $$
  d(\boldsymbol{p},\boldsymbol{q}) = \sqrt{\sum_{i=1}^n (p_i - q_i)^2} \qquad (5)
  $$
* **语义相似度**(Universal Sentence Encoder [7] 编码后余弦):
  $$
  S(\boldsymbol{p},\boldsymbol{q}) = \frac{\boldsymbol{p}\cdot\boldsymbol{q}}{\|\boldsymbol{p}\|\cdot\|\boldsymbol{q}\|} = \frac{\sum_{i=1}^n p_i q_i}{\sqrt{\sum p_i^2}\cdot\sqrt{\sum q_i^2}} \qquad (6)
  $$

### E. 实现

服务器:2× Intel Xeon E5-2640 v4 (2.40GHz, 64GB)、4TB HDD、GTX 1080 Ti。每次实验**重复 5 次取均值**。**不过滤停用词**(实测停用词对预测影响大)。词向量:300 维 **GloVe** 训练于 840 亿 token Common Crawl。预训练外词初始化为 $[-0.1, 0.1]$ 均匀。语义相似度阈值 $\epsilon = 0.8$。

### F. 攻击表现

#### 白盒(Table II,IMDB & MR)

| 模型 | 数据集 | Original Acc. | Random SR / 扰动率 | FGSM+NNS | DeepFool+NNS | **TEXTBUGGER** |
|---|---|---|---|---|---|---|
| LR | MR | 73.7% | 2.1% / 10% | 32.4% / 4.3% | 35.2% / 4.9% | **92.7% / 6.1%** |
| LR | IMDB | 82.1% | 2.7% / 10% | 41.1% / 8.7% | 30.0% / 5.8% | **95.2% / 4.9%** |
| CNN | MR | 78.1% | 1.5% / 10% | 25.7% / 7.5% | 28.5% / 5.4% | **85.1% / 9.8%** |
| CNN | IMDB | 89.4% | 1.3% / 10% | 36.2% / 10.6% | 23.9% / 3.6% | **90.5% / 4.2%** |
| LSTM | MR | 80.1% | 1.8% / 10% | 25.0% / 6.6% | 24.4% / 11.3% | **80.2% / 10.2%** |
| LSTM | IMDB | 90.7% | 0.8% / 10% | 31.5% / 9.0% | 26.3% / 3.6% | **86.7% / 6.9%** |

发现:
* 随机改词几乎无效 → 重要词识别是关键
* 线性模型(LR)比 DNN 更易被对抗文本攻破
* TEXTBUGGER 在 IMDB / LR 上 95.2% 成功率,仅扰动 **4.9% 词**(平均约 10 词);MR 只扰动 ~2-3 词即骗过 LR

#### 黑盒(Table III IMDB,Table IV MR)

对比 **DeepWordBug** [11]。在 IMDB Amazon AWS 上,TEXTBUGGER **100% 成功率**,平均 **4.61 秒**(DeepWordBug 43.98 秒);在 Microsoft Azure 100% 成功率,扰动率 5.7%(DeepWordBug 56.3% 成功率,扰动 10%)。

| 平台(IMDB) | Original Acc. | DeepWordBug SR | TEXTBUGGER SR / Time / 扰动率 |
|---|---|---|---|
| Google Cloud NLP | 85.3% | 43.6% / 266.69s | **70.1% / 33.47s / 1.9%** |
| IBM Waston | 89.6% | 34.5% / 690.59s | **97.1% / 99.28s / 8.6%** |
| Microsoft Azure | 89.6% | 56.3% / 182.08s | **100.0% / 23.01s / 5.7%** |
| Amazon AWS | 75.3% | 68.1% / 43.98s | **100.0% / 4.61s / 1.2%** |
| Facebook fastText | 86.7% | 67.0% / 0.14s | 85.4% / 0.03s / 5.0% |
| ParallelDots | 63.5% | 79.6% / 812.82s | **92.0% / 129.02s / 2.2%** |
| TheySay | 86.0% | 9.5% / 888.95s | **94.3% / 134.03s / 4.1%** |
| Aylien Sentiment | 70.0% | 63.8% / 674.27s | **90.0% / 44.96s / 1.4%** |
| TextProcessing | 81.7% | 57.3% / 303.04s | **97.2% / 59.42s / 8.9%** |
| Mashape Sentiment | 88.0% | 31.1% / 585.72s | 65.7% / 117.13s / 6.1% |

MR 上同样大幅领先。在 MR 上仅扰动 ~2 词即达 96.8% 成功率(Microsoft Azure)。

#### 文档长度影响(Fig. 4)

* 成功率几乎不随长度变化
* IBM Watson / Google Cloud NLP 上,长文档的置信度变化幅度略小
* 生成时间随长度增加(找重要句子代价上升);60 词为拐点
* 整体生成一条对抗文本 < 100 秒(文档上限 200 词)

#### 评分分布(Fig. 5)

即使部分负样本未能被翻转,整体置信度被显著拉向正方向。

### G. 可用性分析

* 白盒:**80%** 对抗文本与原文 edit distance < 25
* **90%** 对抗文本保留 ≥ **0.9 语义相似度**

### H. 讨论

* **毒性词分布**(Fig. 11a 词云):重要词正是"bad / awful / stupid / worst / terrible"等负面词
* **bug 类型占比**(Fig. 11b):Microsoft Azure / Amazon AWS 上 Insert 主导;IBM Watson / fastText 上 Sub-C 主导;Sub-W 总是最少(必须同时语义相似 + 改变得分)

---

## IV. 攻击评估:毒性内容检测

### A. 数据集

**Kaggle Toxic Comment Classification**:Wikipedia 评论,人工标 toxic / severe_toxic / obscene / threat / insult / identity_hate 六类(本文合并为二分类:toxic vs non-toxic)。平衡采样,过滤异常文本(包含大量重复字符),取 ≤ 200 词样本 → 12,630 toxic + 12,630 non-toxic。

### B. 目标模型

* **白盒**:自训 LR / CNN / LSTM(80/10/10 划分)
* **黑盒**:**Google Perspective、IBM Natural Language Classifier、Facebook fastText、ParallelDots AI、Aylien Offensive Detector**。IBM Classifier 与 Facebook fastText 用本地训练(80% Kaggle)

### C. 攻击表现

#### 白盒(Table V)

| 模型 | Original Acc. | Random | FGSM+NNS | DeepFool+NNS | **TEXTBUGGER** |
|---|---|---|---|---|---|
| LR | 88.5% | 1.4% | 33.9% | 29.7% | **92.3% / 10.3% 扰动** |
| CNN | 93.5% | 0.5% | 26.3% | 27.0% | **82.5% / 10.8%** |
| LSTM | 90.7% | 0.9% | 28.6% | 30.3% | **94.8% / 9.5%** |

#### 黑盒(Table VI)

| 平台 | Original Acc. | DeepWordBug | **TEXTBUGGER** |
|---|---|---|---|
| Google Perspective | 98.7% | 33.5% / 400.20s | **60.1% / 102.71s / 5.6% 扰动** |
| IBM Classifier | 85.3% | 9.1% / 75.36s | **61.8% / 21.53s / 7.0%** |
| Facebook fastText | 84.3% | 31.8% / 0.05s | **58.2% / 0.03s / 5.7%** |
| ParallelDots | 72.4% | 79.3% / 148.67s | **82.1% / 23.20s / 4.0%** |
| Aylien Offensive | 74.5% | 53.1% / 229.35s | **68.4% / 37.06s / 32.0%** |

ParallelDots 上仅扰动 ~3 词(4.0%)即达 82.1%。**Score 分布**(Fig. 12):修改后的文本平均 toxic 分被拉到 non-toxic 区。

### E. 讨论

* **Toxic 词分布**(Fig. 15a):"fuck / shit / dick / fucking"等显然
* **bug 类型分布**(Fig. 15b):Sub-C 在所有平台上都占主导;Sub-W 最少

---

## V. 进一步分析(Further Analysis)

### A. 迁移性(Transferability)

在三个白盒模型上生成的对抗文本,在其它模型/平台上的成功率。

| 数据集 | 模型 | LR | CNN | LSTM | Watson | Azure | Google | fastText | AWS |
|---|---|---|---|---|---|---|---|---|---|
| **IMDB** | LR | 95.2% | 20.3% | 14.5% | 24.8% | 15.1% | 18.8% | — | 19.0% |
| **IMDB** | CNN | 28.9% | 90.5% | 21.2% | 31.4% | 20.4% | 25.3% | — | 25.1% |
| **IMDB** | LSTM | 28.8% | 23.8% | 86.6% | 27.3% | 26.7% | 27.4% | — | 23.1% |
| **MR** | LR | 92.7% | 18.3% | 28.7% | 22.4% | 39.5% | 19.8% | 29.8% | — |
| **MR** | CNN | 26.5% | 82.1% | 31.1% | 25.3% | 28.2% | 21.0% | 19.1% | 20.5% |
| **MR** | LSTM | 21.4% | 24.6% | 88.2% | 21.9% | 22.5% | 16.5% | 18.7% | — |

**Kaggle**:LR → ParallelDots 54.3%、CNN → Aylien 52.6%。**结论**:对抗文本具备**跨模型/跨平台迁移性**——即使在线平台有 API 调用限制,攻击者也能用迁移性绕过。

### B. 用户研究(MTurk)

随机抽 500 合法 + 500 对抗样本(白盒/黑盒各半),Amazon Mechanical Turk 让人工标注情感/毒性。规则:每人最多标 20 个,每样本 3 标注 → **3,177 个有效标注,297 工人**。

结果:
* **95.5%** 合法样本被正确分类
* **94.9%** 对抗样本仍被标为**原标签**(即扰动**没影响人类判断**)
* 双方误判都集中在少数语义模糊样本

详细误差源(Fig. 16):
* 所有发现错误中,文本原有错误(拼写、语法等)占 **34.5%**,添加的 bugs 占 **65.5%**
* 在原有错误中,**38.0%**(13.1%/34.5%)被参与者发现
* 在添加 bugs 中,**30.1%**(19.7%/65.5%)被参与者发现 → **多数 bugs 未被察觉**
* Insert 最易被发现;Sub-C 中 "o"→"0" 最易,"l"→"1" 不易;**Sub-W 最难发现**

---

## VI. 潜在防御(Potential Defenses)

### A. 拼写检查(Spelling Check, SC)

用 Microsoft Azure 上下文感知拼写检查⁹纠正对抗文本后再送目标模型。即使经过纠错,TEXTBUGGER 在多平台仍高于 DeepWordBug。

**Table IX:IMDB & MR 上 SC 后的攻击成功率**

| 数据集 | 方法 | Google | Watson | Azure | AWS | fastText |
|---|---|---|---|---|---|---|
| **IMDB** | TEXTBUGGER | 22.2% | 27.1% | 32.2% | 20.8% | 21.1% |
| **IMDB** | DeepWordBug | 15.9% | 12.2% | 15.9% | 9.8% | 13.6% |
| **MR** | TEXTBUGGER | 38.2% | 36.3% | 30.8% | 13.8% | 28.6% |
| **MR** | DeepWordBug | 26.9% | 17.7% | 13.8% | 22.1% | 10.2% |

**Table X:Kaggle 上 SC 后的攻击成功率**

| 方法 | Perspective | IBM | fastText | ParallelDots | Aylien |
|---|---|---|---|---|---|
| TEXTBUGGER | **35.6%** | 14.8% | 29.0% | 40.3% | 42.7% |
| DeepWordBug | 16.5% | 4.3% | 13.9% | 35.1% | 30.4% |

**bug 易纠正性**(Fig. 17):
* **Insert / Delete 最易被纠正**(IMDB / Kaggle 上分别为最易)
* **Sub-W 最难**(< 10% 纠正率)——这正是 TEXTBUGGER 比 DeepWordBug 在 SC 防御下更鲁棒的主因

> 脚注 ⁹:https://azure.microsoft.com/en-us/services/cognitive-services/spell-check/

### B. 对抗训练(Adversarial Training, AT)

把已生成的对抗样本加入训练集重训。

实验:25,000 正常 + 2,000 对抗,10 epochs,lr = 0.0005。

| 数据集 | 模型 | 合法准确率 | SR with AT |
|---|---|---|---|
| **IMDB** | LR | 83.5% | 28.0% |
| **IMDB** | CNN | 85.3% | 15.7% |
| **IMDB** | LSTM | 88.6% | 11.6% |
| **MR** | LR | 76.3% | 23.6% |
| **MR** | CNN | 80.1% | 16.6% |
| **MR** | LSTM | 78.5% | 16.5% |
| **Kaggle** | LR | 86.7% | 27.6% |
| **Kaggle** | CNN | 91.1% | 15.4% |
| **Kaggle** | LSTM | 92.3% | 11.0% |

**对抗训练有效**(攻击成功率从 80-95% 降到 10-30%),且对合法样本影响小。**局限**:防御方需知攻击细节,且需要足够多对抗样本——但攻击者通常不公开,所以 AT 难以防御未知攻击。

### TEXTBUGGER 反制

攻击者可调整 bug 类型比例:Sub-W 难纠正 → 增加 Sub-W 占比;频繁换攻击策略 → 规避 AT。

---

## VII. 讨论

* **扩展到目标攻击**:把 Eq.(2) 中关于真实标签的 Jacobian 改为关于**目标标签** → 直接得到 targeted 版本
* **局限与未来工作**:可用更精细的语言学技术(句法分析、命名实体、同义改写);从词级扩展到 beam search + 短语级修改;研究有效鲁棒的防御

---

## VIII. 相关工作(摘录)

### A. 文本对抗攻击

* **梯度型**:
  * Papernot et al. [29] 白盒迭代修改,但词级反映效果显著改变语义
  * **Ebrahimi et al. [9] (HotFlip)** 用模型对 one-hot 输入的梯度,从一个 token 翻到另一个 token
  * Samanta et al. [33] 用 embedding 梯度定位重要词 + 手工启发规则(同义词 / 拼错)
* **OOV 替换**:
  * Belinkov et al. [4] 显示字符级翻译模型对随机字符扰动极敏感
  * Gao et al.(**DeepWordBug** [11])给字符扰动评分 → 本文主要对照基线
  * Hosseini et al. [14] 显示加空格/点字符能大幅改变 Perspective 毒性分
* **语义/句法相似词替换**:
  * Alzantot et al. [1] 用遗传算法做情感攻击,只用语义相似词
  * Ribeiro et al. [32] 按 POS 同标签随机替换,概率正比于 embedding 相似度
* **其它**:
  * Jia & Liang [16] 给阅读理解输入插入分散句子,但需人工润色
  * Zhao et al. [40] 用 GAN 生成对抗序列(限于短文本)

### B. 防御

文本领域的对抗防御方法稀缺,主要在图像;对抗训练在 DLTU 任务上**仅作为正则化**使用 [18]、[23]——没有专为文本对抗设计的防御。

### C. 区分点

TEXTBUGGER 与已有工作的区别:
1. **同时**使用字符级 + 词级扰动(已有工作要么纯梯度 [29] 要么纯语言学 [16])
2. **大幅提升效率**(亚线性于文本长度)
3. **首个全面**评估真实在线 DLTU 系统的工作(15 个真实平台 vs 已有工作仅评测 1-2 个公开离线模型)

---

## IX. 结论

本文研究白盒与黑盒下针对 SOTA 情感分析与毒性内容检测模型/平台的对抗攻击,提出 **TEXTBUGGER** 框架,在生成有目标对抗 NLP 样本时**有效且高效**。对抗样本的**迁移性**暗示了多种真实应用的潜在脆弱性,包括**文本过滤系统**(种族歧视、色情、恐怖主义、暴乱内容过滤)、**在线推荐系统**等。研究结果同时显示**拼写检查与对抗训练**在防御此类攻击上的可能性;基于**语言学感知 / 结构感知**的集成防御可作为后续方向以进一步提升鲁棒性。

---

## 关键参考文献(摘录)

* [1] Alzantot et al., "Generating natural language adversarial examples," arXiv:1804.07998, 2018.
* [4] Belinkov & Bisk, "Synthetic and natural noise both break neural machine translation," arXiv:1711.02173, 2017.
* [11] Gao et al., "Black-box generation of adversarial text sequences to evade deep learning classifiers," arXiv:1801.04354, 2018. — **DeepWordBug**(主要对照基线)
* [13] Goodfellow et al., "Explaining and harnessing adversarial examples," ICLR 2015. — **FGSM**
* [14] Hosseini et al., "Deceiving Google's Perspective API," arXiv:1702.08138, 2017.
* [16] Jia & Liang, "Adversarial examples for evaluating reading comprehension systems," EMNLP 2017.
* [24] Moosavi-Dezfooli et al., "DeepFool," CVPR 2016.
* [29] Papernot et al., "Crafting adversarial input sequences for recurrent neural networks," MILCOM 2016.
* [30] Pennington, Socher, Manning, "GloVe," EMNLP 2014.
* [32] Ribeiro et al., "Semantically equivalent adversarial rules for debugging NLP models," ACL 2018.
* [33] Samanta & Mehta, "Towards crafting text adversarial samples," arXiv:1707.02812, 2017.

完整 40 条参考文献见原 PDF 第 15 页。

---

## 译者备注:与 SafeMimic / PIDS 攻击的对照

TEXTBUGGER 与你的项目场景高度同构(都是**离散符号空间下的硬标签黑盒攻击**),可借鉴的三大要素:

| TEXTBUGGER 要素 | 对应到 PIDS 黑盒攻击 |
|---|---|
| **重要词识别**(白盒 Jacobian、黑盒 leave-one-out 打分 Eq. 3) | **重要节点/边识别**:代理 PIDS 上做梯度(白盒)或留一查询(黑盒),找对告警贡献最大的子图组件 |
| **5 类 bug 生成**(Insert / Delete / Swap / Sub-C / Sub-W) | **图操作算子**:加边 / 删边 / 改进程名 / 用良性进程替换攻击进程 / 用近邻 syscall 替换 |
| **三步黑盒**:重要句 → 重要词 → bug | **三步 PIDS 攻击**:重要事件块 → 重要节点 → 图操作 |
| **可用性保留语义相似度阈值 $\epsilon=0.8$** | **攻击功能完整性 + 隐蔽度阈值**(本身就是 SafeMimic 已经在做的事) |
| **迁移性**(白盒对抗文本迁移到在线 DLTU 平台) | **代理 PIDS 上扰动迁移到 victim PIDS**——直接对应 |
| **防御 SC + AT** | PIDS 端的 anomaly post-filter + adversarial fine-tune |

**两个直接可借鉴的算法骨架**:
1. **TEXTBUGGER 黑盒算法 3** 的"重要句 → 重要词 → 选最优 bug"三层贪心结构,可直接搬到 PIDS 图扰动:**重要时间窗 → 重要节点/边 → 选最优图算子**。
2. **SelectBug 的 score 函数 score(k) = F_y(x) - F_y(candidate(k))** — 选择"让 victim PIDS 告警置信度下降最多"的算子,对应你 SafeMimic 中的代理 PIDS 反馈信号。

TEXTBUGGER 的"亚线性复杂度"主要源于**先找重要句过滤大量无关单元** —— PIDS 图同样可以先做时间/子图过滤,大幅降低查询数。
