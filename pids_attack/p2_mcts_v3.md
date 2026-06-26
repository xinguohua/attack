> ## 谢老师意见(2026-05-29)
>
> ### 1. Feedback 应该是两类(参考 FCGHUNTER)
>
> 参考论文:**FCGHUNTER: Towards Evaluating Robustness of Graph-Based Android Malware Detection** — 那篇文章用了**两种得分**驱动搜索:
>
> - **(a) 最 sparse 的得分:PIDS 绕没绕过**(binary 二值反馈 — 被抓 / 没被抓)
> - **(b) 良性不良性得分**(连续 / 软信号 — PIDS 判断这次行为有多"良性")
>
> 当前我们只用了 (a) 类 sparse 反馈,信号太稀疏,搜索效率低。
>
> **(a) 我能想得通** —— PIDS 直接反馈就有。**(b) 我想不通** —— 我没有 reference,不知道"系统分布内的良性命令长啥样"。
>
> ### 2. 良性 reference 不需要预知 —— 搜索本身就是在 explore 良性分布
>
> 我跟谢老师说:**我不知道良性 reference 长啥样,系统分布内的良性命令长啥样,所以拿不到 (b) 得分**。
>
> 谢老师回:**你探索的时候其实就是找良性分布**。不需要预先有 `G_benign`,搜索过程**本身**在累积"哪种命令组合让 detector 判良性"的信号 —— **良性分布是 explored 出来的,不是 attacker 假设出来的**。
>
> 这彻底解决了 P2 V2 §5 一直绕不开的"`G_benign` 怎么定义 / 哪儿来 / 跟攻击域怎么对齐"的死结 —— **不存在预设的 G_benign,有的是搜索累积的反馈库**。
>
> ### 3. 约束设计不应预设 G1/G2 —— 应按检测器类型分类,由反馈决定
>
> 我跟谢老师说:**我想优化函数先找良不良得分 (b),动机是不想引入明显的拓扑特征(G1 度分布 / G2 共现)**。
>
> 谢老师纠正:**这个想错了**。约束设计的正确方式不是"attacker 主动绕 G1/G2",而是按**检测器分类**做:
>
> - **纯 GNN 类检测器** —— 一种处理
> - **纯规则类检测器(G1/G2 这种结构约束)** —— 另一种处理
> - **GNN + G1/G2 混合类** —— 又一种处理
>
> **加什么约束 / 怎么避是检测器特性的问题,根据反馈调,不是 attacker 提前 hardcode**。
>
> 这彻底颠覆当前 P2 V2 §5 的设计哲学:
>
> - ~~当前 §5:hardcode Nettack G1 度分布 + G2 共现两条约束,attacker 假设防御方一定有这两条~~
> - **正确:不预设任何约束;先打开始搜索,根据 PIDS 反馈推它是哪类检测器,再针对性调约束**
>
> ### 4. 替代模型(surrogate)也要多点反馈
>
> 参考 FCGHUNTER 的替代模型设计 — surrogate 不应该只学单一 binary 信号,应该学多点反馈(对应上面 (a) + (b))。
>
> 当前 P2 V2 §5 的 surrogate 设计是"GCN 学 P(flagged | G)",**仍是单点信号**。后续要扩成多输出 surrogate 学 (a) 跟 (b) 两类信号。
>
> ### 5. 实施顺序
>
> **Step 1. fitness 定义** — 反馈 + 更细化的反馈(每种 detector model 都要 handle)+ 强约束(加的命令条数等)。参考 **GRABNEL** [Wan et al. NeurIPS'21] 的单标量 CW margin + 硬预算 模式 + `pids_attack/discrete_blackbox_reward_survey.md` 列出的 18 篇离散域黑盒对抗工作的 fitness 范式。
>
> **Step 2. 优化问题形式化** — 把 Step 1 的 fitness + 约束写成一个单一优化问题,落到一个 md 文档。
>
> **Step 3. 框架初步设计**(根据实验后续再调):
> - Phase A surrogate:`pids_attack/phase_a_surrogate_survey.md` 选定 **WL features + Sparse Bayesian Linear Regression**(GRABNEL 风格)
> - Phase B 搜索:`pids_attack/phase_b_search_algorithm_survey.md` 选定 **GRABNEL** [Wan et al. NeurIPS'21] 双层 BO + 内层 GA 结构
>
> **Step 4. 段落修订** — 按 jiongchi 的意见改前面段落,后面接着改。
>
> **Step 5. PIDS 反馈 — 经验主义 incremental 跑通**:
> 1. **先跑最简单的搜索** — 用单点 sparse feedback (a) 把 end-to-end pipeline 打通。跑了知道问题以后才能找到良不良更细反馈的得分。
> 2. **根据结果优化搜索算法,拆分更多反馈** — 此时才回头想 (b) 得分怎么从 PIDS 输出榨出来。
> 3. **最后看替代模型** — 才设计 surrogate 学多点反馈。
>
> **不要并行做 Step 5 的三件事**。经验主义优先:**先跑,跑出问题才能定位真正缺什么**。
>
> ---
>
> ## 审稿人反对意见(已解决,新方案见下)
>
> **问题 1.** §4.2 把两条规则(G1 度数分布 + G2 co-occurrence)当成已知前提,然后用 MCTS 在这两条规则下搜索。规则是别人(Nettack)已知的,MCTS 也是已知的算法,组合起来就是工程问题。而且 attacker 端的良性命令分布 G_benign 本身就不明确(用什么命令源、怎么构、覆盖范围多大、跟实际 attack 域怎么对齐都没定下来),所谓"在 G_benign 下卡两条规则"的前提整个站不住。**SafeMimic 的研究贡献在哪?**
>
> **问题 2.** S3 的 WL canonical-hash cache 假设"同构图 ⇒ 真跑 output 相同,零误差"。但 docker 真实执行带 fs / time / cache / 网络副作用,output 不只依赖当前 G 状态,是非马尔科夫的。用结构等价(WL 同构)替代真实执行等价的前提不成立。**带历史副作用的执行,即使把过去的 query reply 都记录下来,也不能用来优化查询次数 — cache 命中复用不到、reply 不可重用,query budget 省不下来,C3 query-as-exposure 没解决。**
>
> ---

# P2 V3:SafeMimic-CMD — GRABNEL-aligned BO + 双目标 fitness + endogenous reference

> 承接 `p1_formulation_1.md` §3 与 §4。本节给出 §5 — 模仿 **GRABNEL** [Wan et al. NeurIPS'21] §2 + **BagAmmo** [Tang et al. USENIX'23] §5 写作结构:Problem Setup → Sequential perturbation selection → Surrogate model → Two-objective fitness with endogenous reference → Optimisation of acquisition function via genetic algorithm。
>
> **v3 跟 v2 的主要差异:**
> - 优化目标从加权多目标 `α·ER + γ·U − η·|Δ|/N` 改为 (f_1, f_2) **双目标 + soft-min Tchebycheff scalarization**(承 FCGHunter 双目标 + MOS-Attack scalarization)
> - U(G; R) k-NN 软隐蔽信号保留(承谢老师 v2 endogenous R 思路,不预设 G_benign)
> - **去掉 Phase A / Phase B 切分,采 GRABNEL Sequential perturbation selection**(K stage,每 stage 1 atomic op + 1 真 query)
> - 主预算约束改用 `q_used ≤ B_max`(query 次数硬上限)
> - Surrogate 锁定 **WL features + Sparse Bayesian Linear Regression**(GRABNEL 原汁)
> - Warm-start surrogate + reference R 用项目手头 30 份 benign trace(不消耗 query budget)

---

## §5 SafeMimic-CMD: Black-box Command-Level Adversarial Attack via Bayesian Optimisation

### Problem Formulation

我们将命令级对抗攻击形式化为约束组合优化问题。设 G ∈ 𝒢 为命令图(§4 定义),目标 PIDS detector 作黑盒反馈函数 `g : 𝒢 → [0, 1]^{|V|}`,输入图 G 输出节点级 anomaly score `g(G)[v]`。给定阈值 τ,被 detector 报警的节点集合定义为 `F(G) = { v ∈ V(G) : g(G)[v] > τ }`。给定原图 G_0(满足 `F(G_0) ≠ ∅`),adversarial 目标是找扰动序列 Δ 让 `G_adv = apply(Δ, G_0)` 满足 `F(G_adv) = ∅`(所有节点都不再被报警),同时维持原攻击语义。如 Eq (1),第一个 objective 是最大化被报警节点的减少数;Eq (2) 定义第二个 objective — 最小化找到成功扰动所用的真 query 次数 `q_used`。

```
argmax   |F(G_0)| - |F(G_adv)|                   ► maximize flagged-node drop      (1)
    Δ

argmin   q_used                                    ► minimize query count           (2)
    Δ

s.t.:    F(G_0) ≠ ∅,  F(G_adv) = ∅,  G_adv = apply(Δ, G_0) ∈ 𝒢                    (3)

         Δ = o_1 ∘ o_2 ∘ · · · ∘ o_n ∈ 𝒪                                            (4)
```

其中 `o_k ∈ 𝒪 = {Add, Rewrite, Move, Remove}` 是 §4 定义的 4 个 atomic op,`Δ = o_1 ∘ o_2 ∘ · · · ∘ o_n` 表示长度为 n 的 op 序列把 G_0 一步步变换为 G_adv,即 `G_adv = apply(Δ, G_0) ∈ 𝒢`。`q_used` 是搜索算法到当前为止累计的真 query 次数。

**参考论文:**
- **MalGuise** [Ling et al. USENIX Sec'24] §3.1 Eq 1-4:Eq 1 `argmax g(z) - g(z_adv)`、Eq 3 s.t. `f(z) = 1, f(z_adv) = 0, z_adv = T(z) ∈ Z`、Eq 4 `T = T_1 ∘ ... ∘ T_n ∈ 𝕋`(本节 Eq 1, 3, 4 直接对应)。
- **EvadeDroid** [Bostani et al. CnS'24] §4.2 Eq 1:`argmin |δ|` 形式(本节 Eq 2 `argmin q_used` 参考)。

---
---

todo

- 4.定义好优化函数 在这考虑规则怎么办  有改的这种变异方式 欺骗 ids 不被 rule-bas
### §5.1 Challenges and Overview

#### Challenges

在 PIDS 黑盒攻击场景下,搜索使 `F(G_adv) = ∅` 的扰动 Δ 面临三个主要挑战:

**C1. 扰动隐蔽性 (Perturbation Noticeability).** 不加约束的扰动会让命令图脱离 detector 已知的良性分布,容易被基于图拓扑 / 类型分类的 detector 抓。

> **Finding (motivation 实验).**
> - **ProvNinja P2 失效**:96.9% (185/191) 案例,扰动让某 LOLBin 进程同时连接 file 与 socket。
> - **Contorter P2 失效**:100% (15/15) 案例,扰动让某进程 file-degree 远超 baseline。
>
> 两类都是扰动越出 detector 已知良性分布的不同维度表现。

**C2. 多节点攻击目标耦合.** 攻击成功条件是全图无报警 `F(G_adv) = ∅`,扰动 Δ 对各节点的影响存在耦合 — 同一个 Δ 联合调制多节点的报警状态,**不同节点的改善方向往往相反**(救活一个 v_i 反而让另一个 v_j 进入报警集)。

**C3. Query 暴露 (Query-as-Exposure).** Attacker 拿 reply 须真跑扰动脚本,每次 query 都暴露 attacker;搜索算法须尽可能减少总 query 次数(`B_max ≤ 20`)。

#### Overview

SafeMimic-CMD 在每个 query stage 上协同运转 3 个核心组件,共同应对上述挑战:

> **Figure 1.** SafeMimic-CMD pipeline overview — 3 个核心 block:**Block 1 Surrogate model**(§5.2)、**Block 2 Sequential perturbation selection**(§5.3,K stage outer loop,每 stage 1 atomic op + 1 真 query)、**Block 3 Optimisation of acquisition function via GA**(§5.4,内层 GA 在 §4 atomic op 空间演化,acquisition 作 fitness)。Endogenous reference `R = (R_unflagged, R_flagged)` 跟 surrogate 后验在每 stage 真 query 完同步更新。

- **Surrogate model (→ C3).** 在不付真 query 的前提下廉价估计候选扰动图的 reward `s(G) ∈ ℝ`,由 WL features + 带 ARD 先验的 Sparse Bayesian Linear Regression 实现,输出后验 `(μ, σ)` — 把真 query 集中到最值得的候选,**应对 C3 紧 query budget**。详见 §5.2。

- **Sequential perturbation selection + Inner GA (→ C1, C2).** 双层搜索算法,共同在双目标 fitness landscape 上联合优化:reward `s(G)` 由 soft-min Tchebycheff 把 `f_1`(报警节点 hinge 总和,**应对 C2 多节点耦合**)与 `f_2`(G 跟 endogenous reference `R = (R_unflagged, R_flagged)` 的 k-NN 相似度,**应对 C1 扰动隐蔽性**)合成单 scalar。
  - **Sequential perturbation selection** 是外层 K-stage 循环,把整 Δ 搜索拆成 K 个单 op 顺序 commit;每 stage 1 真 query 拿 reply 并累积 `R` + 更新 surrogate 后验,让搜索方向逐步收敛(详见 §5.3)。
  - **Inner GA** 是单 stage 内层,在 §4 atomic op 空间用 surrogate 的 LCB acquisition 排候选,跑 T_GA 代 mutation / crossover / selection 选下一 stage commit,**整个过程 0 真 query**(详见 §5.4)。

**参考论文:**
- **ProvNinja** [Mukherjee et al. USENIX Sec'23] + **Contorter** [Nasr et al. S&P'26]:C1 motivation 实验来源。
- **GRABNEL** [Wan et al. NeurIPS'21] §2 + Fig 1 caption:3-block 架构(Surrogate / Sequential / Acquisition GA)直接对应。

---

### §5.2 Surrogate model

BO 收敛速度由 surrogate 拟合质量决定 — surrogate 需要在不付真 query 的前提下,廉价估计候选扰动图 G 的 reward `s(G)`,并给出概率化的 `(μ, σ)` 后验供 Inner GA 的 LCB acquisition 使用。我们采用两步串联架构:**Weisfeiler-Lehman (WL) feature extractor 先把图压成稀疏向量 → Sparse Bayesian Linear Regression with ARD prior 再从向量回归 s**。

**WL feature extractor.** H 轮 Weisfeiler-Lehman hash 迭代把命令图 G 映射成 D 维稀疏向量 `φ(G)`。每节点 v 初始 label `x^0(v) = type(v)`(节点类型 ∈ {subject, file, netflow}),每轮将 v 自身 label 与邻居 label 集合做 hash,产生新离散 label:

```
x^{h+1}(v) = HASH( x^h(v), {{ x^h(u) : u ∈ N(v) }} ),  ∀ h ∈ {0, 1, ..., H−1}          (5)
```

每一层 h 上,特征向量 `φ_h(G)` 为各 label 在 G 上的出现次数计数向量;H = 3 轮后最终图特征 `φ(G) = concat(φ_0(G), ..., φ_H(G)) ∈ ℝ^D`,D ≈ 200。该过程**无需训练**,既编码节点自身类型,也通过迭代邻居聚合编码 H 跳拓扑。

> **TODO(命令图特征化方案):** 当前 WL hash(GRABNEL 默认 Eq 3 离散版)是暂定方案,先跑通端到端 pipeline 用。命令图域可能需要换其他特征化方案 — 后续按 §6 实验效果选:**(a) GNN embedding**(GCN / GAT / GraphSAGE,有训练成本但拟合表达力强);**(b) Graph kernel 系列其他**(random walk kernel / shortest-path kernel);**(c) graph2vec / sub2vec**(整图无监督 embedding);**(d) 命令序列直接 embedding**(treat strace 为 token 序列,word2vec / BERT 嵌入);**(e) 手工 domain feature**(进程度数分布、syscall 类型计数、文件访问路径等)。先用 WL 跑通,再根据 surrogate 拟合精度 / sample efficiency / 真攻击成功率横向对比择优。

**Sparse Bayesian linear regression with ARD.** 在 φ(G) 上做带 ARD 先验的 Bayesian 线性回归拟合 `s(G)`:

```
s | Φ, α, σ_n²  ~  N( α^⊤ Φ, σ_n² I )                                                 (6)
α | λ           ~  N( 0, diag(λ⁻¹) )                                                   (7)
λ_i             ~  Gamma(k, θ),   k = θ = 10⁻⁴                                         (8)
```

ARD prior 让 α_i 在数据不支持的维度自动收缩到 0,实现自动特征选择 — `B_max = 20` 小数据下尤其关键。**Closed-form posterior update.** 每 stage 拿到新 `(Φ(G_t), s(G_t))`,后验 `(μ_α, Σ_α)` 通过 Bayesian closed-form 公式增量更新,O(D²) 完成,无 epoch 训练。**起步阶段:** BLR 后验 = prior(μ_α = 0,无训练数据),第 1 stage Inner GA 在 prior 上跑,`LCB ≈ -β·σ` 选 σ 最大候选纯 explore;每完成一次真 query 后验越来越准,LCB 从 explore-dominant 渐变 exploit-dominant。

> **TODO(回归模型选型):** 当前 Sparse BLR + ARD prior(GRABNEL 默认)是暂定方案,先跑通端到端 pipeline 用。命令图域可能需要换其他概率回归模型 — 后续按 §6 实验效果选:**(a) Gaussian Process** 配 WL kernel / RBF kernel(更强表达力,但 O(n³))、**(b) Bayesian Neural Network**(MC dropout / variational inference,深度 prior)、**(c) 随机森林 + 分位数回归**(非概率但能给经验 (μ, σ))、**(d) Ensemble of linear regressors**(bootstrap aggregation 估不确定度)、**(e) 直接换 acquisition 不依赖 σ**(用 Thompson sampling 等非 BO 风格)。先用 Sparse BLR + ARD 跑通,再按 surrogate posterior 校准度 / fit 收敛速度 / 真攻击成功率横向比对择优。

**参考论文:**
- **GRABNEL** [Wan et al. NeurIPS'21] §2 Surrogate model block + Eq 3, 5-7:WL feature extractor + Sparse Bayesian Linear Regression with ARD prior + closed-form posterior update(本节 Eq 5-8 直接对应)。
- **Shervashidze et al.** [JMLR'11] *Weisfeiler-Lehman graph kernels*:WL feature extractor 原论文(本节 Eq 5 hash 迭代过程)。

---

### §5.3 Sequential perturbation selection

**Sequential strategy.** 直接搜整 `Δ = o_1 ∘ ... ∘ o_K` 是 `(|V_C|² × |𝒪|)^K` 量级的组合优化,B_max=20 真 query 无法承担。我们把 B_max 摊到 K 个 stage,每 stage 在 1-op neighborhood 上选 1 个 atomic op,逐步组成 `Δ = o_1 ∘ o_2 ∘ ... ∘ o_K`,每 stage 仅消耗 1 次真 query。该策略虽然 greedy(每 stage commit 当前 acquisition 最优 op),但 atomic op 集合 `{Add, Rewrite, Move, Remove}` 在 Add / Remove 上对称 — agent 可以在后续 stage 通过 Remove 之前 Add 的 op 来"撤销"之前的 commit,所以并非单调递增;同时,只要任一 stage 的真 query 拿到 `F(G_t) = ∅` 就立即 return Δ,实际扰动量 |Δ| 通常远小于 B_max,扰动越少 attacker 越隐蔽(parsimonious)。

> **Figure 2.** Sequential stage 化示意 — 每 stage t,在当前 `Δ_{t-1}` 基础上从 atomic op 空间(§4)选 1 个 `o_t*` 增量扩展(类比 GRABNEL Fig 2 的 1-edit neighborhood)。Inner GA(§5.4)在 surrogate 上演化候选,argmin acquisition 者作 stage commit 候选。

> **TODO(sequential commit 策略):** 当前每 stage 单 op greedy commit 是暂定。跑通后按效果调:**(a) 单 op vs 多 op batch commit/stage**;**(b) 单步贪心 vs 多步 lookahead vs beam search**。按 |Δ| 分布 / B_max 利用率 / 收敛速度横向比对择优。

**Two-objective fitness with endogenous reference.** 每 stage 真 query 完拿到 `g(G_t), F(G_t)` 后,需要算 reward `s(G_t)` 喂给 surrogate 跟下 stage 的 acquisition。GRABNEL 单标量 fitness `L_attack = CW margin` 在单标签 graph classification 上够用,但对 PIDS 不够 — motivation 实验(C1)显示 detector 还会因图脱离 benign 分布抓(ProvNinja P2 96.9% / Contorter P2 100% 失效)。我们扩 GRABNEL 单目标到双目标(承 FCGHunter [Sen Chen et al. TSE'25])+ soft-min Tchebycheff scalarization(承 MOS-Attack [arXiv 2501.07251, 2025])合成单 scalar 给 BLR / BO 适配。**主目标 f_1** 量化攻击效果(报警节点 hinge 总和):

```
f_1(G) = - Σ_{v ∈ V(G)} max( 0, g(G)[v] - τ ),   归一: f_1'(G) = f_1 / |V(G)| ∈ [-1, 0]   (9)
```

`f_1' = 0` 即全图无标红(攻击成功);CW-style 推广到 set-level,跟 §5 Eq (1) 一致。**副目标 f_2** 量化 G 跟 detector 已知 benign 分布的相似度,**不预设 detector 内部机制**(规则 / GNN / autoencoder 任意):

```
f_2(G) = U(G; R) = #k-NN_unflagged(G | R) / k  ∈ [0, 1]                                   (10)
```

`R = (R_unflagged, R_flagged)` 是 sequential stage 过程中累积的 detector-validated 命令图集合(每 stage 真 query 完按 `F(G_t)` 是否为空归入两簇);WL graph kernel 算 G 跟 R 中每图距离,取 top-k 最近邻(k=5),数其中多少落在 `R_unflagged` 簇。**endogenous R 而非预设 G_benign** 是关键 — v2 预设 G_benign 碰到 "G_benign 怎么定 / 哪儿来" 死结;endogenous R 由 detector 自己 label,detector 内部偏好(度分布、共现、type 分类等任意机制)通过 R 自动暴露,attacker 不需 hardcode 拓扑规则。Reference 起步用 30 份 benign trace 填 `R_unflagged`(仅参与 k-NN,无需 s),搜索过程中 R 双侧同步累积。最后用 soft-min Tchebycheff scalarization 合成单 scalar:

```
s(G) = - (1/β) · log [ exp( -β · L_1(G) ) + exp( -β · L_2(G) ) ],   β = 5                 (11)
     其中 L_1(G) = -f_1'(G) ∈ [0, 1],  L_2(G) = 1 - f_2(G) ∈ [0, 1]   (越小越好)
```

soft-min 由 `L_1, L_2` 中较"差"那项主导 — 攻击成功但拓扑异常 / 拓扑像良性但攻击失败两种 partial-success 都被惩罚。β = 5 时 soft-min ≈ strict-min(MOS-Attack 推荐值)。`s(G_t)` 算完后 `(Φ(G_t), s(G_t))` 加进 BLR 训练历史 T,后验 closed-form update(§5.2)— 下 stage 的 acquisition 用更新后的 surrogate 算。

> **TODO(fitness 设计):** 当前 f_2 用 k-NN to endogenous R + 合成用 Tchebycheff(β=5)是暂定。跑通后按效果调:**(a) f_2 endogenous R 度量** — k-NN ratio vs 距离加权 vs 密度估计(GMM/KDE);**(b) 合成方式** — Tchebycheff vs 加权和 vs lexicographic。按 fitness landscape 平滑性 + 真攻击成功率横向比对择优。

**参考论文:**
- **GRABNEL** [Wan et al. NeurIPS'21] §2 Sequential perturbation selection block + Fig 2:把总预算 B 摊到 ∆ stage、每 stage 选 1 edge 的串行框架(本节 Per-stage commit 直接对应,1 atomic op 对应 1 edge)。
- **FCGHunter** [Sen Chen et al. TSE'25] §VI-D Eq 4:双目标 fitness `(f_1, f_2)` 范式(本节 Two-objective fitness 直接对应,合成方式改 Tchebycheff 标量化)。
- **MOS-Attack** [arXiv 2501.07251, 2025]:soft-min Tchebycheff scalarization 公式(本节 Eq 11 直接对应)。

---

### §5.4 Optimisation of acquisition function via genetic algorithm

离散 atomic op 序列空间无法用基于梯度的 acquisition 优化器,我们采用 GA — 整个 GA 跑在 surrogate 上,**0 真 query**,所以 GA 自身 sample efficiency 不重要,可以放心多代演化。GA 内部组件(对应 BagAmmo §5.3 Apoem 框架,跳过 Immigration;mutation/crossover 操作基础参考 GA 综述 [Holland 1992])按 (1)-(4) 展开:

**(1) Population & Individual.** Individual 是一条 Δ 序列 `Δ_i = {o_1, o_2, ..., o_n}`,其中每个 `o_k ∈ 𝒪 = {Add, Rewrite, Move, Remove}`(§4 atomic op);该序列施加到 G_0 上得候选扰动图 `G_i = apply(Δ_i, G_0)`。Population 是 m = 20 条 Δ 候选。**初始 population:** 后续 stage 从已 query 历史 T 抽 top-k 高 s 的 Δ 个体作种子,对每条做 mutation 填满种群;首 stage T 空,种群从 §4 atomic op 空间随机采 m 条短 Δ 起步(典型 |Δ| = 1-3 op)。

**(2) Fitness & Selection.** 每个 Δ_i 的 fitness 用 Lower Confidence Bound (LCB,GRABNEL 风格,跟 GP-UCB [Srinivas et al. ICML'10] 同族) 作 acquisition:

```
α(Δ_i) = μ(G_i) - β_LCB · σ(G_i),   G_i = apply(Δ_i, G_0),   β_LCB = 0.5             (12)
```

`(μ, σ)` 来自 BLR 后验(§5.2),整个过程 0 真 query。**Selection** 采用 elitist 策略:按 α 升序选 top-m 个体(α 越低越值得真 query)进入下代 breeding pool,劣质个体被淘汰。

> **TODO(acquisition function 选型):** 当前 LCB `α = μ - β_LCB·σ`(β_LCB=0.5,GRABNEL 默认)是暂定。跑通后按效果调:**(a) LCB vs EI**(Expected Improvement,高维 sparse 后验下可能更准);**(b) LCB vs Thompson sampling**(从后验直接采样,explore 更自然);**(c) β_LCB 值**(0.5 偏 exploit,1-2 偏 explore,也可 stage 内 anneal — 早期 explore 大、后期 exploit 大)。按 surrogate posterior 信号强度 / 早期 explore 率 / 收敛速度横向比对。

**(3) Crossover.** 从 breeding pool 随机选 K 对 Δ 个体作 parents,每对交换一半 op 子序列产生两个 offspring。设 parents 是 `Δ_{p1} = {o_1, o_2, o_3, o_4}` 跟 `Δ_{p2} = {o_1', o_2', o_3', o_4'}`,crossover 后 offspring 是 `Δ_{c1} = {o_1, o_2, o_3', o_4'}` 跟 `Δ_{c2} = {o_1', o_2', o_3, o_4}`。Crossover 把不同种子的好 op 组合,避免局部最优。

**(4) Mutation.** 对每个 Δ 个体随机施加 3 种 mutation 模式之一:**1) Add new op:** `{o_1, ..., o_n} → {o_1, ..., o_n, o_{n+1}}`,在 𝒪 空间随机采新 op 附加;**2) Remove op:** `{o_1, ..., o_n} → {o_1, ..., o_{n-1}}`,去掉一个 op(跟 GRABNEL "可撤销" 哲学一致,允许撤销之前 Add 的 op);**3) Replace op:** `{o_1, ..., o_n} → {o_1, ..., o_{n-1}, o_{n+1}'}`,随机位置替换 op。三种模式覆盖序列长度增 / 减 / 等长改变,所有 mutation 后违反 R1(攻击 op 不可改)或 R2(序列可执行 partial order)的个体被硬过滤。

> **Figure 4.** Inner GA 组件示意 — 3 个子图:**(a) Individual** 一条 Δ 序列例示;**(b) Crossover** 两 parent Δ 交换子序列产 offspring;**(c) Mutation** 3 模式(Add / Remove / Replace)。

**GA 主循环:** 初始 population 建好后,每代算每个 Δ_i 的 α(Δ_i),selection 选 top-m → crossover → mutation → 下代;跑 `T_GA = 50` 代后,返回整个 GA 过程中见过的 `argmin_{Δ} α(Δ)` 作 stage commit 提案 Δ*。每 stage 内层共 `m × T_GA ≈ 1000` 次 BLR forward(廉价 O(D)),外层 sequential stage 真 query 仅 1 次。

> **TODO(GA 跟命令空间适配):** 4 个 GA 组件框架定了,但具体操作在命令空间上的实例化需跑通后调:**(a) Mutation Add 时新 op 的命令选择** — 从 §4 候选池均匀采样 vs 按 P_benign 频率加权;命令参数 args 模板填充策略;**(b) Mutation Move 时的边重定向约束** — 哪些 (src, dst) 组合在命令语义下合法(如文件读边只能 process → file);**(c) Crossover 跨 Δ 拼接的合法性** — 子序列交换后 partial order (R2) 是否仍成立,涉及共享变量(stdout pipe)的 op 链能否拆分;**(d) R1 / R2 硬过滤比例** — invalid 个体占比若高,要改 constrained mutation(直接生成合法的)而非先生成后过滤;**(e) 命令空间的有效搜索半径** — 1-edit neighborhood 在命令空间上"邻居"该怎么定义,Add/Remove 改 1 op 跟 Move 改 1 边的 effective 距离差很大。按 mutation/crossover 后有效个体比例 / 探索覆盖率 / 收敛速度评估。

#### Algorithm 1: SafeMimic-CMD

```
Input:  G_0 (原 attack graph), D_target, B_max = 20,
        β = 5 (Tchebycheff), β_LCB = 0.5, k = 5, τ = 0.5,
        T_GA = 50, m = 20
Output: Δ s.t. F(apply(Δ, G_0)) = ∅,或 ⊥

# ─── Init: reference warm-start (f_2 only), surrogate at prior ───
R_unflagged ← {G : G ∈ 30 benign traces}    # 用于 f_2 的 k-NN reference,无需 s
R_flagged   ← ∅
T ← ∅                                       # surrogate 训练数据,起步空
Δ ← ∅
BLR ← prior(μ_α = 0, Σ_α = λ⁻¹·I)            # Eq (6)-(8),无训练数据

# ─── Sequential perturbation selection (§5.3) ───
for t = 1 to B_max:
    # Inner GA on Δ sequence space (§5.4) — 0 真 query
    pop ← initialise_population(T, Δ, m)             # m 条 Δ 候选,从 T top-k 高 s 历史 mutation 而来
    for g = 1 to T_GA:
        for each Δ_i in pop:
            G_i = apply(Δ_i, G_0)
            μ, σ ← BLR(Φ(G_i))                       # surrogate forward
            α(Δ_i) ← μ - β_LCB · σ                   # Eq (12) LCB acquisition
        pop ← Selection(pop, by α) → Crossover(pop) → Mutation(pop)
    Δ_t* ← argmin_{Δ_i ∈ pop} α(Δ_i)                # GA 过程中 α 最低的 Δ

    # Stage commit + 1 真 query
    Δ ← Δ_t*                                        # 用 GA 选出的新 Δ 替换当前(可能比 Δ_{t-1} 长 / 短 / 等长)
    G_t = apply(Δ, G_0)
    g, F ← D_target(G_t)                            # 真 query (q_used += 1)

    # Early termination (Eq 3)
    if F = ∅:
        return Δ

    # Reference + surrogate update
    if F = ∅: R_unflagged ← R_unflagged ∪ {G_t}
    else:     R_flagged   ← R_flagged   ∪ {G_t}
    f_1, f_2 ← compute_f1_f2(G_t, R)                        # Eq (9), (10)
    s ← compute_tchebycheff(f_1, f_2)                       # Eq (11)
    T ← T ∪ {(Φ(G_t), s)}
    BLR posterior ← closed_form_update(BLR, Φ(G_t), s)

return ⊥                                                    # 预算耗尽
```

**Hyperparameters.**

| 参数 | 取值 | 来源 |
|---|---|---|
| B_max | 20 | 项目预算 |
| H (WL iterations) | 3 | GRABNEL 默认 |
| D (WL feature dim) | ≈ 200 | GRABNEL 默认 |
| k (k-NN k) | 5 | R_unflagged 起步 30 benign,k=5 稳 |
| β (Tchebycheff) | 5 | MOS-Attack 推荐 |
| β_LCB | 0.5 | GRABNEL 默认 |
| τ (detector threshold) | 0.5 | PIDSMaker 项目默认 |
| T_GA | 50 | GRABNEL 推荐 |
| m (GA population) | 20 | GRABNEL 推荐 |
| warm-start size | 31 (30 benign + G_0) | 项目手头 |

**参考论文:**
- **GRABNEL** [Wan et al. NeurIPS'21] §2 Optimisation of acquisition function block:LCB acquisition + 内层 GA(Initialisation 从已 query 历史 mutate、Evolution fitness = acquisition value)在 1-edit neighborhood 演化(本节直接对应,将 1-edit 推广到 §4 atomic op 序列空间)。
- **BagAmmo** [Tang et al. USENIX Sec'23] §5.3 Adversarial Multi-population co-evolution:GA 组件 (1) Population & Individual / (2) Fitness & Selection / (3) Crossover / (4) Mutation 的描述结构与数学表示(本节 (1)-(4) 直接对应,跳过 BagAmmo (3) Immigration)。
- **Srinivas et al.** [ICML'10] *Gaussian Process Optimization in the Bandit Setting*:GP-UCB / LCB acquisition function 原论文(本节 Eq (12) `α(Δ) = μ - β·σ` 出处)。

---

## 引用论文

| 论文 | 出处 | 在本文的角色 |
|---|---|---|
| **GRABNEL (Wan et al.)** | **NeurIPS'21** [arXiv 2111.02842](https://arxiv.org/abs/2111.02842) | **§5 主 anchor**:§5.2 WL features + Sparse BLR surrogate + §5.3 Sequential perturbation selection 框架 + §5.4 内层 GA + LCB acquisition |
| **FCGHunter (Sen Chen et al.)** | **TSE'25** | §5.3 双目标 fitness anchor:f_1 + f_2 双目标范式 |
| **MOS-Attack** | arXiv 2501.07251, 2025 | §5.3 soft-min Tchebycheff scalarization 公式(Eq 11) |
| **Shervashidze et al.** | JMLR'11 | §5.2 WL feature extractor 原论文 |
| **Srinivas et al.** | ICML'10 | §5.4 GP-UCB / LCB acquisition function 原论文 |
| MalGuise [Ling et al.] | USENIX Sec'24 | Problem Formulation 参考(Eq 1, 3, 4 形式) |
| EvadeDroid [Bostani et al.] | CnS'24 | Problem Formulation Eq 2 `argmin q_used` 参考 |
| ProvNinja [Mukherjee et al.] | USENIX Sec'23 | §5.1 motivation:扰动隐蔽性失效模式来源(P2 96.9%) |
| Contorter [Nasr et al.] | S&P'26 | §5.1 motivation:扰动隐蔽性失效模式来源(P2 100%) |
