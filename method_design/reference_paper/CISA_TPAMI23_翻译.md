# CISA:基于自定义迭代与采样的查询高效黑盒对抗攻击

**原文**:Yucheng Shi, Yahong Han, Qinghua Hu, Yi Yang, Qi Tian
**期刊**:IEEE Transactions on Pattern Analysis and Machine Intelligence (TPAMI), Vol. 45, No. 2, pp. 2226–2245, February 2023
**DOI**:10.1109/TPAMI.2022.3169802
**收稿/接收**:2021-10-07 / 2022-04-17;在线发布:2022-04-25
**通讯作者**:Yahong Han (yahong@tju.edu.cn)
**机构**:天津大学智能与计算学部、天津市认知计算与应用重点实验室;浙江大学;华为云 & AI
**代码**:https://github.com/shiyuchengTJU/CISA
**基金**:国家自然科学基金 61876130、61932009、61925602、61732011

---

## 摘要(Abstract)

在仅可查询目标模型的**黑盒设置**下欺骗深度神经网络分类器是一项挑战。当前黑盒攻击中:**迁移型攻击**倾向于在代理模型上**过拟合参数设置**;**决策型攻击**因固定采样和贪婪搜索策略导致**查询效率低、噪声方差大**。为同时缓解上述问题,本文提出一个新的查询高效黑盒攻击框架,把**迁移型攻击**与**决策型攻击**桥接起来,并揭示:决策型攻击的当前噪声与采样方差的关系、噪声压缩的单调性、状态转移函数对决策型攻击的影响。在新框架的指导下,本文提出 **CISA(Customized Iteration and Sampling Attack,自定义迭代与采样攻击)**。CISA 根据"最近邻决策边界距离"估计步长,使用**双向迭代轨迹**寻找中间对抗样本;随后基于中间对抗样本进行**自定义采样**进一步压缩噪声,并**松弛状态转移函数**以提升查询效率。大量实验证明 CISA 在黑盒对抗攻击的查询效率上具有优势。

**索引词**:对抗扰动、黑盒攻击、决策型攻击、迁移型攻击。

---

## 1. 引言(Introduction)

**第 1 段**:对抗样本 [1]、[2]、[3] 揭示了 DNN 的脆弱性。按攻击者对目标模型知识的多少 [4],对抗攻击分为**白盒攻击**(可访问梯度、训练数据、模型结构)与**黑盒攻击** [5](只能查询目标模型并获取预测)。

**第 2 段(黑盒的两个根本困难)**:
* 与白盒相比,**无法直接计算目标模型梯度**,因此不能用基于梯度/优化的攻击直接寻找小扰动 [4]
* 唯一的目标模型信息来源是**查询**,而查询通常代价高、数量受限 [5];在受限查询预算下,基于已找到的对抗样本压缩噪声幅度也很难 [6]

**第 3 段(三类黑盒攻击)**:
* **迁移型攻击** [7]、[8]:在**代理模型**上用白盒攻击生成对抗样本,再迁移到目标模型 [14]、[15]、[16]
* **决策型攻击** [9]、[17]、[18]:从已经误分类的对抗样本起步,通过在输入空间采样**逐步压缩**噪声幅度
* **基于零阶优化的攻击** [10]、[11]、[12]、[13]:通过查询估计目标模型梯度

**第 4 段(黑盒攻击的四大问题)**:在查询数受限、目标模型只返回硬标签的实际黑盒设置下,现有方法存在四个严重缺陷:

* **问题 1**:**迁移型攻击容易过拟合代理模型** [8]、[19]。代理与目标在模型结构和决策边界上有差异,代理上的成功参数(如步长、迭代次数)在目标模型上可能失效
* **问题 2**:**迁移型攻击难以在生成对抗样本后进一步压缩噪声**。它们只依赖代理模型,生成的对抗样本仅与代理相关 [14]、[15]、[16]。即使有方法 [18]、[20]、[21] 组合迁移型与决策型,仍缺乏**两者同时压缩冗余噪声**的机制
* **问题 3**:**现有决策型攻击查询效率低**。Boundary Attack [9] 等总是从**固定分布**采样,与历史查询/当前噪声无关,从不改变采样分布;单步修改的步长也是常数。随着噪声幅度下降,查询成功率会下降,固定步长进一步影响压缩效率
* **问题 4**:**决策型攻击容易陷入局部最优**。Boundary Attack 等贪婪策略只接受比当前噪声更小的对抗样本,几步压缩后会陷入局部最优,后期搜索效率大幅下降

**第 5 段(本文框架)**:提出由 **4 个模块**组成的查询高效黑盒攻击框架(Fig. 1):

* **PAM**(Parameter Adjustment Module,参数调整模块)和 **TAM**(Transfer Attack Module,迁移攻击模块)用于设置攻击参数并在代理模型上生成中间对抗样本
* 获得中间对抗样本后,**NCM**(Noise Compression Module,噪声压缩模块)用**剩余查询数**搜索噪声幅度更小的对抗样本
* **STM**(State Transition Module,状态转移模块)用于调整搜索方向

值得注意:**该框架不强制要求代理模型**;若无代理模型,只需把 TAM 替换为生成中间对抗样本的其它方法(如高斯噪声)。所有现有迁移型与决策型攻击都可纳入此框架。

**第 6 段(CISA 概览)**:在新框架基础上,提出 **CISA(自定义迭代与采样攻击)**:

* **PAM**:在原图加高斯噪声,通过逐步增加高斯方差找到对抗样本;以该对抗样本与原图的距离设置步长
* **TAM**:沿代理模型损失函数的**梯度上升与梯度下降两个方向**迭代,使迭代轨迹弯曲,从而以**更近的距离**穿越目标模型决策边界
* **NCM**:在第三步**自适应调整采样过程的方差、均值、步长、掩码**,提升查询效率。不再使用 Boundary Attack 那种各向同性单位方差,而是把多元正态的方差**与当前噪声的绝对值线性相关**;用历史失败样本**自定义采样均值**——新样本被引导**远离失败方向**;同时根据噪声压缩进展调整步长与掩码
* **STM**:**松弛决策型攻击的接受条件**,降低搜索陷入局部最优的概率

**第 7 段(理论分析与贡献)**:
* 分析了决策型攻击采样分布与噪声压缩的关系、噪声压缩的单调性、状态转移函数对收敛的影响,为后续黑盒攻击设计提供启发
* 在 ImageNet [23]、Tiny-ImageNet [24]、CIFAR-10 [25] 上对现有方法在新框架下进行全面评估,验证了:1) 新框架显著提升查询效率;2) CISA 在 $\ell_2$ 范数下生成的扰动幅度**低于任何现有攻击的组合**

---

## 2. 背景(Background)

### 2.1 记号(Notation)

考虑目标 DNN 模型 $F: X^N \to Y^C$,其中 $X$ 是输入空间,$N = \text{Width}\times\text{Height}\times\text{Channel}$ 为图像维度,$Y$ 是 $C$ 类的分类空间。成功的黑盒对抗攻击要在有限查询下最小化噪声幅度:

$$
\min_{x'\in S_Q}\ \|x'-x\|_v,\quad \text{s.t.}\ F(x)\ne F(x')\ \text{且}\ |S_Q|\le T \qquad (1)
$$

其中 $x$ 是原图,$S_Q$ 是所有误分类目标模型的对抗样本集合,$T$ 是查询数上限,$v$ 指用的范数(包括 $\ell_0$ [26]、$\ell_1$ [27]、$\ell_2$ [9]、$\ell_\infty$ [7])。本文用 $\ell_2$ 距离衡量噪声幅度。

实际黑盒设置有两点:1) 假设攻击者**可以**有限次数地查询目标模型(比完全无法查询 [15] 或可以无限次查询 [10] 更现实);2) 目标模型**只返回硬标签**(比能返回置信度 [4] 更现实)。

### 2.2 迁移型攻击(Transfer-Based Attack)

利用代理模型与目标模型间的**迁移性** [5]。代表方法:FGSM [7] 用交叉熵损失梯度的符号一步扰动;I-FGSM [14] 把扰动拆为多步;MI-FGSM [15] 引入动量使方向更平滑;Vr-IGSM [16] 用**多次加高斯噪声后**的平均梯度替代原图梯度,降低单图的随机性、提升迁移性。此外,还有研究关注**通用对抗扰动**的迁移性 [29]、[30]。

### 2.3 决策型攻击(Decision-Based Attack)

在原图邻域采样,寻找更小的噪声幅度且仍能跨越决策边界。决策型攻击**不依赖代理模型**,但需要**一个已被误分类的初始对抗样本**作为起点。Boundary Attack [9] 从高斯噪声起步,**同时沿两个方向搜索**——**球面方向**与**源方向**:

$$
x_{t+1} = x_t + \delta\cdot\frac{\eta}{\|\eta\|_2} + \varepsilon\cdot\frac{x-x_t}{\|x-x_t\|_2},\quad \eta\sim\mathcal{N}(0,I) \qquad (2)
$$

其中 $x_t$ 是 $t$ 步后的最小噪声对抗样本;$\eta$ 和 $(x-x_t)$ 是球面方向与源方向;$\delta$ 是球面方向步长,$\varepsilon$ 是源方向步长。由于每个维度都是无差别标准正态分布,Boundary Attack **无法评估和利用不同像素噪声敏感性的差异**。

许多决策型攻击基于 Boundary Attack 发展:
* **Evolutionary Attack** [17]:用双线性插值降采样空间维度、把噪声限制在图像中心
* **QEBA** [31]:子空间优化
* **NonLinear-BA** [32]:非线性梯度估计
* **AHA** [33]:聚合历史查询信息作为采样先验
* **SurFree** [34]:基于决策边界的几何机制
* **Whey** [35]:把对抗噪声分组压缩,但贪婪搜索易陷入局部最优
* **HopSkipJumpAttack** [6]:用边界二分搜索估计梯度方向;**PopSkipJump** [36] 把它扩展到概率分类器
* **Tangent attack** [37]:在虚半球上沿切线搜索
* **Sign-OPT** [38]:用零阶 oracle 计算方向导数符号,**仅靠单次查询**实现硬标签攻击

### 2.4 迁移型与决策型的交叠(Overlap)

近期出现了一些**结合两者**的工作:**LeBA** [20] 用决策型反馈更新迁移型的代理模型;**QAIR** [21] 用决策型攻击提取并近似目标模型,生成更可迁移的对抗样本;**DAIR** [39] 在图像检索模型上做高效采样;**Biased Boundary Attack (BBA)** [18] 用代理模型的迁移梯度集中采样在**低频域**,使对抗样本更"自然"。

**这些工作的目标与本文不同**:它们把一种黑盒攻击作为另一种的**辅助/优化**,而本文将**迁移型与决策型同时独立使用**,以更少查询找到并压缩对抗噪声。

---

## 3. 新黑盒攻击框架概览(Overview of New Black-Box Attack Framework)

四模块流水线见 Fig. 1 / Fig. 2:

### 3.1 PAM(参数调整模块)

迁移型攻击在代理模型上做优化,因代理与目标在模型结构和决策边界上存在差异,迁移性受限 [19]、[40]。同时,现有迁移型攻击有多个超参(如步长、迭代次数 [14]、[15]、[16]),代理上能成功的一组参数在目标上未必有效。

**PAM 用估计+查询的组合,为每张原图自适应**地选择攻击参数,利用目标模型反馈。具体方法见 4.1 节。

### 3.2 TAM(迁移攻击模块)

TAM 在**代理模型**上生成中间对抗样本——以原图为起点,用基于梯度/优化的攻击,按 PAM 给的参数构造扰动,输出"误分类目标模型的对抗样本"。几乎所有基于梯度 [7]、[14]、[15]、[16]、[41]、[42] 或基于优化 [43]、[44]、[45] 的攻击都可嵌入 TAM。本文 4.2 节提出新的 TAM 方案,通过**轨迹多样化**解决迁移性差和迭代边际效应递减的问题。

### 3.3 NCM(噪声压缩模块)

NCM 进一步压缩噪声幅度。它把 TAM 的中间对抗样本当作起点,在邻域内采样寻找更小噪声的对抗样本。所有现有决策型黑盒攻击 [6]、[9]、[17]、[18]、[35] 都可纳入 NCM。本文 4.3 节提出新的**自定义采样**方案,缓解决策型攻击查询效率低的问题。

### 3.4 STM(状态转移模块)

STM 控制噪声压缩过程中对抗样本的更新。决策型攻击的状态转移**通常很贪婪**:只有当新样本既误分类又更接近原图,才接受新样本——这种贪婪在 4.4 节将被证明会陷入局部最优。本文提出**松弛状态转移函数**,以降低陷入局部最优的概率。

**注意**:此框架不限于具体方法。所有基于梯度/优化的攻击都可嵌入 TAM,决策型攻击都可嵌入 NCM。即使**没有代理模型**,NCM 和 STM 仍能工作——只需用替代噪声(如高斯噪声)生成中间对抗样本即可。

---

## 4. CISA(Customized Iteration and Sampling Attack)

CISA 的总体流程见 Fig. 2:给定原图,PAM 用**高斯步长调整**确定步长,TAM 用**双向迭代轨迹**在代理模型上生成首个中间对抗样本;然后用剩余查询数做**自定义采样**压缩噪声幅度,其中采样过程的方差、均值、掩码、转移函数分别由当前噪声、历史失败查询、当前噪声绝对值、剩余查询数自定义。

### 4.1 高斯步长调整(Gaussian Stepsize Adjustment)

步长 $\mu$ 是迁移型攻击的关键参数:大步长 → 查询次数少但噪声幅度大;小步长 → 噪声小但查询多。已有两种朴素策略:

1. **固定步长** [14]、[15]、[16]:把步长当超参,所有图像共用同一组参数。但**最小成功扰动**因图而异,固定设置无法保证每张图都生成"噪声幅度足够小"的对抗样本
2. **二分搜索** [46]:多轮搜索找最优步长。能找到小扰动但**消耗大量查询**

**Gaussian Stepsize Adjustment(GSA)**——既不固定也不二分。在迁移型攻击迭代之前,先尝试**对原图加高斯噪声**寻找对抗样本:

$$
x^{Gau} = \text{Clip}_{x,\tau}\{x + \xi^{Gau}\},\quad \xi^{Gau}\sim\mathcal{N}(0,\text{var}^2 I) \qquad (3)
$$

其中 $\xi^{Gau}$ 是与 $x$ 同维度的高斯噪声,初始方差 $\text{var}_0$。**初始用小方差查询**目标模型;若输出未变,**方差翻倍**;否则停止,$x^{Gau}$ 即邻域内的高斯对抗样本。再用 $x^{Gau}$ 与 $x$ 的 $\ell_2$ 距离设定后续迭代步长:

$$
\hat\mu = \min_{t\in\mathbb{N}}\ \|\text{Clip}_{x,\tau}\{x + \xi_t^{Gau}\} - x\|_2 / T,\quad \xi_t^{Gau}\sim\mathcal{N}(0,(2^t\cdot \text{var}_0)^2 I) \qquad (4)
$$

约束 $F(x)\ne F(\text{Clip}_{x,\tau}\{x + \xi^{Gau}\})$,其中 $T$ 是迁移型攻击的总迭代步数。由于基于迭代方法生成的扰动幅度通常**小于**基于高斯噪声的扰动 [47],$\|x^{Gau}-x\|_2/T$ 可以**保守地**保证对抗样本在 $T$ 步内被找到。

Fig. 3 直观展示:粉色椭圆环代表用于步长调整的高斯对抗样本,黑色曲线是"tusker"与"panda"的决策边界。**GSA 比二分搜索显著减少查询数**,且适应每张图的最近边界距离。

### 4.2 迭代轨迹多样化(Iterative Trajectory Diversification)

适配迁移型攻击到受限查询的黑盒设置面临两个问题:

* **代理与目标的梯度方向可能正交** [19]
* **迭代次数增加的边际效应递减**:I-FGSM 中,把查询数 $T$ 增到 $T+1$ 时,噪声压缩的边际增益是
  $$
  \sum_{t=1}^{T+1}\frac{1}{T+1}\cdot\nabla J_{sub}(x_t) - \sum_{t=1}^{T}\frac{1}{T}\cdot\nabla J_{sub}(x_t) \qquad (5)
  $$
  随 $T$ 增大、单步步长缩短,迭代轨迹趋于一致、收敛缓慢

**归因**:1) 沿代理损失梯度上升的迭代倾向于陷入**代理模型的局部最优**,而非跨越**目标模型**的决策边界;2) 简单依赖迁移性、忽略每次查询后目标模型的反馈,缺乏适应性。

**思路**:**轨迹多样化** [48]。Fig. 4 显示一种目标损失分布:沿梯度上升方向(绿色)损失上升慢,但**从近邻起点出发可能穿越决策边界**(紫色)。因此**放弃单一的梯度上升路径**,改用双向迭代:

$$
x_0' = x,\quad x_1' = \text{Clip}_{x,\tau}\{x_0' - \mu\cdot\nabla J_{sub}(x_0')\} \qquad (6)
$$

$$
g_{t+1} = \begin{cases}-\nabla J_{sub}(x_t'),&\ J_{sub}(x_t') < J_{sub}(x_{t-1}')\\ \nabla J_{sub}(x_t'),&\ J_{sub}(x_t')\ge J_{sub}(x_{t-1}')\end{cases} \qquad (7)
$$

$$
x_{t+1}' = \text{Clip}_{x,\tau}\{x_t' + \mu\cdot g_{t+1}\} \qquad (8)
$$

其中 $J_{sub}$ 是代理模型的交叉熵损失。先沿梯度下降扰动原图一步;只要代理损失仍在下降,就**继续梯度下降**;否则切到梯度上升。**实际实现**:为避免对抗噪声更新震荡,不直接判梯度符号,而是每轮分两阶段——第一阶段对原图做梯度下降,代理损失开始低于上一步时第二阶段切到梯度上升直到最后一步。受 Vr-IGSM [16] 启发,梯度计算中加高斯噪声以提升迁移性。

Fig. 4 中,绿色与紫色折线分别表示梯度上升与下降的迭代轨迹。TAM 用双向轨迹同时从两个方向加扰动,**提供中间对抗样本给 NCM**。

### 4.3 自定义采样(Customized Sampling)

#### 4.3.1 从中间对抗样本起步的优势

首先实证证明:**用迁移型攻击的中间对抗样本作为决策型攻击起点,优于从高斯噪声起步**。在 ImageNet 上选 1000 张原图,生成不同噪声幅度的对抗样本,对每个样本重复 Boundary Attack 1000 次,统计误分类概率(Fig. 5):**原图邻域内,噪声压缩的概率与噪声幅度正相关**。

#### 4.3.2 噪声压缩单调性的理论分析

假设误分类概率 $\rho_{F,x}(\lambda)$ 关于距离 $\lambda$ 单调递增(在一定范围内)[28]:
$$
\rho_{F,x}(\lambda) = \mathbb{P}_{z\sim\lambda S}\{F(x)\ne F(x+z)\} \qquad (9)
$$
其中 $\lambda S$ 是球面均匀分布。设 $\Delta_{adv}(x;F)\le\lambda\le\Delta_{unif,\kappa}(x;F)$ 内单调。

**命题 1**:在此假设下,对任意两个对抗样本 $x_1', x_2'$ 满足 $\Delta_{adv}\le\lambda_2<\lambda_1\le\Delta_{unif,\kappa}$,一步决策型攻击后期望噪声幅度满足 $\mathbb{E}(\lambda_2) < \mathbb{E}(\lambda_1)$。

证明(摘要):考虑期望
$$
\mathbb{E}(\lambda) = \int_{\Delta_{adv}(x;F)}^\lambda a\rho(a)\frac{1}{\lambda - \Delta_{adv}(x;F)}\,da \qquad (10)
$$
由于 $\Delta_{adv}(x;F)$ 难以求得且 $\rho(a) = 0$ 当 $\lambda \le \Delta_{adv}(x;F)$ 时,可将其改写为:
$$
\mathbb{E}(\lambda) = \int_0^\lambda a\rho(a)\frac{1}{\lambda}\,da \qquad (11)
$$
化简后利用 $\rho$ 的单调性可得 $\mathbb{E}(\lambda_1) - \mathbb{E}(\lambda_2) > 0$。**结论**:决策型攻击的更新满足**无记忆性(memorylessness)**——一步后的期望噪声只与上一步的噪声有关。由此**多步的单调性具有传递性**:在同一决策型攻击和相同查询数下,最终噪声幅度与**初始噪声幅度正相关**。

**这解释了**为何"用迁移型攻击 → 决策型攻击"是有效的桥接:决策型方法如 Boundary Attack 用大幅高斯噪声初始化,最终噪声也大;改用迁移型攻击的中间对抗样本(噪声小)作初始,**最终噪声也小**。

### 4.3.3 自定义采样三件套

NCM 用自定义采样压缩中间对抗样本的噪声。设 $x^{*}$ 是当前最小噪声对抗样本,目标是

$$
\max_{x'}\ \|x^{*}-x\|_2 - \|x'-x\|_2,\quad \text{s.t.}\ F(x)\ne F(x') \qquad (12)
$$

把 $x^{*}, x'$ 写成原图加噪声 $z^{*}, z^{*}+z$,等价转化为

$$
\min_z\ \|z^{*}+z\|_2,\quad \text{s.t.}\ F(x)\ne F(x+z^{*}+z) \qquad (13)
$$

代入 Boundary Attack 的更新 $z = \delta\cdot\eta/\|\eta\|_2 + \varepsilon\cdot(x-x^{*})/\|x-x^{*}\|_2$,化简后只需最小化 $z^{*}\bullet \eta/\|\eta\|_2$。由 **Cauchy-Schwarz 不等式**:

$$
-\|z^{*}\|_2\cdot\|\eta\|_2\ \le\ z^{*}\bullet\eta\ \le\ \|z^{*}\|_2\cdot\|\eta\|_2 \qquad (14)
$$

可得 $\|z^{*}+z\|_2 \ge \|\,\|\alpha\cdot z^{*}\|_2 - \|\delta\cdot\beta\|_2\,\|$;当 $z^{*} = -k\beta$($k\in\mathbb{R}^+$,$\beta=\eta/\|\eta\|_2$)取等号,即 $\eta$ 与 $-z^{*}$ 同向时**噪声压缩最大化**。

设 $\eta\sim\mathcal{N}(0,\Sigma)$,$\Sigma=\text{diag}(\sigma_1^2,\dots,\sigma_N^2)$。每个 $\eta_i$ 是单变量正态,其平方期望比:
$$
E(\beta_1^2):E(\beta_2^2):\cdots:E(\beta_N^2) = \sigma_1^2:\sigma_2^2:\cdots:\sigma_N^2
$$
**只有当 $z^{*}\bullet \eta\le 0$ 时 Boundary Attack 才查询目标模型**。所以期望最小化要求 $\sigma_i\propto |z_i^{*}|$,即**方差与当前噪声绝对值线性相关**。

**直观对比**(Fig. 6):
* 当 $\sigma_1:\sigma_2 = 3:1 = x_1^{*2}:x_2^{*2}$,采样分布集中在 $-x^{*}$ 反方向,**高效压缩噪声**
* 当 $\sigma_1:\sigma_2 = 1:1$(各向同性,Boundary Attack 的设定),采样均匀分布,**压缩效率低**

#### (a) 方差自定义(Variance Customization)

**降低采样空间维度**对噪声压缩至关重要。Evolutionary Attack [17] 用双线性插值与限制到图像中心降维,这种"按位置定义敏感性"对人脸等单结构小图有效,但对大而复杂图像不适用。当前噪声 $z^{*}$ 是**比人工规则更无偏的像素敏感性表征**。因此,只在**当前噪声已经较大**的像素上调整:

$$
H(z, r) = \arg\max_{\hat z\subset z^{*}, |\hat z|/|z^{*}| = r} \sum_{z\in\hat z} |z| \qquad (15)
$$

$$
\text{mask}_i = \begin{cases}1, & \text{if}\ z_i^{*}\in H \\ 0, & \text{else}\end{cases} \qquad (16)
$$

$r\in(0,1)$ 控制保留的像素比例。**用 mask 过滤掉不敏感区域**,使新噪声只加在最敏感像素上。

#### (b) 均值自定义(Mean Customization)

已有的决策型攻击**直接丢弃失败样本**,但失败样本其实**包含决策边界信息**。CISA 用失败样本调整采样均值,使新样本**远离失败方向**:

$$
\eta\sim\mathcal{N}\left(-\frac{1}{K}\sum_{j=1}^K \tilde\eta_j,\ z^{*2}\right),\quad \text{s.t.}\ F\left(x + \delta\cdot\frac{\tilde\eta}{\|\tilde\eta\|_2} + \varepsilon\cdot\frac{x-x^{*}}{\|x-x^{*}\|_2}\right) = F(x) \qquad
$$

$K$ 是当前对抗样本 $x^{*}$ 上失败采样的总数,$\tilde\eta_j$ 是第 $j$ 个失败方向。维护一个失败样本记录 $\tilde z$ 持续更新,直到一次成功(噪声进一步压缩)。在决策型攻击后期,采样成功率随噪声幅度减小而下降,**保留记录使新样本能持续远离历史失败方向**(Fig. 7)。

#### (c) 步长自定义(Stepsize Customization)

随着噪声幅度持续压缩,在固定 $\delta, \varepsilon$ 下,新查询的误分类概率会逐步下降。为补偿成功率下降,用**指数调度**动态调整两方向的步长:

$$
\delta_s = \delta_0 \varphi^s,\quad \varepsilon_s = \varepsilon_0 \varphi^s \qquad (17)
$$

其中 $s$ 是迄今为止的成功查询数,$\varphi\in(0,1)$ 是衰减因子。**最近邻对抗样本与原图距离缩短时,新查询的步长同步缩小**。指数调度平衡了**查询成功率与噪声压缩率**。

### 4.4 状态转移函数松弛(Transition Function Relaxation)

考虑 Boundary Attack 的状态转移函数(只接受噪声幅度更小的对抗样本)。设 $X^P$ 是原图 $x$、目标模型 $F$ 的所有可能 Boundary Attack 对抗样本集合:

$$
X^P = \{x^\circ\mid\exists\,\tilde x\in X^P\cup\{x^{*}\},\ \eta\sim\mathcal{N}(0,I),\ x^\circ = \tilde x + \delta\cdot\frac{\eta}{\|\eta\|_2} + \varepsilon\cdot\frac{x-\tilde x}{\|x-\tilde x\|_2},\ F(x)\ne F(x^\circ)\}
$$

原始转移函数:
$$
B_t(x^\circ) = \begin{cases}\tilde x, & \text{if}\ F(x)\ne F(\tilde x)\ \text{且}\ \|x-\tilde x\|_2\le\|x-x^\circ\|_2 \\ x^\circ, & \text{else}\end{cases} \qquad (18)
$$

**Boundary Attack 的更新满足 Markov 性**,Boundary Attack 在 $X^P$ 上构成有限状态马尔可夫链。但 $X^P$ 中**有些样本可能不可达**:若当前 $x_j$ 已经是一步内可达的最小噪声样本,那么 $x_i$($\|x-x_i\|<\|x-x_j\|$)就**不可达**——这就是局部最优。

**松弛转移函数**:以一定概率接受**噪声更大**的对抗样本:

$$
B_t(x^\circ) = \begin{cases}\tilde x, & F(x)\ne F(\tilde x)\ \text{且}\ \|x-\tilde x\|_2\le\|x-x^\circ\|_2 \\ \tilde x, & F(x)\ne F(\tilde x)\ \text{且}\ \|x-\tilde x\|_2 > \|x-x^\circ\|_2\ \text{且}\ \text{random}() < \omega \\ x^\circ, & \text{else}\end{cases} \qquad (22)
$$

其中 $0\le\omega\le 1$ 是接受"更大噪声"的概率,$\text{random}()$ 是 $[0,1]$ 均匀随机数。

**命题 2**:在松弛转移函数下,若源步长 $\varepsilon$ 小于球面步长 $\delta$,且 $\omega>0$,则对任意 $x_i, x_j\in X^P$,$\lim_{m\to\infty} U_{i,j}^m(t) = \pi_j(t)$。
**证明思路**:松弛后转移函数允许更新带任意噪声幅度,$X^P$ 在每个有限步 $t$ 后保持不变;因此 $X^P$ 上构成**不可约非周期马尔可夫链**(状态数 $\ll 256^N$,$N$ 是输入维度),由 Theorem 2.1 [50] 极限存在。

**实现细节**:由于决策型攻击后期成功率随噪声减小而下降,更易陷入局部最优,CISA 设 $\omega = t/T$,即随采样过程推进逐步增加接受较大噪声的概率,并更新 NCM 的下次采样起点。

### Algorithm 1:CISA 算法主体

```
输入:目标模型 F,代理模型 Sub
       原图 x,真实标签 y
       最大查询数 T,噪声幅度上限 τ
       梯度计算的高斯噪声方差 R
       初始 GSA 高斯方差 var
       与 x 同维的单位矩阵 I
       初始球面步长 δ₀,源步长 ε₀
       衰减因子 φ,像素保留率 r
       [0,1] 均匀随机数生成器 random()

输出:压缩噪声的对抗样本 x*

// PAM: Gaussian Stepsize Adjustment
while F(x^Gau) = y:
    ξ^Gau ← N(0, var² I);  x^Gau ← Clip_{x,τ}{x + ξ^Gau}
    var ← var × 2
    μ̂ ← ||x^Gau - x||₂ / T;  x'_t ← x, x'^B ← x, downhill ← True

// TAM: Iterative Trajectory Diversification
while T > 0:
    ξ_t^A, ξ_t^B ← N(0, R² I)
    g_t^A ← -∇J_sub(x_t^A + ξ_t^A);  g_t^B ← ∇J_sub(x_t^B + ξ_t^B)
    x_{t+1}^A ← Clip{x_t^A + μ̂·g_t^A}  if downhill else  Clip{x_t^A - μ̂·g_t^A}
    x_{t+1}^B ← Clip{x_t^B + μ̂·g_t^B}
    if J_sub(x_{t+1}^A) > J_sub(x_t^A): downhill ← False
    if F(x_t^A) ≠ y: x' ← x_t^A, T ← T - 1, break
    if F(x_t^B) ≠ y: x' ← x_t^B, T ← T - 1, break
    T ← T - 2

// NCM: Customized Sampling
W ← [], s ← 0, x* ← x', z* ← x* - x
while T > 0:
    if W ≠ ∅:  η ~ N(-1/|W| · Σ η̃_j, z*²),  s.t. η̃ ∈ W
    else:      η ~ N(0, z*²)
    // 选噪声绝对值最大的像素
    H(z,r) = argmax_{ẑ ⊂ z*, |ẑ|/|z*| = r} Σ |z|
    构造 mask
    x' ← x* + mask · (δ_s · η/||η||₂ + ε_s · (x-x*)/||x-x*||₂)
    T ← T - 1
    if F(x') ≠ y:
        // STM: Transition Function Customization
        if ||x'-x||₂ < ||x*-x||₂ OR random() < t/T:
            x* ← x', W ← [], s ← s+1, δ_s ← δ_{s-1}·φ, ε_s ← ε_{s-1}·φ
        else:
            W ← W ∪ η
return x*
```

---

## 5. 实验(Experiments)

### 5.1 实验设置

**数据集**:ImageNet [23](1000 类,选 10000 张能被所有目标模型正确分类的验证集图像)、Tiny-ImageNet [24](200 类,选 2000 张,每类 10 张)、CIFAR-10 [25](10000 测试图像)。

**目标模型**:8 种不同结构 — ResNet-18 [51]、ResNet-101、Inception-V3 [52]、Inception-ResNet-V2 [53]、NASNet [54]、DenseNet-161 [55]、VGG-19-BN [56]、SENet-154 [57]。

**对比攻击**:
* 迁移型(7 种):FGSM [7]、I-FGSM [14]、MI-FGSM [15]、Vr-IGSM [16]、DDN [41]、C&W [43]、EAD [45]
* 决策型(8 种):Boundary Attack [9]、Whey [35]、BBA [18]、Evolutionary [17]、HSJA [6]、Tangent [37]、Sign-OPT [38]、QEBA [31]

**CISA 超参**:$\delta_0=0.1, \varepsilon_0=0.003$(Boundary/BBA/Evo/CISA 共用),$\varphi=0.99$,Iterative Trajectory Diversification 的初始高斯方差 $\text{var}=1$,梯度计算高斯方差 $R=1$,像素保留率 $r=0.2$。**BBA [18]** 采用"每步利用代理模型信息"的版本。FGSM/I-FGSM/MI-FGSM/vr-IGSM 的步长用二分搜索调整。

**查询数分配协议**:除 'Random' 和 'CI' 外,其它迁移型攻击在 'Vanilla' 情形下对目标模型查询 1000 次,在其它情形下查询 500 次,留 500 次给 NCM 中的决策型攻击。对抗样本被舍入(rounding)后再送目标模型以模拟更真实的黑盒场景。

**评估指标**(NIPS 2018 对抗视觉挑战 [24]):
$$
\text{mid} = \text{median}(\{\|x'-x\|_2\mid x\in X\}),\quad \text{avg} = \frac{1}{n_{data}}\sum(\{\|x'-x\|_2\mid x\in X\}) \qquad (23,24)
$$

若一张图 1000 次查询内仍无对抗样本,该图噪声幅度记为 80(惩罚)。

### 5.2 新框架下的对比(Table 1–5)

每张表的第一行是目标-代理模型对,每后续行是迁移型攻击 + 其 PAM,每列是 NCM 中的噪声压缩策略 + STM。'N/A' 表示该模块未启用;'Binary Search' 是二分搜索步长;'GSA' 是本文 4.1 提出的高斯步长调整。'CI' 表示 CISA 在生成中间对抗样本前的过程(GSA + 双向轨迹多样化);'CS' 是 CISA 提出的自定义采样 + 转移松弛。

**核心发现**:
1. **同一迁移型攻击**(同行):用一半查询做二分搜索得到的对抗样本(Vanilla)的噪声 > 用另一半查询做后续压缩(Greedy Search)的噪声 → 说明 NCM 用决策型压缩噪声**优于单独二分搜索**
2. **同一决策型攻击**(同列):用高斯噪声作起点(Random)的最终噪声 > 用迁移型中间对抗样本作起点 → 验证 PAM 用迁移型生成起点的优势
3. **CISA 在所有目标-代理组合上获得最小中位/平均噪声**;尤其相对于"Random+Boundary"(原始 Boundary Attack),CISA 大幅降低噪声

### 5.3 多模型黑盒攻击(Table 6, 7)

在不同 target-substitute 组合下,**CISA 在所有 4 个目标模型上获得最小的中位/平均 $\ell_2$ 范数**,跨多个数据集均成立。同样查询数下,CISA 比 14 种其它攻击都更小。将随机高斯起点替换为 CISA 生成的中间对抗样本后,所有决策型攻击的噪声幅度**显著下降**——再次验证迁移+决策结合的有效性。

### 5.4 消融研究(Ablation Study,Table 8)

在 Tiny-ImageNet 上,用 **4 个代理-目标模型组合**(res-18→inc-res、nasnet→inc-v3、inc-res→nasnet、inc-v3→inc-res)逐项移除 CISA 的模块,测试每个组件的贡献。Table 8 列出 6 项消融:**w/o Gaussian Stepsize Adjustment**(无 GSA)、**w/o Iterative Trajectory Diversification**(无双向迭代轨迹)、**w/o Variance Customization**(无方差自定义)、**w/o Mean Customization**(无均值自定义)、**w/o Stepsize Customization**(无步长自定义)、**w/o Transition Function Relaxation**(无转移松弛)。结果:**每一项都对降低噪声幅度有贡献,简单移除任一项都会让噪声增大**。

**查询数预算 vs 噪声压缩(Fig. 8, 9)**:为更进一步验证 CISA 的噪声压缩能力,用 CISA 的 PAM 和 TAM(记为 'CI')先生成 10000 张 ImageNet 中间对抗样本(代理 DenseNet-161,目标 VGG-19),再用不同决策型攻击在每张上分别查询 10000 次。**平均噪声率**定义为:

$$
\text{Mean noise ratio} = \frac{1}{n_{data}}\sum_{i=1}^{n_{data}}\left(\frac{\|x^{*}-x_i\|_2}{\|x_i^{*}-x_i\|_2}\mid x\in X\right) \qquad (25)
$$

其中 $x_i^{*}$ 是 CI 生成的中间对抗样本,$x^{*}$ 是后续决策型攻击的输出。结果:
* 把 Vr-IGSM 和 Boundary Attack 用不同查询分配比例组合(20% Vr-IGSM + 80% Boundary 等),CISA 的红色曲线在不同数据集与查询数下**始终低于所有组合**
* 决策型对中间对抗样本的查询数越多越能精修
* CISA 的 PAM 用 GSA 动态分配 TAM 查询数,**查询效率显著优于固定查询数分配比例**
* 在 ImageNet 上,**CISA 用约 2000 次查询即达 20% 平均噪声率**,其它决策型方法需 10000+ 次

**对抗训练模型与集成模型(Table 9, 10)**:
* **以 ResNet-18 为代理模型**,攻击 3 个对抗训练目标模型(DenseNet-161 [58]、Inception-V4 [53]、VGG-19)以及由这 3 个模型组成的集成模型(Tiny-ImageNet)
* 9 种迁移型攻击的成功率仍接近 100%——防御主要**增加**扰动幅度,不阻止攻击成功(Table 9)
* 决策型攻击的成功率不受影响,因为本文中迁移型攻击的目标只是生成"中间对抗样本"供后续噪声压缩
* 但 CISA 生成的 $\ell_2$ 范数(Table 10)仍**远低于其它方法**,验证 CISA 在对抗训练模型与集成模型上仍保持强压缩能力

**对抗样本可视化(Fig. 10)**:在 ImageNet 上,展示 5 种攻击的对抗样本——CISA 的中间对抗样本(Intermediate Adv. Example)、Noise (CI)、Noise (CISA)、CISA、I-FGSM、Boundary、BBA;最右一列对比 5 种攻击的 $\ell_2$ 噪声幅度。所有方法对每张图都做 1000 次查询;ResNet-101 与 VGG-19 分别作为 I-FGSM 与 CI 的目标/代理。**CISA 在相同查询数下生成噪声幅度明显更小**的对抗样本。

---

## 6. 结论(Conclusion)

本文提出一个由 **PAM、TAM、NCM、STM** 四模块组成的、面向受限查询数的黑盒对抗攻击框架。基于该框架进一步提出 **CISA**:

* **PAM**:**Gaussian Stepsize Adjustment** 自适应设置迁移型攻击步长
* **TAM**:**梯度上升+下降双向迭代**轨迹,提升中间对抗样本的迁移性
* **NCM**:**自定义采样**——基于当前噪声调整方差、基于失败查询调整均值、基于绝对值调整掩码、基于剩余查询数调整步长
* **STM**:基于噪声压缩单调性的理论分析,**松弛状态转移函数**降低陷入局部最优

在三个数据集上的实验验证了新框架的可行性与泛化能力,以及 CISA 在 $\ell_2$ 范数下生成噪声幅度**显著低于现有迁移型与决策型方法**。

---

## 关键参考文献

* [1] Szegedy et al., "Intriguing properties of neural networks," ICLR 2013.
* [4] Akhtar et al., "Attack to fool and explain deep networks," IEEE TPAMI 2021.
* [5] Papernot, McDaniel, Goodfellow, Jha, Celik, Swami, "Practical black-box attacks against machine learning," AsiaCCS 2017.
* [6] Chen, Jordan, Wainwright, "HopSkipJumpAttack: A query-efficient decision-based attack," IEEE S&P 2020. — **HSJA**
* [7] Goodfellow, Shlens, Szegedy, "Explaining and harnessing adversarial examples," ICLR 2015. — **FGSM**
* [9] Wieland Brendel, Bethge, "Decision-based adversarial attacks: Reliable attacks against black-box machine learning models," ICLR 2018. — **Boundary Attack**
* [14] Kurakin, Goodfellow, Bengio, "Adversarial examples in the physical world," ICLR-W 2017. — **I-FGSM**
* [15] Dong et al., "Boosting adversarial attacks with momentum," CVPR 2018. — **MI-FGSM**
* [16] Wu et al., "Understanding and enhancing the transferability of adversarial examples," arXiv:1802.09707, 2018. — **Vr-IGSM**
* [17] Dong et al., "Efficient decision-based black-box adversarial attacks on face recognition," CVPR 2019. — **Evolutionary Attack**
* [18] Brunner et al., "Guessing smart: Biased sampling for efficient black-box adversarial attacks," ICCV 2019. — **BBA**
* [31] Li et al., "QEBA: Query-efficient boundary-based blackbox attack," CVPR 2020.
* [32] Li et al., "Nonlinear projection based gradient estimation for query efficient blackbox attacks," AISTATS 2021. — **NonLinear-BA**
* [35] Vo, Abbasnejad, Ranasinghe, "Query-efficient decision-based sparse attacks against black-box machine learning models," ICLR 2021. — **Whey**
* [37] Ma, Guo, Chen, Yong, Wang, "Finding optimal tangent points for reducing distortions of hard-label attacks," NeurIPS 2021. — **Tangent attack**
* [38] Cheng, Singh, Chen, Chen, Liu, Hsieh, "Sign-OPT: A query-efficient hard-label adversarial attack," ICLR 2019. — **Sign-OPT**

完整 58 条参考文献见原 PDF 第 2243–2244 页。

---

## 作者简介

* **Yucheng Shi**:2017 年天津大学学士;现为天津大学博士生。研究方向:计算机视觉、对抗机器学习、联邦学习。
* **Yahong Han(Member, IEEE,通讯作者)**:2012 年浙江大学博士;现为天津大学智能与计算学部教授;2014–2015 年加州大学伯克利分校访问学者(Bin Yu 课题组)。研究方向:多媒体分析、计算机视觉、机器学习。
* **Qinghua Hu(Senior Member, IEEE)**:哈尔滨工业大学学士/硕士/博士;现为天津大学人工智能学院院长、中国计算机联合会天津分会副主席、中国人工智能学会副主任。研究方向:大数据不确定性建模、多模态机器学习、智能无人系统。
* **Yi Yang(Senior Member, IEEE)**:2010 年浙江大学博士;现为浙江大学计算机学院教授;曾在 CMU 任博士后。研究方向:多媒体内容分析、视频内容理解。
* **Qi Tian(Fellow, IEEE)**:清华大学学士,UIUC 博士;华为云 & AI 首席科学家、UT San Antonio 计算机系教授、教育部长江学者讲座教授、中科院海外杰出人才。

---

## 译者备注:与 SafeMimic / PIDS 黑盒攻击的对应

CISA 的四模块结构在你的 PIDS 黑盒攻击场景中可一一对应:

| CISA 模块 | 在 PIDS / 离散图攻击场景中的对应 |
|---|---|
| **PAM** — Gaussian Stepsize Adjustment | "代理 PIDS 加随机图扰动,试探最小可触发误报的扰动幅度" → 设定后续图扰动迭代的步长(每轮操作数) |
| **TAM** — 双向迭代轨迹多样化 | 在代理 PIDS 上,**沿"提升攻击得分"和"降低告警概率"两个方向**交替施加图操作(加/删因果边、改进程标签) |
| **NCM** — 自定义采样 | 基于**当前图扰动**的敏感性(代理 PIDS 在哪些节点/边上反应大),定向采样下一轮的图操作 |
| **STM** — 转移函数松弛 | 离散图扰动空间易陷入局部最优,**以概率 $\omega = t/T$ 接受暂时更"坏"的扰动**,避免卡死 |

### 三个值得直接借鉴的洞见

1. **噪声压缩单调性的理论分析(命题 1)** —— 在 PIDS 攻击里,"初始扰动小 → 最终扰动小"同样成立。**用代理 PIDS 找到一个低扰动的初始攻击图,再做精化**,比从随机扰动起步效率高得多
2. **失败采样的复用(均值自定义)** —— PIDS 攻击迭代中,失败的图扰动**包含告警边界信息**,不应直接丢弃;CISA 的均值偏置思路可移植
3. **转移松弛 $\omega = t/T$** —— 在离散图扰动空间,贪婪策略的局部最优问题比连续空间更严重;CISA 给出的"随采样进度提高接受概率"是简洁的解决方案,可直接搬到 SafeMimic
