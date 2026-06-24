# PIDS 黑盒攻击论文写作思路推导
## 完全以 BagAmmo (USENIX Sec'23) 为唯一参考论文

## 工作约定

- 严格按 BagAmmo 论文章节顺序，从 §3 开始逐段推导
- 每段两步：① 分析 BagAmmo 这一段的写作思路 ② 输出适配到 PIDS 问题的写作思路骨架
- 输出的是"思路骨架"——告诉你这一段在做什么论证动作、怎么组织论证、关键变量怎么对应
- 不是抄 BagAmmo 的字，是仿照它的论证逻辑结构
- 触发命令：`mimic-init` / `mimic-next` / `mimic-§X.Y` / `mimic-revise §X.Y: ...` / `mimic-status`

## 核心问题设定

- **攻击目标**：基于 GNN 的 PIDS（如 ThreaTrace、Flash、Kairos、ShadeWatcher）
- **数据形式**：provenance graph（system-call 级）
- **攻击者修改空间**：shell 命令序列 $A$（**不是** smali code）
- **黑盒约束**：query-only，只返回 binary label
- **核心未知**：**detector 类型**（GNN / rule / hybrid，三类**数学上异质**）——这是相对 BagAmmo "feature granularity unknown"（同质，所有粒度共享 graph-classifier 框架）的**关键区别**
- **可实现性约束**：sandbox 执行获取真实 provenance 子图
- **参考论文**：BagAmmo 且**只**有 BagAmmo

## 符号约定

| BagAmmo | PIDS adaptation |
|---|---|
| $s$ (malware sample) | $A$ (attack command sequence) |
| $m$ (manipulation) | $\delta$ (perturbation) |
| $\text{MG}(\cdot)$ (code-to-graph) | $\text{MG}_{\text{cmd}}(\cdot)$ (command-to-provenance, 含 sandbox 执行) |
| $\text{MV}(\cdot)$ (graph-to-vector) | $\text{MV}_{\text{prov}}(\cdot)$ (provenance-to-feature, 类型相关) |
| $L(\cdot)$ (classifier label) | $L(\cdot)$ (保持不变) |
| Population $P_i$, $i \in \{\text{family}, \text{package}, \text{class}\}$ | Population $P_T$, $T \in \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$ |
| Individual $x_r^{(i,j)}$ | Individual $\delta_r^{(i,j)}$ |
| GCN substitute $S(\cdot)$ | Type-conditioned substitute set $\{S_T(\cdot)\}$ |
| Apoem (算法名) | 待用户决定（不擅自命名） |
| Try-catch trap (manipulation primitive) | Read-only / wrapper / split command primitives |
| Fig. 1 (FCG-based detection) | PIDS detection framework figure |
| Fig. 3 (AE generation overview) | Attack workflow figure |
| Fig. 6 (BagAmmo architecture) | Method architecture figure |
| Fig. 7 (Apoem co-evolution) | Co-evolution mechanism figure |
| Fig. 11 (survival proportion) | Type posterior convergence figure |

---

<!-- 后续段落由 mimic-next / mimic-§X.Y 追加在此分隔线之下 -->

## §3 章节引入 (chapter intro)

### 1. 翻译 (BagAmmo §3 中文)

本节首先介绍我们工作中考虑的系统和威胁，然后提出一个攻击形式化定义，用于指导黑盒对抗样本攻击的设计。

### 2. BagAmmo 的 Logical Structure

- 一句话 chapter teaser，给读者本章的路线图："先系统/威胁，再形式化"
- 不展开任何具体内容，纯过渡 / 路标作用
- 紧跟其后是 §3.1，无需 transition 段

### 3. 仿照的 Logical Structure

- 一句话 chapter teaser，按"PIDS 系统/威胁 → 攻击形式化"顺序
- 不展开内容，纯路标
- 紧跟 §3.1

### 4. 仿照段落的内容（中文）

> 本节首先介绍我们工作中考虑的 PIDS 系统及其威胁模型，然后提出一个攻击形式化定义，用于指导黑盒对抗样本攻击的设计。

---

## §3.1 System & Threat

### 1. 翻译 (BagAmmo §3.1 中文)

图 1 描绘了本工作所考虑的基于 FCG 的 Android 恶意软件检测系统。假设攻击者对该系统发起黑盒对抗样本攻击以生成真正可逃避检测的恶意软件。为此，攻击者首先从 APK 文件中获取 classes.dex 文件，并进一步将其反编译为一系列 smali 文件，如图 3 所示。攻击者根据其扰动修改 smali 代码，然后重新构建代码以获得新的 APK 文件。攻击者随后用生成的恶意样本去 query 检测系统，利用收到的二元判定（即 benign 或 malicious）来更新其扰动，并据此重新构建新的恶意样本。上述过程重复进行，直至获得一个真正可逃避检测的样本。

攻击者只知道目标系统使用 FCG 特征做恶意软件检测。但攻击者不知道目标系统使用的特征粒度和图嵌入方法。此外，攻击者对目标分类器的架构、参数和输出概率一无所知。至于防御方，可以使用静态分析和基于白名单的防御来抵御逃避样本。此外，当某用户的 query 数量异常多时，防御方可触发告警[^2]。

[^2]: 我们的实验表明，本方法仅需几十次 query 就能生成可成功攻击目标模型的扰动。此外，通过进行更多 query（如几百次），本方法可进一步减少扰动数量。为加速攻击过程，我们提供 substitute 网络拟合目标模型。相关实验见 §6.3。

### 2. BagAmmo 的 Logical Structure

- **第一段 = workflow narrative**：按 attacker 实操顺序走一遍流程 (拆 APK → 改 smali → rebuild → query → 用 binary 反馈 update → loop)，threat model 嵌入流程而非单列
- **第二段 = known / unknown / defender 三元对偶**：先列 attacker known（一个），再列 attacker unknown（三个：feature granularity / embedding method / classifier 内部），再列 defender 防御（三个：static / whitelist / query-rate alarm）
- 通过双图锚定（Fig. 1 = defender 视角，Fig. 3 = attacker 视角）让 threat boundary 在图层面自然对齐
- "feature granularity unknown" 一句独立成立，作为后续 §5.4 substitute model 设计的核心伏笔
- defender 防御手段与 attacker capability 同段对称呈现，预防 reviewer "but defender could ..." 反问
- 收尾不做总结，靠 §3.2 形式化定义自然过渡

### 3. 仿照的 Logical Structure

- **第一段 = workflow narrative**：按 attacker 实操顺序走一遍 PIDS 域流程（已有命令序列 → 插 camouflage → sandbox 真跑 → query PIDS → 用 binary 反馈 update → loop），threat model 嵌入流程
- **第二段 = known / unknown / defender 三元对偶**：列 attacker known（target 是 PIDS）、attacker unknown（**detector 类型 / 内部 embedding 或规则 / 架构参数**）、defender 防御（sandbox 一致性检查 / 命令白名单 / query-rate alarm）
- 同样双图锚定（PIDS detection 流程图 = defender 视角，AE 生成流程图 = attacker 视角，含 sandbox 执行步）
- "detector 类型未知" 一句独立成立 + 显式 ★ 标 PIDS 异质性差异，作为 §5.4 type-conditioned substitute set 的核心伏笔
- defender 防御手段与 attacker capability 同段对称呈现
- 收尾不做总结，靠 §3.2 形式化过渡

### 4. 仿照段落的内容（中文）

**第一段 · workflow narrative**：

> 图 1 描绘了本工作所考虑的基于 PIDS 的 Linux 主机入侵检测系统。假设攻击者对该系统发起黑盒对抗样本攻击以获得真正可逃避检测的攻击执行。为此，攻击者首先持有原始攻击命令序列 $A_0 = (c_1, \ldots, c_k)$（来自 Cybench、PentestGPT 或红队 playbook 的标准化命令链，攻击者既会写也会跑）。攻击者根据其扰动 $\delta$ 在 $A_0$ 的命令之间插入 camouflage 命令，**在 sandbox 中真实执行**得到的扩展序列 $A_0 \oplus \delta$，由 OS audit / eBPF 自然产出 provenance 子图 $\widetilde{G} = \text{MG}_{\text{cmd}}(A_0 \oplus \delta)$，如图 3 所示。攻击者随后用 $\widetilde{G}$ 去 query PIDS，利用收到的二元判定（benign / malicious）来更新 $\delta$，并据此构造新的扩展序列。上述过程重复进行，直至获得一个真正可逃避检测的攻击执行轨迹。

> ★ **关键差异（注脚或行内强调）**：与基于 APK 静态特征提取的恶意软件检测不同，PIDS 的输入是 **OS 实际执行所产生的 trace**——攻击者无法在不真实执行的情况下"凭空"得到 provenance graph。这使得 sandbox 执行成为攻击 pipeline 中不可或缺的一步。

**第二段 · known / unknown / defender 防御**：

> 攻击者只知道目标系统是 PIDS（接受 provenance graph 输入，输出 benign / malicious 二元标签）。但攻击者不知道目标系统的 **detector 类型**——它可能是基于 GNN 的图分类器、基于一阶规则的检测引擎、或两者的混合。此外，攻击者对 detector 的内部 embedding 函数、规则集、判定阈值，以及架构、参数和输出概率一无所知。至于防御方，可以使用 规则检测、命令白名单防御来抵御扩展序列攻击。此外，当某用户的 query 数量异常多时，防御方可触发告警。

> ★ **PIDS-specific extension point（首次出现，显式 flag）**：与已有黑盒攻击设定（攻击者面对的是单一同质分类器家族，例如不同 feature 粒度下的 GCN）不同，PIDS 设定下的"未知"跨越**数学结构异质**的 detector 类型——黑盒 GNN 给出连续平滑、近似可微的响应；黑盒规则引擎给出离散尖锐、阶梯式的响应；混合 detector 介于二者之间。这一异质性意味着单一 substitute 模型无法跨类型泛化，是后续 §5.4 设计的核心动机。本段仅指出此差异的**存在**，具体如何应对在 §5.4 展开。

---

## §3.2 Attack Formulation

### 1. 翻译 (BagAmmo §3.2 中文)

为方便起见，我们首先用 $s$ 和 $m$ 分别表示恶意软件样本和扰动操作。然后用两个函数 $\text{MG}(\cdot)$ 和 $\text{MV}(\cdot)$ 表示图 1 中所示的代码到图（code-to-graph）映射和图到向量（graph-to-vector）映射。攻击者通过用 $m$ 对 $s$ 施加扰动，将输入图从 $G = \text{MG}(s)$ 改为 $\widetilde{G} = \text{MG}(s+m)$，其中 $G$ 和 $\widetilde{G}$ 分别代表原始 FCG 和扰动后的 FCG。设 $L(\cdot)$ 表示目标分类器预测的标签（即 benign 或 malicious）。那么所期望的对抗扰动 $m^*$ 可通过求解下式得到：

$$L(\text{MV}(\text{MG}(s))) \neq L(\text{MV}(\text{MG}(s+m^*))) \quad (1)$$

并需满足恶意软件功能保持的约束。

上述形式化指出了我们的两项任务：(1) 设计一种 manipulation 技术，在保持恶意软件功能的前提下修改恶意软件代码；(2) 开发一个对抗扰动生成算法以实现 $m^*$。由于 problem-feature space gap 与严格黑盒设定的挑战，$\text{MG}(\cdot)$ 与 $\text{MV}(\cdot)$ 对攻击者实际不可见。因此一击命中所需的对抗扰动极其困难。这促使我们设计一个进化算法（即 Apoem）逐步找到所需扰动。我们将在 §4 和 §5 分别讨论如何完成上述两项任务。

此外，机器学习社区已提出多种 graph adversarial attack 模型 [5,12,40,48,57,62,71]。尽管这些方法对我们有启发，但它们不能直接应用于我们的攻击，原因有二：第一，图对抗攻击模型从特征空间发起攻击，但针对 Android 恶意软件检测的攻击无法直接访问特征空间，必须通过修改 problem space 中的恶意软件代码来间接影响特征空间。第二，我们的攻击需满足实际要求（即 §4.1 讨论的 R1–R4），这些要求在现有图对抗攻击中缺失。因此，恶意软件对抗攻击设计需要专门研究。

### 2. BagAmmo 的 Logical Structure

- **第一段 = 符号引入 + 主方程 + 约束**：先定义 $s, m, \text{MG}(\cdot), \text{MV}(\cdot), L(\cdot)$ → 用方程 (1) 把"对抗扰动"形式化为"使 label 翻转的最小 $m^*$" → 附加 functionality preservation 约束
- **第二段 = 任务分解 + 黑盒挑战 + 算法选择**：从方程 (1) 拆出两个 task（manipulation 技术 + 扰动生成算法）→ 指出黑盒下 $\text{MG}/\text{MV}$ 不可见 → 据此 motivate evolutionary algo (Apoem) → forward 到 §4/§5
- **第三段 = 与已有文献划界**：承认 graph adversarial attack 文献的相关性，但用两条区分理由把自己 isolated 出来——(a) 已有方法在 feature space 攻击，本工作必须在 problem space；(b) 已有方法不满足 R1-R4 实践要求
- 三段结构：**形式化 → 分解任务 → 划界**——典型 problem formulation 模板
- 用方程作为论证工具：方程 (1) 不只是定义，是用来"分裂"出两个 task 的支点
- "$\text{MG}/\text{MV}$ unknown" 这一句直接 motivate §5 evolutionary algorithm 的选择

### 3. 仿照的 Logical Structure

- **第一段 = 符号引入 + 主方程 + 约束**：定义 PIDS 域符号 $A, \delta, \text{MG}_{\text{cmd}}, \text{MV}_{\text{prov}}, L$ → 给出方程（使 PIDS label 翻转的最小 $\delta^*$）→ 附加**一条约束**：攻击命令保序成功执行（直接对应 BagAmmo 的 functionality preservation，1:1）
- **第二段 = 任务分解 + 黑盒挑战 + 算法选择**：从方程拆出两个 task（命令级 manipulation 技术 + 黑盒扰动生成算法）→ 指出黑盒下 $\text{MV}_{\text{prov}}$ **不仅不可见、还跨数学异质类型**（★ 第二次 flag PIDS 异质性，比 §3.1 更具体）→ 据此 motivate **type-conditioned** evolutionary algo → forward 到 §4/§5
- **第三段 = 与已有文献划界**：用三条区分理由把自己 isolated——(a) 同 BagAmmo：现有图对抗攻击在 feature space，本工作在 problem space（命令空间，且需 sandbox 真跑）；(b) 同 BagAmmo：现有方法不满足 PIDS 实践要求（R1-R4 类似的命令级 requirement，§4.1 展开）；(c) **PIDS 特有**：已有黑盒 mimicry 攻击（含 BagAmmo）假设单一同质分类器，无法处理异质 detector 集合

### 4. 仿照段落的内容（中文）

**第一段 · 形式化**：

> 为方便起见，我们用 $A$ 和 $\delta$ 分别表示原始攻击命令序列和插入的扰动（即在 $A$ 各命令之间插入的 camouflage 命令子序列）。用 $\text{MG}_{\text{cmd}}(\cdot)$ 表示"命令序列经 sandbox 执行后产生的 provenance graph"映射（**这是 PIDS 域的特殊性**——映射本身包含真实 OS 执行，不是纯静态变换），用 $\text{MV}_{\text{prov}}(\cdot)$ 表示 detector 内部的 graph-to-decision 映射（在 PIDS 设定下，该映射的**类型**未知——可能是 GNN embedding、规则匹配引擎、或两者的混合）。攻击者通过对 $A$ 施加 $\delta$，将输入图从 $G = \text{MG}_{\text{cmd}}(A)$ 改为 $\widetilde{G} = \text{MG}_{\text{cmd}}(A \oplus \delta)$。设 $L(\cdot)$ 表示 PIDS 预测的二元标签（benign / malicious）。那么所期望的对抗扰动 $\delta^*$ 可通过求解下式得到：
>
> $$L(\text{MV}_{\text{prov}}(\text{MG}_{\text{cmd}}(A))) \neq L(\text{MV}_{\text{prov}}(\text{MG}_{\text{cmd}}(A \oplus \delta^*))) \quad (1)$$
>
> 并需满足攻击功能保持的约束：$A$ 中的每条原始命令在 $A \oplus \delta^*$ 中按原序成功执行。

**第二段 · 任务分解 + 黑盒挑战 + 算法选择**：

> 上述形式化指出了我们的两项任务：(1) 设计一种命令级 manipulation 技术，在保持攻击执行可行性 (P1) 的前提下向命令序列中插入 camouflage 命令；(2) 开发一个黑盒对抗扰动生成算法以实现 $\delta^*$，该算法须能在 $\text{MV}_{\text{prov}}$ 跨数学结构异质（GNN / 规则 / 混合）的情形下工作。
>
> ★ **二次 flag PIDS 异质性**：由于 problem-feature space gap 与严格黑盒设定的挑战，$\text{MG}_{\text{cmd}}(\cdot)$ 与 $\text{MV}_{\text{prov}}(\cdot)$ 对攻击者实际不可见——但**与已有黑盒攻击不同**，这里的不可见性还跨**异质 detector 类型**：单一 substitute 网络无法在所有类型上同时拟合。因此一击命中所需的对抗扰动极其困难。这促使我们设计一个 **type-conditioned 多种群协同进化算法**，让多个针对不同 detector 类型设计的 substitute 同时进化、相互竞争，逐步找到 $\delta^*$。我们将在 §4 和 §5 分别讨论如何完成上述两项任务。

**第三段 · 与已有文献划界**：

> 此外，机器学习社区已提出多种 graph adversarial attack 模型 [refs]。尽管这些方法对我们有启发，但它们不能直接应用于我们的攻击，原因有三：第一，图对抗攻击模型从特征空间发起攻击，但针对 PIDS 的攻击无法直接访问特征空间，必须通过修改命令空间中的攻击命令序列、并经 **sandbox 真实执行**，间接影响 detector 看到的 provenance graph 与其特征。第二，我们的攻击需满足若干实际要求（即 §4.1 讨论的 R1–R4，包括功能保持、跨类型有效、抗静态分析、扰动多样性），这些要求在现有图对抗攻击中缺失。第三，**已有黑盒 mimicry 攻击（含 BagAmmo 等代表性工作）假设单一同质分类器家族**，无法处理 PIDS 设定下的 detector 异质性——这是本工作与已有黑盒 mimicry 文献的根本差异。因此，PIDS 黑盒对抗攻击设计需要专门研究。

---

## §4 章节引入 (chapter intro)

### 1. 翻译 (BagAmmo §4 中文)

本节首先介绍恶意软件 manipulation 的常见要求和已有技术 [10,45,65]，然后提出一种新的恶意软件 manipulation 技术。

### 2. BagAmmo 的 Logical Structure

- 一句话 chapter teaser：路线图"先讲 manipulation 的要求 + 已有技术，再讲新方法"
- 不展开内容
- 紧跟 §4.1

### 3. 仿照的 Logical Structure

- 一句话 chapter teaser：路线图"先讲 PIDS 命令级 manipulation 的要求 + 已有技术，再讲新方法"
- 不展开
- 紧跟 §4.1

### 4. 仿照段落的内容（中文）

> 本节首先介绍命令级 manipulation 的常见要求和已有技术，然后提出一种适用于 PIDS 黑盒攻击的新 manipulation 方法。

---

## §4.1 Background of Manipulation

### 1. 翻译 (BagAmmo §4.1 中文)

虽然恶意软件 manipulation 直觉上简单，但挑战来自以下要求：

- **R1: Functional Consistency**（功能一致性）：恶意软件功能在 manipulation 前后必须保持一致。
- **R2: All-granularities influence**（影响所有粒度）：由于恶意软件检测的 feature 粒度（如 family level 和 package level）未知，manipulation 应能影响所有粒度的特征 [41]。
- **R3: Resilience to static analysis**（抗静态分析）：manipulation 不应被静态分析检查阻碍[^3] [13,42]，且不能完全依赖 dead code（即不可达指令块）。
- **R4: Non-stationary perturbation**（非平稳扰动）：manipulation 应是非平稳的，不能局限于一组固定操作（如预先确定的 white list [65]），以降低被识别风险。

[^3]: 本工作中，静态分析主要指仅检查源代码而不执行程序的程序分析技术。

已有 manipulation 方法概述：

- **Inserting dead codes**：为保持功能一致性，[10] 选择在 smali 文件中插入 dead code（如 no-op 调用）。然而这些代码易被检测和过滤，**违反 R3**。例如，[15] 提出了一种基于加权敏感 API 调用的 Android 恶意软件家族分类方法，能抵抗 no-op 调用的影响。
- **Adding valueless calls**：[10] 创建用户自定义类并向其加入 valueless 调用（即调用空函数）。然而这些调用容易被静态分析识别，且无法攻击 class 粒度的 FCG，**违反 R2 和 R3**。例如，[64] 提出的 Android 恶意软件检测方法不使用自定义函数作为特征，因此不受攻击者插入的 valueless calls 影响。
- **Adding functions from a white list**：为改变 FCG，[65] 的作者从一个预定义白名单中加入函数。然而一旦对抗样本被捕获，白名单就会被揭示，对抗攻击可能失效。请参见 R4 要求。
- **Opaque predicates**：[45] 利用 opaque predicates 插入新 API 以逃避恶意软件检测。具体地，该方法构造**晦涩条件**（其结果在设计期总是已知，但其真值通过静态分析难以或无法确定），因此能有效抵抗静态分析。然而，它可能引入一些 undesired 函数（如 random 函数），对 FCG 造成预期之外的影响。

### 2. BagAmmo 的 Logical Structure

- 一句过渡："直觉上简单，但 4 条 requirement 是挑战"——为 R1-R4 列表铺垫
- 列 R1-R4 四条 requirement，每条一句话定义 + 简短背后原因
- 一句过渡 "Existing manipulation methods are summarized below"
- 列 4 个已有方法，每个**带 R 编号 critique**——明确告诉读者它违反哪条
- 用"requirement 编号 + critique"反复绑定，让读者无法忽视已有方法的不足
- 整段为 §4.2 自家方法埋伏笔——自家方法必须同时满足 R1-R4

### 3. 仿照的 Logical Structure

- 一句过渡：直觉上简单，但 PIDS 域命令级 manipulation 的 requirement 是挑战
- 列对应的 R1-R4（保留 BagAmmo 编号），每条一句话 + 背后原因
- 一句过渡接已有 PIDS-relevant manipulation 方法
- 列 4 个已有命令级方法（[refs] placeholder），每个带 R 编号 critique
- 为 §4.2 PIDS 新方法埋伏笔——必须同时满足 R1-R4

### 4. 仿照段落的内容（中文）

> 虽然命令级 manipulation 直觉上简单，但挑战来自以下要求：
>
> - **R1: Functional Equivalence**（功能等效性）：原始攻击命令序列在 manipulation 前后必须**功能等效**——$A \oplus \delta$ 执行后达成的 attacker effect 与 $A$ 单独执行后完全相同（同份敏感数据被外传、同份持久化建立、同样的权限被获取）。
> - **R2: All-granularities influence**（影响所有粒度）：由于 PIDS detector 看的 provenance graph 特征粒度（**node / edge / graph**）未知，manipulation 必须能影响所有粒度的特征。
> - **R3: Resilience to 显著分布特征**（抗简单规则识别）：manipulation 不应被简单规则（如对 per-process I/O 模式的二阶谓词、固定的命令-参数模板）一眼匹配出来；不能依赖任何 defender 可单条规则识破的固定可观测 pattern。
> - **R4: Camouflage Authenticity**（伪装真实性）：扰动加入的所有 camouflage 行为及其与攻击的 interaction 必须**真实可发生**——camouflage 命令本身在真实 OS 上能完整执行；malicious node 与 benign 实体之间的 interaction 必须是真实因果产生，不是 graph 层凭空记录的伪造关系。

> 已有 PIDS 域 manipulation 方法概述：
>
> - **ProvNinja** (Mukherjee et al., USENIX Sec'23)：**攻击链路替换**——把 conspicuous（低 regularity）事件用 gadget chain 替换，再对 gadget 加 camouflage 边。**违反 R1**——攻击是真实进程链 $\text{fork} \to \text{exec} \to \text{syscall}$ 的因果序列，链路上某个事件被替换后，往往导致后续执行断开：例如把 `dockerd → notepad.exe` 这条 PE 链插入 Linux 攻击 → execve 直接 ENOEXEC 失败；把 `containerd-shim ↔ runc` 之间靠 close-on-exec fd 同步的事件替换掉 → 中间 gadget 触发 cloexec 关 fd → runc init 永远阻塞；甚至把 `apt install` 入口当 conspicuous 删了 → 后续 payload 不存在。
> - **Goyal et al.** (NDSS'23)：**良性子图拼接**——从 benign graph 抠出一片子图（节点 + 边），整块加到 attack graph 上（加桥梁边连到攻击进程），循环到 embedding 离 benign cluster 足够近为止。**违反 R3**——为让 embedding 充分稀释，往往需要拼接成千上万节点/边；一条最简单的计数规则就能抓："某进程在短时间窗内新关联的节点/边数 > 阈值" → 命中，不需要 GNN，一阶谓词即可。
> - **Contorter** (Nasr et al., S&P'26)：**Context Distortion**（上下文扭曲）——对每个 malicious node 找一个同类 benign 节点（按 type + footprint + embedding 相似度筛 top-1），把那个 benign 节点的整套邻居边照搬到 malicious node 周围。**违反 R4**——这些 edge 在 graph 层被"声称"发生，但 malicious node 与 benign 实体之间**没有真实因果**：例如把 `wscript.exe` 的整套邻居边搬到恶意 `update.exe` 周围 → 图上 `update.exe` 突然 read `kernel32.dll` / write `temp/update_patch.tmp` / open `windowsupdate.log`，但恶意进程未必有权访问这些资源、也无现实逻辑去访问——是 attacker 在 graph 层凭空伪造的关系。OccVer 只能验证"这条边在历史 log 中跟 `wscript.exe` 一起出现过"，不能验证"`update.exe` 跟该 benign 实体的因果关系合理"。

---

## §4.2 Command-level Manipulation Method

### 1. 翻译 (BagAmmo §4.2 中文)

我们在此设计一种新的恶意软件 manipulation 方法以修改 smali 代码。根据 R1 要求，我们不能从 FCG 中移除节点或边，因此只考虑加（或插入）节点或边。然而，加孤立节点（即不被他人调用、或不调用他人的函数）有两个理由不可取：第一，孤立节点容易被静态分析检测（如某些进行 redundant code elimination 的程序分析技术会移除不可达代码 [22]）；第二，加节点通常不能影响特征空间，因为多数检测器用边而非节点做分类。因此，我们在 manipulation 方法中选择加边（即 calls）。剩下的问题包括：如何生成 candidate 边、如何从 candidate 中选 desirable 边、以及如何插入选中的边。本节只处理第一和第三个问题，第二个问题在 §5 解决。

**(1) 如何生成 candidate 边？** 如何在不完整特征信息（特征粒度未知）下实现 R2 要求的 all-granularities influence，迄今未被充分研究。为解决，我们提议在**任意类型的两个节点间加一条函数调用边**——该操作不论用什么特征粒度都会改变 FCG。问题随之变为：如何为每条 candidate 边确定 caller 与 callee？由于 R4 要求，我们不能用 white list 来生成 caller 和 callee；相反，从**恶意软件自身使用的函数**里生成，从而保证不同恶意软件的 candidate 边都不同，满足 R4。

现在我们研究在哪里放置新增的边。FCG 由 non-leaf 节点和 leaf 节点组成，如图 4 所示。non-leaf 节点是用户自定义函数，leaf 节点对应不调用他人的 Android 标准函数（如 `java/io/File;->exists()`）。在我们的方法中，non-leaf 节点（即用户自定义函数）选作 caller，因为它们容易被插入新的函数调用；leaf 节点选作 callee，因为调用一个不再调用他人的函数不会触发意外调用。这里我们避免产生意外调用，因为它们可能进一步对 FCG 造成超出预期的扰动。callee 选择的更多讨论见附录 10.1。现在我们可以用上述方法生成 candidate 边；§5 将提出从 candidate 边中选最 desirable 边的算法。

**(2) 如何插入选中的边？** 假设 desirable 边已被选出，研究在 R1 + R3 约束下如何把对应的函数调用插入 smali 文件。我们提出的方法叫 **try-catch trap**：先在 caller 中插入一个 try-catch 块，把 callee 的调用语句放进 try 块；然后在该调用语句之前插入若干用于触发预设异常（如算术异常）的语句。该方法 work 的原因有二：第一，函数调用语句被写入 smali 文件，从而通过加边改变 FCG；第二，该函数调用语句永远不会真正执行，从而保持 malware functionality。图 5 给出 try-catch trap 的示例：左边代码框是某 malware 样本的代码，函数 `callerEX()` 选作 caller；我们在其中放一个 try-catch 块，并在 blue statement 之后调用函数 `callee()`——这样 FCG 多一条新边（如图 5 所示）；当 try-catch 块执行时，会抛出 `IndexOutOfBoundsException`，函数调用语句被跳过。综上，我们的方法可看作 opaque predicates 的变体——精心构造的 obfuscated 条件难以通过静态分析确定，从而具备抗静态分析能力。

插入函数调用的主要步骤简要描述见附录 10.3。

### 2. BagAmmo 的 Logical Structure

- 用排除法定操作类型：不能删 (R1) → 不加孤立节点 (R3 + 不影响特征空间) → 只能**加边**
- 把 §4.2 主问题切成 3 个 sub-question，明确本节答 (1)(3)、(2) 留 §5
- (1) 用"任意类型间加边"破 R2 + "caller/callee 来自 malware 自身"满足 R4 + "non-leaf caller / leaf callee"避免级联副作用
- (3) 用 try-catch trap：FCG 看到调用边（R2）+ 调用语句运行时永不执行（R1）+ opaque-predicate 变体抗静态分析（R3）
- 整段 = "排除 → 分解 → 每个设计选择 1:1 挂回 R1/R2/R3/R4"——R 编号在文中反复显式 cite，让 reviewer 一眼看到每条 requirement 都被对账

### 3. 仿照的 Logical Structure

- 用排除法定操作类型：不能删原攻击命令 (R1) → 不能在 graph 层凭空记录 audit 事件 (R4) → 只能**插入在 sandbox 中真实执行的 camouflage 命令**
- 把 §4.2 主问题切成 3 个 sub-question，本节答 (1)(3)、(2) 留 §5
- (1) 用"shell 命令在 OS 真跑天然影响 node/edge/graph 三粒度"破 R2 + "caller/operand 来自攻击自身已建立的真实因果上下文"满足 R4 + "操作叶子级资源"避免级联副作用 (保 R1)
- (3) 用 PIDS 域 try-catch trap 类比（命名待 §5 后用户定）：camouflage 命令在 audit 层留下事件（R2）+ 实际效果不动 attack-essential resources（R1）+ 命令-参数组合在 benign 中频繁出现、简单规则单条匹配不到（R3）
- 整段同样 = "排除 → 分解 → 每个设计选择 1:1 挂回 R1/R2/R3/R4"

### 4. 仿照段落的内容（中文）

**开篇 · 用排除法定操作类型**：

> 我们在此设计一种新的命令级 manipulation 方法。根据 R1 要求，我们不能删除原始攻击命令序列 $A_0 = (c_1, \ldots, c_k)$ 中的任何命令——删除会断开攻击的真实 fork → exec → syscall 因果链路（FINDINGS 实证 ProvNinja 的 P1 失败正是源于此）。因此我们只考虑在攻击命令之间**插入** camouflage 命令。然而，向 graph 中"凭空"插入只在图层被声称发生、实际未对应真实 OS 行为的事件违反 R4：malicious node 与 benign 实体之间将出现没有真实因果的关系（FINDINGS 实证 Contorter 的 P2 失败源于此）。因此 camouflage 命令必须**在 sandbox 中真实执行**，由 OS audit / eBPF 自然记录其 interaction。剩下的问题分为三个 sub-question：(1) 如何生成 candidate camouflage 命令；(2) 如何从 candidate 中选 desirable；(3) 如何把选中的命令插入攻击命令序列并保证 R1。本节只处理 (1) 和 (3)，(2) 在 §5 解决。

**(1) 如何生成 candidate camouflage 命令？**

> 如何在 detector 类型未知的前提下满足 R2 (All-granularities influence)，是 PIDS 黑盒攻击未充分研究的问题。我们提议**在 sandbox 中真实执行 shell 命令作为 manipulation 原语**——一条命令在 OS 上跑出的 audit 事件天然影响所有粒度：它创建 / 读 / 写文件（改 node-level 文件属性 + graph-level 子图）、打开 / 关闭 socket（改 edge-level 频率 + subgraph 模式）、fork / exec（改进程树）。无论 PIDS detector 看哪个粒度都会被同一动作影响。
>
> 接下来确定 candidate 命令的 caller 与 operand。根据 R4，我们**不能用一个固定 LOLBin 白名单**——白名单一旦暴露就形成跨样本可识别的固定 pattern，且 attacker 与白名单进程之间无真实因果。相反，我们从**攻击自身已建立的真实因果上下文**生成 candidate：caller = 攻击自身已 fork 出的进程（或合法继承 attacker 权限的子进程），operand（被读 / 写 / 连接的资源）= 该进程在攻击轨迹中已自然访问、或与 attacker 控制进程已有真实因果关系的实体。这样不同攻击的 candidate 命令池都不同（满足 R4 的"扰动随攻击自身变化"），且 malicious-benign interaction 是真实可发生的（满足 R4 的"非凭空伪造"）。
>
> 至于命令的"作用对象"角色选择——平行于 BagAmmo 选 leaf node 作 callee 的动机：camouflage 命令应作用在**叶子级资源**（文件元数据查询如 `stat`、链接探测如 `readlink`、socket 状态查询如 `getsockopt`、长格式列表如 `ls -la`），避免触发**意外的级联系统行为**（如 fork 长生命周期 daemon、加载新依赖、改全局配置）。叶子级资源的副作用边界明确，不会扩散到攻击核心资源 → 保 R1；同时叶子级查询命令在 benign 中**极其常见**（每分钟无数个进程做这类查询），简单规则单条匹配不到 → 保 R3。

**(2) 如何选 desirable camouflage？** 留给 §5（type-conditioned 多种群协同进化算法）。

**(3) 如何把选中的 camouflage 命令插入到攻击序列？**

> 假设 desirable camouflage 命令 $c_{\text{camo}}$ 已选出，研究在 R1 + R3 约束下的插入方法。BagAmmo 的 try-catch trap 在静态层让 FCG 见到调用边、动态层让调用永不执行——这一精巧构造在命令级有直接对应（命名待用户定，暂称"PIDS try-catch trap"）：
>
> 一条合格 camouflage 命令 $c_{\text{camo}}$ 必须同时满足三条性质：
> - **在 audit 层留下事件**：$c_{\text{camo}}$ 在 sandbox 真跑后，OS audit 自然记录对应 syscall → graph 中确实新增节点 / 边（满足 R2，对应 BagAmmo "FCG 多了新边"）
> - **在 attack-essential resources 上零副作用**：$c_{\text{camo}}$ 的实际写后效不影响后续 $c_{i+1}, \ldots, c_k$ 所需的 OS state（uid / fd / 文件状态 / 网络 namespace 不被改变）→ 保攻击执行（满足 R1，对应 BagAmmo "调用永不执行" 的"不破坏 functionality"语义）
> - **命令本身在 benign 中常见**：$c_{\text{camo}}$ 的命令-参数组合（不是单独命令名）在 benign profile 中频繁出现 → 简单规则（计数 / 模板匹配）单条无法识别（满足 R3，对应 BagAmmo "opaque predicate 变体抗静态分析"）
>
> 关键差异（与 BagAmmo 的精确 mapping）：
> - BagAmmo 的"调用永不执行"靠**异常截断**实现——静态层有边、动态层零行为
> - PIDS 的对应靠**叶子级零副作用命令**实现——audit 层有事件、攻击状态层零干扰
> - 这一映射保留了 try-catch trap "静态可见 + 动态无害"的核心思想，并将其从 smali 字节码层迁移到 OS 命令层

> ★ 由于 $c_{\text{camo}}$ 在 sandbox 真跑而非图层伪造，$\widetilde{G} = \text{MG}_{\text{cmd}}(A_0 \oplus \delta)$ 由 OS audit 自然产生，**OS 不变量（fork 关系、fd 协议、特权链）由构造保证**——这是 BagAmmo 在 smali / FCG 层面没有面对的额外保证（Android 域可以纯静态修改 FCG，PIDS 域必须经过 OS 真实执行）。这一构造性差异在 §5 黑盒搜索算法的设计中将被利用：搜索过程不需要额外验证 OS 不变量。

---

## §5 章节引入 (chapter intro)

### 1. 翻译 (BagAmmo §5 中文)

在 §4.2 中我们提出了如何从 candidate 边中选 desirable 边的问题。为回答这个问题，我们开发一种新的 GAN 模型和 Apoem 算法以找到所期望的对抗扰动。

### 2. BagAmmo 的 Logical Structure

- 一句话 chapter teaser，回引 §4.2 留下的"如何选 desirable 边"问题
- 给出本章答案的 high-level 形式：GAN 模型 + Apoem 算法
- 不展开内容，紧跟 §5.1

### 3. 仿照的 Logical Structure

- 一句话 chapter teaser，回引 §4.2 留下的"如何选 desirable camouflage"问题
- 给出本章答案的 high-level 形式：substitute-augmented 框架 + 算法（待命名）
- 不展开，紧跟 §5.1

### 4. 仿照段落的内容（中文）

> 在 §4.2 中我们提出了如何从 candidate camouflage 命令中选 desirable 命令的问题。为回答这个问题，我们开发了一个 substitute-augmented 黑盒搜索框架和算法（具体命名待用户决定）以找到所期望的对抗扰动 $\delta$。

---

## §5.1 Challenges & Solutions

### 1. 翻译 (BagAmmo §5.1 中文)

我们首先介绍 BagAmmo 的主要过程：

(1) 给定一个预选的恶意软件样本，BagAmmo 从 smali 代码中找出一些 caller 和 callee，并用它们生成一组 candidate 边（如 §4 所述）。借助 candidate 边，BagAmmo 通过对恶意软件做 manipulation 生成一系列样本，并把它们（即 query）发送给目标系统做恶意软件检测。

(2) 目标模型对 query 返回一个 reply。在我们的严格黑盒设定下 [68]，每条 reply 只包含二元分类结果（即 malicious 或 benign）。

(3) 通过从 query-reply 对中学习，BagAmmo 逐渐识别出最 desirable 的、能成功诱导误分类的边。

设计 BagAmmo 的主要挑战包括：1) 目标模型的特征粒度未知；2) 严格黑盒攻击场景[^4]下通常需要大量 query [1,36]。下面简要说明我们的对策。

[^4]: 此场景下，§3.2 提到的 $\text{MG}(\cdot)$ 与 $\text{MV}(\cdot)$ 都是未知的。此外，黑盒模型的 reply 只包含二元分类结果（如许多恶意软件检测网站 [54] 只返回二元判定而非类概率）。

**Surmising feature granularity（推断特征粒度）**。我们的对抗多种群协同进化算法（即 Apoem）用一个 population 表示一种可能的特征粒度。多个 population 对应多种可能的特征粒度，它们协同进化，直到对应真实特征粒度的 population 存活、其他 population 淡出。这样 BagAmmo 能准确识别目标模型使用的特征粒度，以及所期望的对抗扰动。我们将在 §5.3 讨论这一点。

**Reducing the number of queries（降低 query 数量）**。BagAmmo 构造一个新的 substitute 模型来模拟目标模型。该 substitute 模型用 Apoem 生成的样本和目标模型给的标签训练。如 §5.4 所示，一旦 substitute 模型训练好，BagAmmo 只需攻击它而不必攻击目标模型，从而大大降低 query 数。

### 2. BagAmmo 的 Logical Structure

- **第一段 = main procedure 3 步**：candidate 边 → 用 manipulation 生成样本 query 目标 → 用 binary 反馈学 desirable 边
- **第二段 = 列出 2 个挑战**：(C1) 特征粒度未知，(C2) 严格黑盒下 query 数大
- **第三段 = 给 C1 的对策（forward to §5.3）**：Apoem 多种群协同进化，每个 population 对应一种可能粒度，竞争进化让真实粒度的 population 胜出
- **第四段 = 给 C2 的对策（forward to §5.4）**：substitute model 模拟目标，训练好后只攻击 substitute
- 整段 = "procedure → challenge → solution + forward reference"——经典 challenge-and-solution 模板，每个挑战一对一对应一个后续章节

### 3. 仿照的 Logical Structure

- **第一段 = main procedure 3 步**：candidate camouflage 命令 → 在 sandbox 中真跑 + 让 OS audit 产生 trace → 把 trace query PIDS → 用 binary 反馈学 desirable camouflage
- **第二段 = 列出 2 个挑战**：(C1) ★ **PIDS detector 类型未知（GNN / rule / hybrid，三类数学异质）**，(C2) 严格黑盒下 query 数大 + sandbox 执行也有 wall-clock 成本
- **第三段 = 给 C1 的对策（forward to §5.3）**：type-conditioned 多种群协同进化，每个 population 对应一种可能 detector 类型（GNN / rule / hybrid），竞争进化让真实类型的 population 胜出
- **第四段 = 给 C2 的对策（forward to §5.4）**：★ **type-conditioned substitute set $\{S_T(\cdot)\}$**——不是 BagAmmo 的单一 GCN substitute，而是按 detector 类型预备的一组 substitute（GNN-substitute 用小型 GraphSAGE、rule-substitute 用 boosted decision tree、sequence-substitute 用 transformer）；§5.3 协同进化产出的样本同时训练这一组 substitute，让对应真实类型的 substitute 留存下来
- 整段保持 BagAmmo "procedure → challenge → solution + forward reference" 的论证骨架，但每个挑战和对策都按 PIDS 异质性扩展

### 4. 仿照段落的内容（中文）

**第一段 · main procedure 3 步**：

> 我们首先介绍本方法的主要过程：
> 
> (1) 给定一个预选的攻击命令序列 $A_0 = (c_1, \ldots, c_k)$，本方法从 §4 给出的命令池中找出 candidate camouflage 命令。借助 candidate camouflage，本方法通过对 $A_0$ 做插入式 manipulation 生成一系列扩展序列 $A_0 \oplus \delta$，**在 sandbox 中真实执行**得到 provenance 子图 $\widetilde{G} = \text{MG}_{\text{cmd}}(A_0 \oplus \delta)$，并把 $\widetilde{G}$ 作为 query 发送给目标 PIDS。
>
> (2) 目标 PIDS 对 query 返回一个 reply。在我们的严格黑盒设定下，每条 reply 只包含二元分类结果（即 malicious 或 benign）。
>
> (3) 通过从 query-reply 对中学习，本方法逐渐识别出最 desirable 的、能成功诱导误分类的 camouflage 命令组合。

**第二段 · 列出 2 个挑战**：

> 设计本方法的主要挑战包括：
> 1. ★ 目标 PIDS 的 **detector 类型未知**——它可能是基于 GNN 的图分类器、基于一阶规则的检测引擎、或两者的混合；与已有黑盒攻击设定（攻击者面对单一同质分类器家族）不同，PIDS 设定下的"未知"跨越**数学结构异质**的 detector 类型。
> 2. 严格黑盒攻击场景下通常需要大量 query；同时 PIDS 域中每次 query 还需经过 sandbox 真实执行，进一步增大成本。

**第三段 · 给 C1 的对策（forward to §5.3）**：

> **推断 detector 类型**。我们的对抗多种群协同进化算法用一个 population 表示一种可能的 detector 类型——具体地，三个 population 分别对应 $T \in \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$。多个 population 协同进化，直到对应真实 detector 类型的 population 存活、其他 population 凋亡。这样本方法能准确识别目标 PIDS 使用的 detector 类型，以及所期望的对抗扰动 $\delta$。我们将在 §5.3 讨论这一点。

**第四段 · 给 C2 的对策（forward to §5.4）**：

> **降低 query 数量**。我们构造一个 ★ **type-conditioned substitute 集合** $\{S_T(\cdot)\}_{T \in \Omega}$ 来模拟目标 PIDS——对每种可能的 detector 类型 $T$ 预备一个对应架构的 substitute（如 $T_{\text{GNN}}$ 用小型 GraphSAGE，$T_{\text{rule}}$ 用 boosted decision tree，$T_{\text{hybrid}}$ 用二者集成）。该 substitute 集合用 §5.3 协同进化生成的样本和目标 PIDS 给的标签训练；随着训练推进，对应真实 detector 类型的 substitute 越拟合越好，其他类型的 substitute 自然落后。如 §5.4 所示，一旦合适的 substitute 训练好，本方法只需攻击该 substitute 而不必每步都攻击目标 PIDS，从而大大降低真实 query 数。

> ★ **PIDS-specific extension 的种子**：BagAmmo 用单一 GCN substitute 即可，因为它假设的所有 feature granularity 都是 GCN 同质家族；PIDS 异质 detector 不允许这种简化——必须用一组架构异质的 substitute，并通过 §5.3 协同进化逐步识别该用哪一个。这一改动是本工作相对 BagAmmo 的核心实质扩展，§5.4 详细展开。

---

## §5.2 The Overview of BagAmmo

### 1. 翻译 (BagAmmo §5.2 中文)

参照 GAN 的架构，BagAmmo 采用一个 generator 和一个 discriminator，二者协同训练。

**Generator**：generator 负责生成扰动，即添加到 FCG 中的新边。它由对抗多种群协同进化算法（即 Apoem）实现。

**Discriminator**：discriminator 用于刺激 generator 改进其扰动，由 GCN 实现，作为 substitute 网络 [10] 模拟目标模型。

**Training**：在每轮模型训练中，generator 修改恶意软件的代码并将重建后的恶意软件发送给目标模型或 substitute 模型做恶意软件检测。BagAmmo 以可变概率 $p$ 在目标模型和 substitute 模型之间做选择。收到 query 后，目标模型返回其 replies（即二元判定 binary decisions）。借助 query-reply 对，BagAmmo 训练 substitute 模型并引导其 generator 改进所生成的扰动。概率 $p$ 随轮次增加而增长，以减少发送给目标模型的 query 数。

### 2. BagAmmo 的 Logical Structure

- 一句话定整体架构：GAN 风格——generator + discriminator 协同训练
- 介绍 generator：Apoem 多种群协同进化算法
- 介绍 discriminator：GCN 实现的 substitute network
- 描述 training loop：每轮以可变概率 $p$ 在 target / substitute 之间切换 query；$p$ 随轮次增长以省真 query
- 整段 = "架构选定 → 组件 1 → 组件 2 → training procedure" 4 段式 overview

### 3. 仿照的 Logical Structure

- 一句话定整体架构：substitute-augmented adversarial 框架（沿用 GAN 风格 generator-discriminator 协同）
- 介绍 generator：type-conditioned 多种群协同进化算法
- ★ 介绍 discriminator：**type-conditioned substitute 集合** $\{S_T(\cdot)\}_{T \in \Omega}$——按 detector 类型预备一组架构异质的 substitute（GraphSAGE / decision tree / Transformer），不是 BagAmmo 的单一 GCN
- 描述 training loop：每轮以可变概率 $p$ 在 target PIDS / substitute set 之间切换；$p$ 随轮次增长
- 保持 BagAmmo 的"架构 → 组件 1 → 组件 2 → training"4 段式

### 4. 仿照段落的内容（中文）

**整体架构**：

> 沿用 GAN 风格的协同训练架构，本方法采用一个 generator 和一个 substitute set，二者协同训练。

**Generator**：

> Generator 负责生成扰动 $\delta$（即插入到攻击命令序列 $A_0$ 之间的 candidate camouflage 命令组合），由 §5.3 描述的 type-conditioned 多种群协同进化算法实现。

**Substitute set**（★ 核心扩展）：

> ★ **Substitute 不是单一模型，而是一组按 detector 类型预备的 substitute 集合** $\{S_T(\cdot)\}_{T \in \Omega}$，$\Omega = \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$。每个 $S_T$ 用对应类型适合的架构实现：
> - $S_{T_{\text{GNN}}}$ — 小型 GraphSAGE，模拟连续平滑响应的 GNN detector
> - $S_{T_{\text{rule}}}$ — boosted decision tree，模拟离散尖锐响应的 rule detector
> - $S_{T_{\text{hybrid}}}$ — 二者集成 + 学习权重，模拟混合 detector
>
> 该 substitute set 用 generator 生成的样本和目标 PIDS 给的 binary 标签训练；§5.4 详细展开。

**Training**：

> 每轮训练中，generator 修改攻击命令序列得到 $A_0 \oplus \delta$，**在 sandbox 中真实执行**生成 trace，将 trace 作为 query 发送给目标 PIDS 或 substitute set。本方法以可变概率 $p$ 在目标 PIDS 和 substitute set 之间做选择；收到 query 后获取 binary 判定。借助 query-reply 对，本方法训练 substitute set（让对应真实 detector 类型的 substitute 越拟合越好，其他类型的自然落后）并引导 generator 改进其生成的扰动。概率 $p$ 随轮次增加而增长，以减少发送给目标 PIDS 的真 query 数（同时省下 sandbox 执行成本）。

> **与 BagAmmo training loop 的差异**：BagAmmo 的 query 流是 attacker 直接生成 manipulated APK 喂 target；本方法多一步 sandbox 真实执行（attacker 必须真跑命令才能得到 PIDS 看到的 trace），因此 wall-clock 成本更高、$p$ 调度需更激进地偏向 substitute。

---

## §5.3 Adversarial Multi-population Co-evolution

### 1. 翻译 (BagAmmo §5.3 中文)

generator 面对的主要挑战是真实特征粒度未知。为方便理解，考虑目标系统使用 family-level 特征但我们扰动 class-level 特征的情形——这种情况下我们会陷入巨大搜索空间，延长模型训练时间并需更多 query。为缓解此问题，BagAmmo 用 Apoem 算法**推断**真实特征粒度。Apoem 遵循进化算法的一般框架，但引入多种群协同来加速收敛。随着进化推进，对应真实特征粒度的 population 逐渐从群体中脱颖而出。下面我们先介绍 Apoem 的主要组件（图 6 红色块所示），然后讨论如何用这些组件生成所期望的扰动。

**(1) Population & Individual**：一个 population 代表在某种特征粒度下生成的 AE 集合。例如 family-level population 由"假设目标分类器使用 family-level FCG 作输入"生成的 AE 组成。Apoem 采用多个 population，每个对应一种可能的特征粒度（即 family / package / class）。每个 individual 给出一个可施加于原 FCG 的扰动[^5]，即添加到 FCG 的边集。如图 7 (a) 所示，上方图为原 FCG，下方为 AE，扰动（边集 $(A \to E, B \to D)$）即一个 individual。我们用 $x_r^{(i,j)}$ 表示 Apoem 第 $r$ 代第 $i$ 个 population 的第 $j$ 个 individual，$x_r^{(i,j)} = \{e_1^{(i,j)}, \ldots, e_n^{(i,j)}\}$，$e_k^{(i,j)}$ 是新加的边。初始阶段，我们随机扰动原 FCG，为每个 population 收集足够 individual。

[^5]: 严格来说，individual 指 population 中的一个对抗样本。然而，对抗样本与恶意样本的差异即为扰动，因此我们用扰动来表示 individual。

**(2) Fitness & Selection**：Apoem 用 fitness 度量挑选 superior individual、淘汰 inferior individual。该度量反映 AE 的 aggressivity 和 invisibility，由两因子计算：threat degree $T$ 和 perturbation amount $L$。threat degree 按目标模型 $F(\cdot)$ 或 substitute 模型 $S(\cdot)$ 输出度量[^6]。对于一个 individual $x$，threat degree 定义为：

$$T = \begin{cases} 1 - F(x) & \text{若用目标模型} \\ 1 - S(x) & \text{若用 substitute 模型} \end{cases}$$

perturbation amount 即新加边的数量。此外，Apoem 用 elitist 选择策略 [53] 把好基因传给下一代——保留 fittest individual、淘汰其他。

[^6]: 对于目标模型或 substitute 模型，当其输出 $F(x)$ 或 $S(x)$ 等于或趋近于 1 时，输入被判定为 malicious。

**(3) Immigration**：高 fitness individual 有更大机率产更好后代。为产更多高质量 individual，Apoem 用 immigration 把一个 population 内高 fitness individual 迁移到其他 population，让所有 population 协同进化。Apoem 中有两种 immigration：fine-to-coarse（如 class → family）和 coarse-to-fine（如 family → class）（图 7 (b)）。fine-to-coarse 案例：class-level population 的一个 individual 迁到 package-level population——保留扰动中相关的 package 名（如 `java.lang.StrictMath → java.lang`），把只含 package 名的 individual 放进 package-level population。coarse-to-fine 案例：package-level individual 注入 class-level population——由于一个 package 可能含多个 class，我们随机选 malware 代码用过的一个 class 替换 package，把含 class 名的 individual 放进 class-level population。

**(4) Crossover**：Apoem 用 crossover 随机交换两 parent 的基因产生 offspring。具体地，从 population 随机选 $K$ 对 individual 做 parent，每对的扰动一半被交换产生两个 offspring（图 7 (c)）。设 parent 为 $x_r^{(i,j_1)} = \{e_1, e_2, e_3, e_4\}^{(i,j_1)}$ 和 $x_r^{(i,j_2)} = \{e_1, e_2, e_3, e_4\}^{(i,j_2)}$，其中 $e_k^{(i,j)}$ 是新加的边（如图 7 (c) 中的 $A \to E$）。crossover 得到的 offspring 为 $x_{r+1}^{(i,j_1)} = \{e_1^{(i,j_1)}, e_2^{(i,j_1)}, e_3^{(i,j_2)}, e_4^{(i,j_2)}\}$ 和 $x_{r+1}^{(i,j_2)} = \{e_1^{(i,j_2)}, e_2^{(i,j_2)}, e_3^{(i,j_1)}, e_4^{(i,j_1)}\}$。

**(5) Mutation**：Apoem 用 mutation 给 population 引入新变化。如图 7 (d)，三种 mutation 模式：1) 在现有扰动上随机加函数调用；2) 随机删现有扰动；3) 随机交换现有扰动。数学表示分别为 $x_{r+1}^{(i,j)} = \{e_1, \ldots, e_n, e_{n+1}\}$、$\{e_1, \ldots, e_{n-1}\}$、$\{e_1, \ldots, e_{n-1}, e_{n+1}\}$。

### 2. BagAmmo 的 Logical Structure

- **Lead-in**：用一个具体例子（target 用 family、attacker 扰动 class）说明 granularity 不匹配会导致搜索空间爆炸 → motivate 多种群协同进化的必要
- **(1) Population & Individual**：定义 population = 一种 granularity 下的 AE 集，individual = 一个具体扰动（边集），并给出符号 $x_r^{(i,j)}$
- **(2) Fitness & Selection**：fitness = threat degree $T$ + perturbation amount $L$；用 elitist 选择保留 fittest
- **(3) Immigration**：高 fitness individual 跨 population 迁移（fine-to-coarse + coarse-to-fine），让真实粒度 population 借助其他 population 的好基因
- **(4) Crossover**：同 population 内成对交换基因
- **(5) Mutation**：3 种变异（加 / 删 / 换）维持多样性
- 整段 = "动机 → 5 个标准 EA 组件" 模板，把 EA 框架 instantiate 到 multi-population + immigration 这一关键扩展上

### 3. 仿照的 Logical Structure

- **Lead-in**：用一个具体例子（target 是 rule detector、attacker 用 GNN 视角扰动）说明 detector 类型不匹配会导致搜索空间爆炸 → motivate type-conditioned 多种群协同进化
- **(1) Population & Individual**：population $P_T$ 对应每种可能 detector 类型 $T \in \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$；individual $\delta_r^{(i,j)}$ = 一个具体 camouflage 命令插入序列
- **(2) Fitness & Selection**：fitness = threat degree（用 target PIDS 或 type-conditioned substitute set）+ 扰动量（candidate 命令数）；保留 fittest
- **(3) Immigration**：高 fitness individual 跨 type-population 迁移——比如 GNN-population 的好 individual 迁到 rule-population（需做语义转换：GNN-导向的 candidate 选择需"翻译"成 rule-避开的 candidate）
- **(4) Crossover**：同 type-population 内成对交换 candidate 命令子集
- **(5) Mutation**：同 BagAmmo 三种（加 / 删 / 换 candidate 命令）
- 保持 BagAmmo "动机 → 5 组件" 模板；3 个 detector 类型替换 3 个 granularity 是直接对应

### 4. 仿照段落的内容（中文）

**Lead-in**：

> generator 面对的主要挑战是真实 detector 类型未知。为方便理解，考虑目标 PIDS 是 rule detector 但我们以 GNN 视角扰动——这种情况下我们会陷入巨大搜索空间（GNN-导向 candidate 不一定能避开 rule，反之亦然），延长训练时间并需更多 query。为缓解，本方法用 type-conditioned 多种群协同进化算法**推断**真实 detector 类型。沿用进化算法的一般框架，并通过多种群协同加速收敛——随着进化，对应真实 detector 类型的 population 逐渐脱颖而出。

**(1) Population & Individual**：

> 一个 population $P_T$ 代表在某种 detector 类型假设下生成的 AE 集合。例如 $P_{T_{\text{GNN}}}$ 由"假设目标 PIDS 用 GNN 做检测"假设下生成的 AE 组成。本算法采用 3 个 population，分别对应 $T \in \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$。每个 individual 给出一个可施加于原攻击命令序列 $A_0$ 的扰动 $\delta$（即在 $A_0$ 命令之间插入的 camouflage 命令组合）。我们用 $\delta_r^{(i,j)}$ 表示第 $r$ 代第 $i$ 个 population（$i \in \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$）的第 $j$ 个 individual，$\delta_r^{(i,j)} = \{c_1, c_2, \ldots, c_n\}^{(i,j)}$，每个 $c_k$ 是一条 candidate camouflage 命令。初始阶段，我们对 $A_0$ 随机插入 candidate camouflage，为每个 population 收集足够 individual。

**(2) Fitness & Selection**：

> Fitness 度量挑选 superior individual、淘汰 inferior individual。fitness 由两因子组成：threat degree $T(\delta)$ 和 perturbation amount $L(\delta)$。threat degree 按目标 PIDS $F(\cdot)$ 或 type-conditioned substitute $S_T(\cdot)$ 输出度量：
> 
> $$T(\delta) = \begin{cases} 1 - F(\widetilde{G}) & \text{若用目标 PIDS} \\ 1 - S_T(\widetilde{G}) & \text{若用类型 } T \text{ 的 substitute} \end{cases}$$
> 
> 其中 $\widetilde{G} = \text{MG}_{\text{cmd}}(A_0 \oplus \delta)$。perturbation amount $L(\delta) = $ 插入的 candidate 命令数。沿用 elitist 选择策略保留 fittest individual、淘汰其他。

**(3) Immigration**：

> 高 fitness individual 跨 population 迁移让所有 population 协同进化。本算法的 immigration 在 detector 类型间发生——例如 $P_{T_{\text{GNN}}}$ 的好 individual 迁到 $P_{T_{\text{rule}}}$。由于不同 detector 类型对 candidate 的偏好不同（GNN 看连续平滑、rule 看离散尖锐），迁移需要做"语义转换"：保留 individual 中**类型无关**的 candidate（如纯只读元数据查询、对所有类型都不增加风险的）作为基础；类型相关的 candidate（如针对 GNN 的特定 embedding 漂移命令）替换为目标 type 偏好的命令模板。

**(4) Crossover**：

> 同 population 内成对交换 candidate 子集。从 $P_T$ 随机选 $K$ 对 individual 做 parent，每对的 candidate 一半被交换产生两 offspring。设 parent 为 $\delta_r^{(i,j_1)} = \{c_1, c_2, c_3, c_4\}$ 和 $\delta_r^{(i,j_2)} = \{c_1', c_2', c_3', c_4'\}$，crossover 得 $\delta_{r+1}^{(i,j_1)} = \{c_1, c_2, c_3', c_4'\}$ 和 $\delta_{r+1}^{(i,j_2)} = \{c_1', c_2', c_3, c_4\}$。

**(5) Mutation**：

> 三种 mutation 模式：1) 在现有扰动上随机加 candidate；2) 随机删现有 candidate；3) 随机交换现有 candidate。数学表示分别为 $\delta_{r+1}^{(i,j)} = \{c_1, \ldots, c_n, c_{n+1}\}$、$\{c_1, \ldots, c_{n-1}\}$、$\{c_1, \ldots, c_{n-1}, c_{n+1}\}$。每次 mutation 选 candidate 的来源遵守 §4.2 的 R4 约束（candidate 来自攻击自身 context，不用固定白名单）。

---

## §5.4 Substitute Model — ★ 核心实质扩展段

### 1. 翻译 (BagAmmo §5.4 中文)

Apoem 只知道目标模型的二元判定，难以准确评估 individual。为克服这一挑战，我们设计一个新的 substitute 模型来模拟目标模型，并为 Apoem 提供近似的类概率。

我们的 substitute 模型输入是按 generator 产生的扰动生成的 function-level FCG。我们用 GCN（Graph Convolutional Network）从 substitute 模型抽取特征，如图 6 绿色块所示。GCN 把卷积扩展到图数据，擅长利用结构信息和节点信息来完成图相关的机器学习任务。然而，将 GCN 应用于本任务的主要障碍是节点属性缺失——FCG 不为其节点提供属性信息。为缓解此问题，我们提议把节点的**出度**和**入度**作为节点特征。

下面简述如何用 GCN 从输入抽特征。GCN 有多个卷积层，每层用传播规则聚合节点属性，聚合后的特征再由下一层处理；通过迭代计算，我们得到一个表示 FCG 的特征向量。

### 2. BagAmmo 的 Logical Structure

- **动机**：Apoem 只拿到 binary decision → fitness 评估粗 → 需 substitute 提供"近似类概率"作 finer-grained fitness 信号
- **设计选择**：用单一 GCN 作 substitute，输入 function-level FCG
- **工程难点**：FCG 节点无属性 → 用 in-degree + out-degree 当节点特征
- **GCN 工作机理简介**：多卷积层 + 传播规则 + 迭代得 FCG 特征向量
- 整段 = "动机 → 设计选 GCN → 工程细节 → 简介机理" 4 段式
- **隐含假设（BagAmmo 没明说）**：target model 也是 graph-classifier 家族（GCN / 类似），所以"近似类概率"概念有意义、GCN substitute 能学得对——这一假设在 BagAmmo 同质 granularity 设定下成立，但在 PIDS 异质设定下崩塌

### 3. 仿照的 Logical Structure（★ 核心扩展段，4 步结构）

按 skill 要求 §5.4 必须显式 4 步：

- **(a) 复述 BagAmmo 的设计**：单一 GCN substitute + in/out-degree 节点特征 + 输出近似类概率
- **(b) 识别隐含假设**：BagAmmo §5.4 默认 target 是 graph-classifier 家族（输出连续平滑类概率，可被 GCN 任意逼近）；这一假设来自 BagAmmo 同质 granularity 设定下所有 detector 都是 GCN 类
- **(c) 论证为什么 PIDS 异质设定下假设崩塌**：PIDS 的 target 类型 $T \in \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$ 跨数学异质——
  - $T_{\text{GNN}}$：连续平滑、近似可微 → GCN substitute 能学
  - $T_{\text{rule}}$：离散尖锐、阶梯式 → GCN substitute **学不出**（rule 决策边界非光滑、类概率不连续；GCN 梯度优化无法逼近 step function 边界）
  - $T_{\text{hybrid}}$：介于二者，单一架构都不够
- **(d) 提出 type-conditioned substitute 集合扩展** $\{S_T(\cdot)\}_{T \in \Omega}$：每个 $S_T$ 用对应类型适合的架构——$S_{T_{\text{GNN}}}$ 小型 GraphSAGE，$S_{T_{\text{rule}}}$ boosted decision tree（DT 天然学 step boundary），$S_{T_{\text{hybrid}}}$ 二者集成 + 学习权重 gating；§5.3 协同进化把 (sample, target-label) 对分发给所有 $S_T$ 训练，对应真实类型的 $S_T$ 越拟合越好、其他自然落后；fitness 评估时按 individual 所在 population 的类型 $T$ 选用对应 $S_T$

### 4. 仿照段落的内容（中文）

**(a) 复述 BagAmmo 的设计**：

> BagAmmo §5.4 的 substitute 模型是**单一 GCN**，输入 function-level FCG，节点属性用 in-degree + out-degree 编码，输出近似类概率供 Apoem 计算 fitness。这一设计在 BagAmmo 的设定下 work——所有 feature granularity（family / package / class）都是 GCN 同质家族的不同聚合粒度，单一 GCN 通过协同进化筛选出真实粒度即可逼近目标。

**(b) 识别隐含假设**：

> BagAmmo §5.4 有一个**未显式声明的假设**：target detector 的输出是**连续平滑的类概率**（或近似于此的可微分输出）。这一假设让"用单一 GCN 逼近目标"在数学上成立——GCN 是 universal approximator on continuous functions，能任意逼近另一个连续平滑分类器。
>
> 这一假设在 BagAmmo 的同质 granularity 设定下默认成立——BagAmmo 假设的所有 target（family-level / package-level / class-level GCN）都是 graph-classifier 家族，输出都是连续 softmax 概率。

**(c) 论证为什么 PIDS 异质设定下假设崩塌**：

> ★ PIDS detector 的类型 $T \in \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$ 跨**数学结构异质**——三类 detector 的输出函数有本质不同的解析性质：
> 
> - **$T_{\text{GNN}}$**：输出连续平滑、近似可微 → 单一 GCN substitute **能学**（与 BagAmmo 设定一致）
> - **$T_{\text{rule}}$**：输出离散尖锐、阶梯式（如 D2 这类一阶谓词输出 0/1）→ GCN substitute **学不出**：(i) rule 决策边界是 hard threshold，非光滑；(ii) 类概率不连续，GCN softmax 输出无法逼近 step function；(iii) 用梯度优化训 GCN 在 rule 输出上的 loss 收敛性差（梯度信号在大部分输入上为 0）
> - **$T_{\text{hybrid}}$**：GNN + rule 的混合输出，单一架构（无论 GCN 还是 DT）都不够
> 
> 因此 BagAmmo §5.4 的"用单一 GCN 模拟目标"在 PIDS 异质设定下**结构性失效**——并非超参数没调好，是数学上单一架构无法同时逼近三类异质函数。

**(d) 提出 type-conditioned substitute 集合扩展**：

> ★ 我们把 BagAmmo 的单一 GCN substitute $S(\cdot)$ 扩展为 **type-conditioned substitute 集合** $\{S_T(\cdot)\}_{T \in \Omega}$，$\Omega = \{T_{\text{GNN}}, T_{\text{rule}}, T_{\text{hybrid}}\}$。每个 $S_T$ 用对应类型适合的架构：
> 
> - **$S_{T_{\text{GNN}}}$**：小型 GraphSAGE（2-layer，<100K 参数）。使用与 BagAmmo §5.4 相同的 in/out-degree 节点特征 + 多卷积层迭代抽特征，输出连续概率。**适配 GNN 类目标**。
> - **$S_{T_{\text{rule}}}$**：boosted decision tree（如 XGBoost）。输入是从 provenance graph 抽取的**简单可解释特征**（per-process IO count、syscall freq、neighbor type distribution 等）。DT 天然学 step boundary，适配 rule 类目标的离散尖锐决策。
> - **$S_{T_{\text{hybrid}}}$**：GraphSAGE + DT 二者集成 + 学习 gating（softmax 加权融合两者输出）。适配混合类目标。
> 
> **训练与 fitness**：§5.3 协同进化每轮的 (sample, target-label) 对分发给三个 $S_T$ 训练。对应真实 detector 类型的 $S_T$ 越训越准；其他类型的 $S_T$ 因架构与目标失配而落后。fitness 评估时，第 $i$ 个 population（type $T_i$）的 individual 用 $S_{T_i}$ 算 threat degree——形成"population 假设的类型 ↔ substitute 架构"的硬绑定。这一硬绑定让协同进化和 substitute 学习相互**信号增益**：population 越纯（fitness 越高、其他 population 凋亡），substitute 训练数据越聚焦，substitute 越准；substitute 越准，fitness 信号越精，population 收敛越快。
> 
> **与 BagAmmo §5.4 的精确差异**：BagAmmo 节点特征用 in/out-degree（FCG 域 well-defined）；PIDS 域 $S_{T_{\text{GNN}}}$ 沿用此设计，但 $S_{T_{\text{rule}}}$ 的特征改用 per-process 行为画像（与 §3.1 / §4.1 的 R3 用同一组特征——保证 rule-substitute 学到的判定边界与真实 rule detector 在同一特征空间），$S_{T_{\text{hybrid}}}$ 二者并用。

> ★ **总结**：本段是本工作相对 BagAmmo 的**唯一实质扩展**段——把单一同质 substitute 升级为 type-conditioned 异质 substitute 集合，并通过 §5.3 协同进化让"哪个 substitute 是真实类型"这件事自然涌现。其他章节都是 BagAmmo 设计的直接对应或 PIDS 域工程实例化，没有数学结构层面的新意。

---

## §5.5 Algorithm Design

### 1. 翻译 (BagAmmo §5.5 中文)

Apoem 致力于把多种群协同进化机制与 substitute 模型粘合起来共同生成对抗扰动。其主过程在 Algorithm 1 给出：$F$ 是目标分类器，$N$ 是 population 内 individual 上限，$r_{\max}$ 是最大代数。每次迭代中，Apoem 先随机选目标或 substitute 模型（第 3-6 行），为每个 individual 算 fitness（第 8-12 行），然后按 fitness 保留 high-rate individual（第 13 行），最后做 immigration、crossover、mutation（第 14 行）。当 substitute 被选中时还要训练它（第 15-17 行）。Apoem 终止时输出 fitness 最高的 individual。下面我们总结 Apoem 的重要考量。

**(1) 如何实现 Apoem 的协同进化？** Apoem 的协同进化是两重的。一方面 generator 和 discriminator 相互合作改进生成的扰动；另一方面多个 population 通过 immigration 协同进化。

**(2) 如何避免过早收敛？** 当一些 high-rate individual 的基因迅速主导 population [32] 时，过早收敛发生、进化算法收敛到局部最优。Apoem 通过 population 间协同缓解过早收敛——通过 immigration，不同 population 共享好基因并进一步推动进化。同时，immigration 也帮助 population 跳出局部最优陷阱。我们的理论分析见附录 10.2。

**(3) 何时终止算法？** Apoem 有三条终止准则：第一，所有 offspring 不再能在目标模型上诱导误分类；第二，连续若干代扰动量不再下降；第三，达到最大代数。

**(4) 如何按输出修改 APK？** 我们算法的输出是 caller-callee 函数对。按输出，我们用 §4 提到的 try-catch trap 把 callee 函数插入 caller 函数中实现对抗扰动。实现细节见附录 10.3。

### 2. BagAmmo 的 Logical Structure

- **算法主过程描述**：参数设定（$F$ / $N$ / $r_{\max}$）+ 迭代循环（target/substitute 选 → fitness → top-$N$ 保留 → immigration/crossover/mutation → substitute 训练）+ 终止时输出最优 individual
- **(1) 协同的两重性**：generator-discriminator + 多 population immigration
- **(2) 防过早收敛**：靠 immigration 共享基因 + 跳出局部最优（与 (1) 部分重叠）
- **(3) 终止条件 3 选 1**：无 offspring 致 misclassify / 扰动量不降 / 达 max 代
- **(4) 把 EA 输出落地到 APK**：caller-callee 对 → §4 try-catch trap → 真实 smali 修改
- 整段 = "Algorithm 1 描述 → 4 个 Q&A 形式的设计考量"

### 3. 仿照的 Logical Structure

- **算法主过程描述**：参数设定（$F$ / $N$ / $r_{\max}$）+ 迭代循环（target PIDS / type-conditioned $S_T$ 选 → fitness → top-$N$ 保留 → immigration/crossover/mutation → $\{S_T\}$ 训练）+ 终止时输出最优 $\delta$
- **(1) 协同的多重性**：generator-substitute + 多 type-population immigration + ★ 多 substitute 的同步训练（BagAmmo 单 substitute 没这层）
- **(2) 防过早收敛**：除 immigration 外，再加 ★ **type-population 之间的竞争压力**——即使一个 population 内过早收敛，错误类型的 population 会被 fitness 信号淘汰
- **(3) 终止条件**：三条同 BagAmmo + 一条 PIDS 特有：sandbox query 预算耗尽（PIDS 多了 sandbox 执行成本）
- **(4) 把 EA 输出落地到攻击命令序列**：candidate camouflage 命令组合 → §4.2 描述的"shadow command 机制"（命名待定）→ 真实命令序列扩展
- 保持 BagAmmo "Algorithm 1 描述 → Q&A 设计考量" 模板，但 (1)/(2) 反映 substitute set 的多元性、(3) 加 sandbox 预算约束

### 4. 仿照段落的内容（中文）

**算法主过程描述**：

> 本算法把 type-conditioned 多种群协同进化与 substitute set 粘合起来共同生成对抗扰动。其主过程在 Algorithm 1' 给出：$F$ 是目标 PIDS（黑盒 oracle），$N$ 是每个 population 内 individual 上限，$r_{\max}$ 是最大代数，$Q_{\max}$ 是 sandbox query 预算。每次迭代中，本算法先以变概率 $p(r) = \sigma(a \cdot (r/r_{\max} - b))$ 决定用目标 PIDS 还是用 type-conditioned substitute set $\{S_T\}$；为每个 individual 计算 fitness（用 $F$ 或 individual 所在 population 类型 $T$ 对应的 $S_T$）；按 fitness 保留 top-$N$ individual；执行 immigration / crossover / mutation。当 $\{S_T\}$ 被选中时同步训练 ★ ——把每个 (sample, target-label) 对分发给三个 $S_T$ 训练。终止时输出 fitness 最高的 individual $\delta^*$。

**(1) 如何实现协同进化？**

> 本算法的协同进化是 ★ **三重**的：(i) generator 与 substitute set 相互合作改进生成的扰动；(ii) 三个 type-population 通过 immigration 协同进化（fine-to-coarse 与 coarse-to-fine 的"语义转换"见 §5.3）；(iii) ★ **三个 $S_T$ 同步训练**——每轮真 query 的 (sample, target-label) 对分发给所有 $S_T$，对应真实 detector 类型的 $S_T$ 越训越准、其他类型的 $S_T$ 因架构失配自然落后。这层 (iii) 是 BagAmmo 单 substitute 设定下不存在的。

**(2) 如何避免过早收敛？**

> 除 BagAmmo 已有的 immigration 共享基因机制外，本算法还获得 ★ **type-population 之间的竞争压力**：即使某 type 的 population 内部过早收敛到局部最优，错误类型的 population 会被 substitute 反馈给的 fitness 信号识别（错误类型 $S_T$ 的 fitness 与 target $F$ 给出的 fitness 不一致 → individual 在交叉验证中得分低）→ 错误类型 population 在协同进化中淘汰。

**(3) 何时终止？**

> 本算法有四条终止准则：
> - 所有 offspring 在目标 PIDS 上无法诱导误分类
> - 连续若干代扰动量不再下降
> - 达到最大代数 $r_{\max}$
> - ★ 达到 sandbox query 预算 $Q_{\max}$（PIDS 特有，因为每次 query 真 PIDS 还需 sandbox 执行）

**(4) 如何把输出落地到攻击命令序列？**

> 本算法的输出是 candidate camouflage 命令组合 $\delta^* = (c_1^*, \ldots, c_n^*)$。按输出，我们用 §4.2 (3) 描述的"shadow command 机制"（命名待定）把这些 camouflage 命令插入到攻击命令序列 $A_0$ 之间，并在 sandbox 中执行得到最终扩展序列。每条 camouflage 命令必须满足 §4.2 (3) 三性质（audit 层有事件 / OS 状态层零干扰 / benign 中常见）以保 R1 + R2 + R3 + R4 同时成立。实现细节见附录。

> ★ **整章总结**（§5）：generator（type-conditioned 多种群进化）+ substitute set（type-conditioned $\{S_T\}$）+ training loop（变概率 + 同步训练）+ termination（含 sandbox 预算）+ APK 类比落地（命令序列 + shadow command）—— 这五件事联合解决了 §3.2 形式化的两个 task：(i) 在 $\delta$ 空间搜索 desirable 扰动；(ii) 适配未知异质 detector 类型。其中 (ii) 的应对（type-conditioned substitute set + 三重协同进化）是本工作的核心实质扩展，集中在 §5.4。

---

---

---
