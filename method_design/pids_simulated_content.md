# PIDS 仿照段落内容（中文）汇总

> 本文件抽取自 `pids_writing_thread.md` 中每段的 **"4. 仿照段落的内容（中文）"** 部分，集中放在一处方便阅读。
> 原文件 `pids_writing_thread.md` 不做任何修改。

---

## §3 章节引入 (chapter intro)

> 本节首先介绍我们工作中考虑的 PIDS 系统及其威胁模型，然后提出一个攻击形式化定义，用于指导黑盒对抗样本攻击的设计。

---

## §3.1 System & Threat

**第一段 · workflow narrative**：

> 图 1 描绘了本工作所考虑的基于 PIDS 的 Linux 主机入侵检测系统。假设攻击者对该系统发起黑盒对抗样本攻击以获得真正可逃避检测的攻击执行。为此，攻击者首先持有原始攻击命令序列 $A_0 = (c_1, \ldots, c_k)$（来自 Cybench、PentestGPT 或红队 playbook 的标准化命令链，攻击者既会写也会跑）。攻击者根据其扰动 $\delta$ 在 $A_0$ 的命令之间插入 camouflage 命令，**在 sandbox 中真实执行**得到的扩展序列 $A_0 \oplus \delta$，由 OS audit / eBPF 自然产出 provenance 子图 $\widetilde{G} = \text{MG}_{\text{cmd}}(A_0 \oplus \delta)$，如图 3 所示。攻击者随后用 $\widetilde{G}$ 去 query PIDS，利用收到的二元判定（benign / malicious）来更新 $\delta$，并据此构造新的扩展序列。上述过程重复进行，直至获得一个真正可逃避检测的攻击执行轨迹。

> ★ **关键差异（注脚或行内强调）**：与基于 APK 静态特征提取的恶意软件检测不同，PIDS 的输入是 **OS 实际执行所产生的 trace**——攻击者无法在不真实执行的情况下"凭空"得到 provenance graph。这使得 sandbox 执行成为攻击 pipeline 中不可或缺的一步。

**第二段 · known / unknown / defender 防御**：

> 攻击者只知道目标系统是 PIDS（接受 provenance graph 输入，输出 benign / malicious 二元标签）。但攻击者不知道目标系统的 **detector 类型**——它可能是基于 GNN 的图分类器、基于一阶规则的检测引擎、或两者的混合。此外，攻击者对 detector 的内部 embedding 函数、规则集、判定阈值，以及架构、参数和输出概率一无所知。至于防御方，可以使用 规则检测、命令白名单防御来抵御扩展序列攻击。此外，当某用户的 query 数量异常多时，防御方可触发告警。

> ★ **PIDS-specific extension point（首次出现，显式 flag）**：与已有黑盒攻击设定（攻击者面对的是单一同质分类器家族，例如不同 feature 粒度下的 GCN）不同，PIDS 设定下的"未知"跨越**数学结构异质**的 detector 类型——黑盒 GNN 给出连续平滑、近似可微的响应；黑盒规则引擎给出离散尖锐、阶梯式的响应；混合 detector 介于二者之间。这一异质性意味着单一 substitute 模型无法跨类型泛化，是后续 §5.4 设计的核心动机。本段仅指出此差异的**存在**，具体如何应对在 §5.4 展开。

---

## §3.2 Attack Formulation

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

> 本节首先介绍命令级 manipulation 的常见要求和已有技术，然后提出一种适用于 PIDS 黑盒攻击的新 manipulation 方法。

---

## §4.1 Background of Manipulation

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

> 在 §4.2 中我们提出了如何从 candidate camouflage 命令中选 desirable 命令的问题。为回答这个问题，我们开发了一个 substitute-augmented 黑盒搜索框架和算法（具体命名待用户决定）以找到所期望的对抗扰动 $\delta$。

---

## §5.1 Challenges & Solutions

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

## §5.2 The Overview of [method]

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
