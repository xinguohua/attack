# BagAmmo 论文完整中文翻译

> **原文**:Heng Li, Zhang Cheng, Bang Wu, Liheng Yuan, Cuiying Gao, Wei Yuan, Xiapu Luo
> **标题**:*Black-box Adversarial Example Attack towards FCG Based Android Malware Detection under Incomplete Feature Information*
> **会议**:USENIX Security 2023
> **机构**:华中科技大学(HUST)、香港理工大学(PolyU)、NSFOCUS
>
> 全文 §Abstract – §10 Appendix 均基于 PDF 原文按"句对句"口径整理:每个中文句对应原文一个英文句,不压句、不拆句、不自加段前小标题或总结。行内数学符号用反引号 code span(避开下划线被 md 当作斜体的问题),块公式用 `$$...$$` 包裹(支持 KaTeX/MathJax 的渲染器下会渲染为数学,不支持时也能完整看到原式)。原文 11 个脚注一一对应到 `bagammo-fn1`–`bagammo-fn11`。

---

## Abstract(摘要)

基于函数调用图(function call graph, FCG)的 Android 恶意软件检测方法近期因其良好的性能而吸引了越来越多的关注。然而,这些方法易受对抗样本(adversarial examples, AEs)的攻击。本文中,我们针对基于 FCG 的恶意软件检测系统设计了一种新颖的黑盒 AE 攻击,称为 BagAmmo。为了误导其目标系统,BagAmmo 通过向恶意软件代码中插入"永不执行"(never-executed)的函数调用,有意地扰动恶意软件的 FCG 特征。主要挑战有两方面。第一,恶意软件的功能不应被对抗扰动改变。第二,目标系统的信息(例如图特征粒度与输出概率)是缺失的。

为了保留恶意软件功能,BagAmmo 采用 try-catch trap 来插入函数调用,以扰动恶意软件的 FCG。在没有关于特征粒度与输出概率的知识的情况下,BagAmmo 采用生成对抗网络(generative adversarial network, GAN)的架构,并借助一种多种群协同进化算法(即 Apoem)来生成所期望的扰动。Apoem 中的每一个 population 代表一种可能的特征粒度,当 Apoem 收敛时,真实的特征粒度便能够被达到。

通过在超过 44k 个 Android app 与 32 个目标模型上的广泛实验,我们评估了 BagAmmo 的有效性、效率与韧性(resilience)。BagAmmo 在 MaMaDroid、APIGraph 与 GCN 上取得了超过 99.9% 的平均攻击成功率,并且在 concept drift 与数据不平衡的场景下仍然表现良好。此外,BagAmmo 在攻击成功率上超过了当前 SOTA 的攻击 SRL。

---

## §1 Introduction(引言)

Android 占据了全球移动操作系统市场约 85% 的份额,因而已经成为世界上移动恶意软件的主要目标。最近一份安全报告显示,平均每天大约有 10,000 个新的移动恶意软件样本被捕获 [20]。恶意软件的迅速增长给 Android 用户带来了严重的威胁 [30,37,49],例如隐私泄露与经济损失。为了应对这一问题,人们已经设计出多种基于机器学习的 Android 恶意软件检测方法,根据特征来识别恶意软件 [3,23,25,35,41,55,58,64,66,67]。

作为 Android 恶意软件检测的一种常用特征,函数调用图(Function Call Graph, FCG)[23,25,41,55,58,66,67](例如频繁子图 [15] 与 E-FCG [8])为理解 Android app 的工作方式提供了重要线索。在一个 FCG 中,每一个节点代表一个函数或一个抽象函数(例如,类、包或家族),每一条边表示 caller 与 callee 之间的调用关系。如 Fig 1 所示,基于 FCG 的 Android 恶意软件检测通常由三个步骤组成。第一,从 Android Package (APK) 文件中抽取出 FCG 特征(例如频繁子图)。第二,FCG 被转换为一个特征向量,即图嵌入(graph embedding)。第三,该特征向量被用于恶意软件预测。已有研究 [41,58,67] 表明,基于 FCG 的 Android 恶意软件检测方法能够取得良好的性能。

不幸的是,基于 FCG 的恶意软件检测易受对抗样本(adversarial examples, AEs)[9,40,48,50,51,62] 的攻击,对抗样本是通过对正常样本施加精心构造的对抗扰动以诱发误分类而生成的。为了逃避检测,攻击者只需对一个恶意 app 做 manipulation,即精心地修改(例如插入非功能性的函数调用)并重新打包其代码。虽然恶意软件的 manipulation 发生在 problem space 中(由 Fig 1 中的第一个方框描绘),但它改变了 FCG(例如添加新的边),并在 feature space 中扰动特征向量(由 Fig 1 中的第二个方框描述)。一旦扰动帮助特征向量越过目标分类器的决策边界,重新打包后的恶意软件就会逃避检测。

迄今为止,人们已经提出了多种针对 Android 恶意软件检测的 AE 攻击,用以产出可逃避检测的 Android 恶意软件。它们中的大多数 [21,24,27,33,34] 针对的是基于非图特征(即语法特征)的检测模型,这类模型采用二元特征向量进行 app 分类。近来,越来越多的关注被给予针对基于图特征(即语义特征)的检测模型 [6,10] 的 AE 攻击。例如,Bostani 等 [6] 在黑盒设定下利用随机搜索为 APK 文件寻找最优扰动。Chen 等 [10] 提出了一种在 Android APK 文件上施加最优扰动的方法。

迄今为止,如何产出能够规避基于 FCG 的检测的 Android 恶意软件,仍然是一个开放问题。这促使我们去研究 AE 的生成,以对抗基于 FCG 的 Android 恶意软件检测。在实践中,构造可逃避检测的恶意软件需要考虑以下尚未被充分解决的现实问题。

**(1) Malware functionality preservation(恶意软件功能保留)**。恶意软件的 manipulation 应能够在保留恶意软件功能的前提下误导其目标分类器。

**(2) Problem-feature space gap(problem-feature 空间间隙)**。由于 feature space 中的特征向量无法被直接扰动,攻击者必须在 problem space 中修改恶意软件代码,并期望其修改能在特征向量上带来所期望的对抗扰动。

**(3) Strict black-box setting(严格黑盒设定)**。对攻击者而言,目标分类器是一个严格的黑盒,其架构、参数与输出概率都是未知的。

**(4) Feature information absence(特征信息缺失)**。攻击者无法获得其目标分类器所使用的特征,即 FCG 与图嵌入得到的特征向量(在 Fig 1 中的第二个方框中标出)。此外,一个检测系统可能采用多种可能的特征粒度之一,例如 class level、package level 与 family level(如 §2.1 中所讨论)。在实践中,特征粒度信息对攻击者通常是不可获得的。

为了克服上述挑战,我们设计了一种采用多种群协同进化、针对基于 FCG 的 Android 恶意软件检测的黑盒攻击(black-box attacks towards FCG based Android malware detection with multi-population co-evolution),命名为 BagAmmo。BagAmmo 工作在不完全特征信息(incomplete feature information)的条件下,这意味着攻击者不知道其目标系统所使用的 FCG 特征的粒度。我们的主要任务包括设计一种用于 problem space 的恶意软件 manipulation 技术,以及开发一个算法以在 feature space 中得出对抗扰动。BagAmmo 构造了一个专用的生成对抗网络(Generative Adversarial Network, GAN),并在其 discriminator 的引导下,采用其 generator 来生成候选 manipulation。该 generator 由我们所提出的对抗多种群协同进化算法(Adversarial multi-population co-evolution algorithm, Apoem)实现。BagAmmo 用经过 manipulation 的样本迭代地查询其目标检测系统,并从一系列 query-reply 对中逐步学得所期望的 manipulation。BagAmmo 采用以下技术来克服上述挑战。

(1) BagAmmo 利用一种新颖的恶意软件 manipulation 方法 "try-catch trap" 向恶意软件代码中插入永不执行的函数调用,以实现功能保留。

(2) BagAmmo 把 FCG 映射为一个特征向量,从而把恶意软件 manipulation 的影响传递到 feature space,因此桥接了 problem-feature space gap。

(3) 为了克服严格黑盒的挑战,discriminator 替代目标分类器,引导 generator 快速找出 desirable 的 manipulation。

(4) 在 Apoem 中,每一个 population 都对应一种可能的特征粒度。得益于 population 之间的协同进化,在不完全特征信息下,Apoem 收敛到真实的特征粒度。

本文的主要贡献概括如下。

* 我们提出了一种针对基于 FCG 的 Android 恶意软件检测的新颖黑盒 AE 攻击 BagAmmo。BagAmmo 不需要关于 feature space 的完整信息,因此它是一种具有强泛化能力的广谱攻击。

* 我们从理论上分析了 Apoem 为什么能够缓解常困扰进化算法的过早收敛(prematurity)问题。

* 我们在三种 SOTA 的恶意软件检测方法 MaMaDroid [41]、APIGraph [67] 与 GCN [65] 之上,配合五种分类器(例如 RF 与 DNN),在三种特征粒度下开展了广泛实验。在我们的实验中,BagAmmo 超过了 SOTA 攻击(即基于强化学习的方法 SRL)。它在全部 32 个目标检测系统上取得了超过 99.9% 的平均攻击成功率。我们的实验同样确认了 BagAmmo 的攻击效率以及对 concept drift 与数据不平衡的韧性。

**Roadmap**。本文余下部分组织如下:§2 介绍预备知识;§3 给出问题形式化;§4 讨论如何对恶意软件做 manipulation;§5 描述扰动生成算法;§6 给出性能评估;§7 综述相关工作;§8 给出局限性与讨论。

---

## §2 Preliminaries(预备知识)

### §2.1 Features for Android malware detection(Android 恶意软件检测的特征)

本节我们关注那些在 app 执行前即可获得、且在 Android 恶意软件检测中被广泛使用的静态特征。早期的研究更多地关注语法特征(syntax features),例如:请求的权限(requested permissions)[14,35,70]、intent actions [18,44,64]、跨组件通信(Inter-Component Communications, ICCs)[4,17] 以及 API 调用 [3,47]。近期,语义特征(semantic features)[41,58,67](例如 FCG)开始受到越来越多的关注。它们能够刻画 app 的行为与功能,因此能取得不错的性能。

作为最常见的语义特征,FCG 通常基于 smali 文件构造而成。一个函数或一个抽象函数(abstracted function)既可以用它的函数名(例如 `java.lang.StrictMath: max()`)、类名(例如 `java.lang.StrictMath`)、包名(例如 `java.lang`),也可以用家族名(例如 `java`)来表示,作为 FCG 中的一个节点。因此,FCG 中存在四种特征粒度,即 function level、class level、package level 与 family level,如 Fig 2 所示。粒度更细的特征(例如 class level)通常具有更复杂的图结构,从而带来更重的计算开销,并需要做维度归约(dimensionality reduction)[41]。

显然,关于目标系统所采用特征粒度的知识对于攻击者生成 AE 是有帮助的。然而,该先验知识在实践中是难以获得的。因此,我们提出不完全特征信息假设(incomplete feature information assumption),即假设攻击者不知道目标系统所采用的特征粒度。

---

### §2.2 FCG based Android malware detection(基于 FCG 的 Android 恶意软件检测)

本节我们介绍三种 SOTA 的、基于 FCG 的检测方法,它们将在我们的实验中作为目标检测系统。

**Mamadroid**。Mamadroid [41] 把 package-level 或 family-level 的 FCG 作为其特征。更具体地说,它采用了 340 个 package 与 11 个 family。为了从一个 FCG 中提取特征向量,Mamadroid 基于 package 之间或 family 之间的转移概率构造了一条 Markov 链。所提取得到的特征向量随后被用于训练分类器(例如 KNN 与 SVM)以完成 app 分类。

**APIGraph**。与 Mamadroid 不同,APIGraph [67] 是一个通用框架,用于进一步增强基于图的 Android 恶意软件检测方法的性能。它采用一种聚类算法(例如 K-means),根据 FCG 节点(即函数)在语义上的相似度对其进行聚合。随后,它使用一个特定的函数代表每一个 cluster 内的所有函数。最终,APIGraph 构造出一个粒度更粗的新 FCG,其中每个节点表示一个由若干函数组成的 cluster,每条边表示两个 cluster 之间的调用。实验表明,这种新的 FCG 能带来更好的分类性能。

**GCN**。图卷积网络(Graph Convolutional Network, GCN)是一种强大的图嵌入方法,可被用于检测恶意软件。例如,在 [65] 中,GCN 被用来把控制流图(control flow graph)转换为用于恶意软件检测的特征向量[^bagammo-fn1]。在 §6 中,我们将把 GCN 应用于基于 FCG 的 Android 恶意软件检测。

[^bagammo-fn1]: [65] 主要研究的是如何攻击恶意软件检测器,尽管它本身提出的是一种基于 GCN 的恶意软件检测方法。

虽然这些方法已经取得了令人印象深刻的结果,但它们都易受对抗样本的攻击。对抗样本的存在,被归因于分类模型的决策边界并非理想 [26,52]。这个问题在 Android 恶意软件检测中变得更加严重,因为静态分析方法无法精确地建模恶意软件的行为。因此,现有的 Android 恶意软件检测系统并不真正安全 [2]。

---

## §3 Problem formulation(问题形式化)

本节我们首先介绍工作中所考虑的系统与威胁,随后提出一个攻击形式化定义,以指导黑盒 AE 攻击的设计。

---

### §3.1 System & Threat(系统与威胁)

Fig 1 描绘了本工作所考虑的、基于 FCG 的 Android 恶意软件检测系统。假设攻击者对该系统发起黑盒 AE 攻击,以产出真正可逃避检测的恶意软件。为此,攻击者首先从一个 APK 文件中取出 `classes.dex` 文件,并进一步把它反编译为一系列 smali 文件,如 Fig 3 所示。攻击者依据其扰动修改 smali 代码,然后重新构建代码以得到一个新的 APK 文件。随后,攻击者用所生成的恶意软件样本去 query 检测系统,利用所收到的二元判定(即 benign 或 malicious)更新其扰动,并据此重建一个新的恶意软件样本。上述过程不断重复,直至获得一个真正可逃避检测的恶意软件。

攻击者只知道目标系统采用 FCG 特征来进行恶意软件检测。然而,攻击者不知道目标系统所采用的特征粒度与图嵌入方法。此外,攻击者对目标分类器的架构、参数与输出概率均一无所知。至于防御者,它可以采用静态分析与基于白名单的防御来抵御逃避型恶意软件。此外,一旦某个用户的 query 次数异常多,防御者可以发出告警[^bagammo-fn2]。

[^bagammo-fn2]: 我们的实验表明,我们的方法仅需几十次 query 就能够生成可以成功攻击目标模型的扰动。此外,我们的方法可以通过进行更多的 query(例如几百次)进一步减少扰动数量。为了加速攻击过程,我们提供了一个 substitute 网络以拟合目标模型。相关实验见 §6.3。

---

### §3.2 Attack formulation(攻击形式化)

为方便起见,我们首先分别用 `s` 和 `m` 指代恶意软件样本与扰动(manipulation)。然后,我们用两个函数 `M_G(·)` 与 `M_V(·)` 来表示 Fig 1 中所示的代码到图(code-to-graph)映射与图到向量(graph-to-vector)映射。通过用 `m` 对恶意软件样本 `s` 施加扰动,攻击者把输入图从 `G = M_G(s)` 改变为 `G̃ = M_G(s+m)`,其中 `G` 与 `G̃` 分别表示原始的输入 FCG 与被扰动后的输入 FCG。`L(·)` 表示目标分类器所预测的标签(即 benign 或 malicious)。那么,所期望的对抗扰动 `m*` 可以通过求解下面这个问题得到:

$$
L(\mathcal{M}_V(\mathcal{M}_G(s))) \neq L(\mathcal{M}_V(\mathcal{M}_G(s+m^*))) \qquad (1)
$$

并需满足恶意软件功能保持的约束。

上述形式化为我们指出了两项任务:1) 设计一种 manipulation 技术,在保留恶意软件功能的前提下修改恶意软件代码;2) 开发一个对抗扰动生成算法以实现 `m*`。由于 problem-feature space gap 与严格黑盒设定带来的挑战,`M_G(·)` 与 `M_V(·)` 对攻击者而言实际上都是未知的。因此,一击命中(in one shot)得到所期望的对抗扰动是极其困难的。这促使我们去开发一种进化算法(即 Apoem),以逐步找到所期望的扰动。我们将分别在 §4 与 §5 讨论如何完成上述两项任务。

此外值得指出的是,机器学习社区已经提出了多种图对抗攻击模型 [5,12,40,48,57,62,71]。尽管这些方法对我们有所启发,但它们不能被直接应用于我们的攻击,原因有二。第一,图对抗攻击模型是从特征空间发起攻击的。然而,针对 Android 恶意软件检测的攻击无法直接访问特征空间,而必须通过在 problem space 中修改恶意软件代码来间接影响特征空间。第二,我们的攻击需要满足一些实际中的要求(即 §4.1 中将讨论的 R1–R4),而这些要求在现有的图对抗攻击中是缺失的。因此,恶意软件对抗攻击的设计需要专门的研究。

---

## §4 Malware manipulation(恶意软件 manipulation)

本节我们首先介绍恶意软件 manipulation 中常见的要求与已有的技术 [10,45,65],然后提出一种新的恶意软件 manipulation 技术。

---

### §4.1 Background of malware manipulation(恶意软件 manipulation 的背景)

尽管对恶意软件做 manipulation 直觉上很简单,但挑战来自以下要求。

**R1: Functional Consistency(功能一致性)**。在 manipulation 前后,恶意软件的功能必须保持一致。

**R2: All-granularities influence(影响所有粒度)**。由于恶意软件检测所采用的特征粒度(例如 family level 与 package level)是未知的,manipulation 应能够影响所有粒度的特征 [41]。

**R3: Resilience to static analysis(抗静态分析)**。恶意软件 manipulation 不应被静态分析检查所阻挡[^bagammo-fn3] [13,42],且不能完全依赖于 dead code(即不可达指令块)。

[^bagammo-fn3]: 本工作中,静态分析主要指那些仅检查源代码、而不执行程序的程序分析技术。

**R4: Non-stationary perturbation(非平稳扰动)**。manipulation 应是非平稳的,不能被限制在一组固定的操作之内(例如一份预先确定的白名单 [65]),以降低被识别的风险。

已有的 manipulation 方法总结如下。

**Inserting dead codes(插入死代码)**:为了维持功能一致性,[10] 选择向 smali 文件中插入 dead code(例如 no-op 调用)。不幸的是,这些代码很容易被检测并过滤掉,从而违反了 R3 要求。例如,[15] 提出了一种基于加权敏感 API 调用的 Android 恶意软件家族分类方法,它能够抵抗 no-op 调用的影响。

**Adding valueless calls(添加无效调用)**:[10] 创建了用户自定义类,并向其中加入无效调用(即调用空函数)。然而,这些调用容易受到静态分析的影响,且无法攻击 class 粒度的 FCG,从而违反了 R2 与 R3 要求。例如,[64] 中所提出的 Android 恶意软件检测方法不使用自定义函数作为特征。因此,该方法不受攻击者所插入的无效调用的影响。

**Adding functions from a white list(从白名单中添加函数)**:为了改变 FCG,[65] 的作者从一个预先确定的白名单中加入函数。然而,一旦对抗样本被捕获,白名单就会被揭示,对抗攻击便可能失效。请参见 R4 要求。

**Opaque predicates(不透明谓词)**:[45] 利用不透明谓词插入新的 API 以逃避恶意软件检测。具体而言,该方法构造一些晦涩条件(obfuscated conditions),其结果在设计阶段总是已知的,但其真值通过静态分析却难以或无法确定。因此,该方法能够有效抵抗静态分析。然而,它可能会引入一些 undesired 函数(例如 random 函数),从而对 FCG 造成预期之外的影响。

---

### §4.2 The proposed manipulation method(我们所提出的 manipulation 方法)

我们在此设计一种新的恶意软件 manipulation 方法,用于修改 smali 代码。根据 R1 要求,显然我们不能从 FCG 中移除节点或边。因此,我们只考虑添加(或插入)节点或边。然而,添加孤立节点(即那些既不被他人调用、也不调用他人的函数)是不被推荐的,原因有两点。第一,孤立节点很容易被静态分析检测到(例如,某些进行冗余代码消除(redundant code elimination)的程序分析技术会移除不可达代码 [22])。第二,添加节点通常无法影响特征空间,因为大量的恶意软件检测器使用边(而不是节点)来进行分类。因此,我们在 manipulation 方法中选择添加边(即 calls)。剩下的问题包括:如何创建 candidate 边、如何从 candidate 边中选出 desirable 边、以及如何插入所选的边。本节中我们只考虑第一个与第三个问题。第二个问题将在 §5 中解决。

**(1) 如何创建 candidate 边?** 迄今为止,如何在不完全特征信息(即特征粒度未知)下对 FCG 施加 R2 所要求的 all-granularities influence,仍未被充分研究。为了解决这一问题,我们提议在任意类型的两个节点之间,通过在一个 caller 与一个 callee 之间添加一次函数调用来创建一条边。无论使用何种特征粒度,该方法都会改变 FCG。问题随之变为:如何为每一条 candidate 边确定 caller 与 callee?由于 R4 要求,我们不能利用白名单来生成 caller 与 callee。取而代之,我们提议从恶意软件自身所使用的函数中生成它们。通过这种方式,我们可以确保为不同恶意软件所创建的 candidate 边是多样的,从而满足 R4 要求。

下面我们研究在何处放置所添加的边。如 Fig 4 所示,一个 FCG 由 non-leaf 节点与 leaf 节点构成。non-leaf 节点是用户自定义函数,而 leaf 节点对应于那些不调用他人的 Android 标准函数(例如 `java/io/File;->exists()`)。在我们的方法中,non-leaf 节点(即用户自定义函数)被选作 caller,因为它们很容易被插入新的函数调用。leaf 节点被选作 callee,因为调用一个不再调用他人的函数,将不会触发意外调用(unintended calls)。这里我们避免产生意外调用,是因为它们可能进一步对 FCG 施加我们预期之外的扰动。此外,关于 callee 选择的更多讨论见附录 10.1。现在我们可以使用上述方法来创建 candidate 边。在 §5 中,我们将提出一种算法,用于选出最 desirable 的边以进行 manipulation。

**(2) 如何插入所选的边?** 我们假设 desirable 边已经被选出,并研究在 R1 与 R3 的要求下,如何将相应的函数调用插入到 smali 文件中。我们所提出的方法称为 try-catch trap。它首先在 caller 中插入一个 try-catch 块,并把调用 callee 的语句放置在其 try 块中。然后,它在该函数调用语句之前再添加若干语句。这些语句用于触发一个预先选定的异常(例如算术异常)。下面我们分析为什么该方法能够 work。第一,它在 smali 文件中插入了一条函数调用语句,从而通过添加一条新的边改变了 FCG。第二,该函数调用语句永远不会被执行,从而保留了恶意软件的功能。作为示意,Fig 5 给出了 try-catch trap 的一个例子。假设左侧框中的代码来自某个恶意软件样本。函数 `callerEX()` 被选作我们的 caller。我们在该函数中放置一个 try-catch 块,并在 blue statement 执行之后调用函数 `callee()`。通过这种方式,我们可以向 FCG 中添加一条新的边,如 Fig 5 所示。当该 try-catch 块被执行时,将会抛出一个 `IndexOutOfBoundsException` 异常,函数调用语句也将被跳过。综上,我们的方法可被视为不透明谓词的一种变体。它精心构造了一些在静态分析过程中难以判定真值的晦涩条件,从而具备抵抗静态分析的能力。

插入函数调用的主要步骤将在附录 10.3 中作简要描述。

---

## §5 Adversarial perturbation generation(对抗扰动生成)

在 §4.2 中,我们提出了如何从 candidate 边中选出 desirable 边的问题。为了回答这个问题,我们开发一个新颖的 GAN 模型与 Apoem 算法,以找到所期望的对抗扰动。

---

### §5.1 Challenges & Solutions(挑战与对策)

下面我们首先介绍 BagAmmo 的主要过程。

(1) 给定一个预先选定的恶意软件样本,BagAmmo 从 smali 代码中找出一些 caller 与 callee,并用它们来创建一组 candidate 边,如 §4 所讨论的。借助 candidate 边,BagAmmo 通过对恶意软件做 manipulation 生成一系列样本,并把它们(即 query)发送给目标系统进行恶意软件检测。

(2) 目标模型针对一个 query 返回一个 reply。在我们的严格黑盒设定下 [68],每条 reply 都只包含二元分类结果(即 malicious 或 benign)。

(3) 通过从 query-reply 对中学习,BagAmmo 逐渐识别出最 desirable 的、能成功诱导误分类的边。

设计 BagAmmo 的主要挑战包括:1) 目标模型的特征粒度是未知的;2) 在严格黑盒攻击场景[^bagammo-fn4]下通常需要大量的 query [1,36]。下面对我们的对策作简要说明。

[^bagammo-fn4]: 在该场景下,§3.2 中提到的 `M_G(·)` 与 `M_V(·)` 都是未知的。此外,黑盒模型的 reply 只包含二元分类结果(例如,许多恶意软件检测网站 [54] 只返回二元判定而非类概率)。

**Surmising feature granularity(推断特征粒度)**。我们的对抗多种群协同进化算法,即 Apoem,用一个 population 来表示一种可能的特征粒度。多个 population 对应于多种可能的特征粒度,它们协同进化,直至对应真实特征粒度的那个 population 存活下来、其他 population 逐渐淡出。通过这种方式,BagAmmo 能够准确地识别出其目标模型所使用的特征粒度,这一点将在 §5.3 中展示。

**Reducing the number of queries(降低 query 数量)**。BagAmmo 构造一个新颖的 substitute 模型来模拟其目标模型。该 substitute 模型由 Apoem 所生成的样本以及目标模型所给的标签来训练。如 §5.4 所示,一旦 substitute 模型被训练好,BagAmmo 只需要攻击它而不必攻击目标模型,从而大大降低了 query 数量。

---

### §5.2 The overview of BagAmmo(BagAmmo 总体框架)

参照 GAN 的架构,BagAmmo 采用了一个 generator 与一个 discriminator,二者被协同地训练。

**Generator(生成器)**:generator 负责生成扰动,即添加到 FCG 中的新边。它由一种对抗多种群协同进化算法(即 Apoem)实现。

**Discriminator(判别器)**:discriminator 被引入以激励 generator 改进其扰动。它由一个 GCN 实现,作为一个 substitute 网络 [10] 来模拟目标模型。

**Training(训练)**:在每一轮模型训练中,generator 修改恶意软件的代码,并把重建后的恶意软件发送给目标模型或 substitute 模型进行恶意软件检测。BagAmmo 以一个可变的概率 `p` 在目标模型与 substitute 模型之间做选择。收到 query 后,目标模型送回其 reply,即二元判定(binary decisions)。借助 query-reply 对,BagAmmo 训练 substitute 模型,并引导其 generator 改进所生成的扰动。概率 `p` 随着轮次的增加而不断增大,以减少发送给目标模型的 query 数量。

---

### §5.3 Adversarial Multi-population co-evolution(对抗多种群协同进化)

generator 所面对的主要挑战是真实特征粒度未知。为了便于理解,我们考虑这样一种情形:目标系统使用 family-level 特征,而我们扰动的是 class-level 特征。在这种情形下,我们将陷入一个巨大的搜索空间,从而延长模型训练时间并需要更多的 query。为了缓解这一问题,BagAmmo 使用 Apoem 算法来推断真实的特征粒度。Apoem 遵循进化算法的一般框架,但引入了多种群之间的协同以加速收敛。随着进化的推进,对应真实特征粒度的 population 会逐渐从群体中脱颖而出。在下文中,我们首先描述 Fig 6 红色块中所示的 Apoem 的主要组件,然后讨论如何用这些组件来生成所期望的扰动。

**(1) Population & Individual(种群与个体)**。一个 population 代表在某种特征粒度下所生成的 AE 集合。例如,family-level 的 population 由"在假设目标分类器使用 family-level 的 FCG 作为输入"这一前提下所生成的 AE 组成。Apoem 采用多个 population,其中每一个都对应一种可能的特征粒度(即 family、package 与 class)。一个 population 内的每一个 individual 给出一个可施加于原始 FCG 上的扰动[^bagammo-fn5],即被添加到 FCG 中的边集。如 Fig 7 (a) 所示,上方的图表示原始 FCG,下方的图表示一个对抗样本。相应地,这里的扰动,即边集 `(A→E, B→D)`,被看作一个 individual。我们用 `x_r^(i,j)` 表示 Apoem 第 `r` 代中第 `i` 个 population 的第 `j` 个 individual。我们有 `x_r^(i,j) = {e_1^(i,j), e_2^(i,j), ..., e_n^(i,j)}`,其中 `e_k^(i,j)` (`1 ≤ k ≤ n`) 是被添加的边。在初始阶段,我们需要收集足够多的 individual 来构造 population。因此,我们随机扰动原始 FCG,并为每个 population 得到一组 individual。

[^bagammo-fn5]: 严格来说,一个 individual 指的是 population 中的一个对抗样本。然而,对抗样本与恶意样本之间的差异就是扰动。因此,我们用扰动来表示一个 individual。

**(2) Fitness & Selection(适应度与选择)**。Apoem 采用 fitness 这一度量来选出 superior individual、淘汰 inferior individual。该度量反映了一个 AE 的 aggressivity(攻击性)与 invisibility(隐蔽性)。其计算考虑两个因子:威胁度(threat degree)`T` 与扰动量(perturbation amount)`L`。威胁度根据目标模型 `F(·)` 或 substitute 模型 `S(·)` 的输出来度量[^bagammo-fn6]。对一个 individual `x`,威胁度定义为:

$$
T = \begin{cases}
1 - F(x) & \text{if target model is used} \\
1 - S(x) & \text{if substitute model is used}
\end{cases} \qquad (2)
$$

扰动量被计算为所添加的边的数量。此外,Apoem 引入了 elitist(精英)选择策略 [53],通过保留最适应的 individual、淘汰其他 individual,把好的基因传递到下一代。

[^bagammo-fn6]: 对于目标模型或 substitute 模型,当其输出 `F(x)` 或 `S(x)` 等于或趋近于 1 时,输入被判定为 malicious。

**(3) Immigration(迁移)**。一般而言,具有高 fitness 的 individual 更有可能产出更好的后代。为了产出更多高质量的 individual,Apoem 利用 immigration 操作把一个 population 内具有高 fitness 的 individual 迁移到其他 population。这样,superior individual 迁移到不同的 population,使所有 population 协同地进化,以生成更好的 AE。Apoem 中存在两种 immigration:fine-to-coarse(例如,从 class level 到 family level)与 coarse-to-fine(例如,从 family level 到 class level),如 Fig 7 (b) 所示。我们首先考虑 fine-to-coarse 的情形,即 class-level population 中的一个 individual 被迁入 package-level population。在这种情形下,与扰动相关的 package 名称(例如 `java.lang.StrictMath → java.lang`)会被保留下来,只含 package 名的 individual 随后被放入 package-level population。现在我们考虑 coarse-to-fine 的情形,即来自 package-level population 的 individual 被注入 class-level population。由于一个 package 可能包含多个 class,我们随机选取一个被恶意软件代码使用过的 class 来替换 package,然后把含 class 名的 individual 放入 class-level population。

**(4) Crossover(交叉)**。Apoem 利用 crossover 在两个 parent 之间随机交换基因以产出 offspring。更具体地说,从一个 population 中随机选出 `K` 对 individual 作为 parent,每一对中扰动的一半被交换以产出两个 offspring,如 Fig 7 (c) 所示。假设 parent 为 `x_r^(i,j1) = {e_1, e_2, e_3, e_4}^(i,j1)` 与 `x_r^(i,j2) = {e_1, e_2, e_3, e_4}^(i,j2)`,其中 `e_k^(i,j)` 是被添加的边(例如 Fig 7 (c) 中的 `A→E`)。经由 crossover 得到的 offspring 分别为 `x_{r+1}^(i,j1) = {e_1^(i,j1), e_2^(i,j1), e_3^(i,j2), e_4^(i,j2)}` 与 `x_{r+1}^(i,j2) = {e_1^(i,j2), e_2^(i,j2), e_3^(i,j1), e_4^(i,j1)}`。

**(5) Mutation(变异)**。Apoem 采用 mutation 给一个 population 带来新的变化。如 Fig 7 (d) 所示,存在三种可能的 mutation 模式:1) 在现有扰动上随机添加函数调用;2) 随机减少现有扰动;3) 随机交换现有扰动。它们在数学上分别可表示为 `x_{r+1}^(i,j) = {e_1^(i,j), ..., e_n^(i,j), e_{n+1}^(i,j)}`、`x_{r+1}^(i,j) = {e_1^(i,j), ..., e_{n-1}^(i,j)}`、以及 `x_{r+1}^(i,j) = {e_1^(i,j), ..., e_{n-1}^(i,j), e_{n+1}^(i,j)}`。

---

### §5.4 Substitute model(替代模型)

Apoem 只知道其目标模型的二元判定,这使得准确地评估 individual 变得困难。为了克服这一挑战,我们设计了一个新颖的 substitute 模型来模拟目标模型,并为 Apoem 提供近似的类概率(class probabilities)。

我们的 substitute 模型的输入是按 generator 所产生的扰动生成的 function-level FCG。我们使用一个 GCN(即 Graph Convolutional Network)从 substitute 模型中抽取特征,如 Fig 6 中的绿色块所示。GCN 把卷积扩展到图数据,擅长利用结构信息与节点信息来完成与图相关的机器学习任务。然而,将 GCN 应用于我们任务的主要障碍是节点属性的缺失。也就是说,FCG 不为其节点提供属性信息。为了缓解这一问题,我们提议把一个节点的**出度(out degree)** 与**入度(in degree)** 作为其特征。

下面我们简要说明如何使用一个 GCN 来从输入中抽取特征。GCN 包含多个卷积层。每一层使用某种传播规则聚合节点属性,聚合后的特征随后被下一层处理。相应地,通过迭代计算,我们可以得到一个表示 FCG 的特征向量。

---

### §5.5 Algorithm design(算法设计)

Apoem 致力于把多种群协同进化机制与 substitute 模型粘合起来,共同生成对抗扰动。其主要过程在 Algorithm 1 中给出。在该算法中,`F` 是目标分类器,`N` 是一个 population 中 individual 的最大数量,`r_max` 表示最大代数。在每一次迭代中,Apoem 首先随机选择目标模型或 substitute 模型(第 3-6 行),为每一个 individual 计算 fitness(第 8-12 行),然后基于 fitness 保留 high-rate individual(第 13 行),最后进行 immigration、crossover 与 mutation(第 14 行)。此外,当 substitute 模型被选中时,它也应当被训练,如第 15-17 行所示。当 Apoem 终止时,具有最高 fitness 的 individual 被输出。下面我们总结 Apoem 的重要考量。

**(1) How to implement co-evolution in Apoem?(如何在 Apoem 中实现协同进化?)**
Apoem 中的协同进化是双重的。一方面,generator 与 discriminator 相互配合以改进所生成的扰动。另一方面,多个 population 通过 immigration 协同进化。

**(2) How to avoid premature convergence?(如何避免过早收敛?)**
当一些 high-rate individual 的基因迅速主导整个 population [32] 时,过早收敛便会发生,进化算法收敛到一个局部最优。Apoem 能够借助 population 之间的协同来缓解过早收敛。通过 immigration,不同的 population 分享它们好的基因,并进一步推动其进化。同时,immigration 也帮助 population 跳出局部最优的陷阱。我们的理论分析见附录 10.2。

**(3) When to terminate our algorithm?(何时终止我们的算法?)**
Apoem 有三条终止准则。第一,所有 offspring 都不再能在目标模型上诱导误分类。第二,扰动量在连续若干轮中不再下降。第三,达到最大轮数。

**(4) How to modify the APK according to the output?(如何根据输出修改 APK?)**
我们算法的输出是 caller-callee 函数对。根据该输出,我们使用 §4 中所提到的 try-catch trap 把 callee 函数插入到 caller 函数中,以实现对抗扰动。实现细节可见附录 10.3。

---

## §6 Experiments(实验)

本节中,我们通过回答以下研究问题来开展广泛的实验以评估 BagAmmo:

**RQ1: Effectiveness(有效性)**。BagAmmo 能否成功攻击 SOTA 的 Android 恶意软件检测方法?

**RQ2: Evolution(进化)**。Apoem 中的多个 population 是如何进化的?

**RQ3: Efficiency(效率)**。substitute 模型是否有助于减少 query 数量并提高攻击效率?

**RQ4: Overhead(开销)**。manipulation 开销与攻击成功率之间是否存在权衡?

**RQ5: Resilience(韧性)**。在存在 concept drift 或数据不平衡时,BagAmmo 是否仍然有效?

**RQ6: Functionality(功能)**。我们的对抗扰动是否改变了恶意软件的功能?

**Datasets(数据集)**。
我们的数据集包含 21,399 个 benign 样本与 22,975 个 malicious 样本,它们来自 Androzoo[^bagammo-fn7]、Faldroid 数据集 [15] 与 Drebin 数据集 [3]。从 Androzoo 收集的每一条样本都由 VirusTotal [54] 进行检测。只有当一条样本被超过 4 个反病毒系统判定为 malicious 时,我们才将其标记为 malware。数据集的细节见附录 10.4。

[^bagammo-fn7]: https://androzoo.uni.lu/

此外,我们的实验采用两种配置来评估 BagAmmo。在第一种配置中,我们使用 10-fold 交叉验证来训练目标模型。为了评估各攻击方法,我们随机选取 100 个 malicious 样本(不包含在目标模型的训练数据中)且这些样本能被目标模型正确分类,用于逃避型恶意软件的生成。在第二种配置中,我们按 Android app 出现的年份对数据集进行划分,如 §6.5 所讨论。新近出现的恶意软件样本被用作测试,而旧数据则被用于训练。

最后,在 §6.5 中我们也考虑 concept drift 与数据不平衡两种场景。在 concept drift 场景下,来自 Androzoo 的 17,685 条样本(8,017 个 benign 与 9,668 个 malicious)按生产年份(2016 到 2020 年)分组,并用于训练目标模型。在数据不平衡场景下,我们随机打乱样本,并将 benign-malicious 比例设为 10:1,与 [2] 中的实验设置保持一致。

**Target Model(目标模型)**。
我们选择三种 SOTA 的恶意软件检测方法(即 MaMadroid [41]、APIGraph [67] 与 GCN [65])作为目标系统。在 MaMadroid 与 APIGraph 中,我们分别采用 Random Forest (RF) [7]、AdaBoost (AB) [11]、1-Nearest Neighbor (1-NN) [19]、3-Nearest Neighbor (3-NN) 与 Dense Neural Network (DNN) 作为目标分类器。与 [65] 类似,我们在基于 GCN 的方法中使用一个两层的 DNN 作为目标分类器。

**Metric(指标)**。
我们使用攻击成功率(attack success rate, ASR)、平均扰动比(average perturbation ratio, APR)以及交互轮数(number of interaction rounds, IR)来评估 BagAmmo。ASR 对应于成功生成的 AE 数量(记为 `N_success`)与用于 AE 生成的 malicious 样本数量(记为 `N_total`)之比,即 `ASR = N_success / N_total`。APR 是新添加的边的数量(记为 `E_added`)与总边数(记为 `E_total`)之比,即 `APR = E_added / E_total`。IR 被定义为我们的攻击模型与目标模型之间的交互次数。

---

### §6.1 RQ1: Effectiveness(有效性)

**Experimental Setup(实验设置)**。
为了验证 BagAmmo 的攻击有效性,我们用 BagAmmo 攻击上述 32 个目标模型[^bagammo-fn8],并在每一个目标模型上计算 ASR、APR 与 IR。

[^bagammo-fn8]: 我们的实验使用 2 种传统的、基于 FCG 的特征抽取方法(MaMadroid 与 APIGraph)、3 种特征粒度(class、family 与 package)以及 5 种目标分类器(RF、AB 等)。此外,1 种 GCN 特征抽取方法搭配了 2 种特征粒度(family 与 package)。因此一共有 `32 = 2 × 3 × 5 + 1 × 2` 个分类器。

此外,我们还把 BagAmmo 与三种攻击方法做对比,即 SRL [65]、SRL_N 与 Random Insertion (RI)。据我们所知,SRL 是 SOTA 的恶意软件 AE 生成方法[^bagammo-fn9]。由于 SRL 需要知道目标模型输出的类概率,我们修改了它的 reward 函数,创建了一个只依赖二元输出的 SRL 变体(即 SRL_N)。RI 攻击方法也是从 [65] 引入的,它随机插入非功能性函数。

[^bagammo-fn9]: 注意 SRL 是在控制流图(control flow graph)上工作的,而非 FCG。为了把 SRL 应用到基于 FCG 的 Android 恶意软件检测上,我们设计了一个非功能性 API 列表(取代非功能性指令列表),其中包含 17 个非功能性 API。

**Results & Analyses(结果与分析)**。
Table 1 反映了 BagAmmo 在不同特征粒度下,对 MaMaDroid、APIGraph 与 GCN 的攻击表现。第一,BagAmmo 在 32 个目标模型上取得了平均 99.9% 的 ASR,从而确认了 BagAmmo 的有效性。第二,在攻击 family 粒度的分类器时,BagAmmo 取得了最低的 APR 与 IR(即 0.071 与 10.936)。这表明,虽然 family 粒度的 FCG 通过降低输入复杂度加快了恶意软件检测,但它同样通过缩小搜索空间提高了 BagAmmo 的效率。

Fig 8 比较了 BagAmmo、SRL、SRL_N 与 RI 在不同 APR 下的 ASR。不出所料,RI 在我们的实验中表现最差,原因是其搜索策略很差。SRL 优于 SRL_N,因为 SRL 可以拿到类概率,而类概率比二元判定更有价值。值得注意的是,尽管 BagAmmo 无法利用类概率,它仍然优于 SRL(例如在 APR=0.2 时其 ASR 高 4%)。上述结果证实:在一定的扰动数量下,与其他方法相比,我们的方法所生成的新增边组合对检测器更具欺骗性。

---

### §6.2 RQ2: Evolution(进化)

**Experimental Setup(实验设置)**。
在本节中,我们通过实验来分析多种群协同进化机制的效果。首先,我们希望证明该机制能够克服特征粒度未知的挑战。为此,我们将我们的方法与单种群方法在攻击 MaMaDroid 上做对比。这些单种群方法只依赖一个对应于 class、package 或 family 级别的 population,分别记为 BagAmmo-C、BagAmmo-P 与 BagAmmo-F。我们也随机选取一个恶意软件样本,仔细考察这些方法的攻击过程。

第二,我们希望知道我们的方法是否能找到正确的特征粒度。我们随后记录每个 population 的存活数量,并分析这些 population 是如何进化的。在本实验中,我们选取带 RF 分类器的 MaMaDroid 作为目标模型,并在恶意软件检测中使用 family 级别的特征粒度。

**Results & Analyses(结果与分析)**。
为便于比较,我们选定 family 级别的特征粒度,并在全部测试样本上评估 BagAmmo 与单种群方法。结果展示于 Fig 9。可以看出,BagAmmo 表现最佳,以最低的 APR 取得了最高的 ASR。BagAmmo-C 与 BagAmmo-P 表现最差,因为它们使用了错误的特征粒度。令人惊讶的是,BagAmmo 比 BagAmmo-F 表现更好(即 ASR 高 2%、APR 低 0.06)。这是因为引入多个 population 有助于避免过早收敛,并接近全局最优。然而,这可能会带来与目标模型更多的交互。这就解释了为什么 BagAmmo 的 IR 比 BagAmmo-F 高。

现在我们随机选取一个恶意软件样本,并用它来生成一个 AE,在 family 级别的特征粒度下攻击 5 种分类器。所有方法的攻击过程描绘于 Fig 10。在这张图中,纵轴表示所有方法的扰动比,横轴表示 IR 值。如果某条曲线显示出明显的下降趋势并跌到一个较低的阈值之下,我们就可以断定相应的方法成功地生成了一个 AE 并攻破了目标模型。至于那些保持水平的曲线(例如第一个子图中的绿色曲线),其对应的方法则未能生成 AE。Fig 10 显示 multi-population 的扰动比始终具有令人满意的下降趋势,从而确认了多种群协同进化的效果。此外,使用单一 population 可能导致过早收敛到局部最优,如 Fig 10-(1) 所示。然而,BagAmmo 通过使用多个 population 有效地缓解了这一问题。理论分析见附录 10.2。

最后,我们从另一个角度验证多种群协同进化方法收敛到真实特征粒度。我们在 Fig 11 中展示不同 population 的存活比例(即存活 individual 的数量与 individual 总数之比)。一开始,扰动是随机加入的,不同 population 的存活比例并无规律。然而,随着 query 数量的增加,family population 与 class population 逐渐降到一个较低的水平。相反,对应正确特征粒度(即 family level)的那个 population 的存活比例逐渐升至一个较高的水平。这一现象同样确认了多种群协同进化的效果。

---

### §6.3 RQ3: Efficiency(效率)

**Experimental Setup(实验设置)**。
我们进行消融实验,以验证 substitute 模型在减少 query 数量与提高攻击效率方面的效果。为便于对比,我们移除 substitute 模型,只用目标模型来引导多种群协同进化算法。该方法被称为 BagAmmo-Without-S。然后我们使用 BagAmmo 与 BagAmmo-Without-S 对同一个 APK 文件做 manipulation,并比较它们的表现。

**Results & Analyses(结果与分析)**。
substitute 模型的效果展示于 Fig 12,其中实线与虚线分别表示 BagAmmo 与 BagAmmo-Without-S。纵轴反映扰动比,横轴表示 query 数量。可以看到,在所有情形下,BagAmmo 都具有更快的收敛速度。此外,在扰动比保持在某一阈值(例如 0.1)以下之前,BagAmmo 始终需要更少的 query。需要注意的是,两种方法在初始阶段的差异相对较小。这是因为 substitute 模型在该阶段尚未被很好地训练。然而,一旦 substitute 模型用足够多的数据训练好[^bagammo-fn10],BagAmmo 就表现得更高效,体现出其优势。

[^bagammo-fn10]: 一般而言,substitute 模型的训练精度会随着迭代轮数的增加而上升。然而,训练精度的上升趋势并不严格单调,因为各次迭代中所使用的训练数据是不同的。

Fig 13 在 IR 方面比较了 BagAmmo 与 BagAmmo-Without-S。其上半部分给出了基于 family 级别 FCG 的 MaMadroid 上的结果,下半部分给出了基于 package 级别 FCG 的 MaMadroid 上的结果。横轴表示不同的分类器(例如 AB、RF 与 1-NN)。我们从这张图可以得出两个结论。第一,package 级别的分类器更难被攻击。这是因为 package 级别的 FCG 所包含的节点比 family 级别的 FCG 多得多,从而给 BagAmmo 带来更大的搜索空间。第二,使用 substitute 模型在几乎所有情形下都减少了 query 数量,有助于提升攻击效率。

---

### §6.4 RQ4: Manipulation Overhead(manipulation 开销)

**Experimental Setup(实验设置)**。
在此我们研究生成一个真正逃避型恶意软件所需要的代码修改数量(即 manipulation 开销)。我们用实验结果来反映 ASR 与所允许的扰动比之间的关系。

**Result & Analysis(结果与分析)**。
实验结果展示于 Fig 14。在这张图中,横轴表示所允许的扰动比,纵轴给出 ASR 的累积分布函数(cumulative distribution function, CDF)。可以观察到,ASR 随着所允许的扰动比的增加而不断上升。在实际中,更大的扰动比对攻击者意味着更大的计算开销。因此,manipulation 开销与攻击成功率之间存在权衡。此外,3-NN 分类器比 1-NN 分类器更鲁棒。这是因为 3-NN 分类器在分类一条样本时考虑了比 1-NN 分类器更多的数据,使其更容易区分 benign 与 malicious app。

---

### §6.5 RQ5: Resilience(韧性)

**Experimental Setup(实验设置)**。
Concept drift [63] 在 Android 恶意软件检测的真实应用中经常被观察到。如果白名单没有相应更新,concept drift 会破坏那些从预先确定的白名单中挑选 API 进行插入的现有 AE 生成方法。因此我们希望知道 BagAmmo 是否也易受 concept drift 影响。为此,我们用新近出现的恶意软件样本来生成 AE,去攻击那些在旧数据上训练的分类器。我们按 Android app 出现的年份把数据集划分为训练集与测试集。我们构造了 4 个新数据集来评估 concept drift 下的 BagAmmo,如 Table 2 所示。Table 2 的第一行是用于训练目标分类器的训练样本的年份。第二行是用于生成 AE 的测试样本的年份。第三行是分类器的精度。

数据不平衡是另一个值得考虑的实际问题 [2,16]。由于恶意样本比 benign 样本更难收集,恶意软件检测模型通常是在不平衡数据上训练的。我们希望知道数据不平衡是否会对 BagAmmo 的攻击表现带来负面影响。因此,我们在用不平衡数据(benign-malicious 比例为 10:1)训练的目标模型上评估 BagAmmo。

**Result & Analysis(结果与分析)**。
在 concept drift 的实验中,我们用 BagAmmo 对测试样本做 manipulation,所得到的结果被用于攻击带 family 级别特征与 RF 分类器的 MaMaDroid 模型。BagAmmo 在每一种场景下的 ASR 都呈现在 Table 2 的最后一行。第一,该表表明,随着训练样本越多,目标分类器的精度越高。然而,无论精度多高,BagAmmo 总能取得 100% 的完美 ASR。这表明 BagAmmo 在 concept drift 下表现良好,即使恶意软件检测模型用新数据学到了更多,它仍然有效。需要注意的是,BagAmmo 使用来自恶意软件自身的函数(而非一个静态函数集合)。BagAmmo 降低了使用那些由于 concept drift 而过时的函数的风险。因此,BagAmmo 对恶意软件检测器构成持久的威胁。最后,关于在防御者掌握对抗样本知识时 BagAmmo 的表现,我们在附录 10.5 中讨论。

Table 3 展示了 BagAmmo 在平衡数据与不平衡数据两种情形下的实验结果。我们的实验显示,DNN 模型在用不平衡数据训练时表现非常差。因此,我们不选 DNN 作为我们的目标模型。在两种情形下(即平衡攻击数据集与不平衡数据集),BagAmmo 都取得了 100% 的攻击成功率(即 ASR)。此处我们在 Table 3 中只展示 APR 的数值。更高的 APR 意味着更困难的攻击任务。可以看出,在绝大多数情形下,BagAmmo 攻击在不平衡数据上训练的目标模型时所需的扰动更少(即 APR 更低)。也就是说,数据不平衡并未给 BagAmmo 带来麻烦。这是因为用不平衡数据训练会使目标模型更倾向于把恶意软件判定为 benign app。相应地,这也降低了 AE 生成的难度。

---

### §6.6 RQ6: Functionality(功能)

**Experimental Setup(实验设置)**。
在本节中,我们首先使用静态分析来验证 BagAmmo 所生成的扰动是否被成功施加到恶意软件之上。然后,我们采用动态分析来检查扰动是否改变了恶意软件的功能。

**Result & Analysis(结果与分析)**。
为了知道我们的扰动是否被注入,我们在每一次注入扰动(即 try-catch trap)时添加一条独特的 log 语句。这条 log 语句可以帮助我们在 smali 文件中找到该扰动。然后我们检查在 smali 文件中找到的函数调用是否与 BagAmmo 所生成的扰动一致。在我们的实验中,我们评估了 50 个 APK 文件,发现所有生成的扰动都被正确地注入了 smali 文件中。

在我们的动态分析实验中,我们首先在 Android Virtual Device (AVD) 中安装并运行 50 对原始恶意软件样本与扰动后恶意软件样本。可以观察到,每一对恶意软件的表现都是一样的,具有相同的运行时 UI。为了进一步分析,我们在每一个 try-catch 块中插入了三条 log 语句,分别记为 LOG1、LOG2 与 LOG3,用以记录执行信息。LOG1 位于运行时异常之前,LOG2 位于所插入函数之前,LOG3 位于 catch 块的开头。我们借助 Android Studio 的日志分析工具(即 LogCat)分析了 50 个 APK 文件。我们发现每一个 APK 文件的 LOG1 或 LOG3 都被正常执行,但没有任何 LOG2 被执行。这一现象意味着所有被 manipulation 过的恶意软件样本都正常运行,所插入的函数没有被调用,因此对恶意软件的功能毫无影响。

---

## §7 Related Work(相关工作)

近来,对抗攻击已经被广泛用于各种领域,即图像分类 [60,61]、流量分析 [43,46]、自动驾驶 [28,29] 与目标检测 [39]。至于 Android 恶意软件检测,已经有许多研究 [21,24,27,33,34] 关注面向语法特征的 AE 生成。Huang 等 [27] 使用 saddle-point 优化形式化,在离散(例如二元)域中为恶意软件检测生成对抗样本。Grosse 等 [21] 扩展了现有的 AE 生成算法,构造了一种针对恶意软件检测模型的高效攻击。在 [24,34] 中,Hu 等利用 GAN 在黑盒模式下为恶意软件检测生成对抗样本。Li 等 [33] 提出了一种集成方法,允许攻击者通过多种攻击方法与多种 manipulation 集合对一个恶意软件样本施加扰动。

为了取得更高的检测精度,越来越多的 Android 恶意软件检测方法 [41,58,67] 关注于语义特征。Chen 等 [10] 引入了图像分类中的两种 AE 生成方法用以检测 Android 恶意软件,并提出了一种将最优扰动施加到 Android APK 之上的方法。他们的方法直接在特征空间中扰动特征。Pierazzi 等 [45] 从 benign APK 中抽取字节码切片(即 gadget),并将其注入到一个恶意 APK 中,以生成对抗型恶意软件。Zhang 等 [65] 提出了一种基于强化学习的攻击,用以欺骗基于图特征的恶意软件检测模型。近来,Bostani 等 [6] 提出了一种有趣的黑盒攻击 EvadeDroid,它不需要关于特征空间的知识。与 BagAmmo 不同,EvadeDroid 采用随机搜索,从 benign app 的代码中找到所期望的扰动。

---

## §8 Limitations and Discussion(局限性与讨论)

本文中,我们提出了一种针对基于 FCG 的 Android 恶意软件检测的黑盒 AE 攻击 BagAmmo。我们希望我们的工作对 Android 恶意软件检测的研究具有参考价值,并引起人们对 AE 攻击所构成威胁的关注。此外,我们的方法可被用于评估现有 Android 恶意软件检测方法的鲁棒性。下面我们讨论一些局限性与未来工作。

**Dynamic analysis based defense(基于动态分析的防御)**。我们的方法针对的是静态分析方法。它依赖于通过插入函数调用来改变 FCG。但它并未改变恶意软件的信息流。因此,它不会对动态分析 [31] 带来负面影响。在未来工作中,我们将探索如何针对基于动态分析的 Android 恶意软件检测方法构造对抗样本。

**Transfer to other domains(迁移到其他领域)**。BagAmmo 的思想与框架可在一定程度上迁移到其他领域,因为许多领域都使用语义特征与图结构数据(例如入侵检测系统 [69] 与轨迹预测系统 [56,59])。

**Try/catch detection based defense(基于 try/catch 检测的防御)**。另一个担忧是,防御方是否能够通过统计 try/catch 块的数量来检测 BagAmmo 所生成的 AE。这种防御方法需要一个针对 try-catch 块数量的检测阈值。然而,通过比较原始恶意 APK 的 try-catch 块数量与对抗扰动后 APK 的 try-catch 块数量,我们发现我们的方法所添加的 try-catch 块数量相对较少。因此,很难为所有 APK 找到一个合适的阈值。如果没有这样的阈值,这种防御方法可能会带来很高的误报或漏报率[^bagammo-fn11]。

[^bagammo-fn11]: 更多实验结果可见附录 10.7。

---

## §9 Acknowledgments(致谢)

This work was supported partially by the Hong Kong RGC Project (No. PolyU15219319), HKPolyU Grant No.ZVG0, Fundamental Research Funds for the Central Universities (HUST: Grant No. YCJJ202202016 and 2022JYCXJJ035).

---

## §10 Appendix(附录)

### §10.1 The limitations in callee selection(callee 选择的局限性)

如 §4.2 所示,我们选取 leaf 节点作为 candidate callee。然而,并非所有 leaf 节点都可以被选作 callee。存在两个限制:

**Access modifier(访问修饰符)**。某些 leaf 节点函数完全不被允许调用。因此,我们只考虑那些访问修饰符为 `public` 的 leaf 节点函数。

**Parameter type(参数类型)**。某些 leaf 节点函数的参数是类的实例。在这种情况下,调用这些函数会带来类的实例化,从而产生一条 unintended 边。为了避免这个问题,我们提议选取那些参数为 void、或属于原始数据类型(例如 `int` 与 `short`)与 `String` 类范畴的 leaf 节点函数。

---

### §10.2 Theoretical Analyses for our method(我们方法的理论分析)

我们的方法 BagAmmo 利用 Apoem 算法为一个给定的恶意软件样本寻找所期望的扰动。由于 Apoem 是一种进化算法,如何缓解过早收敛(premature convergence)是一个重要问题。这里,过早收敛(premature convergence,或 prematurity)是一种常见现象,它会使一个进化算法迅速收敛到一个局部最优。对进化算法而言,prematurity 常常是由基因多样性的缺失所导致的。

下文中,我们分析 Apoem 中所引入的多个 population 是如何缓解过早收敛问题的。

由于多个 population 的引入,每一个 population 中都存在一个局部最优解。我们将这个局部最优解定义为 `x_p*`,其中 `p = 1, 2, ..., l` 是 population 的索引。

然后,能够通过 Apoem `G` 达到这些局部最优解的 individual 被记为:

$$
A_p^* = \{x \in A : G(x) = x_p^*\} \qquad (3)
$$

其中 `A` 是解空间。

然后,一个 individual `x ∈ A` 属于集合 `A_p*` 的概率可以被表示为 `θ_p = P(A_p*)`。显然,对 `p = 1, ..., l` 都有 `θ_p > 0`,且 `Σ_{p=1}^l θ_p = 1`。

集合 `A_p*` 的大小可以被记为 `n_p`。按照定义,我们有 `n_p ≥ 0` (`p = 1, ..., l`),随机向量 `(N_1, ..., N_l)` 服从多项分布,且 `Σ_{p=1}^l N_p = N`。

$$
\Pr\{n_1 = N_1, \ldots, n_l = N_l\} = \binom{N}{N_1, \ldots, N_l} \theta_1^{N_1} \cdots \theta_l^{N_l} \qquad (4)
$$

其中

$$
\binom{N}{N_1, \ldots, N_l} = \frac{N!}{N_1! \cdots N_l!}, \quad N_p \ge 0 \;\; (p = 1, \ldots, l) \qquad (5)
$$

我们将 `W` 定义为 Apoem 所找到的局部最优解的数量。那么,找到 `l` 个局部最优解的概率可以被记为

$$
\Pr\{W = l \mid \theta\} = \sum_{N_1 + \ldots + N_l = N} \binom{N}{N_1, \ldots, N_l} \theta_1^{N_1} \cdots \theta_l^{N_l} \qquad (6)
$$

其中

$$
\theta = (\theta_1, \ldots, \theta_l). \qquad (7)
$$

为了分析极限情形,我们定义

$$
\delta = \min\{\theta_1, \ldots, \theta_l\} \le 1/l \qquad (8)
$$

那么我们有

$$
\Pr\{W = l \mid \theta\} \ge \sum_{N_1 + \ldots + N_l = N} \binom{N}{N_1, \ldots, N_l} \delta^N = (\delta l)^N \Pr\left\{W = l \;\middle|\; \left(\tfrac{1}{l}, \ldots, \tfrac{1}{l}\right)\right\} \qquad (9)
$$

对任意的 `l` 与 `θ`,我们可以找到最小的 evaluation 数 `n*`,使得对任意给定的 `γ ∈ (0,1)`,对所有 `n ≥ n*` 都有 `Pr{W = l | θ} ≥ γ`。寻找 `n* = n*(γ, θ)` 是这样一个问题:在 `A` 中找到(最少)多少个点,才能使得所有局部极小点都被找到的概率至少为 `γ`。

我们分析极端情形,即 `θ* = (l^{-1}, ..., l^{-1})`。因此,寻找 `n*(γ, θ)` 的问题被归约为寻找 `n*(γ, θ*)` 的问题。对一个较大的 `N`,`n*(γ, θ)` 可以被近似为

$$
\begin{aligned}
\Pr\{W = l \mid \theta^*\} &= l^{-N} \sum_{N_1 + \ldots + N_l = N} \binom{N}{N_1, \ldots, N_l} \\
&= \sum_{p=0}^{l} (-1)^p \binom{l}{p} (1 - p/l)^N \\
&\sim \exp\{-l \exp\{-N/l\}\}, \quad N \to \infty
\end{aligned} \qquad (10)
$$

通过对 `N` 求解方程 `exp(-l exp(-N/l)) = γ`,我们得到如下近似:

$$
n^*(\gamma, \theta^*) \simeq l \ln l + l \ln(-\ln \gamma) \qquad (11)
$$

借助 Eq.(11),我们如下分析所需 query 数量与 population 数量之间的关系。我们可以看到,多个 population(即 `l > 1`)有助于减慢算法的收敛速度。我们都知道,prematurity 是一种常见现象,即进化算法过早地收敛到一个差的局部最优。然而,Apoem 在 `l` 个起点开始搜索,这使得算法能够以更高的概率找到一个更好的解。我们的算法通过引入多个 population 有效地缓解了这一问题,避免算法在反复找到同一个局部最优上浪费大量努力。

---

### §10.3 Implementation details and an instance of the smali code(实现细节与 smali 代码示例)

在本节中,我们首先提供从 generator 的输出到对恶意软件样本上的扰动这一变换的实现细节。然后我们给出一个 smali 代码的示例。

generator 的输出是 caller-callee 函数对。实现 output-to-perturbation 变换有三个步骤。第一,对每一个函数对,我们根据 caller 的全名,找到与所选 caller 相关的 smali 文件。第二,我们在 smali 文件中插入语句以实现一个 try-catch trap。这里我们可以使用 5 种函数调用类型,包括 `invoke-direct`、`invoke-virtual`、`invoke-static`、`invoke-super` 与 `invoke-interface`。不同的调用类型需要不同的 smali manipulation。Fig 15 展示了每一种调用类型的一个示例。第三,我们使用 Apktool 将修改后的 smali 文件重新构建为 APK 文件。上述操作由一个 Python 脚本自动完成。

为了展示 BagAmmo 是如何对 smali 代码做 manipulation 的,我们在 Fig 16 中提供一个实际的 manipulation 实例。从第 6 行到第 11 行,我们可以找到一个运行时异常。具体而言,我们初始化一个长度为 3 的数组,并采用一个不透明方法(opaque method)去访问这个数组的第 4 个元素。然后它会抛出一个 `java.lang.ArrayIndexOutOfBoundsException` 异常,并跳过所插入的 callee 函数。通过这种方式,我们的方法能够有效地插入调用,并保留恶意软件的原有功能。

值得注意的是,被加入到一个 try 块中的语句并不固定。因此 BagAmmo 能够抵抗基于白名单的防御。例如,假设我们希望通过引发数组访问越界来触发 `IndexOutOfBoundsException` 异常。为此,我们去访问一个超出数组长度的数组下标。BagAmmo 能够为这样的数组下标生成无数的变量名与变量值。因此,要构造一个白名单来排除 BagAmmo 所添加的语句是不可能的。

---

### §10.4 Dataset in our experiments(我们实验中的数据集)

我们的数据集包括 44,375 个发布于 2010 年到 2020 年之间的 Android APK,它们采集自 AndroZoo、FalDroid 与 Drebin。Table 4 给出了我们数据集中 APK 的来源、数量与年份。

Table 4: Dataset used in our experiments(我们实验中所使用的数据集):

| Source | Label | Years | Count |
|---|---|---|---|
| Androzoo | Benign | 2010-2020 | 21,399 |
| Androzoo | Malicious | 2015-2020 | 9,668 |
| FalDroid | Malicious | 2013-2014 | 8,407 |
| Drebin | Malicious | 2010-2012 | 4,900 |
| **Total** | — | 2010-2020 | **44,374** |

---

### §10.5 Resistance to adversarial retraining(对对抗式重训练的抵抗)

对抗式重训练(adversarial retraining)被认为是抵御 AE 攻击的最有效防御方法。在本节中,我们用对抗式重训练来测试 BagAmmo。我们随机选取 100 个由 BagAmmo 生成且能够欺骗目标系统的对抗样本。我们把这些对抗样本划分为一个训练集与一个测试集。在不同的训练样本比例下,我们重新训练目标分类器,以便在测试集上评估 ASR。

我们的结果展示于 Fig 17,其中纵轴是 BagAmmo 的 ASR,横轴是用于对抗式重训练的 AE 所占的比例。不出所料,ASR 随着对抗式重训练所采用的 AE 比例的增加而下降。当该比例超过 40% 时,对抗式重训练在抵抗 BagAmmo 上变得有效。然而在实践中,要收集到足够多的对抗样本用于对抗式重训练是极其困难的。另一方面,值得指出的是,在 BagAmmo 的帮助下,模型拥有者可以通过对抗式重训练提升其模型的防御能力。

---

### §10.6 Attack performance on VirusTotal(在 VirusTotal 上的攻击表现)

我们评估 BagAmmo 在 VirusTotal 上的表现。具体而言,我们使用 BagAmmo 通过查询 MaMadroid 检测器来生成 AE(对抗样本),并把它们上传到 VirusTotal 进行恶意软件检测。VirusTotal 使用大约 60 种我们未知的恶意软件检测方法。然后我们记录成功检测的方法数量与所有方法数量之比,记为 `R_adv`。为便于对比,我们对原始样本也进行同样的设置,相应的比值记为 `R_ori`。此外,我们计算 `R_adv` 与 `R_ori` 之间的差值,记为 `R_ori - R_adv`。结果展示于 Fig 18。该图的横轴展示不同的 APK,纵轴给出比值 `R_adv`(由红线表示)与 `R_ori`(由蓝线表示)。黄线展示成功检测方法的下降比例。可以看出,得益于 AE 的可迁移性 [38],BagAmmo 能够有效降低恶意软件被检测到的概率。值得注意的是,这种攻击效果是在不进行任何 query、也无法获得任何关于检测方法的先验知识的场景下取得的。

---

### §10.7 The number of added try-catch blocks(所添加的 try-catch 块数量)

由于 BagAmmo 在恶意软件代码中插入 try-catch 块,防御者可能选择通过判断 try-catch 块的数量是否超过一个预先设定的阈值来检测它。然而,为所有 APK 找到一个合适的阈值是困难的。如果没有这样的阈值,该防御方法可能带来很高的误报或漏报率。

为了验证这一点,我们记录 50 个恶意 APK 及其对应的对抗扰动后 APK 的 try-catch 块数量与函数调用数量之比,分别记为 `R_ORI` 与 `R_AE`。结果展示于 Fig 19。该图的横轴展示这些 APK 的 ID,纵轴给出 try-catch 块的占比。橙色与绿色的柱状条分别表示原始 APK 与相应的修改后 APK。我们可以从这张图中得出两个结论。第一,与已有的 try-catch 块数量相比,我们的方法所添加的 try-catch 块数量相对较小。因此,很难找到一个阈值来清晰地区分原始 APK 与扰动后的 APK。第二,try-catch 块的数量在不同 APK 之间剧烈波动。因此,要为所有 APK 设置一个固定的阈值也是困难的。

---

## 译后说明

* 全文 §Abstract / §1 / §2 / §3 / §4 / §5 / §6 / §7 / §8 / §9 / §10 均按"句对句"口径基于 PDF 原文翻译:每个中文句对应原文一个英文句,不压句、不拆句、不自加段前小标题或总结。原文中以 "First / Second / Third"、"(1)/(2)/(3)/(4)" 列举的句子分别保留为独立中文句。
* 行内数学/符号(如 `M_G(·)` / `x_r^(i,j)` / `R_adv` / `N_success` 等)统一用反引号 code span,避开 markdown 把下划线当斜体处理;块公式(Eq.(1)–(11))用 `$$...$$` 包裹,在支持 KaTeX/MathJax 的渲染器下渲染为数学,不支持时也能完整看到原式。
* 原文 11 个脚注一一对应到 `bagammo-fn1`–`bagammo-fn11`,标签编号与正文出现顺序一致。
* 论文 32 个目标模型 ASR > 99.9% 的核心 finding 与 v6 round5 等本项目实验路线高度相关:**用恶意软件自身函数当 caller/callee** 是 BagAmmo 对抗 concept drift 的根本原因,这也对应本项目 MUTATE_EDGE_TYPE 在 PIDS 上的迁移设计。
