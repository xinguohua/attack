# P1 Manipulation:命令空间 PIDS 对抗样本攻击的问题形式化与 manipulation 方法



## §3 Problem formulation(问题形式化)

本节我们首先介绍工作中所考虑的系统与威胁,随后提出一个攻击形式化定义,以指导命令空间黑盒对抗样本攻击的设计。

---

### §3.1 System & Threat(系统与威胁)

Fig 1 描绘了基于 provenance graph 的入侵检测系统(PIDS)。攻击者对其发起命令空间黑盒对抗样本攻击:取一个 attack scenario(shell 命令序列 A0),向其注入良性 δ 命令,执行后 query PIDS,拿到 detector 报警的异常节点集合 `F ⊆ V`(`V` 为图中全部节点,`F` 中节点即 detector 判为 malicious 的节点),据此更新 δ 并重建扰动命令链;循环至攻击节点 `v_attack ∉ F`(攻击节点不再被报警)。

攻击者只能向 PIDS 提交命令链执行,并拿到报警异常节点集合 `F`,看不到日志,也不知 detector 架构、参数、训练分布。防御者可监控 query 次数异常,发出报警。

---

### §3.2 Attack formulation(攻击形式化)

为方便起见,我们首先分别用 `A_0` 和 `Δ` 指代原 attack scenario(shell 命令序列)与扰动(即注入的良性 δ 命令集合)。然后,我们用两个映射 `T(·)` 与 `D(·)` 来表示 Fig 1 中所示的命令到日志(commands-to-log)映射(经容器化执行 + syscall 追踪)与日志到检测(log-to-detection)映射(先把 syscall 日志翻译为溯源图,再由 detector 在图上推理),其中 `D(·)` 的输出是 detector 对攻击节点 `v_attack` 的二元判定(即 benign 或 malicious)。通过用 `Δ` 对 `A_0` 施加扰动,攻击者把 syscall 日志从 `O = T(A_0)` 改变为 `Õ = T(A_0 + Δ)`。那么,所期望的对抗扰动 `Δ*` 可以通过求解下面这个问题得到:

```
D(T(A_0)) ≠ D(T(A_0 + Δ*))       (1)
```

并需满足 attack 功能保持的约束(即扰动后 A_0 仍能成功执行)。

上述形式化为我们指出了两项任务:1) 设计一种 manipulation 技术,在保留 attack 功能的前提下扰动 attack scenario;2) 开发一个对抗扰动生成算法以实现 `Δ*`。由于命令空间—日志空间 gap 与严格黑盒设定带来的挑战,`T(·)` 与 `D(·)` 对攻击者而言实际上都是未知的(攻击者看不到中间 syscall 日志,只能拿到 detector 报警的异常节点集合)。因此,一击命中(in one shot)得到所期望的对抗扰动是极其困难的。这促使我们去开发一种迭代搜索算法,以逐步找到所期望的扰动。我们将在 §4 讨论 manipulation 技术,扰动生成算法留作后续工作。

---

## §4 Command-space manipulation(命令空间 manipulation)

本节我们首先介绍命令空间 manipulation 的常见要求与已有技术,然后提出一种新的命令空间 manipulation 方法。

---

### §4.1 Background of command-space manipulation(命令空间 manipulation 的背景)

尽管命令空间扰动直觉上很简单,但挑战来自下述要求:

**R1: Attack Functional Consistency(攻击功能保持)**。Manipulation 前后,A_0 的攻击语义必须保持。具体地,A_0 原始命令不可被改写、删除或重排;扰动只能作用于额外插入的良性命令 δ。执行层面上,`A_0 + Δ` 必须通过原 attack scenario 的 checker,且最终攻击检查 `final_attack_succeeded=True`。因此,本文的 manipulation 不是替换攻击链,而是在不触碰 A_0 的前提下扩展其执行上下文。

**R2: Executability(可执行性)**。Manipulation 后的完整命令序列 `A_0 + Δ` 必须能在真实 OS / shell 环境中执行出来。加入的 δ 命令必须在当前环境中真实可执行,并且不能破坏 A_0 的运行上下文。这里的"不破坏"包括:不覆盖 A_0 后续需要读取的文件,不关闭或占用 A_0 依赖的 socket / fd,不改变后续命令依赖的 cwd / env / privilege 状态,不阻塞 shell 执行流,不消耗 A_0 所需的一次性资源。否则,即使 δ 在图上看似 benign,`T(A_0 + Δ)` 也无法由真实 OS 执行产生。

为满足 R2,manipulation 需要显式建模命令之间的依赖关系,用来判断 δ 能否加入以及能加在哪里。命令间存在多种执行依赖:后续命令读取前序命令写出的文件,子命令由父命令 fork-exec 派生,网络命令连接前序命令启动的 socket 等。若不建模这些依赖,manipulation 无法预判:(a) δ 是否破坏 A_0 已有依赖;(b) δ 自身的前置资源是否已就绪;(c) Move / Remove / Rewrite 是否会让已有 δ 或 A_0 失去输入。依赖建模的目的不是复刻完整 OS 语义,而是在搜索空间中排除明显不可执行的扰动。

已有 PIDS 域 manipulation 方法概述:

- **ProvNinja** (Mukherjee et al., USENIX Sec'23):**攻击链路替换** — 把 conspicuous(低 regularity)事件用 gadget chain 替换,再对 gadget 加 camouflage 边。**违反 R1** — 攻击是真实进程链 `fork → exec → syscall` 的因果序列,链路上某个事件被替换后,往往导致后续执行断开:例如把 `dockerd → notepad.exe` 这条 PE 链插入 Linux 攻击 → execve 直接 ENOEXEC 失败;把 `containerd-shim ↔ runc` 之间靠 close-on-exec fd 同步的事件替换掉 → 中间 gadget 触发 cloexec 关 fd → runc init 永远阻塞;甚至把 `apt install` 入口当 conspicuous 删了 → 后续 payload 不存在。

- **Goyal et al.** (NDSS'23):**良性子图拼接** — 从 benign graph 抠出一片子图(节点 + 边),整块加到 attack graph 上(加桥梁边连到攻击进程),循环到 embedding 离 benign cluster 足够近为止。**违反 R2** — 拼接子图在 graph 层进行,完全跳过命令依赖建模;拼接出的 graph-level edges 在 OS 层无对应的可执行命令序列(无法回答"哪些命令通过怎样的资源 / 派生依赖产生这些边、谁 fork 谁、谁写谁读"),manipulation 在物理上无法实现。即便仅在 graph 评估模式下成立,为让 embedding 充分稀释,往往需要拼接成千上万节点 / 边,一条最简单的计数规则就能抓:"某进程在短时间窗内新关联的节点 / 边数 > 阈值" → 命中,不需要 GNN,一阶谓词即可。

- **Contorter** (Nasr et al., S&P'26):**Context Distortion**(上下文扭曲) — 对每个 malicious node 找一个同类 benign 节点(按 type + footprint + embedding 相似度筛 top-1),把那个 benign 节点的整套邻居边照搬到 malicious node 周围。**违反 R2** — 这些 edges 在 graph 层凭空"声称"发生,Contorter 从未建模命令间依赖,无法说明"`update.exe` 通过哪条命令、什么参数、以怎样的依赖关系产生 `read kernel32.dll` / `write temp/update_patch.tmp` / `open windowsupdate.log` 等边" — manipulation 在 OS 层无可执行实现;同时,即使忽略可执行性,OccVer 只能验证"这条边在历史 log 中跟 `wscript.exe` 一起出现过",不能验证"`update.exe` 跟这些 benign 实体存在合理的可执行因果路径"。

---

### §4.2 The proposed manipulation method(我们所提出的 manipulation 方法)

我们在此设计一种新的命令空间 manipulation 方法。根据 R1,A_0 是 immutable 的:原攻击命令不可被修改、移动或删除。搜索算法只能创建和修改 δ 命令。根据 R2,δ 必须能在真实 shell 中执行,且其插入、移动、改写、删除都不能破坏 A_0 的执行依赖。在这些约束下,命令空间 manipulation 形式化为**良性命令空间上的可执行扰动搜索问题** — 在良性命令库 `L` 与参数空间 `Args` 上,搜索 `Δ ⊆ L × Args`,使 detector 对攻击节点的判定翻转。

本节只定义 manipulation space,不定义最终搜索算法。具体回答三个问题:**(1)** δ 候选库如何构建;(2) 命令之间的依赖与执行序如何形式化建模;(3) 如何定义 atomic 变异算子,并把这些算子落到真实 shell 命令序列上。

**(1) Candidate δ 命令库。** 在 syscall→CDM 标准映射下,subject 节点的邻接边只有 3 种类型:`subject → file`(由 `EVENT_OPEN / READ / WRITE / EXECUTE` 产生)、`subject → netflow`(由 `EVENT_CONNECT / SENDTO / RECVFROM` 产生)、`subject → subject`(由 `EVENT_CLONE` 产生)。据此,我们把 candidate δ 分为 3 类:

- **① File-touching 类**:Linux coreutils 中读取文件的工具(`cat`、`head`、`tail`、`dd`、`xxd`、`stat`、`md5sum`、`grep`、`wc` 等)。其 args 含 file path,真跑后产生 `subject → file` 邻接边。
- **② Network-touching 类**:Linux 网络工具(`curl`、`wget`、`nc`、`ncat`、`ssh`、`openssl s_client`、`python urllib` 等)。其 args 含 socket addr,真跑后产生 `subject → netflow` 邻接边。
- **③ Fork-exec 类**:Linux/Unix 中"运行另一个程序"的标准 launcher,通过 `clone() + execve()` 原子机制 wrap 另一条命令做 fork-exec(`nice`、`time`、`env`、`sudo`、`nohup`、`setsid`、`unshare`、`taskset`、`ionice`、`chrt`、`bash -c`、`sh -c`、`find -exec`、`parallel`、`xargs`、`python -c "subprocess.run(...)"` 等)。其 args 含被 wrap 的 target 命令,真跑后 launcher 作为 parent subject 跟 target child subject 之间产生 `subject → subject` CLONE 邻接边(若 target 内又含命令链,则产生多级 CLONE 链)。

候选库需要满足四个筛选原则。第一,来源必须是攻击者可获得的公开或本地可观测信息,不能依赖 defender 的 benign workload、training traces 或 detector 内部数据。第二,命令模板必须 non-destructive,不得修改目标应用状态、覆盖 A_0 资源、改变后续 shell state 或要求提权。第三,命令必须可参数化,使搜索算法能选择 file path、socket addr 或 wrapped target。第四,命令必须能稳定映射到 CDM 中可观察的邻接类型,否则无法形成可控 manipulation。

δ pool 的来源采用攻击者可用的两类公开信息,职能正交。**(i) Linux man pages**([man7.org](https://man7.org/linux/man-pages/))提供目标运行环境中合法系统工具的**完整词表与官方调用语法**,覆盖 **GNU coreutils / procps-ng / util-linux / iproute2 / net-tools / findutils / bash builtin / wget / clamav** 等系统包;攻击者通过 `command -v`、`--help`、dry-run 等方式确认这些工具在目标环境可执行。**(ii) GTFOBins**([gtfobins.github.io](https://gtfobins.github.io/))的 File-read 子集提供**按 syscall 副作用归类的命令注释** —— 该清单标注了哪些合法二进制能稳定触发 OPEN/READ syscall,man pages 本身按命令功能归类(文本处理、网络、进程管理)不提供 syscall 级行为分类,GTFOBins 弥补这一空缺,使得 ①类 file-touching 候选可按 syscall footprint 精确预筛。该两类来源选择呼应 SPECTRA [Shoaib et al. S&P'25] §7 对 Linux 命令空间逃逸应取自 man pages + GTFOBins 的论断。**参数来源**来自攻击者在 A_0 与公开环境中可观察到的资源,例如标准系统文件(`/etc/os-release`,`/etc/hostname`,`/proc/*`)、公开本地服务端点(`127.0.0.1:3000` 的 GET/health-check 类请求)、以及 A_0 已经使用过但只读访问不会改变攻击状态的 file / socket 标识。最终 δ pool 必须逐条记录 source tag、语义类别、参数模板、攻击者如何获得该模板/参数、non-destructive 理由、dry-run 结果和被排除原因。

**(2) 命令依赖图 `G = (V_C, E_res, E_spawn, E_seq)`。** 节点 V_C 通过 E_seq 形成全序(执行序的"时间层"),通过 E_res 与 E_spawn 承载命令之间的依赖层。两类信息共存于单一图 G,用于判断某个 δ 是否能加入、能放在哪里,以及后续 Rewrite / Move / Remove 是否仍保持可执行。

**节点 `V_C`(三要素属性)**:每条 shell 命令一个节点,属性 `(cmd_name, args, outputs)`，从 args / outputs 提取的资源标识符分别记为 `R_in(c)` 与 `R_out(c)`,命令 c 涉及的全部资源集为 `R(c) = R_in(c) ∪ R_out(c) ⊆ Resources`(file 用 path 表示,netflow 用 (ip, port) 表示):

- `args = (arg_1, ..., arg_k)` 是输入参数列表,含字面值参数与**输入资源参数**(读取的 file path / 拨连的 socket / stdin 等)
- `outputs` 是输出产生的资源集(写入的 file path / 发送的 socket / stdout 重定向 / 派生子进程等)

**边 `E = E_res ∪ E_spawn ∪ E_seq`(共 3 类)**:

- **`E_res ⊆ V_C × V_C`(资源依赖)**:`(c_1, c_2) ∈ E_res` 当 `R(c_1) ∩ R(c_2) ≠ ∅` — 两命令通过共享资源连通。覆盖 3 子型:**共读** `R_in ∩ R_in ≠ ∅`、**共写** `R_out ∩ R_out ≠ ∅`、**数据流** `R_out(c_1) ∩ R_in(c_2) ≠ ∅`(producer-consumer)。
- **`E_spawn ⊆ V_C × V_C`(派生依赖)**:`(c_1, c_2) ∈ E_spawn` 当 c_1 通过 fork-exec 启动 c_2,即 OS 进程层的 parent-child 关系。
- **`E_seq ⊆ V_C × V_C`(执行序边)**:`(c_1, c_2) ∈ E_seq` 当 c_1 在 shell 执行序中**紧邻** c_2 之前。V_C 上的 E_seq 形成 chain(每节点入度 / 出度 ≤ 1),给出 V_C 的全序。

**可执行约束。** E_seq chain 的顺序必须 respect 由 `E_res` 数据流子型 + `E_spawn` 导出的 partial order(producer 先于 consumer,parent 先于 child)。此外,任何 δ 不得写入 A_0 后续读取的资源,不得改变 A_0 依赖的 shell state,不得引入阻塞命令。若违反这些约束,对应变异被拒绝。

> TODO-1(并入 §6 攻击消融):本节的可执行约束通过攻击消融而非独立实验验证,体现为两个并列指标:**(a) 攻击完整性** —— `all_steps_passed`、`final_attack_succeeded`(R1);**(b) δ 命令可执行性** —— `δ 命令成功率`、阻塞/超时率、资源冲突率(R2)。若关闭依赖图后 (a) 或 (b) 显著下降,则依赖图建模对 R2 是必要的。

**(3) Atomic 变异算子。** 在 `G` 上定义 4 个 atomic 算子。令 `V_C^0` 表示 A_0 的原始命令节点。所有算子只作用于 `V_C \ V_C^0`,即只编辑 δ,不编辑 A_0。共同后置约束是:结果图 G' 必须仍满足上述可执行约束;否则算子拒绝执行。

**算子 1 — `Add(δ_cmd, δ_args, e)`**(对应 FCGHunter Add Node):加新命令节点 δ,插入 E_seq 链上 `e = (c_prev, c_next)` 处。输入 `δ_cmd ∈ L`、`δ_args ∈ Args(δ_cmd)`、`e ∈ E_seq`。新节点 δ 的属性 `(cmd_name = δ_cmd, args = δ_args, outputs = derive(δ_cmd, δ_args))`,由此派生 `R_in(δ), R_out(δ), R(δ)`。状态转移:

```
V_C     ← V_C ∪ {δ}
E_seq   ← (E_seq \ {(c_prev, c_next)}) ∪ {(c_prev, δ), (δ, c_next)}
E_res   ← E_res ∪ { (δ, c) : c ∈ V_C \ {δ}, R(δ) ∩ R(c) ≠ ∅ }
E_spawn ← E_spawn ∪ { (c_p, δ) : c_p fork-execs δ }
```

**算子 2 — `Rewrite(δ, args')`。** 改 δ 的 args,通过共享资源建立新 E_res 边。输入 `δ ∈ V_C \ V_C^0`、`args' ∈ Args(δ.cmd_name)`,要求新 args 至少使 R(δ) 与某条 existing 命令的资源集相交(否则不是 "Add Edge" 语义)。状态转移(只动 E_res):

```
δ.args    ← args'
δ.outputs ← derive(δ.cmd_name, args')      -- R_in(δ), R_out(δ), R(δ) 随之更新
E_res     ← (E_res \ { edges incident to δ }) ∪ { (δ, c) : c ∈ V_C \ {δ}, R(δ) ∩ R(c) ≠ ∅ }
```

V_C, E_seq, E_spawn 不变。

**算子 3 — `Move(δ, e_new)`。** 把 δ 从 E_seq 当前位置抽出,塞到 `e_new = (c_a, c_b) ∈ E_seq` 处。输入 `δ ∈ V_C \ V_C^0`,要求 e_new 不是 δ 当前的入 / 出 E_seq 边。**前置条件(尊重依赖关系):** δ 的新位置必须使 E_seq chain 仍 respect partial order — 即:(i) 所有满足 `R_out(c) ∩ R_in(δ) ≠ ∅` 的 producer `c` 在新位置仍出现在 δ 之前;(ii) 所有满足 `R_out(δ) ∩ R_in(c) ≠ ∅` 的 consumer `c` 在新位置仍出现在 δ 之后;(iii) δ 的 E_spawn parent 在 δ 之前,E_spawn children 在 δ 之后。违反则拒绝执行。状态转移(只动 E_seq):

```
设 δ 当前的 E_seq 邻居为 (c_prev, δ), (δ, c_next)
// detach δ 从老位置
E_seq ← (E_seq \ {(c_prev, δ), (δ, c_next)}) ∪ {(c_prev, c_next)}
// insert δ 到 e_new
E_seq ← (E_seq \ {(c_a, c_b)}) ∪ {(c_a, δ), (δ, c_b)}
```

V_C, E_res, E_spawn 不变(因 δ.args 不变)。等价于 `Remove(δ) ∘ Add(δ.cmd, δ.args, e_new)`,但只动 E_seq,语义上是纯时序扰动。

**算子 4 — `Remove(δ)`。** 删 δ 节点,E_seq chain 自动接回。输入 `δ ∈ V_C \ V_C^0`。**前置条件(无下游依赖):** δ 不能被任何 existing 命令所依赖 — 即:(i) 不存在 `c ∈ V_C \ {δ}` 满足 `R_out(δ) ∩ R_in(c) ≠ ∅`(δ 作为 producer 被 c 消费 → 删 δ 会让 c 拿不到输入);(ii) 不存在 `c ∈ V_C \ {δ}` 满足 `(δ, c) ∈ E_spawn`(δ 是 c 的 fork-exec parent → 删 δ 让 c 无法启动)。换言之,δ 必须是依赖图上的**叶子节点**(出度 0,不被任何下游 consumer / child 依赖)才可 Remove,否则违反 R2 可执行性。状态转移:

```
设 δ 的 E_seq 邻居为 (c_prev, δ), (δ, c_next)
V_C     ← V_C \ {δ}
E_seq   ← (E_seq \ {(c_prev, δ), (δ, c_next)}) ∪ {(c_prev, c_next)}
E_res   ← E_res \ { edges incident to δ }
E_spawn ← E_spawn \ { edges incident to δ }
```

> TODO-2(并入 §6 攻击消融):4 个 atomic 算子的角色通过攻击消融的**变异搜索**视角验证 — 即在攻击搜索过程中,搜索算法能否真正利用这 4 个算子找到有效 δ,且每个算子是否**独立贡献**。Ablation 关闭算子子集对比:**(i) Add-only**、**(ii) Add + Rewrite**、**(iii) Add + Rewrite + Move**、**(iv) 全 4 算子**。若关闭 Rewrite / Move / Remove 后攻击 SR 显著下降或 query 数显著上升,则该算子是独立扰动 primitive(搜索真的需要它);若不显著,则它仅是搜索过程中的参数调整 / 位置调整 / 撤销机制,可以从 primitive 集合中合并或剔除。



**Translating Command-Graph Mutation to Shell-Level Perturbation**(把命令图变异翻译成 shell 层扰动)。It is essential to convert command-dependency-graph mutations into shell-level perturbations,即把 G 上的 4 个 atomic 算子分别落到 attack scenario 真实可跑的 shell 命令序列上。翻译后的执行链必须满足:原 A_0 命令字面不变、A_0 checker 仍通过、δ 命令在 strace/CDM 中产生可观察 footprint。

**`Add(δ_cmd, δ_args, e)` 落到 shell。** 在 attack scenario 的 shell 命令序列中,找到 E_seq 链上 `e = (c_prev, c_next)` 对应的位置(c_prev 之后、c_next 之前),插入一行 `δ_cmd δ_args`;**算子的 partial order 后置约束自动保证 δ 真跑时其资源依赖已就绪** — 若 δ 是 producer-consumer 链中的 consumer,则 producer 已先于 δ 执行;若 δ 是 fork-exec child,则 parent 已先启动。该行的具体形式由 δ_cmd 所属的 3 类候选库(承 (1))决定:**① File-touching 类**形如 `cat <file_path> > /dev/null 2>&1` 或 `stat <file_path>`,真跑产生 OPEN / READ syscall,翻译为 subject → file 邻接边;**② Network-touching 类**形如 `curl -s http://<host>:<port>/` 或 `nc -z <host> <port>`,真跑产生 CONNECT / SENDTO syscall,翻译为 subject → netflow 邻接边;**③ Fork-exec 类**形如 `nice <target>`、`sudo <target>`、`nohup <target>`、`bash -c '<target>'`、`find <p> -exec <target> \;` 等(target 为被 wrap 的命令),真跑时 launcher 通过 `clone() + execve()` 产生 CLONE syscall,翻译为 launcher 与 target 间的 subject → subject 邻接边。

**`Rewrite(δ, args')` 落到 shell。** 在 shell 命令序列中找到 δ 对应的那行命令,字面只改资源参数部分(命令名 δ.cmd_name 不变):**①** 类改 file path(如 `cat /tmp/x` → `cat /etc/passwd`),δ 改连到新 file 邻居,产生新的 subject → file 边;**②** 类改 socket addr(如 `curl http://x.com:80/` → `curl http://target.com:443/`),δ 改连到新 netflow 邻居,产生新的 subject → netflow 边;**③** 类的 args 是被 wrap 的 target 命令,Rewrite 通过改写 target 实现(如 `nice ls` → `nice cat /etc/passwd`,或 `bash -c "ls"` → `bash -c "curl http://target.com:443/"`),δ launcher 改连到新 target child subject,产生新的 subject → subject CLONE 边。

**`Move(δ, e_new)` 落到 shell。** 从 shell 命令序列原位置删除 δ 那行命令字符串,在 E_seq 新位置 `e_new = (c_a, c_b)` 对应的 shell 序列位置(c_a 之后、c_b 之前)重新插入同一行命令字符串。命令字符串本身不变,只改时序位置 — 与 3 类库无关,通用适用。

**`Remove(δ)` 落到 shell。** 从 shell 命令序列中直接删除 δ 对应的那行命令 — 适用全部 3 类库。

本节 manipulation 设计的验证(候选命令的 footprint 稳定性、dependency-aware placement 价值、4 个算子的角色)并入 §6 攻击消融,不作为独立实验。最终如何组合这些 primitive 生成 `Δ*` 属于 §5 搜索算法。
