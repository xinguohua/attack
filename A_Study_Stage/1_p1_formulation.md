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

**R1: Attack Functional Consistency(攻击功能保持)**。在 manipulation 前后,A_0 attack 须仍执行成功,且攻击命令字符串字面保留。

《确保攻击可执行的限制》

《R2:正常命令执行成功-----具体》

《这只是其中一条 你再总结其他》 

**R2: Dependency Modeling for Executability(为可执行而建模依赖)**。Manipulation 必须**显式建模命令之间的依赖关系**。命令间存在多种执行依赖 — c_2 读 c_1 写的文件、c_2 是 c_1 fork-exec 的子进程、c_2 连 c_1 创建的 socket 等;若不显式建模这些依赖,manipulation 在加入 δ 时无法预判:(a) δ 是否破坏 A_0 已有的执行依赖、(b) δ 自身的依赖前提是否被满足 — 两者都可能让 `A_0 + Δ` 命令序列在 OS 上**执行失败**,manipulation 在物理上不成立。

已有 PIDS 域 manipulation 方法概述:

- **ProvNinja** (Mukherjee et al., USENIX Sec'23):**攻击链路替换** — 把 conspicuous(低 regularity)事件用 gadget chain 替换,再对 gadget 加 camouflage 边。**违反 R1** — 攻击是真实进程链 `fork → exec → syscall` 的因果序列,链路上某个事件被替换后,往往导致后续执行断开:例如把 `dockerd → notepad.exe` 这条 PE 链插入 Linux 攻击 → execve 直接 ENOEXEC 失败;把 `containerd-shim ↔ runc` 之间靠 close-on-exec fd 同步的事件替换掉 → 中间 gadget 触发 cloexec 关 fd → runc init 永远阻塞;甚至把 `apt install` 入口当 conspicuous 删了 → 后续 payload 不存在。

- **Goyal et al.** (NDSS'23):**良性子图拼接** — 从 benign graph 抠出一片子图(节点 + 边),整块加到 attack graph 上(加桥梁边连到攻击进程),循环到 embedding 离 benign cluster 足够近为止。**违反 R2** — 拼接子图在 graph 层进行,完全跳过命令依赖建模;拼接出的 graph-level edges 在 OS 层无对应的可执行命令序列(无法回答"哪些命令通过怎样的资源 / 派生依赖产生这些边、谁 fork 谁、谁写谁读"),manipulation 在物理上无法实现。即便仅在 graph 评估模式下成立,为让 embedding 充分稀释,往往需要拼接成千上万节点 / 边,一条最简单的计数规则就能抓:"某进程在短时间窗内新关联的节点 / 边数 > 阈值" → 命中,不需要 GNN,一阶谓词即可。

- **Contorter** (Nasr et al., S&P'26):**Context Distortion**(上下文扭曲) — 对每个 malicious node 找一个同类 benign 节点(按 type + footprint + embedding 相似度筛 top-1),把那个 benign 节点的整套邻居边照搬到 malicious node 周围。**违反 R2** — 这些 edges 在 graph 层凭空"声称"发生,Contorter 从未建模命令间依赖,无法说明"`update.exe` 通过哪条命令、什么参数、以怎样的依赖关系产生 `read kernel32.dll` / `write temp/update_patch.tmp` / `open windowsupdate.log` 等边" — manipulation 在 OS 层无可执行实现;同时,即使忽略可执行性,OccVer 只能验证"这条边在历史 log 中跟 `wscript.exe` 一起出现过",不能验证"`update.exe` 跟这些 benign 实体存在合理的可执行因果路径"。

---

### §4.2 The proposed manipulation method(我们所提出的 manipulation 方法)

我们在此设计一种新的命令空间 manipulation 方法。根据 R1,我们不能修改 A_0 任何元素,只能通过添加良性 δ 命令扩展 attack scenario;根据 R2,manipulation 须显式建模命令间依赖以保 `A_0 + Δ` 在 OS 上可执行。在 R1 + R2 共同约束下,命令空间 manipulation 形式化为**良性命令空间上的搜索问题** — 在良性命令库 `L` 与参数空间 `Args` 上,搜索 `Δ ⊆ L × Args`,使 detector 对攻击节点的判定翻转。剩下的问题是:**(1)** δ 候选库从何而来;**(2)** 命令之间的依赖与执行序如何形式化建模为可搜索的图;**(3)** 在该图上如何定义 atomic 变异算子并真实施加到 attack scenario。本节回答这三个问题;desirable Δ 的选取(即搜索算法本身)留作后续工作(§5)。

**(1) Candidate δ 命令库。** 在 syscall→CDM 标准映射下,subject 节点的邻接边只有 3 种类型:`subject → file`(由 `EVENT_OPEN / READ / WRITE / EXECUTE` 产生)、`subject → netflow`(由 `EVENT_CONNECT / SENDTO / RECVFROM` 产生)、`subject → subject`(由 `EVENT_CLONE` 产生)。据此,我们把 candidate δ 分为 3 类:

- **① File-touching 类**:Linux coreutils 中读取文件的工具(`cat`、`head`、`tail`、`dd`、`xxd`、`stat`、`md5sum`、`grep`、`wc` 等)。其 args 含 file path,真跑后产生 `subject → file` 邻接边。
- **② Network-touching 类**:Linux 网络工具(`curl`、`wget`、`nc`、`ncat`、`ssh`、`openssl s_client`、`python urllib` 等)。其 args 含 socket addr,真跑后产生 `subject → netflow` 邻接边。
- **③ Fork-exec 类**:Linux/Unix 中"运行另一个程序"的标准 launcher,通过 `clone() + execve()` 原子机制 wrap 另一条命令做 fork-exec(`nice`、`time`、`env`、`sudo`、`nohup`、`setsid`、`unshare`、`taskset`、`ionice`、`chrt`、`bash -c`、`sh -c`、`find -exec`、`parallel`、`xargs`、`python -c "subprocess.run(...)"` 等)。其 args 含被 wrap 的 target 命令,真跑后 launcher 作为 parent subject 跟 target child subject 之间产生 `subject → subject` CLONE 邻接边(若 target 内又含命令链,则产生多级 CLONE 链)。

《良性命令库的构建得有理由 确保搜索范围是合理的 》

库的具体来源:**GTFOBins**([gtfobins.github.io](https://gtfobins.github.io/))的 File-read 子集,**Atomic Red Team**([atomicredteam.io](https://atomicredteam.io/))的 Discovery 类技术(MITRE ATT&CK T1082/T1083/T1018/T1049/T1033 等),以及 **GNU coreutils / procps-ng / util-linux / iproute2 / bash builtin 官方 manpages** 中文档化的标准查询用法。所有命令都在 baseline 训练分布常见,自身不会成为新 anomaly。

《命令依赖图查新》

**(2) 命令依赖图 `G = (V_C, E_res, E_spawn, E_seq)`。** 节点 V_C 通过 E_seq 形成全序(执行序的"时间层"),通过 E_res 与 E_spawn 承载命令之间的依赖层。两类信息共存于单一图G, 

**节点 `V_C`(三要素属性)**:每条 shell 命令一个节点,属性 `(cmd_name, args, outputs)`，从 args / outputs 提取的资源标识符分别记为 `R_in(c)` 与 `R_out(c)`,命令 c 涉及的全部资源集为 `R(c) = R_in(c) ∪ R_out(c) ⊆ Resources`(file 用 path 表示,netflow 用 (ip, port) 表示):

- `args = (arg_1, ..., arg_k)` 是输入参数列表,含字面值参数与**输入资源参数**(读取的 file path / 拨连的 socket / stdin 等)
- `outputs` 是输出产生的资源集(写入的 file path / 发送的 socket / stdout 重定向 / 派生子进程等)

**边 `E = E_res ∪ E_spawn ∪ E_seq`(共 3 类)**:

- **`E_res ⊆ V_C × V_C`(资源依赖)**:`(c_1, c_2) ∈ E_res` 当 `R(c_1) ∩ R(c_2) ≠ ∅` — 两命令通过共享资源连通。覆盖 3 子型:**共读** `R_in ∩ R_in ≠ ∅`、**共写** `R_out ∩ R_out ≠ ∅`、**数据流** `R_out(c_1) ∩ R_in(c_2) ≠ ∅`(producer-consumer)。
- **`E_spawn ⊆ V_C × V_C`(派生依赖)**:`(c_1, c_2) ∈ E_spawn` 当 c_1 通过 fork-exec 启动 c_2,即 OS 进程层的 parent-child 关系。
- **`E_seq ⊆ V_C × V_C`(执行序边)**:`(c_1, c_2) ∈ E_seq` 当 c_1 在 shell 执行序中**紧邻** c_2 之前。V_C 上的 E_seq 形成 chain(每节点入度 / 出度 ≤ 1),给出 V_C 的全序。

**可执行约束(R2)**:E_seq chain 的顺序必须 respect 由 `E_res` 数据流子型 + `E_spawn` 导出的 partial order(producer 先于 consumer,parent 先于 child);违反则 `A_0 + Δ` 在 OS 上不可执行。



《确保命令加减能保持命令执行成功 你这个命令依赖图有用么 变异你确保能执行成功 》

**(3) Atomic 变异算子。** 在 `G` 上定义 4 个 atomic 算子,作用于 `V_C \ V_C^0`(不动攻击命令),共同后置约束:结果图 G' 必须仍满足 partial order(E_seq chain respects `E_res^{dataflow} ∪ E_spawn`),否则算子拒绝执行解决R2。

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



**Translating Command-Graph Mutation to Shell-Level Perturbation**(把命令图变异翻译成 shell 层扰动)。It is essential to convert command-dependency-graph mutations into shell-level perturbations,即把 G 上的 4 个 atomic 算子分别落到 attack scenario 真实可跑的 shell 命令序列上,既维持 A_0 字面与执行成功(R1),也使所有命令在 OS 上可实现(R2)。

**`Add(δ_cmd, δ_args, e)` 落到 shell。** 在 attack scenario 的 shell 命令序列中,找到 E_seq 链上 `e = (c_prev, c_next)` 对应的位置(c_prev 之后、c_next 之前),插入一行 `δ_cmd δ_args`;**算子的 partial order 后置约束自动保证 δ 真跑时其资源依赖已就绪** — 若 δ 是 producer-consumer 链中的 consumer,则 producer 已先于 δ 执行;若 δ 是 fork-exec child,则 parent 已先启动。该行的具体形式由 δ_cmd 所属的 3 类候选库(承 (1))决定:**① File-touching 类**形如 `cat <file_path> > /dev/null 2>&1` 或 `stat <file_path>`,真跑产生 OPEN / READ syscall,翻译为 subject → file 邻接边;**② Network-touching 类**形如 `curl -s http://<host>:<port>/` 或 `nc -z <host> <port>`,真跑产生 CONNECT / SENDTO syscall,翻译为 subject → netflow 邻接边;**③ Fork-exec 类**形如 `nice <target>`、`sudo <target>`、`nohup <target>`、`bash -c '<target>'`、`find <p> -exec <target> \;` 等(target 为被 wrap 的命令),真跑时 launcher 通过 `clone() + execve()` 产生 CLONE syscall,翻译为 launcher 与 target 间的 subject → subject 邻接边。

**`Rewrite(δ, args')` 落到 shell。** 在 shell 命令序列中找到 δ 对应的那行命令,字面只改资源参数部分(命令名 δ.cmd_name 不变):**①** 类改 file path(如 `cat /tmp/x` → `cat /etc/passwd`),δ 改连到新 file 邻居,产生新的 subject → file 边;**②** 类改 socket addr(如 `curl http://x.com:80/` → `curl http://target.com:443/`),δ 改连到新 netflow 邻居,产生新的 subject → netflow 边;**③** 类的 args 是被 wrap 的 target 命令,Rewrite 通过改写 target 实现(如 `nice ls` → `nice cat /etc/passwd`,或 `bash -c "ls"` → `bash -c "curl http://target.com:443/"`),δ launcher 改连到新 target child subject,产生新的 subject → subject CLONE 边。

**`Move(δ, e_new)` 落到 shell。** 从 shell 命令序列原位置删除 δ 那行命令字符串,在 E_seq 新位置 `e_new = (c_a, c_b)` 对应的 shell 序列位置(c_a 之后、c_b 之前)重新插入同一行命令字符串。命令字符串本身不变,只改时序位置 — 与 3 类库无关,通用适用。

**`Remove(δ)` 落到 shell。** 从 shell 命令序列中直接删除 δ 对应的那行命令 — 适用全部 3 类库。



---

todo

- 4.定义好优化函数 在这考虑规则怎么办  有改的这种变异方式 欺骗 ids 不被 rule-base
