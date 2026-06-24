# 从 ProvNinja / Contorter 的失效到 SafeMimic 的形式化目标

## 1. 相关工作

### 1.1 ProvNinja

ProvNinja(Mukherjee et al., USENIX Security'23)是 provenance graph 上的 mimicry-attack 工具,目标是在不破坏攻击意图的前提下,把攻击图改造得让基于 GNN 的入侵检测器(Prov-GAT)将其分类为 benign。

**算法三步**:

1. **REMOVE** conspicuous PROC_CREATE 边
2. **INSERT** gadget chain 替换
3. **CAMOUFLAGE** 给新 gadget 配伪装边(从该进程 benign profile 的 files + sockets 全字段采样)

**优化目标**:找改造图 `G'` 使目标 detector `M` 把它分类为 benign,同时给每条新加边加 regularity 阈值约束 `R_e > τ` 剪枝候选 chain:

$$
\begin{aligned}
\text{find} \quad & G' \\
\text{s.t.} \quad & M(G') = \text{benign} & \text{(主目标:detector 漏报)} \\
& \forall e \in G' \setminus G: \; R_e(u, v, r) = \frac{|\text{Freq}(u, v, r)|}{|\text{Freq}(u, *, r)|} > \tau & \text{(剪枝:新边足够 regular)}
\end{aligned}
$$

算法递归搜 G',每次 APPLY_GADGET 后查 `M(G') == benign`,命中即停。

### 1.2 Contorter

Contorter(IEEE S&P'26)是 provenance 表征上的 mimicry-attack 工具,目标是在不破坏攻击的前提下,把恶意进程的行为画像改得让目标 PIDS detector 把它分类成 benign。论文配套 4 个 detector(Flash / ThreaTrace / Magic / NodLink),本文档以 **NodLink/Cadets**(VAE 作 process-level detector,本仓库唯一可完整复现的组合)为案例。

**算法五步**(`baselines/contorter/NodLink/Cadets/NodLink_Cadets_Contorter.ipynb` cell 16-24):

1. **TypeSel** —— 按 process label 把 attack 进程分组
2. **FOpt** —— 滤出 `[FMin, FMax]` 互动数内的 benign 候选
3. **CSMax** —— 在 FastText 嵌入空间挑 top-10% cosine 相似的 benign exemplar
4. **ImpMax** —— 在候选里选 VAE reconstruction loss 最低的 chosen
5. **Gadget Insertion** —— `augmented.paths = attack.paths ∪ chosen.paths`(并集,不替换)

**优化目标**:在 chosen exemplar 池中选 c 使 augmented 进程的 VAE recon loss 最小:

$$
\begin{aligned}
\text{find} \quad & c \in \text{Top-10\%}_{\text{cosine}}(\text{benign}) \\
\text{s.t.} \quad & \min_c \; \text{VAE}_{\text{recon}}\bigl(\text{FastText}(\text{attack.paths} \cup c.\text{paths})\bigr) & \text{(主目标:VAE 漏报)}
\end{aligned}
$$

跟 ProvNinja 的 graph-level 边/点编辑不同,Contorter 在**进程-文件路径文本**层面做 set-union,不发任何 syscall。

---

## 2. Motivation

两条共同失效轴 —— ProvNinja 与 Contorter 在不同投影层(图 vs 文本)做修改,但**底层错误是同一个**:在 detector 看到的投影空间做手术,而不是在攻击的真实因果实体上做手术。

### P1 — 单层 mutation 不蕴含 OS-level 可执行性

Provenance 表示(无论是图还是 process-event 文本)是 OS 给攻击发生时记的**事件投影**,而不是攻击本身怎么跑。算法只在投影上加/删 / set-union,但攻击真在 OS 上跑时,涉及一堆算法看不到的真实约束:

- **父进程到底会不会 fork 那个子进程**(ProvNinja):图上画一条 `dockerd → notepad.exe` 边,但 dockerd 这个程序根本不会启动 notepad
- **被删掉的边是不是攻击关键步**(ProvNinja):算法把"图里看起来异常"的边删了,但这些边可能恰好是攻击核心动作(`sudo → /etc/shadow READ` 是窃凭证的核心),删了攻击就缺了关键一步
- **进程之间靠什么通信**(ProvNinja):`containerd-shim ↔ runc` 用 fd 同步,中间硬塞 bash 进去关闭 fd,后续 runc 卡死
- **注入路径权限是否兼容**(Contorter):tmux uid=1002 被声称访问 `/etc/spwd.db`(FreeBSD root-only mode 600),OS 上直接 EACCES
- **进程二进制是否有这条 syscall 的代码路径**(Contorter):tmux 二进制不会调 `open("/etc/aliases.db")`,要让 syscall 真发出必须 LD_PRELOAD / ptrace 注入额外代码,反向引入更显眼的攻击事件

**算法盲点**:ProvNinja 的 freq DB 只看图模式 regularity,Contorter 的 ImpMax 只看 FastText cosine + VAE recon loss —— 都不下到 OS 那一层去验证 augmented 表征是否真能由原攻击进程产生。

**结果**:detector 在改完的表征上看不出问题(因为表征改得很像 benign),但按这个表征真去跑攻击,有些攻击根本跑不通(ProvNinja Type 1)、有些攻击的 syscall 在 OS 上不可执行(Contorter L1 权限破墙)、有些要执行就得放大攻击面(Contorter L2 行为锚点缺失)。

### P2 — 单维优化必然在被忽略维度上留取证指纹

两个 baseline 的优化目标都跟目标 detector 的特征空间**同维**,evasion 在构造上必然成立。但这意味着**任何目标 detector 没看的统计 / 行为画像维度,baseline 完全没有约束**:

- **ProvNinja**:`apply_camoflauge` 从 `files ∪ sockets` 全字段均匀采样,导致 LOLBin 进程节点上**同时出现文件 IO 和网络 IO 边**,违反 OS 上 LOLBin 进程的单一职责画像
- **Contorter**:Gadget Insertion 把 chosen exemplar 的整套 paths(常 60-90 条,因为 chosen 多是高活动 sshd / qmgr 类系统服务 —— FastText cosine 偏好长 list)合并到 attack 名下,**没有任何机制约束总数**;FastText sentence embedding mean-pool 平均掉 raw count → augmented attack 的 file count = orig (~10) + chosen (~60-80) ≈ 60-100,远超 benign 中位数 9 / p99 46

**结果**:任何利用目标 detector 没看维度的简单规则都能识破 augmented 攻击 —— ProvNinja 漏给 LOLBin 单一职责规则 D2,Contorter 漏给 file-count 阈值规则 D。

---

## 3. 实验

### 数据集与方法

**ProvNinja**:`sample-supply-chain-data/` test set 851 张(636 benign + 215 anomaly)+ ProvNinja 自己保存的 191 张 `(orig, adv)` 对。
- **P1 验证**:对每对走 5 条 OS-level check(调用语义 / 资源冲突 / 拓扑可实现 / 特权 / 运行时上下文),任一命中记 `disrupted`。
- **P2 验证**:在 191 张图上跑三步 — 原图喂 GAT、改后图喂 GAT、改后图喂 **D2 规则**。
  > **D2 规则**:进程节点同时满足 (a) 是 LOLBin(`bash`/`sh`/`python3.8`/`dpkg` 等 ProvNinja gadget 池里那 16 个 Linux 工具)+ (b) 既读写文件又收发网络(出边里 FileNode ≥ 1 ∧ SocketNode ≥ 1)→ 标"被改过"

**Contorter**:`baselines/contorter/NodLink/Cadets/dependancies/` 上由 contorter `download.ipynb` 拉来的 28272 张 benign + 15 张 orig 攻击 + 15 张 contorter-augmented(adv)。本仓库 fresh `nbconvert --execute` 跑过完整 28-cell notebook,0 errors。
- **P1 验证**:`extract_diffs.py` 对 15 对 (orig, adv) 求 file-path diff,逐对反推注入路径在 attack 进程 OS 语境下的可执行性(权限 / 二进制行为锚点)。
- **P2 验证**:三步 — Step 0 NodLink VAE 在 orig 上 sanity,Step 1 NodLink VAE 在 adv 上 evasion baseline,Step 2 单条 domain rule **D = file count ≥ 50** 在 adv 上 standalone。
  > **D 规则**:进程的 file path 列表长度 ≥ 50 条 → 标"被改过"。阈值依据:orig max=26,adv min=62,benign p99=46,K=50 在三集上**清晰可分**。

### P1 结果

#### ProvNinja — 5/191 disrupted (2.6%),两类失败模式

**Type 1:进程起不来**(4 张,`0243_59` / `0335_32` / `0424_06` / `0430_36`)。`gadget-chain.json` 跨 OS 污染,Linux attack 被插入 Windows PE 链(`wordpad.exe → notepad.exe`)。Linux `execve("*.exe")` 返回 ENOEXEC,链第一跳就死。

**Type 2:状态依赖断**(5 张,跟 Type 1 部分重叠 + `0746_41`)。进程能起来,但前后状态传不过去:
- **fd 同步断**(4 张 PE case):`containerd-shim ↔ runc` 用 `exec.fifo` close-on-exec fd 同步,中间 gadget execve 把 fd 关掉,runc init 永远阻塞。
- **装包链断**(`0746_41`):0 gadget 退化时算法 REMOVE 110 边但 INSERT 0 chain,modified 图没 apt 入口 → `apt install net-tools` 不发生 → 后续 payload 不存在。

#### Contorter — 15/15 注入路径都需要 attack 进程做 OS 上不可执行的 syscall

引用文件:`baselines/pipelines/contorter/diffs/_summary.json`。

15/15 样本的 `removed_by_contorter == 0`(原攻击 syscall 序列完全保留,attack chain 在 OS 层未受影响)。但 `total_files_added = 857` —— 平均每对注入 ~64 条新 path,全部来自 ImpMax 选中的 sshd / qmgr 类系统服务的 footprint。

**Type 1:权限破墙**(15/15 都中):每对样本至少 2 条 `/etc/spwd.db` `/etc/master.passwd` 类 root-only 文件(FreeBSD mode 600),attack 进程 uid=1002 调 open 直接 EACCES,augmented log 这部分声称在 OS 上**物理不可达**。

**Type 2:行为锚点缺失**(15/15 都中):每对样本 ~7 条 `/etc/aliases.db / hosts / services / pwd.db` 等 mail/NSS/auth 子系统专属 path,attack 进程的二进制根本没相应代码路径,要让 syscall 真发出必须 LD_PRELOAD / ptrace 注入额外代码 → **反向引入更显眼的攻击事件**,放大攻击面。

### P2 结果

#### ProvNinja — 96.9% vs 0% 完全反转

| Step | 输入 | Detector | detection / 191 |
|---|---|---|---|
| Step 0 | 原图 | Prov-GAT | **191 / 191 = 100.0%** |
| Step 1 | 改后图 | Prov-GAT | **0 / 191 = 0.0%** |
| Step 2 | 改后图 | **D2** | **185 / 191 = 96.9%** |

**案例 `0143_55`**(D2 精准命中):

```
原图(纯文件型 attack):              改后图(ProvNinja 给空闲的 P2 加 camouflage):
                                      
  P2 python3.8 (CMD: apt-check)       P2 python3.8 (CMD: <空>)  ★ D2 命中
   ├─ P1 python3.8 (apt-check)         ├─ P1 (没变)
   │   └─ READ × 50 FileNode           │   └─ READ × 50 FileNode
   └─ P0 python3.8 (lsb_release)       ├─ P0 (没变)
                                       ├─ READ × 5 FileNode  ← 注入
                                       └─ R/W × 5 SocketNode ← 凭空出现

  P2 IO: file=0  sock=0                P2 IO: file=5  sock=5
  → 单一职责                            → 违反单一职责 → D2 抓
```

GAT 在原图上 pred 中位数 0.936,改后被推到 0.017 —— 被精心欺骗。但 D2 看的是 LOLBin 进程是否单一职责,这个维度算法完全没碰:改造图 605 个 LOLBin 进程**40% 违反**,benign + 原始 anomaly 的 1373 个 LOLBin 进程**全部合规**。D2 漏的 6 张恰好是 P1 失败的 PE 容器逃逸 case —— **同一个跨 OS 污染 bug 同时引发 P1 和 P2 失败**。

#### Contorter — D 抓 100% vs NodLink VAE 33%

引用文件:`baselines/pipelines/contorter/results/{contorter_nodlink_eval, d_filecount_eval}.json`。

| Step | 输入 | Detector | recall | TP | FN | FP | FP rate (benign) |
|---|---|---|---|---|---|---|---|
| Step 0 | orig | NodLink VAE | **15/15 = 100.0%** | 15 | 0 | 19 | 0.07% |
| Step 1 | adv  | NodLink VAE | **5/15 = 33.3%** | 5 | 10 | 24 | 0.09% |
| Step 2 | adv  | **D=count≥50** | **15/15 = 100.0%** | 15 | 0 | 256 | 0.91% |

**案例 `pair_00 tmux-1002`**(D 精确命中,VAE 漏):

```
原图(orig):                          augmented(contorter 加 sshd-类 exemplar):
                                      
  tmux-1002 (cmd: 终端复用)            tmux-1002 (cmd: 同;声称访问 62 条)
  ├─ 真实访问 10 条:                   ├─ 原 10 条保留(syscall 真实)
  │   /dev/hpet0                       ├─ + 45+ 条新加 ★(声称 tmux 访问):
  │   /etc/libmap.conf                 │   ★ /etc/spwd.db    ← root-only,uid=1002 EACCES
  │   /lib/libc.so.7                   │   ★ /etc/aliases.db ← tmux 二进制无此 code path
  │   /lib/libpcap.so.8                │   ★ /etc/group
  │   /tmp/tmux-1002                   │   ★ /etc/hosts
  │   ...                              │   ... 共 45+ 条系统服务级 path ...
  └─ file count = 10                   └─ file count = 62  ★ D 命中
  
  VAE recon loss > cutoff=130 → flag   VAE recon loss < 130 → 漏(被 evade)
  D: 10 < 50 → 不命中(D 不抓 orig)    D: 62 ≥ 50 → 命中(D 抓 modification)
```

NodLink VAE 在 orig 上 R=1.0,被 contorter 推到 R=0.33(10 个 attack evade 成功)。但 D 在 adv 上 R=1.0 —— Contorter 的 ImpMax 把 VAE recon loss 压到 130 以下,代价是把 file count 从 10 推到 62-96,**这个推升完全在 VAE 的盲区**(FastText mean pooling 把 count 信息平均掉了),但落进 D 的视野里。FP 256/28272 = 0.91%(主要是 chunky benign sshd / qmgr 进程,即 contorter 本身 exemplar 池),可解释性高。

### 综合实证

**ProvNinja**:自报 85% evasion success。综合两个失效模式:**攻击能执行且躲过 D2 的比例 ≤ 3%**,比 README 声称低一个数量级。

**Contorter**:论文 Table 5 自报 NodLink/Cadets 上 evasion 让 recall 大降。本仓库**复现一致**(R 1.0 → 0.33,−67pp)。但综合两个失效模式:
- **P1**:15/15 augmented 攻击的注入项里都有不可执行 / 须放大攻击面才能执行的 syscall —— augmented log 在 OS 上根本"长不出来"
- **P2**:同一份 augmented log,D 单条规则在 adv 上 R=1.0,比 NodLink VAE 高 67pp

**Contorter 的 evasion 只对 VAE-on-FastText 这一种 detector 有效**。任何能利用 OS 权限/二进制语义反查或保留 raw count 维度的 defender 都能 100% 抓回来。

---

## 4. SafeMimic — 新的形式化目标

ProvNinja 与 Contorter 都是单维优化:ProvNinja 让每条边 regularity 高,Contorter 让 augmented 进程的 FastText embedding 上 VAE recon loss 低。两者都犯同一个根本错误 —— 在 detector 的某个投影空间里做手术,而不是在攻击的因果实体上做手术,因此都既无法保证 OS 可执行(P1),又必然在某个正交维度上留指纹(P2)。SafeMimic 把 evasion 形式化成两条独立约束的联合求解。

### 4.1 SafeMimic 的优化目标

在**命令层**搜命令序列 `c = (c_1, c_2, \dots, c_n)`,以 detector D 作黑盒 oracle 给反馈,在两条硬约束下找最优解:

$$
\begin{aligned}
\text{find} \quad & c = (c_1, \dots, c_n) \in \text{Command}^* \\
\text{s.t.} \quad & \text{exec}(c) \text{ 实现 } S_{\text{dep}}(\text{原攻击}) & \text{(P1: 攻击仍能跑)} \\
& D\bigl(\text{trace}(\text{exec}(c))\bigr) < \tau & \text{(P2: detector 漏报)}
\end{aligned}
$$

trace 是 `c` 真实执行后 OS audit 出的 provenance graph,**自然满足 OS 不变量**(fork 关系真实、fd 协议真实、特权链真实)—— P1 不需要算法另加约束。

### 4.2 两个模块

**Part 1 — 命令选择执行隐蔽**:候选命令 `c_i` 满足两条筛选:(a) 在当前攻击状态下功能可行(推进 `S_dep` 子目标);(b) detector 在 `trace(c_1, \dots, c_i)` 上仍输出 benign。两条都过 → 入候选池。

**Part 2 — 最优解的探测优化**:在候选池上跑搜索(beam / MCTS / RL),把 detector 当 reward oracle,找端到端 `D(trace(c)) < \tau` 且 `S_dep` 完整覆盖的最优序列。探测过程允许局部回退,避免单步贪心导致 dimension collapse。

### 4.3 SafeMimic vs ProvNinja vs Contorter

| 维度 | ProvNinja | Contorter | SafeMimic |
|---|---|---|---|
| 优化层 | graph 边/点(post-hoc rewriting) | process-paths 文本(set-union) | command(执行前选 + 边执行边搜) |
| detector 用法 | 白盒拆 freq DB 特征 | 白盒读 VAE recon loss + FastText embedding | 黑盒 oracle 反馈 |
| 攻击语义约束 | 无 | 无(只看 cosine + recon loss) | `S_dep` 硬约束 |
| 隐蔽约束 | per-edge regularity 单维 | FastText embedding 上 VAE recon loss 单维 | detector 端到端反馈 + 多步搜索 |
| P1 处理 | — | — | trace 来自真实执行,OS 不变量天然成立 |
| P2 处理 | — | — | detector 直接评每步,任何看目标 detector 没看维度的 defender 都可挂入 |
| 实测失效 | P1 5/191 disrupted, P2 96.9% recall by D2 | P1 15/15 注入项有 OS 不可执行/须放大攻击面, P2 100% recall by D=count≥50 | — |
