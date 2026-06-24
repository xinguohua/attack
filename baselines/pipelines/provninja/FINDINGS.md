# 从 ProvNinja 的失效到 SafeMimic 的形式化目标

## 1. 相关工作:ProvNinja

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

---

## 2. Motivation

### P1 — 日志变异脱离运行时,部分攻击执行失败

Provenance 图就是 OS 给攻击发生时记的**事件日志**。ProvNinja 改的只是这份日志,不是攻击本身怎么跑。但攻击真在 OS 上跑时,涉及一堆算法看不到的真实约束,例如:

- **父进程到底会不会 fork 那个子进程**:图上画一条 `dockerd → notepad.exe` 边,但 dockerd 这个程序本身根本不会启动 notepad —— 算法只在图上加边,不知道这条边在真实进程关系里不存在
- **被删掉的边是不是攻击的关键步**:算法把"图里看起来异常"的边删了,但这些边可能恰好是攻击的核心动作(比如 `sudo → /etc/shadow READ` 是窃凭证的核心),删了攻击就缺了关键一步
- **进程之间靠什么通信**:比如 `containerd-shim` 跟 `runc` 之间靠一个文件描述符同步,中间硬塞个 bash 进去,bash 启动时把文件描述符关了,通信就断,后续 runc 卡死

**结果**:GAT 在改完的图上看不出问题(因为图改得很像 benign),但按这个图真去跑攻击,有些攻击根本跑不通。

### P2 — 变异为绕过 GAT 引入的新特征,反成简单规则的识别依据

ProvNinja 的优化目标跟 Prov-GAT 的特征空间**同维**,所以 evasion 在构造上必然成立。但这意味着**任何 GAT 没看的统计 / 行为画像维度,ProvNinja 完全没有约束**。

具体地,`apply_camoflauge` 从 `files ∪ sockets` 全字段均匀采样,导致 LOLBin 进程节点上**同时出现文件 IO 和网络 IO 边**,违反 OS 上 LOLBin 进程的行为画像 —— 真实数据中 LOLBin 进程在攻击窗口内都是单一职责(纯文件 OR 纯网络,不混合)。

**结果**:任何利用 GAT 没看维度的简单 detector 都能识破 `G_{\text{adv}}`。

---

## 3. 实验

### 数据集与方法

`sample-supply-chain-data/` test set 851 张(636 benign + 215 anomaly)+ ProvNinja 自己保存的 191 张 `(orig, adv)` 对。

- **P1 验证**:对每对走 5 条 OS-level check(调用语义 / 资源冲突 / 拓扑可实现 / 特权 / 运行时上下文),任一命中记 `disrupted`。
- **P2 验证**:在同一份 191 张图上跑三步 — 原图喂 GAT、改后图喂 GAT、改后图喂 **D2 规则**。

  **D2 规则**:看图里**有没有任何一个进程节点**同时满足下面两条 → 满足就标"被改过":
  1. 这个进程是 **LOLBin 系统工具**(`bash` / `sh` / `python3.8` / `dpkg` 等 —— 就是 ProvNinja 自己 gadget 池里那 16 个 Linux 工具)
  2. 这个进程**既读写过文件,又收发过网络**(出边里到 FileNode 的 ≥ 1 条,且到 SocketNode 的 ≥ 1 条)

### P1 结果 — 5/191 disrupted (2.6%),两类失败模式

**Type 1:进程起不来**(4 张,`0243_59` / `0335_32` / `0424_06` / `0430_36`)

`gadget-chain.json` 跨 OS 污染,Linux attack 被插入 Windows PE 链(`wordpad.exe → notepad.exe`)。Linux `execve("*.exe")` 返回 ENOEXEC,链第一跳就死。

**Type 2:状态依赖断**(5 张,跟 Type 1 部分重叠 + `0746_41`)

进程能起来,但前后状态传不过去:

- **fd 同步断**(4 张 PE case):`containerd-shim ↔ runc` 用 `exec.fifo` close-on-exec fd 同步,中间 gadget execve 把 fd 关掉,runc init 永远阻塞。
- **装包链断**(`0746_41`):0 gadget 退化时算法 REMOVE 110 边但 INSERT 0 chain,modified 图没 apt 入口 → `apt install net-tools` 不发生 → 后续 payload 不存在。

### P2 结果 — 96.9% vs 0% 完全反转

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

GAT 在原图上 pred 中位数 0.936,改后被推到 0.017 —— 被精心欺骗。但 D2 看的是 LOLBin 进程是否单一职责,这个维度算法完全没碰:改造图 605 个 LOLBin 进程**40% 违反**,benign + 原始 anomaly 的 1373 个 LOLBin 进程**全部合规**。

D2 漏的 6 张恰好是 P1 失败的 PE 容器逃逸 case —— ProvNinja 给它们插的是 Windows PE 进程,不在 Linux LOLBin 池里。**同一个跨 OS 污染 bug 同时引发 P1 和 P2 失败**。

### 综合实证

ProvNinja 自报 85% evasion success。综合两个失效模式:**攻击能执行且躲过 D2 的比例 ≤ 3%**,比 README 声称低一个数量级。

---

## 4. SafeMimic — 新的形式化目标

ProvNinja 单目标优化(只让每条边 regularity 高)→ 单维 dimension-collapse。SafeMimic 的目标是把 evasion 形式化成两条独立约束的联合求解。

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

### 4.3 SafeMimic vs ProvNinja

| 维度 | ProvNinja | SafeMimic |
|---|---|---|
| 优化层 | graph(post-hoc rewriting) | command(执行前选 + 边执行边搜) |
| detector 用法 | 白盒拆 freq DB 特征 | 黑盒 oracle 反馈 |
| 攻击语义约束 | 无 | `S_dep` 硬约束 |
| 隐蔽约束 | per-edge regularity 单维 | detector 端到端反馈 + 多步搜索 |
| P1 处理 | — | trace 来自真实执行,OS 不变量天然成立 |
| P2 处理 | — | detector 直接评每步,任何看 GAT 没看维度的 detector 都可挂入 |
