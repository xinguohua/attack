# ProvNinja 上的问题验证

## 1. 要验证的问题

> ProvNinja(USENIX Security'23)将 evasion 攻击的成功标准定义为"修改后的 provenance 图能让 GAT detector 输出 `pred < 0.5`"。本节论证该标准存在两个**正交**的盲点 —— 一个关于 attack 的**功能正确性**(P1),一个关于 evasion 的**统计真隐蔽性**(P2),并把每个盲点形式化成可证伪假设供 §2 实验检验。

### 1.1 P1 —— 图层修改不蕴含运行时可执行性 (Functional Integrity Gap)

**待检验论断 (H1)**:**在 provenance graph 表示层施加的对抗修改(边的增删、节点的替换),不能保证底层 attack 链在 OS 上仍可成功执行**。Provenance 图是 OS 行为的**被动审计投影**,改图等价于改"过去发生了什么的记录",**不等价于改"现在能做什么"**。前者修改 detector 的输入空间,后者要求修改 OS 的进程 / 文件 / 网络运行时语义 —— 两者是不同抽象层的对象。

**算法盲点定位**:`provninjaGraph.py` 全程在 `dgl.heterograph` 上操作,优化目标为 `Freq(u, v, r) / Freq(u, *, r) > τ`(每条边在 benign frequency DB 中的 regularity score)。该目标**完全不引用**以下 OS 层不变量:

| 不变量 | 算法是否检查 |
|---|---|
| 父子进程的 fork 合法性(parent 二进制实际是否会 fork child)| ✗ |
| 攻击效果的资源依赖闭包(被删除的边是否承担 attack 的 S_dep 操作)| ✗ |
| 进程间协议契约(fd 继承、stdin 管道协议、env / cwd 传递)| ✗ |

**可证伪形式**:在 ProvNinja 主动产出并 save 的 191 张 evasion-success 样本上,至少存在 **k ≥ 1** 张图在以上三类不变量任一处被破坏 → 对应 attack 链虽通过 GAT 但实际无法执行。若 191 张全部 OS 层有效 → H1 证伪。

**验证方法**:§2.1 —— 对每对 (orig, adv) 走 5 条 OS-level 强制 check(args/调用语义、资源冲突、fork 拓扑、uid/cap、运行时上下文),check 锚定到具体二进制源码(containerd-shim ↔ runc 的 `exec.fifo` 协议、apt ↔ store 的 stdin URI 协议、Linux ENOEXEC PE 拒绝等)。

---

### 1.2 P2 —— 单维优化必然留下正交维度的取证指纹 (Stealthiness Asymmetry)

**待检验论断 (H2)**:**ProvNinja 的 evasion 是单目标优化** —— 唯一目标是把每条边推到 GAT 学到的 per-edge regularity 分布之内。这个目标恰好与目标 GAT 的特征空间同维,所以对 GAT 的 evasion 在构造上就是成立的。但这同时意味着**任何与该维度正交的统计 / 行为画像维度,ProvNinja 完全没有约束**。一个利用任意正交维度的简单检测器,应当在同一组 ProvNinja-evasion 样本上获得**显著高于**目标 GAT 的 detection recall —— 即使该检测器朴素到一行代码。

**算法盲点定位**:`apply_camoflauge`(`provninjaGraph.py:384-399`,`num_actions=10`)对每个新插入 gadget 节点 g 配伪装边的过程为均匀采样:

```
candidates(g) ← process_meta[name(g)]["files"] ∪ process_meta[name(g)]["sockets"]
sampled       ← uniform_sample(candidates(g), num_actions=10)
```

该构造对**两个**已知存在 ground-truth distribution 的维度未施加任何约束:

| 正交维度 | 真实分布 | ProvNinja 行为 |
|---|---|---|
| 全局节点类型分布 | benign 中纯文件型进程图 `SocketChannelNode = 0` | 改后必有 socket 节点,从 0 跳到非零 |
| 进程行为画像(单一职责)| LOLBin 进程在攻击窗口内 `min(f(p), s(p)) = 0` —— 1373 个真实 LOLBin 进程节点(636 benign + 215 原始攻击)中 **0 违反** | 40% 的 ProvNinja gadget 节点同时 `f(p) ≥ 1 ∧ s(p) ≥ 1` |

**可证伪形式**:存在某条单图、单参数、领域驱动的检测规则 D(无 embedding、无训练、无原图对比),使得在同一组 191 张 ProvNinja-evasion 样本上 `recall(D) ≫ recall(GAT)`,且 D 在 benign + 原始 anomaly 上 `Precision = 1.0`。若不存在这样的 D → H2 证伪;若存在 → H2 立住,且揭示 ProvNinja 的"隐蔽"是**针对目标 GNN 的 dimension-collapse**,不是 distribution-level 的真隐蔽。

**验证方法**:§2.2 —— 三步 pipeline 在同一份 191 张图上对比 (a) GAT 在原图,(b) GAT 在改后图,(c) 单一职责规则 D2 在改后图。D2 形式化为 `∃ p ∈ G : name(p) ∈ LOLBin ∧ f(p) ≥ 1 ∧ s(p) ≥ 1`,τ = 0 由 1373 个真实样本的经验观测锚定,非任意阈值。

---

### 1.3 两个问题的关系

P1 与 P2 是**正交**的失效模式,不互相蕴含也不互相排斥:

- 一张攻击图可以**同时**在 P1 上失败(攻击执行不下去)且在 P2 上失败(简单规则识破)—— 例如 §4.1 + §4.2 共享的 4 张 PE 容器逃逸 case
- 一张攻击图可以**只**在 P2 上失败(攻击仍可执行,但简单规则识破)—— 例如 §4.2 主例 `nd_220323_0143_55`(纯文件型 attack 的 socket 注入)
- ProvNinja 的"成功"在每张样本上要求**两个**问题都不发生,§3 实测显示这个联合条件被严重违反

P1 攻击的是 ProvNinja 的**安全性论断**(攻击仍能成功),P2 攻击的是 ProvNinja 的**隐蔽性论断**(GAT 漏报 = stealthy)。两个问题共同支撑 SafeMimic 的设计动机:**evasion 必须在 OS-level 命令层(保证 P1)+ 多维度分布匹配层(保证 P2)同时求解,而不是在单一图层做单目标优化**。

---

## 2. 验证设计:在 ProvNinja 上做什么实验

### 2.1 问题一的实验

**目标**:把 ProvNinja 跑出的 191 张 evasion-success 改造图(本地复现 `adversarial_examples/` 实际产出 191 个目录,upstream 论文报 168/198),逐对(改造前 vs 改造后)做安全判断,**列出哪些攻击仍能成功、哪些被干扰失败**。

#### Step 1 — 提 191 对前后样本 + 求带位置的 diff

数据源:`adversarial_examples/<图名>/{original,adversarial}_graph.pkl` × 191 对(§2.6 跑完产出)。

写 `extract_diffs.py`,对每对:

1. 加载 `original_graph.pkl`(改造前的恶意图)和 `adversarial_graph.pkl`(改造后的恶意图)
2. 求 diff,**每条 diff 必须带"在原图哪儿动的"位置信息**:

   - **删除位置**:被删的边 `(src_node, edge_type, dst_node)` 三元组,以及被连带删除的中间节点的所有边(完整 ego)
   - **插入位置**:插入链的"接口节点"—— 链跟原图衔接的两端(链首接到哪个原图 src_node,链尾接到哪个原图 dst_node),以及链中间每一跳 gadget 的位置
   - **伪装边位置**:每条新加的 READ/WRITE/IP_CONNECTION 边,挂在哪个新插入的 gadget 节点上、连到哪个目标(文件路径 / IP)

3. 物化成 `pair_<图名>.json`:
《这个结构是不是变了》
```json
{
  "graph": "nd_220323_0105_24",
  "original_attack": {
    "attack_processes": ["<原图里所有 attack 进程名>"],
    "attack_files":     ["<原图里 attack 进程读写的文件>"],
    "attack_ips":       ["<原图里 attack 进程连的 IP>"]
  },
  "removed": [
    {
      "edge": "PROC_CREATE",
      "src":  "<原 src_node 进程名>",
      "dst":  "<被删的 node_to_replace 进程名>",
      "follow_on_removed_edges": ["<这个被删节点上其他所有被连带删的边>"]
    }
  ],
  "inserted": {
    "anchor_src":  "<链首接到的原图 src_node>",
    "anchor_dst":  "<链尾接到的原图 dst_node>",
    "chain":       ["<gadget1 名>", "<gadget2 名>", "..."],
    "chain_edges": [
      {"src": "<src_node>",  "dst": "<gadget1>",  "edge": "PROC_CREATE"},
      {"src": "<gadget1>",   "dst": "<gadget2>",  "edge": "PROC_CREATE"},
      {"src": "<gadgetN>",   "dst": "<dst_node>", "edge": "PROC_CREATE"}
    ],
    "camouflage_edges_per_gadget": {
      "<gadget1>": [
        {"edge": "READ",  "target": "/etc/ld.so.cache"},
        {"edge": "WRITE", "target": "/var/log/..."}
      ],
      "<gadget2>": []
    }
  }
}
```

→ 191 个 JSON 就是后续 Step 2 安全判断的素材。每个 JSON **包含完整的"哪儿删 / 哪儿插 / 插的伪装边落在哪"位置信息**,让 Claude 判断时不光知道改了什么,还知道改在 attack 链路的哪一段。

#### Step 2 — Claude 在线逐对做安全判断(强制 6 条 check)

Claude ,每个 subagent 对每个 `pair_<图名>.json` 走下面这套 **6 条强制 check** 出 verdict。

**底层问题**:**ProvNinja 的隐蔽行为(加 gadget + 删边)有没有干扰原攻击的成功?**

**5 条 check,每条只有一个核心问题 + 怎么答**:

---

### Check 1

**核心问题**:**替换链 `a → g1 → ... → gN → b` 能不能实现原 `a → b` 边里 `b` 本来要干的恶意功能 `X`?**

**判断单元**:diff JSON 的 `replacements` 字段每条 `(a, b, chain)`。

**怎么答**:
1. 找 `b` 在原 `a → b` 里干的恶意操作 `X`(写恶意路径 / 连 C2 / 跑恶意二进制 / 触发 hook),以及 `b` 干 `X` 需要的 args / 调用方式(原 `a` 怎么给 `b` 传命令行 / 输入)
2. 看 modified 链跑到 `b` 时,attacker 给链上 gadget 配 args 后,`b` 最终拿到的 args 是不是还能让它干原来的 `X`

**fire 的情形**:
- 中间 gadget 把 args 拦了 / 改了,`b` 拿到的命令行不再触发 `X`
- 链上中间过程把恶意 payload 替换成 benign 操作(比如原 `a` 直接给 `b` 传 `--config malicious.yaml`,中间 gadget 把 yaml 路径丢了)
- `b` 启动时的调用语义改变,等价于 attacker 没法再让 `b` 干 `X`

**不 fire**:
- `a → b` 是系统二进制内部协议(sudo → shadow READ、apt → store → python、dockerd → runc 这种系统强制),attacker 跑系统二进制时 `X` 在真实 runtime 还是会发生,跟 modified 图怎么改无关 → 不算 `X` 消失,**不命中**(trace 失真留给 problem 2)
- `b` 拿到的 args 仍能触发 `X`(典型情形:gadget 配 `bash -c "exec b --orig-args"` 透传 args 到 `b`)

判断不出来 → 不命中。

---

### Check 2

**核心问题**:**ProvNinja 插的 gadget 跑起来,会撞 attack 用的资源吗?**

**判断**:
- ProvNinja 插 gadget 默认只填 EXE_NAME 不填 CMD,gadget 是 bare 跑
- 看 gadget bare 启动后实际动什么资源:
  - 解释器 / shell / GUI 在 headless / Linux 上 PE / 无 args daemon-class → 启动后 fail-fast / print usage / ENOEXEC,**不动任何资源**
  - 真持锁 / 抢调度 / 发信号的(很少,除非 gadget 真带触发性 args)
- gadget 真动的资源 ∩ attack 用的资源 ≠ ∅ → **答**:有 → 命中
- 否则 → **答**:没有 → 不命中

看不出 gadget bare 跑动什么资源 → 默认不动,不命中。

---

### Check 3

**核心问题**:**modified 图里有没有不合理的 fork 关系?**

**判断方法**:看 modified 图里每条 fork 边 `parent → child`,问自己:**`parent` 这个程序的实际行为里,会不会去 fork `child`?**
- **会 fork** → 这条边合理
- **不会 fork** → 这条边不合理 → 命中

只要有任一条 attack 关键进程 P 的入边链路上**至少一跳是不合理的 fork**,P 在 modified 图里就实际起不来 → fire。

**典型不合理的 fork**:

1. **进程不会自己 fork 出同名进程**:`docker-scan → bash → docker-scan` self-loop —— docker-scan 工作流不会内部 fork bash 再 fork 出另一个 docker-scan
2. **进程不会 fork 跟自己工作流无关的程序**:`docker → notepad.exe` —— docker 工作流里没理由 fork Windows 记事本
3. **二进制在该 OS 上跑不起来**:Linux 上 fork Windows PE → ENOEXEC,虽然图里画了这条边但实际 fork 不出来
4. **关键进程没人能 fork 出它**:`runc` 应该被 `containerd-shim` 启动,modified 图里没任何能起 runc 的边 → runc orphan
5. **fork 链上中间进程跟下游传递关系不匹配**:`containerd-shim` 给 `runc` 传 `exec.fifo` fd 是 shim 自己实现的逻辑,塞个 sh 进来 sh 不知道这个 fd 该传 → 链断

**注意**:仅"gadget 没 CMD args"不算不合理 —— attacker 实际跑能给 gadget 补合理 args。**只有当 gadget 加 args 也救不回来时才算不合理**(上面 5 类都满足这个标准)。

---

### Check 4

**核心问题**:**P 真启动了,但 P 拿到的 uid / cap 够干 attack 操作 O 吗?**

**判断**:
- Linux setuid 是 **execve 时机型**:第一个 setuid 二进制(sudo)execve 时把 uid 设成 0,**之后所有 execve 默认保留**(只有显式 `setuid()` 系统调用 / fcaps drop / `sudo -u <other>` 切换才能掉)
- 所以 `sudo → sh → bash → docker`:bash exec docker 时 uid 仍是 0,docker.sock 连得上 → uid 够 → **答**:够 → 不命中
- 真不够的情形:
  - **第一次 sudo 之前 gadget 拦截**(sudo 永远不被启动,uid 永远不切 root)
  - `sudo -u <other>` / `su - <other>` 显式 uid 切换链被 gadget 替代 → uid 没切到 `<other>`
  - gadget 二进制有 fcaps drop,把 attack 需要的 cap 砍了
  - attack 靠特定 cap(`CAP_NET_ADMIN` / `CAP_SYS_PTRACE`),gadget execve 在没 fcaps 的二进制上 → cap 丢
- 看到上面 4 种之一 → uid / cap 不够 → **答**:不够 → 命中
- 看不到 → 默认够 → 不命中

---

### Check 5

**核心问题**:**P 启动了 uid 也对,但 P 干 O 需要的 fd / env / cwd / stdin 够吗?**

**判断**(两步,同时满足才命中):
1. 能具体说出 P 干 O 需要什么上下文吗?(fd 继承 / stdin 管道 / env 变量 / cwd / signal mask)
2. 能具体说出 modified 图里哪个 gadget execve 把这上下文截断了吗?(gadget execve 关 close-on-exec fd / 重置 env / shell 重设 stdin=EOF)

典型场景:
- `containerd-shim → runc` 中间塞 shell → shim 传给 runc 的 `exec.fifo` fd 在 shell execve 时关闭 → runc init 卡住
- `apt-get → apt-method/store` 中间塞 fresh python → stdin URI 协议断
- attack 靠 `LD_PRELOAD` 加载恶意 lib,gadget execve 不保 env → evil.so 不加载

两步都能具体说出来 → **答**:不够 → 命中
其中任一说不出来 → **答**:够 / 默认够 → 不命中(不要凭空假设依赖)

---

### 总判断

任一 check 命中 → `verdict = "disrupted"`
5 条全不命中 → `verdict = "intact"`

**判断规则**:
- 5 条 check 任一命中 → `verdict = "disrupted"`,在 `disruption_point` 字段标出哪条 check + 哪个 S_dep 操作 + 哪个 gadget / 哪条 removed 边
- 5 条 check 全过(且 ProvNinja 确实做了改动)→ `verdict = "intact"`,在 `rationale` 解释为什么 5 条都过(典型情况:gadget 全是 inert exit + 没删 S_dep 边 + 关键进程仍有别的 fork 路径或 attacker 可旁路启动)

**单对输出**(`judgment_<图名>.json`):

```jsonc
{
  "graph": "<name>",
  "S_dep": "一句话:攻击的成功效果操作集 (持久化 WRITE / 凭据 READ / 外泄 IP / 关键 PC 边)",
  "inserted_gadgets": "gadget1 + gadget2 + ...",
  "checks": {
    "check1_removed_attack_op":        {"hit": false, "evidence": "具体哪条 removed 边 / 'none'"},
    "check2_gadget_resource_conflict": {"hit": false, "evidence": "gadget X 持锁/信号撞 attack 资源 Y / 'none'"},
    "check3_topology":                 {"hit": false, "evidence": "S_dep 进程 P 的 fork 链上哪一跳断 / 'none'"},
    "check4_privilege":                {"hit": false, "evidence": "setuid/cap/uid 在哪丢 / 'none'"},
    "check5_context":                  {"hit": false, "evidence": "fd/env/cwd/stdin 在哪丢 / 'none'"}
  },
  "verdict": "intact",
  "disruption_point": "disrupted 时:哪条 check 命中 + 具体的 S_effect ∩ S_dep / 拓扑断点 / 权限丢失 / 上下文丢失。intact 则 null",
  "rationale": "2-4 句 OS 层推理。disrupted 必须引用 attack 进程 / S_dep 操作 / gadget 名;intact 必须解释为什么 5 条都过"
}
```

**Step 2 落盘**:`judgments/judgment_<图名>.json` × 191。

##### 给 subagent 的可复用 prompt 模板

下面这段是给每个 batch subagent 的完整 prompt(把 `<BATCH_RANGE>` 替换成 "first 48 / files 49-96 / files 97-144 / files 145-191"):


#### Step 3 — Claude 在线语义聚类,产出机制频次 + anomaly

**不写规则归类**。再开 1 个 subagent,Read 全部 191 个 `judgment_*.json`,**让 Claude 用 OS 层语义聚类**(不是字符串 / 正则 bucketing):

- 同样 `python3.8 → python3.8` 替换,如果 rationale 一个说"fresh interpreter REPL/EOF"、另一个说"apt-method 协议在 stdin 上需要 re-exec /usr/lib/apt/methods/store" —— **算两个机制**(REPL EOF 是通用语言层、apt-method 协议是接口层)
- 同样 sh/bash 插入,如果一个是丢 setuid、另一个是丢 daemon socket fd —— **算两个机制**
- 单独识别那些"在跑的 Linux 攻击图里被插了 Windows PE 二进制(`.exe`)"的样本 —— 这是 ProvNinja 的另一种算法缺陷(gadget pool 跨 OS 污染),不能跟 S_dep 缺失混在一起

**Step 3 落盘**:`judgments/summary.json`,schema:

```json
{
  "method": "Claude per-pair semantic judgment (Step 2) + Claude semantic aggregation (Step 3)",
  "total": 191,
  "verdicts": {"intact": <int>, "disrupted": <int>},
  "mechanism_clusters": [
    {
      "category": "<short label>",
      "count": <int>,
      "percent": <float>,
      "definition": "<这个 cluster 在 OS 层断的是哪个机制>",
      "representative_pair": "<一个 graph 名>",
      "explanation": "<2-3 句,引用一两个 representative judgment 的 rationale>"
    },
    ...
  ],
  "anomalies": [
    {"category": "<label>", "graphs": [...], "why_notable": "<一句话>"}
  ],
  "design_takeaway": "<3-5 句:这些机制告诉了 ProvNinja 什么算法盲点>"
}
```

`mechanism_clusters` 数量之和 = 191。`anomalies` 列出"不属于主流模式但值得在 §3.1 单独提名"的 case(跨 OS 污染 / 纯删除无 gadget / exfil 通道砍 / 协议层断裂等)。

#### 期望产出

| 字段 | 内容 |
|---|---|
| `intact` 数量 / 总 191 | X / 191(ProvNinja 真有效的部分) |
| `disrupted` 数量 / 总 191 | Y / 191(被自己 gadget 干扰失败的部分,这就是问题一的"反例池") |
| 机制 cluster 列表 | Step 3 语义聚类产出,每条带 representative pair + OS 层 definition |
| 重点 anomaly | 跨 OS 污染 / 纯删除 / exfil 通道砍 等独立案例 |

**核心数字**:`Y / 191` 就是 ProvNinja **本地复现 191 张** evasion-success 改造图里的"虚高比例" —— 比例越大,问题一越严重(可顺带跟 upstream 论文报的 168/198 = 84.8% 做参考对比)。


### 2.2 问题二的实验

**核心论点**:**ProvNinja 把对抗图推过 GAT 的判别阈值,但 GAT 没看的领域特征(LOLBin 进程的单一职责行为画像)它完全没碰**,任何看 process behavior profile 的简单 detector 都识破 → 愚弄 GNN ≠ 真隐蔽。

**数据源**:`adversarial_examples/<图名>/{original, adversarial}_graph.pkl` × 191 对(ProvNinja 自己产出的 evasion-success 子集)。

**证明结构**:三步,每步把 191 张图喂一个 detector,数 detection 率:

```
   adversarial_examples/ × 191
            │
            ├─→ Step 0: 原图     → Prov-GAT  → 期望 ≈ 100%(detector 工作正常)
            │
            ├─→ Step 1: 改后图    → Prov-GAT  → 期望 ≈ 0%  (确认 evasion 成功)
            │
            └─→ Step 2: 改后图    → D2 规则   → 期望 ≥ 90% (简单规则完胜 GAT)
```

#### Step 0 — sanity check:Prov-GAT 在原图上能识别恶意

**目的**:排除"GAT 漏报全是 detector 本身坏"的歧义。

**怎么跑**:`eval_gat_on_adv.py` 加载 `models/gat_768_10_0.001_20_5_128_bidirection.bin`(README §2.5 训出 weighted F1=0.95 的 .bin),把每张原图 `orig.pkl` 喂模型,记 `orig_pred`。判定 `orig_pred > 0.5` → 抓到。

**判定**:191 张里 GAT 抓到的比例 ≥ 90% 才算 detector 可用。

#### Step 1 — Prov-GAT 在改造图上的 detection 率

**目的**:复现 ProvNinja 论文 README §2.6 的"evasion 成功"主张。

**怎么跑**:同一个脚本,把 `adv.pkl` 喂模型记 `adv_pred`,跟原代码 `provninjaGraph.py:478-479` 完全同跑法:

```python
attack_pred = model(graph, agg_func(graph))
if attack_pred < THRESHOLD:    # THRESHOLD = 0.5
    # GAT 漏报,evasion 成功
```

**判定**:detection 率 ≤ 10% → ProvNinja 在 GAT 上 evasion 成功立住。

**注**:`adversarial_examples/` 的 save 条件是 `attack_pred < THRESHOLD`(`provninjaGraph.py:483`),所以这 191 张本质上是 GAT 已经漏的样本,Step 1 接近 0% 是 deterministic 的合理结果,不是 cherry-picked。

#### Step 2 — 领域规则 D2 standalone 检测

##### D2 的设计 —— 单一职责原则

**领域知识**:LOLBin(`/usr/bin/{sh, bash, python, dpkg, ...}` 这类系统工具)在攻击窗口里通常**单一职责** —— 要么读写文件(本地落 ROP / 写 artifact),要么收发网络(C2 通信),**不会同一进程同时大量混合两类 IO**。

**形式化定义**:

| 记号 | 定义 |
|---|---|
| `LOLBin` | 16 个进程白名单(从 `gadget_files/gadget-chain.json` 提取):`/usr/bin/{sh, bash, dockerd, dpkg, env, fiberlamp, git, mandb, perl, python3.8, run-parts, start-stop-daemon, thunderbird, xfce-terminal, anacron}` |
| `f(p)` | 进程节点 p 的出边里去 FileNode 的数量(READ + WRITE + FILE_EXEC) |
| `s(p)` | 进程节点 p 的出边里去 SocketChannelNode 的数量(READ + WRITE + IP_CONNECTION) |

**触发条件 D2**:

```
∃ p ∈ G.ProcessNode :
    name(p) ∈ LOLBin   AND   f(p) ≥ 1   AND   s(p) ≥ 1
→ 标 anomaly
```

**实现**:`eval_d2_full.py` 一行 if 判断,无 embedding、无 K-hop、无训练。

##### 为什么单一职责原则站得住(经验论证)

在 1373 个真实 LOLBin 进程节点上验证(test set 851 张里的 LOLBin 进程):

| 集合 | LOLBin 进程节点总数 | 违反单一职责数 | 占比 |
|---|---|---|---|
| Benign(636 张图) | 816 | **0** | **0.00%** |
| 原始攻击(215 张) | 557 | **0** | **0.00%** |

→ **τ = 0 不是任意阈值,是 1373 个真实样本验证的 hard distribution gap**。Linux 真实工作负载里没有任何 LOLBin 进程在攻击图窗口同时大量读写文件 + 联网。

##### 为什么 ProvNinja 必然违反

`apply_camoflauge`(`provninjaGraph.py:384-399`,`num_actions=10`)伪代码:

```python
for new_gadget in inserted_gadgets:
    process_meta = load_process_json(gadget.name)
    candidates   = process_meta["files"] + process_meta["sockets"]  # 文件 + socket 全字段
    sampled      = sample(candidates, num_actions=10)               # 随机抽 10 个
    for target in sampled:
        graph.add_edge(gadget, target)
```

**全字段随机采样必然两类都摸到** → `f(gadget) ≥ 1 AND s(gadget) ≥ 1` 概率极高 → ProvNinja 在算法层面违反单一职责。

#### 判定标准(三步)

**H2 立住**当且仅当:
- **Step 0**:GAT 在原图上 detection ≥ 90% → detector 工作正常,有比较意义
- **Step 1**:GAT 在改后图上 detection ≤ 10% → 确认 evasion 成功
- **Step 2**:D2 在改后图上 detection ≥ 90% → 简单 domain rule 完胜 GAT

**期望产出表**(实测填进 §3.2):

| 输入 | Detector | detection 率 / 191 |
|---|---|---|
| 原图(未改) | Prov-GAT | (期望 ≈ 100%) |
| 改造图 | Prov-GAT | (期望 ≈ 0%) |
| **改造图** | **D2** | **(期望 ≥ 90%)** |

**局限**:
- LOLBin 池只有 16 个 Linux 工具,如果 ProvNinja 攻击 Windows 系统(gadget pool 是 Windows PE)就漏 —— 实测漏了 4-6 张 PE 容器逃逸 case
- D2 抓的是 ProvNinja 算法层面的领域漏洞(全字段采样违反单一职责),即使作者修了实现 bug 仍然有效

---

## 3. 实验结果

> **状态:实测完成**。Step 1 = `extract_diffs.py` 跑完 191 对(已修 dgl 跨版本 pickle alias 问题、修 `reconstruct_chains` 贪心 bug、加 `replacements` 字段,191 对全部经独立 BFS 人工验证 0 错误)。Step 2 = **挨个 191 对走 5 条 check**,结果写到 `judgments/judgment_<name>.json` × 191。

### 3.1 问题一结果

#### 总体数字

判断口径:每对走 §2.1 Step 2 的 5 条 check,任一 check 命中 → `disrupted`,5 条全过 → `intact`。

| 指标 | 数值 |
|---|---|
| ProvNinja 自报 evasion-success 攻击图(本地保留) | 191 |
| 成功加载并提 diff | 191 / 191 |
| **verdict = `intact`(原攻击仍能成功)** | **186 / 191 = 97.4%** |
| **verdict = `disrupted`(原攻击被改造干扰失败)** | **5 / 191 = 2.6%** |

→ ProvNinja 自报 168/198 = 84.8% evasion 成功率,**实测 191 张本地复现的 evasion-success 改造图里有 5 张攻击实际跑不下去**,实际 attack-execution 安全率 ≈ 84.8% × 97.4% = **82.6%**。**问题一 H1 立住但幅度小**。

判断方法两步修正(2026-05-02):

1. **`extract_diffs.py` 加 `replacements` 字段**:对每条 removed cross-name PC 边 `(a, b)`,在整个 adversarial 图(原图保留 + 新插入)的 PC 边 label-空间邻接里跑 BFS 找最短路径 `a → g1 → ... → gN → b`,直接告诉判断者每条删边有没有被 chain reroute。原 `reconstruct_chains` 贪心选第一个 orig 出口,把 `python ↔ sh ↔ env ↔ run-parts ↔ bash ↔ git` 这种双向 chain 错压成 `python → sh → python` + `git → bash → git` 两条 self-loop,**漏掉了 5 跳 cross-anchor 路径**

2. **5 条 check 角色明确分工**(避免相互重叠):
   - Check 1 = 替换链跑通后 `b` 拿到的 args / 调用语义还能让它干 `X` 吗(语义保留)
   - Check 2 = gadget 跑起来撞 attack 用的资源吗(资源冲突)
   - Check 3 = 链拓扑可不可实现 + attack 关键进程有没有 entry path(拓扑可实现性)
   - Check 4 = b 拿到的 uid / cap 够干 `X` 吗(权限)
   - Check 5 = b 拿到的 fd / env / cwd / stdin 够干 `X` 吗(运行时上下文)
   - **System-mandated 删边的 carve-out**:像 `sudo → /etc/shadow READ` / `dockerd → runc` / `apt → store → python` 这种系统二进制内部协议被删 → attacker 跑系统二进制时还是会触发 → **不算 problem 1 disrupted**(归 problem 2 fingerprint 失真)

#### 5 个 disrupted 按 Check 分类

| 命中分布 | 数 | pair |
|---|---|---|
| **Check 3 单独命中** | 1 | `0746_41`(0 gadget 退化大批删边)|
| **Check 3 + Check 5 双命中** | 4 | `0243_59` / `0335_32` / `0424_06` / `0430_36`(containerd-shim → runc 经 Windows PE chain) |

5 条 check 实际只有 2 条 fire(Check 3 + Check 5),其他 3 条 0 命中。下面按 Check 1 → 5 顺序详细分析每条触发情况。

##### Check 1(args / 调用语义保留)—— 0 命中

**触发条件**:替换链 `a → g1 → ... → gN → b` 跑通后,`b` 拿到的 args / 调用方式跟原 `a` 给的不一致,导致 `b` 没法继续干原来的恶意操作 `X`。

##### Check 2(gadget 撞资源)—— 0 命中

**触发条件**:ProvNinja 插的 gadget 跑起来动到 attack 用的资源(锁 / 信号 / socket / PID file / 调度)。

**0 命中**。ProvNinja `add_process_node()`(`provninjaGraph.py:309-342`)插 gadget 不填 CMD,所有 gadget 都默认 bare 调用 = fail-fast = `S_effect ≈ ∅`:

- bare `dpkg` 没 args → print usage 退出,**不持** `/var/lib/dpkg/lock-frontend`
- bare `anacron` 无 anacrontab → state-check 退出,**不抢** cron.daily 调度
- bare `start-stop-daemon` 没 `--pidfile` → print usage,**不 SIGTERM**
- bare `dockerd` → 试 re-bind socket 被占,fail 退出,**不影响原 daemon**
- bare shell / interpreter / GUI(`bash` / `python3.8` / `thunderbird` / `xfce-terminal`)→ stdin EOF / no DISPLAY → 立即退出,**不动任何资源**

→ 所有 gadget 跑起来不动 attack 资源,`S_effect ∩ S_dep = ∅` → 0 命中。

##### Check 3(拓扑可实现性)—— 5 个命中

**触发条件**:modified 图描述的进程树拓扑在 OS 层不可实现,导致 modified 图本身没法实现原图的恶意功能。

**5 个命中,2 个子类**:

| 子类 | 数 | pair | 不可实现的原因 |
|---|---|---|---|
| **Windows PE on Linux** | 4 | `0243_59` / `0335_32` / `0424_06` / `0430_36` | chain 是 `wordpad.exe → backgroundTaskHost.exe → notepad.exe`,Linux kernel `execve("*.exe")` 直接返回 ENOEXEC(ELF loader 拒绝 PE 格式),链第一跳就死 |
| **0 gadget 退化大批删边** | 1 | `0746_41` | 0 gadget 没插任何 chain,删 110 条边后 modified 图剩 10 个孤立 python 互相 fork(cycle 闭环没外部入口)→ 这个进程树跑出来什么都不会装(没 apt → 没 dpkg → 不会装 net-tools),无法实现原图的恶意功能 |

**核心规律**:Check 3 fire 的根因是 ProvNinja 算法**没有 "modified 图必须能实现原恶意功能" 的约束** —— gadget pool 跨 OS 污染产生 PE 链;算法退化产生空 chain 闭环。

##### Check 4(uid / cap)—— 0 命中

**触发条件**:替换链上的 gadget 把 attack 进程拿到的 uid / cap 砍了,导致 attack 进程没权限干 `X`。

**0 命中**。Linux setuid 是 execve 时机型 —— sudo execve 时把 uid 设成 0,后续 execve 默认保留(只有显式 `setuid()` / fcaps drop / `sudo -u <other>` 切换才能掉)。`sudo → sh → bash → docker` 链路上 docker 仍是 root,docker.sock 连得上。

本数据集**没看到这些会真 fire 的场景**:
- `sudo -u <other>` / `su - <other>` 显式 uid 切换链被 gadget 替代
- gadget 二进制有 fcaps drop
- attack 靠特定 cap(`CAP_NET_ADMIN` / `CAP_SYS_PTRACE` 等)

→ 0 命中。

##### Check 5(运行时上下文 fd / env / cwd / stdin)—— 4 个命中

**触发条件**:链跑通了 b 也启动了,但 b 干 `X` 需要的 fd / env / cwd / stdin 因中间 gadget execve 被切断。

**4 个命中,全是 `containerd-shim-runc-v2 → runc` 经 chain 的容器运行时栈**:

| pair | chain | 上下文断在哪 |
|---|---|---|
| `0243_59` / `0335_32` / `0424_06` / `0430_36` | `containerd-shim → wordpad.exe → backgroundTaskHost.exe → notepad.exe → runc` | shim 给 runc 传的 `exec.fifo` fd 必须靠 `os/exec.ExtraFiles` 透传(只在 shim 直接 execve runc 时有效),中间多次 execve 把 fd 关了 → runc 拿不到 fifo → init 阻塞 |

容器运行时栈的 fd handshake 协议:
1. `containerd-shim-runc-v2` 用 `mkfifo()` 创建 `exec.fifo`,`open()` 时**默认带 close-on-exec 标志**
2. shim 用 Go 的 `os/exec.Cmd.ExtraFiles` 显式 spawn runc,Go runtime 在 fork 之后 / execve 之前清掉 fd 的 close-on-exec
3. 子进程 execve 变成 runc(原始路径)→ runc 拿到 fifo fd
4. runc init **必须读 fifo fd 等 shim 写"启动信号"**才能继续

ProvNinja 在中间塞 gadget,attacker 真按这个图跑:
- shim 不再直接 execve runc,而是 execve gadget(比如 wordpad.exe / bash)
- gadget 不知道 fd 应该被特殊处理,execve 时 kernel 强制关掉所有 close-on-exec 的 fd(包括 `exec.fifo`)
- runc 最终启动时 fd 表里**已经没有 fifo** → 读不到信号 → init 永远阻塞 → 容器起不来

**`0304_04` 和 `0330_17` 不在这 4 个里** —— 它们删的是 `dockerd → runc`(libnetwork-setkey,args-driven,**不依赖 fifo 继承**),不是 `shim → runc`。中间塞 bash/sh 不影响 libnetwork-setkey 的 runc 调用,Check 5 不 fire。

**只有删 `containerd-shim-runc-v2 → runc` + 中间塞 gadget 才命中 Check 5**。其他 attack 类型(sudo+docker / python self-spawn / git hook / dockerd→runc 等)不依赖特殊 fd 继承 → 不 fire。

### 3.2 问题二结果

> 实测来源:`eval_problem2.py` 一次性跑完三步 → `eval_problem2.json`(per-pair 191 条)。

#### 三步实测

| Step | 输入 | Detector | detection 率 / 191 |
|---|---|---|---|
| **Step 0** | 原图(未改) | Prov-GAT | **191 / 191 = 100.0%** |
| **Step 1** | 改造图 | Prov-GAT | **0 / 191 = 0.0%** |
| **Step 2** | 改造图 | **D2 规则** | **185 / 191 = 96.9%** |

**一句话结论**:同一组 191 张图,GAT 在原图 100% 抓到 → 改后被推到 0%(完全失效);D2 单条 domain 规则在改后图直接抓 96.9%。**愚弄 GNN ≠ 真隐蔽**。

#### Step 0 — Prov-GAT 在原图上 100% detection

样本 evidence(原图 GAT 输出):
- `0158_13`: 1.000  `0307_07`: 0.936  `0629_18`: 1.000  `0842_53`: 0.999

原图 pred 分布:min=0.610, median=0.936, max=1.000 → **全部 > 0.5**,GAT 工作正常。

#### Step 1 — Prov-GAT 在改造图上 0% detection

同样这 191 张图,改后 GAT 输出:
- `0158_13`: 1.000 → **0.314**(从极度可疑推到 low-confidence benign)
- `0307_07`: 0.936 → **0.000**(从 93% anomaly 推到 0%)
- `0629_18`: 1.000 → **0.000**
- `0842_53`: 0.999 → **0.231**

改后 pred 分布:min=0.000, median=0.017, max=0.477 → **全部 ≤ 0.5**,GAT 全部漏报。

ProvNinja 在 GAT 看的 per-edge regularity 维度上把每张图都精修成 "benign-like" → evasion 100% 成功。

#### Step 2 — D2 单条 domain 规则抓 96.9%

D2 规则:**∃ p ∈ ProcessNode : name(p) ∈ LOLBin AND f(p) ≥ 1 AND s(p) ≥ 1**(任一 LOLBin 进程同时有 file IO 和 socket IO)。

**触发**:185 / 191 = 96.9%。

**经验论证**(`eval_d2_full.json`):D2 在 test set 全集上同时验证:

| 集合 | LOLBin 进程节点数 | 违反单一职责数 |
|---|---|---|
| Benign(636 张图) | 816 | **0** |
| 原始攻击(215 张) | 557 | **0** |
| ProvNinja 改造(191 张) | 605 | **243(40%)** |

→ **1373 个真实 LOLBin 进程,0 个违反单一职责**。τ = 0 不是任意阈值,是经验事实。
→ D2 在 851 张测试集上 **0 误报**,在改造图上 96.9% 抓到 → Precision = 1.000。

#### 漏掉的 6 张

跟 §4.1 案例 1-4 (PE 容器逃逸)重合 —— ProvNinja 给这几张插的是 Windows PE 进程(`wordpad.exe`、`notepad.exe`),根本不在 16 个 Linux LOLBin 池里,所以 D2 不触发。这是 ProvNinja gadget pool 跨 OS 污染的另一个 bug,不算 D2 弱点。

#### bottom line

```
GAT 在 191 张原图:    100% 抓到  ← detector 工作正常
GAT 在 191 张改造图:    0% 抓到   ← evasion 完全成功
D2  在 191 张改造图:  96.9% 抓到  ← 一行 if 判断完胜 GAT
```

**H2 强立住**:ProvNinja 在 per-edge regularity(GAT 看的维度)上做了精心欺骗,但完全没碰 process behavior profile(LOLBin 单一职责)这种 domain 维度。任何利用领域常识的简单检测器都识破。

---

## 4. 根因分析

> **状态:实测完成,§4 根因由 §3 实测数字锚定**。

### 4.1 问题一根因

#### 总体数字

**实测 5/191 disrupted (2.6%), 186/191 intact**。5 个 disrupted 分两组:
- **案例 1-4**(同质):4 个 PE on Linux 容器场景(`0243_59` / `0335_32` / `0424_06` / `0430_36`)
- **案例 5**:`0746_41`(0 gadget 退化大批删边)

下面用统一 4 段结构(原攻击 → 修改后攻击 → 算法错在哪 → log 角度分析)逐组分析,§4.1 末尾给出共同根因。

---

#### 案例 1-4:容器逃逸 / 恶意容器(`0243_59` / `0335_32` / `0424_06` / `0430_36`)

##### 1. 原攻击

attacker 入侵 Linux 主机后通过 docker 启动恶意容器(挖矿 / C2 / 数据外泄等),是云原生 post-exploit 最常见模式。真实参考报告:

- TeamTNT 针对 misconfigured Docker daemon 部署挖矿容器:[Trend Micro](https://www.trendmicro.com/en_us/research/22/k/teamtnt-targets-misconfigured-docker-daemons.html) / [Sysdig](https://sysdig.com/blog/teamtnt-the-first-crypto-mining-worm-to-steal-aws-credentials/)
- CVE-2019-5736 runc 容器逃逸:[Sysdig Falco rule analysis](https://sysdig.com/blog/cve-2019-5736-runc-container-breakout/)
- CVE-2024-21626 (Leaky Vessels) runc fd 泄漏:[Snyk advisory](https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/)
- Kinsing / H2Miner:[Aqua Security](https://blog.aquasec.com/kinsing-malware-attacks-targeting-container-environments)

**attacker 真敲的命令**:`docker run malicious-image`(或类似)

**audit log 实际记录的真实进程链**(报告里直接看到):
```
attacker → dockerd → containerd → containerd-shim-runc-v2 → runc → 恶意容器
```

**log 体现攻击成功执行的关键证据**:
- `containerd-shim → runc` 直接 fork 边(shim 启动 runc 的关键)
- shim 跟 runc 之间的 `exec.fifo` fd 继承协议(确保 runc init 拿到 shim 的"go"信号才启动容器)
- runc 起来后跑容器进程

##### 2. 修改后的攻击

ProvNinja 把 `containerd-shim → runc` 直接边替换成:

```
containerd-shim → wordpad.exe → backgroundTaskHost.exe → notepad.exe → runc
```

跟原 log 对比:
- `shim → runc` 直接边:**没了**(被替换)
- 中间多了 3 个 Windows PE 节点
- shim 不再直接 fork runc

##### 3. ProvNinja 算法应用哪里不对

**论文 §4.6 算法步骤简述**:找原图 conspicuous 边,从 gadget pool 查替换 chain(每跳 regularity > 0.03 的概率路径),应用 chain 替换原边。

**应用到 case 1-4 的具体动作**:
1. 算法选 conspicuous 边:`(containerd-shim, runc)`
2. 查 `gadget_dict[(shim, runc)]` 拿候选 chain → 找到 `[wordpad.exe, bgTaskHost.exe, notepad.exe]`
3. 应用 chain:删 shim → runc 直接边,中间插 3 个 PE 节点
4. GAT 看 modified 图给 benign 评分 → 算法保存

**算法应用过程改了 / 破坏了原 log 的两个底层运行时依赖**:

(a) **fork 合理性破坏**(Check 3):每条插入的 fork 边在 binary 代码层面都不合理:

| fork 边 | 真实 binary 行为里这事会发生吗 |
|---|---|
| containerd-shim → wordpad.exe | ❌ shim 是 Linux Go binary,代码硬编码只 fork runc,不会 fork Windows 写字板 |
| wordpad.exe → bgTaskHost.exe | ❌ wordpad 是 GUI 编辑器,无此 fork 行为 |
| bgTaskHost.exe → notepad.exe | ❌ 后台任务进程跟记事本无父子关系 |
| notepad.exe → runc | ❌ notepad 没启动 Linux runc 的代码路径 |

ProvNinja 靠 benign 数据频率统计(R > 0.03)选 chain,但**频率高 ≠ binary 代码合理**(数据有跨 OS 污染、PID 复用、采集 noise),所以拼出 nonsense chain。

(b) **fd 继承协议依赖破坏**(Check 5):shim 跟 runc 之间有 `exec.fifo` fd 继承协议(参 [containerd init.go](https://github.com/containerd/containerd/blob/main/runtime/v2/runc/v2/init.go) + [runc init_linux.go](https://github.com/opencontainers/runc/blob/main/libcontainer/init_linux.go)):

1. shim `mkfifo()` + `open(O_CLOEXEC)` 拿 fd
2. shim 在 fork 之前**手动清掉 fd 的 close-on-exec**(代码 hardcoded,只为 runc 做)
3. shim 直接 `execve("runc")` → runc 拿到 fd
4. runc init 必须 `read(fifo)` 等 shim 写"go"才继续启动容器

→ 协议依赖 **shim 跟 runc 是直接父子关系,中间不能有任何其他进程 execve**(否则 close-on-exec 关 fd)。ProvNinja 在中间塞 chain → 中间多次 execve → fd 丢 → runc init 阻塞。

**ProvNinja 在日志层面看不出这两个依赖**:audit log 不记 binary 代码层 fork 合理性,也不记 fd 继承协议。所有 PROC_CREATE 边在 log 里**长得一模一样**,算法分不清哪条边背后有协议依赖、哪条 fork 在 binary 代码层不合理,所以敢在任何边上随意拼 chain。

##### 4. 从 log 角度分析:为什么 modified log 保证不了攻击成功执行

**attacker 真攻击的物理现实**:
- attacker 想起恶意容器 → 必须经过 docker → containerd → shim → runc(Linux 容器运行时唯一通道)
- 真敲 `docker run` → OS 必然产生完整 shim → runc 直接 fork 边 + fd 继承
- attacker 无法跳过这条路径起容器

**modified log vs 真 log 对比**:

| | modified log(ProvNinja 给的)| attacker 真敲命令产生的真 log |
|---|---|---|
| shim → runc 直接边 | 没有(被替换成 PE 链) | **必然有**(docker 容器启动唯一路径)|
| PE 中间节点 | 有 3 个 | 没有(Linux 上 .exe 跑不了)|
| `exec.fifo` fd 继承 | 协议被破坏(中间 execve 关 fd)| **必然完整**(shim 直接 execve runc)|

attacker 想用 modified log 做 evasion,**两条路都死**:
- **按 modified log 跑**(让 runtime 产 PE 链 trace)→ Linux kernel `execve("*.exe")` 返回 ENOEXEC,链第一跳就死 → 攻击不发生
- **按原命令跑**(`docker run`)→ 真 log 是标准 shim → runc 链,跟 modified log 完全不一样 → detector 看真 log 报警

→ **modified log 在 OS 兼容性 + fd 协议两个维度上跟 attacker 真实命令产出的 log 永远不一致,日志级修改保证不了攻击成功**。

---

#### 案例 5:`0746_41`(0 gadget 退化大批删边)

##### 1. 原攻击

**TeamTNT-style apt install 侦察工具部署**(参考: [Intezer TeamTNT 凭据收集器](https://www.intezer.com/blog/cloud-security/teamtnts-extended-credential-harvester/) / [HiddenWasp Linux 恶意软件](https://www.intezer.com/blog/research/hiddenwasp-malware-targeting-linux-systems/) / [GTFOBins apt 滥用](https://gtfobins.github.io/gtfobins/apt/))

attacker 入侵 Linux 后真敲命令:`apt install net-tools`(目的:装 ifconfig / netstat / route / arp 做内网侦察)。

**audit log 实际记录**(忠于 0746_41 原图 pkl 数据):

```
ProcessNode: 56 个(1 apt + 4 dash + 51 python3.8)
FileNode:    39 个(/var/lib/apt/lists/*、/var/lib/dpkg/status 等 apt 元数据)
PROC_CREATE 边: 110 条
WRITE 边:    0 条(数据采集时只 filter 了 apt/dash/python 这 3 类进程)

进程链:
  apt(/usr/bin/apt install net-tools)
    ↓ apt 触发 update-notifier 后处理钩子
    dash(/bin/sh -e /usr/lib/update-notifier/update-motd-updates-available)× 4
    ↓
    python3.8(/usr/bin/python3 /usr/lib/update-notifier/apt-check --human-readable)
    ↓
    python multiprocessing 自衍生 51 个实例
```

log 体现的"`apt install` 命令真跑了"的**3 个执行证据**:
1. apt 进程节点 + 它读 `/var/lib/apt/lists/*` 等 apt 元数据(命令入口证据)
2. dash 节点跑 update-notifier 钩子脚本(apt 装包流程进到后处理阶段的证据)
3. 51 个 python multiprocessing 实例(apt-check 真在跑多进程检查的证据)

##### 2. 修改后的攻击

ProvNinja 对原图执行替换后的 modified log:

```
ProcessNode: 10 个(全是 python3.8,CMD: 'apt-check --human-readable')
PROC_CREATE 边: 18 条(全是 python ↔ python 互相 fork,闭环 cycle)

apt 节点:                     没了
dash 节点:                    没了
update-notifier 钩子触发链:    没了
apt 元数据 READ 边:           没了
```

##### 3. ProvNinja 算法应用哪里不对 —— 改 log 的时候改了原始攻击的触发点

**原始攻击的 trigger 节点是什么**

`apt install net-tools` 这个攻击的 audit log 里,**`apt` 节点是攻击的 trigger** —— 它对应 attacker 真敲的命令本身。后续整条进程链(dash 触发 update-notifier 钩子、python 跑 apt-check、multiprocessing × 50)**都是这个 trigger 的下游传播**:

```
apt(trigger,attacker 真敲的命令) 
    ↓ 触发
    dash(传播节点)→ python(传播节点)→ multiprocessing(传播节点)
```

attacker 想要的攻击效果(装 net-tools)**只能通过这个 trigger 实现** —— 没敲 apt install 就没攻击,敲了就必然产生 apt trigger 节点。

**ProvNinja 算法的具体动作**

应用论文 §4.6 算法到 0746_41:
1. 算法选某条 conspicuous 边(比如 `dash → python`)替换
2. 查 `gadget_dict[("dash","python")]` 拿替换 chain → 没匹配 → 返回空 chain
3. 应用空 chain:`remove_node(dash)` + 不插任何 gadget
4. 副作用:`remove_isolated_nodes()` 级联清扫 → **apt trigger 节点变孤立 → 被一并扫掉**
5. 剩下 10 个 python 闭环 → GAT 判 benign → 算法保存

**算法应用错在哪 —— 它改了原始攻击的 trigger**

ProvNinja 把 `apt` 节点级联清扫掉了。这个 apt 节点**就是 attacker 真敲的 `apt install` 命令在 log 里的对应 trigger**。**算法把攻击的触发点从 log 里删掉了**。

```
原 log 的 trigger:  apt (= attacker 敲的 apt install)
                       ↓ 触发后续链
                       dash → python → multiprocessing

改后 log 的 trigger:  无任何节点(apt 被删,只剩 10 个孤立 python)
```

**算法没意识到 apt 节点的特殊性** —— 在 ProvNinja 看来,apt 跟其他进程节点(dash、python 等)在 log 数据结构上完全等价,都是 PROC_CREATE 边的端点。**它分不清"trigger 节点 vs 传播节点"**,所以它级联清扫的时候敢把 trigger 一并扫了。

##### 4. 从 log 角度分析:改了 trigger 为什么让攻击成功执行保证不了

**核心矛盾:trigger 在 log 里被改了,但 attacker 真攻击必须重新产生这个 trigger**

attacker 真攻击的物理现实:
- attacker 想装 net-tools → **必须真敲 `apt install net-tools`**(只有这条命令能触发装包)
- 真敲这条命令 → OS **必然产生 apt 进程节点**(trigger 在真 log 里必然存在)
- attacker 没法在不敲 apt 的情况下装 net-tools

modified log 描述的执行 vs attacker 真攻击的执行:

| | modified log(ProvNinja 给的)| attacker 真敲命令产生的真 log |
|---|---|---|
| **trigger 节点(apt)**| **没有**(算法删了)| **必然有**(命令真敲了)|
| 后续传播链 | 没有 | **必然有**(apt 必触发 update-notifier 钩子链)|
| python multiprocessing | 10 个孤立 cycle | 51 个完整 multiprocessing 实例 |

→ **trigger 在 modified log 里没了,但 attacker 真攻击必然重新产生 trigger**。两个 log 在 trigger 这件事上**根本对不上**。

attacker 想用 ProvNinja 给的 modified log 做 evasion,有两条路:

- **按 modified log 跑**(即让 runtime trace 跟 modified log 一致)→ 不能敲 apt install(trigger 不能产生)→ **没法装 net-tools,攻击不发生**
- **按原命令跑**(真敲 `apt install`)→ 真 log 必然有 apt trigger → **跟 modified log 完全不一致** → detector 看真 log → 报警

→ **modified log 跟 attacker 真实命令产出的 log 在 trigger 这件事上永远对不上,日志级修改保证不了攻击成功执行**。

---

#### 共同根因:资源依赖锁定运行时依赖

5 个 disrupted 表面看是两类失败(case 1-4 fork 关系不合理 + fd 协议被破坏;case 5 trigger 被改),**但深层都源于同一个根因 —— 资源依赖**:

```
攻击 = 想要某种系统资源效果(装包 / 起容器 / 写文件 / 连网络)
   ↓
   系统资源被特定工具守着(apt 守着包管理、docker→runc 守着容器、curl 守着网络等)
   ↓
   要拿资源 → 必须用守门工具
   ↓
   用守门工具 → log 里必然出现工具的 trigger 节点
   ↓
   attacker 想攻击 → trigger 必然产生 → ProvNinja 改了 trigger 也没用
```

**fork 逻辑只是守门工具被调用后产生 log 的具体形状**(apt 调用后 fork dash → python、shim execve runc 用 fd 继承等),由 binary 代码决定。**根因是资源依赖** —— attacker 没法跳过守门工具直接拿资源。

**两个 case 在这个根因下的具体表现**:

| | 资源依赖(根因)| fork 逻辑(表面)| ProvNinja 怎么破坏 |
|---|---|---|---|
| 案例 1-4 | attacker 要"启动容器"资源 → 必经 shim → runc gatekeeper | shim 跟 runc 之间用 `exec.fifo` fd 继承同步(代码 hardcoded 清 close-on-exec)| 中间塞 chain → fork 关系不合理 + fd 协议被破坏 |
| 案例 5 | attacker 要"装包"资源 → 必经 apt gatekeeper | apt 装包后期 fork dash → python multiprocessing(代码 hardcoded)| 删了 trigger 节点(apt) |

**根本论点**:任何真实攻击都有"资源依赖 → gatekeeper → 必然 trigger"这条链。ProvNinja 在日志层面改图 → 算法看不出 trigger / fd 协议 / fork 合理性这些**底层运行时依赖** → 改完的 log 在资源依赖锁定的"必然 trigger"这件事上永远对不上 attacker 真实执行 → 日志级方法保证不了攻击成功。

**命令级方法直接绕过资源依赖盲区**:attacker 自己选要敲什么命令,trigger 是输入而不是从 log 推出来的。命令一敲,资源依赖、gatekeeper、fork 链路、fd 协议全部交给 OS + binary 代码自己处理 —— **不需要算法识别哪些是 trigger / 哪些是有协议依赖的边**,真跑就自然全部满足。

---

### 4.2 问题二根因

#### 总体数字

**实测**:191 张改造图,GAT 全漏(0/191),D2 抓 **185/191 = 96.9%**(漏的 6 张是 PE 容器逃逸 case,跟 §4.1 案例 1-4 重合)。两个 detector 在同一组样本上 detection 率完全反过来。

下面用统一 4 段结构(原图 → 改后图 → ProvNinja 算法应用错在哪 → 从 detector 角度分析)分析 D2 精准命中的典型 case,§4.2 末尾给出共同根因。

---

#### 案例:`nd_220323_0143_55` —— D2 精准命中

##### 1. 原图

```
                  P2  python3.8 (LOLBin)
                  (CMD: apt-check)
                       /     \
                      ↓       ↓
                ┌──────────┐  ┌──────────┐
                │ P1       │  │ P0       │
                │ python   │  │ python   │
                │ apt-check│  │ lsb_release│
                └──────────┘  └──────────┘
                      │
                      │ READ × 50
                      ↓
                ┌─────────────────────┐
                │ 50 FileNode         │
                │ (apt config files)  │
                └─────────────────────┘
```

| 进程 | file 边 | socket 边 |
|---|---|---|
| P0 | 0 | 0 |
| P1 | **50** | 0 |
| P2 | 0 | 0 |

物理意义:**纯本地文件型攻击**(apt-check 读配置)。所有 LOLBin python3.8 进程严格单一职责 —— P1 只读文件,P0/P2 仅做进程链,**完全没 socket 边**。

##### 2. 改后图(ProvNinja 给原本闲着的 P2 加 camouflage)

```
                  P2  python3.8 (LOLBin)     ★ D2 命中:同时 file+socket IO
                  (CMD = <空>)                  违反单一职责!
                       /     \   │  │  │  │  │  │  │  │  │  │
                      ↓       ↓  │  │  │  │  │  │  │  │  │  │
                ┌──────────┐  ┌──────────┐  READ×5  │ READ×4+WRITE×1
                │ P1       │  │ P0       │     ↓    ↓
                │ python   │  │ python   │  ┌──────┐ ┌──────────┐
                │ apt-check│  │ lsb_rel  │  │5 File│ │5 Socket  │
                └──────────┘  └──────────┘  │(新加)│ │(新加,无中生有)│
                      │                     └──────┘ └──────────┘
                      │ READ × 50
                      ↓
                ┌─────────────────────┐
                │ 50 FileNode         │
                │ (apt config files)  │
                └─────────────────────┘
```

| 进程 | file 边 | socket 边 |
|---|---|---|
| P0 | 0 | 0 |
| P1 | 50 | 0 |
| **P2** | **5** | **5** ← **D2 触发** |

**关键变化**:
- P2 从空闲 `(file=0, sock=0)` 变成 mixed IO `(file=5, sock=5)`
- 整图从 `0 SocketChannel` 变成 `5 SocketChannel`(无中生有)
- **同一个 python3.8 进程同时摸文件 + 摸网络 → 违反单一职责原则**

##### 3. ProvNinja 算法应用哪里不对

**`apply_camoflauge`(`provninjaGraph.py:384-399`,`num_actions=10`)的伪代码**:

```python
for new_gadget in inserted_gadgets:
    process_meta = load_process_json(gadget.name)
    candidates   = process_meta["files"] + process_meta["sockets"]  # 文件 + socket 全字段
    sampled      = sample(candidates, num_actions=10)               # 随机抽 10 个目标
    for target in sampled:
        graph.add_edge(gadget, target)
```

**两个失败模式**:

(a) **采样源不区分类型** —— `candidates` 是 `files + sockets` 拼接的扁平列表,随机抽 10 个,**自然两类都摸到**。算法没有"采样源类型平衡 / 跟原图节点类型对齐"约束。

(b) **不看原图行为画像** —— 算法给 P2 配伪装边时只看 `python3.8.json` 里 benign 全局聚合的"python3.8 通常读什么 / 连什么",**完全不看当前 attack 图里 P2 的现有职责**。原图 P2 闲着,改后变 mixed,跟原图行为画像完全不对。

**为什么作者没写**:作者优化目标是"每条新边在 benign freq DB 里看起来像 benign",这就需要从 process_meta 全量采样(包括 socket)以增加伪装多样性。**给单边像 benign 优化 → 全图行为画像失真**,作者没意识到这违反了 process behavior profile 的领域常识。

##### 4. 从 detector 角度分析

| detector | 看什么 | 在这张图上的判定 |
|---|---|---|
| **Prov-GAT(原作者用)** | 学的 embedding,看 per-edge regularity + K-hop 邻居 | **判 benign(漏)** —— 5 条新加 socket 边都从 `python3.8.json` 采,GAT freq DB 里都常见,单边过关 |
| **D2(单一职责)** | 任一 LOLBin 进程是否同时 file IO + socket IO | **判改造(抓)** —— P2 python3.8 同时 file=5 sock=5,直接命中 |

**为什么 GAT 漏、D2 不漏**:
- **GAT 看的维度 = ProvNinja 优化的维度**:ProvNinja 把每条边都改成 freq DB benign-like,GAT 看每条边都正常
- **D2 看的维度跟 ProvNinja 完全不重合**:D2 看的是 process-level 的"行为画像是否单一职责",这个**不在 ProvNinja 的目标函数里**

**经验数据兜底**:test set 上 1373 个真实 LOLBin 进程节点,**0 个违反单一职责**;改造图 605 个 LOLBin 进程,**243 个违反(40%)**。τ=0 是经验事实,不是任意阈值。

→ 这一类 case 共 185/191 = 96.9%,是 H2 强立住的核心证据。剩下 6/191 漏的是 PE 容器逃逸 case(`0243_59` / `0335_32` / `0424_06` / `0430_36` 等,详见 §4.1 案例 1-4),ProvNinja 给 Linux 攻击插了 Windows PE,EXE_NAME 不在 LOLBin 池里,这是 ProvNinja 算法 bug 留下的 corner case,不是 D2 设计盲点。

---

#### 共同根因:ProvNinja 的优化目标只覆盖 GAT 看的维度,完全跨过 process behavior profile

**根本机制**:

```
ProvNinja 优化目标:Freq(u, v, r) / Freq(u, *, r) > 阈值(每条边 regularity)
                   ↓
                   这正是 GAT 学到的特征(per-edge embedding 核心信号)
                   ↓
GAT 漏报 100%      ← ProvNinja 在每条边上把 regularity 改高,GAT 看每条边都正常
                   ↓
process behavior profile 完全没在算法里出现过
                   ↓
D2 抓 96.9%        ← LOLBin 进程的单一职责约束,ProvNinja 一次都没考虑
```

**核心论点**:**ProvNinja 在 GAT 看的维度(per-edge regularity)上做了精心欺骗,但在 GAT 没看、自己也没考虑的维度(process behavior profile / 单一职责)上留下完整指纹**。D2 不需要学 embedding、不需要训练、不需要原图作对比 —— 单一条 LOLBin 单一职责检查就完胜 GAT 的复杂模型。

**`provninjaGraph.py` 三个层面缺约束**:
- `apply_camoflauge`:`candidates = files + sockets` 拼接采样,**不约束节点类型平衡 / 单一职责** → 案例 A 共同根因
- `gadget_chain.json`:**没按 OS 分桶**,Linux attack 用 Windows PE chain → 案例 B + §4.1 案例 1-4 共同根因
- 整个算法没有 "process-level behavior profile" 这个概念 —— 只在 edge-level freq DB 上优化,跨过 process-level domain knowledge

**这是 ProvNinja 的"优化层级过窄"盲点** —— 算法只关心 edge-level 跟 GAT 同维的 regularity 信号,**没把 process-level 行为画像写进目标函数或约束里**,所以连"LOLBin 进程不混合 IO"这种最朴素的领域常识都违反。

**对 SafeMimic 的启示**:核心 gap 是**多层级一致性约束**,具体要在算法 loss / 约束里加:
- **process-level**:LOLBin 进程的行为画像跟原图保持一致(单一职责不混合)—— 直接对应 D2
- **graph-level**:节点类型分布、边类型分布跟原图对齐 —— 之前 F6 的方向
- **OS-level**:gadget pool 按 OS 分桶,不让 Linux attack 用 Windows PE —— §4.1 + 这里案例 B 共同根因

这是 SafeMimic 的 distribution match + 资源依赖模块该共同解决的:**不是只让每条边在 freq DB 里像 benign,而是让攻击图作为整体在 process / graph / OS 多个层级都跟真实分布一致**。

---

## 附:产物文件位置

```
baselines/pipelines/provninja/
├── PROBLEM_JUSTIFICATION.md     (本文档)
├── README.md                    (上游 ProvNinja 复现文档)
├── provninja_usenix23.pdf       (原论文)
│
├── 问题一(P1)产物 ────────────────────────────────────────────────
├── extract_diffs.py             (Step 1: 节点对齐 + 7 元 tuple 边 diff,带 dgl 跨版本 alias + 5 跳 BFS replacements)
├── diffs/                        (Step 1 输出)
│   ├── pair_<图名>.json × 191   (每对的完整 diff,带 removed/inserted/replacements 字段)
│   └── summary.json              (全集统计,0 failures)
├── judgments/                    (Step 2 输出,Claude 在线 5-check 判断)
│   └── judgment_<图名>.json × 191  (每对的 verdict + disruption_point + rationale。5 disrupted / 186 intact)
│
└── 问题二(P2)产物 ─── 每个脚本配同名 .json 输出 ────────────────────
    ├── eval_problem2.py            (统一三步 pipeline:GAT-on-orig / GAT-on-adv / D2-on-adv)
    ├── eval_problem2.json           ↳ 三步对比 100% / 0% / 96.9%,per-pair 191 条
    ├── eval_gat_on_adv.py          (Step 0/1 实现:GAT 在 191 对的 per-sample forward)
    ├── eval_gat_on_adv.json         ↳ per-sample GAT 预测
    ├── eval_d2_full.py             (D2 在 851 张 test set 上的 P/R/F1 + 单一职责经验论证)
    └── eval_d2_full.json            ↳ Task A 改造检测 + Task B anomaly 分类 P/R/F1
```
