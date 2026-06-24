z# Problem Statement & Motivation Experiment

> 本文件**只**回答四件事:打谁(baseline)→ 问题是什么 → 怎么验 → 凭什么算证明了。
> 不涉及 SafeMimic 解法。

---

## 1. Baseline 与符号

### Baseline 方法(我们要打的)

| 方法 | 来源 | 选 b 的打分函数 | 共同盲点 |
|---|---|---|---|
| **ProvNinja** | USENIX'23 | `score_PN(b) = freq(b)`(按系统中常见度排序) | 不查 `b` 的副作用 |
| **Goyal et al.** | NDSS'23 | `score_GY(b) = −ΔKL(P_{A⊕b} ∥ P_normal)`(按检测分降幅排序) | 不查 `b` 的副作用 |
| **Contorter** | S&P'26 | `score_CT(b) = sim(context(b), context(attack_node))`(类型选择 TypeSel + 足迹优化 FOpt) | 自称 preserve attack,但 context similarity 不等于 `S_dep` 安全 |
| **Random** | 无 | 均匀采样 | 不查任何东西 |
| **Raw** | 无 | 不插任何操作 | 参考线 |

> **三个 baseline 时间线**:USENIX'23 → NDSS'23 → **S&P'26**。如果 Problem 1 / Problem 2 在最新的 Contorter 上仍然立住,说明这是**整条研究线的结构性盲点**,不是某一个方法的疏漏。

### 符号

- **攻击链** `A = (s_1, ..., s_n)`,每步 `s_i` 需要的资源记 `deps(s_i)`
- **攻击依赖集** `S_dep(A) = ⋃ deps(s_i)` —— 攻击靠哪些进程/网络/凭据/文件活着
- **良性操作** `b` 的**影响集** `S_effect(b)` —— `b` 执行时会修改哪些资源
- **危险池** `B_unsafe(A) = { b | S_effect(b) ∩ S_dep(A) ≠ ∅ }` —— 撞到攻击资源的操作
- **安全池** `B_safe(A) = B_all \ B_unsafe(A)`
- 方法 `M` 选出 `B_M ⊂ B_all` 插入攻击,得**伪装轨迹** `A ⊕ B_M`
- **正常分布** `P_normal` —— 目标环境的良性行为基线

---

## 2. 两个问题

### 问题 1 —— ProvNinja/Goyal 的变异日志里就藏着会让攻击失效的良性操作

ProvNinja / Goyal 挑伪装 `b` 时只看"像不像正常",**完全不检查 `b` 会不会撞到攻击的关键资源**(进程、网络、凭据、文件)。

后果在他们生成的变异日志里**一望可见**:他们的输出 log 包含 `kill -9 <pid>` / `iptables DROP` / `systemctl stop` 这种良性操作插入 —— 这些操作的影响集 `S_effect(b)` 跟攻击依赖集 `S_dep(A)` 直接冲突,这条变异链路如果跑下去,攻击会在这一步终止。

具体反例(打分高 × `S_effect ∩ S_dep ≠ ∅` × 直接断攻击命脉):

| 伪装操作 | ProvNinja/Goyal 给的高分理由 | 撞到的攻击命脉 |
|---|---|---|
| `kill -9 <pid>` | freq 高,完美伪装 | 攻击进程被杀 → **整条链断在这** |
| `iptables -A INPUT -j DROP` | 管理员常用,自然 | C2 通道切断 → **后续命令无法下发** |
| `systemctl stop <service>` | 中等 freq | 寄生服务停 → **攻击载体消失** |

形式化:存在 `b ∈ B_unsafe(A)` 出现在 `M` 输出的变异 log 里 ⇒ 该 log 对应的 `A ⊕ B_M` 跑下去 `success = false`。

**重点不是"成功率打折",而是 ProvNinja/Goyal 的输出日志里就藏着会让攻击失效的炸弹 —— 这件事直接读他们的 log 就能看出来。**

### 问题 2 —— ProvNinja/Goyal 的变异日志在统计特征上明显偏离原始日志

ProvNinja / Goyal 为了"骗过 ML 检测器"插了一堆操作。把他们的输出 log 跟原始攻击 log 对照,**插入过程本身**会让前者在 provenance graph 上出现新偏差:

- **边数膨胀** —— 原本 90 条边的攻击 trace 在变异 log 里变成 290 条
- **操作类型偏斜** —— 几乎全是 read,write/exec/connect 比例严重失衡
- **时间突发** —— 短时间内大量新增边,跟原始 log 的时间分布完全不像

这些偏差**直接对比 `original.log` 和 `chain.log` 一望可见**,而且**逃不过简单频率规则**(边数 +3σ、操作类型 KL > τ、5min 窗口突增),也可能让某些 ML 检测器异常分**反而升高**。

---

## 3. 怎么实验验证

> **核心思路**:不跑新实验,直接**读 `baselines/results/` 里已有的 ProvNinja/Goyal 变异输出**,从中挖反例。

### 3.0 数据库存(都在仓库里,已跑完)

#### 原始攻击 trace
`baselines/results/strace_logs/CVE-XXX_original.log` —— 3 个 CVE 的真实 strace
- `CVE-2014-6271`(Shellshock,82 行)
- `CVE-2017-9841`(PHPUnit RCE)
- `CVE-2021-41773`(Apache 路径穿越)

#### ProvNinja 的输出(每 CVE 67 条 chain)
`baselines/results/replay_logs/provninja/CVE-XXX_chainN.log` —— 每条 log 包含:
```
Gadget chain: sh → run-parts → bash
Commands:
  echo '[gadget] sh' / dpkg --version / ...
Flag found: False
```
**关键**:这里给的是 ProvNinja **选出的 gadget 提议**(不是 replay 的真实 strace)。`Flag found: False` 是 replay pipeline 的局限性产物,**不能直接当反例**——我们要看的是 ProvNinja 选了什么 gadget,以及这些 gadget 真跑会不会撞 `S_dep`。

#### Goyal 的输出(每 CVE 4 个 variant)
`baselines/results/replay_logs/goyal/CVE-XXX_{FGA,provDetector,streamSpot,unicorn}.log`
对应 4 种 ML 检测器目标。每个 log 给出:
- 注入的良性行数(`benign_rows`)
- 提取的攻击命令(`Attack commands extracted`)
- `Flag found: True/False`

#### 已聚合的 metadata
`baselines/results/evaded/step3_summary.json` —— 每个 Goyal variant 的:
- `attack_rows`:原攻击多少 syscall 行
- `benign_rows`:Goyal 注入了多少良性行
- `total_rows`:加起来

CVE-2014-6271 的实测数:

| Variant | 攻击行 | 注入良性行 | **膨胀比** |
|---|---|---|---|
| provDetector | 14 | 500 | **35×** |
| unicorn | 14 | 2000 | **143×** |
| streamSpot | 14 | 3000 | **214×** |
| FGA | 14 | 5000 | **357×** |

CVE-2021-41773 同上(11 行攻击 + 500/2000/3000/5000 良性)。

---

### 3.1 验问题 1 ── 在 ProvNinja gadget 提议里找"会撞 `S_dep`"的反例

**做法**:对每个 CVE,人工读所有 67 条 ProvNinja chain log 的 `Gadget chain:` 行,把出现过的 gadget 操作提取出来,标注 `S_effect`,跟该 CVE 的 `S_dep(A)` 比对。

**步骤**:
1. **跑 grep 提取所有 gadget**:`grep -h "Gadget chain:" replay_logs/provninja/CVE-2014-6271_*.log | sort -u` —— 得到全部出现过的 gadget 链
2. **拆出每个原子操作**(比如 "sh → run-parts → bash" 拆成 sh、run-parts、bash)
3. **人工标注每个原子操作的 `S_effect`**(读、写、改进程、改网络...)
4. **写出该 CVE 的 `S_dep(A)`**:
   - CVE-2014-6271 (Shellshock): `S_dep = { bash process, /flag.txt readable, env vars }`
   - CVE-2017-9841 (PHPUnit RCE): `S_dep = { php-fpm process, eval'ed payload, http listener }`
   - CVE-2021-41773 (Apache traversal): `S_dep = { httpd process, /etc/passwd readable, request handler }`
5. **找冲突**:任何 `S_effect ∩ S_dep ≠ ∅` 的 gadget 就是反例
6. **解释**:这条 chain 真跑会在哪一步死掉

**期望产出**:一张"ProvNinja gadget 危险性"清单,列出至少 3-5 个具体反例 gadget(打分高 × 撞 `S_dep` × 解释为什么会死攻击)

**注意**:很多 ProvNinja gadget 的 commands 是 `echo '[gadget] X'` 占位符 —— 这是 replay pipeline 的简化,**真实的 ProvNinja 论文里这些 gadget 是真跑的二进制**(sh、bash、dpkg 等)。我们要标注的是**那些真实二进制的 `S_effect`**(比如 `dpkg --version` 写 lock 文件、`run-parts` 启动子进程),不是 echo 的 effect。

### 3.2 验问题 2 ── 在 Goyal 注入数据里找"统计偏离原始"的反例

**做法**:用 `step3_summary.json` 里现成的 `attack_rows` / `benign_rows` 数,直接算膨胀比;再读 Goyal 的实际变异 trace 文件算操作类型分布偏斜。

**步骤**:
1. **边数膨胀**(已现成):
   - 算 `total_rows / attack_rows`,得到表格里那些 35× / 143× / 214× / 357× 的比例
   - 任意一个 variant > 2× 就触发 R1(边数 +3σ)告警
2. **操作类型偏斜**(需要读 trace):
   - 找到 Goyal 实际注入的 trace 文件(`evaded/goyal/...` 或 `evaded/goyal_supply_chain/SC-Attack-*_provDetector.csv`)
   - 统计 `read / write / execve / connect / open / ...` 各类 syscall 的频次比例
   - 跟 `original.log` 里同样的统计算 KL 散度
   - 任一 variant KL > 0.3 就触发 R2 告警
3. **时间突发**(需要 trace 有时间戳):
   - 把 trace 按时间戳分 1 分钟桶,统计每桶 syscall 数
   - 看 Goyal 注入是不是集中在某几个桶里
   - 任一桶 > μ + 3σ 就触发 R3 告警

**期望产出**:一张"Goyal 注入异常程度"表,4 个 variant × 3 条规则 = 12 个数,标记哪几格触发告警。

**ProvNinja 这边怎么办**:ProvNinja chain log 没真 trace,但可以从 `evaded/provninja/` 的输出图(如果有的话)间接拿到。如果 ProvNinja 的实际 trace 不在仓库里,**Problem 2 主要靠 Goyal 的 357× 膨胀立** —— 一个 baseline 立住就够 motivation 了。

---

### 3.3 输出形式

每条反例写成一段:

```markdown
#### 反例 R1.A (CVE-2014-6271, ProvNinja, Problem 1)
**ProvNinja 选的 gadget**:`run-parts`(出现在 chain5/chain8/chain12 共 11 条 chain 里)
**S_effect**:`{process_creation: 子进程 fork, file_system: 写 /var/run/run-parts.pid}`
**攻击 S_dep**:bash 进程必须独占 stdin/stdout 接收 attacker payload
**冲突**:`run-parts` fork 子进程会让 bash 上下文丢失;
        新进程接管 fd → bash 收不到后续 attacker 输入 → 攻击中断
**证据**:`replay_logs/provninja/CVE-2014-6271_chain5.log:2`("Gadget chain: sh → run-parts → bash")

#### 反例 R2.A (CVE-2014-6271, Goyal-FGA, Problem 2)
**Goyal-FGA 在 14 行攻击之上注入了 5000 行良性 syscall**(膨胀比 357×)
**触发规则**:R1(边数远超 baseline μ + 3σ)
**机制**:为了骗 FGA 检测器,Goyal 在小攻击 trace 里塞了大量"benign-looking" syscall,
        但任何带边数监控的规则都会立刻报警
**证据**:`evaded/step3_summary.json` —— `{cve_id: CVE-2014-6271, variant: FGA, attack_rows: 14, benign_rows: 5000}`
```

最终 motivation 章节列 3-6 个这样的具体反例。

---

### 3.4 工作量估计

| 步骤 | 工时 |
|---|---|
| **3.1**: grep 出所有 ProvNinja gadget,标注 `S_effect`,跟 `S_dep` 比对 | 1 天 |
| **3.2**: 读 Goyal trace 文件,算 op 类型 KL + 时间桶 | 半天 |
| 整理成反例文档(3-6 个) | 半天 |

**总计 2 天**,产出可以直接进 paper §1 motivation。

---

## 4. 看什么证据

### 问题 1 立住的证据

| 证据 | 阈值 |
|---|---|
| ProvNinja/Goyal 的 top-10 含 ≥1 个 `B_unsafe(A)` 操作 | ≥ 3/4 场景 |
| **存在场景使 `success(A ⊕ B_M) = false` 必然发生** | ≥ 1 个场景下 30 次 reps **全部失败**(确定性失败) |
| 在其他场景上 `Pr[success(A ⊕ B_M)] ≤ 0.5` | ≥ 2/4 场景,`p < 0.01`(配对 bootstrap) |
| 至少 1 个具体反例链:打分高 × 撞 `S_dep` × 实测攻击在哪一步终止 | 1 个就够 |

### 问题 2 立住的证据(任一条成立即可)

| 证据 | 阈值 |
|---|---|
| **(a) 规则层**:`Pr[告警 \| A⊕B_M] − Pr[告警 \| A] ≥ 0.30` | ≥ 2/4 场景,Wilcoxon `p < 0.01` |
| **(b) ML 层**:`Anom_D(A ⊕ B_M) > Anom_D(A)` 显著 | 至少 1 个 `D`,Cliff's δ ≥ 0.33,`p < 0.01` |
| **(c) 机制溯源**:能定位到 `B_M` 里具体哪类操作贡献了偏差 | 跟 (a) 或 (b) 配套,做消融 |

### 不立住意味着什么(关键 —— 决定下一步走向)

| 结果 | 含义 | 行动 |
|---|---|---|
| 问题 1 立、问题 2 立 | 双重打击,SafeMimic 故事完整 | → 进解法实验 |
| 只有问题 1 立 | 现有方法只是"会坏",不是"会暴露" | → SafeMimic 砍掉分布匹配,聚焦 safety |
| 只有问题 2 立 | 现有方法在受控环境其实不坏 | → 重新审视 `S_dep / S_effect` 形式定义 |
| 都不立 | 问题不存在,或现有公式化错了 | → 回到 §2 重新想问题 |

> **不论结果哪个方向,都比"7.5/10 自评"有价值** —— 因为它是真实的。
