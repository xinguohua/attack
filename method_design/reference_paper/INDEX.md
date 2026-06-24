# Reference Papers 索引

11 篇 PDF，分三组：

| 组 | 数量 | 角色 | 在 SafeMimic 论文中出现的位置 |
|----|------|------|------------------------------|
| **A · Baselines** | 3 | 与 SafeMimic 在同 axis 上对比的攻击方法 | §6 Related Work + §5 Experiments 对照组 |
| **B · Methodology references** | 6 | Android / PE 域的方法学启发，不直接对比 | §6 Related Work（一句话提及） |
| **C · Testbeds / Environment sources** | 2 | 提供 attack scenarios + 命令链 + 可部署 vulnerable target | §3.7 Infrastructure + §5 Experiments 数据源；不在 §6 Related Work |

---

## A 组 · Baselines（3 篇，与 SafeMimic 对比）

| 文件 | 论文 | 会议 | 本地代码 | 角色 |
|------|------|------|---------|------|
| `ProvNinja_USENIX23.pdf` | Mukherjee et al., "Evading Provenance-Based ML Detectors with Adversarial System Actions" | USENIX Security '23 | `baselines/provninja/` | **主对比**——FINDINGS 已实测其联合可用率 ≤ 3% |
| `Goyal_NDSS23.pdf` | Goyal, Han, Wang, Bates, "Sometimes, You Aren't What You Do" | NDSS '23 | `baselines/goyal/` | **次对比**——同期 mimicry 工作 |
| `Contorter_SP26.pdf` | Nasr, Rastogi, Tabiban, "A Context is Worth a Thousand Lies" | IEEE S&P '26 | `baselines/contorter/` | **最新对手**——白盒 + 黑盒双 setting |

---

## B 组 · Methodology References（6 篇，方法学启发）

来自 `../ORIGINAL_MAIN_THREAD.pdf` 整理的安卓 / PE 对抗样本工作。**不是评估对比项**，是技术 inspiration。

### P1（攻击有效性 / 功能保持）维度

| 文件 | 论文 | 会议 | 在 ORIGINAL_MAIN_THREAD 中的角色 | 对应 SafeMimic 设计块 |
|------|------|------|---------------------------------|--------------------|
| `BagAmmo_USENIX23.pdf` | Black-box Adversarial Example Attack towards FCG Based Android Malware Detection | USENIX Sec '23 | "图效果大、系统效果小" | Block ② + Block ③ |
| `EvadeDroid_CnS24.pdf` | EvadeDroid: Practical Evasion Attack on Black-box Android Malware Detection | Computers & Security '24 | "作用域隔离" + "精准选择" | Block ② + Block ④ |
| `HRAT_CCS21.pdf` | Structural Attack against Graph-based Android Malware Detection | CCS '21 | "操作效果可预测" | Block ② δ(c) Hoare triple |
| `MalGuise_USENIX24.pdf` | A Wolf in Sheep's Clothing (Windows malware) | USENIX Sec '24 | "安全空间前置 + MCTS 预测" | Block ② SafeCandidate + Block ④ |

### P2（隐蔽性）维度

| 文件 | 论文 | 会议 | 在 ORIGINAL_MAIN_THREAD 中的角色 | 对应 SafeMimic 设计块 |
|------|------|------|---------------------------------|--------------------|
| `AdvDroidZero_CCS23.pdf` | Efficient Query-Based Attack against ML-Based Android Malware Detection | CCS '23 | "经验指导减少盲目尝试" | Block ④ active query |
| `HagDe_USENIX25.pdf` | Fighting Fire with Fire: Continuous Attack for Adversarial Android Malware Detection | USENIX Sec '25 | "避免决策边界不稳定区域"（防御侧反向用） | Block ③ J_dist 避开决策边界 |

---

## C 组 · Testbeds / Environment Sources（2 篇）

提供 SafeMimic 实验所需的 attack scenarios、命令链、可部署 vulnerable target。
**实际的 testbed 资产（docker / scripts / VM）等做实验时再 clone 到 `testbeds/` 目录**，论文只是查阅用。

| 文件 | 论文 | 会议 | 提供给 SafeMimic 的资产 | 用法 |
|------|------|------|---------------------|------|
| `Cybench_ICLR25.pdf` | Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models — Zhang et al. (Stanford / Boneh / Liang) | ICLR '25 | 40 个 CTF 任务（pwn / web / forensics / crypto）+ docker-compose 启动脚本 + 已知解法 + 子任务分解 | (a) Block ① S_dep 标注**几乎免费**——CTF 已分子任务；(b) §5 多样化攻击场景库；(c) sandbox 直接拉起 |
| `PentestGPT_USENIX24.pdf` | PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing — Deng et al. | USENIX Security '24 | HackTheBox + VulnHub 25 台 testbed VM + 182 个 sub-task + 标准化命令链（recon → exploit → privesc → lateral） | (a) Block ③ Π_B 攻击者侧补集；(b) Block ① S_dep DSL 校准；(c) §5 multi-stage 端到端评估 |

**OWASP Juice Shop**（无 canonical 论文，未收 PDF）：作为 Web-attack vulnerable target 直接 clone repo（`https://github.com/juice-shop/juice-shop`），实验时再处理。

---

## 五个参考点 → SafeMimic 设计映射（B 组细化）

来自 ORIGINAL_MAIN_THREAD §"总结"：

### P1 维度
| 参考点 | 主要论文 | SafeMimic 中对应 |
|--------|---------|------------------|
| 选什么操作 | BagAmmo（低副作用 + 相似度） | Block ② Cands(g_j) + Block ③ J_dist |
| 在哪执行 | EvadeDroid（隔离） | Block ② ψ(σ) 的 namespace/cgroup 子集 |
| 能不能预测 | HRAT（确定性映射） | Block ② δ(c) Hoare triple |
| 怎么组织 | MalGuise（安全空间前置） | Block ② SafeCandidate 解耦"安全"与"搜索" |

### P2 维度
| 参考点 | 主要论文 | SafeMimic 中对应 |
|--------|---------|------------------|
| 减少操作数 | AdvDroidZero (UCB) + MalGuise（小空间） + EvadeDroid（精准） | Block ④ surrogate 节省 query |
| 分布匹配 | BagAmmo（相似度引导） | Block ③ J_dist 核心思想 |
| 避免被检测 | HagDe（平滑偏移） | Block ③ 反向应用 |

---

## 与 SafeMimic 的核心差异

**A 组 baselines** 与 SafeMimic 同域（provenance HIDS evasion），主要差异：

| 维度 | ProvNinja | Goyal | Contorter | SafeMimic |
|------|-----------|-------|-----------|-----------|
| 优化层 | graph rewrite | graph rewrite | graph rewrite (context distortion) | command synthesis |
| 执行接地 | ✗ | ✗ | ✗ | **✓** (sandbox) |
| 攻击语义模型 | ✗ | ✗ | partial | **✓** (S_dep + v_j) |
| Detector 接口 | white-box | white-box | white-box + black-box | **black-box surrogate** |
| 隐蔽目标 | per-edge regularity | feature evasion | context similarity | **distribution matching** |

**B 组 Android 参考**与 SafeMimic 不同域：

| 维度 | Android / PE 参考 | SafeMimic |
|------|------------------|-----------|
| 目标域 | APK / PE 二进制 | Linux provenance graph 流式 trace |
| 修改对象 | 静态可执行文件 | 动态命令序列 + 沙箱真实执行 |
| 状态空间 | 单进程 CFG / FCG | 跨进程 OS-level state |
| 隐蔽目标 | 单一 ML 检测器 | 任意 detector ensemble + 分布层 detector-agnostic |

**C 组 testbeds** 与 SafeMimic 是 **producer-consumer** 关系——它们生产 attack scenarios，SafeMimic 消费这些 scenarios 做 evasion 评估。
