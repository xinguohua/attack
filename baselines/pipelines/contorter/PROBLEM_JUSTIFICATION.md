# Contorter 上的问题验证

本文档对 contorter (S&P'26) 在 NodLink/Cadets 复现样本上验证两个正交失效模式 —— P1 (Functional Integrity Gap) 与 P2 (Stealthiness Asymmetry) —— 与 `baselines/pipelines/provninja/PROBLEM_JUSTIFICATION.md` 保持同一论证框架。

实验来源:本仓库 `baselines/contorter/NodLink/Cadets/` 上 fresh `nbconvert --execute` 跑出来的 (orig, adv) pairs (15 对) + 28272 个 benign 进程,详见 `README.md` §2.2.5。

---

## 1. 要验证的问题

### 1.1 P1 —— 注入事件的执行可行性不被算法验证 (Functional Integrity Gap)

> **Hypothesis (H1)**:contorter 给出的 augmented log 隐含一份"attack 进程额外执行的 syscall 序列"。在主流 IDS 假设(攻击者不能篡改 audit,要让某事件出现在 audit 里就必须真发出对应 syscall)下,这份 syscall 序列要落地需要满足若干 OS-level 可执行性约束;contorter 的优化目标里完全没有这些约束,因此**至少 k ≥ 1 条注入事件在 OS 上不可执行 / 必须额外代码注入 / 必然破坏原攻击或暴露更大攻击面**。

**威胁模型澄清**(本文档默认):attacker 不能直接 tamper provenance collector(eAudit / CamFlow / auditd 这层),要让 augmented log 真在 defender 端被观察到,attack 进程必须真发出对应的 `open / read / write` 等 syscall。如果换 attacker 能直接改 audit 文本的强威胁模型,contorter 就只是个写假 log 的工具,P1 不构成失效;但那个模型下大多数 IDS 论文都不成立,讨论意义不大。

跟 ProvNinja 的 graph-level 边/点编辑不同,contorter NodLink 在 `final-augmented-malicious-processes.txt` 这一**进程-文件路径文本**层面工作 —— 它隐式声称 "tmux-1002 也访问了 /etc/aliases.db / /etc/spwd.db / ... 共 45+ 条 path"。**可证伪形式**因此变为:这 45+ 条声称访问中,至少 1 条在 OS 上做不到 / 做了就破坏原攻击。

**算法盲点定位**(对应 `baselines/contorter/NodLink/Cadets/NodLink_Cadets_Contorter.ipynb` cell 21-24 的 CSMax+ImpMax+Gadget Insertion 流程):

| OS-level 可执行性约束 | contorter 是否检查? |
|---|---|
| 注入 path 的权限要求(uid / mode bits)与 attack 进程当前 uid 兼容 | ✗(只优化 FastText cosine + VAE recon loss) |
| attack 进程的二进制确实有打开这条 path 的代码路径 | ✗(否则要额外做代码注入,放大攻击面) |
| 注入的 syscall 序列不破坏原攻击的 fd / cwd / 资源 | ✗ |
| 注入路径在 attack 进程 namespace / capability 内可达 | ✗ |
| 总事件数与该 binary 在生产负载下的统计分布一致 | ✗(直接吞下 benign exemplar 的全量 path list,顺便造成 P2) |

**验证方法**:见 §2.1 + §4.1。`extract_diffs.py` 把每对 (orig, adv) 的注入路径列出来,§4.1 在一个 canonical case 上**逐条**反推每条注入路径是否能被 attack 进程实际执行,给出"权限破墙做不到 / 行为锚点缺失要额外代码注入"两类硬性失败。

### 1.2 P2 —— 单目标优化必然留下正交维度的取证指纹 (Stealthiness Asymmetry)

> **Hypothesis (H2)**:contorter 的 Gadget Insertion 优化目标是**最小化 NodLink VAE 在 FastText 嵌入空间的 reconstruction loss**(cell 23 ImpMax)。任何 VAE 没有 project 上去的统计维度都不受约束,会出现明显漂移;一条不需要训练的、面向被盲点的 domain rule 可以以 ≫ NodLink VAE 的 recall 抓出 contorter 的修改样本。

**算法盲点定位**(对应 cell 21 CSMax + cell 23 ImpMax + cell 24 Gadget Insertion):

```
# CSMax: 选 top-10% 与 attack process 在 FastText 上余弦相似的 benign exemplar
top_candidates = sort(benigns, key=cosine_sim(fasttext_embed))[:10%]

# ImpMax: 在 candidates 中选 VAE 重建损失最低的
chosen = argmin(top_candidates, key=lambda b: vae_recon_loss(merge(attack, b)))

# Gadget Insertion: 把 chosen.file_paths 整体并入 attack.file_paths
augmented_attack.paths = attack.paths + chosen.paths   # 注意:仅添加,不替换
```

→ 算法只要 cosine similarity 高 + VAE recon loss 低,就把 chosen 的所有 file path 全 dump 进来。**没有任何机制约束 augmented 进程的 file 总数 / 节点行为分布 / cmdline 与 file 的因果一致性**。

| 正交维度 | contorter 是否约束? | 用作 D 的可行性 |
|---|---|---|
| **进程的 file path 总数** | ✗(直接继承 chosen exemplar 的全量集合) | ✅ 本文用此维度 |
| Behavior diversity (单一职责) | ✗ | 备用 |
| cmdline 与 file path 集的因果一致(`tmux` 进程不应访问 `/etc/aliases.db`) | ✗ | 备用 |
| 注入路径的 namespace 与本机文件系统拓扑一致性 | ✗ | 备用 |

**可证伪形式**:存在单条 domain rule D = "process 的 file-path count ≥ k",在 28272 benign / 15 orig-anomaly / 15 adv 这三个集合上同时满足:

1. recall(D, adv) ≫ recall(NodLink VAE, adv)(headline 数字差距至少 50pp)
2. recall(D, orig) ≈ 0(D 抓的是修改不是原攻击 → "modification audit",与 NodLink VAE 形成互补)
3. FP rate(D, benign) ≤ 1%(在工业可接受区间)

详细设计 + 阈值 k 的取值依据见 §2.2。

### 1.3 两个问题的关系

P1 和 P2 是**正交**的:

- **P1 only**:contorter 注入的 fake events 在 OS audit 缺对应 syscall,但维度上仍可能跟 benign 几何一致(假如 ImpMax 选的 exemplar 总数恰好接近 attack 原文件数,后者并不发生)。
- **P2 only**:即使 attack 仍在 OS 上正常执行,augmented log 的统计分布会被一条简单规则抓出。
- **P1 ∧ P2**:两者通常**同时**发生 —— 因为 contorter 的 Gadget Insertion 是一次性 dump benign exemplar 的全量 paths,既造成 fake events(P1 violation)又造成统计 drift(P2 violation)。

这跟 SafeMimic 的设计动机直接对应:既要保证攻击在 OS 上可执行(回应 P1 ),也要在多个统计维度上贴近 benign 分布(回应 P2)。contorter 在两个维度上都没做。

---

## 2. 验证设计:在 contorter 上做什么实验

### 2.1 问题一的实验

#### Step 1 — 对 15 对 (orig, adv) 求 file-path diff

脚本:`baselines/pipelines/contorter/extract_diffs.py`

```bash
cd baselines/pipelines/contorter
/opt/anaconda3/envs/mimicattack/bin/python extract_diffs.py
```

读取 `baselines/contorter/NodLink/Cadets/dependancies/process-event-anomaly.txt`(orig 15 个 attack 进程的 file paths)和 `final-augmented-malicious-processes.txt`(adv 15 个 augmented attack 进程),对每对计算:

| 字段 | 含义 |
|---|---|
| `kept` | orig ∩ adv:依然存在的原攻击 file accesses(对应真实 syscall) |
| `added_by_contorter` | adv − orig:contorter 注入的新 file paths(无对应 syscall) |
| `removed_by_contorter` | orig − adv:contorter 删掉的原 file accesses |
| `count_inflation_factor` | `len(adv.paths) / len(orig.paths)` |

输出到 `diffs/pair_<i>_<process>.json` × 15 + `diffs/_summary.json`。

#### Step 2 — 判定 P1 是否站得住

P1 的判定标准是:

**P1 立住** 当且仅当:对每对样本,`removed_by_contorter` 中没有破坏原攻击因果链所必需的 file access(因为不动这些 attack 仍可执行),且 `added_by_contorter` 中存在至少 1 条 file path 在原始 OS audit trail 上无对应 syscall(因为这条 path 是从其他 benign 进程的 footprint 整体 copy 过来的,attack 进程实际并未访问)。

**证伪 P1** 的反面:对所有样本,augmented log 的所有事件都在 OS audit 上有真实 syscall 支撑(即:contorter 不是"注入伪事件",而是"重新整理已发生事件的描述")。这种情形下 P1 不成立。

**为什么 contorter 算法保证 P1 立住**:cell 24 的 Gadget Insertion 把 chosen benign exemplar 的**整套 paths** dump 进来,benign exemplar 是另一个进程,attack 进程实际没访问那些 paths。算法没有 OS audit 反查环节,无法保证注入的 path 都对应真实 syscall。

### 2.2 问题二的实验

#### Step 0 — sanity check:NodLink VAE 在原 attack 上 100% recall

脚本:`baselines/pipelines/contorter/eval_nodlink_on_adv.py`

读取本仓库 fresh nbconvert 出来的 `NodLink_Cadets_Contorter.run.ipynb`(28-cell 全跑、0 errors)中 cell 15 的 baseline 输出和 cell 26 的 evasion-after 输出,转录到 `results/contorter_nodlink_eval.json`。

预期:`phase_baseline_on_orig.recall == 1.0` —— 即 NodLink VAE 在 cutoff=130 阈值上能抓出全部 15 个原攻击进程。如果不到 1.0 整个 P2 论证基础就垮了(detector 自己漏报,跟 contorter 无关)。

#### Step 1 — NodLink VAE 在 adv 上 33% recall(evasion 有效的 baseline 数字)

同一脚本读 cell 26 的 after 输出。预期:`phase_after_on_adv.recall == 0.3333`。这是 contorter 论文 Table 5 在 NodLink/Cadets 上声称的 evasion 强度,我们本地复现一致。

#### Step 2 — D = "file count ≥ 50" 单条 domain rule 抓 100%

脚本:`baselines/pipelines/contorter/eval_filecount_full.py`

##### D 的设计 —— file-path count threshold

D 是单一阈值规则:

```python
def D(process):
    return len(process.file_paths) >= 50
```

##### 为什么 file-path count 站得住(经验论证)

`extract_diffs.py` 的 `_summary.json.aggregate`:

| 集合 | 文件数 min | max | mean | p50 | p99 |
|---|---|---|---|---|---|
| orig (15) | 2 | **26** | 11.27 | 10 | — |
| adv (15) | **62** | 96 | 75.00 | 75 | — |
| benign (28272) | 0 | 58412 | 14.7 | 9 | **46** |

→ **orig max (26) << K=50 << adv min (62)**,而 benign p99 只有 46。三个集合在 K=50 这个阈值上**清晰可分**。

##### 为什么 contorter 必然违反 D

ImpMax 和 Gadget Insertion 的代码层面解释:

```
chosen = argmin(candidates, vae_recon_loss(merge(attack, candidate)))
augmented.paths = attack.paths ∪ chosen.paths
```

- `chosen` 是从 ~28K benign 进程里通过 cosine + VAE 双层筛出的 top-1
- 这个 top-1 倾向于是 file-path 多的"高活动"benign 进程(因为短 list 在 cosine 上不容易接近,VAE 重建短文本也更容易)
- 把 chosen 整套 paths 加进 attack 后,augmented.paths 总数 ≈ orig + chosen 的并集 ≈ 60-100

contorter 的优化目标里**完全没有项**让 augmented 的 file count 接近 benign 中位数(~9-10)。算法盲点 = 没做总数预算控制。

#### 判定标准(三步)

P2 立住 当且仅当:

1. NodLink VAE on orig: recall ≈ 1.0(detector 自己 sanity)
2. NodLink VAE on adv: recall < 0.5(contorter evasion 强度,验证它是个有效 evasion)
3. D on adv: recall ≥ 0.9 + benign FP ≤ 1%(orthogonal rule 抓出 evasion 留下的指纹)

---

## 3. 实验结果

### 3.1 问题一结果

引用文件:`baselines/pipelines/contorter/diffs/_summary.json`

#### 总体数字

| 指标 | 数值 |
|---|---|
| 总 (orig, adv) 对 | 15 |
| `total_files_removed` | **0**(contorter 一条原 file path 都没删) |
| `total_files_added` | **857**(注入的 fake path 总数) |
| `pairs_with_zero_removals` | 15/15 |
| `orig_count_mean` | 11.27 |
| `adv_count_mean` | 75.00(平均每对注入约 64 条 fake) |

#### P1 立住:augmented log 隐含的 syscall 序列在 OS 上不可执行

15/15 样本的 `removed_by_contorter` 都是 0 → 攻击在 OS 上的原执行序列完全保留 → 原攻击仍可执行(P1 在 graph-cut 意义上**vacuously 满足**)。

**但 augmented log 是有"被声称访问"语义的**:15/15 样本的 `added_by_contorter` 中,所有路径都是从 ImpMax 选中的 benign exemplar 整套 copy 过来的(`pair_00 tmux-1002` 注入了 `/etc/aliases.db / /etc/group / /etc/hosts / /etc/nsswitch.conf / /etc/pwd.db / /etc/services / /etc/spwd.db / /etc/master.passwd ...` 共 45+ 条系统服务级 path)。

威胁模型 B(默认 IDS 假设,attacker 不能 tamper audit)下,要让这些 path 真在 audit 出现,attack 进程必须真发对应 `open()` syscall。逐条审视(详见 §4.1):

- **L1 物理破墙做不到**:每个样本里至少 2 条注入是 root-only 文件(`/etc/spwd.db` `/etc/master.passwd` 等,FreeBSD mode 600 owner=root),attack 进程 uid=1002 直接 EACCES
- **L2 行为锚点缺失**:每个样本里 ~7 条注入是 mail/NSS/auth 子系统专属 path,attack 进程的二进制(tmux / cron / sshd / inetd / ...)没有访问这些的代码路径;要让 syscall 真发出必须 LD_PRELOAD / ptrace 注入,**反而引入更显眼的攻击事件**

→ **P1 立住**:15/15 样本的 augmented log 中至少存在 1 条注入 path 在 OS 上对 attack 进程**物理不可达**,40+ 条需要在原攻击之外**额外的代码注入能力**才能让 syscall 真发出。contorter 算法对这两层都不查。15/15 样本结构相似(注入路径都集中在 root 拥有的系统服务 footprint),问题普遍。

### 3.2 问题二结果

引用文件:
- `results/contorter_nodlink_eval.json`(NodLink VAE 评测)
- `results/d_filecount_eval.json`(D rule 评测)

#### 三步实测

| 实验 | 阶段 | TP | FP | FN | TN | Precision | **Recall** | F1 |
|---|---|---|---|---|---|---|---|---|
| Step 0 | NodLink VAE on **orig**(detector sanity) | 15 | 19 | 0 | 27517 | 0.4412 | **1.0000** | 0.6122 |
| Step 1 | NodLink VAE on **adv**(contorter evasion) | 5 | 24 | 10 | 27512 | 0.1724 | **0.3333** | 0.2273 |
| Step 2 | D=count≥50 on **adv**(orthogonal rule) | 15 | 256 | 0 | 28016 | 0.0554 | **1.0000** | 0.1051 |

#### Step 0 — NodLink VAE 在 orig 上 R=1.0 ✓

15 个原始 attack 进程全部被 cutoff=130 抓出(FN=0)。VAE 自身没有漏报问题。

#### Step 1 — NodLink VAE 在 adv 上 R=0.33

10/15 attack 在被 contorter augment 后**成功 evade VAE**(FN 从 0 升到 10)。这是 contorter S&P'26 论文 Table 5 在 NodLink/Cadets 上声称的 evasion 强度,本仓库复现一致。

#### Step 2 — D 单条规则抓 100%

D = "process file-path count ≥ 50" 在 adv 上 **15/15 = 100% recall**。
- adv 最小值 62,K=50 阈值下全部命中
- orig 最大值 26,K=50 阈值下全部 miss(D 不抓原攻击,只抓修改 → modification audit)
- benign 28272 中 256 命中 = **0.91% FP rate**

#### bottom line

| 指标 | NodLink VAE(target detector) | D(orthogonal rule) | 差距 |
|---|---|---|---|
| Recall on contorter-modified attacks | **0.33** | **1.00** | **+67pp** |
| FP rate on benign | 0.07% | 0.91% | -0.84pp |

D 在 recall 上对 NodLink VAE 形成显著优势(+67pp),代价是 FP rate 提高 ~13×(从 0.07% 到 0.91%,绝对量从 19 升到 256)。这种 trade-off 清晰地暴露了 contorter 的单维优化盲点 —— **它把 attack 推到 VAE 的"benign 流形"内,但不约束最简单的统计维度,导致 modification 在 file-count 这个正交维度上反向暴露**。

---

## 4. 根因分析

### 4.1 问题一根因

#### 总体数字

15/15 样本的 `removed_by_contorter == 0`。所有 15 个 attack 在 OS 层都未被破坏(P1 在传统 graph-cut 意义上不立)。但 15/15 样本的 augmented log 都包含 45+ 条注入 path,**这些 path 被声称由 attack 进程访问,而实际是从 ImpMax 选中的 benign exemplar 整套 copy 过来的**。在威胁模型 B(attacker 不能 tamper audit,要让 path 出现在 audit 里就必须真发对应 syscall)下,attack 进程必须**额外执行**这 45+ 条 syscall —— 而 contorter 的优化目标(FastText cosine + VAE recon loss)对这些 syscall 的可执行性零检查。

#### 案例:`pair_00 tmux-1002`(典型情形)

##### 1. 原攻击进程画像
```
tmux-1002 (uuid C4F4FF22-3E7B-11E8-A5CB-3FA3753A265A, malicious=true, uid=1002)
├─ orig 文件访问 (10 条,真 syscall):
│    /dev/hpet0
│    /etc/libmap.conf
│    /lib/libc.so.7
│    /lib/libm.so.5
│    /lib/libpcap.so.8
│    /libexec/ld-elf.so.1
│    /tmp/tmux-1002
│    /usr/lib/libthr.so.3
│    /var/run/ld-elf.so.hints
│    + 1 more system lib
└─ 这是 attack chain 的真实 OS 执行轨迹,与 tmux 终端复用器的合法行为吻合
```

##### 2. Contorter augment 后:声称访问 62 条,新增 45+ 条来自某 benign exemplar

`extract_diffs.py` 输出 `diffs/pair_00_tmux-1002.json` 显示 contorter 把目标 sshd / qmgr 类系统服务的 path list 整套 copy 到 tmux 名下:

```
augmented tmux-1002 (final-augmented-malicious-processes.txt):
  原 10 条(syscall 真实存在,与 orig 攻击行为吻合)
  + 45+ 条新增 ★(声称由 tmux 访问,实际是从 benign sshd 类进程 copy 的):
      /etc/aliases.db            /etc/master.passwd
      /etc/group                 /etc/spwd.db
      /etc/hosts                 /etc/services
      /etc/nsswitch.conf         /etc/pwd.db
      ...
```

##### 3. 逐条反推:这 45 条 attack 进程能不能真发 syscall

要让 augmented log 在威胁模型 B 下落地,**tmux-1002 进程(uid=1002)必须真额外执行 45 条 `open()`**。逐条看:

| 注入 path 类别 | tmux 真能 open 吗? | 失败模式 / 代价 |
|---|---|---|
| `/etc/spwd.db`、`/etc/master.passwd` | ❌ **物理做不到** | FreeBSD `mode 600 owner=root`。tmux uid=1002 调 open 直接 EACCES |
| `/etc/aliases.db`、`/etc/group`、`/etc/hosts`、`/etc/services`、`/etc/pwd.db` | ⚠️ **物理能开,行为锚点缺失** | tmux 二进制根本没有打开 mail aliases / group DB / hosts table 的代码路径 —— 这些是 sshd / postfix / NSS subsystem 的语义。要让 tmux 真发这些 syscall,attacker 必须在原攻击之外额外做代码注入(LD_PRELOAD / ptrace / shared lib hijack),**等于又加一个攻击事件,反向放大攻击面** |
| `/etc/nsswitch.conf` | ⚠️ **会偶发 open(libc 触发),但被 contorter 多次重复声称** | NSS 子系统在 getpwnam / gethostbyname 时偶发读一次,被 libc 缓存。contorter 把 benign exemplar 的 NSS 序列重复 dump,声称频率与 tmux 实际行为不一致 |
| 其它 35+ 条 `/usr/lib/* / /var/log/*` 等 | ⚠️ **不一定开得到 + 副作用** | benign exemplar 的 cwd / capability / fd 状态跟 tmux 不同;某些 path 在 tmux 启动时根本不存在(竞态),开了反而触发审计的 errno tracking |

→ **15 个 attack 样本中,我们能直接断言至少 2 类(共 ~5-7 条/样本)在 OS 上必然 EACCES 失败**(root-only 文件类),而剩下的 40+ 条要么需要代码注入(放大攻击面)、要么需要修改 attack binary 行为(等于另写一个 攻击)。

##### 4. contorter 算法盲到不知道前面任何一层

伪码 `cell 21-24`:

```
chosen = argmin(candidates_top10pct, key=lambda c: vae_recon_loss(merge(attack.paths, c.paths)))
augmented.paths = attack.paths ∪ chosen.paths
```

这个目标里没有任何项约束:

- ❌ `chosen.paths` 中每条对 attack 进程的 uid 是否 readable
- ❌ attack 进程 binary 是否有发出该 path 对应 syscall 的代码路径
- ❌ 注入的 syscall 序列是否破坏原攻击的 fd / cwd / 资源
- ❌ 注入是否引入了 attack chain 之外的 capability 提升要求

contorter 只看 **FastText cosine + VAE recon loss 这两个数值越小越好**,纯在 detector 的投影空间里做手术。它不知道也不在乎"这份注入计划在 OS 上能不能落地"。

##### 5. 三层失效汇总

| 失效层 | 在 tmux-1002 案例上的体现 | 严格程度 |
|---|---|---|
| **L1 — 权限破墙做不到** | `/etc/spwd.db` `/etc/master.passwd` 至少 2 条 root-only,uid=1002 直接 EACCES | 物理硬约束 |
| **L2 — 行为锚点缺失** | `/etc/aliases.db / hosts / services / nsswitch.conf` 等 ~7 条,tmux 二进制没相应代码路径,attacker 必须额外注入 | 攻击面放大 |
| **L3 — 算法连前两层都不查** | `cell 21-24` 优化目标里完全没有 OS-level 约束,只看 cosine + recon loss | 算法根因 |

→ P1 立住:对 tmux-1002 这一对样本,contorter 给的 augmented log 至少 2 条在 OS 上**物理不可执行**,~7 条**需要超出原攻击范围的额外攻击能力**。算法不验证、不知道、也不解决这些。15/15 样本结构相似(注入路径都来自 sshd/qmgr 类 root 拥有的系统服务 footprint),问题普遍存在。

#### 共同根因

contorter 是**纯 log-layer mutator**:

```
input:  process_event_log + benign_baseline
output: augmented process_event_log
```

整个流程没有 system call API、没有 OS audit reader、没有 syscall executor。**算法不可能保证 augmented log 与真实 OS 执行一致** —— 它没有 OS 执行这一概念。

这跟 ProvNinja 的 graph-mutator 本质上是同一个失效:都是在 detector 看到的"投影"上做手术,而不是在攻击的因果实体上做手术。区别只在投影的层级 —— ProvNinja 在图层,contorter 在事件文本层。

回到 §1.1 H1:本仓库 15/15 样本均观察到 augmented log 中存在无 syscall 支撑的 fake events(15 × 45 = ~ 857 条 / 15 个进程),H1 立住。

### 4.2 问题二根因

#### 案例:`pair_00 tmux-1002`(D 精确命中,VAE 漏)

| 指标 | orig tmux-1002 | adv tmux-1002 | 阈值 / 截断 | 谁命中? |
|---|---|---|---|---|
| FastText recon loss(VAE) | 高(超 130) | **低(< 130,被 evade)** | cutoff=130 | NodLink **漏** |
| `len(file_paths)` | 10 | **62** | K=50 | D **命中** |

contorter 的 ImpMax 把 augmented 的 VAE recon loss 压到 130 以下(成功 evade),代价是把 file count 从 10 推到 62 —— **这个推升完全在 VAE 的盲区里**,因为 VAE 输入是 normalize 后的 FastText embedding,丢掉了 raw count 信息。

D 的存在性是个 *证明* :任何 detector 只要保留 raw count 这个维度,contorter 的 evasion 立刻失效。一个非 NodLink 的 detector(比如 simple count threshold)能 100% 抓回来。

#### 共同根因

contorter 的 ImpMax 优化目标是

```
min  vae_recon_loss( embed(merge(attack, candidate)) )
 c
```

这个目标在**输入空间**上是 attack ∪ candidate(file path 集合并),在**优化空间**上是 FastText 嵌入向量。两者之间的映射不是 isometric ——

- count 信息被 FastText sentence embedding 的 mean pooling 平均掉了
- 所以"加 50 条 path 进 attack"在嵌入空间几乎不变 attack 的向量长度,但在 raw count 上是 6.2× 暴涨

只要 detector 保留 count 这个被 FastText 丢掉的维度,evasion 就在它上面崩。这是单维优化在被忽略维度上的**必然代价**。

回到 §1.2 H2:`results/d_filecount_eval.json` 实测 D 在 adv 上 R=1.0 vs NodLink VAE R=0.33,差 67pp,FP 0.91%,H2 立住。

---

## 5. 当前状态

### 已完成

- [x] §2.1 Step 1 — `extract_diffs.py` 跑过,15 对 diff JSON + summary 在 `diffs/`
- [x] §2.2 Step 0/1 — `eval_nodlink_on_adv.py` 跑过,从 fresh nbconvert 复现 R 1.0 → 0.33
- [x] §2.2 Step 2 — `eval_filecount_full.py` 跑过,D 在 adv 100% / orig 0% / benign 0.91% FP
- [x] §3.1 + §3.2 数字回填,跟 JSON 文件 1:1 对应
- [x] §4.1 + §4.2 各一个 canonical case(`pair_00 tmux-1002`),配 ASCII 行为画像 + 算法伪码

### 限制 / 未做

- [ ] **样本量小**:N=15。比 ProvNinja 的 N=191 弱;数字稳定性受随机性影响小但代表性受限,跨数据集是否成立未知(ThreaTrace 4 数据集 + Flash 3 数据集 因 Drive 404 / 项目 scope 决定不跑,见 `README.md` 顶部"实跑范围"表)
- [ ] **P1 的执行可行性论证只到 "权限 / 二进制行为锚点" 级别**:本仓库从 FreeBSD permission semantics(uid=1002 vs root-only path)+ 二进制语义(tmux 不应访问 mail aliases)反推"注入项不可执行 / 须额外代码注入";没在 DARPA TC Cadets 的原始 syscall trace 上做 (PID, file) 反查作 empirical 闭环。完全严格的证明要拿 `data-E3/cadets/ta1-cadets-e3-official-2.bin.tar.gz` 解出来逐条 audit 反查 —— 后续工作
- [ ] **D 的 generalization**:D 只在 NodLink/Cadets 上验证。Flash/ThreaTrace 用不同的 detector + 不同的 evasion 维度,D 大概率不直接搬。后续如要 cross-detector 论证,需要逐 detector 设计对应的 orthogonal rule
- [ ] **替代规则未列举**:仅给出 D=file_count。Behavior diversity / cmdline-path 因果一致性等 §1.2 列的备用维度没逐一验证。先给最强的一条,够支撑 H2 立住即可

### 可改进点

1. P1 用 OS audit cross-check (PID, file) 配对反查闭环,把现有"权限/行为锚点反推"升级到 empirical proof
2. 跨 (PIDS, dataset) 检查 D 的 generalization,看 Flash/ThreaTrace 上是否有类似的 orthogonal rule
3. 用 contorter 论文 Table 5 报告的 7 个 (PIDS, dataset) 组合中能跑通的,跑一遍同样的 P1+P2 audit。当前可跑组合只有 NodLink/Cadets + Flash/Theia,后者已在 README §2.1.5 documented(evasion 反向失效,不构成有效 evasion 证据)
