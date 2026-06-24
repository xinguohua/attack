# FINDINGS

> **3 个 detector × 2 个原子扰动模式(P1 / P2)+ 实测数据**
>
> 数据来源:`experiments/E1_operators/proofs/{magic,orthrus,threatrace}.py` 真跑(JUICESHOP / `01_juiceshop_login_admin_sqli.json`)。
> Models:magic `5dfa19b2`,orthrus `87e0d7c2`,threatrace `d2d7c9ea`(`detection/data/pidsmaker_artifacts/training/training/`)。

---

## §0. 总览 — 2 个原子扰动覆盖 3 种 detector

**统一原则**:全部 variant 基于 BL(detector baseline 标的 anomaly 集合)扰动,用 `evade_rate = |{n∈BL : after_y(n)=0}| / |BL|` 衡量。

**2 个原子扰动**(代码实现在 `experiments/E1_operators/proofs/_common.py`):

| 原子 | 函数 | 操作 |
|---|---|---|
| **P1** shared-neighbor dilution | `shared_neighbor_dilution(target, n, ops, proc)` | 加 N 个新 process 节点,每个发 outgoing ops edges 到目标已有节点(BL 自己 / BL 邻居)|
| **P2** edge rerouting | `edge_rerouting(src, dst, midway, n)` | 删 BL 节点关联 edge + 加中转节点 + 加 **N 条**绕道 edge(在 3 种 op 模式间循环:src→mid CONNECT / mid→dst CONNECT / dst→mid RECVFROM)|

**实测 2 个原子 × 3 个 detector(全部基于 BL,统一 evade_rate)**:

| Detector | P1 shared-neighbor dilution | P2 edge rerouting |
|---|---|---|
| **magic** | **4/4 = 100% ★**(score 111.5→84.94)| **4/4 = 100% ★**(score 111.5→103.13)|
| **orthrus** | **8/9 = 88.9% ★**(score 不变,阈值动)| 0/9 = 0%(score 7.17→4.18 但仍在簇内)|
| **threatrace** | **4/6 = 66.7% ★**(file 4/4,netflow 0/2)| 0/6 = 0%(file cor 翻 0,反向暴露)|

**一键复现**:
```bash
for det in magic orthrus threatrace; do
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/$det.py
done
```

---

## §1. magic(图重建类)

### 1.1 baseline 状态

| 量 | 值 |
|---|---|
| total nodes | 49 |
| BL(detector 标的 anomaly)| **5 个**(全是 subject / curl)|
| 全图 unique scores | `subject=111.5` / `file=106.52` |

**退化现象**:JUICESHOP 图小+拓扑同构,GAT 聚合后所有 subject 节点 embedding 相同 → reconstruction error 完全一致 → **所有 subject 共享同一分**。看起来像类型分类器,而不是 instance-level anomaly detector。

### 1.2 ★ 起效:P1 shared-neighbor dilution(作用于 BL 邻居)

**实测**(`variant_p1_dilution(n_per_target=100, n_targets=5)`):

| 量 | baseline | after(+500 节点)|
|---|---|---|
| BL evade_rate(canonical)| — | **4/4 = 100% ★** |
| BL 5 个 score(2 个 head 同 canonical 合并)| 111.5 | **84.94**(暴跌出 threshold)|
| F2 δ 误进 | — | **0/500**(新加 cat 全 y=0!)|

**操作**:对 BL 5 个 curl 节点的邻居 file(数据库里已存在的 file 节点)各加 100 个 cat process,每个 cat 做 `EVENT_OPEN` 到目标 file。共加 500 个新 process。

注:BL 5 个 subject 实例里 2 个 `head -30` 进程 canonical 相同((subject, /usr/bin/head, "head -30")),按"逻辑行为"去重后 = 4 unique canonical。

**Finding F1(图传染)论证**:
> 1. 已有 file 节点突然多 100 个 incoming OPEN → file 节点邻居拓扑暴变
> 2. file 节点的 GAT embedding 重算
> 3. BL 5 个 curl 跟这些 file 互动 → curl 的 embedding 跟着变
> 4. reconstruction error 暴跌 111.5 → 84.94,跨过 threshold → y=1→0 ★
> 5. **副效果**:新加 500 个 cat 因邻居模式像"典型 file-interacting subject" → 0 个 y=1

### 1.3 P2 edge rerouting(socat 中转)

**实测**(`variant_p2_rerouting(n=3)`):

| 量 | baseline | after |
|---|---|---|
| BL score | 111.5 | **103.13** |
| BL evade_rate(canonical)| — | **4/4 = 100% ★** |

**操作**:删 `BL 代表节点 ↔ :3000` 原 edge + 加 socat 节点 + N=3 条绕道 edge。

**Finding F2 论证**:
> P2 把 BL 节点的关联 edge endpoint 从 :3000 改向 socat midway,GAT 聚合时邻居拓扑变 → BL embedding 重算,reconstruction error 从 111.5 降到 103.13,跨过 threshold → y=1→0 ★。
>
> 跟 P1 同样 4/4 evade,但跌幅小很多(P1 跌 26.6,P2 跌 8.4)— P2 只改 1 个 endpoint 影响有限,P1 加 500 个邻居影响图传染更彻底。

### 1.4 Root Cause #1:magic 对 BL 邻居拓扑变化敏感

> magic 学整图分布,**只对 BL 邻居拓扑变化敏感**。P1 和 P2 都成立,机制不同但殊途同归:
> - **P1**:加 N 个良性 process 跟 BL 邻居 file 关联 → file embedding 暴变 → BL curl 跟着变
> - **P2**:删 BL 关联 edge 换成 midway 中转 → BL 节点直接邻居拓扑变 → BL embedding 暴变
>
> **一句话**:让 BL 的 1-hop / 2-hop 邻居"看起来跟原来不同",magic 就把 BL 的 embedding 一起拖走。

### 1.5 数据来源

- `experiments/E1_operators/proofs/magic.py` → `proofs_results/magic.json`

---

## §2. orthrus(edge type 预测类)

### 2.1 baseline 状态

| 量 | 值 |
|---|---|
| BL(detector 标的 anomaly)| **10 个节点** |
| BL 代表节点 score | 7.172,y=1 |
| 阈值簇 | kmeans top-30 |

注:BL 10 个节点共享相似的邻居拓扑(都关联同一 `:3000` socket),被 orthrus kmeans 打成同一 anomaly 簇。下文 "BL 代表节点" 指 BL 里 max-loss 节点(实际 SQLi 场景下是 curl POST 节点)。

### 2.2 ★ 起效:P1 shared-neighbor dilution(作用于 BL 节点的邻居 socket)

**实测**(`variant_p1_dilution_nai(n=50)`):

| 量 | baseline | after(+50 节点)|
|---|---|---|
| BL 代表节点 score | 7.172 | **7.172(不变)** |
| BL 代表节点 y | 1 | **0 ★** |
| BL evade_rate(canonical)| — | **8/9 = 88.9% ★** |

**操作**:加 50 个良性 curl process,每个对 BL 代表节点的邻居 `:3000` socket 做 `EVENT_CONNECT + EVENT_SENDTO`。

**Finding F-orth-1 论证**:
> 50 个良性 curl 跟 BL 节点共享同一 socket,orthrus 给它们相同高分 → 占满 kmeans top-30 阈值簇 → 把 BL 节点挤出 anomaly 簇。BL 节点 score 不变,但分类阈值被推走,y=1→0。
>
> 关键参数:N ≥ 50(N<50 失败,kmeans top-K=30 还没被占满)。

### 2.3 P2 edge rerouting(NAT 中转,单独不够)

**实测**(`variant_p2_rerouting_socat`):

| 量 | baseline | after |
|---|---|---|
| BL 代表节点 score | 7.172 | **4.182(Δ=-2.99)** |
| BL 代表节点 y | 1 | 1(单独不够)|
| BL evade_rate(canonical)| — | 0/9 = 0% |

**操作**:删 `BL 代表节点 ↔ :3000` 原 edge + 加 socat 节点 + 加 **N 条**绕道 edge(在 3 种 op 间循环:`BL→socat` CONNECT、`socat→:3000` CONNECT、`:3000→socat` RECVFROM)。实测 N=3 已够把 score 从 7.17 拉到 4.18。

**Finding F-orth-2 论证**:
> 把 BL 代表节点关联 edge 的 dst 从 :3000 socket 改向 socat 中转节点,max-loss 来源被改 → score 大降。
>
> 单独不够 evade:kmeans 阈值仍在 top-30 簇内,4.182 还在 anomaly 区,要叠加 P1 才能跨阈值。

### 2.4 Root Cause #2:orthrus kmeans top-K 簇可被双向打破

> orthrus 判定靠 `per-edge MLP → per-node max edge loss → kmeans top-30 簇`。kmeans top-K 不是死阈值,是相对排序 — 可以从**两个方向**打破:
> - **P1 dilution(把别人推上去)**:加 N 个同类高分节点占满 top-30,本不在 top-30 的 BL 节点被挤进 benign 区(score 不变,阈值动)
> - **P2 rerouting(把自己拉下来)**:把 BL 节点 max-loss 来源 edge 改向,BL 节点自己 score 暴跌(单独不够 evade,因 4.18 仍在 anomaly 簇)

### 2.5 数据来源

- `experiments/E1_operators/proofs/orthrus.py` → `proofs_results/orthrus.json`

---

## §3. threatrace(node type 预测类)

### 3.1 ★ 起效:P1 shared-neighbor dilution(作用于每个 BL 节点本身)

**实测**(`variant_p1_dilution_universal(n=100)`,对所有 6 个 BL 节点同时扰动):

| BL 节点 | type | 操作 | baseline | after |
|---|---|---|---|---|
| node 16 | file | +100 incoming OPEN | score=0.002 cor=0 y=1 | **score=9.927 cor=1 y=0** ★ |
| node 8 | file | +100 incoming OPEN | score=0.684 cor=1 y=1 | **score=9.907 cor=1 y=0** ★ |
| node 10 | file | +100 incoming OPEN | score=1.204 cor=1 y=1 | **score=9.978 cor=1 y=0** ★ |
| node 12 | file | +100 incoming OPEN | score=1.204 cor=1 y=1 | **score=9.978 cor=1 y=0** ★ |
| node 0 | netflow | +100 incoming CONNECT/SENDTO/RECVFROM | score=3.573 cor=0 y=1 | score=1.099 cor=0 y=1 ✗ |
| node 1 | netflow | +100 incoming CONNECT/SENDTO/RECVFROM | score=4.808 cor=0 y=1 | score=1.124 cor=0 y=1 ✗ |

→ **BL evade_rate = 4/6 = 66.7% ★**(file 4/4 ✓,netflow 0/2 ✗)

**操作**:对每个 BL 节点加 100 个 cat process,每个 cat 对 BL 发 type-typical op edge(file→OPEN;netflow→CONNECT/SENDTO/RECVFROM)。

**Finding F-tt-1 论证**:
> 对 file 类 BL 节点 +incoming OPEN(file pattern dominant op)→ distribution 匹配训练 file pattern → score 暴升(0.x → 10.x)+ cor 翻 1 → y=1→0 ★ 通杀。
>
> 对 netflow 类 BL +socket op 失败:JUICESHOP 训练集 netflow 样本远少于 file/subject(class imbalance,`balanced_loss: False`),model 死认 file label,加 netflow-typical op 反而把 score 推向"应被分类为 file"的方向。

### 3.2 P2 edge rerouting(单独失败)

**实测**(`variant_p2_rerouting(n=3)`):

| 量 | baseline | after |
|---|---|---|
| BL evade_rate | — | 0/6 = 0% ✗ |

**操作**:对每个 BL 节点找一个入边(process → BL),删原 edge + 加 socat midway 中转。

**Finding F-tt-2 论证**:
> P2 改 BL 节点的入边 endpoint,但用 socat 走 CONNECT/RECVFROM 模式。对 file BL 来说,把原 OPEN edge 换成 CONNECT pattern → file 节点的 edges_distribution 突然多了 socket-typical op → model 把 file 误判为 netflow type → **cor 从 1 翻 0,触发 anomaly,y 维持 1**。
>
> 跟 P1 反向:P1 用 file-typical OPEN 让 file 看起来更像 file ✓;P2 用 socket-typical pattern 让 file 看起来不像 file ✗。结论:对 prediction 类 detector,P2 用 socket-typical 中转 reroute 对非 socket 类 BL 节点是**反向破坏**。

### 3.3 Root Cause #3:threatrace edges_distribution 决定一切

```
threatrace 用 per-node GraphSAGE 学 edges_distribution → node_type
判定:y=1 ⟺ (score<1.5) OR (correct_pred≠1)
```

> 要操纵 y,本质就是操纵节点的 `edges_distribution`。
>
> - **起效方向**:加目标节点 declared_type 的 dominant op(file → +OPEN;subject → +outgoing OPEN+READ)→ score 暴升 + cor 对 → y=0
> - **危险方向**:加目标节点 declared_type 不该有的 op(subject → +socket op)→ distribution 飘 → score 暴跌 → 反向暴露

### 3.4 数据来源

- `experiments/E1_operators/proofs/threatrace.py` → `proofs_results/threatrace.json`

---

## §4. 实验代码与数据

```
experiments/
├── README.md                  3 个 detector → FINDINGS § 对应表 + 一键跑法
├── proofs/                    ★ 3 个 detector × P1/P2 原子扰动验证
│   ├── _common.py             共享:load_baseline / predict_all_nodes / compute_evade_rate
│   │                                 ★ shared_neighbor_dilution(P1)
│   │                                 ★ edge_rerouting(P2)
│   ├── magic.py               §1 magic       variant_p1_dilution + variant_p2_rerouting
│   ├── orthrus.py             §2 orthrus     variant_p1_dilution_nai + variant_p2_rerouting
│   └── threatrace.py          §3 threatrace  variant_p1_dilution_universal + variant_p2_rerouting
└── proofs_results/            *.json 输出
    ├── magic.json
    ├── orthrus.json
    └── threatrace.json
```

### 一句话总结整套扰动

> **3 个 detector × 2 个原子扰动(P1 共邻 dilution / P2 边改路由)= 6 个实测格子。**
>
> | | P1 | P2 |
> |---|---|---|
> | magic | 100% ★(4/4)| 100% ★(4/4)|
> | orthrus | 88.9% ★(8/9)| 0%(0/9)|
> | threatrace | 67% ★(4/6)| 0%(0/6)|
>
> P1 在 3 个 detector 上 100% / 88.9% / 67% **全部起效 ★**;P2 只在 magic 起效,在 orthrus 和 threatrace 单独失败。
>
> 注:evade_rate 用 canonical id 算(`("file",path) / ("netflow",addr) / ("subject",path,cmd)`),跨 run 节点身份稳定。同 path+cmd 的多 process 实例去重为 1 个 unique canonical。
>
> **共通规律**:扰动起点 = detector baseline 检出的 BL 集合。加节点 / 改边到 BL 自己或 BL 邻居,改变 BL 节点的 GAT 邻居分布 → BL 跌出阈值 → evade。
