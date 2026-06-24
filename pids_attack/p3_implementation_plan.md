# P3:SafeMimic-CMD v3 实施方案

> 承接 `p2_mcts_v3.md` §5 定稿设计:**GRABNEL BO 外层 + Inner GA 内层 + WL features + Sparse BLR with ARD surrogate + 双目标 Tchebycheff fitness(f_1 攻击效果 + f_2 endogenous R k-NN 良性度)+ LCB acquisition**。
>
> 本文档给出 3 个并行任务的实施方案 + 实验框架:
> - **Task 1:** `attack/grabnel_cmd/` v3 主算法实现
> - **Task 2:** 4 个新 detector(G1 / G2 / G1+G2 / G1+G2+GNN)
> - **Task 3:** 实验框架拆分为 `experiments/E2_ablation/` 和 `experiments/E3_attack/`

---

## 📊 进度跟踪(最近更新:2026-06-02)

| Step | 内容 | 状态 |
|---|---|---|
| **Step 1** | 写 p3_implementation_plan.md(本文件) | ✅ 完成 |
| **Step 2** | 删除 `attack/mcts_cmd/` + `tests/test_mcts*.py` + `scripts/run_mcts.py` | ✅ 完成 |
| **Step 3** | Task 1 GRABNEL 主算法实现 | ⬜ 待办 |
| 　　Step 3.1 | `attack/grabnel_cmd/{__init__,config}.py` + AtomicOp dataclass | ✅ |
| 　　Step 3.2 | `surrogate/wl_features.py`(扩展 cmd_graph/wl_hash.py) | ✅ |
| 　　Step 3.3 | `surrogate/sparse_blr.py` + unit test | ✅ |
| 　　Step 3.4 | `fitness/{reference,attack_term,stealth_term,scalarize}.py` | ✅ |
| 　　Step 3.5 | `acquisition/lcb.py` | ✅ |
| 　　Step 3.6 | `inner_ga.py` + unit test | ✅ |
| 　　Step 3.7 | `commit.py` + `algorithm.py` + unit test | ✅ |
| 　　Step 3.8 | `scripts/run.py attack` + `attack/grabnel_cmd/runner.py` + 端到端 smoke test | ✅ |
| **Step 3** | Task 1 GRABNEL 主算法实现 | ✅ 完成(8 子步全部 ✅,13 unit test pass) |
| **Step 4** | Task 2 — 4 类新 detector 实现 | ⬜ 待办 |
| 　　Step 4.1 | `detection/rules.py` | ✅ |
| 　　Step 4.2 | `scripts/run.py detect train-rules` + 跑训规则 | ✅ |
| 　　Step 4.3 | `detection/rules.py`(4 detector)+ unit test | ✅ |
| 　　Step 4.4 | `pidsmaker_wrapper.py` 加 dispatch 分支 | ✅ |
| **Step 4** | Task 2 — 4 类新 detector | ✅ 完成(规则训完,4 unit test pass,wrapper 接通)|
| **Step 5** | Task 3 — 实验框架 | ⬜ 待办 |
| 　　Step 5.1 | `experiments/E2_ablation/` + `experiments/E3_attack/` 目录 + `scripts/run_one.sh` | ✅ |
| 　　Step 5.2 | `scripts/run_grid.sh` + `aggregate.py` | ✅ |
| 　　Step 5.3 | 端到端 dry-run(E3.0 主表 1 cell 跑通) | ✅ |
| **Step 5** | Task 3 — 实验框架 | ✅ 完成(grid dry-run 700 cells ok,smoke 1 cell mock 跑通 + aggregate.py OK)|
| **Step 6** | 实际跑 700 cells 主表 + ablations | 🔄 跑中(2026-06-02 启动,见下方详细计划) |

**Legend:** ✅ 完成 / 🔄 进行中 / ⬜ 待办 / ❌ blocked / ⏸ 暂停

---

## 🚀 Step 6 跑实验计划(2026-06-02 启动)— **全部 2450 cells**

按部就班全跑,不分优先级。共 8 个 experiment / 39 个 variant × 10 scn × 5 seed:

| Experiment | Variants | wired 状态 | Cells |
|---|---|---|---|
| **E2.1** features | wl / gnn / random_walk / graph2vec / domain = 5 | ⚠️ 只 wl wired,其他=wl(stub) | **250** |
| **E2.2** surrogate | blr / gp_wl / gp_rbf / rf / ensemble = 5 | ⚠️ 只 blr wired,其他=blr(stub) | **250** |
| **E2.3** f2_metric | knn(k=3/5/10)/ dist_weighted / kde / gmm = 6 | ✅ 全 wired | **300** |
| **E2.4** scalarize | tcheby(β=1/5/20)/ weighted / lex = 5 | ✅ 全 wired | **250** |
| **E2.5** commit | single / batch_2 / beam_3 / lookahead_2 = 4 | ⚠️ 只 single wired,其他=single(stub) | **200** |
| **E2.6** acquisition | lcb(β=0.1/0.5/1/2)/ ei / thompson = 6 | ✅ 全 wired | **300** |
| **E2.7** ga_cmd | 4 flag 组合 | ⚠️ flag 存在但 GA 不消费(stub) | **200** |
| **E3.0** main attack | 2 algos × 7 detectors = 14 | ✅ 全 wired | **700** |
| **总计** | | | **2450** |

**跑配置(所有 cell 统一):** `B_max=20, T_GA=20, m=10, H=3, D_cap=200`

### 执行批次(顺序跑,不并发,避免 GPU 抢资源)

```
Stage A:E3.0 main attack (700 cells)
  A.1  rule detectors × grabnel    (150) ← 已启动 [27/300 ish per 2 algo]
  A.2  rule detectors × random     (150)
  A.3  GNN detectors × grabnel     (150)
  A.4  GNN detectors × random      (150)
  A.5  hybrid magic_g1g2 × 2 algos (100)
Stage B:E2.4 scalarize (250)
Stage C:E2.3 f2_metric (300)
Stage D:E2.6 acquisition (300)
Stage E:E2.1 features stub (250) — 全部 = default
Stage F:E2.2 surrogate stub (250) — 全部 = default
Stage G:E2.5 commit stub (200) — 全部 = default
Stage H:E2.7 ga_cmd stub (200) — 全部 = default
Stage I:聚合 + 出表
```

### 预计总耗时

- Stage A(700):~3 hours(rule 快,GNN 慢)
- Stage B-D(850):~2 hours
- Stage E-H stub(900):~1.5 hours
- Stage I:几分钟
- **总:~6-7 hours**(过夜应该够)

### ⚠️ 跑实验铁律(2026-06-02 启动起生效,跑的全程都要遵守)

1. **每个 stage 跑完必须立刻聚合 + 分析**
   - 跑 `aggregate.py --root experiments/E2_ablation --out snapshots/<stage>/summary.csv` 或 `aggregate.py --root experiments/E3_attack --out snapshots/<stage>/summary.csv`
   - stdout 摘要(SR / q★ / |Δ★| 按 detector / variant 分维度)落到 `snapshots/<stage>/summary.txt`
   - 关键发现(例如"g1 检测器太宽松导致 SR 100% 但失真")同步写到下方进度表"备注"列
2. **每个 stage 跑完必须立刻 snapshot 留存**
   - `snapshots/<stage>/summary.csv` 保留**全量** row(含之前所有 stage 累积)
   - 即使中途崩了也能从上一个 snapshot 完整恢复
3. **跑的过程不能停**
   - 用 `experiments/E2_ablation/scripts/orchestrator.sh` 或 `experiments/E3_attack/scripts/orchestrator.sh` 串行跑对应 stage
   - `run_cell` 幂等(文件已存在自动跳过),崩了重跑不丢已有 cell
   - 后台 nohup,日志在对应实验目录的 `logs/stage_<x>.log`
4. **绝不删 `results/*.json`** — 原始 JSON 含 config + history + 全字段,CSV 只是摘要
5. **跑的代码也要每阶段留存** — 每个 snapshot 含:
   - `summary.csv` 全量数据
   - `summary.txt` stdout 分析摘要
   - `code_snapshot.tgz` 当时 `attack/grabnel_cmd + detection + attack/oracle.py + cmd_graph + scripts/run.py + experiments/*/scripts + p3_implementation_plan.md` 源码 tar
   - `git.diff` + `git.head` (若是 repo) 记录当时 HEAD 跟 dirty diff
   - 这样每个 stage 结果都能完整复现:同一个 cmd × 同一份源码 × 同一份配置
6. **🔥 每个 stage 跑完必须更新 `pids_attack/p3_results.md`** — 这是 paper writing 的唯一数据源
   - 8 个 experiment × variant × cell 数填表
   - SR / q★ / |Δ★| / wall/cell 都要填(只有 n 不够,要算指标)
   - 关键发现写到对应 experiment 的"关键发现"小节
   - 进度日志加新行
   - 没及时填 = 没跑完(progress.md 是 orchestrator 自动写的运行日志,不替代 results.md 的人工分析)

### 实时进度日志

| 时间 | 阶段 | 状态 | 备注 |
|---|---|---|---|
| 2026-06-02 启动 | Stage A.1 grabnel × rule | 🔄 | 52/150,~10s/cell。**g1 100% conv q=1(太宽松,后期写 paper 要注明)**,g2 q=20 不收敛(待算 SR) |



## Context

### 现有 codebase 状态

参考 Explore agent 扫描结果(`/Users/xinguohua/mimicattack/pids_attack/`):

| 模块 | 状态 | 处理 |
|---|---|---|
| `cmd_graph/{graph,operators,builder,wl_hash,benign,translator}.py` | ✅ 完整 | 直接复用 |
| `cmd_graph/nettack.py` | ✅ 已有 R3 filter(attacker-side) | 🔁 移植到 detector-side 作 rule 检查 |
| `detection/pidsmaker.py` + `attack/oracle.py` | ✅ 3 base GNN(magic/orthrus/threatrace)接通 | 直接复用 + 加 dispatch |
| `range/{execute,checker,converter}.py` | ✅ docker + strace + CDM 全跑通 | 不动 |
| `attack/framework/{base,history}.py` | ✅ AttackAlgorithm ABC | 直接复用 |
| `detection/data/training_traces/benign_*` | ✅ 31 份 benign trace | 用作 R_unflagged warm-start + 训规则 |
| `shared/candidate_pool.txt` | ✅ 106 候选命令 | Inner GA Mutation 采样池 |
| `attack/mcts_cmd/` | ❌ 完整 MCTS 实现 | **删除**(用户拍板) |

### 关键决策

| 决策点 | 选择 |
|---|---|
| MCTS-CMD 去留 | **全部删除**(`attack/mcts_cmd/` 整个砍掉) |
| Hybrid rule 跟 GNN 合并方式 | **OR**(任一标红即标红,strict 模式) |
| 新 detector 数量 | **4 个** — G1 / G2 / G1+G2(纯规则,无 GNN)+ G1+G2+GNN(混合) |
| Hybrid 的 base GNN | **magic**(默认,最快;后续可加 orthrus/threatrace 变体) |

---

## Task 1: GRABNEL-CMD 主算法实现

### 1.1 文件结构(参考 GRABNEL repo bayesopt/ + src/ 划分)

```
pids_attack/attack/grabnel_cmd/
├── __init__.py              # exports GrabnelCMDAttack, GrabnelConfig
├── algorithm.py             # 主类 GrabnelCMDAttack(AttackAlgorithm),实现 v3 Algorithm 1
├── config.py                # GrabnelConfig dataclass(所有 hyperparam + ablation flag)
├── inner_ga.py              # Inner GA(BagAmmo §5.3 4 组件:Pop&Ind / Fit&Sel / Crossover / Mutation)
├── commit.py                # Sequential commit 策略(single 默认 / batch / beam / lookahead)
├── surrogate/
│   ├── __init__.py
│   ├── wl_features.py       # wl_feature_vector(G, H, D_cap) → Φ(G) ∈ ℝ^D
│   ├── sparse_blr.py        # closed-form Sparse BLR + ARD 后验(numpy/scipy,无 PyTorch)
│   ├── gp.py                # E2.2 备选 — GP+WL/RBF kernel
│   ├── rf.py                # E2.2 备选 — Random Forest + quantile
│   └── ensemble.py          # E2.2 备选 — bootstrap linear ensemble
├── features/                # E2.1 备选 feature scheme
│   ├── gnn.py               # frozen GCN/GAT embedding
│   ├── graph2vec.py
│   ├── random_walk_kernel.py
│   └── domain.py            # 手工 domain feature(度数分布 / syscall 计数)
├── fitness/
│   ├── __init__.py
│   ├── attack_term.py       # f_1 hinge sum(Eq 9)
│   ├── stealth_term.py      # f_2 — k-NN ratio(默认 Eq 10)+ E2.3 备选(dist-weighted/KDE/GMM)
│   ├── scalarize.py         # Tchebycheff(默认 Eq 11)+ E2.4 备选(weighted/lex)
│   └── reference.py         # Reference class(R_unflagged / R_flagged 状态)+ warm_start
└── acquisition/
    ├── __init__.py
    ├── lcb.py               # α = μ - β·σ(默认 Eq 12)
    ├── ei.py                # E2.6 备选
    └── thompson.py          # E2.6 备选
```

### 1.2 关键 class / 函数签名

```python
# config.py
@dataclass
class GrabnelConfig:
    B_max: int = 20            # query budget (§5 Eq 2)
    H: int = 3                 # WL iters (§5.2)
    D_cap: int = 200           # max WL feature dim
    beta: float = 5.0          # Tchebycheff (§5.3 Eq 11)
    beta_lcb: float = 0.5      # LCB (§5.4 Eq 12)
    k_nn: int = 5              # f_2 k-NN (§5.3 Eq 10)
    T_GA: int = 50             # GA 代数 (§5.4)
    m_pop: int = 20            # GA 种群 (§5.4)
    tau: float = 0.5           # detector 阈值 (§5.2 Eq 9)
    # ablation switches(对应 v3 §5 中 7 个 TODO)
    feature_method: str = "wl"        # E2.1: wl|gnn|random_walk|graph2vec|domain
    surrogate: str = "blr"            # E2.2: blr|gp_wl|gp_rbf|rf|ensemble
    f2_metric: str = "knn"            # E2.3: knn|dist_weighted|kde|gmm
    scalarize: str = "tcheby"         # E2.4: tcheby|weighted|lex
    commit_mode: str = "single"       # E2.5: single|batch_2|beam_3|lookahead_2
    acquisition: str = "lcb"          # E2.6: lcb|ei|thompson|lcb_anneal
    ga_mutation_weighted: bool = False # E2.7
    ga_constrained_mut: bool = False   # E2.7
    seed: int = 42

# surrogate/wl_features.py
def wl_feature_vector(G: CommandGraph, H: int = 3, D_cap: int = 200) -> np.ndarray:
    """H 轮 WL hash,每轮统计 label 计数,concat 成 D 维稀疏向量。
    复用 cmd_graph/wl_hash.py::_node_label 抽节点初始 label,
    hash 桶化到 D_cap 维(md5 % D_cap)。"""

def wl_feature_vector_batch(Gs: list, H: int = 3, D_cap: int = 200) -> np.ndarray

# surrogate/sparse_blr.py
class SparseBLR:
    """closed-form Sparse BLR with ARD prior(§5.2 Eq 6-8)。
    posterior update via rank-1 Sherman-Morrison,O(D²)。"""
    def __init__(self, D: int, k: float = 1e-4, theta: float = 1e-4, sigma_n2: float = 0.1)
    def update(self, phi: np.ndarray, s: float) -> None
    def posterior(self, phi: np.ndarray) -> tuple[float, float]
    def batch_posterior(self, Phi: np.ndarray) -> tuple[np.ndarray, np.ndarray]
    @property
    def lambdas(self) -> np.ndarray  # ARD λ_i,稀疏度诊断

# fitness/reference.py
@dataclass
class Reference:
    R_unflagged: list[CommandGraph]
    R_flagged: list[CommandGraph]
    phi_unflagged: np.ndarray   # cached WL features
    phi_flagged: np.ndarray
    def update(self, G: CommandGraph, flagged: bool) -> None
    @classmethod
    def warm_start_from_benign(cls, n: int = 30) -> "Reference":
        """从 detection/data/training_traces/benign_*.sql reconstruct CommandGraph
        填 R_unflagged。不消耗 query budget。"""

# fitness/attack_term.py
def f1_hinge(score_vec: list[float], tau: float = 0.5) -> float:
    """§5.3 Eq 9:f_1 = -Σ_v max(0, g(G)[v] - τ),归一到 [-1, 0]。"""

# fitness/stealth_term.py
def f2_knn_ratio(G: CommandGraph, R: Reference, k: int) -> float:
    """§5.3 Eq 10:f_2 = #k-NN_unflagged(G | R) / k,∈ [0, 1]。
    WL kernel 距离用 wl_feature_vector 算 cosine。"""

# fitness/scalarize.py
def tchebycheff(L1: float, L2: float, beta: float = 5.0) -> float:
    """§5.3 Eq 11:s = -(1/β) log(exp(-β·L_1) + exp(-β·L_2))。"""

# acquisition/lcb.py
def lcb(mu: float, sigma: float, beta_lcb: float = 0.5) -> float:
    """§5.4 Eq 12:α = μ - β_LCB·σ。"""

# inner_ga.py
@dataclass
class Individual:
    delta: list[AtomicOp]  # AtomicOp = ("add"|"rewrite"|"move"|"remove", params)
    G_cache: Optional[CommandGraph] = None
    phi: Optional[np.ndarray] = None
    alpha: Optional[float] = None

class InnerGA:
    """BagAmmo §5.3 风格 4 组件 GA(跳 Immigration)。"""
    def __init__(self, cfg, surrogate, acq_fn, G_0, cmd_pool, validator, rng)
    def initialise_population(self, T: list, current_delta: list) -> list[Individual]
    def step(self, pop: list) -> list[Individual]
        # 1. forward 所有个体 → surrogate (μ, σ)
        # 2. α(Δ_i) = acquisition(μ, σ)
        # 3. Selection(elitist top-m by argmin α)
        # 4. Crossover(subsequence swap)
        # 5. Mutation(Add / Remove / Replace,3 模式)
        # 6. R1/R2 硬过滤
    def run(self, T: list, current_delta: list) -> Individual

# algorithm.py
class GrabnelCMDAttack(AttackAlgorithm):
    """SafeMimic-CMD v3 主算法,§5.4 Algorithm 1 实现。"""
    def __init__(self, cfg: GrabnelConfig)
    def run(self, scenario, candidate_pool, query_fn) -> AttackResult
```

### 1.3 Algorithm 1 → 文件映射

| §5.4 Algorithm 1 步骤 | 文件 / 函数 |
|---|---|
| Init R_unflagged from 30 benign | `fitness/reference.py::Reference.warm_start_from_benign` |
| BLR ← prior | `surrogate/sparse_blr.py::SparseBLR.__init__` |
| `for t = 1 to B_max` 外层 | `algorithm.py::GrabnelCMDAttack.run` |
| `pop ← initialise_population(T, Δ, m)` | `inner_ga.py::InnerGA.initialise_population` |
| `for g = 1 to T_GA` | `inner_ga.py::InnerGA.step` |
| `μ, σ ← BLR(Φ(G_i))` | `surrogate/sparse_blr.py::posterior` |
| `α = μ − β·σ`(Eq 12) | `acquisition/lcb.py::lcb` |
| Selection / Crossover / Mutation | `inner_ga.py::InnerGA.step` |
| `Δ_t* = argmin α` | `inner_ga.py::InnerGA.run` 返回 |
| `Δ ← Δ_t*; G_t = apply(Δ, G_0)` | `commit.py::commit_single` |
| `g, F ← D_target(G_t)` | `attack/oracle.py::query_with_validation_strict` |
| Early stop `F = ∅` | `algorithm.py::GrabnelCMDAttack.run` |
| R + BLR update | `fitness/reference.py::Reference.update` + `surrogate/sparse_blr.py::update` |

### 1.4 Integration map

| 现有模块 | 复用方式 |
|---|---|
| `cmd_graph/{graph,operators,builder,wl_hash,benign,translator}.py` | 不动,直接 import |
| `cmd_graph/wl_hash.py::_node_label` | `surrogate/wl_features.py` 复用 |
| `cmd_graph/operators.py::apply_*, precondition_*` | InnerGA mutation/crossover + R1/R2 validator |
| `attack/framework/{base,history}.py::AttackAlgorithm, QueryHistory` | GrabnelCMDAttack 继承 |
| `attack/oracle.py::query_with_validation_strict` | `attack/grabnel_cmd/runner.py` 绑成 query_fn |
| `range/{execute,checker,converter}.py` | 不动,被 wrapper 调用 |

### 1.5 Driver

`pids_attack/scripts/run.py attack` — 统一入口,调 GrabnelCMDAttack:

```bash
PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack \
  --scenario 01 --detector magic --B-max 20 \
  --feature wl --surrogate blr --f2 knn --scalarize tcheby \
  --commit single --acquisition lcb \
  --beta 5.0 --beta-lcb 0.5 --k-nn 5 --T-GA 50 --m 20 \
  --seed 1 --output /tmp/grabnel_run.json
```

---

## Task 2: 4 个新 detector(G1 / G2 / G1+G2 / G1+G2+GNN)

### 2.1 设计

`cmd_graph/nettack.py` 当前是 attacker 端 R3 filter,有以下函数可直接复用(只是调用点从 attacker 端移到 detector 端):
- `precompute_co_occurrence(G_benign)` → c_benign 共现图
- `precompute_power_law(G_benign)` → (α, S_d, n, d_min) power-law 参数
- `eq10_incremental_lambda(power_law, delta_degree) → Λ`(G1 检查)
- `eq12_check(node, G, c_benign, sigma) → bool`(G2 检查)

参考实现:
- Nettack github(https://github.com/danielzuegner/nettack):`nettack/nettack.py` 里 `compute_alpha` / `update_Sx` / `compute_log_likelihood` / `filter_chisquare`(G1)+ `Nettack.compute_cooccurrence_constraint`(G2)
- 论文 §4.1 Eq 6-10(G1 度分布 power-law)+ Eq 11-12(G2 共现)

### 2.2 文件结构

```
pids_attack/
├── detection/
│   ├── rules.py                    # 规则 detector + SQL CDM dump → CommandGraph
│   └── data/
│       └── hybrid_rules/           # 训好的规则 pickle
│           ├── g1_rule.pkl         # {alpha_benign, S_d, n_benign, d_min, tau_lambda}
│           ├── g2_rule.pkl         # {c_benign(共现图), sigma}
│           └── magic_g1g2.pkl      # base GNN 名 + 两规则
```

### 2.3 4 个 detector 类(`detection/rules.py`)

```python
class G1RuleDetector:
    """纯规则 G1 — 度分布 power-law 违反检测(Nettack §4.1 Eq 6-10)。"""
    def __init__(self, rule_path="detection/data/hybrid_rules/g1_rule.pkl", tau_lambda=0.004):
        self.power_law = pickle.load(open(rule_path, "rb"))
        self.tau_lambda = tau_lambda

    def predict(self, sql_path: str) -> int:
        return int(any(nd["y_pred"] for nd in self.predict_per_node(sql_path)))

    def predict_per_node(self, sql_path: str) -> list[dict]:
        G = sql_to_cmd_graph(sql_path)
        out = []
        for v in G.nodes:
            d_new = degree_change_at(G, v)
            lam = eq10_incremental_lambda(self.power_law, d_new)
            flag = lam > self.tau_lambda
            out.append({"node": v.id, "y_pred": int(flag), "score": float(flag)})
        return out

class G2RuleDetector:
    """纯规则 G2 — 共现违反检测(Nettack §4.1 Eq 11-12)。"""
    def __init__(self, rule_path="detection/data/hybrid_rules/g2_rule.pkl", sigma=0.05):
        self.c_benign = pickle.load(open(rule_path, "rb"))
        self.sigma = sigma

    def predict_per_node(self, sql_path: str) -> list[dict]:
        G = sql_to_cmd_graph(sql_path)
        out = []
        for v in G.nodes:
            ok = eq12_check(v, G, self.c_benign, self.sigma)
            flag = not ok  # 违反 = 标红
            out.append({"node": v.id, "y_pred": int(flag), "score": float(flag)})
        return out

class G1G2RuleDetector:
    """纯规则 G1 + G2,OR 合并。"""
    def __init__(self):
        self.g1 = G1RuleDetector()
        self.g2 = G2RuleDetector()

    def predict_per_node(self, sql_path: str) -> list[dict]:
        out_g1 = self.g1.predict_per_node(sql_path)
        out_g2 = self.g2.predict_per_node(sql_path)
        return [{"node": x["node"],
                 "y_pred": max(x["y_pred"], y["y_pred"]),
                 "score": max(x["score"], y["score"])}
                for x, y in zip(out_g1, out_g2)]

class HybridGNNRuleDetector:
    """GNN + G1 + G2,OR 合并 — 混合类(motivation 实验最强 detector)。"""
    def __init__(self, base_gnn="magic", rule_path="detection/data/hybrid_rules/magic_g1g2.pkl"):
        self._base = _LocalDetector(detector_name=base_gnn)
        self._rule = G1G2RuleDetector()

    def predict_per_node(self, sql_path: str) -> list[dict]:
        gnn_out = self._base.predict_per_node(sql_path)
        rule_out = self._rule.predict_per_node(sql_path)
        return [{"node": g["node"],
                 "y_pred": max(g["y_pred"], r["y_pred"]),
                 "score": max(g["score"], r["score"])}
                for g, r in zip(gnn_out, rule_out)]
```

### 2.4 PIDSOracle 接入

`attack/oracle.py::_ensure_detector` 加 dispatch 分支:

```python
SUPPORTED_RULE_DETECTORS = ("g1", "g2", "g1g2", "magic_g1g2")

def _ensure_detector(self, name: str):
    if name in SUPPORTED_RULE_DETECTORS:
        self._detector = make_rule_detector(name)
    else:
        self._detector = _LocalDetector(detector_name=name)
```

API 完全兼容 `_LocalDetector`(`predict / predict_per_node / predict_with_score`)— 现有 `query_with_validation_strict` 不需要任何修改。

### 2.5 规则训练脚本(`scripts/run.py detect train-rules`)

```bash
PYTHONPATH=pids_attack conda run -n mimicattack python scripts/run.py detect train-rules \
  --benign-dir pids_attack/detection/data/training_traces \
  --out-dir pids_attack/detection/data/hybrid_rules \
  --base-gnn magic
```

一次性离线脚本,不需 GPU:
1. 遍历 31 份 benign_*.sql → reconstruct CommandGraph(via `sql_to_cmd_graph`)
2. union 出 G_benign
3. `precompute_power_law(G_benign)` → 存 `g1_rule.pkl`
4. `precompute_co_occurrence(G_benign)` → 存 `g2_rule.pkl`
5. 同时存 `magic_g1g2.pkl` 含 base GNN tag + 规则路径

---

## Task 3: 实验框架(`experiments/E2_ablation/` + `experiments/E3_attack/`)

### 3.1 目录结构

```
pids_attack/experiments/
├── E2_ablation/
│   ├── scripts/
│   ├── E2.1_features/results/
│   ├── E2.2_surrogate/results/
│   ├── E2.3_f2_metric/results/
│   ├── E2.4_scalarize/results/
│   ├── E2.5_commit/results/
│   ├── E2.6_acquisition/results/
│   ├── E2.7_ga_cmd/results/
│   └── figures/
└── E3_attack/
    ├── scripts/
    ├── E3.0_main_attack/results/  # 主攻击表(grabnel vs random) × 7 detector × 10 scn × 5 seed
    └── figures/
```

### 3.2 共享配置

- **Scenarios:** 10 个 `scenarios/juiceshop/*.json`(跟项目 v4 主实验同一批)
- **Seeds:** 每 cell 5 seed
- **Budget:** B_max = 20
- **Ablation base detector:** `magic`(默认,最快,缩 compute)
- **Metrics:**
  - SR(success rate)= 成功 evade 的 (scn × seed) 比例
  - q★ = 成功 run 上平均真 query 数
  - |Δ★| = 成功 run 上平均扰动 op 数
  - AUC q-SR = SR vs queries 曲线下面积
  - 仅 E2.2:surrogate NLL on held-out (Δ, s)
  - 仅 E2.3:fitness landscape smoothness = corr(s(Δ), s(Δ + 1 mut))

### 3.3 E3.0 主攻击表(最重要)

| Field | Value |
|---|---|
| Algorithms | `grabnel`(v3 默认 config)、`random`(纯随机 Δ baseline) |
| Detectors(7 个) | 3 base GNN(magic / orthrus / threatrace)+ 3 纯规则(g1 / g2 / g1g2)+ 1 hybrid(magic_g1g2) |
| Cells | 2 × 7 × 10 × 5 = **700 cells** |

输出:`results/{algo}_{detector}_{scn}_s{seed}.json`,聚合成主表 LaTeX。

### 3.4 E2.1 ~ E2.7 ablation 对应 v3 §5 TODO

| Ablation | Flag 变化 | 对应 §5 TODO |
|---|---|---|
| **E2.1 features** | `--feature wl\|gnn\|random_walk\|graph2vec\|domain` | §5.2 (a) WL feature 替代方案 |
| **E2.2 surrogate** | `--surrogate blr\|gp_wl\|gp_rbf\|rf\|ensemble` | §5.2 (b) 回归模型替代方案 |
| **E2.3 f2_metric** | `--f2 knn\|dist_weighted\|kde\|gmm` + `--k-nn 3\|5\|10` | §5.3 (a) f_2 度量 |
| **E2.4 scalarize** | `--scalarize tcheby\|weighted\|lex` + `--beta 1\|5\|20` | §5.3 (b) 合成方式 |
| **E2.5 commit** | `--commit single\|batch_2\|beam_3\|lookahead_2` | §5.3 sequential commit 策略 |
| **E2.6 acquisition** | `--acquisition lcb\|ei\|thompson\|lcb_anneal` + `--beta-lcb 0.1\|0.5\|1\|2` | §5.4 acquisition function |
| **E2.7 ga_cmd** | `--ga-mut-weighted` + `--ga-constrained-mut` + `--ga-edit-edge` | §5.4 GA 跟命令空间适配 |

每个 ablation:variants × 10 scenario × 5 seed,在 magic 上跑。

### 3.5 单 cell 命令模板

```bash
PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack \
  --scenario 01 --detector magic --B-max 20 \
  --feature wl --surrogate blr --f2 knn --scalarize tcheby \
  --commit single --acquisition lcb --seed 1 \
  --output pids_attack/experiments/E3_attack/E3.0_main_attack/results/grabnel_magic_01_s1.json
```

### 3.6 Aggregation

`experiments/E2_ablation/scripts/aggregate.py` 和 `experiments/E3_attack/scripts/aggregate.py` 走各自 `results/*.json`,构 tall-form DataFrame,出:
- `E2_summary.csv`(所有 cells,列:experiment / variant / detector / scenario / seed / SR / q★ / |Δ★|)
- LaTeX 主表(`figures/main_table.tex`)
- 每个 ablation 1 张折线图 / box plot(`figures/E2.{n}_*.png`)

---

## 实施顺序

```
Step 1  写本文档(p3_implementation_plan.md)  ✓ 已完成
Step 2  删除 attack/mcts_cmd/ + tests/test_mcts*.py + scripts/run_mcts.py(如有)
Step 3  Task 1 GRABNEL 主算法:
        3.1  attack/grabnel_cmd/{__init__,config}.py + AtomicOp dataclass
        3.2  surrogate/wl_features.py(扩展 cmd_graph/wl_hash.py)
        3.3  surrogate/sparse_blr.py + unit test
        3.4  fitness/{reference,attack_term,stealth_term,scalarize}.py
        3.5  acquisition/lcb.py
        3.6  inner_ga.py + unit test
        3.7  commit.py + algorithm.py + unit test
        3.8  scripts/run.py attack + attack/grabnel_cmd/runner.py + 端到端 smoke test
Step 4  Task 2 4 类新 detector:
        4.1  detection/rules.py
        4.2  scripts/run.py detect train-rules + 跑训规则
        4.3  detection/rules.py(4 detector)+ unit test
        4.4  pidsmaker_wrapper.py 加 dispatch 分支
Step 5  Task 3 实验框架:
        5.1  experiments/E2_ablation/ + experiments/E3_attack/ 目录 + scripts/run_one.sh
        5.2  scripts/run_grid.sh + aggregate.py
        5.3  端到端 dry-run(E3.0 主表 1 cell 跑通)
Step 6  实际跑 700 cells 主表 + 7 个 ablation
```

---

## Verification

### Unit tests
```bash
PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.test_wl_features -v
PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.test_sparse_blr -v
PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.test_inner_ga -v
PYTHONPATH=pids_attack conda run -n mimicattack python -m unittest pids_attack.tests.test_rule_detector -v
```

Test 内容设计:
- `test_wl_features.py`:节点 id 重排不变性;G_0 非空;dim ≤ D_cap;Add op 后 Φ 改变。
- `test_sparse_blr.py`:prior 后验 = (0, finite);合成线性数据 → 后验收敛到真 α;rank-1 update 跟 batch solve 数值一致(1e-8)。
- `test_inner_ga.py`:种群在合成 surrogate 上 α 单调下降;mutation/crossover 后 R1/R2 always pass(constrained 模式)。
- `test_rule_detector.py`:rule-only 模式能 flag ProvNinja-style 高 degree 节点;OR 合并 ≥ base flagged set。

### Smoke run(端到端,1 scenario × 1 detector × 1 seed × 短 budget)
```bash
PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack \
  --scenario 01 --detector magic --B-max 5 --T-GA 10 --m 8 --seed 1 \
  --output /tmp/grabnel_smoke.json
```

### Hybrid 规则训练(Task 2 prerequisite)
```bash
PYTHONPATH=pids_attack conda run -n mimicattack python scripts/run.py detect train-rules \
  --benign-dir pids_attack/detection/data/training_traces \
  --out-dir pids_attack/detection/data/hybrid_rules \
  --base-gnn magic
```

### 主实验(全 grid,smoke 通过后)
```bash
bash pids_attack/experiments/E3_attack/scripts/run_grid.sh E3.0_main_attack
python pids_attack/experiments/E3_attack/scripts/aggregate.py \
  --root pids_attack/experiments/E3_attack \
  --out pids_attack/experiments/E3_attack/figures/E3_attack_summary.csv
```

---

## 风险 + 缓解

| 风险 | 缓解 |
|---|---|
| Sparse BLR + ARD closed-form 实现 bug → surrogate 全错 | toy 数据(已知 α 生成)→ 验回 posterior 收敛;加 NLL 监控 |
| WL hash 桶冲突 → feature 信息丢失 | 监控冲突率,D_cap 跑实验前先 sweep(100 / 200 / 500) |
| R 累积慢 → f_2 早期信号弱 | warm-start 31 benign;f_2 权重 anneal(早期低,后期高)可选 |
| Hybrid detector OR 合并太 strict → baseline 都打不下 | 跑 baseline 看真实成功率;若太严换 confidence 加权(rule_score · 0.5 + gnn_score · 0.5) |
| 失去 MCTS baseline 对照 | 用 `random` Δ 当 baseline(随机采 atomic op 序列) |
| GA 内层 1000 forward 慢 | WL + BLR forward 都 O(D) numpy,1000 次 < 1 秒,不是瓶颈 |
| 700 cells × 20 query × 3s ≈ 12 小时主表 | 先 magic 5 cells 估算实际 wall-clock;若太慢则 scenario 砍到 5 个 |

---

## 引用论文(实施依据)

| 论文 | 出处 | 在本文档的角色 |
|---|---|---|
| GRABNEL [Wan et al.] | NeurIPS'21 [arXiv 2111.02842](https://arxiv.org/abs/2111.02842) | §5 主 anchor:Task 1 整体架构 + WL+BLR + LCB + 内层 GA |
| Adversarial Attacks on Neural Networks for Graph Data [Zugner et al.] | KDD'18 | Task 2 G1/G2 规则原论文(§4.1 Eq 6-12) |
| FCGHunter [Sen Chen et al.] | TSE'25 | §5.3 双目标 fitness 范式 |
| MOS-Attack | arXiv 2501.07251, 2025 | §5.3 soft-min Tchebycheff scalarization |
| BagAmmo [Tang et al.] | USENIX Sec'23 | §5.4 Inner GA 4 组件 (Pop&Ind / Fit&Sel / Crossover / Mutation) 写作范式 |
| Srinivas et al. | ICML'10 | §5.4 LCB acquisition 原论文 |
| Shervashidze et al. | JMLR'11 | §5.2 WL feature 原论文 |

参考实现库:
- GRABNEL repo: https://github.com/xingchenwan/grabnel
- Nettack repo: https://github.com/danielzuegner/nettack
