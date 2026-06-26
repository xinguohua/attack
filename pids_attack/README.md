# pids_attack — 黑盒命令级 PIDS 对抗攻击

针对 Provenance-based IDS(PIDS)的命令级 mimicry 攻击实现。
攻击者以 shell 命令为单位,在保持原攻击 A0 仍能成功的前提下,插入良性 camouflage δ,
让 PIDS 把整条命令链判为 benign。整套实现按 BlackboxBench / BagAmmo / [PIDSMaker](https://github.com/ubc-provenance/PIDSMaker) 的接口对齐,
目标投四大安全顶会(S&P / CCS / USENIX Security / NDSS)。

> PIDSMaker 资源:[GitHub](https://github.com/ubc-provenance/PIDSMaker) · [Paper (USENIX Sec'25)](https://arxiv.org/abs/2601.22983) · [Docs](https://ubc-provenance.github.io/PIDSMaker)

---

## Threat Model(SoK Pitfalls SaTML 2024 四维定位)

| 维度 | 取值 |
|---|---|
| Query Access | Interactive — 攻击者可通过 `docker exec` 真发 query |
| Feedback Granularity | Hard-label — 只拿 0/1 binary,无置信度 |
| Auxiliary Data Quality | 无重叠 — 不假设防御方训练数据 |
| Auxiliary Data Quantity | Insufficient — 几乎没有辅助数据 |

攻击者输入:完整命令序列 `A_0 ⊕ δ`(A_0=恶意,δ=camouflage)。
攻击者输出:`y ∈ {0, 1}`(0=benign,1=malicious)。
目标:在 `query_budget` 内找到 δ 使 `y=0` 同时 A_0 全 checker 通过。

---

## 统一入口

```bash
conda run -n mimicattack python pids_attack/scripts/run.py --help
```

`scripts/run.py` 是**唯一公开入口**。当前只有两个一等模块：

```text
detect  = 训练 + 检测框架
attack  = 攻击框架
```

当前方法框架和代码边界见 `METHOD_CODE_MAP.md`。

```bash
python pids_attack/scripts/run.py detect collect
python pids_attack/scripts/run.py detect train-gnn
python pids_attack/scripts/run.py detect train-rules
python pids_attack/scripts/run.py detect e0

python pids_attack/scripts/run.py attack smoke-query
python pids_attack/scripts/run.py attack run --scenario 01 --detector magic --B-max 10
```

跑前置条件:Docker Desktop 已开;`mimicattack` conda env(numpy / sklearn / torch + torch-geometric)。

---

## 跑起来后会发生什么

```
PART A — 环境保障
  STAGE 0   preflight: docker daemon / pids_range image / scenario JSON 检查
  STAGE 1   起容器: pids_postgres + pids_range,等 juice-shop 200,容器内 strace 自检

PART B — 原始攻击 → PIDS 初始判定(不带 δ,不走攻击算法)
  STAGE 2   load scenario JSON (A_0)
  STAGE 3   execute_with_checks: 容器执行原始攻击 A_0 + strace + checker
  STAGE 5   trace_to_pidsmaker: strace text → CDM 节点边 → SQL dump
  STAGE 6   _LocalDetector.predict: SQL → y∈{0,1}  (初始状态,攻击前)

Attack mode
  scripts/run.py attack smoke-query   单次真实 A0 query 走查
  scripts/run.py attack run           SafeMimic-CMD 主循环 + verbose query 日志
```

---

## 5 层 pipeline 架构

```
                  ┌────────────────────────────────┐
                  │  attack/safemimic_cmd/         │   ← Layer A 算法
                  │  paper §5 分层(6 子目录):       │
                  │   operators (§4 Add/Rw/Mv/Rm)  │
                  │   constraints (§3 R1/R2)       │
                  │   objectives (§5.3 f1/f2)      │
                  │   search (§5.3 + §5.4)         │
                  │   surrogate (§5.2 WL+BLR+ARD)  │
                  │   acquisition (§5.4 LCB/EI/Th) │
                  └───────────┬────────────────────┘
                              │ candidate cmd seq
                              ▼
                  ┌────────────────────────────────┐
                  │ attack/framework/oracle.py     │   ← Layer B
                  │ query_with_validation_mixed    │
                  └───────────┬────────────────────┘
                              │ scenario + δ + positions
                              ▼
                  ┌────────────────────────────────┐
                  │ range/cached_mixed.py          │   ← Layer C
                  │ cached benign + fresh A0⊕δ     │
                  │ range/mixed_workload.py        │
                  │   marker(A0⊕δ) docker+strace   │
                  │   ⇨ clean.strace / gt.json     │
                  └───────────┬────────────────────┘
                              │ trace 文件路径
                              ▼
                  ┌────────────────────────────────┐
                  │ range/converter.py             │   ← Layer D
                  │ parse_strace_text → CDM graph  │
                  │ graph_to_sql                   │
                  │   ⇨ trace_<uuid>.strace.sql    │
                  └───────────┬────────────────────┘
                              │ CDM SQL dump
                              ▼
                  ┌────────────────────────────────┐
                  │ detection/* detector adapter   │   ← Layer E
                  │ _LocalDetector.predict_per_node│
                  │ filter GT/attack nodes         │
                  └────────────┬───────────────────┘
                               │ y ∈ {0, 1} for attack node
                               ▼
                       回到 attack/framework/oracle.py,再回 Layer A 更新算法状态
```

### 关键代码点(直接给行号)

| 关心什么 | 看哪 | 行号 |
|---|---|---|
| **入口/总流程** | `scripts/run.py` | 全 |
| **攻击框架入口** | `attack/safemimic_cmd/runner.py` | — |
| **攻击算法主循环** | `attack/safemimic_cmd/search/sequential.py`(K-stage commit + inner GA) | — |
| **strace 采集真正在哪起的** | `range/checker.py:_exec_traced_batch_safe` 里的 batch runner | — |
| **strace 跟踪的 19 个 syscall** | `range/execute.py STRACE_SYSCALLS` | 21-30 |
| **6 条命令的交错顺序** | `range/checker.py:_interleave` | 219-235 |
| **strace text → CDM 节点边** | `range/converter.py:build_cdm_graph_from_strace` | 344 |
| **CDM → SQL** | `range/converter.py:graph_to_sql` | 216 |
| **detector 判 y** | `detection/training/pidsmaker.py:_LocalDetector.predict` | 150 |

---

## CDM Schema(对齐 PIDSMaker / DARPA TC)

**3 种节点**:
- `subject` — 进程/线程(uuid, pid, exec_path, cmdline, comm)
- `file` — 文件/目录(uuid, path)
- `netflow` — 网络连接(uuid, src_ip, src_port, dst_ip, dst_port)

**10 种边(EVENT_*)**:
`READ / WRITE / OPEN / EXECUTE / CONNECT / RECVFROM / RECVMSG / SENDTO / SENDMSG / CLONE`

**syscall → EVENT 映射**:`range/converter.py SYSCALL_TO_EVENT` 字典。
strace 输出的 syscall 名 → CDM 边类型,再加上从 args 提取的 fd path / sockaddr → 节点。

---

## Checker 机制(为什么必须有)

A_0 ⊕ δ 在容器里跑时**每一步都可能失败**:网络抖动、应用没起、δ 副作用打挂、上一步失败级联等。
没 checker 的话:攻击根本没打成功 → PIDS 反馈 benign → 算法误以为找到了好 δ → query 信号失真。
**Checker 验证 A_0 的每一步真打成功了,PIDS 反馈才算数。**

**6 类 checker(`range/checker.py`)**:
| 类型 | 用途 | 例 |
|---|---|---|
| `http_response_contains` / `http_status_code` / `http_header_present` | HTTP 响应验证 | `200`、body 含 `"authentication"` |
| `exit_code` | 退出码验证 | `0` |
| `stdout_contains` / `stdout_not_contains` / `stdout_regex_match` | 输出文本验证 | stdout 含 `HTTP` |
| `file_exists` / `file_contains` / `file_size_min` | 文件系统验证 | `/tmp/x` 存在 |
| `exfiltrated_data_present` / `privilege_escalated` / `shell_obtained` | 攻击副作用最终验证 | 拿到 admin token |
| `custom` | 自定义脚本 | 退出 0=pass |

**checker 失败的处理**:`query_with_validation_strict` 返回 INVALID(不消耗 query 预算),
`guidance.handle_invalid_query` 给被怀疑的 element 降权(策略 B)+ 短暂 retry(策略 C)。

---

## 数据(攻击命令的来源 + 设计)

| 文件 | 用途 | 数量 |
|---|---|---|
| `scenarios/juiceshop/*.json` | A_0 攻击场景(每个含多条 step + checker) | 10 |
| `shared/candidate_pool.txt` | δ camouflage 候选命令池 | 106 |
| `attack/data/command_templates.json` | Search Space 方案 D 用的命令模板 | — |

### `scenarios/juiceshop/*.json` — 10 个 A_0 攻击场景

**来源 = Juice-Shop 官方源码精确触发条件 + Claude 翻译成 curl + 真容器实测验证**。

每个 JSON 对应 Juice-Shop 一个 challenge,挑选 + payload 构造的 3 条参考依据:

1. **Juice-Shop 官方 `challenges.yml`** — challenge 元数据(name / description / hints)
   `https://github.com/juice-shop/juice-shop/blob/master/data/static/challenges.yml`
2. **Juice-Shop 源码 `routes/*.ts` 里 `solveIf(...)` 那行** — 服务器**到底怎么判 challenge 解开**。这是权威触发条件,curl payload 就是从这里**1:1 翻译**过来的。例 `routes/login.ts`:
   ```typescript
   challengeUtils.solveIf(challenges.weakPasswordChallenge, () =>
     req.body.email === 'admin@juice-sh.op' && req.body.password === 'admin123')
   ```
   → curl payload 就是 `{"email":"admin@juice-sh.op","password":"admin123"}`。
3. **OWASP Pwning Juice Shop 解题手册** — 给人看的解题说明,辅助验证。
   `https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html`

每个 JSON 的 `source` 字段就两个键(`task` + `solution`),分别给到官方题目原文 + OWASP 解题章节 anchor URL。

**10 个 challenge 覆盖 6 类攻击**:SQLi 绕登录 ×3、UNION SQLi 提取 schema、IDOR 越权、Mass-Assignment、Open Redirect、Path-Traversal、Information Disclosure、Weak-Password。

**每条 step 的 `expected` 字段**:Claude 在容器里**真发 curl 一次** → 拿真响应 → 从候选 marker 列表里选第一个真出现在响应里的字符串。不是猜测填的。

**真实可证明 challenge 解开**:跑 `attack_scenarios.py` 会重启 Juice-Shop 清所有 `solved` 状态,逐个跑 JSON 后查 `/api/Challenges/?name=<name>` 确认 server 端 `solved` 字段从 `false` 翻成 `true`——server 自己说"这个 challenge 我标记 solved 了"才算数。**实测 10/10 全过**。

### `shared/candidate_pool.txt` — 106 条 δ camouflage 命令

每条命令右侧 `# xxx/yyy` 注释标了来源,3 类共 106 条:

| 来源 tag | 数量 | 物理来源 |
|---|---|---|
| `# coreutils/...` `# procps/...` `# iproute2/...` 等 | 80 | Claude 手写到生成脚本里的常用 Linux 命令(基于 GNU coreutils / procps-ng / util-linux 的标准用法) |
| `# ART/T1xxx` | 18 | 真去 GitHub 抓的 Atomic Red Team Discovery 战术 YAML(T1082/T1083/T1057/T1018/T1016/T1049/T1033/T1518) |
| `# gtfobins/xxx` | 8 | 真去 GitHub 抓的 GTFOBins File-read 类条目 |

**筛选准则**:
- ✅ 只读文件操作 / 进程系统查询 / 本地网络探测
- ❌ 写文件 / 长生命周期 fork / 触碰 attack-essential 路径 / 需要特权
- ✅ 全部命令在 `pids_range` 容器内 `timeout 5 <cmd>` dry-run 通过

### 改数据怎么办
直接编辑 `scenarios/juiceshop/*.json` 或 `shared/candidate_pool.txt`(纯文本)。改完 JSON 跑 `scripts/validation/attack_scenarios.py` 验证 challenge 还能解开。

---

## 目录结构

```
pids_attack/
├── detection/
│   ├── data/collect.py        # benign / attack trace 采集
│   ├── data/data_prep.py      # PIDSMaker JUICESHOP 灌库逻辑
│   ├── training/pidsmaker.py  # GNN train / eval / inference adapter
│   ├── training/rules.py      # G1/G2/G1G2/hybrid rule detectors
│   ├── inference/registry.py  # final detector artifact registry
│   ├── diagnostics.py         # audit / threshold sweep
│   ├── artifacts/             # 9 个 detector 的当前可运行模型/规则/参数
│   │   ├── manifest.json      # global_best / best_by_class
│   │   ├── magic/
│   │   ├── orthrus/
│   │   ├── threatrace/
│   │   ├── g1/
│   │   ├── g2/
│   │   ├── g1g2/
│   │   ├── magic_g1g2/
│   │   ├── orthrus_g1g2/
│   │   └── threatrace_g1g2/
│   ├── training/
│   │   └── artifacts/         # PIDSMaker GNN 训练产物
│   └── data/
│       ├── benign_collection_plan.yml
│       ├── training_traces/
│       ├── test_traces/
│       └── archive/
├── attack/
│   ├── data/
│   │   └── command_templates.json
│   ├── framework/             # AttackScenario / Delta / QueryResult / QueryHistory / SafeMimicConfig
│   ├── safemimic_cmd/         # 唯一 paper-facing 攻击框架(SafeMimic-CMD)
│   │   ├── runner.py          # scripts/run.py attack run 唯一入口,by-config dispatch
│   │   ├── search/one_shot.py # E1.0 minimal Add profile
│   │   ├── operators/         # §4: add / rewrite / move / remove                ← E1.1
│   │   ├── constraints/       # §3: r1_attack_integrity / r2_delta_executable    ← E1.0
│   │   ├── objectives/        # §5.3: f1_hinge / f2_endogenous_r / scalarize     ← E1.2
│   │   ├── search/            # §5.3+§5.4: sequential / inner_ga / commit / one_shot  ← E1.3/E1.0
│   │   ├── surrogate/         # §5.2: wl_features / sparse_blr / ard             ← E1.4
│   │   └── acquisition/       # §5.4: lcb / ei / thompson                        ← E1.5
│   └── framework/oracle.py    # attack-time black-box oracle
├── scenarios/
│   └── juiceshop/             # 10 个 A0 JSON 场景
├── shared/
│   ├── candidate_pool.txt     # detection 和 attack 共用候选命令池
│   └── g_benign.pkl           # attacker-side benign prior
├── cmd_graph/
│   ├── builder.py             # A0 JSON → CommandGraph
│   ├── operators.py           # P1/P2 mutation operators
│   ├── nettack.py             # R3 unnoticeability
│   ├── wl_hash.py             # WL hash / feature
│   └── benign.py              # G_benign 构造
├── range/
│   ├── Dockerfile         # juice-shop + strace + Kali 工具
│   ├── execute.py         # _execute_strace + STRACE_SYSCALLS 列表
│   ├── checker.py         # 6 类 checker + execute_with_checks + _interleave + batch runner
│   ├── validation.py      # 离线 scenario 校验
│   └── converter.py       # strace text → CDM 图 → SQL dump
├── experiments/
│   ├── E0_detection/      # A0 原始攻击检测实验
│   ├── E1_ablation/       # finding-driven 6-stage ablation / framework revision
│   └── E2_attack/         # SafeMimic-CMD 完整主攻击实验
├── tests/                 # unittest suite
├── scripts/
│   ├── run.py                   # ★ 唯一公开 CLI 入口:detect / attack
│   ├── validation/              # 实验前置验证
│   │   ├── attack_scenarios.py
│   │   ├── graph_semantics.py
│   │   └── r3_recall.py
│   └── diagnostics/             # 辅助诊断脚本，公开入口仍走 scripts/run.py detect
├── PIDSMaker/             # upstream vendored code,不重构
├── results/               # 跑出的 trace + sql + history.json
└── README.md
```

---

## 输出格式

**单次攻击**:`scripts/run.py attack run --output <path>.json`
```
{
  "schema_version": "safemimic.attack_run.v1",
  "scenario_id": "juiceshop_sqli_login_bypass",
  "detector": "magic",
  "algo": "full",
  "converged": false,
  "q_used": 4,
  "best_F_count": 1,
  "best_delta": [...],
  "queries": [...]
}
```

**每次 query 的 trace**:`results/demo_traces/trace_<uuid>.strace`(strace 原始文本)
和 `trace_<uuid>.strace.sql`(CDM 灌库 SQL)。

---

## debug 攻略

```bash
# 看最新 trace 文件
ls -lt results/demo_traces/*.strace | head -3
less results/demo_traces/trace_<uuid>.strace        # syscall 流,带绝对时间戳

# 看 CDM SQL dump
less results/demo_traces/trace_<uuid>.strace.sql    # 节点 + 边的 INSERT 语句

# 容器状态
docker ps --filter name=pids_
docker exec pids_range tail -f /var/log/juice-shop.log

# 手动跑一条 strace 看采集格式
docker exec pids_range strace -f -ttt -e trace=execve,openat bash -c 'curl -s http://localhost:3000/'

# 单测
conda run -n mimicattack python -m unittest discover tests/ -q
```

PyCharm debug 路径:`scripts/run.py` STAGE 3 行设断点 → F7 进 `range/checker.py` 看 `_interleave`
排序的命令 → F7 进 `_exec_traced_batch_safe` 看 batch runner 生成的分段执行脚本。

---

## 各模块分析(随 debug 过程逐步填充)

> 结构按 `scripts/run.py attack smoke-query` 的 STAGE 0-6 和 `scripts/run.py attack run` 的 SafeMimic-CMD full loop 排列。
> 写法建议:**一句话职责** + **关键代码点(文件:行号)** + **输入/输出** + **debug 笔记**。

### PART A — 环境保障

#### STAGE 0 · preflight
- **职责**:体检 — docker daemon / `pids_range` 镜像 / scenario JSON,缺啥 abort
- **代码**:`scripts/run.py:47-62`

#### STAGE 1 · 起容器
- **职责**:idempotent 拉起 `pids_postgres` + `pids_range`,等 juice-shop 200,容器内 strace 自检
- **代码**:`scripts/run.py:77-124`
- **三步**:
  1. **启动**:`docker ps -a` 查状态 → Up 跳过 / Exited 走 `docker start` / 不存在走 `docker run -d`(pids_range 必须 `--privileged` + `:3000`)
  2. **HTTP 探测**:`curl localhost:3000` 轮询 60s,200 就过
  3. **strace 自检**:`docker exec pids_range strace --version`,装好才放行(避免 STAGE 3 才暴露)
- **为什么是这两个容器**:

  | 容器 | 镜像 | 作用 |
  |---|---|---|
  | `pids_range` | 自 build(`range/Dockerfile`) | 攻击靶机 — Juice-Shop v15 + strace + Kali 工具,**攻击命令、Juice-Shop、strace 采集**全在里面 |
  | `pids_postgres` | `postgres:14` | CDM 后端,给真 PIDSMaker 留的接口位(当前 stub detector 不连) |

#### 数据准备(offline,跑 run.py 之前)

**A_0 攻击命令 — `scenarios/juiceshop/*.json`(10 条)**
- 来源 = Juice-Shop 源码精确触发条件 → 翻译成 curl → 真容器实测
- 每个 JSON 写之前查 3 处:① 挑哪个 challenge ② curl payload 怎么写 ③ 怎么算解开:
  1. `challenges.yml` — 列出所有 challenge 的元数据(用来**挑哪个**)
  2. `routes/*.ts` 里 `solveIf(...)` — 服务器判 solved 的真条件,curl payload **1:1 翻译**自这里(用来**写 payload**)
  3. OWASP Pwning Juice Shop 解题手册 — 给人看的解题说明(辅助校对)
- 每条 step 的 `expected` 是**真发 curl 拿响应**后挑的真出现字符串(非猜测)
- 覆盖 6 类攻击:SQLi 绕登录 ×3 / UNION SQLi / IDOR / Mass-Assignment / Open Redirect / Path-Traversal / InfoDisclosure / Weak-Password
- 验证:`scripts/validation/attack_scenarios.py` 查 `/api/Challenges/?name=<name>` 的 `solved` 字段,**10/10 全过**

**C 良性命令池 — `shared/candidate_pool.txt`(106 条)**

每条命令右侧 `# xxx/yyy` 注释标来源,3 类全部带可追溯来源:

| 来源 tag | 数量 | 物理来源(URL / 仓库 / 文档) |
|---|---|---|
| `# ART/T1xxx` | 18 | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) Discovery 战术 YAML,T1082(System Information)/ T1083(File and Directory)/ T1057(Process)/ T1018(Remote System)/ T1016(Network Config)/ T1049(Network Connections)/ T1033(System Owner/User)/ T1518(Software)。命令逐条从 `atomics/T1xxx/T1xxx.yaml` 的 `executor.command` 抠出 |
| `# gtfobins/xxx` | 8 | [GTFOBins](https://gtfobins.github.io/)([仓库](https://github.com/GTFOBins/GTFOBins.github.io))File-read 类页面([function: file-read](https://gtfobins.github.io/#+file-read)),从 `_gtfobins/<binary>.md` 的 `file-read` 段抠命令 |
| `# coreutils/...` `# procps/...` `# util-linux/...` `# iproute2/...` `# bash/...` 等 | 80 | 各 Linux 包**官方 man page 文档示例**:GNU coreutils(`ls`/`cat`/`stat`/`wc`/`du`/`df`...,[manpages](https://www.gnu.org/software/coreutils/manual/))、procps-ng(`ps`/`top`/`free`/`uptime`/`vmstat`...,[manpages](https://gitlab.com/procps-ng/procps))、util-linux(`lscpu`/`lsblk`/`lsipc`...,[manpages](https://github.com/util-linux/util-linux))、iproute2(`ip a`/`ip route`...,[manpages](https://wiki.linuxfoundation.org/networking/iproute2))、bash builtin。每条都是文档里 documented 的标准查询用法,非自创 |

**筛选准则**:✅ 只读文件 / 进程查询 / 本地探测;❌ 写文件 / 长 fork / 碰 attack-essential 路径 / 需特权;✅ 容器内 `timeout 5 <cmd>` dry-run 全过(returncode=0)


> 🚧 **TODO · 数据 + 靶场扩容**(顶会实验体量需要,优先级高)
>
> 1. **A_0 攻击命令扩量**(目前 10 → 目标 ≥ 50)
>    - 多挑 Juice-Shop challenge:除现有 6 类外,补 XSS / CSRF / Deserialization / SSRF / RCE
>    - 新靶场上的攻击场景:见第 3 条
>    - 每条仍按"`solveIf` 1:1 翻译 + `attack_scenarios.py` 验证 server `solved=true`"流程,不放水
>
> 2. **C 良性命令池扩量**(目前 106 → 目标 ≥ 300)
>    - 补 ART 其他战术族:Persistence(T1547)/ Defense Evasion(T1070)/ Collection(T1005)等的**只读子集**
>    - 补 GTFOBins 其他 function:`shell-spawn` / `command-execution` 的**安全子集**(需重新过筛选准则)
>    - LOLBAS / LOOBins 备选(目前没用,跨平台时再说)
>    - 每条照旧:容器内 `timeout 5` dry-run 必须 returncode=0,inline source 注释必须可追溯
>
> 3. **靶场环境扩量**(目前 Juice-Shop 单靶 → 目标 ≥ 3 个异质靶机)
>    - **DVWA**(PHP/MySQL 漏洞靶机)— 覆盖 Apache + PHP 这条技术栈
>    - **WebGoat**(Java/Spring 漏洞靶机)— 覆盖 JVM + Tomcat 这条技术栈
>    - **Metasploitable3** 或 **HackTheBox 离线靶机**— 覆盖系统级漏洞(非 web)
>    - 每个靶机都要重做:`range/Dockerfile` 加镜像、`scripts/run.py` 加 STAGE 1 启动逻辑、`scenarios/juiceshop/` 加对应 JSON
>    - **目的**:验证攻击算法的**跨靶机泛化性**(论文实验必备),否则 reviewer 会问"只在 Juice-Shop 上证不了 PIDS 在异质环境也被骗"

---

### PART B — 5 层 smoke-query 单次走查(固定 δ,不走攻击算法)

#### STAGE 2 · load scenario JSON (A_0)
- **职责**:从 `scenarios/juiceshop/*.json` 读一个 A_0 进内存,纯 IO,不发命令
- **代码**:`scripts/run.py:131-147`
- **逻辑**:`sorted(glob("*.json"))` 取**字典序第一个**(默认 `01_juiceshop_sqli_login_bypass.json`),`json.load` 进 dict,打印 `scenario_id` / `attack_type` / 每条 step
- **输出 `scenario: dict`**:`scenario_id` / `attack_type` / `steps[]`(含 command + checker)/ `final_attack_check`
- **debug 笔记**:换场景就改字典序 / 直接传路径

> 🚧 **TODO · STAGE 2 多场景遍历**(顶会实验必备,优先级高)
>
> 1. **当前只跑第一个 JSON 一次**,论文实验需要在**所有 A_0**(目前 ≥10,扩量后 ≥50)上各跑 N 次,拿成功率 / 平均 query 数 / wall-clock,做统计显著性检验
> 2. **接口改造**:`stage_2` 改返回 `List[scenario]`,主循环 `for scenario in scenarios: PART B + PART C`,结果聚合到 `results/<exp_id>/per_scenario.json`
> 3. **跨靶机扩展**:配合 PART A 的靶场扩容 TODO(DVWA / WebGoat / Metasploitable3),`scenario` 要新增 `target_container` 字段,告诉 STAGE 3 在哪个容器里 `docker exec`

> **δ 扰动属于 attack mode**,不在 PART B。`scripts/run.py attack run` 启动 SafeMimic-CMD,动态生成 (delta_cmds, positions),每轮 query 都会换。
> `positioned_individual.py` 按 guidance score / importance 挑位置(`positions[i]` 必须 `< n_steps`,否则 δ 落到 A_0 最末步之后会让 `final_attack_check` 误判 `final_attack_succeeded=False`)。

#### STAGE 3 · execute_with_checks(容器执行原始攻击 A_0 + strace 采集 + checker 判过)
- **职责**:把**原始攻击 A_0**(不带 δ)真打进容器跑一遍,按 A_0 step 分段 batch 执行;段内每条命令仍单独用 strace 包采 syscall(全部 append 到同一 trace),A_0 步骤当场用 checker 判过/不过(fail-fast),最后跑 `final_attack_check` 判攻击是否真成功,trace cp 出宿主给 STAGE 5
- **代码**:`scripts/run.py:181-205` + `range/checker.py:execute_with_checks` → `_exec_traced_batch_safe` → `range/execute.py:_docker_exec (54)`
- **逻辑**:
  1. `reset_container()` — `pkill -f node` + 重启 juice-shop + 30 次 1s `curl localhost:3000` 探活(`execute.py:61-88`),`reset=True` 时跑,~3-5s
  2. `rm -f && touch /tmp/pids_trace_<uuid12>.strace` — 容器内一个 trace 文件,所有 cmd 共写(`checker.py:267-273`)
  3. `_interleave(A0_steps, delta_commands, delta_positions)` — bucket 拼出 `[(kind, item)]` 执行序
  4. 按 step 分段 flush:每段包含 step 前累积 δ + 当前 step;step 跑完当场 `run_checker(spec, co)`,**fail-fast** 第一条不过就 break
  5. `_exec_traced_batch_safe`:每段一次 `docker exec`,段内每条真实命令仍用 `timeout 8s strace -fA -ttt -s 256 -e trace=<19 syscalls> -o <trace> bash <cmd_file>`;`-A` append 模式让所有调用共写一个文件,19 syscall 1:1 覆盖 PIDSMaker 10 种 EVENT_*(`execute.py:21-30`)
  6. `final_attack_check` — 仅 `all_steps_passed=True` 跑,在 `cmd_outputs[-1]` 上判(`checker.py:300-308`)
  7. `docker cp` trace 出宿主 `${PIDS_RANGE_SYSDIG_DIR:-/tmp/pids_attack_traces}/trace_<uuid>.strace`(`checker.py:311-320`),fail-fast 失败也照 cp(trace 截到失败那条)
- **关键约束**:`cmd_outputs[-1]` 喂给 final_check → `positions[i] < n_steps`(见 STAGE 3 约束的根因);file/privilege 类 checker 内部的 `_docker_exec` 没 strace 包(`execute.py:54`),**不**污染攻击者 syscall 画像;容器内 `timeout 8s` + 宿主 `subprocess.run(timeout=12)` 双重硬限,卡死走 exit_code=124 + `[TIMEOUT]`
- **输出**:`AttackExecutionResult { all_steps_passed, final_attack_succeeded, step_results, failed_step, trace_path, command_outputs }`;`run.py:203-204` 守门 — 两个 bool 都 True 才放行 STAGE 5,否则 `sys.exit`

#### STAGE 5 · trace → CDM(strace text → 节点边 → SQL dump)
- **职责**:把 STAGE 3 的 `.strace` 文本逐行解析成 CDM provenance graph(3 类节点 + 10 类边),序列化成 PostgreSQL 填库 SQL 给 STAGE 6 detector 吃
- **代码**:`scripts/run.py:208-225` + `range/converter.py:trace_to_pidsmaker (399)` → `strace_to_pidsmaker (387)` → `build_cdm_graph_from_strace (344)` → `parse_strace_text (283)` → `graph_to_sql (216)`
- **逻辑**:
  1. `sql_path = trace_path + ".sql"` — 同目录拼后缀(`run.py:212`)
  2. `trace_to_pidsmaker(trace_path, sql_path)` — 按文件后缀派发:`.scap` → sysdig 路径(macOS 不可用), 其他 → strace 路径(`converter.py:399-403`)
  3. `parse_strace_text` — 逐行正则 `[pid] ts syscall(args) = retval`(`_STRACE_LINE_RE` @ `converter.py:274-280`),产出 sysdig schema 的 event dict 列表;`fd.name` 按 syscall 抠路径或 sockaddr `"ip:port"`(`_strace_extract_path` @ `converter.py:322-341`)
  4. `build_cdm_graph_from_strace`(`converter.py:344-384`)逐 event 三步:查 `SYSCALL_TO_EVENT` 19→10 映射(`converter.py:28-39`)/ `_ensure_subject_node|file_node|netflow_node` 按 `node_key_to_uuid` O(1) dedup / `append` 一条 `CDMEvent` 边(subject_uuid → object_uuid)
  5. `graph_to_sql`(`converter.py:216-245`)— `DDL_SQL`(4 张表 + 3 索引)+ 节点 INSERT + 边 INSERT 拼成纯文本 SQL
  6. `open(sql_path, "w").write(sql)` — 落盘(`converter.py:391-392`)
  7. wrapper 又调一次 `build_cdm_graph_from_strace` 只为打 node_types / edge_types 统计(`run.py:214-220`,跟 trace_to_pidsmaker 内那次重复构图,trace 大时占一半耗时)
- **关键约束**:strace 后端字段缺失 — `proc.exe` / `proc.cmdline` 依赖 `/proc` snapshot + execve args 补齐,仍可能有空值;节点 uuid 由 semantic key deterministic 生成,便于 E0 离线重算 GT;`EVENT_CLONE` 的 `object_uuid=None`,等 PIDSMaker 自己关联子进程
- **输出**:`sql_path: str`(`<trace>.sql`),内容 = DDL(`subject_node` / `file_node` / `netflow_node` / `cdm_event` 4 表 + 3 索引)+ 每节点一条 INSERT + 每事件一条 INSERT

#### STAGE 6 · detector 推理(SQL → per-node scores)
- **职责**:把 STAGE 5 产出的 `.sql` 喂进 PIDS oracle,打印 node-level detector 输出;这里的 `y` 只是 raw graph summary
- **代码**:`scripts/run.py:stage_6_detector_predict` → `detection/training/pidsmaker.py:_LocalDetector.predict_per_node` → 「**PIDS oracle —— 推理**」详见下面独立 section
- **关键事实**:每次 predict 真跑 GNN forward(不是关键字 stub,不查训练时 eval pkl);δ 改 SQL 内容 → forward 输出真变化
- **输出**:per-node `y_pred/score`;attack mode 的成功判断不使用整图 `any(y_pred)`,而由 `query_with_validation_mixed()` 的 E0-style node-level GT/metrics 生成

---

### PIDS oracle —— 推理(STAGE 6 / attack mode 用)

输入 PIDSMaker 兼容 SQL → 输出 per-node prediction。E2 attack oracle 的 $y\in\{0,1\}$ 定义为:至少一个 GT/attack node 被 flagged 时 `y=1`,否则 `y=0`。

#### 调用链

```
STAGE 6:  run.py:stage_6_detector_predict
            └── _LocalDetector.predict_per_node(sql) → raw node-level predictions

Attack:   scripts/run.py attack run
            └── attack/safemimic_cmd/runner.py run_attack(cfg)
                └── search/sequential.py K-stage commit + inner_ga
                └── query_with_validation_mixed(scenario, δ_cmds, positions)
                  ├── collect_cached_mixed_workload
                  │   ├── fresh marker(A0⊕δ) execution for R1/R2
                  │   └── cached benign trace composition
                  ├── clean.strace.sql          # composed strace → SQL
                  ├── _LocalDetector.predict_per_node
                  └── E0-style node GT/metrics  # QueryResult.y = attack_detected
```

#### 文件

| 文件 | 作用 |
|---|---|
| `detection/training/pidsmaker.py` | `PIDSMakerEngine` 真 forward + `_LocalDetector` cache + `SUPPORTED_DETECTORS` |
| `attack/framework/oracle.py` | `PIDSOracle` + `query_with_validation_mixed`(fresh A0⊕δ 执行 + cached-mixed 组合 + 推理入口) |

> 训练 / 评测 / setup 见 [PIDS oracle —— 训练](#pids-oracle--训练一次性跑完已落盘) 与 [PIDS oracle —— 评测](#pids-oracle--评测训练完成验收) 两节。

#### 8 detector(`SUPPORTED_DETECTORS`)

| detector | encoder | task | threshold | F1 |
|---|---|---|---|---|
| kairos | TGN | predict_edge_type | p99_val_loss | 0.808 |
| threatrace | SAGE | predict_node_type | threatrace(1.5) | 0.733 |
| velox | linear-only | reconstruct_node_features | p98_val_loss | 0.663 |
| rcaid | rcaid_gat (pseudo_graph) | predict_node_type | p90_val_loss | 0.492 |
| magic | GAT | reconstruct + predict | magic (train_distance) | 0.416 |
| orthrus | TGN | predict_edge_type | max_val_loss + kmeans top-30 | 0.294 |
| nodlink | sum_aggregation | reconstruct_node_features | nodlink (p90) | 0.044 |
| flash | SAGE | predict_node_type | flash (0.53) | 0.000 |

> 上游 `max_val_loss` 被 JUICESHOP val 集 outlier 顶飞 → F1 全 0;切 p99/p98/p90 后 0 → 0.49~0.81。改动:`PIDSMaker/config/{kairos,rcaid,velox}.yml` + `evaluation_utils.py` 加 3 个 method 分支。

#### 首次 predict 加载产物

`PIDSMakerEngine._ensure_loaded()`(只调一次,~3-5 分钟):
1. `cfg` + `device`
2. `model` ← `build_model` + `load_model(best_dir)` + `eval()`
3. `threshold` ← `best_model/threshold.pkl`(dict 或 float)
4. `etype2oh` / `ntype2oh` / `rel2id`
5. `indexid2vec` ← `cfg.featurization.used_method` 分发(word2vec / fasttext / alacarte / doc2vec / hierarchical_hashing / temporal_rw / flash / magic / only_type)
6. `oov_emb_fn` ← method-specific(word2vec 用 decline_rate,fasttext 用 subword,其余 zero)
7. `magic_train_distance` ← `best_dir/train_distance.txt`(仅 magic)
8. `_reindexer`(`GraphReindexer`)+ `_neighbor_loader` + `_max_node`(训练时全局)

`_LocalDetector._engines: Dict[str, PIDSMakerEngine]` class-level cache,跨实例复用。

#### `predict_per_node(sql_path)` 流程

```
predict_per_node:
  1.  parse_sql_to_events_and_nodes(sql, cfg)       regex 抽 INSERT,绕 DB
  2.  cdm_to_nx_graph(events, indexid2msg, cfg)     复制 construction.gen_edge_fused_tw
  3.  apply_graph_transformations(graph, methods, cfg)   PIDSMaker 直调(rcaid 走 pseudo_graph)
  4.  single_graph_to_temporal_data(...)            自写,feat_inference + OOV
  5.  extract_msg_from_data([data], cfg)            PIDSMaker 直调,物化 x_src/x_dst
  6a. non-TGN: reindex_graphs([[[data]]], reindexer, ...)
  6b. TGN:     compute_tgn_graphs(... max_node=query_max ...)   按当前图重建 LastNeighborLoader
  7.  model.reset_state() + model(data, inference=True)         torch.no_grad
  8.  compute_detector_score(out, data, cfg, ...)   4 分支:
      predict_edge_type     (orthrus / kairos)
      predict_node_type     (threatrace / flash / rcaid)
      reconstruct + magic   (magic)
      reconstruct_node_feat (nodlink / velox)
  9.  apply_threshold(node_list, thr, method)       p99/p98/p90/threatrace/flash/magic/nodlink
      orthrus 额外:_kmeans_top_k_labels(K=30)
```

#### 不变量

- δ 改 SQL → events / graph / forward / per-node score 全链路重算,无固化查表
- TGN `compute_tgn_graphs` 用 query 自带 `max_node` 新建 LastNeighborLoader,跨 query 无状态串号
- `model.reset_state()` 在 TGN forward 前清 memory,跨 query 不累积

#### `PIDSOracle`(attack query 包装)

| 入口 | 通路 |
|---|---|
| `PIDSOracle.pids_query(cmd_seq)` | `execute_in_range → trace_to_pidsmaker → predict`(raw graph-summary helper,不验 checker) |
| `query_with_validation_strict(scenario, δ_cmds, positions, oracle)` | `execute_with_checks(checker) → trace_to_pidsmaker → predict_per_node → filter GT/attack nodes`;checker 不过 → `QueryResult.invalid_` 不消耗预算。`attack/safemimic_cmd/runner.py` 和 `experiments/_common.py:make_oracle` 都直接调它 |

返回 `attack.framework.result.QueryResult`:
- `valid_(y=0|1, extra={trace_path, dump, n_flagged, gt_flagged_nodes, attack_detected, oracle_target})`
- `invalid_(failed_step, extra={reason})`

---

### PIDS oracle —— 数据采集(`detect collect`)

- **职责**:在 docker 容器内真录 N 份独立 benign syscall trace,转成 PIDSMaker 兼容 SQL 落到 `detection/data/training_traces/benign_<i>.sql`。**真采,不复制**(取代旧的 replicate_sql 假数据增强)。

- **代码**:
  - `detection/data/collect.py` — 采集实现
  - `scripts/run.py detect collect` — 公开入口
  - `detection/data/benign_collection_plan.yml` — 计划文件:容器配置 + 7 daemon 周期 + 10 scenario 池 + strace flags + 输出路径
  - `range/converter.py:trace_to_pidsmaker` — strace 文本 → CDM 图 → PIDSMaker SQL(STAGE 5 同款)
  - 复用 `pids_range` docker image(juice-shop + bash 工具齐全)

- **完整命令**:

```bash
# 默认单次(产 benign.sql)
python pids_attack/scripts/run.py detect collect

# N 次并行采集(产 benign_00.sql ... benign_<N-1>.sql,本项目主用法)
python pids_attack/scripts/run.py detect collect --num-collections 30 --parallel 4

# 缩短单份时长(yml 默认 1800s 太长,我们一般 300s 够训)
python pids_attack/scripts/run.py detect collect --num-collections 30 --parallel 4 --duration-override 300
```
- **逻辑**(嵌套调用,Python 在 host,bash 在容器):

```
[host Python] main() [L410]
  └── 分发 num-collections == 1 走 run_one_collection;否则走 run_parallel_collections
      │
      ▼
  run_parallel_collections(plan, n, parallel) [L385]
    └── ThreadPoolExecutor(max_workers=parallel):
          for i in range(n): pool.submit(run_one_collection, plan, f"pids_benign_{i:02d}", i)
        │
        ▼
    run_one_collection(plan, container_name, idx) [L327]    ★ 单份采集核心
      ├── 1. start_container [L78]            docker run --cap-add SYS_PTRACE 起容器 + 等 juice-shop ready
      ├── 2. time.sleep(warmup_sec)           默认 10s 让 juice-shop 稳定
      ├── 3. dump_proc_snapshot [L188]        docker exec ps -eo pid,ppid,exe,cmdline > proc_snapshot
      │                                        (供 trace 解析回填 cmdline / exe path)
      ├── 4. start_strace_with_orchestrator(name, plan) [L204]
      │       │
      │       ├── orch_text = build_orchestrator_script(plan) [L105]
      │       │       │       ↑↑↑ 这一步只是「生成 bash 文本」,在 host Python 里跑
      │       │       │
      │       │       └── 生成下面这段 bash 字符串(用 plan yml 数据拼出来):
      │       │             ─────────────────────────────────────────
      │       │             #!/bin/bash
      │       │             # Layer 2:7 个后台 daemon while-loop
      │       │             (sleep $offset_D1; while true; do pgrep -l bash; sleep 10; done) &
      │       │             (sleep $offset_D2; while true; do curl localhost:3000; sleep 30; done) &
      │       │             ...(D3 metric / D4 disk / D5 net / D6 backup / D7 cron)
      │       │
      │       │             # Layer 3:scenario 触发循环
      │       │             SCENARIOS=( sysadmin_daily_check / incident_triage / ... 共 10 )
      │       │             while [ ELAPSED < END ]; do
      │       │                if NOW >= NEXT_AT:
      │       │                    随机选 1 个 scenario
      │       │                    for slot in scenario.slots:
      │       │                        随机选 1 个 candidate command, eval 执行
      │       │                        sleep 1-3s
      │       │                    NEXT_AT = NOW + 随机间隔
      │       │                sleep 2
      │       │             done
      │       │             # 杀所有后台 daemon + wait
      │       │             ─────────────────────────────────────────
      │       │
      │       ├── docker exec -i bash -c "cat > /tmp/benign_orchestrator.sh"
      │       │   └── 把刚才生成的 bash 文本写进容器
      │       ├── docker exec chmod +x /tmp/benign_orchestrator.sh
      │       ├── pgrep -f "node build/app.js"     拿 juice-shop PID
      │       ├── [container] docker exec -d:
      │       │     strace_a = strace bash /tmp/benign_orchestrator.sh    ★ strace 包它跑(daemon + scenario)
      │       └── [container] docker exec -d:
      │             strace_b = strace -p <juice_shop_pid> -f              ★ strace attach juice-shop(应用层)
      │             (两路 strace 都 APPEND 写同一份 /tmp/benign.strace)
      │
      ├── 5. wait_loop                每 30s 打印一次 trace 文件大小,等 duration 完
      ├── 6. stop_strace [L259]       docker exec pkill -f strace
      ├── 7. docker cp                容器 /tmp/benign.strace + proc_snapshot → host 输出路径
      ├── 8. trace_to_pidsmaker       strace 文本 → CDM 图 → PIDSMaker SQL(range/converter.py)
      └── 9. finally                  docker rm -f 容器(无论成功失败都清)
```

**3 层数据 / 函数职责对照**:

| 函数 | 在哪跑 | 干啥 |
|---|---|---|
| `build_orchestrator_script` [L105] | host Python | 把 plan yml 的 7 daemon + 10 scenario 配置拼成 bash 文本字符串(不执行) |
| `start_strace_with_orchestrator` [L204] | host → container | 把 bash 文本灌进容器 + 起两路 strace 包它跑 |
| orchestrator.sh(生成的 bash) | container 内 | 真跑 daemon 循环 + scenario 触发循环,直到 duration 到 |
| strace_a + strace_b | container 内 | 旁观所有 syscall,写到 trace 文件 |

- **关键约束**:
  - **3 层数据**:Layer 1 = juice-shop 应用 syscall(D2 curl 触发的 access log);Layer 2 = 7 个系统周期 daemon(运维场景);Layer 3 = 10 个前台 scenario(人类操作模拟)
  - **strace 跟全容器**:`-fA -p 1 -f` + 单独 attach juice-shop,确保应用层 syscall 进 trace
  - **每份独立**:容器名唯一(`pids_benign_<idx:02d>`)+ 输出路径唯一(`benign_<idx:02d>.{strace,proc_snapshot,sql}`),并行不冲突
  - **fail-safe**:容器永远 `finally docker rm -f`,即便 strace 挂了也清干净
  - **耗时**(实测,Mac M-series,parallel 4):单份 300s strace + 60s juice-shop 启动 + 20s cp 转换 ≈ **~6.5min/份**,30 份共 **~50min 墙钟**
  - **运行时资源**:4 容器各 ~165MB RAM / 5-15% CPU,远低于 Mac 上限

- **输出**:`detection/data/training_traces/` 下 N 份:

```
detection/data/training_traces/
├── benign_00.strace            5-20 MB(原始 strace 文本)
├── benign_00.proc_snapshot     <1KB(ps -eo 输出)
├── benign_00.sql               ~6 MB(PIDSMaker 格式 INSERT)
├── benign_01.{strace,proc_snapshot,sql}
├── ...
└── benign_29.{strace,proc_snapshot,sql}
```

`benign_<i>.sql` 是 `detection/data/data_prep.py` 后续 ingest 的输入。

---

### PIDS oracle —— 训练(一次性,跑完已落盘)

- **职责**:把 PIDSMaker 8 个 detector 在 JUICESHOP 上各训一份,落盘到 `pids_attack/detection/training/artifacts/`(~4.6 GB,模型本身 ~80 MB,其余是 5 个 task 的中间 cache),供 STAGE 6 推理 load。**离线一次性**,跟 STAGE 6 完全分离。

- **代码**:
  - `detection/pidsmaker_setup.sh` — 一次性 bootstrap(幂等):clone `pids_attack/PIDSMaker` + 装 `requirements.txt` + 起 `pids_postgres` docker + 自检 detector cfg
  - `detection/data/collect.py` — **数据采集**:`detect collect --num-collections N --parallel K` 并行起 K 个 docker 容器各采一份独立 benign,产 `detection/data/training_traces/benign_<i>.sql` × N
  - `detection/data/data_prep.py` — **灌库层**:读 N 份 `training_traces/benign_*.sql` + 10 份 `test_traces/attack/*.strace.sql` → timestamp shift 到 fake-dates → 灌 `pids_postgres` → 写 Ground Truth
  - `scripts/run.py detect train-gnn` — **训练唯一入口**,5 step:overview / ingest / clean / train / eval(`--skip-ingest` / `--skip-clean` / `--skip-eval` 各自可关)

- **完整命令**:

```bash
# Step A:第一次,采集 30 份独立 benign(墙钟 ~50min,4 并行)
python pids_attack/scripts/run.py detect collect --num-collections 30 --parallel 4

# Step B:训练全套(灌库 + 清 cache + 训 8 detector + eval 报告)
python pids_attack/scripts/run.py detect train-gnn

# 后续 debug
python pids_attack/scripts/run.py detect train-gnn --skip-ingest -d orthrus
python pids_attack/scripts/run.py detect train-gnn --skip-ingest --skip-clean -d orthrus
python pids_attack/scripts/run.py detect train-gnn --skip-ingest --skip-clean
```

- **逻辑**(`python scripts/run.py detect train-gnn` 执行流):

```
scripts/run.py detect train-gnn:main()
  ├── Step 1  step_print_dataset_overview     打印数据集划分(fake-dates + 10 scenario 分布)
  ├── Step 2  step_ingest                     subprocess.run(python -m data_prep.juiceshop)
  │           ├── 前置检查:detection/data/training_traces/benign_*.sql 必须存在,否则 fail-fast
  │           └── detection/data/data_prep.py:ingest_juiceshop_dataset
  │                 ├── 读 benign_*.sql(N 份独立采集)
  │                 ├── 读 test_traces/attack/*.strace.sql(10 个 scenario)
  │                 ├── 各份 timestamp shift 到 fake-dates(US/Eastern 时区,跟 PIDSMaker 对齐)
  │                 │       - benign[i] → date = (TRAIN_DATES + VAL_DATES)[i % 4],hour = (i//4) % 24
  │                 │       - attack[i] → date = ATTACK_TO_DATE[i],同日多 attack 隔 2 小时
  │                 ├── 灌 PostgreSQL(无 replicate,真数据 N 份)
  │                 ├── reassign_global_unique_index_ids + fix_event_index_ids
  │                 └── write_ground_truth_from_db × 10 scenario → PIDSMaker/Ground_Truth/orthrus/JUICESHOP/
  ├── Step 3  step_clean_cache                rm detection/training/artifacts/{construction,...,evaluation}
  ├── Step 4  step_train                      for d in detectors:
  │           └── subprocess.run([python pidsmaker/main.py <d> JUICESHOP --cpu --artifact_dir ...],
  │                              env=PYTHONPATH=PIDSMAKER_DIR)
  │                 ↓
  │           pids_attack/PIDSMaker/pidsmaker/main.py 顺序跑 8 个 task(每 task hash cache,跑过跳过):
  │
  │             ① construction       build_default_graphs.py:gen_edge_fused_tw
  │                                  ├── 从 DB 读节点表 → indexid2msg
  │                                  └── 从 DB event_table 按 fake-date 切片 + BATCH=1024 切图
  │                                      → 落盘 nx.MultiDiGraph
  │             ② transformation     apply_graph_transformations(rcaid 走 pseudo_graph,其他 no-op)
  │             ③ featurization      训 word2vec / fasttext / 等 model
  │             ④ feat_inference     nx → CollatableTemporalData
  │             ⑤ batching           extract_msg + (TGN: compute_tgn_graphs / 非 TGN: reindex_graphs)
  │                                  ★ patch: compute_tgn_graphs return (datasets, neighbor_loader)
  │             ⑥ training           build_model + for epoch: forward/backward
  │                                  ★ patch: build_model 后绑 model.encoder.neighbor_loader
  │                                  ★ patch: save_model / load_model 严格逻辑(删 getattr 兜底)
  │                                  → save best_model/{state_dict, threshold, memory, neighbor_loader}.pkl
  │             ⑦ evaluation         读 ⑥ edge_losses csv → 用 cfg.threshold_method 算 y_preds
  │                                  → 落盘 scores_model_epoch_<N>.pkl(供 Step 5 eval 报告用)
  │             ⑧ triage             后处理,本项目不用
  │
  └── Step 5  step_eval                       detection.training.pidsmaker.eval_main(...)
              └── 读 ⑦ scores_model_epoch_<N>.pkl → 出 P/R/F1 + 10 scenario 表
```

**数据分配规则(timestamp shift 怎么落到 6 天)**:

```
benign 30 份 → 4 天(train + val)
  i % 4 决定哪天,i // 4 决定哪小时(轮流分)

attack 10 份 → 2 天(test)
  写死映射(5 个 → 01-05,5 个 → 01-06),同日隔 2 小时

shift = 把 SQL 里所有 timestamp 整体平移到「目标天那个小时」起点,
        事件之间相对时序保留
```

**4 处 PIDSMaker upstream patch(标 ★ 的位置)实际改的文件**:

| 文件 | 改动 | 修了什么 |
|---|---|---|
| `data_utils.py:compute_tgn_graphs` | return `(datasets,)` → `(datasets, neighbor_loader)` | 把局部变量传出来 |
| `data_utils.py:run_intra_graph_batching` + `load_all_datasets` + `tasks/batching.py:get_preprocessed_graphs` | 沿调用链一路 return neighbor_loader | 同上 |
| `training_loop.py:main` | build_model 后绑 `model.encoder.neighbor_loader = neighbor_loader` | 让 save_model 取到非 None |
| `data_utils.py:save_model` / `load_model` | 删 getattr 兜底,还原严格逻辑 | 上一步绑了就行 |

→ 上面 4 处 patch 只修 PIDSMaker 自己的 save_model bug(原版 batching 阶段建的 LastNeighborLoader 是局部变量,函数返回就丢,save_model 取它直接 AttributeError)。

**Threshold 新增 method(2026-05-11)**:`max_val_loss` 在 JUICESHOP val 集小且有 outlier 时把 threshold 顶到 attack 头上 → kairos/rcaid/velox 全 F1=0。新增 3 个 N 分位 method(`p99/p98/p90_val_loss`)绕开 outlier,3 个 detector F1 从 0 跃升至 0.49~0.81:

| 文件 | 改动 |
|---|---|
| `pidsmaker/utils/utils.py` | 加 `percentile_98` / `percentile_99` |
| `pidsmaker/detection/evaluation_methods/evaluation_utils.py` | `get_threshold` / `reduce_losses_to_score` / `calculate_threshold` 各加 3 分支 |
| `pidsmaker/config/config.py` | `THRESHOLD_METHODS` 列表加 `p90/p98/p99_val_loss` |
| `config/kairos.yml` | `max_val_loss` → `p99_val_loss` |
| `config/rcaid.yml` | `max_val_loss` → `p90_val_loss` |
| `config/velox.yml` | 加 override `threshold_method: p98_val_loss` |

- **关键约束**:
  - **不在 PIDSMaker 里塞 replicate_sql**(旧设计是 1 份 benign textual 复制 30 份补量,假数据);新设计是 `scripts/run.py detect collect --num-collections 30 --parallel 4` 真采 30 份独立 benign,假数据彻底删
  - 训练数据自采(`scripts/run.py detect collect` 在 docker 容器内跑 7 daemon + 10 benign scenario,strace 真录),attack/test trace 单独放在 `detection/data/test_traces/attack/`
  - 默认落盘 `pids_attack/detection/training/artifacts/`(项目内,持久);可用 `export PIDSMAKER_ARTIFACT_DIR=<custom>` 改
  - 训练耗时(实测,8 detector):flash ~521s(最久,word2vec)/ kairos ~176s / orthrus ~108s / 其他 < 50s,总 ~17min
  - **JUICESHOP / PIDSMaker fake-date 配置必须对齐两边**:`detection/data/data_prep.py:TRAIN_DATES/VAL_DATES/TEST_DATES/ATTACK_TO_DATE` ↔ `PIDSMaker/pidsmaker/config/config.py:JUICESHOP.train_dates/val_dates/test_dates/attack_to_time_window`,改一边记得改另一边

- **输出**:`pids_attack/detection/training/artifacts/` 下 8 个 detector 各自一个 `<cfg-hash>` 目录(互不冲突):

```
pids_attack/detection/training/artifacts/
├── construction/JUICESHOP/<hash>/         # nx 图(每 fake-date 一个 dir)
├── transformation/JUICESHOP/<hash>/       # nx → nx(rcaid 走 pseudo_graph)
├── featurization/JUICESHOP/<hash>/        # word2vec / fasttext model
├── feat_inference/JUICESHOP/<hash>/       # CollatableTemporalData
├── batching/<hash>/                       # PyG batches + neighbor_loader
├── training/training/<hash>/JUICESHOP/trained_models/
│     ├── best_model/state_dict.pkl        # ← STAGE 6 load 这个
│     ├── best_model/threshold.pkl         # ← STAGE 6 load 这个
│     ├── best_model/memory.pkl            # (TGN only:orthrus / kairos)
│     ├── best_model/neighbor_loader.pkl   # (TGN only)
│     └── model_epoch_<N>/state_dict.pkl   # 中间 epoch 备份
├── evaluation/evaluation/<hash>/JUICESHOP/precision_recall_dir/
│     └── scores_model_epoch_<N>.pkl       # PIDSMaker 自己 evaluation 输出(STAGE 6 不查)
└── triage/triage/<hash>/                  # 后处理,推理不用
```

  验收(8/8 都过):8 个 `best_model/state_dict.pkl` 都落盘 ✓ · TGN(orthrus / kairos)`memory.pkl` + `neighbor_loader.pkl` 都落盘 ✓ · 8 detector 全跑完 evaluation 产出 `scores_model_epoch_<N>.pkl` ✓

---

### PIDS oracle —— 训练完成验收

- **职责**:跑完上面训练后,看 8 detector 在 test set 上的真实 precision / recall / F1 + 10 个 scenario 各自的命中。该报告是 `detect train-gnn` 的内部 Step 5,由 PIDSMaker evaluation 产物计算。

- **代码**:`detection/training/pidsmaker.py:eval_main` — 读训练时落盘的 `scores_model_epoch_<N>.pkl`,出整体 + 10 scenario 拆分指标。

- **逻辑**:

  ```
  detect train-gnn 内部 Step 5
  ↓
  for d in detectors:
    load scores_model_epoch_<latest>.pkl           ← ⑦ evaluation 落盘的
    y_preds, y_truth, node2attacks, nodes = pkl[...]
    compute_metrics:
      整体 TP / FP / FN / TN / precision / recall / f1
      per-scenario TP / GT / recall(10 个 attack scenario 各自的命中)
    打印整体 + 10 scenario 表
  最后打印 8 detector 汇总对比表(按 F1 降序)
  ```

- **关键约束**:eval_pidsmaker 看到的指标是 PIDSMaker 自己算的,我们这边不参与计算 —— 论文阶段直接引用这些数字也站得住脚。

- **输出**(本次 30 份真采 + 重训实测,2026-05-11):

  `unittest discover tests` 期望:**Ran 100 tests, OK**(0 fail / 0 expected failure)

  `detect train-gnn` 内部 Step 5 输出 8 detector × P/R/F1:

  | detector | yp_sum | TP / FP / FN / TN | Precision | Recall | F1 | 状态 |
  |---|---|---|---|---|---|---|
  | **kairos** | 63 | 63 / 0 / 30 / 453 | **1.00** | 0.68 | **0.81** | ✅ 最佳(p99_val_loss ⚙) |
  | **threatrace** | 109 | 74 / 35 / 19 / 418 | 0.68 | 0.80 | 0.73 | ✅ |
  | **velox** | 100 | 64 / 36 / 29 / 417 | 0.64 | 0.69 | 0.66 | ✅ (p98_val_loss ⚙) |
  | **rcaid** | 90 | 45 / 45 / 48 / 408 | 0.50 | 0.48 | 0.49 | ✅ (p90_val_loss ⚙) |
  | **magic** | 292 | 80 / 212 / 13 / 241 | 0.27 | 0.86 | 0.42 | ✅ 高 recall 低 precision |
  | **orthrus** | 16 | 16 / 0 / 77 / 453 | **1.00** | 0.17 | 0.29 | ✅ 完美 precision 低 recall |
  | nodlink | 89 | 4 / 85 / 89 / 368 | 0.04 | 0.04 | 0.04 | ⚠️ 有检出但乱 |
  | flash | 0 | 0 / 0 / 93 / 453 | 0.00 | 0.00 | 0.00 | ❌ 全漏(模型未学到) |

  **7/8 检测有效,只有 flash 全漏**(SAGE + 公式 0.53 在 JUICESHOP 不开火)。
  ⚙ = 改了 threshold method:`max_val_loss` 在 JUICESHOP val 集 outlier 上失效(F1=0),
  切到 N 分位绕开 outlier 后 F1 跃升(kairos 0→0.81 / velox 0→0.66 / rcaid 0→0.49)。

---

### PART C — 显式 attack mode

#### `scripts/run.py attack run` · SafeMimic-CMD 主循环 + verbose query 日志
- **职责**:在 PART B(stage 2-6 验证 oracle 可用)的基础上,跑黑盒攻击循环 ——
  attacker 每轮选 δ 扰动 → 容器执行 + checker 验证 + PIDS 推理 → 拿到 (y, valid) → 更新搜索状态,
  直到 PIDS 报 benign(y=0)或耗尽 query 预算
- **关键代码**:`scripts/run.py:attack_main` + `attack/safemimic_cmd/runner.py::run_attack(cfg)` → `attack/safemimic_cmd/search/sequential.py`
- **输入**:`scenario + candidate_pool + query_fn`
- **输出**:`AttackResult { history, best_candidate, converged }` + JSON summary

##### 调试用法

```bash
# 攻击前阶段验证(STAGE 0-6 跑通,~30 秒)
conda run -n mimicattack python pids_attack/scripts/run.py attack smoke-query

# 不碰 docker / detector 的算法 smoke
PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/scripts/run.py attack run \
  --scenario 01 --detector magic --mock --B-max 4 --T-GA 2 --m 3
```

---

### attack/ 核心设计(attack mode 内部)

PART C 只有 2 个核心问题,每节按统一 7-template 展开(核心问题&动机 / 输入 / 输出 / 核心设计方案 / 方案 justify / 参考 / 实验设计 + finding)。

#### 7.1 搜索空间(δ 表示 + 变异原语)

**1. 核心问题 && 动机**
δ 怎么表示才能既覆盖所有可能的扰动,又能逐步演化?对应需要哪些变异原语?

**2. 输入**
A0(攻击命令序列)

**3. 输出**
- δ 表示:`δ = [(p_1, c_1), ..., (p_k, c_k)]`,p_i ∈ {0..n-1},c_i ∈ candidate 命令集合,k ∈ [0, K_max]
- 4 个变异原语:**ADD / REMOVE / REPLACE_CMD / MOVE_POSITION**

**4. 核心设计方案**

δ 由 **3 维**构成:size `k` / position `p_i` / command `c_i`。

每维至少一个 op:

| op | 改变 | 含义 |
|---|---|---|
| **ADD** | size↑ | 加一个 (p, c) 元素 |
| **REMOVE** | size↓ | 删 δ 中某元素 |
| **REPLACE_CMD** | c↻ | 改某位置的命令 c,p 不变 |
| **MOVE_POSITION** | p↻ | 改某元素位置 p,c 不变 |

（c 具体从哪个集合取见 7.2,本节只定义搜索空间结构与 op 集合。）

**5. 方案 justify**
- **必要性**:δ 三维每维都得有「能改」的操作,否则那一维搜不动
- **完备性**:任何 δ → δ' 都能用 4 op 有限步组合
- **不冗余**:任两个 op 互不替代,Swap = 2 次 MOVE_POSITION,故省略

**6. 参考**
- TextBugger (NDSS 2019) §III.A + Table I —— 5 种 bug,沿用 Insert / Delete / Sub-W 对应 ADD / REMOVE / REPLACE_CMD
- BagAmmo (USENIX Sec 2024) §4 Methodology —— GA 个体 δ + add/remove/replace operator

**7. 实验设计 + finding**

**① 实验设计:单策略 evasion 刻画**

设置:
```
固定:    8 detector × 10 scenario × query_budget = 50
变量:    单 op 模式(4 变体)+ ALL-4 对照
重复:    每 (detector, scenario, op) 跑 5 个 random seed
初始:    δ_0 = ∅(从 A0 起步,已确认 y=1)
```

每轮 query 只用一个 op,记录逐步 (t, |δ|, op, y_before, y_after, op_args)。

**② 预期 finding(为 7.2 设计铺垫)**
- F1. **单种变异的影响** —— 每个 op 单独使用的 evade 能力
- F2. **组合变异的影响** —— 任意 op 子集组合(单 / 双 / 三 / 全 4)+ 不同应用顺序的 evade 能力对比,看哪些组合互补、哪些冗余、顺序是否影响结果
- F3. **每种变异最有效的时机** —— 在 δ 的什么状态下(早 / 中 / 后期)某个 op 最容易让 y 翻转

---

#### 7.2 黑盒攻击循环(三阶段贝叶斯自适应)

**1. 核心问题 && 动机**

decision-based(y ∈ {0,1})+ 检测器结构未知,3 件事必须在同一循环里**串行**解决:

- **Q1. 不知道检测器类型** → 不同类型(node / edge / graph)对不同 op 敏感度不同 → 先要"心里有数"
- **Q2. 知道(或带 belief)类型** → 该选哪种变异?
- **Q3. 选定了变异** → 命令库万级,怎么从中挑 c?

→ 设计成 **三阶段贝叶斯条件决策**,每步用 belief 来 condition 下一步。

**2. 输入**

```
A0                              # 攻击命令序列
4 op                            # 7.1 定义的变异原语
命令大空间 Ω                    # 系统 binary + GTFOBins ≈ 数千
syscall 特征 φ : Ω → R^k        # offline 一次性提取每条 c 的 syscall 直方图
Θ_op[type]                      # 来自 7.1 实验:每个 (op, type) 组合的 y=0 经验概率
oracle: A0 ⊕ δ → y ∈ {0,1}      # decision-based 反馈
```

**3. 输出**

```
δ*           # 成功 evade 的 δ(若有)
b_final      # 收敛的检测器类型 belief(可解释:p_node / p_edge / p_graph)
C ⊆ Ω        # 在线积累的成功命令子集
```

**4. 核心设计方案 — 三阶段循环**

**维护的状态**

```
b_t = (p_node, p_edge, p_graph)         # 检测器类型 belief,初始 (1/3, 1/3, 1/3)
δ_t                                      # 当前接受的扰动
(θ_c, A_c, b_c)                          # LinUCB over c 的参数
History H_t = [(op_τ, c_τ, y_τ)]_{τ<t}   # 全部 query 历史
```

**Step 1 — 检测器类型 belief 更新(回答 Q1)**

```
看到上一步 (op_{t-1}, c_{t-1}, y_{t-1}),贝叶斯更新:

  L(y | op, c, type) ← 来自 7.1 实验拟合的 likelihood 表
     (例:type=edge 时 op=MOVE 的 P(y=0) = 0.42)

  p(type | H_t) ∝ L(y_{t-1} | op_{t-1}, c_{t-1}, type) · p(type | H_{t-1})

  归一化 → b_t
```

★ `L(y | op, c, type)` 是 **7.1 实验产物**,把 motivation 实验与 7.2 算法绑死。**没有 7.1 = belief 无法更新**。
★ 直观:每查一次,b_t 就更尖一点;前 ~10 query 大概率收敛到某一类(p_某 > 0.7)。

**Step 2 — 变异策略选择(回答 Q2,基于 b_t)**

```
方式 A — Thompson Sampling(默认):
  type_sample ~ b_t                    # 从 belief 抽一个 type
  op* = argmax_op  Θ_op[type_sample]    # 抽到的 type 下最优 op

方式 B — Bayesian expected value:
  op* = argmax_op  Σ_type b_t[type] · Θ_op[type]
```

★ belief 散 → Thompson sampling 自动多样化探索;belief 尖 → 几乎确定选最优 op;**不需要硬阈值切换,平滑过渡**。

**Step 3 — 命令选择(回答 Q3,基于 op*)**

```
仅当 op* ∈ {ADD, REPLACE_CMD},否则跳过:

LinUCB over Ω,共享参数 (θ_c, A_c, b_c):

  对每个 c ∈ Ω:
    μ_c = θ_c^T φ(c)
    UCB_c = μ_c + α · √( φ(c)^T A_c^{-1} φ(c) )

  c* = argmax_{c ∈ Ω} UCB_c
```

★ 参数只 k ≈ 10 维(syscall 类别数)不是 per-c → 万级 Ω 不爆。
★ 没见过的 c'(若 φ(c') ≈ φ(c_succeeded))自动继承高 UCB → **隐式聚类**:syscall feature 近邻共享信用,无 offline cluster 步骤。

**Step 4 — 应用变异 + Query**

```
δ_t' = apply(δ_t, op*, c*)
y_t = oracle(A0 ⊕ δ_t')
```

**Step 5 — 三组后验联合更新**

一次 y_t 同时驱动:

```
① b_t → b_{t+1}                # Step 1 的贝叶斯更新

② LinUCB:
   A_c ← A_c + φ(c*) φ(c*)^T
   b_c ← b_c + r · φ(c*)        ,r = (y_t == 0) ? 1 : 0
   θ_c = A_c^{-1} b_c

③ δ 推进:
   y=0 → δ_{t+1} = δ_t';c* 加入 C
   y=1 + op=ADD → 保留 δ_t'(允许临时退化)
   y=1 + op=REMOVE → 回滚 δ_t' = δ_t
   y=1 + op=REPLACE/MOVE → 视 b_t 决定接受/丢
```

**Step 6 — 终止判定**

```
连续 k 次 y=0  OR  query budget 耗尽  → 停
```

**5. 方案 justify**

- **三阶段条件式 sequential decision**,清晰对应三个核心问题:
  - Q1 检测器推断 → Step 1 维护 belief b_t
  - Q2 变异策略   → Step 2 condition on b_t
  - Q3 命令选择   → Step 3 condition on op* + φ(c)
- 同一 y_t **同时更新三组后验**(belief / LinUCB / δ),不重复消耗 budget
- **belief 是显式可解释变量**(p_node / p_edge / p_graph),可画 belief 随 query 数收敛曲线,非黑盒
- **LinUCB 在 syscall feature 上学**,把万级 c 压成 k 维问题,query 复杂度 O(|Ω|) → O(k)
- `L(y | op, c, type)` 由 7.1 实验提供,**实验—算法形成完整证据链**

**6. 参考**

**主线:基于黑盒历史信息的 Bayesian 对抗样本生成**
- Ilyas et al., *Prior Convictions: Black-Box Adversarial Attacks with Bandits and Priors*, **ICLR 2019** —— bandit + 时空 prior(score-based)
- Ru et al., *BayesOpt Adversarial Attack*, **ICLR 2020** —— GP-based Bayesian Optimization(score-based)
- Shukla et al., *Simple and Efficient Hard Label Black-box Adversarial Attacks in Low Query Budget Regimes*, **KDD 2021** —— 低 query hard-label,最接近本工作 threat model
- Cheng et al., *Efficient Black-box Adversarial Attacks via Bayesian Optimization Guided by a Function Prior*, **ICML 2024** —— BO + function prior 引导,query-efficient

**我们的延展点**:posterior 对象从输入扰动空间 → **扩展到检测器类型隐变量空间**,适配 PIDS 域异构检测器(node / edge / graph)。

**Supporting**
- LinUCB(Li et al. WWW'10)—— feature-based contextual bandit
- HQA-Attack(NeurIPS'23)/ TextHoaxer(AAAI'22)—— hard-label 离散域 c 选择

**7. 实验设计 + finding**

三个实验 = 三个核心问题,每个直接驱动 7.2 主循环的一个 stage:

```
Q1. 估计    → E1 → 产出 Θ_op[type]               → 喂给 Step 1 + Step 2
Q2. 指导    → E2 → 验证 prior 能否有效指导搜索   → 验证 Step 1 + Step 2 必要性
Q3. 选命令  → Archived Q3 → 用历史信息在大空间选 c        → 验证 Step 3 设计
```

---

**E1 — 策略-检测器敏感性测量(驱动 Step 1 likelihood)**

```
任务:测「不同 op 对不同 detector 是否有敏感性差异」
      有差异 → Θ_op[type] 可估计 → Step 1 / Step 2 成立
      无差异 → Bayesian 框架前提失效,得改方案

Detector 按论文原文的训练目标(学习 loss)分 3 类:

   edge prediction      (边类型预测,self-supervised):
                        orthrus (Sec'25), kairos (S&P'24), velox (Sec'25)

   node classification  (节点类型分类,supervised):
                        threatrace (TIFS'22), flash (S&P'24), rcaid (S&P'24)

   reconstruction       (掩码 / VAE 重构 node feature 或 graph 结构):
                        magic (Sec'24), nodlink (NDSS'24)

   注:evaluation 阶段 8 个 detector 都输出节点级 anomaly score(论文层面都
       claim node-level detection),但训练目标 / loss 信号源不同 → 对不同
       op 的敏感性预期不同 → 这正是 E1 要测的对象

belief 隐变量:
   type ∈ {edge_prediction, node_classification, reconstruction}  (维度 3)

设计:对每个 (detector, op) 跑大量随机 c / 随机参数的单步注入:
       8 detector × 4 op × 100 random sample × 5 seed
       offline 一次性,~16000 query

核心 finding:
  Θ_op[type] 表填出来(3 type × 4 op = 12 个数),
  且类型间差异显著(类型内方差 << 类型间方差)
     → 这张表 = Cheng ICML'24 意义的 function prior
     → 喂给 Step 1 likelihood + Step 2 Thompson sampling
```

---

**E2 — 用 E1 prior 跑在线攻击(对应 Cheng ICML 2024 创新范式)**

```
任务:E1 已给出 Θ_op[type] 表。E2 用这表跑 7.2 完整攻击循环,验证:
      ① belief b_t 能否随 query 数正确收敛到真实 detector type?
      ② 一旦 belief 收敛,后续 op 选择是否对齐到最优,攻击是否快速成功?

      → 这正是 Cheng ICML'24 的核心创新:offline 训 prior → online 用 prior 加速

设置:8 detector × 10 scenario × budget = 50 × 5 seed
      用 E1 给的 Θ_op[type] 表,b_0 = (1/3, 1/3, 1/3) 均匀初始

度量:
  ① belief 收敛曲线:‖ b_t − δ(true_type) ‖ 随 t 的变化
  ② time-to-convergence:多少 query 后 b_t 尖到 max_type p > 0.7
  ③ time-to-first-success:首次拿到 y=0 的 query 数
  ④ ASR @ budget=50

核心 finding:
  - belief 几步内收敛到真实 detector type(可解释、可视化)
  - 收敛后 op 选择立刻锁定到该 type 的最优 op
  - ASR 远高于无 prior baseline(论文主卖点)
  - 论文可写:"沿用 Cheng ICML'24 offline-prior / online-attack 范式,
              在 hard-label PIDS setting 下首次落地"
```

---

**Archived Q3 — 历史信息驱动的命令选择(驱动 Step 3 LinUCB)**

```
任务:命令大空间 Ω ≈ 数千,如何用历史 H 高效选下一个 c?

设计:固定 detector,固定 op = ADD(或 REPLACE_CMD),对比 3 种选 c 策略:
  S1  Random Uniform        从 Ω 均匀采(完全不学,baseline)
  S2  Per-c Counter         每条 c 维护成功计数加权采(学,但不会泛化:
                            没见过的 c 永远是 0)
  S3  LinUCB + syscall φ(c) ★ 本方案,k-dim syscall feature
                            μ_c = θ_c^T φ(c),UCB_c = μ_c + α√(...)
                            (学 + 泛化:syscall 相似的 c 共享 reward)

  8 detector × 3 策略 × 50 query × 5 seed

核心 finding:
  ① S3 比 S1 / S2 快 ≥ 3× 找到首个 successful c
     → 证明 LinUCB + syscall feature 比随机 / 无泛化方案优
  ② S3 选出的 successful c 中 ≥ 30% 是从未直接 query 过的
     → syscall feature 实现"隐式聚类",相似命令共享信用
     → Step 3 设计在 PIDS 域有效
```

---

**实验—设计—文献 闭环**

```
E1 ──→ 产 Θ_op[type] ────────→ 喂 Step 1 likelihood + Step 2 Thompson
E2 ──→ 验证 prior 有效性 ─────→ 验证 Step 1 + Step 2 设计,引 Cheng ICML'24
Archived Q3 ──→ 验证 LinUCB + syscall ──→ 验证 Step 3 设计,query 复杂度 O(|Ω|) → O(k)
```

---

## 参考文献

**直接相关**
- [BagAmmo](https://www.usenix.org/conference/usenixsecurity24/presentation/li-yikun)(USENIX Sec'24)— 唯一参考的 mimicry attack 框架
- [Mimicry Attacks against Provenance HIDS](https://gangw.cs.illinois.edu/ndss23-mimicry.pdf)(NDSS'23)
- PIDSMaker(USENIX Sec'25)— PIDS oracle + CDM schema · [GitHub](https://github.com/ubc-provenance/PIDSMaker) · [Paper](https://arxiv.org/abs/2601.22983) · [Docs](https://ubc-provenance.github.io/PIDSMaker)
- DARPA Transparent Computing — CDM 格式 · [Repo](https://github.com/darpa-i2o/Transparent-Computing) · [CDM Schema](https://github.com/darpa-i2o/Transparent-Computing/blob/master/schema/TCCDMDatum.avsc)

**黑盒攻击 SoK / Framework**
- BlackboxBench(arXiv 2023)— unified pipeline 4 functional blocks · [Paper](https://arxiv.org/abs/2312.16979) · [Code](https://github.com/SCLBD/BlackboxBench) · [Site](https://blackboxbench.github.io/)
- FoolBox(JOSS 2017/2020)— Attack = model + criterion + distance · [Paper](https://arxiv.org/abs/1707.04131) · [Code](https://github.com/bethgelab/foolbox) · [Docs](https://foolbox.readthedocs.io)
- [ART](https://github.com/Trusted-AI/adversarial-robustness-toolbox)([Paper](https://arxiv.org/abs/1807.01069)) / [CleverHans](https://github.com/cleverhans-lab/cleverhans) / [AdverTorch](https://github.com/BorealisAI/advertorch) / [DEEPSEC](https://github.com/kleincup/DEEPSEC) / [SecML](https://github.com/pralab/secml) / [DeepRobust](https://github.com/DSE-MSU/DeepRobust)
- [SoK: Pitfalls in Evaluating Black-Box Attacks](https://arxiv.org/abs/2310.17534)(SaTML'24)— 4 维 threat model · [Code](https://github.com/iamgroot42/blackboxsok)
- [Black-Box Adversarial Attacks: A Survey](https://ieeexplore.ieee.org/document/9984916)(IEEE 2022)

**经典算法**
- [Practical Black-Box](https://arxiv.org/abs/1602.02697)(AsiaCCS'17)/ [Boundary Attack](https://arxiv.org/abs/1712.04248)(ICLR'18)/ [NES](https://arxiv.org/abs/1804.08598)(ICML'18)
- [HSJA](https://arxiv.org/abs/1904.02144)(S&P'20, [code](https://github.com/Jianbo-Lab/HSJA))/ [Square](https://arxiv.org/abs/1912.00049)(ECCV'20, [code](https://github.com/max-andr/square-attack))/ [Sign-OPT](https://arxiv.org/abs/1909.10773)(ICLR'20, [code](https://github.com/cmhcbb/attackbox))
- [Opt-Attack](https://arxiv.org/abs/1807.04457)(ICLR'19)/ [Bandits Attack](https://arxiv.org/abs/1807.07978)(ICLR'19)/ [Bayes-Attack](https://arxiv.org/abs/2007.07210)(BMVC'20)
- [GeoDA](https://arxiv.org/abs/2003.06468)(CVPR'20)/ [QEBA](https://arxiv.org/abs/2005.14137)(CVPR'20)
- [BASES](https://arxiv.org/abs/2208.03610)(NeurIPS'22)/ [Learning to Query](https://openreview.net/forum?id=pzpytjk3Xb2)(ICLR'22)
- [Copy-Paste Initialization](https://arxiv.org/abs/1906.06086)(初始化相关)

**数据来源**
- A_0:[Cybench](https://github.com/andyzorigin/cybench)([site](https://cybench.github.io/), [paper](https://arxiv.org/abs/2408.08926))/ [PentestGPT](https://github.com/GreyDGL/PentestGPT)([paper](https://arxiv.org/abs/2308.06782))/ [Juice-Shop](https://github.com/juice-shop/juice-shop)([OWASP](https://owasp.org/www-project-juice-shop/))
- C:[GTFOBins](https://gtfobins.github.io/)([repo](https://github.com/GTFOBins/GTFOBins.github.io))/ [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)([site](https://atomicredteam.io/))/ [LOLBAS](https://lolbas-project.github.io/)([repo](https://github.com/LOLBAS-Project/LOLBAS), 备选)/ [LOOBins](https://www.loobins.io/)([repo](https://github.com/infosecB/LOOBins), 备选)

**采集工具**
- [sysdig](https://github.com/draios/sysdig) — Linux syscall 采集
- [auditd](https://github.com/linux-audit/audit-userspace) — Linux audit 子系统
