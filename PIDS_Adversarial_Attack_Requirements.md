# 黑盒命令级 PIDS 对抗攻击算法 — Claude 实施需求文档

**目标级别：** 四大安全顶会（S&P / CCS / USENIX Security / NDSS）论文实现质量

---

## 0. 给 Claude 的总体说明

本项目实现一个面向四大安全顶会论文的黑盒命令级对抗攻击算法。文档严格遵循黑盒对抗样本生成领域的标准模块化结构，参考 BlackboxBench、FoolBox、SoK Pitfalls 等领域权威工作。

**Claude 的实施原则：**

1. **完整搭建**所有标记为"确定"的基础设施
2. **针对每个研究问题（标记 【研究问题】），完整实施所有候选方案**——禁止只挑一个实施
3. **模块化设计**通过依赖注入支持自由组合所有候选方案
4. **提供完整实验脚本**让用户能跑对比实验
5. **顶会级别的工程质量**：完整测试、详细日志、可复现实验

**实施过程中 Claude 禁止的行为：**

- 凭空选定研究问题的某个方案而不实施其他方案
- 跳过模块测试
- 凭空决定超参数（必须参数化、可调优）
- 跳过文档撰写
- 跳过 checker 机制（直接相信攻击命令一定执行成功）

---

## 1. 项目目标

实现一个黑盒命令级对抗攻击算法，达到顶会论文实验所需的完整性。算法在 Docker 靶场内执行命令，通过查询基于 PIDSMaker 搭建的 PIDS oracle 拿到 binary 反馈，在命令空间通过迭代优化找到 camouflage 命令组合 δ，使原始攻击 A_0 ⊕ δ 被判定为 benign。

**论文层面的核心贡献预期：**

- 首个真实问题空间下针对未知异质 PIDS 的黑盒攻击
- 基于黑盒对抗样本生成领域标准模块化结构的系统性研究
- 跨 detector 类型（GNN / rule / hybrid）鲁棒性验证
- 完整开源实施可复现

---

## 2. Threat Model（确定）

**攻击者位置：** 通过 `docker exec` 进入 target 容器执行命令

**攻击者输入：** 完整命令序列（恶意命令 A_0 + camouflage 命令 δ）

**攻击者输出：** binary 反馈 y（0 = benign, 1 = malicious）

**SoK Pitfalls (SaTML 2024) 四维分类下的定位：**

| 维度 | 取值 | 说明 |
|---|---|---|
| Query Access | Interactive Access ✓ | 攻击者可 query target |
| Feedback Granularity | Hard-label | 只拿到 top-1 预测 |
| Auxiliary Data Quality | 无重叠 | 无防御方训练数据 |
| Auxiliary Data Quantity | Insufficient | 几乎没有辅助数据 |

**参考：** SoK: Pitfalls in Evaluating Black-Box Attacks (SaTML 2024) — https://arxiv.org/abs/2310.17534

---

## 3. 数据来源（确定）

### 3.1 恶意攻击命令序列 A_0

**Cybench**（Stanford CTF benchmark）

- https://cybench.github.io/
- https://github.com/andyzorigin/cybench
- 论文：https://arxiv.org/abs/2408.08926

**PentestGPT**（LLM 自动化渗透测试）

- https://github.com/GreyDGL/PentestGPT
- 论文：https://arxiv.org/abs/2308.06782

**Juice-Shop**（OWASP 脆弱 Web 应用）

- https://github.com/juice-shop/juice-shop
- https://owasp.org/www-project-juice-shop/

**实施要求：** 收集**至少 10 个**攻击场景，每个场景必须包含 step checkers（详见第 5.4 节），保存为 JSON 格式（结构在第 5.4 节定义）。

存储在 `data/attack_sequences/`。

### 3.2 候选 camouflage 命令池 C

**GTFOBins**（Living off the Land for Linux）

- https://gtfobins.github.io/
- https://github.com/GTFOBins/GTFOBins.github.io

**Atomic Red Team**（MITRE ATT&CK 测试用例）

- https://github.com/redcanaryco/atomic-red-team
- https://atomicredteam.io/

**LOLBAS**（Windows 参考，备选）

- https://lolbas-project.github.io/
- https://github.com/LOLBAS-Project/LOLBAS

**LOOBins**（macOS 参考，备选）

- https://www.loobins.io/
- https://github.com/infosecB/LOOBins

**筛选准则：**

- 保留：只读文件操作、进程系统查询、本地网络探测
- 排除：写文件类、长生命周期 fork、触碰 attack-essential 路径、需要特权

**实施要求：** 构造 **150-300 条**候选命令，存储在 `data/candidate_pool.txt`，每行一条。

---

## 4. PIDS Oracle（确定）

### 4.1 PIDSMaker 选型

**使用 PIDSMaker**

- https://github.com/ubc-provenance/PIDSMaker
- 论文：https://arxiv.org/abs/2601.22983（USENIX Security 2025）
- 文档：https://ubc-provenance.github.io/PIDSMaker

**PIDSMaker 的 7-stage pipeline：**

1. `construction.py` — 解析 raw provenance + 构建 graph
2. `transformation.py` — graph transformations
3. `featurization.py` — text embedding (Word2Vec/Doc2Vec)
4. `batching.py` — batch construction
5. `training.py` — GNN training + inference
6. `evaluation.py` — metrics + plots
7. `triage.py` — optional post-processing

**节点类型（3 种）：**

- `subject` — Process/thread (cmd line, exec path)
- `file` — File/directory (file path)
- `netflow` — Network connection (IP, port)

**边类型（10 种）：**

EVENT_READ / EVENT_WRITE / EVENT_OPEN / EVENT_EXECUTE / EVENT_CONNECT / EVENT_RECVFROM / EVENT_RECVMSG / EVENT_SENDTO / EVENT_SENDMSG / EVENT_CLONE

**支持的 detector（实验时切换）：**

- `orthrus` (USENIX Sec'25)
- `kairos` (S&P'24)
- `magic` (GNN-based)
- `flash` (S&P'24, node-level)
- 其他 PIDSMaker 内置 detector

参考：https://ubc-provenance.github.io/PIDSMaker/tuned_systems/

### 4.2 PIDSMaker 输入格式适配（确定）

PIDSMaker 的输入是 DARPA TC 的 **CDM (Common Data Model) schema**，存储在 PostgreSQL 数据库中。原始格式是 Avro/JSON，schema 文件是 `TCCDMDatum.avsc`。我们用 sysdig 采集的 syscall 数据必须转换成这个格式才能送入 PIDSMaker。

**实施 `range/converter.py`：**

```python
def sysdig_to_pidsmaker(
    sysdig_trace_file: str,        # sysdig采集的.scap文件
    output_db_dump: str,           # 输出的PostgreSQL dump文件
) -> None:
    """
    转换流程：
    1. 用 sysdig 工具把 .scap 解析成 syscall 事件流
    2. 把每个 syscall 事件映射成 CDM schema 的事件:
       - syscall: read/open/openat → EVENT_READ/EVENT_OPEN
       - syscall: write/writev → EVENT_WRITE
       - syscall: execve → EVENT_EXECUTE
       - syscall: connect → EVENT_CONNECT
       - syscall: clone/fork → EVENT_CLONE
       - syscall: send*/recv* → EVENT_SEND*/EVENT_RECV*
    3. 节点提取:
       - 进程（PID + exec path）→ subject 节点
       - 文件路径 → file 节点
       - socket（IP:port）→ netflow 节点
    4. 写入 PostgreSQL，schema 与 PIDSMaker 一致
    """
```

**关键参考：**

- DARPA TC 官方仓库：https://github.com/darpa-i2o/Transparent-Computing
- CDM schema：https://github.com/darpa-i2o/Transparent-Computing/blob/master/schema/TCCDMDatum.avsc
- CDM 文档：https://github.com/darpa-i2o/Transparent-Computing/blob/master/schema/cdm.pdf
- PIDSMaker 的 create_database 脚本可作为参考实施：`dataset_preprocessing/darpa_tc/create_database_e3.py`

**实施关键点：**

- 字段映射完整（覆盖 3 种节点 + 10 种边）
- 时间戳格式对齐（CDM 使用 nanoseconds since epoch）
- UUID 字段保证唯一性
- 直接生成 PostgreSQL 填库脚本，跳过 Avro 序列化以简化实施

### 4.3 PIDSMaker 小数据集训练（确定）

**不使用** PIDSMaker 的 DARPA TC 大数据集（数十 GB，单次跑数小时）。用 Docker 靶场实时生成的小规模 benign 数据训练 baseline detector。

**实施 `oracle/train_pidsmaker.py`：**

```python
def collect_benign_data(num_samples: int = 80) -> List[ProvenanceTrace]:
    """
    在靶场内执行多种benign行为，采集训练数据
    benign行为包括:
    - 启动Juice-Shop并正常运行
    - curl/wget访问Juice-Shop合法接口
    - 执行常见Linux命令(ls, ps, cat等)
    - 正常Web交互(登录、浏览商品、加购物车等)
    返回 num_samples 个provenance trace
    """

def train_baseline_detector(
    benign_traces: List[ProvenanceTrace],
    detector_name: str,
    custom_config: dict,
) -> Detector:
    """
    1. 把 benign traces 转换成 PIDSMaker 输入格式（CDM）
    2. 灌入 PostgreSQL
    3. 用 PIDSMaker 的训练 pipeline 训练 detector
    4. 在小数据集上验证（loss收敛、threshold校准）
    5. 返回训练好的 detector
    """

def setup_pidsmaker_for_attack(detector_name: str = "orthrus") -> Detector:
    """
    主入口：
    1. 检查是否已有训练好的baseline detector
    2. 如果没有，调用 collect_benign_data + train_baseline_detector
    3. 返回 detector
    """
```

**数据集规模：**

- 训练集：80 个 benign traces
- 验证集：20 个 benign traces（用于阈值校准）
- 测试集：10 个 malicious traces（sanity check：未 camouflage 的 A_0 应被检测到）

**小数据集配置（custom_small.yml）：**

```yaml
training:
  num_epochs: 50
  batch_size: 16
  early_stopping: true
featurization:
  emb_dim: 64
batching:
  num_neighbors: 10
```

**训练时间预估：** 数据采集 ~30 分钟 + 训练 ~15 分钟 = **总计 1 小时内**

### 4.4 Wrapper 接口

```python
def pids_query(command_sequence: List[str]) -> int:
    """
    完整流程：
    1. 在靶场容器内执行 command_sequence（含checker验证，详见第5.4节）
    2. sysdig 采集 syscall
    3. 转换成 CDM 格式 → PostgreSQL
    4. 调用训练好的 PIDSMaker detector
    5. 返回 0 (benign) 或 1 (malicious)
    """
```

支持切换不同 detector：

```python
SUPPORTED_DETECTORS = ["orthrus", "kairos", "magic", "flash", ...]
```

---

## 5. Docker 靶场（确定）

### 5.1 单容器架构

只有一个 target 容器。攻击者通过 `docker exec` 进入 target 容器执行命令，PIDS 采集 target 容器内 syscall 产生溯源图。

```
┌──────────────────────────────────────────────┐
│         target容器（被攻击主机）              │
│                                              │
│  ┌────────────────┐                          │
│  │  Juice-Shop    │ (本地3000端口)            │
│  │  作为victim服务 │                          │
│  └────────────────┘                          │
│         ↑                                    │
│         │ 攻击命令打本地服务                  │
│         │                                    │
│  ┌──────────────────────────────────┐        │
│  │  攻击者执行的命令 (A0 ⊕ δ)        │        │
│  │  curl/sqlmap/wget/...            │        │
│  └──────────────────────────────────┘        │
│         │                                    │
│         ▼                                    │
│  ┌──────────────────────────────────┐        │
│  │  sysdig 采集本容器所有syscall    │        │
│  └──────────────────────────────────┘        │
│         │                                    │
└─────────┼────────────────────────────────────┘
          │ trace.scap
          ▼
   ┌────────────────────────┐
   │  CDM Converter         │
   │  (range/converter.py)  │
   └────────────────────────┘
          │
          ▼
   ┌────────────────────────┐
   │   PostgreSQL DB        │
   └────────────────────────┘
          │
          ▼
   ┌────────────────────────┐
   │   PIDSMaker (trained)  │
   │   返回 0/1             │
   └────────────────────────┘
```

### 5.2 Dockerfile

```dockerfile
FROM kalilinux/kali-rolling

RUN apt update && apt install -y \
    curl wget sqlmap nmap hydra \
    sysdig auditd \
    nodejs npm \
    coreutils procps net-tools \
    iproute2 dnsutils \
    postgresql-client jq

RUN npm install -g juice-shop

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
```

**entrypoint.sh：**

```bash
#!/bin/bash
juice-shop &
sleep 5
tail -f /dev/null
```

**启动方式：**

```bash
docker run -it --privileged \
    -p 3000:3000 \
    -v ./logs:/var/log/sysdig \
    --name pids_range \
    pids_range:latest
```

### 5.3 执行接口

实施 `range/execute.py`：

```python
def execute_in_range(commands: List[str]) -> Dict[str, Any]:
    """
    1. Reset容器（清理状态、重启Juice-Shop）
    2. 容器内启动sysdig采集
    3. 通过 docker exec 在容器内逐条执行commands
    4. 收集每条命令的: stdout, stderr, exit_code, response_time
    5. 停止sysdig，导出trace.scap
    6. 返回 {
        "trace_path": str,
        "command_outputs": List[CommandOutput]
       }
    """
```

**采集工具参考：**

- sysdig：https://github.com/draios/sysdig
- auditd：https://github.com/linux-audit/audit-userspace

### 5.4 攻击步骤 Checker（确定）

#### 5.4.1 背景

攻击命令序列 A_0 ⊕ δ 在靶场内执行时，每一步都可能失败：

- 网络问题导致 curl 失败
- Juice-Shop 未完全启动导致请求被拒
- 命令语法错误
- 之前步骤失败导致后续步骤无意义（如登录失败导致后续 session 操作无效）

**没有 checker 的问题：**

- 攻击实际没打成功，但 PIDS 反馈 benign，算法误以为找到了好的 δ
- 攻击实际打成功了，但被某条 camouflage 命令的副作用干扰，PIDS 反馈 malicious 但不是因为攻击本身
- 整个 query 的反馈 y 失去了真实意义

**Checker 的角色：** 验证 A_0 的每一步攻击都真正打成功了，PIDS 反馈才有意义。

#### 5.4.2 A_0 的 JSON 格式

每个攻击场景 A_0 必须配套一组 step checkers，每条命令对应一个 checker：

```json
{
  "scenario_id": "juiceshop_sqli",
  "source": "PentestGPT",
  "target": "Juice-Shop",
  "attack_type": "SQL_Injection",
  "steps": [
    {
      "step_id": 1,
      "command": "curl -s -X POST 'http://localhost:3000/rest/user/login' -d '...'",
      "checker": {
        "type": "http_response_contains",
        "expected": "authentication",
        "field": "response_body"
      }
    },
    {
      "step_id": 2,
      "command": "curl -s 'http://localhost:3000/api/Users/1' -H 'Authorization: Bearer {{token}}'",
      "checker": {
        "type": "http_status_code",
        "expected": 200
      }
    },
    {
      "step_id": 3,
      "command": "curl -s 'http://localhost:3000/rest/products/search?q=...'",
      "checker": {
        "type": "regex_match",
        "expected": "admin@juice-sh\\.op",
        "field": "response_body"
      }
    }
  ],
  "final_attack_check": {
    "type": "exfiltrated_data_present",
    "expected": "admin@juice-sh.op"
  },
  "validation": {
    "validated_at": "2026-05-07T10:00:00Z",
    "all_checkers_pass_on_clean_run": true
  }
}
```

#### 5.4.3 Checker 类型

实施以下 checker 类型，覆盖常见攻击场景：

**类型 1：HTTP 响应 checker**

```python
class HTTPResponseChecker:
    """验证HTTP响应"""
    type: "http_response_contains" | "http_status_code" | "http_header_present"
    expected: str | int
    field: "response_body" | "status_code" | "headers"
```

**类型 2：命令退出码 checker**

```python
class ExitCodeChecker:
    """验证命令退出码"""
    type: "exit_code"
    expected: int  # 通常是0
```

**类型 3：输出文本 checker**

```python
class OutputChecker:
    """验证stdout/stderr输出"""
    type: "stdout_contains" | "stdout_not_contains" | "stdout_regex_match"
    expected: str
```

**类型 4：文件系统 checker**

```python
class FileSystemChecker:
    """验证文件系统状态变化"""
    type: "file_exists" | "file_contains" | "file_size_min"
    path: str
    expected: any
```

**类型 5：副作用 checker（针对攻击成功的最终验证）**

```python
class SideEffectChecker:
    """验证攻击的最终效果（如数据泄露、权限提升）"""
    type: "exfiltrated_data_present" | "privilege_escalated" | "shell_obtained"
    expected: any
```

**类型 6：自定义脚本 checker**

```python
class CustomScriptChecker:
    """对复杂场景使用自定义检查脚本"""
    type: "custom"
    script_path: str  # 返回 0=pass, 非0=fail
```

#### 5.4.4 Checker 执行流程

实施 `range/checker.py`：

```python
class StepCheckResult:
    step_id: int
    command: str
    success: bool
    actual: any
    expected: any
    error_message: Optional[str]

class AttackExecutionResult:
    scenario_id: str
    all_steps_passed: bool
    final_attack_succeeded: bool
    step_results: List[StepCheckResult]
    failed_step: Optional[int]
    trace_path: str

def execute_with_checks(
    scenario: AttackScenario,
    delta_commands: List[str],
    delta_positions: List[int],
) -> AttackExecutionResult:
    """
    完整执行流程：
    1. 在靶场启动sysdig
    2. 按顺序执行A0命令和δ命令（按position插入）
    3. 对A0的每一条命令，执行后立即调用对应checker
    4. 记录每步结果
    5. 执行 final_attack_check 验证攻击的最终效果
    6. 停止sysdig
    7. 返回完整执行结果
    """
```

#### 5.4.5 Checker 与 PIDS 反馈的联动

**关键逻辑：** 只有 attack 真正成功时，PIDS 反馈才有意义。

```python
def query_with_validation(
    scenario: AttackScenario,
    delta: List[str],
    pids_oracle,
) -> QueryResult:
    """
    1. execute_with_checks → 拿到 attack_execution_result
    2. 如果 all_steps_passed == False:
       → 返回 INVALID_QUERY (不消耗query预算，不更新算法状态)
       → 算法层应该重新尝试或调整δ
    3. 如果 final_attack_succeeded == False:
       → 同样视为 INVALID_QUERY
    4. 如果攻击完整执行成功:
       → 把sysdig trace送入PIDSMaker
       → 拿到binary y
       → 返回 VALID_QUERY(y)
    """
```

**这一机制保证：**

- PIDS 反馈的 y 真实反映"攻击成功 + camouflage 是否绕过 PIDS"
- 不会浪费 query 预算在执行失败的 δ 上
- 算法不会因为执行失败而误判某些 δ"成功"

#### 5.4.6 Checker 失败的处理策略

当 `all_steps_passed == False`，算法层有几种应对策略：

**策略 A：丢弃该 δ 重新生成**

- 直接放弃当前 δ，算法生成下一个候选

**策略 B：定位失败步骤诊断**

- 检查第一个失败的 step_id
- 判断是 camouflage 命令的副作用导致的，还是 δ 的位置不当
- 若是副作用，把这条 camouflage 命令的 imp 分数大幅降低（"破坏性"信号）

**策略 C：retry**

- 短暂等待后重试一次（应对偶发网络抖动）

实施时**默认采用策略 B + C 组合**，这是研究问题之一可以做 ablation。

#### 5.4.7 Checker 测试与验证

实施 `range/validation.py`：

```python
def validate_scenario_checkers(scenario: AttackScenario) -> bool:
    """
    1. 在干净环境执行A0（无δ）
    2. 验证所有checker都通过
    3. 验证 final_attack_check 通过
    4. 如果以上都成立，scenario可用于实验
    """
```

每个 A_0 JSON 文件加入实施前的 validation 字段（见 5.4.2 的格式）。

---

## 6. 算法核心：基于黑盒对抗样本生成的标准模块化结构

### 6.1 模块化设计的领域参考

本节按黑盒对抗样本生成领域标准模块化结构组织。综合参考：

#### SoK / Survey

- **SoK: Pitfalls in Evaluating Black-Box Attacks** (SaTML 2024)
  - 论文：https://arxiv.org/abs/2310.17534
  - 代码：https://github.com/iamgroot42/blackboxsok
  - 贡献：threat model 四维 taxonomy、模块化 codebase

- **Black-Box Adversarial Attacks: A Survey** (IEEE 2022): https://ieeexplore.ieee.org/document/9984916

#### Benchmark / Framework（顶级开源项目）

- **BlackboxBench** (arxiv 2023)
  - 论文：https://arxiv.org/abs/2312.16979
  - 代码：https://github.com/SCLBD/BlackboxBench
  - 项目页：https://blackboxbench.github.io/
  - 贡献：unified attack pipeline = Initialization + Perturbation Generation + Acceptance Check + Update 四个 functional blocks

- **FoolBox** (JOSS 2017, 2020)
  - 代码：https://github.com/bethgelab/foolbox
  - 文档：https://foolbox.readthedocs.io
  - 论文：https://arxiv.org/abs/1707.04131
  - 贡献：Attack class 包含 model + criterion + distance 三个核心组件

- **ART (Adversarial Robustness Toolbox)** (Linux Foundation, IBM)
  - 代码：https://github.com/Trusted-AI/adversarial-robustness-toolbox
  - 论文：https://arxiv.org/abs/1807.01069
  - 贡献：BlackBoxClassifier 抽象接口

- **CleverHans**: https://github.com/cleverhans-lab/cleverhans
- **AdverTorch**: https://github.com/BorealisAI/advertorch
- **DEEPSEC**: https://github.com/kleincup/DEEPSEC
- **SecML**: https://github.com/pralab/secml
- **DeepRobust**: https://github.com/DSE-MSU/DeepRobust

#### 经典算法实现

| 算法 | 顶会 | 论文 | 代码 |
|---|---|---|---|
| Practical Black-Box | AsiaCCS 2017 | https://arxiv.org/abs/1602.02697 | — |
| Boundary Attack | ICLR 2018 | https://arxiv.org/abs/1712.04248 | https://github.com/bethgelab/foolbox |
| NES Attack | ICML 2018 | https://arxiv.org/abs/1804.08598 | — |
| Opt-Attack | ICLR 2019 | https://arxiv.org/abs/1807.04457 | — |
| Bandits Attack | ICLR 2019 | https://arxiv.org/abs/1807.07978 | — |
| Sign-OPT | ICLR 2020 | https://arxiv.org/abs/1909.10773 | https://github.com/cmhcbb/attackbox |
| HSJA | S&P 2020 | https://arxiv.org/abs/1904.02144 | https://github.com/Jianbo-Lab/HSJA |
| GeoDA | CVPR 2020 | https://arxiv.org/abs/2003.06468 | — |
| QEBA | CVPR 2020 | https://arxiv.org/abs/2005.14137 | — |
| Square Attack | ECCV 2020 | https://arxiv.org/abs/1912.00049 | https://github.com/max-andr/square-attack |
| Bayes-Attack | BMVC 2020 | https://arxiv.org/abs/2007.07210 | — |
| Learning to Query | ICLR 2022 | https://openreview.net/forum?id=pzpytjk3Xb2 | — |
| BASES | NeurIPS 2022 | https://arxiv.org/abs/2208.03610 | — |

### 6.2 整体 Pipeline（确定）

综合 BlackboxBench 和 FoolBox 设计，标准黑盒攻击 pipeline 为：

```
[Search Space 定义]
        ↓
[Initialization] → 起点 x_0
        ↓
   主循环:
   ├── [Perturbation Generation] → 候选扰动 δ_t
   ├── [Acceptance Check] → 是否query target
   ├── target query (含checker验证) → 反馈 y 或 INVALID_QUERY
   ├── [Guidance Mechanism update] → 更新内部状态
   ├── [State Update] → 更新当前最优
   └── [Termination Criterion] → 是否停止
        ↓
最终对抗样本 x*
```

每个 block 都是研究问题，需实施多个候选方案。

---

### 6.3【研究问题 1】Search Space 定义（Individual 表示）

**问题：** 攻击者要搜索的"扰动"在数学上是什么对象？

**领域参考：** image domain 用连续向量；discrete domain 用集合 / 序列 / 结构化对象。

**候选方案：**

**方案 A：扰动 = 命令集合（无序）**

```python
class IndividualSet:
    elements: Set[str]
```

**方案 B：扰动 = 命令序列（有序）**

```python
class IndividualSequence:
    elements: List[str]
```

**方案 C：扰动 = 命令 + 注入位置**

```python
class IndividualPositioned:
    elements: List[Tuple[str, int]]
```

**方案 D：扰动 = 命令模板实例化**

```python
class IndividualTemplated:
    instances: List[Tuple[str, Dict]]
```

**文件位置：** `attack/search_space/`

每个方案实施：

- 数据结构定义
- `to_command_sequence(A0)` 方法
- `random_init(C, size_range)` 方法
- `serialize()` / `deserialize()` 方法

---

### 6.4【研究问题 2】Initialization（初始化）

**问题：** 攻击循环的起点 x_0 如何选择？

**领域参考：**

- HSJA：从已是 adversarial 的 blended 样本开始
- Boundary Attack：从随机噪声开始
- Copy-Paste Initialization (Brunner et al.) — https://arxiv.org/abs/1906.06086
- FoolBox 把初始化独立成 `init_attack` 参数

**候选方案：**

- **方案 A：随机初始化** — 从 C 中随机 sample
- **方案 B：基于历史的初始化** — 用历史成功记录作起点
- **方案 C：领域知识初始化** — 优先选高隐蔽性命令
- **方案 D：分层初始化（多起点）** — 同时维护多起点

**文件位置：** `attack/initialization/`

每个方案实施 `initialize(A0, C, config) -> List[Individual]` 方法。

---

### 6.5【研究问题 3】Perturbation Generation（扰动生成）

**问题：** 给定当前状态，如何生成下一个候选扰动？

**领域参考：**

- HSJA: 决策边界估计梯度方向 (S&P 2020)
- NES: natural evolution strategies 随机搜索 (ICML 2018)
- Square Attack: 随机搜索方块状扰动 (ECCV 2020)
- Sign-OPT: 估计梯度符号 (ICLR 2020)
- Boundary Attack: 决策边界附近随机游走 (ICLR 2018)

**候选方案：**

- **方案 A：随机扰动** — 类比 Boundary Attack 随机游走
- **方案 B：基于 importance 的 guided 扰动** — 类比 NES weighted sampling
- **方案 C：基于历史相似度的扰动**
- **方案 D：基于估计梯度的扰动** — 借鉴 HSJA 思想在离散空间估计
- **方案 E：组合策略**

**针对不同 Search Space 的额外操作：**

- 针对 IndividualSequence：顺序交换变异、子序列反转
- 针对 IndividualPositioned：位置扰动
- 针对 IndividualTemplated：参数替换

**文件位置：** `attack/perturbation/`

每个方案实施：

- `generate(current_state, context) -> Individual` 方法
- `crossover(ind1, ind2, context) -> Individual` 方法（适用于 population-based）

---

### 6.6【研究问题 4】Acceptance Check（接受判定）

**问题：** 候选扰动是否值得 query target？query 后的反馈是否接受为新状态？

**领域参考：**

- BlackboxBench 把 acceptance-check 独立成一个 block
- Boundary Attack：候选必须保持 adversarial 才被接受
- Simulated Annealing 类思想

**候选方案：**

- **方案 A：贪心接受** — 只接受 fitness 严格更优
- **方案 B：模拟退火接受** — 以 exp(-ΔE/T) 概率接受较差候选
- **方案 C：基于本地评估的接受** — local fitness 预筛
- **方案 D：基于不确定性的接受** — 借鉴 Bayesian Optimization 的 acquisition function

**文件位置：** `attack/acceptance/`

每个方案实施：

- `should_query(candidate, history, context) -> bool` 方法
- `should_accept(candidate, y, current_best) -> bool` 方法

---

### 6.7【研究问题 5】Guidance Mechanism（反馈引导机制）

**问题：** 怎么用 query 反馈指导后续搜索？

**领域参考：**

- HSJA: gradient direction estimation (S&P 2020)
- NES: distribution 参数更新 (ICML 2018)
- Bandits Attack: multi-armed bandits (ICLR 2019)
- Bayes-Attack: Gaussian Process (BMVC 2020)
- Papernot et al.: surrogate model + transfer (AsiaCCS 2017)

**候选方案：**

- **方案 A：Importance Score 归因** — imp(c) = P(c | benign) - P(c | malicious)
- **方案 B：Bandit 风格更新** — UCB1 或 Thompson Sampling
- **方案 C：贝叶斯优化** — Gaussian Process 建模
- **方案 D：决策边界估计** — 借鉴 HSJA
- **方案 E：Leave-one-out 归因** — 失败 δ 逐元素分析
- **方案 F：Surrogate Model** — 训练本地代理模型

**文件位置：** `attack/guidance/`

每个方案实施：

- `update(individual, y)` 方法
- `score_element(c) -> float` 方法
- `score_individual(individual) -> float` 方法

**特殊实施要求：** 配合 checker 失败处理策略 B，guidance 机制需要支持"破坏性命令"信号——即对 checker 失败时归因的 camouflage 命令做特殊处理。

---

### 6.8【研究问题 6】State Update（状态更新）

**问题：** 接受候选后如何更新算法的当前状态？

**候选方案：**

- **方案 A：单点状态更新** — 维护单一当前最佳
- **方案 B：Population 状态更新** — 维护一个 population
- **方案 C：多 Population 协同** — 多个 population 对应不同假设、跨 population 迁移
- **方案 D：基于精英存档的更新** — 维护精英 archive

**文件位置：** `attack/state_update/`

每个方案实施 `update(current_state, accepted_candidate, y) -> new_state` 方法。

---

### 6.9【研究问题 7】Termination Criterion（终止判定）

**领域参考：** FoolBox 把 criterion 独立成参数。

**候选方案：**

- **方案 A：达成攻击目标即停止** — 第一次 benign 反馈停止
- **方案 B：连续 k 次成功才停止** — 抗噪声
- **方案 C：Query 预算耗尽**
- **方案 D：组合**

**文件位置：** `attack/termination/`

每个方案实施 `should_terminate(state, history) -> bool` 方法。

---

### 6.10【研究问题 8】Distance / Quality Metric（Local Fitness）

**问题：** 怎么衡量扰动的"好坏"？无法 query 真 target 时的本地评估方式？

**领域参考：** FoolBox 把 distance 独立成参数（L0/L1/L2/Linf）。

**候选信号：**

- 信号 A：基于 Guidance score
- 信号 B：基于历史相似度
- 信号 C：基于多样性
- 信号 D：基于 δ 大小（隐蔽性）
- 信号 E：基于 population 偏好
- 信号 F：组合信号

**文件位置：** `attack/fitness/`

每个信号实施 `compute(individual, context) -> float` 方法。

---

### 6.11【研究问题 9】超参数

实施时**全部参数化**：

- `population_size`
- `individual_size_min/max`
- `query_budget`
- `max_iterations`
- `convergence_consecutive_benign` (k 值)
- `checker_retry_count`
- 各方案算法专属参数

实施在 `attack/config.py`。

---

## 7. 主算法框架（确定）

实施 `attack/algorithm.py`：

```python
class BlackboxAttack:
    def __init__(
        self,
        search_space: Type[Individual],
        initialization: InitializationStrategy,
        perturbation: PerturbationStrategy,
        acceptance: AcceptanceStrategy,
        guidance: GuidanceMechanism,
        state_update: StateUpdateStrategy,
        termination: TerminationCriterion,
        fitness: FitnessFunction,
        config: Config,
    ):
        """通过依赖注入支持自由组合所有候选方案"""
        ...
    
    def run(
        self,
        scenario: AttackScenario,  # 包含A0+checker
        C: List[str],
        pids_query_with_validation,
    ) -> AttackResult:
        # 1. Initialization → x_0
        state = self.initialization.initialize(scenario.A0, C, self.config)
        history = QueryHistory()
        
        # 2. Main loop
        while not self.termination.should_terminate(state, history):
            # Perturbation Generation
            candidate = self.perturbation.generate(state, self.search_space, self.guidance)
            
            # Acceptance Check (本地预筛)
            if not self.acceptance.should_query(candidate, history, self.fitness):
                continue
            
            # Query target with validation
            query_result = pids_query_with_validation(scenario, candidate.delta)
            
            if query_result.is_invalid():
                # Checker失败 → 应对策略B+C
                self.guidance.handle_invalid_query(
                    candidate, 
                    query_result.failed_step,
                )
                continue  # 不消耗query预算
            
            y = query_result.y
            history.add(candidate, y)
            
            # Guidance update
            self.guidance.update(candidate, y)
            
            # Acceptance after query
            if self.acceptance.should_accept(candidate, y, state):
                state = self.state_update.update(state, candidate, y)
        
        return AttackResult(state, history)
```

---

## 8. 项目文件结构

```
project/
├── attack/
│   ├── __init__.py
│   ├── algorithm.py                     # 主算法框架（依赖注入）
│   ├── config.py                        # 超参数配置
│   ├── history.py                       # QueryHistory数据结构
│   │
│   ├── search_space/                    # 【研究问题1】扰动表示
│   │   ├── base.py
│   │   ├── set_individual.py
│   │   ├── sequence_individual.py
│   │   ├── positioned_individual.py
│   │   └── templated_individual.py
│   │
│   ├── initialization/                  # 【研究问题2】初始化
│   │   ├── base.py
│   │   ├── random_init.py
│   │   ├── history_init.py
│   │   ├── prior_knowledge_init.py
│   │   └── multi_start_init.py
│   │
│   ├── perturbation/                    # 【研究问题3】扰动生成
│   │   ├── base.py
│   │   ├── random_perturbation.py
│   │   ├── importance_perturbation.py
│   │   ├── history_perturbation.py
│   │   ├── gradient_estimation_perturbation.py
│   │   ├── combined_perturbation.py
│   │   ├── order_swap_perturbation.py
│   │   ├── position_shift_perturbation.py
│   │   └── parameter_swap_perturbation.py
│   │
│   ├── acceptance/                      # 【研究问题4】接受判定
│   │   ├── base.py
│   │   ├── greedy_acceptance.py
│   │   ├── annealing_acceptance.py
│   │   ├── threshold_acceptance.py
│   │   └── uncertainty_acceptance.py
│   │
│   ├── guidance/                        # 【研究问题5】反馈引导
│   │   ├── base.py
│   │   ├── importance_score.py
│   │   ├── bandit_guidance.py
│   │   ├── bayesian_guidance.py
│   │   ├── boundary_guidance.py
│   │   ├── leave_one_out.py
│   │   └── surrogate_guidance.py
│   │
│   ├── state_update/                    # 【研究问题6】状态更新
│   │   ├── base.py
│   │   ├── single_point_update.py
│   │   ├── population_update.py
│   │   ├── multi_population_update.py
│   │   └── elite_archive_update.py
│   │
│   ├── termination/                     # 【研究问题7】终止判定
│   │   ├── base.py
│   │   ├── first_success.py
│   │   ├── consecutive_success.py
│   │   ├── budget_exhausted.py
│   │   └── combined_termination.py
│   │
│   └── fitness/                         # 【研究问题8】Local fitness
│       ├── base.py
│       ├── guidance_fitness.py
│       ├── similarity_fitness.py
│       ├── diversity_fitness.py
│       ├── size_fitness.py
│       ├── population_pref_fitness.py
│       └── combined_fitness.py
│
├── data/
│   ├── attack_sequences/                # A0 集合（≥10个JSON文件，含checker）
│   ├── candidate_pool.txt               # C 集合（150-300条）
│   └── command_templates.json           # 命令模板（方案D用）
│
├── range/                               # Docker靶场
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── execute.py                       # execute_in_range
│   ├── checker.py                       # 6种Checker实施
│   ├── validation.py                    # validate_scenario_checkers
│   └── converter.py                     # sysdig → CDM格式
│
├── oracle/
│   ├── pidsmaker_setup.sh               # PIDSMaker安装
│   ├── train_pidsmaker.py               # 小数据集训练
│   ├── pidsmaker_wrapper.py             # pids_query / query_with_validation
│   └── custom_small.yml                 # 小数据集配置
│
├── experiments/                         # 对比实验脚本
│   ├── compare_search_space.py
│   ├── compare_initialization.py
│   ├── compare_perturbation.py
│   ├── compare_acceptance.py
│   ├── compare_guidance.py
│   ├── compare_state_update.py
│   ├── compare_termination.py
│   ├── compare_fitness.py
│   ├── compare_checker_strategy.py      # checker失败处理策略对比
│   ├── tune_hyperparams.py
│   ├── compare_detectors.py             # 跨detector类型鲁棒性
│   └── final_attack.py                  # 最终攻击实验
│
├── results/                             # 实验输出目录
│
├── tests/                               # 单元测试
│   ├── test_search_space.py
│   ├── test_initialization.py
│   ├── test_perturbation.py
│   ├── test_acceptance.py
│   ├── test_guidance.py
│   ├── test_state_update.py
│   ├── test_termination.py
│   ├── test_fitness.py
│   ├── test_algorithm.py
│   ├── test_converter.py                # CDM转换测试
│   ├── test_checker.py                  # Checker测试
│   ├── test_validation.py               # Scenario validation测试
│   └── test_oracle.py                   # PIDS oracle测试
│
├── requirements.txt
├── README.md
└── setup.py
```

---

## 9. 实施步骤

### Phase 1：基础设施

1. 搭建 Docker 靶场（Dockerfile + entrypoint.sh）
2. 测试容器启动后 Juice-Shop 可访问
3. 测试 sysdig 能在容器内采集到 syscall
4. 实施 `range/execute.py` 中的 `execute_in_range(commands)` 函数

### Phase 2：CDM 格式适配

5. 研究 DARPA TC 的 CDM schema 和 PIDSMaker 的输入要求
6. 实施 `range/converter.py`：sysdig trace → CDM → PostgreSQL
7. 实施单元测试：在已知输入下验证 CDM 转换正确性

### Phase 3：数据准备 + Checker

8. 用 PentestGPT 针对 Juice-Shop 生成至少 10 个攻击场景
9. **为每个场景设计 step checkers 和 final_attack_check**
10. **实施 `range/checker.py`，支持所有 6 种 checker 类型**
11. **实施 `range/validation.py`，验证每个 scenario 的 checker 正确**
12. 在干净环境跑 validation，确认所有 scenario 可用
13. 从 GTFOBins + Atomic Red Team 筛选构造候选池 C（150-300 条）
14. 在容器内验证候选池所有命令可正常执行
15. 构造命令模板库（针对 Search Space 方案 D）

### Phase 4：PIDSMaker 集成与小数据集训练

16. 安装 PIDSMaker，配置 PostgreSQL
17. 实施 `oracle/train_pidsmaker.py`：collect_benign_data + train_baseline_detector
18. 用 80 个 benign trace 训练 baseline detector（orthrus）
19. 实施 `pids_query` wrapper 整合 `query_with_validation`（支持切换不同 detector）
20. 验证 `pids_query(A0) == 1` 且所有 checker 通过（每个 A_0 都被检测到）

### Phase 5：算法核心（**所有候选方案都要实施**）

21. 实施 `attack/search_space/` 下 4 个方案
22. 实施 `attack/initialization/` 下 4 个方案
23. 实施 `attack/perturbation/` 下所有策略
24. 实施 `attack/acceptance/` 下 4 个方案
25. 实施 `attack/guidance/` 下 6 个方案（含 checker 失败处理）
26. 实施 `attack/state_update/` 下 4 个方案
27. 实施 `attack/termination/` 下 4 个方案
28. 实施 `attack/fitness/` 下所有信号
29. 实施 `attack/algorithm.py` 主算法（依赖注入）

### Phase 6：测试

30. 为每个模块写单元测试
31. CDM 转换正确性测试
32. Checker 各类型测试
33. PIDS oracle 端到端测试
34. 算法端到端集成测试

### Phase 7：实验

35. 实施 `experiments/` 下所有对比脚本
36. 跑各模块对比实验，选最优组合
37. **跑 checker 失败处理策略对比实验**
38. 跑超参数调优
39. 跑跨 detector 鲁棒性实验（orthrus / kairos / magic / flash）
40. 跑最终攻击实验（在所有 A_0 上验证）

---

## 10. 输出格式

### 10.1 单次攻击输出

`results/single_attack_<timestamp>.json`：

```json
{
  "scenario_id": "juiceshop_sqli",
  "timestamp": "2026-05-07T10:30:00Z",
  "config": {
    "search_space": "IndividualSet",
    "initialization": "RandomInit",
    "perturbation": "ImportancePerturbation",
    "acceptance": "GreedyAcceptance",
    "guidance": "ImportanceScore",
    "state_update": "PopulationUpdate",
    "termination": "ConsecutiveSuccess",
    "fitness": "CombinedFitness",
    "checker_strategy": "B+C",
    "detector": "orthrus",
    "hyperparams": {}
  },
  "A0": ["..."],
  "best_individual": {},
  "final_y": 0,
  "total_queries": 47,
  "invalid_queries": 12,
  "convergence_iteration": 23,
  "wall_clock_time_sec": 1234.5,
  "history": [
    {"iteration": 1, "individual": {}, "y": 1, "checker_passed": true},
    {"iteration": 2, "individual": {}, "y": null, "checker_passed": false, "failed_step": 2}
  ]
}
```

### 10.2 对比实验输出

`results/compare_<module>_<timestamp>.json`：

```json
{
  "experiment_type": "compare_perturbation",
  "fixed_config": {
    "search_space": "IndividualSet",
    "initialization": "RandomInit"
  },
  "candidates": ["random", "importance", "history", "gradient_estimation", "combined"],
  "test_scenarios": ["juiceshop_sqli", "juiceshop_xss"],
  "results": {
    "random": {
      "avg_queries": 87,
      "avg_invalid_queries": 23,
      "success_rate": 0.6,
      "avg_individual_size": 12,
      "avg_wall_clock": 1500,
      "per_scenario": {}
    }
  },
  "best_candidate": "importance",
  "statistical_significance": {}
}
```

---

## 11. 完整参考文献

### 11.1 直接相关攻击工作

- **BagAmmo** (USENIX Security 2024): https://www.usenix.org/conference/usenixsecurity24/presentation/li-yikun
- **Mimicry Attacks against Provenance HIDS** (NDSS 2023): https://gangw.cs.illinois.edu/ndss23-mimicry.pdf

### 11.2 黑盒对抗样本生成 — Survey/SoK

- **SoK: Pitfalls in Evaluating Black-Box Attacks** (SaTML 2024): https://arxiv.org/abs/2310.17534 — https://github.com/iamgroot42/blackboxsok
- **Black-Box Adversarial Attacks: A Survey** (IEEE 2022): https://ieeexplore.ieee.org/document/9984916

### 11.3 黑盒对抗样本生成 — Benchmark/Framework

- **BlackboxBench**: https://arxiv.org/abs/2312.16979 — https://github.com/SCLBD/BlackboxBench — https://blackboxbench.github.io/
- **FoolBox**: https://github.com/bethgelab/foolbox — https://foolbox.readthedocs.io — https://arxiv.org/abs/1707.04131
- **ART**: https://github.com/Trusted-AI/adversarial-robustness-toolbox — https://arxiv.org/abs/1807.01069
- **CleverHans**: https://github.com/cleverhans-lab/cleverhans
- **AdverTorch**: https://github.com/BorealisAI/advertorch
- **DEEPSEC**: https://github.com/kleincup/DEEPSEC
- **SecML**: https://github.com/pralab/secml
- **DeepRobust**: https://github.com/DSE-MSU/DeepRobust

### 11.4 黑盒对抗样本生成 — 经典算法

**奠基：**

- Practical Black-Box Attacks (AsiaCCS 2017): https://arxiv.org/abs/1602.02697
- Boundary Attack (ICLR 2018): https://arxiv.org/abs/1712.04248
- NES Attack (ICML 2018): https://arxiv.org/abs/1804.08598

**优化 formulation：**

- Opt-Attack (ICLR 2019): https://arxiv.org/abs/1807.04457
- Bandits Attack (ICLR 2019): https://arxiv.org/abs/1807.07978

**梯度估计：**

- Sign-OPT (ICLR 2020): https://arxiv.org/abs/1909.10773
- HSJA (S&P 2020): https://arxiv.org/abs/1904.02144 — https://github.com/Jianbo-Lab/HSJA
- GeoDA (CVPR 2020): https://arxiv.org/abs/2003.06468
- QEBA (CVPR 2020): https://arxiv.org/abs/2005.14137
- Square Attack (ECCV 2020): https://arxiv.org/abs/1912.00049 — https://github.com/max-andr/square-attack

**贝叶斯/学习增强：**

- Bayes-Attack (BMVC 2020): https://arxiv.org/abs/2007.07210
- Learning to Query (ICLR 2022): https://openreview.net/forum?id=pzpytjk3Xb2

**Surrogate 增强：**

- BASES (NeurIPS 2022): https://arxiv.org/abs/2208.03610

**初始化相关：**

- Copy-Paste Initialization: https://arxiv.org/abs/1906.06086

### 11.5 LotL 命令池来源

- GTFOBins: https://gtfobins.github.io/ — https://github.com/GTFOBins/GTFOBins.github.io
- LOLBAS: https://lolbas-project.github.io/ — https://github.com/LOLBAS-Project/LOLBAS
- LOOBins: https://www.loobins.io/ — https://github.com/infosecB/LOOBins
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team

### 11.6 攻击场景来源

- Cybench: https://cybench.github.io/ — https://github.com/andyzorigin/cybench — https://arxiv.org/abs/2408.08926
- PentestGPT: https://github.com/GreyDGL/PentestGPT — https://arxiv.org/abs/2308.06782
- Juice-Shop: https://github.com/juice-shop/juice-shop — https://owasp.org/www-project-juice-shop/

### 11.7 PIDS Oracle

- PIDSMaker: https://github.com/ubc-provenance/PIDSMaker — https://arxiv.org/abs/2601.22983 — https://ubc-provenance.github.io/PIDSMaker

### 11.8 数据格式与采集工具

- DARPA Transparent Computing: https://github.com/darpa-i2o/Transparent-Computing
- CDM Schema: https://github.com/darpa-i2o/Transparent-Computing/blob/master/schema/TCCDMDatum.avsc
- sysdig: https://github.com/draios/sysdig
- auditd: https://github.com/linux-audit/audit-userspace

---

## 12. Claude 实施检查清单

### 基础设施

- [ ] Docker 靶场可启动、Juice-Shop 可访问
- [ ] sysdig 能采集到容器内 syscall
- [ ] `execute_in_range` 函数可用

### CDM 格式适配

- [ ] `range/converter.py` 实施完成
- [ ] sysdig trace → CDM → PostgreSQL 端到端流程通畅
- [ ] CDM 转换的单元测试通过
- [ ] 至少覆盖 3 种节点类型 + 10 种边类型

### Checker 机制

- [ ] `range/checker.py` 实施 6 种 checker 类型
- [ ] `range/validation.py` 实施完成
- [ ] 每个 attack scenario 的 checker 在干净环境通过 validation
- [ ] `query_with_validation` 实施完成（含 checker 失败处理）

### PIDSMaker 集成

- [ ] PIDSMaker 已安装并可被 wrapper 调用
- [ ] 已采集 80 个 benign traces 作训练数据
- [ ] baseline detector 训练完成
- [ ] `pids_query(A0) == 1`（每个 A_0 都被检测到）
- [ ] 支持切换不同 detector

### 数据

- [ ] `data/attack_sequences/` 至少 10 个 JSON 文件，含 checker
- [ ] `data/candidate_pool.txt` 包含 150-300 条命令
- [ ] 候选池所有命令在容器内可执行
- [ ] `data/command_templates.json` 模板库（方案 D）

### 算法（所有候选方案都要实施）

- [ ] `attack/search_space/` 4 个方案完整实施
- [ ] `attack/initialization/` 4 个方案完整实施
- [ ] `attack/perturbation/` 所有策略完整实施
- [ ] `attack/acceptance/` 4 个方案完整实施
- [ ] `attack/guidance/` 6 个方案完整实施（含 checker 失败处理）
- [ ] `attack/state_update/` 4 个方案完整实施
- [ ] `attack/termination/` 4 个方案完整实施
- [ ] `attack/fitness/` 所有信号完整实施
- [ ] `attack/algorithm.py` 支持依赖注入自由组合所有方案

### 实验脚本

- [ ] 各模块的 compare 脚本完整实施
- [ ] compare_checker_strategy.py
- [ ] tune_hyperparams.py
- [ ] compare_detectors.py
- [ ] final_attack.py

### 测试

- [ ] 所有模块有单元测试
- [ ] CDM 转换正确性测试
- [ ] Checker 各类型测试
- [ ] PIDS oracle 端到端测试
- [ ] 算法端到端集成测试

### 文档

- [ ] README.md 描述如何运行
- [ ] 每个模块有 docstring 说明设计动机和参考文献
- [ ] 论文实验完整复现指南

---

**文档完成。所有参考链接已核实。每个研究问题都标明了可参考的顶会论文和开源项目。Claude 可按此文档完整实施一个面向四大安全顶会论文的实现。**
