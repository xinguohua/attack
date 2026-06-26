# P3 实施 plan(替代,指向新 finding-driven loop)

> 老 V3 实施 plan 已归档为 `p3_implementation_plan.archive_pre_refactor.md`,只作历史参考,**不再 maintain**。

新的攻击框架建设 plan 已经合并到:

- **`p3_results.md` §3.0 Finding-driven 6 阶段 gate** — 6 个 stage 的 build / pilot / gate / finding 流程
- **`p3_results.md` §3.7-§3.12** — 每个 E1.x cell 的 4-slot 模板(研究问题 / 实验逻辑 / 结果 / Finding+Framework revision)
- **`AGENTS.md` + `CLAUDE.md` §3** — 代码侧 `attack/safemimic_cmd/` 分层目标结构 + experiment 边界

## 关键 anchor

- **框架名 = SafeMimic-CMD**(`attack/safemimic_cmd/`)。GRABNEL / BagAmmo / FCGHunter / MOS-Attack 只是 references。
- **`attack/grabnel_cmd/` + `attack/minimal_cmd/` 已退役/删除。** 不要恢复旧名字,不要往旧路径加新代码。
- **`fitness/` → `objectives/`** 改名,对齐 paper §5.3 术语。
- **`SafeMimicConfig`** 是唯一 config 类(`attack/framework/config.py`)。
- **`experiments/E1_ablation/`** 0 行攻击代码,只配 config + invoke + log。

## 推进顺序(对齐 `p3_results.md` §3.0)

| Stage | 代码动作 | 实验动作 |
|---|---|---|
| E1.0 | 建 `safemimic_cmd/{runner,search/one_shot,framework,constraints}/` 真 dispatch | 2-cell pilot,过 G0 gate |
| E1.1 | 搬 mutation → `safemimic_cmd/operators/{add,rewrite,move,remove}.py` | E1.1 pilot,看 operator usage |
| E1.2 | 搬 `fitness/*` → `safemimic_cmd/objectives/*`(改名) | E1.2 pilot,看 f_1/f_2 标量化是否稳定 |
| E1.3 | 搬 `algorithm.py + inner_ga.py + commit.py` → `safemimic_cmd/search/*` | E1.3 pilot,full vs random |
| E1.4 | 搬 `surrogate/*` → `safemimic_cmd/surrogate/*` | E1.4 pilot,看 sample efficiency |
| E1.5 | 搬 `acquisition/*` → `safemimic_cmd/acquisition/*` | E1.5 pilot,LCB vs EI vs Thompson |

每阶段:**搬完 → 跑 pilot → 写 finding → 改 framework → re-pilot → 过 gate → 进下一阶段**。
