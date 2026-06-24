# experiments/ — FINDINGS.md 实验验证

按 detector 组织(对应 [FINDINGS.md](../FINDINGS.md) §1-§3),全 runtime 真跑,无 mock。

## 结构

```
experiments/
├── README.md                  本文件
├── proofs/                    ★ 3 个 detector × 各自变异(全 runtime 真跑)
│   ├── _common.py             共享(load_baseline / eval_attack_node / SQL 改写)
│   ├── magic.py               §1 magic(图空间 ADD)
│   ├── orthrus.py             §2 orthrus(图空间,3 个变异)
│   └── threatrace.py          §3 threatrace(图空间通用范式,3 个变异)
└── proofs_results/            统一 JSON 输出
    ├── magic.json
    ├── orthrus.json
    └── threatrace.json
```

## 变异 × FINDINGS 对应

**统一原则:全部 variant 基于 BL(detector baseline 标的 anomaly 集合),用 evade_rate 衡量。代码层只 2 个原子扰动 P1/P2**(在 `proofs/_common.py`)。

| FINDINGS § | detector 文件 | variant | 原子 | 预期 |
|---|---|---|---|---|
| §1.2 | `proofs/magic.py` | `variant_p1_dilution(100, 5)` ★ | P1 | **5/5 = 100%** |
| §1.3 | `proofs/magic.py` | `variant_p2_rerouting(3)` ★ | P2 | **5/5 = 100%** |
| §2.2 | `proofs/orthrus.py` | `variant_p1_dilution_nai(50)` ★ | P1 | **9/10 = 90%** |
| §2.3 | `proofs/orthrus.py` | `variant_p2_rerouting_socat` | P2 | 0/10 = 0%(单独不够)|
| §3.1 | `proofs/threatrace.py` | `variant_p1_dilution_universal(100)` ★ | P1 | **4/6 = 66.7%**(file 4/4,netflow 0/2)|
| §3.2 | `proofs/threatrace.py` | `variant_p2_rerouting(3)` | P2 | 0/6 = 0%(反向破坏)|

## 跑法

```bash
# 跑全部 3 个 detector
for det in magic orthrus threatrace; do
    PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/$det.py
done

# 单跑某个
PYTHONPATH=pids_attack conda run -n mimicattack python pids_attack/experiments/E1_operators/proofs/orthrus.py
```

## 输出

每次跑后 `proofs_results/<detector>.json` 含所有 variant 结果。
预期数据点跟 FINDINGS.md §1-§3 一致(model `5dfa19b2` / `87e0d7c2` / `d2d7c9ea`)。
