"""GRABNEL-CMD acquisition functions(p2_mcts_v3.md §5.4)。

- lcb.lcb (默认,§5.4 Eq 12)— Lower Confidence Bound,α = μ − β·σ,argmin 选 commit
- ei (E2.6 备选)— Expected Improvement
- thompson (E2.6 备选)— Thompson sampling

argmin α 表示 surrogate 预测 s 越低(攻击效果好)+ 不确定度高的候选越优先真 query。
"""
from .lcb import lcb
from .ei import ei
from .thompson import thompson

__all__ = ["lcb", "ei", "thompson"]
