"""SafeMimic-CMD — 唯一 paper-facing 攻击框架。

入口约定:
  - `SafeMimicConfig`(framework 定义)— 唯一 paper-facing config,覆盖 E1.0-E1.5 全 variants。
  - `run_attack(cfg, scenario=None, *, reset=True, ...)` — 唯一 by-config 入口。
    `cfg.search_policy` 选 dispatch:`"one_shot"`(E1.0) / `"full"`(SafeMimic-CMD 主算法) /
    `"random"`(baseline)。
  - 6 子目录按 paper §5 分层(`operators`/`constraints`/`objectives`/`search`/`surrogate`/`acquisition`)。
"""

from attack.framework import SafeMimicConfig

from .operators import OperatorProtocol
from .constraints import ConstraintProtocol
from .objectives import F1Protocol, F2Protocol, ScalarizeProtocol, ObjectiveProtocol
from .search import SearchPolicyProtocol, InnerOptimizerProtocol
from .surrogate import FeatureExtractorProtocol, SurrogateProtocol
from .acquisition import AcquisitionProtocol

from .runner import (
    run_attack,
    main as runner_main,
    random_baseline_run,
    write_summary,
)

__all__ = [
    "SafeMimicConfig",
    # 6 子层 Protocol(分层架构契约)
    "OperatorProtocol",
    "ConstraintProtocol",
    "F1Protocol", "F2Protocol", "ScalarizeProtocol", "ObjectiveProtocol",
    "SearchPolicyProtocol", "InnerOptimizerProtocol",
    "FeatureExtractorProtocol", "SurrogateProtocol",
    "AcquisitionProtocol",
    # Runner
    "run_attack",
    "runner_main",
    "random_baseline_run",
    "write_summary",
]
