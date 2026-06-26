"""SafeMimic-CMD §3 validity constraints — R1 / R2.

Subdir built in E1.0 stage. Implementations:
  - `r1_attack_integrity.py`: enforces `all_steps_passed AND final_attack_succeeded` (R1).
  - `r2_delta_executable.py`: enforces δ commands run without timeout / block / resource conflict (R2).
"""
from ._protocol import ConstraintProtocol

__all__ = ["ConstraintProtocol"]
