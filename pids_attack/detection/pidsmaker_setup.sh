#!/bin/bash
# PIDSMaker 安装脚本 — 锁定版本 + 幂等(安全反复跑)
#
# 解决 RISK_P1_DEPS_CONFLICT(BLOCKERS.md):
#   PIDSMaker 4.0 用 pyproject.toml,没声明运行时依赖 → 必须显式装一堆 deps。
#   全部依赖(mimicattack 核心 + PIDSMaker 上游)统一在 pids_attack/requirements.txt
#   里 pin 死,本脚本读它(单一 requirements 文件,装到同一 mimicattack conda env)。
#
# 跑法:
#   conda activate mimicattack
#   bash pids_attack/detection/pidsmaker_setup.sh
#
# 幂等:已 clone / 已装 deps / 已起 postgres 都跳过,失败 fail-fast。

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDSMAKER_DIR="${PIDSMAKER_DIR:-$PROJECT_ROOT/PIDSMaker}"
REQUIREMENTS_FILE="$PROJECT_ROOT/requirements.txt"
PGUSER="${PGUSER:-pids}"
PGDB="${PGDB:-pids_attack}"

# 确认在 mimicattack conda env(防误装到 base)
if [ -z "${CONDA_DEFAULT_ENV:-}" ] || [ "$CONDA_DEFAULT_ENV" != "mimicattack" ]; then
    echo "[setup] WARN: 当前 conda env = '${CONDA_DEFAULT_ENV:-none}',应为 'mimicattack'"
    echo "[setup] 请先: source activate mimicattack"
    echo "[setup] 或: conda run -n mimicattack bash $0"
    exit 1
fi

echo "[setup] PROJECT_ROOT = $PROJECT_ROOT"
echo "[setup] PIDSMAKER_DIR = $PIDSMAKER_DIR"
echo "[setup] REQUIREMENTS = $REQUIREMENTS_FILE"

# ============================================================================
# 1. clone PIDSMaker(幂等)
# ============================================================================
if [ ! -d "$PIDSMAKER_DIR" ]; then
    echo "[setup] clone PIDSMaker → $PIDSMAKER_DIR"
    git clone https://github.com/ubc-provenance/PIDSMaker.git "$PIDSMAKER_DIR"
else
    echo "[setup] PIDSMaker 已 clone,跳过"
fi

# ============================================================================
# 2. 校验 PIDSMaker 源码可 import(走 sys.path,不 pip install -e)
# ============================================================================
# 我们的代码在 detection/pidsmaker.py 等里手动 sys.path.insert(0, PIDSMAKER_DIR),
# 不依赖 site-packages,保证 PIDSMaker 在项目目录下编辑可见而非「外部库」。
if pip show pidsmaker > /dev/null 2>&1; then
    echo "[setup] WARN: site-packages 里有 pip install 的 pidsmaker,可能跟 sys.path 路径冲突"
    echo "[setup]       建议手动 pip uninstall pidsmaker"
fi
if [ ! -f "$PIDSMAKER_DIR/pidsmaker/__init__.py" ]; then
    echo "[setup] FAIL: $PIDSMAKER_DIR/pidsmaker/__init__.py 不存在"
    exit 1
fi
echo "[setup] PIDSMaker 源码 OK,走 sys.path 加载"

# ============================================================================
# 3. 装锁定的运行时依赖(读 requirements 文件)
# ============================================================================
if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo "[setup] ERROR: requirements 文件不存在 — $REQUIREMENTS_FILE"
    exit 1
fi

echo "[setup] 装运行时依赖 from $REQUIREMENTS_FILE"
# torch_scatter 单独从 PyG wheel index 装(macOS Apple Silicon 必须)
# 先看有没有装好
if python -c "import torch_scatter" > /dev/null 2>&1; then
    echo "[setup] torch_scatter 已装,跳过"
else
    echo "[setup] 装 torch_scatter from PyG wheel index"
    pip install torch_scatter==2.1.2 \
        -f https://data.pyg.org/whl/torch-2.1.0+cpu.html \
        --no-build-isolation
fi

# 其他 deps 走标准 PyPI(过滤掉 torch_scatter 行,因为已单独装)
TMP_REQ=$(mktemp)
trap "rm -f $TMP_REQ" EXIT
grep -v "^torch_scatter" "$REQUIREMENTS_FILE" | grep -v "^#" | grep -v "^$" > "$TMP_REQ"
pip install -r "$TMP_REQ"

# ============================================================================
# 4. 起 PostgreSQL(幂等)
# ============================================================================
if pg_isready -h localhost > /dev/null 2>&1; then
    echo "[setup] postgres 已 ready 在 localhost:5432"
elif docker ps --format '{{.Names}}' | grep -q "^pids_postgres$"; then
    echo "[setup] pids_postgres 容器已 up"
else
    echo "[setup] 起 pids_postgres docker 容器"
    docker run -d --name pids_postgres -p 5432:5432 \
        -e POSTGRES_USER="$PGUSER" -e POSTGRES_PASSWORD="$PGUSER" \
        -e POSTGRES_DB="$PGDB" postgres:14
    sleep 5
fi

# ============================================================================
# 5. import 自检 + 落盘 commit hash
# ============================================================================
echo "[setup] 自检 import..."
python -c "
import sys
sys.path.insert(0, '$PIDSMAKER_DIR')
import pidsmaker
import torch_scatter
import gensim
import psycopg
import psycopg2
import yacs
import wandb
import wget
import igraph
import networkx
print('[selftest] all imports OK')
print('  pidsmaker:', pidsmaker.__file__)
" || {
    echo "[setup] FAIL: import 自检失败"
    exit 1
}

# 8 个 detector config 加载自检
python -c "
import yaml
detectors = ['orthrus', 'kairos', 'magic', 'flash', 'threatrace', 'nodlink', 'rcaid', 'velox']
for d in detectors:
    with open('$PIDSMAKER_DIR/config/' + d + '.yml') as f:
        yaml.safe_load(f)
print('[selftest] 8 detector configs all parseable')
" || {
    echo "[setup] FAIL: detector config 加载失败"
    exit 1
}

# 落盘版本
git -C "$PIDSMAKER_DIR" rev-parse HEAD > "$PROJECT_ROOT/PIDSMAKER_VERSION.txt"
COMMIT=$(cat "$PROJECT_ROOT/PIDSMAKER_VERSION.txt")

echo ""
echo "============================================================"
echo "[setup] DONE"
echo "  PIDSMaker:         $PIDSMAKER_DIR"
echo "  PIDSMaker commit:  $COMMIT"
echo "  postgres db:       $PGDB"
echo "  requirements:      $REQUIREMENTS_FILE"
echo "============================================================"
