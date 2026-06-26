"""detection/data/data_prep.py — 数据源无关的灌库 / 时间映射 / 索引修正 / GT 工具。

跟 PIDSMaker 解耦:这一层只产 PIDSMaker 兼容的 PostgreSQL DB,跟具体数据源(JUICESHOP / DARPA / OpTC)无关。

不含 `replicate_sql`(已弃用)—— 数据量靠 `scripts/run.py detect collect --num-collections N` 真采集解决。
"""
from __future__ import annotations
import os
import re
import subprocess
from datetime import datetime
from typing import List, Tuple

# ============================================================================
# Postgres 客户端(走 docker exec,host 没装 psql client)
# ============================================================================

PG_CONTAINER = os.environ.get("PIDS_PG_CONTAINER", "pids_postgres")


def docker_psql_exec(sql: str, db_name: str, user: str, password: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}", PG_CONTAINER,
         "psql", "-U", user, "-d", db_name, "-c", sql],
        capture_output=True, text=True,
    )


def docker_psql_file(sql_file_host: str, db_name: str, user: str, password: str) -> subprocess.CompletedProcess:
    """psql -f file:把 host 文件 cp 进容器再执行。"""
    container_path = f"/tmp/{os.path.basename(sql_file_host)}"
    cp = subprocess.run(
        ["docker", "cp", sql_file_host, f"{PG_CONTAINER}:{container_path}"],
        capture_output=True, text=True,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"docker cp failed: {cp.stderr}")
    return subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}", PG_CONTAINER,
         "psql", "-U", user, "-d", db_name, "-f", container_path],
        capture_output=True, text=True,
    )


# ============================================================================
# DB 生命周期
# ============================================================================

def ensure_database(db_name: str = "juiceshop", user: str = "postgres", password: str = "postgres"):
    """创建 db(若不存在) + 4 张 PIDSMaker schema 表(若不存在)。"""
    cp = subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}", PG_CONTAINER,
         "psql", "-U", user, "-d", "postgres", "-tAc",
         f"SELECT 1 FROM pg_database WHERE datname='{db_name}'"],
        capture_output=True, text=True,
    )
    if cp.returncode == 0 and cp.stdout.strip() == "1":
        print(f"[create_db] db {db_name} already exists")
    else:
        subprocess.run(
            ["docker", "exec", "-e", f"PGPASSWORD={password}", PG_CONTAINER,
             "psql", "-U", user, "-d", "postgres", "-c", f"CREATE DATABASE {db_name}"],
            check=False,
        )
        print(f"[create_db] created db {db_name}")

    ddl = """
CREATE TABLE IF NOT EXISTS subject_node_table (
    node_uuid VARCHAR, hash_id VARCHAR, path VARCHAR, cmd VARCHAR, index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE IF NOT EXISTS file_node_table (
    node_uuid VARCHAR NOT NULL, hash_id VARCHAR NOT NULL, path VARCHAR, index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE IF NOT EXISTS netflow_node_table (
    node_uuid VARCHAR NOT NULL, hash_id VARCHAR NOT NULL,
    src_addr VARCHAR, src_port VARCHAR, dst_addr VARCHAR, dst_port VARCHAR, index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
CREATE TABLE IF NOT EXISTS event_table (
    src_node VARCHAR, src_index_id VARCHAR, operation VARCHAR,
    dst_node VARCHAR, dst_index_id VARCHAR, event_uuid VARCHAR NOT NULL,
    timestamp_rec BIGINT, _id SERIAL PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS event_table_src_idx ON event_table (src_node);
CREATE INDEX IF NOT EXISTS event_table_dst_idx ON event_table (dst_node);
CREATE INDEX IF NOT EXISTS event_table_ts_idx ON event_table (timestamp_rec);
"""
    ddl_path = "/tmp/_data_prep_ddl.sql"
    with open(ddl_path, "w") as f:
        f.write(ddl)
    cp = docker_psql_file(ddl_path, db_name, user, password)
    if cp.returncode != 0:
        raise RuntimeError(f"DDL apply failed: {cp.stderr}")
    print(f"[create_db] DDL applied to {db_name}")


def truncate_tables(db_name: str = "juiceshop", user: str = "postgres", password: str = "postgres"):
    sql = "TRUNCATE TABLE event_table, subject_node_table, file_node_table, netflow_node_table CASCADE;"
    cp = docker_psql_exec(sql, db_name, user, password)
    if cp.returncode != 0:
        print(f"[truncate] WARN: {cp.stderr[:200]}")
    else:
        print(f"[truncate] cleared {db_name}")


def load_sql_to_db(sql_path: str, db_name: str = "juiceshop", user: str = "postgres", password: str = "postgres"):
    """docker cp + psql -f 灌进 db。"""
    cp = docker_psql_file(sql_path, db_name, user, password)
    if cp.returncode != 0:
        print(f"[load_sql] FAIL: {sql_path}\n  stderr={cp.stderr[:500]}")
        raise RuntimeError(f"psql -f {sql_path} failed")
    print(f"[load_sql] OK: {sql_path}")


# ============================================================================
# Timestamp 映射(把真实采集时间映射到 PIDSMaker fake-dates)
# ============================================================================

DATE_DURATION_NS = 24 * 60 * 60 * 1_000_000_000  # 1 day in ns

# 匹配 INSERT INTO event_table ... VALUES (..., timestamp_rec_int);
_RE_EVENT_INSERT = re.compile(
    r"(INSERT INTO event_table[^V]+VALUES \(.*?, .*?, .*?, .*?, .*?, .*?, )(\d+)(\);)"
)


def get_timestamp_range(sql_text: str) -> Tuple[int, int]:
    """扫 SQL 拿 event_table.timestamp_rec 的 (min, max)。"""
    timestamps = []
    for m in _RE_EVENT_INSERT.finditer(sql_text):
        timestamps.append(int(m.group(2)))
    if not timestamps:
        return (0, 0)
    return (min(timestamps), max(timestamps))


def shift_timestamps_in_sql(sql_text: str, src_min_ns: int, dst_start_ns: int) -> str:
    """只平移,不拉伸。

    把每个事件的 timestamp 从 [src_min, src_max] 整体平移到 [dst_start, dst_start + (src_max - src_min)]。
    事件之间的相对时序保持原样,密度不变。

    用途:真实采集 timestamp 在 2026-05,PIDSMaker config fake-dates 在 2026-01,
    需要 shift 到 fake-date 上让 PIDSMaker construction 阶段能 filter 到事件;
    但**不应该把 5 min 拉伸成 24h**(那会破坏 rcaid 等 baseline 的事件密度假设)。
    """
    def replace(m):
        prefix = m.group(1)
        src_ts = int(m.group(2))
        suffix = m.group(3)
        delta = src_ts - src_min_ns
        return f"{prefix}{dst_start_ns + delta}{suffix}"

    return _RE_EVENT_INSERT.sub(replace, sql_text)


# ============================================================================
# Index 重写(灌库后修 event_table.src_index_id / dst_index_id 引用)
# ============================================================================

def reassign_global_unique_index_ids(db_name: str = "juiceshop", user: str = "postgres", password: str = "postgres"):
    """重分配 subject/file/netflow index_id,跨表全局唯一(PIDSMaker 期望)。"""
    sql_a = (
        "UPDATE subject_node_table SET index_id = sub.rn FROM ("
        "SELECT node_uuid, hash_id, ROW_NUMBER() OVER () - 1 AS rn FROM subject_node_table"
        ") sub WHERE subject_node_table.node_uuid = sub.node_uuid AND subject_node_table.hash_id = sub.hash_id;"
    )
    sql_b = (
        "UPDATE file_node_table SET index_id = sub.rn FROM ("
        "SELECT node_uuid, hash_id, ROW_NUMBER() OVER () - 1 + (SELECT COUNT(*) FROM subject_node_table) AS rn "
        "FROM file_node_table"
        ") sub WHERE file_node_table.node_uuid = sub.node_uuid AND file_node_table.hash_id = sub.hash_id;"
    )
    sql_c = (
        "UPDATE netflow_node_table SET index_id = sub.rn FROM ("
        "SELECT node_uuid, hash_id, ROW_NUMBER() OVER () - 1 + "
        "(SELECT COUNT(*) FROM subject_node_table) + (SELECT COUNT(*) FROM file_node_table) AS rn "
        "FROM netflow_node_table"
        ") sub WHERE netflow_node_table.node_uuid = sub.node_uuid AND netflow_node_table.hash_id = sub.hash_id;"
    )
    for sql in [sql_a, sql_b, sql_c]:
        cp = docker_psql_exec(sql, db_name, user, password)
        if cp.returncode != 0:
            raise RuntimeError(f"reassign_global_unique_index_ids failed: {cp.stderr}")
    print(f"[reassign_index] subject/file/netflow index_id 重分配完成,全局唯一")


def fix_event_index_ids(db_name: str = "juiceshop", user: str = "postgres", password: str = "postgres"):
    """修 event_table.src_index_id / dst_index_id 引用:hash_id → 节点表 index_id::text。

    用 JOIN-based UPDATE(O(N) 而不是 correlated subquery 的 O(N²))。
    """
    create_idx = """
    CREATE INDEX IF NOT EXISTS subject_hash_idx ON subject_node_table (hash_id);
    CREATE INDEX IF NOT EXISTS file_hash_idx ON file_node_table (hash_id);
    CREATE INDEX IF NOT EXISTS netflow_hash_idx ON netflow_node_table (hash_id);
    CREATE INDEX IF NOT EXISTS event_src_node_idx ON event_table (src_node);
    CREATE INDEX IF NOT EXISTS event_dst_node_idx ON event_table (dst_node);
    """
    docker_psql_exec(create_idx, db_name, user, password)

    updates = [
        ("src_subject", "UPDATE event_table e SET src_index_id = s.index_id::text "
                        "FROM subject_node_table s WHERE e.src_node = s.hash_id;"),
        ("src_file",    "UPDATE event_table e SET src_index_id = f.index_id::text "
                        "FROM file_node_table f WHERE e.src_node = f.hash_id "
                        "AND e.src_index_id = e.src_node;"),
        ("src_netflow", "UPDATE event_table e SET src_index_id = n.index_id::text "
                        "FROM netflow_node_table n WHERE e.src_node = n.hash_id "
                        "AND e.src_index_id = e.src_node;"),
        ("dst_subject", "UPDATE event_table e SET dst_index_id = s.index_id::text "
                        "FROM subject_node_table s "
                        "WHERE e.dst_node IS NOT NULL AND e.dst_node != '' "
                        "AND e.dst_node = s.hash_id;"),
        ("dst_file",    "UPDATE event_table e SET dst_index_id = f.index_id::text "
                        "FROM file_node_table f "
                        "WHERE e.dst_node IS NOT NULL AND e.dst_node != '' "
                        "AND e.dst_node = f.hash_id AND e.dst_index_id = e.dst_node;"),
        ("dst_netflow", "UPDATE event_table e SET dst_index_id = n.index_id::text "
                        "FROM netflow_node_table n "
                        "WHERE e.dst_node IS NOT NULL AND e.dst_node != '' "
                        "AND e.dst_node = n.hash_id AND e.dst_index_id = e.dst_node;"),
    ]
    for label, sql in updates:
        cp = docker_psql_exec(sql, db_name, user, password)
        if cp.returncode != 0:
            raise RuntimeError(f"fix_event_index_ids {label} failed: {cp.stderr}")
    print(f"[fix_event] event_table.src_index_id/dst_index_id remapped to int(index_id)::text")


def delete_empty_dst_events(db_name: str = "juiceshop", user: str = "postgres", password: str = "postgres"):
    """删空 dst_node 的边(EVENT_CLONE 这类没填 dst,PIDSMaker gen_edge_fused_tw 不处理)。"""
    cp = docker_psql_exec(
        "DELETE FROM event_table WHERE dst_node IS NULL OR dst_node = '' "
        "OR dst_index_id IS NULL OR dst_index_id = '';",
        db_name, user, password,
    )
    if cp.returncode != 0:
        print(f"[delete_empty_dst] WARN: {cp.stderr[:200]}")
    else:
        print(f"[delete_empty_dst] removed events with empty dst")


# ============================================================================
# Ground Truth 生成(从 DB join 抽,跟 PIDSMaker save_indexid2msg filter 对齐)
# ============================================================================

def write_ground_truth_from_db(scenario_id: str, gt_dir: str, db_name: str,
                                user: str, password: str,
                                attack_day_start_ns: int, attack_day_end_ns: int) -> str:
    """从 DB 抽指定时间窗内 attack scenario 涉及的 subject/file/netflow,写 PIDSMaker GT csv。"""
    os.makedirs(gt_dir, exist_ok=True)
    gt_path = os.path.join(gt_dir, f"{scenario_id}.csv")

    sql_query = f"""
SELECT DISTINCT s.node_uuid, s.index_id, 'subject' AS ty
FROM subject_node_table s
JOIN event_table e ON e.src_node = s.hash_id OR e.dst_node = s.hash_id
WHERE e.timestamp_rec >= {attack_day_start_ns} AND e.timestamp_rec < {attack_day_end_ns}
UNION ALL
SELECT DISTINCT f.node_uuid, f.index_id, 'file' AS ty
FROM file_node_table f
JOIN event_table e ON e.dst_node = f.hash_id
WHERE e.timestamp_rec >= {attack_day_start_ns} AND e.timestamp_rec < {attack_day_end_ns}
  AND (f.path LIKE '%passwd%' OR f.path LIKE '%shadow%' OR f.path LIKE '%sqlite%' OR f.path LIKE '%juice-shop%')
UNION ALL
SELECT DISTINCT n.node_uuid, n.index_id, 'netflow' AS ty
FROM netflow_node_table n
JOIN event_table e ON e.dst_node = n.hash_id
WHERE e.timestamp_rec >= {attack_day_start_ns} AND e.timestamp_rec < {attack_day_end_ns};
"""
    cp = subprocess.run(
        ["docker", "exec", "-e", f"PGPASSWORD={password}", PG_CONTAINER,
         "psql", "-U", user, "-d", db_name, "-tAF", "|", "-c", sql_query],
        capture_output=True, text=True,
    )
    if cp.returncode != 0:
        print(f"[gt] FAIL {scenario_id}: {cp.stderr[:200]}")
        open(gt_path, "w").close()
        return gt_path

    rows = []
    for line in cp.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        node_uuid, index_id, ty = parts[0], parts[1], parts[2]
        rows.append((node_uuid, f"{{'{ty}': 'attack_node'}}", index_id))

    with open(gt_path, "w") as f:
        for uuid, label, idx in rows:
            f.write(f"{uuid},{label},{idx}\n")
    print(f"[gt] {scenario_id}: {len(rows)} attack nodes (db-joined) → {gt_path}")
    return gt_path


# ============================================================================
# JUICESHOP ingestion
# ============================================================================

"""detection/data/data_prep.py — JUICESHOP 灌库主流程。

读 N 份 training_traces/benign_*.sql + 10 份 test_traces/attack/*.sql 真采集数据,直接灌进 PostgreSQL。
**不复制(replicate_sql 弃用)** —— 数据量靠 scripts/run.py detect collect --num-collections N 真采集解决。

跟 PIDSMaker 解耦:这层只产数据,PIDSMaker 不知道有 30 份 benign。

用法:
    python -m data_prep.juiceshop                          # 默认 user=pids password=pids
    python -m data_prep.juiceshop --user pids --password pids
    python -m data_prep.juiceshop --no-truncate            # 不清表(追加灌)
"""
import argparse
import glob
import os
import sys
from datetime import datetime

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)

import pytz


HOUR_NS = 3600 * 1_000_000_000

# 关键:PIDSMaker 用 US/Eastern 时区解读 fake-dates(见 utils/utils.py:datetime_to_ns_time_US),
# 所以我们灌库时的 timestamp 锚点也必须用 US/Eastern,否则事件落到不对的 fake-date 上。
PIDSMAKER_TZ = pytz.timezone("US/Eastern")


def date_to_pidsmaker_ns(d: datetime, hour: int = 0) -> int:
    """把 naive date 当成 US/Eastern 的某天 hour 点,返回 UTC ns timestamp。
    跟 PIDSMaker datetime_to_ns_time_US 对齐。
    """
    naive = datetime(d.year, d.month, d.day, hour, 0, 0)
    aware = PIDSMAKER_TZ.localize(naive)
    return int(aware.timestamp() * 1_000_000_000)


# ============================================================================
# JUICESHOP 配置(对齐 PIDSMaker pids_attack/PIDSMaker/pidsmaker/config/config.py)
# ============================================================================

TRAIN_DATES = [datetime(2026, 1, 1), datetime(2026, 1, 2), datetime(2026, 1, 3)]
VAL_DATES = [datetime(2026, 1, 4)]
TEST_DATES = [datetime(2026, 1, 5), datetime(2026, 1, 6)]
ALL_DATES = TRAIN_DATES + VAL_DATES + TEST_DATES  # 6 fake-dates

# attack scenario → 对应 fake test date
ATTACK_TO_DATE = [
    ("juiceshop_basket_idor",                  TEST_DATES[0]),
    ("juiceshop_db_schema_union_sqli",         TEST_DATES[1]),
    ("juiceshop_directory_listing_ftp",        TEST_DATES[0]),
    ("juiceshop_exposed_metrics",              TEST_DATES[1]),
    ("juiceshop_login_admin_sqli",             TEST_DATES[0]),
    ("juiceshop_login_bender_sqli",            TEST_DATES[1]),
    ("juiceshop_login_jim_sqli",               TEST_DATES[0]),
    ("juiceshop_redirect_open",                TEST_DATES[1]),
    ("juiceshop_register_admin_mass_assignment", TEST_DATES[0]),
    ("juiceshop_weak_password_admin",          TEST_DATES[1]),
]

GT_DIR = os.path.join(PROJECT_ROOT, "PIDSMaker", "Ground_Truth", "orthrus", "JUICESHOP")

BENIGN_LEAK_PATTERNS = [
    " OR 1=1",
    "admin123",
    "admin@juice-sh.op",
    "bender@juice-sh.op",
    "jim@juice-sh.op",
    "sqlite_master",
    "UNION SELECT",
    "/rest/user/login",
    "/rest/basket/",
    "/api/Users",
    "/ftp/acquisitions.md",
    "/metrics",
    "/redirect?to=",
    "explorer.dash.org",
    "data/static/codefixes",
    "redirectChallenge",
    "loginAdminChallenge",
    "resetPassword",
]


# ============================================================================
# 灌库主流程
# ============================================================================

def discover_benign_sqls(traces_dir: str) -> list:
    """先找 benign_*.sql(多次采集),没有则 fallback 到 benign.sql 单份。"""
    multi = sorted(glob.glob(os.path.join(traces_dir, "benign_*.sql")))
    if multi:
        return multi
    single = os.path.join(traces_dir, "benign.sql")
    if os.path.exists(single):
        return [single]
    return []


def audit_training_data_separation(traces_dir: str, attack_dir: str) -> None:
    """Fail fast if benign training data is mixed with attack/test traces.

    Training/validation data must be benign-only. Attack traces are allowed only
    under detection/data/test_traces/attack and are ingested into test dates.
    """
    legacy_attack_dir = os.path.join(traces_dir, "attack")
    if os.path.isdir(legacy_attack_dir):
        raise RuntimeError(
            "attack traces are mixed under training_traces; move them to "
            f"{attack_dir}"
        )
    if os.path.commonpath([os.path.abspath(traces_dir), os.path.abspath(attack_dir)]) == os.path.abspath(traces_dir):
        raise RuntimeError(
            f"attack_dir must not live inside training traces: {attack_dir}"
        )

    benign_files = sorted(glob.glob(os.path.join(traces_dir, "benign*.sql")))
    benign_files += sorted(glob.glob(os.path.join(traces_dir, "benign*.strace")))
    leaks = []
    for path in benign_files:
        with open(path, errors="ignore") as f:
            text = f.read()
        for pattern in BENIGN_LEAK_PATTERNS:
            if pattern in text:
                leaks.append((path, pattern))
                break
    if leaks:
        lines = [
            "benign training traces contain attack/source-footprint leakage; "
            "recollect benign traces before training:"
        ]
        lines.extend(
            f"  - {os.path.relpath(path, PROJECT_ROOT)} contains {pattern!r}"
            for path, pattern in leaks[:20]
        )
        raise RuntimeError("\n".join(lines))


def ingest_juiceshop_dataset(
    db_name: str = "juiceshop",
    user: str = "pids",
    password: str = "pids",
    truncate_first: bool = True,
):
    """主入口:读 N 份 benign + 10 份 attack SQL → 灌 DB → 写 GT."""

    traces_dir = os.path.join(PROJECT_ROOT, "detection", "data", "training_traces")
    attack_dir = os.path.join(PROJECT_ROOT, "detection", "data", "test_traces", "attack")
    audit_training_data_separation(traces_dir, attack_dir)

    benign_sqls = discover_benign_sqls(traces_dir)
    if not benign_sqls:
        raise FileNotFoundError(
            f"no benign SQL found in {traces_dir} "
            f"(expected benign_*.sql or benign.sql; "
            f"run scripts/run.py detect collect --num-collections 30 --parallel 4 first)"
        )

    print(f"[juiceshop] {len(benign_sqls)} benign SQL files found")
    for f in benign_sqls[:3]:
        print(f"  - {os.path.relpath(f, PROJECT_ROOT)}")
    if len(benign_sqls) > 3:
        print(f"  - ... ({len(benign_sqls) - 3} more)")

    # 1. DB 起来 + 清表
    ensure_database(db_name, user, password)
    if truncate_first:
        truncate_tables(db_name, user, password)

    # 2. 灌 N 份独立 benign —— shift 平移版:每份分配到 train/val 4 天中的 1 天 +
    #    1 个独立小时,事件之间相对时序保留(密度不变)。
    #    分配规则:i-th benign → date = days[i % 4],hour = (i // 4) % 24
    benign_target_days = TRAIN_DATES + VAL_DATES  # 4 days
    print(f"\n[benign] loading {len(benign_sqls)} independent collections (shift-only)")
    for i, benign_sql in enumerate(benign_sqls):
        with open(benign_sql) as f:
            text = f.read()
        ts_min, _ = get_timestamp_range(text)
        if ts_min == 0:
            print(f"  [skip] {benign_sql}: no events")
            continue
        target_date = benign_target_days[i % len(benign_target_days)]
        hour_in_day = (i // len(benign_target_days)) % 24
        target_ns = date_to_pidsmaker_ns(target_date, hour=hour_in_day)
        remapped = shift_timestamps_in_sql(text, ts_min, target_ns)
        tmp_path = f"/tmp/juiceshop_{os.path.basename(benign_sql)}"
        with open(tmp_path, "w") as f:
            f.write(remapped)
        load_sql_to_db(tmp_path, db_name, user, password)

    # 3. 灌 10 份 attack —— shift 平移版:按 ATTACK_TO_DATE 分到 test_date,
    #    同一天内多个 attack 隔 2 小时不重叠。
    print(f"\n[attack] loading {len(ATTACK_TO_DATE)} scenarios (shift-only)")
    attack_target_days = []
    attack_hour_per_day: dict = {}  # date.date() → next free hour offset
    for sid, target_date in ATTACK_TO_DATE:
        attack_sql = os.path.join(attack_dir, f"{sid}.strace.sql")
        if not os.path.exists(attack_sql):
            print(f"  [skip] {sid}: file not found at {attack_sql}")
            continue
        with open(attack_sql) as f:
            text = f.read()
        ts_min, _ = get_timestamp_range(text)
        if ts_min == 0:
            print(f"  [skip] {sid}: no events")
            continue
        day_key = target_date.date()
        hour = attack_hour_per_day.get(day_key, 0)
        target_ns = date_to_pidsmaker_ns(target_date, hour=hour)
        remapped = shift_timestamps_in_sql(text, ts_min, target_ns)
        tmp_path = f"/tmp/juiceshop_attack_{sid}.sql"
        with open(tmp_path, "w") as f:
            f.write(remapped)
        load_sql_to_db(tmp_path, db_name, user, password)
        attack_target_days.append((sid, target_date))
        attack_hour_per_day[day_key] = hour + 2  # 隔 2 小时下一个

    # 4. 修索引 + 删空边
    print()
    reassign_global_unique_index_ids(db_name, user, password)
    fix_event_index_ids(db_name, user, password)
    delete_empty_dst_events(db_name, user, password)

    # 5. 写 Ground Truth(从 DB join 抽,跟 PIDSMaker 期望对齐)
    print(f"\n[gt] writing ground truth → {GT_DIR}")
    for sid, target_date in attack_target_days:
        # GT 查询时间窗也用 US/Eastern,跟 PIDSMaker construction 阶段对齐
        day_start_ns = date_to_pidsmaker_ns(target_date, hour=0)
        day_end_ns = day_start_ns + DATE_DURATION_NS
        write_ground_truth_from_db(sid, GT_DIR, db_name, user, password,
                                    day_start_ns, day_end_ns)

    print(f"\n[done] juiceshop dataset ingestion complete")
    print(f"  db:     {db_name}")
    print(f"  GT dir: {GT_DIR}")
    print(f"  benign: {len(benign_sqls)} files")
    print(f"  attack: {len(attack_target_days)} scenarios")


def main(args=None):
    parser = argparse.ArgumentParser(description="JUICESHOP 灌库(无 replicate)")
    parser.add_argument("--db-name", default="juiceshop")
    parser.add_argument("--user", default="pids")
    parser.add_argument("--password", default="pids")
    parser.add_argument("--no-truncate", action="store_true", help="不清表(追加灌)")
    args = parser.parse_args(args)
    ingest_juiceshop_dataset(
        db_name=args.db_name,
        user=args.user,
        password=args.password,
        truncate_first=not args.no_truncate,
    )


if __name__ == "__main__":
    main()
