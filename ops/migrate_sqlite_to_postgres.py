import os
import sqlite3
import sys
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_values


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT))


TABLES = [
    "clientes",
    "servidores",
    "logs_email",
    "logs_nao_cadastrados",
    "config_email",
    "usuarios",
    "user_sessions",
    "maintenance_runs",
    "retention_config",
    "monitoramento_diario",
    "agendamentos_backup",
    "worker_runs",
    "zammad_config",
    "zammad_alertas",
    "api_keys",
    "agent_heartbeats",
    "agent_heartbeat_history",
]


def sqlite_columns(conn, table):
    return [row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def postgres_columns(conn, table):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema='public' AND table_name=%s
            ORDER BY ordinal_position
            """,
            (table,),
        )
        return [row[0] for row in cur.fetchall()]


def table_exists_postgres(conn, table):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema='public' AND table_name=%s
            """,
            (table,),
        )
        return cur.fetchone() is not None


def table_exists_sqlite(conn, table):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def init_postgres():
    os.environ["DATABASE_URL"] = os.environ["DATABASE_URL"].strip()
    from db import init_db

    init_db()


def main():
    sqlite_path = Path(os.getenv("SQLITE_DB_PATH", "/data/backups.db"))
    database_url = os.getenv("DATABASE_URL", "").strip()
    if not sqlite_path.exists():
        raise SystemExit(f"SQLite DB not found: {sqlite_path}")
    if not database_url:
        raise SystemExit("DATABASE_URL is required")

    init_postgres()

    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row
    pg_conn = psycopg2.connect(database_url)
    pg_conn.autocommit = False

    try:
        with pg_conn.cursor() as cur:
            existing = [
                table
                for table in TABLES
                if table_exists_sqlite(sqlite_conn, table)
                and table_exists_postgres(pg_conn, table)
            ]
            if existing:
                cur.execute(
                    "TRUNCATE TABLE "
                    + ", ".join(existing)
                    + " RESTART IDENTITY CASCADE"
                )

        report = {}
        for table in TABLES:
            if not table_exists_sqlite(sqlite_conn, table):
                continue

            source_cols = sqlite_columns(sqlite_conn, table)
            target_cols = postgres_columns(pg_conn, table)
            cols = [col for col in source_cols if col in target_cols]
            if not cols:
                continue

            rows = sqlite_conn.execute(
                f"SELECT {', '.join(cols)} FROM {table} ORDER BY id"
                if "id" in cols
                else f"SELECT {', '.join(cols)} FROM {table}"
            ).fetchall()
            if rows:
                values = [tuple(row[col] for col in cols) for row in rows]
                with pg_conn.cursor() as cur:
                    execute_values(
                        cur,
                        f"INSERT INTO {table} ({', '.join(cols)}) VALUES %s",
                        values,
                        page_size=1000,
                    )
            report[table] = len(rows)

        with pg_conn.cursor() as cur:
            for table in TABLES:
                cur.execute("SELECT pg_get_serial_sequence(%s, 'id')", (table,))
                seq = cur.fetchone()[0]
                if not seq:
                    continue
                cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}")
                max_id = cur.fetchone()[0]
                cur.execute("SELECT setval(%s, %s, %s)", (seq, max_id, max_id > 0))

        pg_conn.commit()

        for table, count in report.items():
            print(f"{table}: {count}")
        print("Migration finished.")
    except Exception:
        pg_conn.rollback()
        raise
    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == "__main__":
    main()
