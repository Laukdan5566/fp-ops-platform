"""Retencao automatica e manual dos logs de backup (limpa registros antigos e guarda copia do banco antes)."""
import json
import shutil
from datetime import datetime, timedelta

from db import DB_PATH, USING_POSTGRES, get_db
from util import agora_sql

def retention_config(db):
    config = db.execute("SELECT * FROM retention_config WHERE id=1").fetchone()
    if config:
        return config

    db.execute("""
        INSERT OR IGNORE INTO retention_config (
            id, logs_full_days, unknown_logs_days, worker_runs_days,
            zammad_alerts_days, heartbeat_history_days, session_history_days, auto_enabled, updated_at
        )
        VALUES (1, 90, 30, 180, 180, 90, 30, 1, ?)
    """, (agora_sql(),))
    db.commit()
    return db.execute("SELECT * FROM retention_config WHERE id=1").fetchone()


def executar_retencao(manual=False):
    db = get_db()
    config = retention_config(db)
    run_id = None
    backup_path = None
    try:
        cur = db.execute("""
            INSERT INTO maintenance_runs (action, started_at, status, detail)
            VALUES ('retention', ?, 'running', ?)
        """, (agora_sql(), "manual" if manual else "auto"))
        run_id = cur.lastrowid
        db.commit()

        if USING_POSTGRES:
            backup_path = "postgres"
        else:
            backup_dir = DB_PATH.parent
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_path = backup_dir / f"backups-retention-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
        if not USING_POSTGRES and DB_PATH.exists():
            shutil.copy2(DB_PATH, backup_path)

        logs_limite = (datetime.now() - timedelta(days=int(config["logs_full_days"] or 90))).strftime("%Y-%m-%d %H:%M:%S")
        unknown_limite = (datetime.now() - timedelta(days=int(config["unknown_logs_days"] or 30))).strftime("%Y-%m-%d %H:%M:%S")
        worker_limite = (datetime.now() - timedelta(days=int(config["worker_runs_days"] or 180))).strftime("%Y-%m-%d %H:%M:%S")
        zammad_limite = (datetime.now() - timedelta(days=int(config["zammad_alerts_days"] or 180))).strftime("%Y-%m-%d %H:%M:%S")
        heartbeat_limite = (datetime.now() - timedelta(days=int(config["heartbeat_history_days"] or 90))).strftime("%Y-%m-%d %H:%M:%S")
        session_limite = (datetime.now() - timedelta(days=int(config["session_history_days"] or 30))).strftime("%Y-%m-%d %H:%M:%S")

        stats = {}
        cur = db.execute("""
            UPDATE logs_email
            SET conteudo_raw=NULL
            WHERE conteudo_raw IS NOT NULL
              AND datetime(data_email) < datetime(?)
        """, (logs_limite,))
        stats["logs_compactados"] = cur.rowcount

        cur = db.execute("""
            DELETE FROM logs_nao_cadastrados
            WHERE datetime(COALESCE(created_at, data_email)) < datetime(?)
        """, (unknown_limite,))
        stats["nao_cadastrados_removidos"] = cur.rowcount

        cur = db.execute("""
            DELETE FROM worker_runs
            WHERE datetime(started_at) < datetime(?)
        """, (worker_limite,))
        stats["worker_runs_removidos"] = cur.rowcount

        cur = db.execute("""
            DELETE FROM zammad_alertas
            WHERE datetime(COALESCE(updated_at, created_at)) < datetime(?)
        """, (zammad_limite,))
        stats["zammad_alertas_removidos"] = cur.rowcount

        cur = db.execute("""
            DELETE FROM agent_heartbeat_history
            WHERE datetime(seen_at) < datetime(?)
        """, (heartbeat_limite,))
        stats["heartbeat_history_removidos"] = cur.rowcount

        cur = db.execute("""
            DELETE FROM user_sessions
            WHERE ativo=0
              AND datetime(COALESCE(logged_out_at, last_seen, created_at)) < datetime(?)
        """, (session_limite,))
        stats["sessoes_removidas"] = cur.rowcount

        detalhe = json.dumps({**stats, "backup": str(backup_path)}, ensure_ascii=False)
        db.execute("""
            UPDATE maintenance_runs
            SET finished_at=?, status='success', detail=?
            WHERE id=?
        """, (agora_sql(), detalhe, run_id))
        db.commit()
        db.execute("VACUUM")
        db.close()
        return stats, str(backup_path)
    except Exception as exc:
        if run_id:
            db.execute("""
                UPDATE maintenance_runs
                SET finished_at=?, status='error', detail=?
                WHERE id=?
            """, (agora_sql(), str(exc), run_id))
            db.commit()
        db.close()
        raise


def talvez_executar_retencao_automatica():
    db = get_db()
    try:
        config = retention_config(db)
        if not int(config["auto_enabled"] or 0):
            return
        hoje = datetime.now().strftime("%Y-%m-%d")
        ja_rodou = db.execute("""
            SELECT 1
            FROM maintenance_runs
            WHERE action='retention'
              AND status IN ('success', 'running')
              AND date(started_at)=date(?)
            LIMIT 1
        """, (hoje,)).fetchone()
        if ja_rodou:
            return
    finally:
        db.close()

    executar_retencao(manual=False)
