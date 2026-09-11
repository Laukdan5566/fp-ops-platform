import hashlib
import os
import re
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash


DB_PATH = Path(os.getenv("DB_PATH", "/data/backups.db"))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USING_POSTGRES = bool(DATABASE_URL)


def _pg_module():
    import psycopg2
    from psycopg2.extras import DictCursor
    return psycopg2, DictCursor


def _translate_placeholders(sql):
    parts = []
    in_single = False
    in_double = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'" and not in_double:
            parts.append(ch)
            if in_single and i + 1 < len(sql) and sql[i + 1] == "'":
                parts.append(sql[i + 1])
                i += 2
                continue
            in_single = not in_single
        elif ch == '"' and not in_single:
            parts.append(ch)
            in_double = not in_double
        elif ch == "?" and not in_single and not in_double:
            parts.append("%s")
        else:
            parts.append(ch)
        i += 1
    return "".join(parts)


def _translate_insert_or_ignore(sql):
    if not re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", sql, re.I):
        return sql
    sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.I)
    if re.search(r"\bON\s+CONFLICT\b", sql, re.I):
        return sql
    return sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"


def _translate_schema_sql(sql):
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    sql = sql.replace("TEXT DEFAULT CURRENT_TIMESTAMP", "TEXT DEFAULT to_char(now(), 'YYYY-MM-DD HH24:MI:SS')")
    return sql


def _translate_sql(sql):
    if not USING_POSTGRES:
        return sql
    sql = _translate_insert_or_ignore(sql)
    sql = _translate_schema_sql(sql)
    sql = _translate_placeholders(sql)
    return sql


def _insert_uses_default_id(sql):
    match = re.search(r"\bINSERT\s+INTO\s+\w+\s*\(([^)]*)\)", sql, re.I | re.S)
    if not match:
        return False
    columns = [part.strip().strip('"').lower() for part in match.group(1).split(",")]
    return "id" not in columns


class PostgresCursor:
    def __init__(self, conn, cursor):
        self.conn = conn
        self.cursor = cursor
        self.lastrowid = None

    @property
    def rowcount(self):
        return self.cursor.rowcount

    def execute(self, sql, params=None):
        statement = sql.strip().rstrip(";")
        if statement.upper() == "VACUUM":
            self.conn.commit()
            old_autocommit = self.conn.raw.autocommit
            self.conn.raw.autocommit = True
            try:
                self.cursor.execute("VACUUM")
            finally:
                self.conn.raw.autocommit = old_autocommit
            self.lastrowid = None
            return self

        translated = _translate_sql(sql)
        if params is None:
            self.cursor.execute(translated)
        else:
            self.cursor.execute(translated, params)
        self.lastrowid = None
        if statement.upper().startswith("INSERT ") and _insert_uses_default_id(translated):
            try:
                with self.conn.raw.cursor() as cur:
                    cur.execute("SELECT LASTVAL()")
                    self.lastrowid = cur.fetchone()[0]
            except Exception:
                self.lastrowid = None
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


class PostgresConnection:
    def __init__(self, raw):
        self.raw = raw

    def execute(self, sql, params=None):
        cur = self.cursor()
        return cur.execute(sql, params)

    def cursor(self):
        _, dict_cursor = _pg_module()
        return PostgresCursor(self, self.raw.cursor(cursor_factory=dict_cursor))

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


def get_db():
    if USING_POSTGRES:
        psycopg2, dict_cursor = _pg_module()
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=dict_cursor)
        return PostgresConnection(conn)

    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def column_exists(cur, table, column):
    if USING_POSTGRES:
        row = cur.execute("""
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema='public'
              AND table_name=%s
              AND column_name=%s
            LIMIT 1
        """, (table, column)).fetchone()
        return row is not None

    columns = cur.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in columns)


def _pg_column_definition(definition):
    definition = _translate_schema_sql(definition)
    definition = definition.replace("INTEGER", "INTEGER")
    return definition


def add_column_if_missing(cur, table, column, definition):
    if column_exists(cur, table, column):
        return

    try:
        if USING_POSTGRES:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {_pg_column_definition(definition)}")
        else:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except Exception as exc:
        if "duplicate column" not in str(exc).lower():
            raise


def create_postgres_helpers(cur):
    if not USING_POSTGRES:
        return

    cur.execute("SELECT pg_advisory_xact_lock(74639201)")
    cur.execute("""
    CREATE OR REPLACE FUNCTION public.datetime(value text)
    RETURNS timestamp AS $$
    BEGIN
        IF value IS NULL OR btrim(value) = '' THEN
            RETURN NULL;
        END IF;
        IF lower(value) = 'now' THEN
            RETURN now()::timestamp;
        END IF;
        RETURN value::timestamp;
    EXCEPTION WHEN others THEN
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql IMMUTABLE;
    """)
    cur.execute("""
    CREATE OR REPLACE FUNCTION public.datetime(value text, modifier text)
    RETURNS timestamp AS $$
    DECLARE
        base timestamp;
    BEGIN
        base := public.datetime(value);
        IF base IS NULL THEN
            RETURN NULL;
        END IF;
        IF modifier IS NULL OR btrim(modifier) = '' THEN
            RETURN base;
        END IF;
        RETURN base + modifier::interval;
    EXCEPTION WHEN others THEN
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql STABLE;
    """)
    cur.execute("""
    CREATE OR REPLACE FUNCTION public.date(value text)
    RETURNS date AS $$
    BEGIN
        RETURN public.datetime(value)::date;
    EXCEPTION WHEN others THEN
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql IMMUTABLE;
    """)


def init_db():
    conn = get_db()
    cur = conn.cursor()
    create_postgres_helpers(cur)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS clientes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome_exibicao TEXT NOT NULL,
        ativo INTEGER DEFAULT 1,
        responsavel_nome TEXT,
        responsavel_email TEXT,
        alertar_eventos_windows INTEGER DEFAULT 0
    )
    """)
    add_column_if_missing(cur, "clientes", "responsavel_nome", "TEXT")
    add_column_if_missing(cur, "clientes", "responsavel_email", "TEXT")
    add_column_if_missing(cur, "clientes", "alertar_eventos_windows", "INTEGER DEFAULT 0")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS servidores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_id INTEGER,
        nome_log TEXT,
        backups_semana INTEGER,
        ativo INTEGER DEFAULT 1,
        dias_execucao TEXT,
        hora_execucao TEXT,
        tolerancia_min INTEGER DEFAULT 120
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs_email (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        servidor_log TEXT,
        status TEXT,
        data_email TEXT,
        conteudo_raw TEXT,
        message_id TEXT,
        subject TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    add_column_if_missing(cur, "logs_email", "subject", "TEXT")
    add_column_if_missing(cur, "logs_email", "created_at", "TEXT")
    add_column_if_missing(cur, "logs_email", "origem", "TEXT DEFAULT 'email'")
    add_column_if_missing(cur, "logs_email", "conteudo_hash", "TEXT")
    logs_sem_hash = cur.execute("""
        SELECT id, conteudo_raw
        FROM logs_email
        WHERE conteudo_hash IS NULL AND conteudo_raw IS NOT NULL
    """).fetchall()
    for log in logs_sem_hash:
        cur.execute(
            "UPDATE logs_email SET conteudo_hash=? WHERE id=?",
            (hashlib.sha256((log[1] or "").encode()).hexdigest(), log[0]),
        )

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs_nao_cadastrados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        servidor_log TEXT,
        data_email TEXT,
        message_id TEXT,
        subject TEXT,
        conteudo_raw TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    add_column_if_missing(cur, "logs_nao_cadastrados", "message_id", "TEXT")
    add_column_if_missing(cur, "logs_nao_cadastrados", "subject", "TEXT")
    add_column_if_missing(cur, "logs_nao_cadastrados", "conteudo_raw", "TEXT")
    add_column_if_missing(cur, "logs_nao_cadastrados", "created_at", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS config_email (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        imap_server TEXT,
        imap_port INTEGER,
        email_user TEXT,
        email_pass TEXT,
        pasta TEXT,
        usar_ssl INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        senha_hash TEXT,
        tipo TEXT,
        ativo INTEGER DEFAULT 1
    )
    """)
    add_column_if_missing(cur, "usuarios", "max_sessoes", "INTEGER DEFAULT 1")

    admin_user = os.getenv("ADMIN_USER")
    admin_pass = os.getenv("ADMIN_PASS")

    if admin_user and admin_pass:
        senha_hash = generate_password_hash(admin_pass, method="scrypt")
        cur.execute("""
            INSERT OR IGNORE INTO usuarios (username, senha_hash, tipo)
            VALUES (?, ?, 'admin')
        """, (admin_user, senha_hash))
        cur.execute("""
            UPDATE usuarios
            SET max_sessoes=3
            WHERE username=? AND (max_sessoes IS NULL OR max_sessoes < 1)
        """, (admin_user,))

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        username TEXT,
        ip TEXT,
        user_agent TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_seen TEXT,
        logged_out_at TEXT,
        ativo INTEGER DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS maintenance_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        detail TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS retention_config (
        id INTEGER PRIMARY KEY CHECK (id=1),
        logs_full_days INTEGER DEFAULT 90,
        unknown_logs_days INTEGER DEFAULT 30,
        worker_runs_days INTEGER DEFAULT 180,
        zammad_alerts_days INTEGER DEFAULT 180,
        heartbeat_history_days INTEGER DEFAULT 90,
        session_history_days INTEGER DEFAULT 30,
        auto_enabled INTEGER DEFAULT 1,
        updated_at TEXT
    )
    """)
    add_column_if_missing(cur, "retention_config", "heartbeat_history_days", "INTEGER DEFAULT 90")
    cur.execute("""
        INSERT OR IGNORE INTO retention_config (
            id, logs_full_days, unknown_logs_days, worker_runs_days,
            zammad_alerts_days, heartbeat_history_days, session_history_days, auto_enabled, updated_at
        )
        VALUES (1, 90, 30, 180, 180, 90, 30, 1, CURRENT_TIMESTAMP)
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS monitoramento_diario (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        servidor_id INTEGER,
        data_referencia TEXT,
        status TEXT,
        detalhe TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS agendamentos_backup (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        servidor_id INTEGER,
        dias_execucao TEXT,
        hora_execucao TEXT,
        tolerancia_min INTEGER DEFAULT 120,
        ativo INTEGER DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS worker_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        emails_encontrados INTEGER DEFAULT 0,
        novos INTEGER DEFAULT 0,
        duplicados INTEGER DEFAULT 0,
        ignorados INTEGER DEFAULT 0,
        erros INTEGER DEFAULT 0,
        detalhe TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS zammad_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ativo INTEGER DEFAULT 0,
        base_url TEXT,
        token TEXT,
        grupo TEXT,
        customer_email TEXT,
        prioridade TEXT DEFAULT '2 normal',
        prioridade_agent_offline TEXT DEFAULT '3 high',
        criar_chamado_erro INTEGER DEFAULT 1,
        criar_chamado_nao_recebido INTEGER DEFAULT 0,
        criar_chamado_agent_offline INTEGER DEFAULT 1,
        agent_offline_minutos INTEGER DEFAULT 15,
        fechar_chamado_agent_online INTEGER DEFAULT 1
    )
    """)
    add_column_if_missing(cur, "zammad_config", "prioridade_agent_offline", "TEXT DEFAULT '3 high'")
    add_column_if_missing(cur, "zammad_config", "criar_chamado_agent_offline", "INTEGER DEFAULT 1")
    add_column_if_missing(cur, "zammad_config", "agent_offline_minutos", "INTEGER DEFAULT 15")
    add_column_if_missing(cur, "zammad_config", "fechar_chamado_agent_online", "INTEGER DEFAULT 1")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS zammad_alertas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alerta_key TEXT,
        log_email_id INTEGER,
        servidor_log TEXT,
        status_backup TEXT,
        zammad_ticket_id INTEGER,
        zammad_ticket_number TEXT,
        status_envio TEXT NOT NULL,
        erro TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT
    )
    """)
    add_column_if_missing(cur, "zammad_alertas", "alerta_key", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        cliente_id INTEGER,
        servidor_log TEXT,
        ativo INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_used_at TEXT
    )
    """)
    add_column_if_missing(cur, "api_keys", "cliente_id", "INTEGER")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS agent_heartbeats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        servidor_log TEXT NOT NULL UNIQUE,
        api_key_id INTEGER,
        hostname TEXT,
        ip_local TEXT,
        agent_version TEXT,
        status TEXT DEFAULT 'online',
        detalhe TEXT,
        metadata_json TEXT,
        started_at TEXT,
        last_seen TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT
    )
    """)
    add_column_if_missing(cur, "agent_heartbeats", "api_key_id", "INTEGER")
    add_column_if_missing(cur, "agent_heartbeats", "hostname", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "ip_local", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "agent_version", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "status", "TEXT DEFAULT 'online'")
    add_column_if_missing(cur, "agent_heartbeats", "detalhe", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "metadata_json", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "started_at", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "last_seen", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "created_at", "TEXT")
    add_column_if_missing(cur, "agent_heartbeats", "updated_at", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS agent_heartbeat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        servidor_log TEXT NOT NULL,
        api_key_id INTEGER,
        hostname TEXT,
        ip_local TEXT,
        agent_version TEXT,
        status TEXT,
        detalhe TEXT,
        seen_at TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS windows_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_id INTEGER NOT NULL,
        servidor_log TEXT,
        api_key_id INTEGER,
        hostname TEXT NOT NULL,
        channel TEXT NOT NULL DEFAULT 'System',
        record_id TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        provider TEXT,
        level TEXT,
        event_type TEXT,
        occurred_at TEXT NOT NULL,
        received_at TEXT NOT NULL,
        initiated_by TEXT,
        process_name TEXT,
        reason_code TEXT,
        reason TEXT,
        comment TEXT,
        message TEXT,
        raw_json TEXT,
        is_historical INTEGER DEFAULT 0,
        UNIQUE(cliente_id, hostname, channel, record_id)
    )
    """)
    add_column_if_missing(cur, "windows_events", "is_historical", "INTEGER DEFAULT 0")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_firewalls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        address TEXT NOT NULL,
        ssh_port INTEGER DEFAULT 22,
        username_enc TEXT NOT NULL,
        password_enc TEXT,
        private_key_enc TEXT,
        auth_type TEXT DEFAULT 'ssh_key',
        host_key_fingerprint TEXT NOT NULL,
        active INTEGER DEFAULT 1,
        monitor_interval_minutes INTEGER DEFAULT 5,
        backup_interval_hours INTEGER DEFAULT 24,
        backup_retention_days INTEGER DEFAULT 30,
        speedtest_enabled INTEGER DEFAULT 0,
        speedtest_interval_hours INTEGER DEFAULT 6,
        last_check_at TEXT,
        last_status TEXT,
        last_error TEXT,
        last_backup_at TEXT,
        last_config_hash TEXT,
        last_speedtest_at TEXT,
        last_speedtest_status TEXT,
        last_speedtest_error TEXT,
        speedtest_requested_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    add_column_if_missing(cur, "pfsense_firewalls", "speedtest_enabled", "INTEGER DEFAULT 0")
    add_column_if_missing(cur, "pfsense_firewalls", "speedtest_interval_hours", "INTEGER DEFAULT 6")
    add_column_if_missing(cur, "pfsense_firewalls", "last_speedtest_at", "TEXT")
    add_column_if_missing(cur, "pfsense_firewalls", "last_speedtest_status", "TEXT")
    add_column_if_missing(cur, "pfsense_firewalls", "last_speedtest_error", "TEXT")
    add_column_if_missing(cur, "pfsense_firewalls", "speedtest_requested_at", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firewall_id INTEGER NOT NULL,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL,
        latency_ms INTEGER,
        hostname TEXT,
        version TEXT,
        load1 REAL,
        load5 REAL,
        load15 REAL,
        cpu_count INTEGER,
        memory_total BIGINT,
        disk_percent INTEGER,
        interfaces_total INTEGER,
        interfaces_up INTEGER,
        gateway_monitors INTEGER,
        openvpn_processes INTEGER,
        wireguard_interfaces INTEGER,
        metrics_json TEXT,
        error TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firewall_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        config_hash TEXT NOT NULL,
        file_path TEXT NOT NULL,
        size_bytes INTEGER,
        changed INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        error TEXT,
        remote_status TEXT,
        remote_path TEXT,
        remote_uploaded_at TEXT,
        remote_error TEXT
    )
    """)
    add_column_if_missing(cur, "pfsense_backups", "remote_status", "TEXT")
    add_column_if_missing(cur, "pfsense_backups", "remote_path", "TEXT")
    add_column_if_missing(cur, "pfsense_backups", "remote_uploaded_at", "TEXT")
    add_column_if_missing(cur, "pfsense_backups", "remote_error", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_speedtests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firewall_id INTEGER NOT NULL,
        tested_at TEXT NOT NULL,
        status TEXT NOT NULL,
        ping_ms REAL,
        download_mbps REAL,
        upload_mbps REAL,
        server_id TEXT,
        server_name TEXT,
        server_sponsor TEXT,
        error TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firewall_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        provider TEXT NOT NULL,
        link_type TEXT NOT NULL DEFAULT 'broadband',
        interface_key TEXT NOT NULL,
        device_name TEXT NOT NULL,
        gateway_name TEXT,
        contracted_down_mbps REAL,
        contracted_up_mbps REAL,
        minimum_delivery_percent INTEGER DEFAULT 80,
        active INTEGER DEFAULT 1,
        probe_enabled INTEGER DEFAULT 1,
        probe_interval_minutes INTEGER DEFAULT 5,
        speedtest_enabled INTEGER DEFAULT 0,
        speedtest_interval_hours INTEGER DEFAULT 6,
        last_probe_at TEXT,
        last_probe_status TEXT,
        last_probe_error TEXT,
        probe_requested_at TEXT,
        last_speedtest_at TEXT,
        last_speedtest_status TEXT,
        last_speedtest_error TEXT,
        speedtest_requested_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    add_column_if_missing(cur, "pfsense_links", "probe_requested_at", "TEXT")
    add_column_if_missing(cur, "pfsense_links", "speedtest_requested_at", "TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_link_probes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        link_id INTEGER NOT NULL,
        probed_at TEXT NOT NULL,
        status TEXT NOT NULL,
        latency_ms REAL,
        packet_loss_percent REAL,
        target TEXT,
        route_id TEXT,
        error TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_link_speedtests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        link_id INTEGER NOT NULL,
        tested_at TEXT NOT NULL,
        status TEXT NOT NULL,
        ping_ms REAL,
        download_mbps REAL,
        upload_mbps REAL,
        delivered_down_percent REAL,
        delivered_up_percent REAL,
        server_name TEXT,
        server_sponsor TEXT,
        route_id TEXT,
        error TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pfsense_storage (
        id INTEGER PRIMARY KEY,
        protocol TEXT NOT NULL DEFAULT 'ftps',
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 21,
        username_enc TEXT NOT NULL,
        password_enc TEXT NOT NULL,
        remote_dir TEXT NOT NULL DEFAULT '/pfsense-backups',
        passive INTEGER DEFAULT 1,
        verify_tls INTEGER DEFAULT 1,
        active INTEGER DEFAULT 1,
        retention_enabled INTEGER DEFAULT 1,
        retention_days INTEGER DEFAULT 90,
        last_test_at TEXT,
        last_status TEXT,
        last_error TEXT,
        last_cleanup_at TEXT,
        last_cleanup_status TEXT,
        last_cleanup_error TEXT,
        last_cleanup_deleted INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    add_column_if_missing(cur, "pfsense_storage", "retention_enabled", "INTEGER DEFAULT 1")
    add_column_if_missing(cur, "pfsense_storage", "retention_days", "INTEGER DEFAULT 90")
    add_column_if_missing(cur, "pfsense_storage", "last_cleanup_at", "TEXT")
    add_column_if_missing(cur, "pfsense_storage", "last_cleanup_status", "TEXT")
    add_column_if_missing(cur, "pfsense_storage", "last_cleanup_error", "TEXT")
    add_column_if_missing(cur, "pfsense_storage", "last_cleanup_deleted", "INTEGER DEFAULT 0")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS cliente_contatos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cliente_id INTEGER,
        nome TEXT NOT NULL,
        telefone TEXT,
        email TEXT,
        cargo TEXT,
        whatsapp_enabled INTEGER DEFAULT 1,
        ativo INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS helpdesk_tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        numero TEXT UNIQUE,
        cliente_id INTEGER,
        servidor_id INTEGER,
        pfsense_firewall_id INTEGER,
        requester_contact_id INTEGER,
        requester_name TEXT,
        requester_phone TEXT,
        requester_email TEXT,
        assunto TEXT NOT NULL,
        descricao TEXT,
        categoria TEXT NOT NULL DEFAULT 'support',
        prioridade TEXT NOT NULL DEFAULT 'normal',
        status TEXT NOT NULL DEFAULT 'open',
        assignee_user_id INTEGER,
        opened_by_type TEXT NOT NULL DEFAULT 'user',
        opened_by_user_id INTEGER,
        opened_by_external_id TEXT,
        opened_by_name TEXT,
        origem TEXT NOT NULL DEFAULT 'manual',
        source_external_id TEXT,
        source_url TEXT,
        incident_key TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        resolved_at TEXT,
        closed_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS helpdesk_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER,
        author_type TEXT NOT NULL DEFAULT 'user',
        author_name TEXT,
        body TEXT NOT NULL,
        internal INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS helpdesk_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        actor_type TEXT NOT NULL,
        actor_user_id INTEGER,
        actor_name TEXT,
        details_json TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS integration_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        scopes TEXT NOT NULL DEFAULT 'tickets:create',
        ativo INTEGER DEFAULT 1,
        last_used_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        revoked_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS external_ticket_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        company_external_id TEXT NOT NULL DEFAULT '',
        ticket_external_id TEXT NOT NULL,
        conversation_uuid TEXT,
        helpdesk_ticket_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ticketz_config (
        id INTEGER PRIMARY KEY CHECK (id=1),
        ativo INTEGER DEFAULT 0,
        endpoint TEXT NOT NULL DEFAULT 'https://chat.fpinformatica.com.br:443/backend/api/messages/send',
        token_enc TEXT,
        save_on_ticket INTEGER DEFAULT 1,
        link_preview INTEGER DEFAULT 1,
        notify_ticket_opened INTEGER DEFAULT 0,
        notify_ticket_updated INTEGER DEFAULT 0,
        notify_ticket_resolved INTEGER DEFAULT 0,
        updated_at TEXT
    )
    """)
    cur.execute("""
        INSERT OR IGNORE INTO ticketz_config (id, ativo, updated_at)
        VALUES (1, 0, CURRENT_TIMESTAMP)
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS notification_outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel TEXT NOT NULL DEFAULT 'ticketz_whatsapp',
        ticket_id INTEGER,
        contact_id INTEGER,
        staff_recipient_id INTEGER,
        recipient TEXT NOT NULL,
        event_type TEXT NOT NULL,
        body TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER DEFAULT 0,
        available_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_attempt_at TEXT,
        sent_at TEXT,
        response_code INTEGER,
        error TEXT,
        idempotency_key TEXT NOT NULL UNIQUE,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)
    add_column_if_missing(cur, "notification_outbox", "staff_recipient_id", "INTEGER")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS helpdesk_reminder_config (
        id INTEGER PRIMARY KEY CHECK (id=1),
        ativo INTEGER DEFAULT 0,
        unassigned_initial_minutes INTEGER DEFAULT 30,
        reminder_interval_minutes INTEGER DEFAULT 180,
        daily_limit INTEGER DEFAULT 3,
        business_start_hour INTEGER DEFAULT 8,
        business_end_hour INTEGER DEFAULT 18,
        weekdays_only INTEGER DEFAULT 1,
        base_url TEXT DEFAULT 'https://bkp.fpinformatica.com.br',
        updated_at TEXT
    )
    """)
    cur.execute("""
        INSERT OR IGNORE INTO helpdesk_reminder_config (id, ativo, updated_at)
        VALUES (1, 0, CURRENT_TIMESTAMP)
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS helpdesk_staff_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        telefone TEXT NOT NULL,
        notify_unassigned INTEGER DEFAULT 1,
        notify_own INTEGER DEFAULT 1,
        notify_all_overdue INTEGER DEFAULT 0,
        ativo INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS notification_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        outbox_id INTEGER NOT NULL,
        attempted_at TEXT DEFAULT CURRENT_TIMESTAMP,
        status TEXT NOT NULL,
        response_code INTEGER,
        error TEXT
    )
    """)

    if USING_POSTGRES:
        cur.execute("""
            ALTER TABLE pfsense_checks
            ALTER COLUMN memory_total TYPE BIGINT
        """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_email_message_id
        ON logs_email(message_id)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_email_servidor_data
        ON logs_email(servidor_log, data_email)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_email_data
        ON logs_email(data_email)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_email_servidor_hash
        ON logs_email(servidor_log, conteudo_hash)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_nao_cadastrados_servidor
        ON logs_nao_cadastrados(servidor_log)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_worker_runs_started_at
        ON worker_runs(started_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_zammad_alertas_log_email_id
        ON zammad_alertas(log_email_id)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_zammad_alertas_key
        ON zammad_alertas(alerta_key)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_zammad_alertas_servidor_status
        ON zammad_alertas(servidor_log, status_backup)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_api_keys_token_hash
        ON api_keys(token_hash)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_api_keys_cliente
        ON api_keys(cliente_id)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_last_seen
        ON agent_heartbeats(last_seen)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_agent_heartbeat_history_servidor_seen
        ON agent_heartbeat_history(servidor_log, seen_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_windows_events_occurred
        ON windows_events(occurred_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_windows_events_cliente_host
        ON windows_events(cliente_id, hostname, occurred_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_user_sessions_user_active
        ON user_sessions(user_id, ativo, last_seen)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_maintenance_runs_action_started
        ON maintenance_runs(action, started_at)
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_pfsense_firewalls_address_port
        ON pfsense_firewalls(address, ssh_port)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_pfsense_checks_firewall_checked
        ON pfsense_checks(firewall_id, checked_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_pfsense_backups_firewall_created
        ON pfsense_backups(firewall_id, created_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_pfsense_speedtests_firewall_tested
        ON pfsense_speedtests(firewall_id, tested_at)
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_pfsense_links_firewall_interface
        ON pfsense_links(firewall_id, interface_key)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_pfsense_link_probes_link_probed
        ON pfsense_link_probes(link_id, probed_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_pfsense_link_speedtests_link_tested
        ON pfsense_link_speedtests(link_id, tested_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_cliente_contatos_cliente
        ON cliente_contatos(cliente_id, ativo)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_helpdesk_tickets_status_updated
        ON helpdesk_tickets(status, updated_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_helpdesk_tickets_cliente
        ON helpdesk_tickets(cliente_id, created_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_helpdesk_comments_ticket
        ON helpdesk_comments(ticket_id, created_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_helpdesk_audit_ticket
        ON helpdesk_audit_log(ticket_id, created_at)
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_external_ticket_source
        ON external_ticket_links(source, company_external_id, ticket_external_id)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_notification_outbox_due
        ON notification_outbox(status, available_at)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_helpdesk_staff_notifications_active
        ON helpdesk_staff_notifications(ativo, user_id)
    """)
    if USING_POSTGRES:
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_email_upper_servidor_dt_id
            ON logs_email (UPPER(servidor_log), datetime(data_email) DESC, id DESC)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_email_dt_id
            ON logs_email (datetime(data_email) DESC, id DESC)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_upper_servidor
            ON agent_heartbeats (UPPER(servidor_log))
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_history_seen_upper_servidor
            ON agent_heartbeat_history (datetime(seen_at), UPPER(servidor_log))
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_servidores_cliente_ativo
            ON servidores (cliente_id, ativo, nome_log)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_agendamentos_servidor_ativo
            ON agendamentos_backup (servidor_id, ativo)
        """)

    conn.commit()
    conn.close()
