from flask import Flask, render_template, request, redirect, session, jsonify, Response, send_file
from db import DB_PATH, USING_POSTGRES, get_db, init_db
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import secrets
import os
import re
import shutil
import zipfile
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo
from werkzeug.security import check_password_hash, generate_password_hash
from pfsense_storage import (
    cleanup_storage, normalize_remote_dir, test_storage_connection, upload_backup_from_db,
)
from secret_store import decrypt_backup, encrypt_secret

app = Flask(__name__)
secret_key = os.getenv("SECRET_KEY", "").strip()
if not secret_key:
    raise RuntimeError("SECRET_KEY must be configured")
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
LATEST_AGENT_VERSION = "1.3.1"
BRASILIA_TZ = ZoneInfo("America/Sao_Paulo")
AGENT_UPDATE_URL = "https://bkp.fpinformatica.com.br/static/backup-monitor-agent.zip"
AGENT_UPDATE_URL_WS2012 = "https://bkp.fpinformatica.com.br/static/backup-monitor-agent-legacy-ws2012.zip"
AGENT_SETUP_URL = "https://bkp.fpinformatica.com.br/static/BackupMonitorAgentSetup.exe"
AGENT_SETUP_URL_WS2012 = "https://bkp.fpinformatica.com.br/static/BackupMonitorAgentSetupLegacy2012.exe"
AUTO_RECOVER_AGENTS = int(os.getenv("AUTO_RECOVER_AGENTS", "0"))
_AGENT_PACKAGE_HASH_CACHE = {}


@app.template_filter("br_datetime")
def br_datetime(value, fmt="%d/%m/%Y %H:%M"):
    if not value:
        return "-"
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(BRASILIA_TZ).strftime(fmt)
    except (TypeError, ValueError):
        return str(value)


def agent_package_sha256(filename):
    path = Path(__file__).resolve().parent / "static" / filename
    stat = path.stat()
    cached = _AGENT_PACKAGE_HASH_CACHE.get(filename)
    if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _AGENT_PACKAGE_HASH_CACHE[filename] = (stat.st_mtime_ns, stat.st_size, digest)
    return digest


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip()
    if request.is_secure or forwarded_proto == "https":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    return response


def hash_password(password):
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash, password):
    stored_hash = stored_hash or ""
    if re.fullmatch(r"[0-9a-fA-F]{64}", stored_hash):
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        valid = secrets.compare_digest(stored_hash.lower(), legacy_hash)
        return valid, valid
    try:
        return check_password_hash(stored_hash, password), False
    except (TypeError, ValueError):
        return False, False

init_db()
from helpdesk import bp as helpdesk_blueprint
app.register_blueprint(helpdesk_blueprint)
SESSION_IDLE_HOURS = int(os.getenv("SESSION_IDLE_HOURS", "8"))

# =========================
# DECORATORS
# =========================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("tipo") != "admin":
            return "Acesso negado", 403
        return f(*args, **kwargs)
    return decorated_function


def support_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("tipo") not in ("admin", "operador"):
            return "Acesso negado", 403
        return f(*args, **kwargs)
    return decorated_function


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_conteudo(texto):
    return hashlib.sha256((texto or "").encode()).hexdigest()


def normalizar_servidor(nome):
    return re.sub(r"\s+", "_", (nome or "").strip().upper())


def detectar_status_log(texto):
    texto = (texto or "").lower()
    texto_sem_zero_erros = re.sub(r"\b0\s+erros?\b", " ", texto)

    if re.search(r"\b[1-9][0-9]*\s+erros?\b", texto_sem_zero_erros):
        return "error"

    if any(p in texto_sem_zero_erros for p in (
        "backup finalizado com erros",
        "backup finalizado com erro",
        "backup concluido com erros",
        "backup concluído com erros",
        "falha",
        "failed",
        "failure",
    )):
        return "error"

    if any(p in texto for p in (
        "backup concluido com sucesso",
        "backup concluído com sucesso",
        "success",
        "successful",
        "sucesso na transferencia",
        "sucesso na transferência",
        "sucesso no envio",
    )):
        return "success"

    return "warning"


def parse_data(valor):
    if not valor:
        return None

    for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(valor)[:19], formato)
        except ValueError:
            pass

    return None


def agora_sql():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def limpar_sessoes_expiradas(db):
    limite = (datetime.now() - timedelta(hours=SESSION_IDLE_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute("""
        UPDATE user_sessions
        SET ativo=0,
            logged_out_at=COALESCE(logged_out_at, ?)
        WHERE ativo=1
          AND (last_seen IS NULL OR datetime(last_seen) < datetime(?))
    """, (agora_sql(), limite))


def sessao_atual_valida(db):
    user_id = session.get("user_id")
    session_id = session.get("session_id")
    if not user_id or not session_id:
        return False

    limpar_sessoes_expiradas(db)
    row = db.execute("""
        SELECT us.id
        FROM user_sessions us
        JOIN usuarios u ON u.id = us.user_id
        WHERE us.session_id=?
          AND us.user_id=?
          AND us.ativo=1
          AND u.ativo=1
        LIMIT 1
    """, (session_id, user_id)).fetchone()
    if not row:
        db.commit()
        return False

    db.execute("""
        UPDATE user_sessions
        SET last_seen=?
        WHERE session_id=?
    """, (agora_sql(), session_id))
    db.commit()
    return True


def criar_sessao_usuario(db, user):
    session_id = secrets.token_urlsafe(32)
    session.clear()
    session["session_id"] = session_id
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["tipo"] = user["tipo"]
    db.execute("""
        INSERT INTO user_sessions (
            session_id, user_id, username, ip, user_agent, created_at, last_seen, ativo
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    """, (
        session_id,
        user["id"],
        user["username"],
        request.headers.get("X-Forwarded-For", request.remote_addr or "")[:120],
        (request.headers.get("User-Agent") or "")[:300],
        agora_sql(),
        agora_sql(),
    ))
    db.commit()


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


@app.before_request
def preparar_requisicao():
    endpoint = request.endpoint or ""
    if endpoint.startswith("static") or endpoint in ("login", "favicon"):
        return None

    if "user_id" in session:
        db = get_db()
        try:
            if not sessao_atual_valida(db):
                session.clear()
                return redirect("/login")
        finally:
            db.close()

    return None


def extrair_api_token():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.headers.get("X-API-Key", "").strip()


def ler_json_tolerante():
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        return payload

    raw = request.get_data(cache=True, as_text=True) or ""
    if not raw:
        return {}

    try:
        payload = json.loads(raw, strict=False)
    except (TypeError, ValueError):
        return {}

    return payload if isinstance(payload, dict) else {}


def autenticar_api_key(db, token):
    if not token:
        return None

    token_hash = hash_token(token)
    key = db.execute("""
        SELECT *
        FROM api_keys
        WHERE token_hash=? AND ativo=1
        LIMIT 1
    """, (token_hash,)).fetchone()

    if key:
        db.execute("""
            UPDATE api_keys
            SET last_used_at=?
            WHERE id=?
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), key["id"]))
        db.commit()

    return key


def recuperar_agent_api_key(db, token, servidor):
    if not AUTO_RECOVER_AGENTS or not token or not servidor:
        return None

    servidor = normalizar_servidor(servidor)
    token_hash = hash_token(token)
    key = db.execute("""
        SELECT *
        FROM api_keys
        WHERE token_hash=? AND ativo=1
        LIMIT 1
    """, (token_hash,)).fetchone()
    if key:
        return key

    cliente = db.execute("""
        SELECT id
        FROM clientes
        WHERE nome_exibicao='RECUPERADO AGENTS'
        LIMIT 1
    """).fetchone()
    if cliente:
        cliente_id = cliente["id"]
    else:
        cur = db.execute("""
            INSERT INTO clientes (nome_exibicao, ativo)
            VALUES ('RECUPERADO AGENTS', 1)
        """)
        cliente_id = cur.lastrowid

    existe_servidor = db.execute("""
        SELECT id
        FROM servidores
        WHERE UPPER(nome_log)=?
        LIMIT 1
    """, (servidor,)).fetchone()
    if not existe_servidor:
        db.execute("""
            INSERT INTO servidores (cliente_id, nome_log, backups_semana, ativo)
            VALUES (?, ?, 7, 1)
        """, (cliente_id, servidor))

    cur = db.execute("""
        INSERT INTO api_keys (nome, token_hash, cliente_id, servidor_log, ativo, last_used_at)
        VALUES (?, ?, ?, ?, 1, ?)
    """, (
        f"Auto recuperada {servidor}",
        token_hash,
        cliente_id,
        None,
        agora_sql(),
    ))
    db.commit()

    return db.execute("""
        SELECT *
        FROM api_keys
        WHERE id=?
        LIMIT 1
    """, (cur.lastrowid,)).fetchone()


def garantir_servidor_recuperado(db, key, servidor):
    if not AUTO_RECOVER_AGENTS or not key or not servidor:
        return key

    cliente_id = key["cliente_id"]
    if not cliente_id:
        cliente = db.execute("""
            SELECT id
            FROM clientes
            WHERE nome_exibicao='RECUPERADO AGENTS'
            LIMIT 1
        """).fetchone()
        if cliente:
            cliente_id = cliente["id"]
        else:
            cur = db.execute("""
                INSERT INTO clientes (nome_exibicao, ativo)
                VALUES ('RECUPERADO AGENTS', 1)
            """)
            cliente_id = cur.lastrowid

    if key["servidor_log"]:
        db.execute("""
            UPDATE api_keys
            SET servidor_log=NULL,
                cliente_id=?
            WHERE id=?
        """, (cliente_id, key["id"]))

    existe_servidor = db.execute("""
        SELECT id
        FROM servidores
        WHERE UPPER(nome_log)=?
        LIMIT 1
    """, (servidor,)).fetchone()
    if not existe_servidor:
        db.execute("""
            INSERT INTO servidores (cliente_id, nome_log, backups_semana, ativo)
            VALUES (?, ?, 7, 1)
        """, (cliente_id, servidor))

    db.commit()
    return db.execute("""
        SELECT *
        FROM api_keys
        WHERE id=?
        LIMIT 1
    """, (key["id"],)).fetchone()


def api_key_autorizada_para_servidor(key, servidor, db=None):
    if key["servidor_log"]:
        if servidor != normalizar_servidor(key["servidor_log"]):
            return False
        db = db or get_db()
        autorizado = db.execute("""
            SELECT 1
            FROM servidores s
            JOIN clientes c ON c.id = s.cliente_id
            WHERE UPPER(s.nome_log)=?
              AND s.ativo=1
              AND c.ativo=1
            LIMIT 1
        """, (servidor,)).fetchone()
        return autorizado is not None

    if key["cliente_id"]:
        db = db or get_db()
        autorizado = db.execute("""
            SELECT 1
            FROM servidores s
            JOIN clientes c ON c.id = s.cliente_id
            WHERE s.cliente_id=?
              AND UPPER(s.nome_log)=?
              AND s.ativo=1
              AND c.ativo=1
            LIMIT 1
        """, (key["cliente_id"], servidor)).fetchone()
        return autorizado is not None

    return True


def ultimo_horario_previsto(agendamento, agora):
    hora_txt = (agendamento["hora_execucao"] or "").strip()
    try:
        hora = datetime.strptime(hora_txt, "%H:%M").time()
    except ValueError:
        return None

    dias = [d.strip() for d in (agendamento["dias_execucao"] or "").split(",") if d.strip()]
    if not dias:
        return None

    for offset in range(0, 15):
        dia = agora.date() - timedelta(days=offset)
        if str(dia.weekday()) in dias:
            previsto = datetime.combine(dia, hora)
            if previsto <= agora:
                return previsto

    return None


def montar_linha_backup_servidor(servidor, agora, ultimo_log=None, heartbeat=None, agendamentos=None):
    agendamentos = agendamentos or []
    agente = formatar_status_agente(heartbeat, agora)

    ultimo_dt = parse_data(ultimo_log["data_email"]) if ultimo_log else None
    idade_min = None
    if ultimo_dt:
        idade_min = max(0, int((agora - ultimo_dt).total_seconds() // 60))

    status = "sem_agenda"
    detalhe = "Sem agendamento ativo"
    previsto = None
    prazo = None

    if agendamentos:
        candidatos = []
        for agendamento in agendamentos:
            previsto_ag = ultimo_horario_previsto(agendamento, agora)
            if previsto_ag:
                tolerancia = int(agendamento["tolerancia_min"] or 120)
                candidatos.append((previsto_ag, tolerancia))

        if candidatos:
            previsto, tolerancia = max(candidatos, key=lambda item: item[0])
            prazo = previsto + timedelta(minutes=tolerancia)

            if ultimo_dt and ultimo_dt >= previsto:
                if ultimo_log["status"] == "error":
                    status = "erro"
                    detalhe = "Ultimo backup previsto chegou com erro"
                elif ultimo_log["status"] == "warning":
                    status = "alerta"
                    detalhe = "Ultimo backup previsto chegou como alerta"
                else:
                    status = "ok"
                    detalhe = "Ultimo backup previsto recebido"
            elif agora <= prazo:
                status = "aguardando"
                detalhe = "Dentro da tolerancia do horario previsto"
            else:
                status = "atrasado"
                detalhe = "Backup previsto ainda nao chegou"
        else:
            status = "sem_agenda"
            detalhe = "Agendamento sem horario valido"

    if not agendamentos:
        if not ultimo_dt:
            status = "sem_log"
            detalhe = "Nenhum log recebido"
        elif ultimo_log["status"] == "error":
            status = "erro"
            detalhe = "Ultimo log recebido com erro"
        elif idade_min > 48 * 60:
            status = "atrasado"
            detalhe = "Ultimo log recebido ha mais de 48 horas"
        else:
            status = "ok"
            detalhe = "Ultimo log recente"

    return {
        "cliente": servidor["nome_exibicao"],
        "nome_log": servidor["nome_log"],
        "status": status,
        "detalhe": detalhe,
        "ultimo_log": ultimo_log["data_email"] if ultimo_log else None,
        "ultimo_status": ultimo_log["status"] if ultimo_log else None,
        "origem": ultimo_log["origem"] if ultimo_log else None,
        "idade_min": idade_min,
        "previsto": previsto.strftime("%Y-%m-%d %H:%M:%S") if previsto else None,
        "prazo": prazo.strftime("%Y-%m-%d %H:%M:%S") if prazo else None,
        "agente": agente,
    }


def calcular_disponibilidade_servidor(db, servidor, agora):
    ultimo_log = db.execute("""
        SELECT data_email, status, origem
        FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        ORDER BY datetime(data_email) DESC, id DESC
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()

    heartbeat = db.execute("""
        SELECT hostname, ip_local, agent_version, last_seen, status, detalhe
        FROM agent_heartbeats
        WHERE UPPER(servidor_log)=UPPER(?)
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()

    agendamentos = db.execute("""
        SELECT dias_execucao, hora_execucao, tolerancia_min
        FROM agendamentos_backup
        WHERE servidor_id=? AND ativo=1
    """, (servidor["id"],)).fetchall()

    return montar_linha_backup_servidor(servidor, agora, ultimo_log, heartbeat, agendamentos)


def formatar_idade(minutos):
    if minutos is None:
        return "-"
    if minutos < 60:
        return f"{minutos} min"

    horas = minutos // 60
    mins = minutos % 60
    if horas < 48:
        return f"{horas}h {mins}min"

    dias = horas // 24
    horas_restantes = horas % 24
    return f"{dias}d {horas_restantes}h"


def enriquecer_uptime_pfsense(metrics, checked_at=None):
    result = dict(metrics or {})
    try:
        uptime_seconds = max(0, int(result.get("UPTIME_SECONDS")))
    except (TypeError, ValueError):
        result["UPTIME_LABEL"] = "-"
        result["BOOT_AT"] = None
        result["RECENT_REBOOT"] = False
        return result
    if uptime_seconds > 10 * 365 * 24 * 60 * 60:
        result["UPTIME_LABEL"] = "-"
        result["BOOT_AT"] = None
        result["RECENT_REBOOT"] = False
        return result

    result["UPTIME_LABEL"] = (
        "< 1 min" if uptime_seconds < 60 else formatar_idade(uptime_seconds // 60)
    )
    collected_at = parse_data(checked_at)
    if collected_at:
        boot_utc = collected_at.replace(tzinfo=timezone.utc) - timedelta(seconds=uptime_seconds)
        result["BOOT_AT"] = boot_utc.astimezone(
            ZoneInfo("America/Sao_Paulo")
        ).strftime("%d/%m/%Y %H:%M")
    else:
        result["BOOT_AT"] = None
    result["RECENT_REBOOT"] = uptime_seconds < 24 * 60 * 60
    return result


def formatar_status_agente(heartbeat, agora, limite_online_min=10):
    if not heartbeat:
        return {
            "status": "sem_agente",
            "label": "Sem agente",
            "idade_min": None,
            "last_seen": None,
            "hostname": None,
            "ip_local": None,
            "version": None,
            "detalhe": None,
        }

    last_seen_dt = parse_data(heartbeat["last_seen"])
    idade_min = None
    online = False
    if last_seen_dt:
        idade_min = max(0, int((agora - last_seen_dt).total_seconds() // 60))
        online = idade_min <= limite_online_min

    heartbeat_status = heartbeat["status"] or ""
    if online and heartbeat_status == "online_no_evidence":
        status = "online_no_evidence"
        label = "Online sem log local"
    else:
        status = "online" if online else "offline"
        label = "Online" if online else "Offline"

    version = heartbeat["agent_version"]
    return {
        "status": status,
        "label": label,
        "idade_min": idade_min,
        "last_seen": heartbeat["last_seen"],
        "hostname": heartbeat["hostname"],
        "ip_local": heartbeat["ip_local"],
        "version": version,
        "detalhe": heartbeat["detalhe"],
        "latest_version": LATEST_AGENT_VERSION,
        "update_available": comparar_versao_agent(version, LATEST_AGENT_VERSION) < 0,
    }


def status_agent_disponivel(status):
    return status in ("online", "online_no_evidence")


def calcular_uptime_por_eventos(eventos, inicio, fim, tolerancia_min=10):
    if not eventos:
        return {
            "observado_min": 0,
            "online_min": 0,
            "offline_min": 0,
            "percentual": None,
        }

    pontos = []
    for evento in eventos:
        visto = parse_data(evento["seen_at"])
        if visto:
            pontos.append((visto, evento["status"] or "online"))

    if not pontos:
        return {
            "observado_min": 0,
            "online_min": 0,
            "offline_min": 0,
            "percentual": None,
        }

    pontos.sort(key=lambda item: item[0])
    inicio_observado = min(max(pontos[0][0], inicio), fim)
    online_seg = 0
    tolerancia_seg = tolerancia_min * 60

    for idx, (quando, status) in enumerate(pontos):
        if quando < inicio:
            quando = inicio
        if quando > fim:
            continue

        proximo = pontos[idx + 1][0] if idx + 1 < len(pontos) else fim
        proximo = min(proximo, fim)
        if proximo <= quando:
            continue

        duracao = (proximo - quando).total_seconds()
        if status_agent_disponivel(status):
            online_seg += min(duracao, tolerancia_seg)

    observado_seg = max(0, (fim - inicio_observado).total_seconds())
    online_min = int(online_seg // 60)
    observado_min = int(observado_seg // 60)
    offline_min = max(0, observado_min - online_min)
    percentual = round((online_min / observado_min) * 100, 2) if observado_min else None

    return {
        "observado_min": observado_min,
        "online_min": online_min,
        "offline_min": offline_min,
        "percentual": percentual,
    }


def calcular_streak_agent(eventos, agora, tolerancia_min=10):
    pontos = []
    for evento in eventos:
        visto = parse_data(evento["seen_at"])
        if visto:
            pontos.append((visto, evento["status"] or "online"))

    if not pontos:
        return {"estado": "sem_dados", "desde_min": None}

    pontos.sort(key=lambda item: item[0])
    ultimo_quando, ultimo_status = pontos[-1]
    idade_min = max(0, int((agora - ultimo_quando).total_seconds() // 60))
    if idade_min > tolerancia_min or not status_agent_disponivel(ultimo_status):
        return {"estado": "offline", "desde_min": idade_min}

    inicio = ultimo_quando
    anterior = ultimo_quando
    for quando, status in reversed(pontos[:-1]):
        gap_min = (anterior - quando).total_seconds() / 60
        if gap_min > tolerancia_min or not status_agent_disponivel(status):
            break
        inicio = quando
        anterior = quando

    return {
        "estado": "online",
        "desde_min": max(0, int((agora - inicio).total_seconds() // 60)),
    }


def comparar_versao_agent(atual, latest):
    def parts(value):
        if not value:
            return []
        nums = []
        for item in str(value).split("."):
            try:
                nums.append(int(re.sub(r"\D.*$", "", item) or "0"))
            except ValueError:
                nums.append(0)
        return nums

    atual_parts = parts(atual)
    latest_parts = parts(latest)
    tamanho = max(len(atual_parts), len(latest_parts))
    atual_parts += [0] * (tamanho - len(atual_parts))
    latest_parts += [0] * (tamanho - len(latest_parts))
    if atual_parts < latest_parts:
        return -1
    if atual_parts > latest_parts:
        return 1
    return 0


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form["username"].strip()
        senha = request.form["senha"]
        db = get_db()
        limpar_sessoes_expiradas(db)
        user = db.execute("""
            SELECT * FROM usuarios
            WHERE username=? AND ativo=1
        """, (username,)).fetchone()

        password_valid = False
        upgrade_hash = False
        if user:
            password_valid, upgrade_hash = verify_password(user["senha_hash"], senha)
            if password_valid and upgrade_hash:
                db.execute(
                    "UPDATE usuarios SET senha_hash=? WHERE id=?",
                    (hash_password(senha), user["id"]),
                )
                db.commit()

        if user and password_valid:
            max_sessoes = max(1, int(user["max_sessoes"] or 1))
            sessoes_ativas = db.execute("""
                SELECT COUNT(*) AS total
                FROM user_sessions
                WHERE user_id=? AND ativo=1
            """, (user["id"],)).fetchone()["total"]
            if sessoes_ativas >= max_sessoes:
                db.commit()
                db.close()
                return render_template(
                    "login.html",
                    erro=f"Limite de {max_sessoes} login(s) simultaneo(s) atingido para este usuario.",
                )

            criar_sessao_usuario(db, user)
            db.close()
            return redirect("/dashboard")

        db.close()
        return render_template("login.html", erro="Usuario ou senha invalidos")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session_id = session.get("session_id")
    if session_id:
        db = get_db()
        db.execute("""
            UPDATE user_sessions
            SET ativo=0, logged_out_at=?
            WHERE session_id=?
        """, (agora_sql(), session_id))
        db.commit()
        db.close()
    session.clear()
    return redirect("/login")


@app.route("/favicon.ico")
def favicon():
    return redirect("/static/favicon.svg")


# =========================
# CLIENTES
# =========================

@app.route("/")
@login_required
def clientes():
    db = get_db()
    clientes = db.execute("""
        WITH server_counts AS (
            SELECT cliente_id, COUNT(*) AS total FROM servidores WHERE ativo=1 GROUP BY cliente_id
        ), agent_counts AS (
            SELECT s.cliente_id, COUNT(*) AS total
            FROM servidores s JOIN agent_heartbeats h ON UPPER(h.servidor_log)=UPPER(s.nome_log)
            WHERE s.ativo=1 AND datetime(h.last_seen)>=datetime('now','-10 minutes')
            GROUP BY s.cliente_id
        ), ticket_counts AS (
            SELECT cliente_id, COUNT(*) AS total FROM helpdesk_tickets
            WHERE status NOT IN ('resolved','closed') GROUP BY cliente_id
        ), event_counts AS (
            SELECT cliente_id, COUNT(*) AS total FROM windows_events
            WHERE datetime(occurred_at)>=datetime('now','-30 days') GROUP BY cliente_id
        )
        SELECT c.*, COALESCE(sc.total,0) AS server_count, COALESCE(ac.total,0) AS agent_online,
               COALESCE(tc.total,0) AS ticket_count, COALESCE(ec.total,0) AS event_count
        FROM clientes c
        LEFT JOIN server_counts sc ON sc.cliente_id=c.id
        LEFT JOIN agent_counts ac ON ac.cliente_id=c.id
        LEFT JOIN ticket_counts tc ON tc.cliente_id=c.id
        LEFT JOIN event_counts ec ON ec.cliente_id=c.id
        ORDER BY c.ativo DESC, c.nome_exibicao
    """).fetchall()
    summary = {
        "active": sum(1 for row in clientes if row["ativo"]),
        "servers": sum(int(row["server_count"] or 0) for row in clientes if row["ativo"]),
        "online": sum(int(row["agent_online"] or 0) for row in clientes if row["ativo"]),
        "tickets": sum(int(row["ticket_count"] or 0) for row in clientes if row["ativo"]),
    }
    db.close()
    return render_template("clientes.html", clientes=clientes, summary=summary, title="Clientes")


@app.route("/search")
@login_required
def global_search():
    query = (request.args.get("q") or "").strip()[:80]
    results = {"clientes": [], "servidores": [], "firewalls": [], "chamados": []}
    if query:
        term = f"%{query}%"
        db = get_db()
        try:
            results["clientes"] = db.execute("""
                SELECT id, nome_exibicao, ativo FROM clientes
                WHERE UPPER(nome_exibicao) LIKE UPPER(?)
                ORDER BY ativo DESC, nome_exibicao LIMIT 10
            """, (term,)).fetchall()
            results["servidores"] = db.execute("""
                SELECT s.id, s.nome_log, s.ativo, c.nome_exibicao AS cliente_nome
                FROM servidores s JOIN clientes c ON c.id=s.cliente_id
                WHERE UPPER(s.nome_log) LIKE UPPER(?) OR UPPER(c.nome_exibicao) LIKE UPPER(?)
                ORDER BY s.ativo DESC, c.nome_exibicao, s.nome_log LIMIT 10
            """, (term, term)).fetchall()
            results["firewalls"] = db.execute("""
                SELECT id, name, address, last_status FROM pfsense_firewalls
                WHERE UPPER(name) LIKE UPPER(?) OR UPPER(address) LIKE UPPER(?)
                ORDER BY active DESC, name LIMIT 10
            """, (term, term)).fetchall()
            results["chamados"] = db.execute("""
                SELECT t.id, t.numero, t.assunto, t.status, c.nome_exibicao AS cliente_nome
                FROM helpdesk_tickets t LEFT JOIN clientes c ON c.id=t.cliente_id
                WHERE UPPER(t.numero) LIKE UPPER(?) OR UPPER(t.assunto) LIKE UPPER(?)
                   OR UPPER(COALESCE(c.nome_exibicao,'')) LIKE UPPER(?)
                ORDER BY datetime(t.updated_at) DESC LIMIT 10
            """, (term, term, term)).fetchall()
        finally:
            db.close()
    total = sum(len(items) for items in results.values())
    return render_template("search.html", query=query, results=results, total=total, title="Busca global")


@app.route("/clientes/add", methods=["POST"])
@login_required
@admin_required
def add_cliente():
    nome = request.form["nome_exibicao"].strip()
    responsavel_nome = request.form.get("responsavel_nome", "").strip()
    responsavel_email = request.form.get("responsavel_email", "").strip().lower()
    alertar = 1 if request.form.get("alertar_eventos_windows") == "1" else 0
    db = get_db()
    db.execute("""
        INSERT INTO clientes (
            nome_exibicao, responsavel_nome, responsavel_email,
            alertar_eventos_windows
        ) VALUES (?, ?, ?, ?)
    """, (nome, responsavel_nome or None, responsavel_email or None, alertar))
    db.commit()
    return redirect("/")


@app.route("/clientes/<int:cliente_id>/windows-alerts", methods=["POST"])
@login_required
@admin_required
def save_cliente_windows_alerts(cliente_id):
    responsavel_nome = request.form.get("responsavel_nome", "").strip()
    responsavel_email = request.form.get("responsavel_email", "").strip().lower()
    alertar = 1 if request.form.get("alertar_eventos_windows") == "1" else 0
    if alertar and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", responsavel_email):
        return "Informe um e-mail valido para ativar os alertas Windows.", 400

    db = get_db()
    db.execute("""
        UPDATE clientes
        SET responsavel_nome=?, responsavel_email=?, alertar_eventos_windows=?
        WHERE id=?
    """, (responsavel_nome or None, responsavel_email or None, alertar, cliente_id))
    db.commit()
    return redirect("/")


@app.route("/clientes/delete/<int:id>")
@login_required
@admin_required
def delete_cliente(id):
    db = get_db()
    db.execute("DELETE FROM servidores WHERE cliente_id=?", (id,))
    db.execute("DELETE FROM clientes WHERE id=?", (id,))
    db.commit()
    return redirect("/")


@app.route("/clientes/toggle/<int:id>")
@login_required
@admin_required
def toggle_cliente(id):
    db = get_db()
    cliente = db.execute("SELECT ativo FROM clientes WHERE id=?", (id,)).fetchone()
    if cliente:
        novo_status = 0 if int(cliente["ativo"] or 0) == 1 else 1
        db.execute("UPDATE clientes SET ativo=? WHERE id=?", (novo_status, id))
        db.commit()
    return redirect("/")


# =========================
# SERVIDORES
# =========================

@app.route("/servidores/<int:cliente_id>")
@login_required
def servidores(cliente_id):

    db = get_db()
    cliente = db.execute("SELECT * FROM clientes WHERE id=?", (cliente_id,)).fetchone()

    servidores = db.execute("""
        SELECT * FROM servidores
        WHERE cliente_id=?
        ORDER BY nome_log
    """, (cliente_id,)).fetchall()

    return render_template("servidores.html", cliente=cliente, servidores=servidores)


@app.route("/servidores/add/<int:cliente_id>", methods=["POST"])
@login_required
@admin_required
def add_servidor(cliente_id):

    nome_log = request.form["nome_log"].strip().upper()
    backups_semana = request.form.get("backups_semana", 7)

    db = get_db()

    db.execute("""
        INSERT INTO servidores (cliente_id, nome_log, backups_semana)
        VALUES (?,?,?)
    """, (cliente_id, nome_log, backups_semana))

    db.commit()

    return redirect(f"/servidores/{cliente_id}")


@app.route("/servidores/delete/<int:id>/<int:cliente_id>")
@login_required
@admin_required
def delete_servidor(id, cliente_id):

    db = get_db()
    db.execute("DELETE FROM servidores WHERE id=?", (id,))
    db.commit()

    return redirect(f"/servidores/{cliente_id}")


@app.route("/servidores/toggle/<int:id>/<int:cliente_id>")
@login_required
@admin_required
def toggle_servidor(id, cliente_id):
    db = get_db()
    servidor = db.execute("SELECT ativo FROM servidores WHERE id=?", (id,)).fetchone()
    if servidor:
        novo_status = 0 if int(servidor["ativo"] or 0) == 1 else 1
        db.execute("UPDATE servidores SET ativo=? WHERE id=?", (novo_status, id))
        db.commit()
    return redirect(f"/servidores/{cliente_id}")


@app.route("/servidores/editar/<int:id>")
@login_required
@admin_required
def editar_servidor(id):

    db = get_db()

    servidor = db.execute(
        "SELECT * FROM servidores WHERE id=?",
        (id,)
    ).fetchone()

    agendamentos = db.execute("""
        SELECT * FROM agendamentos_backup
        WHERE servidor_id=? AND ativo=1
        ORDER BY hora_execucao
    """, (id,)).fetchall()

    return render_template(
        "editar_servidor.html",
        servidor=servidor,
        agendamentos=agendamentos
    )
@app.route("/servidores/update/<int:id>", methods=["POST"])
@login_required
@admin_required
def update_servidor(id):

    nome_log = request.form["nome_log"].strip().upper()
    cliente_id = request.form["cliente_id"]

    db = get_db()

    db.execute("""
        UPDATE servidores
        SET nome_log=?
        WHERE id=?
    """, (nome_log, id))

    db.commit()

    return redirect(f"/servidores/{cliente_id}")


# =========================
# DASHBOARD INTELIGENTE
# =========================

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    try:
        agora = datetime.now()
        backups_data = montar_dados_backups(db)
        availability = montar_dados_tempo_online(db, "", 24)
        pfsense_rows, pfsense_summary = montar_disponibilidade_pfsense(db, availability["agora"], 24)
        ticket_summary = db.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) AS active,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open,
                   SUM(CASE WHEN status='open' AND assignee_user_id IS NULL THEN 1 ELSE 0 END) AS unassigned,
                   SUM(CASE WHEN status='in_progress' THEN 1 ELSE 0 END) AS in_progress,
                   SUM(CASE WHEN status='waiting_customer' THEN 1 ELSE 0 END) AS waiting,
                   SUM(CASE WHEN prioridade='critical' AND status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) AS critical
            FROM helpdesk_tickets
        """).fetchone()
        windows_summary = db.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN event_id IN (41,6008) THEN 1 ELSE 0 END) AS unexpected,
                   SUM(CASE WHEN event_id IN (41,6008) AND datetime(occurred_at)>=datetime('now','-24 hours') THEN 1 ELSE 0 END) AS unexpected_24h,
                   COUNT(DISTINCT hostname) AS hosts
            FROM windows_events
            WHERE datetime(occurred_at)>=datetime('now','-30 days')
        """).fetchone()
        estate = db.execute("""
            SELECT (SELECT COUNT(*) FROM clientes WHERE ativo=1) AS clients,
                   (SELECT COUNT(*) FROM servidores WHERE ativo=1) AS servers,
                   (SELECT COUNT(*) FROM notification_outbox WHERE status IN ('pending','retry')) AS notifications_pending,
                   (SELECT COUNT(*) FROM logs_nao_cadastrados) AS unknown_logs
        """).fetchone()
        latest_tickets = db.execute("""
            SELECT t.id, t.numero, t.assunto, t.prioridade, t.status, t.created_at,
                   c.nome_exibicao AS cliente_nome, u.username AS assignee_name
            FROM helpdesk_tickets t
            LEFT JOIN clientes c ON c.id=t.cliente_id
            LEFT JOIN usuarios u ON u.id=t.assignee_user_id
            WHERE t.status NOT IN ('resolved','closed')
            ORDER BY CASE t.prioridade WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                     datetime(t.created_at) DESC LIMIT 6
        """).fetchall()
        windows_recent = db.execute("""
            SELECT we.id, we.hostname, we.event_id, we.occurred_at, we.initiated_by,
                   c.nome_exibicao AS cliente_nome
            FROM windows_events we JOIN clientes c ON c.id=we.cliente_id
            WHERE we.event_id IN (41,6008,1074)
            ORDER BY datetime(we.occurred_at) DESC, we.id DESC LIMIT 5
        """).fetchall()
        backup_attention = [row for row in backups_data["linhas"] if row["status"] in ("erro", "atrasado", "alerta", "sem_log")][:7]
        agent_attention = [row for row in availability["linhas"] if row["streak"]["estado"] != "online"][:7]
        firewall_attention = [row for row in pfsense_rows if row["estado"] != "online" or row["backup_problem"] or row["ftp_problem"] or row["link_problem"] or row["speedtest_problem"]][:6]
        attention_total = (
            int(backups_data["resumo"]["problemas"] or 0)
            + int(availability["resumo"]["offline"] or 0)
            + len(firewall_attention)
            + int(ticket_summary["unassigned"] or 0)
            + int(windows_summary["unexpected_24h"] or 0)
            + int(estate["notifications_pending"] or 0)
        )
        return render_template(
            "dashboard.html", backups=backups_data, availability=availability,
            pfsense_rows=pfsense_rows, pfsense=pfsense_summary, tickets=ticket_summary,
            windows=windows_summary, estate=estate, latest_tickets=latest_tickets,
            windows_recent=windows_recent, backup_attention=backup_attention,
            agent_attention=agent_attention, firewall_attention=firewall_attention,
            attention_total=attention_total, now=agora, formatar_idade=formatar_idade,
            title="Central de operações",
        )
    finally:
        db.close()


# =========================
# LOGS NÃO CADASTRADOS
# =========================

def montar_dados_backups(db):
    agora = datetime.now()

    servidores = db.execute("""
        SELECT s.id, s.nome_log, c.nome_exibicao
        FROM servidores s
        JOIN clientes c ON c.id = s.cliente_id
        WHERE s.ativo = 1 AND c.ativo = 1
        ORDER BY c.nome_exibicao, s.nome_log
    """).fetchall()

    ultimos_logs = {
        (row["servidor_log"] or "").upper(): row
        for row in db.execute("""
            SELECT servidor_log, data_email, status, origem
            FROM (
                SELECT
                    servidor_log,
                    data_email,
                    status,
                    origem,
                    ROW_NUMBER() OVER (
                        PARTITION BY UPPER(servidor_log)
                        ORDER BY datetime(data_email) DESC, id DESC
                    ) AS rn
                FROM logs_email
            ) ranked
            WHERE rn=1
        """).fetchall()
    }
    heartbeats = {
        (row["servidor_log"] or "").upper(): row
        for row in db.execute("""
            SELECT servidor_log, hostname, ip_local, agent_version, last_seen, status, detalhe
            FROM agent_heartbeats
        """).fetchall()
    }
    agendamentos_por_servidor = {}
    for row in db.execute("""
        SELECT servidor_id, dias_execucao, hora_execucao, tolerancia_min
        FROM agendamentos_backup
        WHERE ativo=1
    """).fetchall():
        agendamentos_por_servidor.setdefault(row["servidor_id"], []).append(row)

    linhas = [
        montar_linha_backup_servidor(
            servidor,
            agora,
            ultimos_logs.get((servidor["nome_log"] or "").upper()),
            heartbeats.get((servidor["nome_log"] or "").upper()),
            agendamentos_por_servidor.get(servidor["id"], []),
        )
        for servidor in servidores
    ]

    ordem_status = {
        "erro": 0,
        "atrasado": 1,
        "alerta": 2,
        "aguardando": 3,
        "sem_log": 4,
        "sem_agenda": 5,
        "ok": 6,
    }
    linhas.sort(key=lambda item: (ordem_status.get(item["status"], 9), item["cliente"], item["nome_log"]))

    resumo = {
        "ok": sum(1 for item in linhas if item["status"] == "ok"),
        "problemas": sum(1 for item in linhas if item["status"] in ("erro", "atrasado")),
        "aguardando": sum(1 for item in linhas if item["status"] == "aguardando"),
        "sem_agenda": sum(1 for item in linhas if item["status"] == "sem_agenda"),
        "sem_log": sum(1 for item in linhas if item["status"] == "sem_log"),
        "total": len(linhas),
    }

    ultimo_worker = db.execute("""
        SELECT *
        FROM worker_runs
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 1
    """).fetchone()

    worker_fresh = False
    worker_age_min = None
    if ultimo_worker:
        worker_ref = parse_data(ultimo_worker["finished_at"]) or parse_data(ultimo_worker["started_at"])
        if worker_ref:
            worker_age_min = max(0, int((agora - worker_ref).total_seconds() // 60))
            worker_fresh = worker_age_min <= 15 and ultimo_worker["status"] in ("success", "running")

    origem_24h = db.execute("""
        SELECT COALESCE(origem, 'email') AS origem, COUNT(*) AS total
        FROM logs_email
        WHERE datetime(data_email) >= datetime('now', '-24 hours')
        GROUP BY COALESCE(origem, 'email')
        ORDER BY total DESC
    """).fetchall()

    recentes = db.execute("""
        SELECT servidor_log, data_email, status, origem, subject
        FROM logs_email
        ORDER BY datetime(data_email) DESC, id DESC
        LIMIT 12
    """).fetchall()

    return {
        "linhas": linhas,
        "resumo": resumo,
        "ultimo_worker": ultimo_worker,
        "worker_fresh": worker_fresh,
        "worker_age": formatar_idade(worker_age_min),
        "origem_24h": origem_24h,
        "recentes": recentes,
        "agora": agora,
    }


@app.route("/backups")
@login_required
def backups():
    db = get_db()
    dados = montar_dados_backups(db)
    db.close()
    return render_template(
        "backups.html",
        linhas=dados["linhas"],
        resumo=dados["resumo"],
        ultimo_worker=dados["ultimo_worker"],
        worker_fresh=dados["worker_fresh"],
        worker_age=dados["worker_age"],
        origem_24h=dados["origem_24h"],
        recentes=dados["recentes"],
        agora=dados["agora"].strftime("%Y-%m-%d %H:%M:%S"),
        formatar_idade=formatar_idade,
        title="Backups",
    )


def montar_dados_tempo_online(db, cliente_id="", periodo_horas=24):
    agora = datetime.now()
    if periodo_horas not in (24, 168, 720):
        periodo_horas = 24

    clientes = db.execute("""
        SELECT id, nome_exibicao
        FROM clientes
        WHERE ativo=1
        ORDER BY nome_exibicao
    """).fetchall()

    params = []
    filtro_cliente = ""
    if cliente_id:
        filtro_cliente = "AND c.id=?"
        params.append(cliente_id)

    servidores = db.execute(f"""
        SELECT s.id, s.nome_log, c.id AS cliente_id, c.nome_exibicao
        FROM servidores s
        JOIN clientes c ON c.id = s.cliente_id
        WHERE s.ativo=1 AND c.ativo=1
        {filtro_cliente}
        ORDER BY c.nome_exibicao, s.nome_log
    """, params).fetchall()

    periodo_key = {24: "24h", 168: "7d", 720: "30d"}[periodo_horas]
    inicio_periodo = agora - timedelta(hours=periodo_horas)
    inicio_periodo_sql = inicio_periodo.strftime("%Y-%m-%d %H:%M:%S")
    nomes_servidores = {(servidor["nome_log"] or "").upper() for servidor in servidores}
    heartbeats = {
        (row["servidor_log"] or "").upper(): row
        for row in db.execute("""
            SELECT servidor_log, hostname, ip_local, agent_version, last_seen, status, detalhe
            FROM agent_heartbeats
        """).fetchall()
        if (row["servidor_log"] or "").upper() in nomes_servidores
    }
    eventos_por_servidor = {}
    for row in db.execute("""
        SELECT servidor_log, status, seen_at
        FROM agent_heartbeat_history
        WHERE datetime(seen_at) >= datetime(?)
        ORDER BY UPPER(servidor_log), datetime(seen_at)
    """, (inicio_periodo_sql,)).fetchall():
        nome = (row["servidor_log"] or "").upper()
        if nome in nomes_servidores:
            eventos_por_servidor.setdefault(nome, []).append(row)

    linhas = []

    for servidor in servidores:
        nome_key = (servidor["nome_log"] or "").upper()
        heartbeat = heartbeats.get(nome_key)
        eventos = list(eventos_por_servidor.get(nome_key, []))

        eventos_status_atual = list(eventos)
        if heartbeat and heartbeat["last_seen"]:
            eventos_status_atual.append({
                "status": heartbeat["status"] or "online",
                "seen_at": heartbeat["last_seen"],
            })

        periodo_metricas = calcular_uptime_por_eventos(eventos_status_atual, inicio_periodo, agora)
        metricas = {
            "24h": periodo_metricas if periodo_key == "24h" else {"percentual": None, "online_min": 0, "offline_min": 0, "observado_min": 0},
            "7d": periodo_metricas if periodo_key == "7d" else {"percentual": None, "online_min": 0, "offline_min": 0, "observado_min": 0},
            "30d": periodo_metricas if periodo_key == "30d" else {"percentual": None, "online_min": 0, "offline_min": 0, "observado_min": 0},
        }
        streak = calcular_streak_agent(eventos_status_atual, agora)

        agente = formatar_status_agente(heartbeat, agora) if heartbeat else {
            "status": "sem_agente",
            "label": "Sem agente",
            "idade_min": None,
            "last_seen": None,
            "hostname": None,
            "ip_local": None,
            "version": None,
            "detalhe": None,
            "latest_version": LATEST_AGENT_VERSION,
            "update_available": False,
        }

        linhas.append({
            "cliente": servidor["nome_exibicao"],
            "nome_log": servidor["nome_log"],
            "agente": agente,
            "metricas": metricas,
            "periodo": metricas[periodo_key],
            "streak": streak,
            "eventos": len(eventos),
        })

    linhas.sort(key=lambda item: (
        999 if item["periodo"]["percentual"] is None else item["periodo"]["percentual"],
        item["cliente"],
        item["nome_log"],
    ))

    resumo = {
        "total": len(linhas),
        "online": sum(1 for item in linhas if item["streak"]["estado"] == "online"),
        "offline": sum(1 for item in linhas if item["streak"]["estado"] == "offline"),
        "sem_dados": sum(1 for item in linhas if item["streak"]["estado"] == "sem_dados"),
    }
    percentuais = [item["periodo"]["percentual"] for item in linhas if item["periodo"]["percentual"] is not None]
    resumo["media"] = round(sum(percentuais) / len(percentuais), 2) if percentuais else None

    cliente_nome = "Todos os clientes"
    if cliente_id:
        cliente = next((item for item in clientes if str(item["id"]) == str(cliente_id)), None)
        if cliente:
            cliente_nome = cliente["nome_exibicao"]

    return {
        "clientes": clientes,
        "cliente_id": cliente_id,
        "cliente_nome": cliente_nome,
        "horas": periodo_horas,
        "linhas": linhas,
        "resumo": resumo,
        "agora": agora,
    }


def montar_disponibilidade_pfsense(db, agora, periodo_horas):
    inicio = (agora - timedelta(hours=periodo_horas)).strftime("%Y-%m-%d %H:%M:%S")
    storage = db.execute("SELECT active FROM pfsense_storage WHERE id=1").fetchone()
    storage_active = bool(storage and storage["active"])
    firewalls = db.execute("""
        SELECT f.*,
               c.hostname, c.version, c.latency_ms, c.interfaces_total, c.interfaces_up,
               c.disk_percent, c.metrics_json, c.checked_at AS latest_checked_at,
               b.created_at AS latest_backup_created_at, b.remote_status,
               b.remote_uploaded_at, b.remote_error,
               s.tested_at AS latest_speedtest_tested_at, s.status AS latest_speedtest_result,
               s.ping_ms, s.download_mbps, s.upload_mbps, s.error AS speedtest_error
        FROM pfsense_firewalls f
        LEFT JOIN pfsense_checks c ON c.id=(
            SELECT pc.id FROM pfsense_checks pc
            WHERE pc.firewall_id=f.id ORDER BY pc.id DESC LIMIT 1
        )
        LEFT JOIN pfsense_backups b ON b.id=(
            SELECT pb.id FROM pfsense_backups pb
            WHERE pb.firewall_id=f.id ORDER BY pb.id DESC LIMIT 1
        )
        LEFT JOIN pfsense_speedtests s ON s.id=(
            SELECT ps.id FROM pfsense_speedtests ps
            WHERE ps.firewall_id=f.id ORDER BY ps.id DESC LIMIT 1
        )
        WHERE f.active=1
        ORDER BY f.name
    """).fetchall()

    linhas = []
    for row in firewalls:
        latest_metrics = {}
        if row["metrics_json"]:
            try:
                latest_metrics = json.loads(row["metrics_json"])
            except (TypeError, ValueError):
                pass
        uptime = enriquecer_uptime_pfsense(latest_metrics, row["latest_checked_at"])
        last_check = parse_data(row["last_check_at"] or row["latest_checked_at"])
        idade_min = max(0, int((agora - last_check).total_seconds() // 60)) if last_check else None
        limite_min = max(10, int(row["monitor_interval_minutes"] or 5) * 3)
        if not last_check:
            estado, label, classe = "sem_dados", "SEM DADOS", "secondary"
            detalhe = "aguardando primeira verificacao"
        elif row["last_status"] != "online":
            estado, label, classe = "offline", "DOWN", "danger"
            detalhe = row["last_error"] or "ultima verificacao falhou"
        elif idade_min > limite_min:
            estado, label, classe = "atrasado", "ATRASADO", "danger"
            detalhe = f"sem verificacao ha {formatar_idade(idade_min)}"
        else:
            estado, label, classe = "online", "UP", "success"
            detalhe = f"verificado ha {formatar_idade(idade_min)}"

        periodo = db.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='online' THEN 1 ELSE 0 END) AS online
            FROM pfsense_checks
            WHERE firewall_id=? AND datetime(checked_at) >= datetime(?)
        """, (row["id"], inicio)).fetchone()
        total_checks = int(periodo["total"] or 0)
        online_checks = int(periodo["online"] or 0)
        percentual = round((online_checks * 100.0) / total_checks, 2) if total_checks else None

        last_backup = parse_data(row["last_backup_at"] or row["latest_backup_created_at"])
        backup_idade_min = max(0, int((agora - last_backup).total_seconds() // 60)) if last_backup else None
        backup_limite_min = int(row["backup_interval_hours"] or 24) * 60 + limite_min
        backup_problem = not last_backup or backup_idade_min > backup_limite_min
        ftp_problem = storage_active and row["remote_status"] != "success"
        speedtest_problem = bool(row["speedtest_enabled"]) and row["last_speedtest_status"] == "error"
        internet_links = []
        for link_row in db.execute("""
            SELECT l.*,
                   p.status AS probe_status, p.latency_ms AS probe_latency_ms,
                   p.packet_loss_percent,
                   s.status AS speed_status, s.download_mbps, s.upload_mbps,
                   s.delivered_down_percent, s.delivered_up_percent
            FROM pfsense_links l
            LEFT JOIN pfsense_link_probes p ON p.id=(
                SELECT lp.id FROM pfsense_link_probes lp WHERE lp.link_id=l.id ORDER BY lp.id DESC LIMIT 1
            )
            LEFT JOIN pfsense_link_speedtests s ON s.id=(
                SELECT ls.id FROM pfsense_link_speedtests ls WHERE ls.link_id=l.id ORDER BY ls.id DESC LIMIT 1
            )
            WHERE l.firewall_id=? AND l.active=1 ORDER BY l.name
        """, (row["id"],)).fetchall():
            item = dict(link_row)
            below = bool(
                item["speed_status"] == "success"
                and item["delivered_down_percent"] is not None
                and (
                    float(item["delivered_down_percent"]) < float(item["minimum_delivery_percent"] or 80)
                    or float(item["delivered_up_percent"]) < float(item["minimum_delivery_percent"] or 80)
                )
            )
            item["problem"] = (
                item["probe_status"] in ("offline", "error")
                or (item["packet_loss_percent"] is not None and float(item["packet_loss_percent"]) > 20)
                or item["speed_status"] == "error" or below
            )
            internet_links.append(item)
        link_problem = any(item["problem"] for item in internet_links)

        linhas.append({
            "id": row["id"], "name": row["name"], "address": row["address"],
            "ssh_port": row["ssh_port"], "estado": estado, "label": label,
            "classe": classe, "detalhe": detalhe, "idade_min": idade_min,
            "hostname": row["hostname"], "version": row["version"],
            "latency_ms": row["latency_ms"], "interfaces_total": row["interfaces_total"],
            "interfaces_up": row["interfaces_up"], "disk_percent": row["disk_percent"],
            "uptime_label": uptime["UPTIME_LABEL"], "boot_at": uptime["BOOT_AT"],
            "recent_reboot": uptime["RECENT_REBOOT"],
            "periodo_total": total_checks, "periodo_online": online_checks,
            "periodo_percentual": percentual,
            "last_backup_at": row["last_backup_at"] or row["latest_backup_created_at"],
            "backup_idade_min": backup_idade_min, "backup_problem": backup_problem,
            "remote_status": row["remote_status"], "remote_uploaded_at": row["remote_uploaded_at"],
            "remote_error": row["remote_error"], "ftp_problem": ftp_problem,
            "storage_active": storage_active,
            "speedtest_enabled": bool(row["speedtest_enabled"]),
            "speedtest_status": row["latest_speedtest_result"],
            "speedtest_at": row["latest_speedtest_tested_at"],
            "speedtest_ping_ms": row["ping_ms"],
            "speedtest_download_mbps": row["download_mbps"],
            "speedtest_upload_mbps": row["upload_mbps"],
            "speedtest_error": row["speedtest_error"] or row["last_speedtest_error"],
            "speedtest_problem": speedtest_problem,
            "internet_links": internet_links, "link_problem": link_problem,
        })

    resumo = {
        "total": len(linhas),
        "online": sum(1 for item in linhas if item["estado"] == "online"),
        "offline": sum(1 for item in linhas if item["estado"] in ("offline", "atrasado")),
        "sem_dados": sum(1 for item in linhas if item["estado"] == "sem_dados"),
        "problemas_backup": sum(1 for item in linhas if item["backup_problem"] or item["ftp_problem"]),
        "problemas_speedtest": sum(1 for item in linhas if item["speedtest_problem"]),
        "problemas_links": sum(1 for item in linhas if item["link_problem"]),
        "storage_active": storage_active,
    }
    return linhas, resumo


@app.route("/disponibilidade")
@login_required
def disponibilidade():
    db = get_db()
    cliente_id = request.args.get("cliente_id", "").strip()
    try:
        periodo_horas = int(request.args.get("horas") or 24)
    except ValueError:
        periodo_horas = 24
    dados = montar_dados_tempo_online(db, cliente_id, periodo_horas)
    pfsense_linhas, pfsense_resumo = montar_disponibilidade_pfsense(
        db, dados["agora"], dados["horas"]
    )
    db.close()

    agente_alertas = []
    for row in dados["linhas"]:
        agente = row["agente"]
        estado = row["streak"]["estado"]
        update_only = agente.get("update_available") and estado == "online"
        if estado == "online" and not update_only:
            continue

        if estado == "offline":
            label = "Offline"
            classe = "danger"
            detalhe = f"off ha {formatar_idade(row['streak'].get('desde_min'))}"
            prioridade = 0
        elif estado == "sem_dados":
            label = "Sem dados"
            classe = "secondary"
            detalhe = "sem historico de heartbeat"
            prioridade = 1
        else:
            label = "Atualizar"
            classe = "info"
            detalhe = f"v{agente.get('version')} -> {agente.get('latest_version')}"
            prioridade = 2

        agente_alertas.append({
            "cliente": row["cliente"],
            "nome_log": row["nome_log"],
            "label": label,
            "classe": classe,
            "detalhe": detalhe,
            "hostname": agente.get("hostname"),
            "ip_local": agente.get("ip_local"),
            "prioridade": prioridade,
            "desde_min": row["streak"].get("desde_min"),
            "href": f"/servidor/{row['nome_log']}",
        })

    for firewall in pfsense_linhas:
        if firewall["estado"] == "online" and not firewall["backup_problem"] and not firewall["ftp_problem"] and not firewall["speedtest_problem"] and not firewall["link_problem"]:
            continue
        if firewall["estado"] in ("offline", "atrasado"):
            label, classe, prioridade = firewall["label"], "danger", 0
            detalhe = firewall["detalhe"]
        elif firewall["estado"] == "sem_dados":
            label, classe, prioridade = "Sem dados", "secondary", 1
            detalhe = firewall["detalhe"]
        elif firewall["ftp_problem"]:
            label, classe, prioridade = "FTP", "warning", 1
            detalhe = firewall["remote_error"] or "ultimo backup ainda nao foi enviado"
        elif firewall["speedtest_problem"]:
            label, classe, prioridade = "Internet", "warning", 1
            detalhe = firewall["speedtest_error"] or "teste de velocidade falhou"
        elif firewall["link_problem"]:
            label, classe, prioridade = "Link WAN", "warning", 1
            detalhe = "uma ou mais Internets apresentam falha ou entrega abaixo do limite"
        else:
            label, classe, prioridade = "Backup", "warning", 1
            detalhe = "backup ausente ou atrasado"
        agente_alertas.append({
            "cliente": "pfSense",
            "nome_log": firewall["name"],
            "label": label,
            "classe": classe,
            "detalhe": detalhe,
            "hostname": firewall["hostname"],
            "ip_local": firewall["address"],
            "prioridade": prioridade,
            "desde_min": firewall["idade_min"],
            "href": f"/pfsense/{firewall['id']}",
        })

    agente_alertas.sort(key=lambda item: (
        item["prioridade"],
        -(item["desde_min"] or 0),
        item["cliente"],
        item["nome_log"],
    ))
    dados["resumo"]["atencao"] = len(agente_alertas)

    return render_template(
        "disponibilidade.html",
        clientes=dados["clientes"],
        cliente_id=dados["cliente_id"],
        cliente_nome=dados["cliente_nome"],
        horas=dados["horas"],
        linhas=dados["linhas"],
        resumo=dados["resumo"],
        agente_alertas=agente_alertas,
        pfsense_linhas=pfsense_linhas,
        pfsense_resumo=pfsense_resumo,
        agora=dados["agora"].strftime("%Y-%m-%d %H:%M:%S"),
        formatar_idade=formatar_idade,
        title="Disponibilidade",
    )


@app.route("/tempo-online")
@login_required
def tempo_online():
    destino = "/disponibilidade"
    if request.query_string:
        destino += "?" + request.query_string.decode("utf-8", errors="ignore")
    return redirect(destino)


@app.route("/disponibilidade/relatorio")
@app.route("/tempo-online/relatorio")
@login_required
def tempo_online_relatorio():
    db = get_db()
    cliente_id = request.args.get("cliente_id", "").strip()
    try:
        periodo_horas = int(request.args.get("horas") or 24)
    except ValueError:
        periodo_horas = 24
    dados = montar_dados_tempo_online(db, cliente_id, periodo_horas)
    db.close()

    html = render_template(
        "tempo_online_relatorio.html",
        cliente_nome=dados["cliente_nome"],
        horas=dados["horas"],
        linhas=dados["linhas"],
        resumo=dados["resumo"],
        agora=dados["agora"].strftime("%Y-%m-%d %H:%M:%S"),
        formatar_idade=formatar_idade,
    )
    periodo_label = {24: "24h", 168: "7dias", 720: "30dias"}.get(dados["horas"], "24h")
    cliente_slug = re.sub(r"[^A-Za-z0-9_-]+", "_", dados["cliente_nome"]).strip("_").lower() or "clientes"
    filename = f"relatorio-disponibilidade-{cliente_slug}-{periodo_label}.html"
    headers = {}
    if request.args.get("download") == "1":
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(html, headers=headers, mimetype="text/html; charset=utf-8")


@app.route("/logs-nao-cadastrados")
@login_required
def logs_nao_cadastrados():

    db = get_db()

    logs = db.execute("""
        SELECT
            l.servidor_log,
            MAX(l.data_email) AS ultima_data,
            COUNT(*) AS ocorrencias,
            MAX(l.subject) AS subject
        FROM logs_nao_cadastrados l
        LEFT JOIN servidores s
          ON UPPER(l.servidor_log)=UPPER(s.nome_log)
        WHERE s.id IS NULL
        GROUP BY l.servidor_log
        ORDER BY l.servidor_log
    """).fetchall()

    return render_template("logs_nao_cadastrados.html", logs=logs)


# =========================
# CADASTRO RÁPIDO
# =========================

@app.route("/servidores/novo/<nome_log>")
@login_required
@admin_required
def novo_servidor_detectado(nome_log):

    db = get_db()
    clientes = db.execute("SELECT * FROM clientes WHERE ativo=1 ORDER BY nome_exibicao").fetchall()

    return render_template(
        "novo_servidor_detectado.html",
        nome_log=nome_log.strip().upper(),
        clientes=clientes
    )


@app.route("/servidores/salvar-detectado", methods=["POST"])
@login_required
@admin_required
def salvar_servidor_detectado():

    db = get_db()

    nome_log = request.form["nome_log"].strip().upper()
    cliente_id = request.form["cliente_id"]
    backups_semana = request.form.get("backups_semana", 7)

    if cliente_id == "novo":
        nome_cliente = request.form["novo_cliente"]
        db.execute(
            "INSERT INTO clientes (nome_exibicao) VALUES (?)",
            (nome_cliente,)
        )
        db.commit()

        cliente_id = db.execute(
            "SELECT id FROM clientes ORDER BY id DESC LIMIT 1"
        ).fetchone()["id"]

    db.execute("""
        INSERT INTO servidores (cliente_id, nome_log, backups_semana)
        VALUES (?,?,?)
    """, (
        cliente_id,
        nome_log,
        backups_semana
    ))

    db.commit()

    return redirect(f"/servidores/{cliente_id}")


# =========================
# HISTÓRICO GERAL
# =========================
# =========================
# HISTÓRICO INDIVIDUAL DO SERVIDOR
# =========================

@app.route("/servidor/<nome_log>")
@login_required
def historico_servidor(nome_log):

    db = get_db()

    logs = db.execute("""
        SELECT data_email, status, conteudo_raw
        FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        ORDER BY data_email DESC
        LIMIT 200
    """, (nome_log,)).fetchall()

    return render_template(
        "historico_servidor.html",
        nome_log=nome_log,
        logs=logs
    )

@app.route("/historico")
@login_required
def historico():

    db = get_db()

    servidor = request.args.get("servidor", "")
    inicio = request.args.get("inicio", "")
    fim = request.args.get("fim", "")

    query = """
        SELECT l.*, s.nome_log, c.nome_exibicao
        FROM logs_email l
        JOIN servidores s ON UPPER(s.nome_log)=UPPER(l.servidor_log)
        JOIN clientes c ON c.id = s.cliente_id
        WHERE 1=1
    """

    params = []

    if servidor:
        query += " AND UPPER(l.servidor_log)=UPPER(?)"
        params.append(servidor)

    if inicio:
        query += " AND date(l.data_email) >= ?"
        params.append(inicio)

    if fim:
        query += " AND date(l.data_email) <= ?"
        params.append(fim)

    query += " ORDER BY l.data_email DESC LIMIT 200"

    logs = db.execute(query, params).fetchall()

    servidores = db.execute("""
        SELECT DISTINCT nome_log FROM servidores ORDER BY nome_log
    """).fetchall()

    return render_template(
        "historico_geral.html",
        logs=logs,
        servidores=servidores,
        servidor_filtro=servidor,
        inicio=inicio,
        fim=fim
    )


@app.route("/status")
@login_required
def status_sistema():
    db = get_db()

    ultimo_worker = db.execute("""
        SELECT *
        FROM worker_runs
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 1
    """).fetchone()

    historico_worker = db.execute("""
        SELECT *
        FROM worker_runs
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 20
    """).fetchall()

    email_config = db.execute("""
        SELECT imap_server, imap_port, email_user, pasta, usar_ssl
        FROM config_email
        LIMIT 1
    """).fetchone()

    totais = {
        "clientes": db.execute("SELECT COUNT(*) AS c FROM clientes WHERE ativo=1").fetchone()["c"],
        "servidores": db.execute("SELECT COUNT(*) AS c FROM servidores WHERE ativo=1").fetchone()["c"],
        "logs": db.execute("SELECT COUNT(*) AS c FROM logs_email").fetchone()["c"],
        "nao_cadastrados": db.execute("""
            SELECT COUNT(*) AS c
            FROM logs_nao_cadastrados l
            LEFT JOIN servidores s ON UPPER(l.servidor_log)=UPPER(s.nome_log)
            WHERE s.id IS NULL
        """).fetchone()["c"],
        "notificacoes_pendentes": db.execute("SELECT COUNT(*) AS c FROM notification_outbox WHERE status IN ('pending','retry')").fetchone()["c"],
        "notificacoes_falhas": db.execute("SELECT COUNT(*) AS c FROM notification_outbox WHERE status='failed'").fetchone()["c"],
    }
    ticketz = db.execute("SELECT ativo, CASE WHEN token_enc IS NULL OR token_enc='' THEN 0 ELSE 1 END AS token_ok FROM ticketz_config WHERE id=1").fetchone()
    storage = db.execute("SELECT active, last_status, last_test_at, last_cleanup_at FROM pfsense_storage WHERE id=1").fetchone()
    agent_versions = db.execute("SELECT COALESCE(agent_version,'desconhecida') AS version, COUNT(*) AS total FROM agent_heartbeats GROUP BY COALESCE(agent_version,'desconhecida') ORDER BY total DESC").fetchall()
    worker_ref = parse_data(ultimo_worker["finished_at"] or ultimo_worker["started_at"]) if ultimo_worker else None
    worker_age = max(0, int((datetime.now() - worker_ref).total_seconds() // 60)) if worker_ref else None
    worker_fresh = worker_age is not None and worker_age <= 15 and ultimo_worker["status"] in ("success", "running")
    db.close()

    return render_template(
        "status.html",
        ultimo_worker=ultimo_worker,
        historico_worker=historico_worker,
        email_config=email_config,
        totais=totais,
        ticketz=ticketz, storage=storage, agent_versions=agent_versions,
        worker_age=worker_age, worker_fresh=worker_fresh,
        title="Saúde da plataforma",
    )


@app.route("/admin")
@login_required
@admin_required
def admin_painel():
    db = get_db()
    limpar_sessoes_expiradas(db)
    db.commit()

    usuarios = db.execute("""
        SELECT u.id, u.username, u.tipo, u.ativo, u.max_sessoes, u.is_technician,
               COUNT(CASE WHEN us.ativo=1 THEN 1 END) AS sessoes_ativas,
               MAX(us.last_seen) AS ultimo_acesso
        FROM usuarios u
        LEFT JOIN user_sessions us ON us.user_id = u.id
        GROUP BY u.id
        ORDER BY u.username
    """).fetchall()

    sessoes = db.execute("""
        SELECT us.*, u.tipo
        FROM user_sessions us
        JOIN usuarios u ON u.id = us.user_id
        WHERE us.ativo=1
        ORDER BY datetime(us.last_seen) DESC
    """).fetchall()

    config = retention_config(db)
    retencoes = db.execute("""
        SELECT *
        FROM maintenance_runs
        WHERE action='retention'
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 10
    """).fetchall()

    return render_template(
        "admin.html",
        usuarios=usuarios,
        sessoes=sessoes,
        retention=config,
        retencoes=retencoes,
        title="Administracao",
    )


@app.route("/admin/users/add", methods=["POST"])
@login_required
@admin_required
def admin_add_user():
    username = request.form.get("username", "").strip()
    senha = request.form.get("senha", "")
    tipo = request.form.get("tipo", "operador")
    max_sessoes = max(1, int(request.form.get("max_sessoes") or 1))
    is_technician = 1 if request.form.get("is_technician") == "1" else 0

    if not username or not senha:
        return redirect("/admin")

    db = get_db()
    senha_hash = hash_password(senha)
    db.execute("""
        INSERT INTO usuarios (username, senha_hash, tipo, ativo, max_sessoes, is_technician)
        VALUES (?, ?, ?, 1, ?, ?)
    """, (username, senha_hash, tipo, max_sessoes, is_technician))
    db.commit()
    db.close()
    return redirect("/admin")


@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
@login_required
@admin_required
def admin_update_user(user_id):
    tipo = request.form.get("tipo", "operador")
    ativo = 1 if request.form.get("ativo") == "1" else 0
    max_sessoes = max(1, int(request.form.get("max_sessoes") or 1))
    nova_senha = request.form.get("senha", "")
    is_technician = 1 if request.form.get("is_technician") == "1" else 0

    if user_id == session.get("user_id"):
        ativo = 1

    db = get_db()
    if nova_senha:
        db.execute("""
            UPDATE usuarios
            SET tipo=?, ativo=?, max_sessoes=?, is_technician=?, senha_hash=?
            WHERE id=?
        """, (tipo, ativo, max_sessoes, is_technician, hash_password(nova_senha), user_id))
    else:
        db.execute("""
            UPDATE usuarios
            SET tipo=?, ativo=?, max_sessoes=?, is_technician=?
            WHERE id=?
        """, (tipo, ativo, max_sessoes, is_technician, user_id))

    if not ativo:
        db.execute("""
            UPDATE user_sessions
            SET ativo=0, logged_out_at=?
            WHERE user_id=? AND ativo=1
        """, (agora_sql(), user_id))
    db.commit()
    db.close()
    return redirect("/admin")


@app.route("/admin/users/<int:user_id>/sessions/clear", methods=["POST"])
@login_required
@admin_required
def admin_clear_user_sessions(user_id):
    db = get_db()
    db.execute("""
        UPDATE user_sessions
        SET ativo=0, logged_out_at=?
        WHERE user_id=? AND ativo=1
    """, (agora_sql(), user_id))
    db.commit()
    db.close()
    return redirect("/admin")


@app.route("/admin/retention/save", methods=["POST"])
@login_required
@admin_required
def admin_save_retention():
    db = get_db()
    db.execute("""
        UPDATE retention_config
        SET logs_full_days=?,
            unknown_logs_days=?,
            worker_runs_days=?,
            zammad_alerts_days=?,
            heartbeat_history_days=?,
            session_history_days=?,
            auto_enabled=?,
            updated_at=?
        WHERE id=1
    """, (
        max(1, int(request.form.get("logs_full_days") or 90)),
        max(1, int(request.form.get("unknown_logs_days") or 30)),
        max(1, int(request.form.get("worker_runs_days") or 180)),
        max(1, int(request.form.get("zammad_alerts_days") or 180)),
        max(1, int(request.form.get("heartbeat_history_days") or 90)),
        max(1, int(request.form.get("session_history_days") or 30)),
        1 if request.form.get("auto_enabled") == "1" else 0,
        agora_sql(),
    ))
    db.commit()
    db.close()
    return redirect("/admin")


@app.route("/admin/retention/run", methods=["POST"])
@login_required
@admin_required
def admin_run_retention():
    executar_retencao(manual=True)
    return redirect("/admin")


@app.route("/zammad-config")
@login_required
@admin_required
def zammad_config():
    db = get_db()

    config = db.execute("""
        SELECT id, ativo, base_url, grupo, customer_email, prioridade,
               prioridade_agent_offline,
               criar_chamado_erro, criar_chamado_nao_recebido,
               criar_chamado_agent_offline, agent_offline_minutos,
               fechar_chamado_agent_online,
               CASE WHEN token IS NULL OR token='' THEN 0 ELSE 1 END AS tem_token
        FROM zammad_config
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    alertas = db.execute("""
        SELECT *
        FROM zammad_alertas
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 30
    """).fetchall()

    return render_template(
        "zammad_config.html",
        config=config,
        alertas=alertas,
        title="Config Zammad",
    )


@app.route("/zammad-config/save", methods=["POST"])
@login_required
@admin_required
def save_zammad_config():
    db = get_db()
    atual = db.execute("""
        SELECT *
        FROM zammad_config
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    token = request.form.get("token", "").strip()
    if not token and atual:
        token = atual["token"]

    db.execute("DELETE FROM zammad_config")
    db.execute("""
        INSERT INTO zammad_config
        (ativo, base_url, token, grupo, customer_email, prioridade,
         prioridade_agent_offline,
         criar_chamado_erro, criar_chamado_nao_recebido,
         criar_chamado_agent_offline, agent_offline_minutos,
         fechar_chamado_agent_online)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        1 if request.form.get("ativo") else 0,
        request.form.get("base_url", "").strip().rstrip("/"),
        token,
        request.form.get("grupo", "").strip(),
        request.form.get("customer_email", "").strip(),
        request.form.get("prioridade", "2 normal").strip() or "2 normal",
        request.form.get("prioridade_agent_offline", "3 high").strip() or "3 high",
        1 if request.form.get("criar_chamado_erro") else 0,
        1 if request.form.get("criar_chamado_nao_recebido") else 0,
        1 if request.form.get("criar_chamado_agent_offline") else 0,
        max(5, int(request.form.get("agent_offline_minutos") or 15)),
        1 if request.form.get("fechar_chamado_agent_online") else 0,
    ))

    db.commit()
    return redirect("/zammad-config")


@app.route("/api-keys")
@login_required
@admin_required
def api_keys():
    db = get_db()
    keys = db.execute("""
        SELECT k.id, k.nome, k.cliente_id, k.servidor_log, k.ativo,
               k.created_at, k.last_used_at, c.nome_exibicao
        FROM api_keys k
        LEFT JOIN clientes c ON c.id = k.cliente_id
        ORDER BY k.id DESC
    """).fetchall()
    clientes = db.execute("""
        SELECT id, nome_exibicao
        FROM clientes
        WHERE ativo=1
        ORDER BY nome_exibicao
    """).fetchall()
    servidores = db.execute("""
        SELECT s.id, s.nome_log, c.nome_exibicao
        FROM servidores s
        LEFT JOIN clientes c ON c.id = s.cliente_id
        WHERE s.ativo=1 AND COALESCE(c.ativo, 1)=1
        ORDER BY c.nome_exibicao, s.nome_log
    """).fetchall()
    novo_token = session.pop("novo_api_token", None)

    return render_template(
        "api_keys.html",
        keys=keys,
        clientes=clientes,
        servidores=servidores,
        novo_token=novo_token,
        title="Agents / Chaves",
    )


@app.route("/api-keys/create", methods=["POST"])
@login_required
@admin_required
def create_api_key():
    nome = request.form.get("nome", "").strip() or "Agente"
    cliente_id = request.form.get("cliente_id") or None
    servidor_log = normalizar_servidor(request.form.get("servidor_log", ""))
    token = secrets.token_urlsafe(32)

    if servidor_log:
        cliente_id = None

    db = get_db()
    db.execute("""
        INSERT INTO api_keys (nome, token_hash, cliente_id, servidor_log, ativo)
        VALUES (?,?,?,?,1)
    """, (nome, hash_token(token), cliente_id, servidor_log or None))
    db.commit()

    session["novo_api_token"] = token
    return redirect("/api-keys")


@app.route("/api-keys/toggle/<int:key_id>")
@login_required
@admin_required
def toggle_api_key(key_id):
    db = get_db()
    key = db.execute("SELECT ativo FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if key:
        db.execute("UPDATE api_keys SET ativo=? WHERE id=?", (0 if key["ativo"] else 1, key_id))
        db.commit()
    return redirect("/api-keys")


DEFAULT_AGENT_LOG_PATHS = [
    "C:\\ProgramData\\IperiusBackup\\Logs",
    "C:\\ProgramData\\Iperius Backup\\Logs",
    "C:\\Program Files\\Iperius Backup\\Logs",
    "C:\\Program Files (x86)\\Iperius Backup\\Logs",
    "C:\\Users\\*\\AppData\\Local\\Temp\\IperiusTemp",
]


def montar_job_config(nome_log, log_path=None, usar_filtro_conteudo=True):
    nome_log = normalizar_servidor(nome_log)
    if log_path:
        log_paths = [log_path]
    else:
        log_paths = DEFAULT_AGENT_LOG_PATHS

    job = {
        "servidor_log": nome_log,
        "log_paths": log_paths,
        "patterns": ["*.txt", "*.log", "*.html", "*.htm"],
        "include_patterns": ["*"],
        "exclude_patterns": [],
        "exclude_content_patterns": [],
    }

    if usar_filtro_conteudo:
        job["content_patterns"] = [
            f"*{nome_log}*",
            f"*{nome_log.replace('_', ' ')}*",
        ]
    else:
        job["content_patterns"] = []

    return job


def responder_agent_config(filename, jobs):
    config = montar_agent_config(jobs)

    body = json.dumps(config, ensure_ascii=False, indent=2)
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


def montar_agent_config(jobs, api_key="COLE_A_CHAVE_API_AQUI"):
    return {
        "monitor_url": "https://bkp.fpinformatica.com.br",
        "api_key": api_key,
        "jobs": jobs,
        "email_grace_minutes": 10,
        "scan_interval_seconds": 30,
        "heartbeat_interval_seconds": 300,
        "recent_hours_on_start": 72,
        "windows_event_monitoring_enabled": True,
        "windows_event_recent_hours_on_start": 168,
        "auto_update_enabled": True,
        "state_path": "C:\\ProgramData\\BackupMonitorAgent\\state.json",
        "log_path": "C:\\ProgramData\\BackupMonitorAgent\\agent.log",
    }


def criar_api_key_cliente(db, cliente_id, nome):
    token = secrets.token_urlsafe(32)
    db.execute("""
        INSERT INTO api_keys (nome, token_hash, cliente_id, servidor_log, ativo)
        VALUES (?,?,?,?,1)
    """, (nome, hash_token(token), cliente_id, None))
    db.commit()
    return token


def buscar_cliente_jobs(cliente_id, log_path=None, usar_filtro_conteudo=True):
    db = get_db()
    cliente = db.execute("""
        SELECT id, nome_exibicao
        FROM clientes
        WHERE id=? AND ativo=1
    """, (cliente_id,)).fetchone()
    if not cliente:
        return None, None

    servidores = db.execute("""
        SELECT nome_log
        FROM servidores
        WHERE cliente_id=? AND ativo=1
        ORDER BY nome_log
    """, (cliente_id,)).fetchall()

    jobs = [
        montar_job_config(s["nome_log"], log_path, usar_filtro_conteudo)
        for s in servidores
    ]
    return cliente, jobs


def montar_zip_agent_bytes(filename, config_json, legacy=False):
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(app_dir)
    static_dir = os.path.join(app_dir, "static")
    agent_dir = os.path.join(app_dir, "agents")
    if not os.path.isdir(agent_dir):
        agent_dir = os.path.join(project_root, "agents")

    files = [
        (os.path.join(agent_dir, "BackupMonitorAgentService.exe"), "BackupMonitorAgentService.exe"),
        (os.path.join(agent_dir, "windows-backup-agent.ps1"), "windows-backup-agent.ps1"),
        (os.path.join(agent_dir, "install-windows-agent.ps1"), "install-windows-agent.ps1"),
        (os.path.join(agent_dir, "enable-agent-auto-update.ps1"), "enable-agent-auto-update.ps1"),
        (os.path.join(agent_dir, "test-agent-compatibility.ps1"), "test-agent-compatibility.ps1"),
        (os.path.join(agent_dir, "README.md"), "README.md"),
    ]
    if legacy:
        files.extend([
            (os.path.join(static_dir, "BackupMonitorAgentSetupLegacy2012.exe"), "BackupMonitorAgentSetupLegacy2012.exe"),
            (os.path.join(agent_dir, "install-legacy-ws2012.ps1"), "install-legacy-ws2012.ps1"),
            (os.path.join(agent_dir, "Instalar-Legacy-WS2012.cmd"), "Instalar-Legacy-WS2012.cmd"),
        ])
        instalar_cmd = """@echo off
setlocal
cd /d "%~dp0"
echo Backup Monitor Agent Legacy - Windows Server 2012
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-legacy-ws2012.ps1" -RunNow
echo.
pause
"""
        instrucoes = f"""Backup Monitor Agent Legacy - Windows Server 2012

1. Extraia este ZIP em uma pasta simples, por exemplo C:\\bkp-agent.
2. Execute INSTALAR.cmd como Administrador.

Se preferir pelo PowerShell, rode:

   cd "C:\\bkp-agent"
   Get-ChildItem -Recurse | Unblock-File
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\install-legacy-ws2012.ps1 -RunNow

4. Confira:

   Get-Service -Name BackupMonitorAgent
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\agent.log" -Tail 50
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\service.log" -Tail 50

Config incluida: {filename}
A chave API deste cliente ja esta embutida na config.
"""
    else:
        files.extend([
            (os.path.join(static_dir, "BackupMonitorAgentSetup.exe"), "BackupMonitorAgentSetup.exe"),
            (os.path.join(agent_dir, "setup-wizard.ps1"), "setup-wizard.ps1"),
        ])
        instalar_cmd = f"""@echo off
setlocal
cd /d "%~dp0"
echo Backup Monitor Agent
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows-agent.ps1" -ConfigTemplate "%~dp0{filename}" -InstallMode Service -SkipTest -RunNow
echo.
pause
"""
        instrucoes = f"""Backup Monitor Agent

1. Extraia este ZIP em uma pasta simples, por exemplo C:\\bkp-agent.
2. Execute INSTALAR.cmd como Administrador.

Se preferir pelo PowerShell, rode:

   cd "C:\\bkp-agent"
   Get-ChildItem -Recurse | Unblock-File
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\install-windows-agent.ps1 -ConfigTemplate ".\\{filename}" -InstallMode Service -SkipTest -RunNow

4. Confira:

   Get-Service -Name BackupMonitorAgent
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\agent.log" -Tail 50
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\service.log" -Tail 50

Config incluida: {filename}
A chave API deste cliente ja esta embutida na config.
"""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, config_json)
        zf.writestr("config-name.txt", filename)
        zf.writestr("install-mode.txt", "legacy" if legacy else "normal")
        zf.writestr("LEIA-ME-INSTALAR.txt", instrucoes)
        zf.writestr("INSTALAR.cmd", instalar_cmd)
        for path, arcname in files:
            if os.path.exists(path):
                zf.write(path, arcname)

    buffer.seek(0)
    return buffer.getvalue()


def montar_agent_exe_bytes(filename, config_json, legacy=False):
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(app_dir)
    agent_dir = os.path.join(app_dir, "agents")
    if not os.path.isdir(agent_dir):
        agent_dir = os.path.join(project_root, "agents")

    stub_path = os.path.join(agent_dir, "BackupMonitorAgentInstallerStub.exe")
    if not os.path.exists(stub_path):
        raise FileNotFoundError("BackupMonitorAgentInstallerStub.exe nao encontrado")

    with open(stub_path, "rb") as f:
        stub = f.read()

    payload = montar_zip_agent_bytes(filename, config_json, legacy=legacy)
    marker = b"\n--BACKUP_MONITOR_AGENT_PAYLOAD_V1--\n"
    return stub + marker + payload


def montar_jobs_customizados():
    db = get_db()

    servidor_ids = request.form.getlist("servidor_ids")
    if not servidor_ids:
        return None, None, ("Selecione pelo menos um servidor", 400)

    placeholders = ",".join(["?"] * len(servidor_ids))
    servidores = db.execute(f"""
        SELECT s.id, s.nome_log, c.nome_exibicao
        FROM servidores s
        JOIN clientes c ON c.id = s.cliente_id
        WHERE s.id IN ({placeholders}) AND s.ativo=1 AND c.ativo=1
        ORDER BY c.nome_exibicao, s.nome_log
    """, servidor_ids).fetchall()

    if not servidores:
        return None, None, ("Nenhum servidor valido selecionado", 400)

    log_path = request.form.get("log_path", "").strip() or "C:\\ProgramData\\IperiusBackup\\Logs"
    usar_filtro_conteudo = request.form.get("usar_filtro_conteudo") == "1"
    jobs = [
        montar_job_config(s["nome_log"], log_path, usar_filtro_conteudo)
        for s in servidores
    ]

    nome_pacote = request.form.get("nome_pacote", "").strip()
    if not nome_pacote:
        nomes_clientes = sorted({s["nome_exibicao"] or "cliente" for s in servidores})
        nome_pacote = nomes_clientes[0] if len(nomes_clientes) == 1 else "personalizado"

    filename = f"agent.config.{normalizar_servidor(nome_pacote).lower()}.json"
    return filename, jobs, None


@app.route("/api-keys/config/custom", methods=["POST"])
@login_required
@admin_required
def download_custom_agent_config():
    filename, jobs, erro = montar_jobs_customizados()
    if erro:
        return erro

    return responder_agent_config(filename, jobs)


@app.route("/api-keys/package/legacy-ws2012", methods=["POST"])
@login_required
@admin_required
def download_legacy_ws2012_package():
    filename, jobs, erro = montar_jobs_customizados()
    if erro:
        return erro

    config = montar_agent_config(jobs)
    config_json = json.dumps(config, ensure_ascii=False, indent=2)
    data = montar_zip_agent_bytes(filename, config_json, legacy=True)
    package_name = filename.replace("agent.config.", "backup-monitor-agent-legacy-ws2012-").replace(".json", ".zip")
    return Response(
        data,
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename={package_name}"},
    )


@app.route("/clientes/<int:cliente_id>/agent-package")
@login_required
@support_required
def download_cliente_agent_package(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_zip_agent_bytes(filename, config_json, legacy=False)
    return Response(
        data,
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename=backup-monitor-agent-{filename_base}.zip"},
    )


@app.route("/clientes/<int:cliente_id>/agent-exe")
@login_required
@support_required
def download_cliente_agent_exe(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent EXE {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    config_filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_agent_exe_bytes(config_filename, config_json, legacy=False)
    return Response(
        data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=BackupMonitorAgent-{filename_base}.exe"},
    )


@app.route("/clientes/<int:cliente_id>/agent-package/legacy-ws2012")
@login_required
@support_required
def download_cliente_agent_package_legacy(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent WS2012 {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_zip_agent_bytes(filename, config_json, legacy=True)
    return Response(
        data,
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename=backup-monitor-agent-ws2012-{filename_base}.zip"},
    )


@app.route("/clientes/<int:cliente_id>/agent-exe/legacy-ws2012")
@login_required
@support_required
def download_cliente_agent_exe_legacy(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent EXE WS2012 {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    config_filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_agent_exe_bytes(config_filename, config_json, legacy=True)
    return Response(
        data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=BackupMonitorAgent-WS2012-{filename_base}.exe"},
    )


@app.route("/api-keys/config/cliente/<int:cliente_id>")
@login_required
@admin_required
def download_cliente_agent_config(cliente_id):
    db = get_db()
    cliente = db.execute("""
        SELECT id, nome_exibicao
        FROM clientes
        WHERE id=? AND ativo=1
    """, (cliente_id,)).fetchone()
    if not cliente:
        return "Cliente nao encontrado", 404

    servidores = db.execute("""
        SELECT nome_log
        FROM servidores
        WHERE cliente_id=? AND ativo=1
        ORDER BY nome_log
    """, (cliente_id,)).fetchall()

    jobs = []
    for servidor in servidores:
        jobs.append(montar_job_config(servidor["nome_log"]))

    filename = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    return responder_agent_config(f"agent.config.{filename}.json", jobs)


@app.route("/api/logs/ingest", methods=["POST"])
def ingest_log():
    db = get_db()
    token = extrair_api_token()
    payload = ler_json_tolerante()
    servidor_payload = normalizar_servidor(payload.get("servidor_log") or payload.get("servidor") or "")
    key = autenticar_api_key(db, token)
    if not key:
        key = recuperar_agent_api_key(db, token, servidor_payload)
    if not key:
        return jsonify({"error": "unauthorized"}), 401

    servidor = normalizar_servidor(servidor_payload or key["servidor_log"])

    if not servidor:
        return jsonify({"error": "servidor_log is required"}), 400

    key = garantir_servidor_recuperado(db, key, servidor)
    if not api_key_autorizada_para_servidor(key, servidor, db):
        return jsonify({
            "error": "api key not allowed for this server",
            "servidor_log": servidor,
            "api_key_id": key["id"],
            "api_key_cliente_id": key["cliente_id"],
            "api_key_servidor_log": key["servidor_log"],
        }), 403

    body = payload.get("conteudo_raw") or payload.get("body") or payload.get("log") or ""
    subject = payload.get("subject") or payload.get("assunto") or f"Log local - {servidor}"
    status_backup = payload.get("status") or detectar_status_log(f"{subject}\n{body}")
    data_email = payload.get("data_email") or payload.get("data_backup") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    origem = payload.get("origem") or "agent"
    message_id = payload.get("message_id")
    conteudo_hash = payload.get("conteudo_hash") or hash_conteudo(body)

    if not message_id:
        fingerprint = hashlib.sha256(f"{servidor}|{data_email}|{subject}|{conteudo_hash}".encode()).hexdigest()
        message_id = f"agent-{fingerprint}"

    existe = db.execute("SELECT id FROM logs_email WHERE message_id=?", (message_id,)).fetchone()
    if existe:
        return jsonify({"status": "duplicate", "id": existe["id"]}), 200

    existe_hash = db.execute("""
        SELECT id, origem
        FROM logs_email
        WHERE UPPER(servidor_log)=? AND conteudo_hash=?
        LIMIT 1
    """, (servidor, conteudo_hash)).fetchone()
    if existe_hash:
        return jsonify({
            "status": "duplicate",
            "id": existe_hash["id"],
            "matched_by": "conteudo_hash",
            "origem": existe_hash["origem"],
        }), 200

    existe_servidor = db.execute("""
        SELECT id FROM servidores
        WHERE UPPER(nome_log)=?
    """, (servidor,)).fetchone()

    if not existe_servidor:
        ja_existe = db.execute("""
            SELECT 1
            FROM logs_nao_cadastrados
            WHERE UPPER(servidor_log)=?
        """, (servidor,)).fetchone()
        if not ja_existe:
            db.execute("""
                INSERT INTO logs_nao_cadastrados
                (servidor_log, data_email, message_id, subject, conteudo_raw)
                VALUES (?,?,?,?,?)
            """, (servidor, data_email, message_id, subject, body))
            db.commit()
        return jsonify({"status": "unknown_server", "servidor_log": servidor}), 202

    cur = db.execute("""
        INSERT INTO logs_email
        (servidor_log, data_email, status, conteudo_raw, message_id, subject, origem, conteudo_hash)
        VALUES (?,?,?,?,?,?,?,?)
    """, (servidor, data_email, status_backup, body, message_id, subject, origem, conteudo_hash))
    db.commit()

    return jsonify({
        "status": "created",
        "id": cur.lastrowid,
        "servidor_log": servidor,
        "backup_status": status_backup,
    }), 201


@app.route("/windows-events")
@login_required
@support_required
def windows_events():
    db = get_db()
    cliente_id = request.args.get("cliente_id", "").strip()
    event_id = request.args.get("event_id", "").strip()
    busca = request.args.get("q", "").strip()
    where = []
    params = []
    if cliente_id.isdigit():
        where.append("we.cliente_id=?")
        params.append(int(cliente_id))
    if event_id.isdigit():
        where.append("we.event_id=?")
        params.append(int(event_id))
    if busca:
        where.append("(UPPER(we.hostname) LIKE UPPER(?) OR UPPER(COALESCE(we.initiated_by,'')) LIKE UPPER(?) OR UPPER(COALESCE(we.message,'')) LIKE UPPER(?))")
        term = f"%{busca[:80]}%"
        params.extend([term, term, term])
    where_sql = " WHERE " + " AND ".join(where) if where else ""
    eventos = db.execute(f"""
        SELECT we.*, c.nome_exibicao, c.responsavel_nome,
               c.responsavel_email, c.alertar_eventos_windows
        FROM windows_events we
        JOIN clientes c ON c.id=we.cliente_id
        {where_sql}
        ORDER BY datetime(we.occurred_at) DESC, we.id DESC
        LIMIT 500
    """, params).fetchall()
    clientes = db.execute("""
        SELECT id, nome_exibicao FROM clientes WHERE ativo=1 ORDER BY nome_exibicao
    """).fetchall()
    resumo = db.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN event_id=1074 THEN 1 ELSE 0 END) AS planejados,
            SUM(CASE WHEN event_id IN (41,6008) THEN 1 ELSE 0 END) AS inesperados,
            COUNT(DISTINCT hostname) AS hosts
        FROM windows_events
        WHERE datetime(occurred_at) >= datetime('now', '-30 days')
    """).fetchone()
    db.close()
    return render_template(
        "windows_events.html",
        eventos=eventos,
        clientes=clientes,
        resumo=resumo,
        filtros={"cliente_id": cliente_id, "event_id": event_id, "q": busca},
        title="Eventos Windows",
    )


def normalizar_data_evento_windows(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            return datetime.strptime(text[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


@app.route("/api/agent/windows-events", methods=["POST"])
def agent_windows_events():
    if request.content_length and request.content_length > 1024 * 1024:
        return jsonify({"error": "payload too large"}), 413

    db = get_db()
    token = extrair_api_token()
    payload = ler_json_tolerante()
    servidor = normalizar_servidor(payload.get("servidor_log") or payload.get("servidor") or "")
    key = autenticar_api_key(db, token)
    if not key:
        key = recuperar_agent_api_key(db, token, servidor)
    if not key:
        return jsonify({"error": "unauthorized"}), 401

    servidor = normalizar_servidor(servidor or key["servidor_log"])
    if servidor:
        key = garantir_servidor_recuperado(db, key, servidor)
        if not api_key_autorizada_para_servidor(key, servidor, db):
            return jsonify({"error": "api key not allowed for this server"}), 403

    cliente_id = key["cliente_id"]
    if not cliente_id and servidor:
        servidor_row = db.execute("""
            SELECT cliente_id FROM servidores WHERE UPPER(nome_log)=UPPER(?) LIMIT 1
        """, (servidor,)).fetchone()
        cliente_id = servidor_row["cliente_id"] if servidor_row else None
    if not cliente_id:
        return jsonify({"error": "agent is not linked to a client"}), 422

    cliente = db.execute("SELECT id FROM clientes WHERE id=? AND ativo=1", (cliente_id,)).fetchone()
    if not cliente:
        return jsonify({"error": "client not found or inactive"}), 404

    hostname = str(payload.get("hostname") or "").strip()[:120]
    if not hostname:
        return jsonify({"error": "hostname is required"}), 400
    events = payload.get("events")
    if not isinstance(events, list):
        events = [payload.get("event") or payload]
    if len(events) > 100:
        return jsonify({"error": "maximum 100 events per request"}), 400

    accepted_ids = {41, 1074, 1076, 6006, 6008}
    created = 0
    duplicates = 0
    rejected = 0
    received_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for event in events:
        if not isinstance(event, dict):
            rejected += 1
            continue
        try:
            windows_event_id = int(event.get("event_id"))
        except (TypeError, ValueError):
            rejected += 1
            continue
        record_id = str(event.get("record_id") or "").strip()[:80]
        occurred_at = normalizar_data_evento_windows(event.get("occurred_at"))
        if windows_event_id not in accepted_ids or not record_id or not occurred_at:
            rejected += 1
            continue

        cur = db.execute("""
            INSERT INTO windows_events (
                cliente_id, servidor_log, api_key_id, hostname, channel,
                record_id, event_id, provider, level, event_type,
                occurred_at, received_at, initiated_by, process_name,
                reason_code, reason, comment, message, raw_json, is_historical
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cliente_id, hostname, channel, record_id) DO NOTHING
        """, (
            cliente_id,
            servidor or None,
            key["id"],
            hostname,
            str(event.get("channel") or "System")[:40],
            record_id,
            windows_event_id,
            str(event.get("provider") or "")[:120] or None,
            str(event.get("level") or "")[:40] or None,
            str(event.get("event_type") or "")[:60] or None,
            occurred_at,
            received_at,
            str(event.get("initiated_by") or "")[:240] or None,
            str(event.get("process_name") or "")[:500] or None,
            str(event.get("reason_code") or "")[:80] or None,
            str(event.get("reason") or "")[:500] or None,
            str(event.get("comment") or "")[:1000] or None,
            str(event.get("message") or "")[:6000] or None,
            json.dumps(event, ensure_ascii=False)[:12000],
            1 if event.get("is_historical") else 0,
        ))
        if cur.rowcount:
            created += 1
        else:
            duplicates += 1
    db.commit()

    return jsonify({
        "status": "ok",
        "created": created,
        "duplicates": duplicates,
        "rejected": rejected,
    })


@app.route("/api/agent/heartbeat", methods=["POST"])
def agent_heartbeat():
    db = get_db()
    token = extrair_api_token()
    payload = ler_json_tolerante()
    servidor_payload = normalizar_servidor(payload.get("servidor_log") or payload.get("servidor") or "")
    key = autenticar_api_key(db, token)
    if not key:
        key = recuperar_agent_api_key(db, token, servidor_payload)
    if not key:
        return jsonify({"error": "unauthorized"}), 401

    servidor = normalizar_servidor(servidor_payload or key["servidor_log"])

    if not servidor:
        return jsonify({"error": "servidor_log is required"}), 400

    key = garantir_servidor_recuperado(db, key, servidor)
    if not api_key_autorizada_para_servidor(key, servidor, db):
        return jsonify({
            "error": "api key not allowed for this server",
            "servidor_log": servidor,
            "api_key_id": key["id"],
            "api_key_cliente_id": key["cliente_id"],
            "api_key_servidor_log": key["servidor_log"],
        }), 403

    existe_servidor = db.execute("""
        SELECT id
        FROM servidores
        WHERE UPPER(nome_log)=?
    """, (servidor,)).fetchone()
    if not existe_servidor:
        return jsonify({"status": "unknown_server", "servidor_log": servidor}), 202

    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    metadata = payload.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {"raw": str(metadata)}

    db.execute("""
        INSERT INTO agent_heartbeats (
            servidor_log, api_key_id, hostname, ip_local, agent_version,
            status, detalhe, metadata_json, started_at, last_seen, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(servidor_log) DO UPDATE SET
            api_key_id=excluded.api_key_id,
            hostname=excluded.hostname,
            ip_local=excluded.ip_local,
            agent_version=excluded.agent_version,
            status=excluded.status,
            detalhe=excluded.detalhe,
            metadata_json=excluded.metadata_json,
            started_at=COALESCE(excluded.started_at, agent_heartbeats.started_at),
            last_seen=excluded.last_seen,
            updated_at=excluded.updated_at
    """, (
        servidor,
        key["id"],
        (payload.get("hostname") or "")[:120],
        (payload.get("ip_local") or "")[:80],
        (payload.get("agent_version") or "")[:40],
        (payload.get("status") or "online")[:30],
        (payload.get("detalhe") or "")[:500],
        json.dumps(metadata, ensure_ascii=False),
        payload.get("started_at"),
        agora,
        agora,
    ))
    db.execute("""
        INSERT INTO agent_heartbeat_history (
            servidor_log, api_key_id, hostname, ip_local, agent_version,
            status, detalhe, seen_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        servidor,
        key["id"],
        (payload.get("hostname") or "")[:120],
        (payload.get("ip_local") or "")[:80],
        (payload.get("agent_version") or "")[:40],
        (payload.get("status") or "online")[:30],
        (payload.get("detalhe") or "")[:500],
        agora,
    ))
    db.commit()

    return jsonify({
        "status": "ok",
        "servidor_log": servidor,
        "last_seen": agora,
        "next_heartbeat_seconds": 300,
        "agent_version": payload.get("agent_version") or "",
        "latest_agent_version": LATEST_AGENT_VERSION,
        "update_available": comparar_versao_agent(payload.get("agent_version"), LATEST_AGENT_VERSION) < 0,
        "update_url": AGENT_UPDATE_URL,
        "update_url_ws2012": AGENT_UPDATE_URL_WS2012,
        "update_sha256": agent_package_sha256("backup-monitor-agent.zip"),
        "update_sha256_ws2012": agent_package_sha256("backup-monitor-agent-legacy-ws2012.zip"),
        "update_setup_url": AGENT_SETUP_URL,
        "update_setup_url_ws2012": AGENT_SETUP_URL_WS2012,
    })


@app.route("/api/logs/exists", methods=["POST"])
def log_exists():
    db = get_db()
    token = extrair_api_token()
    payload = ler_json_tolerante()
    servidor_payload = normalizar_servidor(payload.get("servidor_log") or payload.get("servidor") or "")
    key = autenticar_api_key(db, token)
    if not key:
        key = recuperar_agent_api_key(db, token, servidor_payload)
    if not key:
        return jsonify({"error": "unauthorized"}), 401

    servidor = normalizar_servidor(servidor_payload or key["servidor_log"])

    if not servidor:
        return jsonify({"error": "servidor_log is required"}), 400

    key = garantir_servidor_recuperado(db, key, servidor)
    if not api_key_autorizada_para_servidor(key, servidor, db):
        return jsonify({
            "error": "api key not allowed for this server",
            "servidor_log": servidor,
            "api_key_id": key["id"],
            "api_key_cliente_id": key["cliente_id"],
            "api_key_servidor_log": key["servidor_log"],
        }), 403

    message_id = payload.get("message_id")
    conteudo_hash = payload.get("conteudo_hash")
    body = payload.get("conteudo_raw") or payload.get("body") or payload.get("log")
    if not conteudo_hash and body is not None:
        conteudo_hash = hash_conteudo(body)

    rows = []
    matched_by = None

    if message_id:
        rows = db.execute("""
            SELECT id, origem, status, data_email, subject
            FROM logs_email
            WHERE message_id=?
            LIMIT 5
        """, (message_id,)).fetchall()
        matched_by = "message_id" if rows else None

    if not rows and conteudo_hash:
        rows = db.execute("""
            SELECT id, origem, status, data_email, subject
            FROM logs_email
            WHERE UPPER(servidor_log)=? AND conteudo_hash=?
            ORDER BY id DESC
            LIMIT 5
        """, (servidor, conteudo_hash)).fetchall()
        matched_by = "conteudo_hash" if rows else None

    logs = [dict(row) for row in rows]
    return jsonify({
        "exists": bool(logs),
        "matched_by": matched_by,
        "logs": logs,
        "origens": sorted({(row.get("origem") or "email") for row in logs}),
    })


@app.route("/health")
def health():
    db = get_db()
    ultimo_worker = db.execute("""
        SELECT started_at, finished_at, status, detalhe
        FROM worker_runs
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 1
    """).fetchone()

    return jsonify({
        "status": "ok",
        "worker": dict(ultimo_worker) if ultimo_worker else None,
    })


# =========================
# CONFIG E-MAIL
# =========================

@app.route("/email-config")
@login_required
@admin_required
def email_config():

    db = get_db()
    config = db.execute("SELECT * FROM config_email LIMIT 1").fetchone()

    return render_template("email_config.html", config=config)


@app.route("/email-config/save", methods=["POST"])
@login_required
@admin_required
def save_email_config():

    imap_server = request.form["imap_server"]
    imap_port = request.form["imap_port"]
    email_user = request.form["email_user"]
    email_pass = request.form["email_pass"]
    pasta = request.form["pasta"]
    usar_ssl = 1 if request.form.get("usar_ssl") else 0

    db = get_db()

    db.execute("DELETE FROM config_email")

    db.execute("""
        INSERT INTO config_email
        (imap_server, imap_port, email_user, email_pass, pasta, usar_ssl)
        VALUES (?,?,?,?,?,?)
    """, (
        imap_server,
        imap_port,
        email_user,
        email_pass,
        pasta,
        usar_ssl
    ))

    db.commit()

    return redirect("/email-config")

@app.route("/agendamento/add/<int:servidor_id>", methods=["POST"])
@login_required
@admin_required
def add_agendamento(servidor_id):

    db = get_db()

    dias_execucao = ",".join(request.form.getlist("dias_execucao"))
    hora_execucao = request.form.get("hora_execucao")
    tolerancia_min = request.form.get("tolerancia_min", 120)

    db.execute("""
        INSERT INTO agendamentos_backup
        (servidor_id, dias_execucao, hora_execucao, tolerancia_min, ativo)
        VALUES (?,?,?,?,1)
    """, (
        servidor_id,
        dias_execucao,
        hora_execucao,
        tolerancia_min
    ))

    db.commit()

    return redirect(f"/servidores/editar/{servidor_id}")

@app.route("/agendamento/update/<int:ag_id>", methods=["POST"])
@login_required
@admin_required
def update_agendamento(ag_id):

    db = get_db()

    dias_execucao = ",".join(request.form.getlist("dias_execucao"))
    hora_execucao = request.form.get("hora_execucao")
    tolerancia_min = request.form.get("tolerancia_min", 120)

    servidor_id = db.execute("""
        SELECT servidor_id FROM agendamentos_backup
        WHERE id=?
    """, (ag_id,)).fetchone()["servidor_id"]

    db.execute("""
        UPDATE agendamentos_backup
        SET dias_execucao=?,
            hora_execucao=?,
            tolerancia_min=?
        WHERE id=?
    """, (
        dias_execucao,
        hora_execucao,
        tolerancia_min,
        ag_id
    ))

    db.commit()

    return redirect(f"/servidores/editar/{servidor_id}")

@app.route("/agendamento/delete/<int:ag_id>/<int:servidor_id>")
@login_required
@admin_required
def delete_agendamento(ag_id, servidor_id):

    db = get_db()

    db.execute("""
        DELETE FROM agendamentos_backup
        WHERE id=?
    """, (ag_id,))

    db.commit()

    return redirect(f"/servidores/editar/{servidor_id}")


# =========================
# PFSENSE AGENT
# =========================

def pfsense_form_values(form, require_username=True):
    name = (form.get("name") or "").strip()
    address = (form.get("address") or "").strip()
    username = (form.get("username") or "").strip()
    auth_type = (form.get("auth_type") or "password").strip()
    fingerprint = (form.get("host_key_fingerprint") or "").strip()
    if not name or not address or (require_username and not username):
        raise ValueError("Nome, endereco e usuario sao obrigatorios.")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", address):
        raise ValueError("Endereco invalido.")
    if auth_type not in ("ssh_key", "password"):
        raise ValueError("Metodo de autenticacao invalido.")
    if fingerprint and not fingerprint.startswith("SHA256:"):
        raise ValueError("Informe o fingerprint SHA256 da chave SSH do pfSense.")
    port = int(form.get("ssh_port") or 22)
    if not 1 <= port <= 65535:
        raise ValueError("Porta SSH invalida.")
    return {
        "name": name,
        "address": address,
        "ssh_port": port,
        "username": username,
        "auth_type": auth_type,
        "host_key_fingerprint": fingerprint,
        "monitor_interval_minutes": max(1, min(1440, int(form.get("monitor_interval_minutes") or 5))),
        "backup_interval_hours": max(1, min(720, int(form.get("backup_interval_hours") or 24))),
        "backup_retention_days": max(1, min(3650, int(form.get("backup_retention_days") or 30))),
        "speedtest_enabled": 1 if form.get("speedtest_enabled") else 0,
        "speedtest_interval_hours": max(1, min(168, int(form.get("speedtest_interval_hours") or 6))),
        "active": 1 if form.get("active") else 0,
    }


def pfsense_link_form_values(form):
    name = (form.get("name") or "").strip()
    provider = (form.get("provider") or "").strip()
    link_type = (form.get("link_type") or "broadband").strip()
    interface_key = (form.get("interface_key") or "").strip()
    device_name = (form.get("device_name") or "").strip()
    gateway_name = (form.get("gateway_name") or "").strip()
    if not name or not provider or not interface_key or not device_name:
        raise ValueError("Nome, operadora, interface e dispositivo sao obrigatorios.")
    if link_type not in ("dedicated", "broadband"):
        raise ValueError("Tipo de link invalido.")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface_key) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", device_name):
        raise ValueError("Interface WAN invalida.")
    down = float(form.get("contracted_down_mbps") or 0)
    up = float(form.get("contracted_up_mbps") or 0)
    if down <= 0 or up <= 0 or down > 100000 or up > 100000:
        raise ValueError("Informe download e upload contratados em Mbps.")
    return {
        "name": name, "provider": provider, "link_type": link_type,
        "interface_key": interface_key, "device_name": device_name,
        "gateway_name": gateway_name, "contracted_down_mbps": down,
        "contracted_up_mbps": up,
        "minimum_delivery_percent": max(1, min(100, int(form.get("minimum_delivery_percent") or 80))),
        "active": 1 if form.get("active") else 0,
        "probe_enabled": 1 if form.get("probe_enabled") else 0,
        "probe_interval_minutes": max(1, min(1440, int(form.get("probe_interval_minutes") or 5))),
        "speedtest_enabled": 1 if form.get("speedtest_enabled") else 0,
        "speedtest_interval_hours": max(1, min(168, int(form.get("speedtest_interval_hours") or 6))),
    }


def montar_relatorio_links(db, firewall_id, days):
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    links = []
    for row in db.execute(
        "SELECT * FROM pfsense_links WHERE firewall_id=? AND active=1 ORDER BY name",
        (firewall_id,),
    ).fetchall():
        link = dict(row)
        probes = db.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='online' THEN 1 ELSE 0 END) AS online,
                   AVG(CASE WHEN status='online' THEN latency_ms END) AS latency_avg,
                   AVG(CASE WHEN status='online' THEN packet_loss_percent END) AS loss_avg
            FROM pfsense_link_probes WHERE link_id=? AND datetime(probed_at)>=datetime(?)
            """,
            (link["id"], since),
        ).fetchone()
        speeds = db.execute(
            """
            SELECT COUNT(*) AS total,
                   AVG(download_mbps) AS download_avg, MIN(download_mbps) AS download_min,
                   MAX(download_mbps) AS download_max, AVG(upload_mbps) AS upload_avg,
                   MIN(upload_mbps) AS upload_min, MAX(upload_mbps) AS upload_max,
                   AVG(ping_ms) AS ping_avg, AVG(delivered_down_percent) AS delivery_down_avg,
                   AVG(delivered_up_percent) AS delivery_up_avg
            FROM pfsense_link_speedtests
            WHERE link_id=? AND status='success' AND datetime(tested_at)>=datetime(?)
            """,
            (link["id"], since),
        ).fetchone()
        probe_total = int(probes["total"] or 0)
        probe_online = int(probes["online"] or 0)
        availability = round(probe_online * 100.0 / probe_total, 2) if probe_total else None
        delivery_values = [
            float(value) for value in (speeds["delivery_down_avg"], speeds["delivery_up_avg"])
            if value is not None
        ]
        delivery = min(delivery_values) if delivery_values else None
        latency = float(probes["latency_avg"]) if probes["latency_avg"] is not None else None
        components = []
        weights = []
        if availability is not None:
            components.append(min(100, availability) * 0.5); weights.append(0.5)
        if delivery is not None:
            components.append(min(100, delivery) * 0.35); weights.append(0.35)
        if latency is not None:
            components.append(max(0, 100 - latency) * 0.15); weights.append(0.15)
        score = round(sum(components) / sum(weights), 1) if weights else None
        diagnostics = []
        if not link["contracted_down_mbps"] or not link["contracted_up_mbps"]:
            diagnostics.append("Preencha a velocidade contratada para calcular a entrega do provedor.")
        if availability is None:
            diagnostics.append("Ainda nao ha sondas suficientes para medir disponibilidade.")
        elif availability < 99:
            diagnostics.append(f"Disponibilidade de {availability:.2f}% no periodo, abaixo de 99%.")
        if delivery is not None and delivery < float(link["minimum_delivery_percent"] or 80):
            diagnostics.append(
                f"Entrega media minima de {delivery:.1f}% do contratado, abaixo do limite de {link['minimum_delivery_percent']}%."
            )
        if speeds["ping_avg"] is not None and float(speeds["ping_avg"]) > 80:
            diagnostics.append(f"Ping medio elevado nos speedtests: {float(speeds['ping_avg']):.1f} ms.")
        if probes["loss_avg"] is not None and float(probes["loss_avg"]) > 5:
            diagnostics.append(
                f"Perda/bloqueio medio de ICMP em {float(probes['loss_avg']):.1f}%; a disponibilidade HTTPS e avaliada separadamente."
            )
        if not diagnostics:
            diagnostics.append("Link dentro dos parametros cadastrados no periodo analisado.")
        link.update({
            "probe_total": probe_total, "probe_online": probe_online,
            "availability": availability,
            "latency_avg": round(latency, 2) if latency is not None else None,
            "loss_avg": round(float(probes["loss_avg"]), 2) if probes["loss_avg"] is not None else None,
            "speed_total": int(speeds["total"] or 0),
            "download_avg": round(float(speeds["download_avg"]), 2) if speeds["download_avg"] is not None else None,
            "download_min": round(float(speeds["download_min"]), 2) if speeds["download_min"] is not None else None,
            "download_max": round(float(speeds["download_max"]), 2) if speeds["download_max"] is not None else None,
            "upload_avg": round(float(speeds["upload_avg"]), 2) if speeds["upload_avg"] is not None else None,
            "upload_min": round(float(speeds["upload_min"]), 2) if speeds["upload_min"] is not None else None,
            "upload_max": round(float(speeds["upload_max"]), 2) if speeds["upload_max"] is not None else None,
            "ping_avg": round(float(speeds["ping_avg"]), 2) if speeds["ping_avg"] is not None else None,
            "delivery_down_avg": round(float(speeds["delivery_down_avg"]), 2) if speeds["delivery_down_avg"] is not None else None,
            "delivery_up_avg": round(float(speeds["delivery_up_avg"]), 2) if speeds["delivery_up_avg"] is not None else None,
            "score": score, "diagnostics": diagnostics,
        })
        links.append(link)
    links.sort(key=lambda item: (-1 if item["score"] is None else -item["score"], item["name"]))
    best = next((link for link in links if link["score"] is not None), None)
    return links, best


@app.route("/pfsense")
@login_required
def pfsense_list():
    db = get_db()
    rows = db.execute("""
        WITH latest_checks AS (
            SELECT pc.*, ROW_NUMBER() OVER (PARTITION BY firewall_id ORDER BY id DESC) AS rn
            FROM pfsense_checks pc
        ), backup_counts AS (
            SELECT firewall_id, COUNT(*) AS total
            FROM pfsense_backups WHERE status='success' GROUP BY firewall_id
        )
        SELECT f.*, lc.latency_ms, lc.version, lc.hostname, lc.disk_percent,
               lc.interfaces_total, lc.interfaces_up, COALESCE(bc.total,0) AS backup_count
        FROM pfsense_firewalls f
        LEFT JOIN latest_checks lc ON lc.firewall_id=f.id AND lc.rn=1
        LEFT JOIN backup_counts bc ON bc.firewall_id=f.id
        ORDER BY f.active DESC, f.name
    """).fetchall()
    firewalls = [dict(row) for row in rows]
    summary = {
        "total": sum(1 for item in firewalls if item["active"]),
        "online": sum(1 for item in firewalls if item["active"] and item["last_status"] == "online"),
        "error": sum(1 for item in firewalls if item["active"] and item["last_status"] == "error"),
        "waiting": sum(1 for item in firewalls if item["active"] and not item["last_status"]),
        "backups": sum(int(item["backup_count"] or 0) for item in firewalls),
    }
    links_summary = db.execute("""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN last_probe_status='online' THEN 1 ELSE 0 END) AS online,
               SUM(CASE WHEN last_probe_status IN ('offline','error') THEN 1 ELSE 0 END) AS error,
               SUM(CASE WHEN contracted_down_mbps IS NULL OR contracted_up_mbps IS NULL THEN 1 ELSE 0 END) AS incomplete
        FROM pfsense_links WHERE active=1
    """).fetchone()
    storage_row = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
    storage = dict(storage_row) if storage_row else None
    if storage:
        storage.pop("username_enc", None)
        storage.pop("password_enc", None)
    db.close()
    return render_template(
        "pfsense_list.html", firewalls=firewalls, storage=storage, summary=summary,
        links_summary=links_summary, message=request.args.get("message"), title="pfSense e Internet",
    )


@app.route("/pfsense/storage", methods=["GET", "POST"])
@login_required
@admin_required
def pfsense_storage_settings():
    db = get_db()
    try:
        current_row = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
        current = dict(current_row) if current_row else None
        if request.method == "POST":
            protocol = (request.form.get("protocol") or "ftps").lower()
            if protocol not in ("ftps", "ftp"):
                raise ValueError("Protocolo invalido.")
            host = (request.form.get("host") or "").strip()
            if not host or len(host) > 255 or any(char.isspace() for char in host):
                raise ValueError("Informe um endereco FTP valido.")
            port = int(request.form.get("port") or 21)
            if port < 1 or port > 65535:
                raise ValueError("Porta FTP invalida.")
            username = request.form.get("username") or ""
            password = request.form.get("password") or ""
            username_enc = current["username_enc"] if current and not username else encrypt_secret(username)
            password_enc = current["password_enc"] if current and not password else encrypt_secret(password)
            if not username_enc or not password_enc:
                raise ValueError("Usuario e senha FTP sao obrigatorios.")
            remote_dir = normalize_remote_dir(request.form.get("remote_dir"))
            retention_days = int(request.form.get("retention_days") or 90)
            if retention_days < 1 or retention_days > 3650:
                raise ValueError("A retencao FTP deve ficar entre 1 e 3650 dias.")
            now = agora_sql()
            db.execute(
                """
                INSERT INTO pfsense_storage
                    (id, protocol, host, port, username_enc, password_enc, remote_dir,
                     passive, verify_tls, active, retention_enabled, retention_days,
                     created_at, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    protocol=excluded.protocol, host=excluded.host, port=excluded.port,
                    username_enc=excluded.username_enc, password_enc=excluded.password_enc,
                    remote_dir=excluded.remote_dir, passive=excluded.passive,
                    verify_tls=excluded.verify_tls, active=excluded.active,
                    retention_enabled=excluded.retention_enabled,
                    retention_days=excluded.retention_days,
                    last_status=NULL, last_error=NULL, updated_at=excluded.updated_at
                """,
                (
                    protocol, host, port, username_enc, password_enc, remote_dir,
                    1 if request.form.get("passive") else 0,
                    1 if request.form.get("verify_tls") else 0,
                    1 if request.form.get("active") else 0,
                    1 if request.form.get("retention_enabled") else 0,
                    retention_days, now, now,
                ),
            )
            db.commit()
            return redirect("/pfsense/storage?message=Armazenamento+salvo.+Execute+o+teste+de+conexao.")
        if current:
            current["has_username"] = bool(current.pop("username_enc", None))
            current["has_password"] = bool(current.pop("password_enc", None))
        return render_template(
            "pfsense_storage.html", storage=current, error=None,
            message=request.args.get("message"),
        )
    except Exception as exc:
        db.rollback()
        submitted = {
            "protocol": request.form.get("protocol") or "ftps",
            "host": request.form.get("host") or "",
            "port": request.form.get("port") or 21,
            "remote_dir": request.form.get("remote_dir") or "/pfsense-backups",
            "passive": bool(request.form.get("passive")),
            "verify_tls": bool(request.form.get("verify_tls")),
            "active": bool(request.form.get("active")),
            "retention_enabled": bool(request.form.get("retention_enabled")),
            "retention_days": request.form.get("retention_days") or 90,
            "has_username": bool(current and current.get("username_enc")),
            "has_password": bool(current and current.get("password_enc")),
        }
        return render_template("pfsense_storage.html", storage=submitted, error=str(exc), message=None), 400
    finally:
        db.close()


@app.route("/pfsense/storage/test", methods=["POST"])
@login_required
@admin_required
def pfsense_storage_test():
    db = get_db()
    try:
        storage = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
        if not storage:
            return redirect("/pfsense/storage?message=Salve+a+configuracao+antes+do+teste.")
        result = test_storage_connection(storage)
        now = agora_sql()
        db.execute(
            "UPDATE pfsense_storage SET last_test_at=?, last_status=?, last_error=?, updated_at=? WHERE id=1",
            (now, result["status"], result.get("error"), now),
        )
        db.commit()
        message = "Conexao+FTP+testada+com+sucesso." if result["status"] == "success" else "Falha+no+teste+FTP.+Consulte+o+erro."
        return redirect(f"/pfsense/storage?message={message}")
    finally:
        db.close()


@app.route("/pfsense/storage/cleanup", methods=["POST"])
@login_required
@admin_required
def pfsense_storage_cleanup():
    db = get_db()
    try:
        result = cleanup_storage(db, force=True)
        db.commit()
        if result["status"] == "success":
            message = f"Limpeza+FTP+concluida.+{result.get('deleted', 0)}+arquivo(s)+removido(s)."
        elif result["status"] == "disabled":
            message = "Retencao+FTP+desativada."
        else:
            message = "Falha+na+limpeza+FTP.+Consulte+o+erro."
        return redirect(f"/pfsense/storage?message={message}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@app.route("/pfsense/new")
@login_required
@admin_required
def pfsense_new():
    return render_template("pfsense_form.html", firewall=None, error=None)


@app.route("/pfsense/add", methods=["POST"])
@login_required
@admin_required
def pfsense_add():
    try:
        values = pfsense_form_values(request.form)
        password = request.form.get("password") or ""
        private_key = request.form.get("private_key") or ""
        if values["auth_type"] == "ssh_key" and not private_key.strip():
            raise ValueError("A chave privada SSH e obrigatoria.")
        if values["auth_type"] == "password" and not password:
            raise ValueError("A senha SSH e obrigatoria.")
        if not values["host_key_fingerprint"]:
            from worker.pfsense_agent import discover_host_key_fingerprint
            values["host_key_fingerprint"] = discover_host_key_fingerprint(
                values["address"], values["ssh_port"]
            )
        db = get_db()
        db.execute(
            """
            INSERT INTO pfsense_firewalls
                (name, address, ssh_port, username_enc, password_enc, private_key_enc,
                 auth_type, host_key_fingerprint, active, monitor_interval_minutes,
                 backup_interval_hours, backup_retention_days, speedtest_enabled,
                 speedtest_interval_hours, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                values["name"], values["address"], values["ssh_port"],
                encrypt_secret(values["username"]), encrypt_secret(password),
                encrypt_secret(private_key), values["auth_type"],
                values["host_key_fingerprint"], values["active"],
                values["monitor_interval_minutes"], values["backup_interval_hours"],
                values["backup_retention_days"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], agora_sql(), agora_sql(),
            ),
        )
        db.commit()
        db.close()
        return redirect("/pfsense?message=Firewall+cadastrado.+Execute+Testar+agora.")
    except Exception as exc:
        return render_template("pfsense_form.html", firewall=None, error=str(exc)), 400


@app.route("/pfsense/<int:firewall_id>")
@login_required
def pfsense_detail(firewall_id):
    db = get_db()
    firewall = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    if not firewall:
        db.close()
        return "Firewall nao encontrado", 404
    checks = db.execute(
        "SELECT * FROM pfsense_checks WHERE firewall_id=? ORDER BY id DESC LIMIT 100",
        (firewall_id,),
    ).fetchall()
    backups = db.execute(
        "SELECT * FROM pfsense_backups WHERE firewall_id=? ORDER BY id DESC LIMIT 100",
        (firewall_id,),
    ).fetchall()
    speedtests = db.execute(
        "SELECT * FROM pfsense_speedtests WHERE firewall_id=? ORDER BY id DESC LIMIT 100",
        (firewall_id,),
    ).fetchall()
    links = []
    for link_row in db.execute(
        "SELECT * FROM pfsense_links WHERE firewall_id=? ORDER BY name", (firewall_id,)
    ).fetchall():
        link = dict(link_row)
        link["latest_probe"] = db.execute(
            "SELECT * FROM pfsense_link_probes WHERE link_id=? ORDER BY id DESC LIMIT 1",
            (link["id"],),
        ).fetchone()
        link["latest_speedtest"] = db.execute(
            "SELECT * FROM pfsense_link_speedtests WHERE link_id=? ORDER BY id DESC LIMIT 1",
            (link["id"],),
        ).fetchone()
        links.append(link)
    latest_metrics = {}
    if checks and checks[0]["metrics_json"]:
        try:
            latest_metrics = json.loads(checks[0]["metrics_json"])
        except (TypeError, ValueError):
            pass
    latest_metrics = enriquecer_uptime_pfsense(
        latest_metrics, checks[0]["checked_at"] if checks else None
    )
    result = dict(firewall)
    result["has_password"] = bool(result.pop("password_enc", None))
    result["has_private_key"] = bool(result.pop("private_key_enc", None))
    result.pop("username_enc", None)
    db.close()
    return render_template(
        "pfsense_detail.html", firewall=result, checks=checks, backups=backups,
        speedtests=speedtests, latest_speedtest=speedtests[0] if speedtests else None,
        links=links,
        metrics=latest_metrics, message=request.args.get("message"),
    )


@app.route("/pfsense/<int:firewall_id>/links/discover", methods=["POST"])
@login_required
@admin_required
def pfsense_links_discover(firewall_id):
    db = get_db()
    firewall = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not firewall:
        return "Firewall nao encontrado", 404
    from worker.pfsense_links import sync_discovered_links
    result = sync_discovered_links(dict(firewall))
    return redirect(
        f"/pfsense/{firewall_id}?message={result['found']}+interfaces+WAN+encontradas.+{result['created']}+adicionadas."
    )


@app.route("/pfsense/<int:firewall_id>/links/new")
@login_required
@admin_required
def pfsense_link_new(firewall_id):
    db = get_db()
    firewall = db.execute("SELECT id, name FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not firewall:
        return "Firewall nao encontrado", 404
    return render_template("pfsense_link_form.html", firewall=firewall, link=None, error=None)


@app.route("/pfsense/<int:firewall_id>/links/add", methods=["POST"])
@login_required
@admin_required
def pfsense_link_add(firewall_id):
    try:
        values = pfsense_link_form_values(request.form)
        now = agora_sql()
        db = get_db()
        db.execute(
            """
            INSERT INTO pfsense_links
                (firewall_id, name, provider, link_type, interface_key, device_name,
                 gateway_name, contracted_down_mbps, contracted_up_mbps,
                 minimum_delivery_percent, active, probe_enabled, probe_interval_minutes,
                 speedtest_enabled, speedtest_interval_hours, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                firewall_id, values["name"], values["provider"], values["link_type"],
                values["interface_key"], values["device_name"], values["gateway_name"],
                values["contracted_down_mbps"], values["contracted_up_mbps"],
                values["minimum_delivery_percent"], values["active"], values["probe_enabled"],
                values["probe_interval_minutes"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], now, now,
            ),
        )
        db.commit()
        db.close()
        return redirect(f"/pfsense/{firewall_id}?message=Link+de+Internet+cadastrado.")
    except Exception as exc:
        return render_template("pfsense_link_form.html", firewall={"id": firewall_id}, link=None, error=str(exc)), 400


@app.route("/pfsense/<int:firewall_id>/links/<int:link_id>/edit")
@login_required
@admin_required
def pfsense_link_edit(firewall_id, link_id):
    db = get_db()
    firewall = db.execute("SELECT id, name FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    link = db.execute("SELECT * FROM pfsense_links WHERE id=? AND firewall_id=?", (link_id, firewall_id)).fetchone()
    db.close()
    if not firewall or not link:
        return "Link nao encontrado", 404
    return render_template("pfsense_link_form.html", firewall=firewall, link=link, error=None)


@app.route("/pfsense/<int:firewall_id>/links/<int:link_id>/update", methods=["POST"])
@login_required
@admin_required
def pfsense_link_update(firewall_id, link_id):
    try:
        values = pfsense_link_form_values(request.form)
        db = get_db()
        db.execute(
            """
            UPDATE pfsense_links SET name=?, provider=?, link_type=?, interface_key=?,
                device_name=?, gateway_name=?, contracted_down_mbps=?, contracted_up_mbps=?,
                minimum_delivery_percent=?, active=?, probe_enabled=?, probe_interval_minutes=?,
                speedtest_enabled=?, speedtest_interval_hours=?, updated_at=?
            WHERE id=? AND firewall_id=?
            """,
            (
                values["name"], values["provider"], values["link_type"],
                values["interface_key"], values["device_name"], values["gateway_name"],
                values["contracted_down_mbps"], values["contracted_up_mbps"],
                values["minimum_delivery_percent"], values["active"], values["probe_enabled"],
                values["probe_interval_minutes"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], agora_sql(), link_id, firewall_id,
            ),
        )
        db.execute(
            """
            UPDATE pfsense_link_speedtests
            SET delivered_down_percent=CASE
                    WHEN ? IS NOT NULL AND ? > 0
                    THEN ROUND(CAST(download_mbps * 100.0 / ? AS NUMERIC), 2)
                    ELSE NULL
                END,
                delivered_up_percent=CASE
                    WHEN ? IS NOT NULL AND ? > 0
                    THEN ROUND(CAST(upload_mbps * 100.0 / ? AS NUMERIC), 2)
                    ELSE NULL
                END
            WHERE link_id=? AND status='success'
            """,
            (
                values["contracted_down_mbps"], values["contracted_down_mbps"],
                values["contracted_down_mbps"], values["contracted_up_mbps"],
                values["contracted_up_mbps"], values["contracted_up_mbps"], link_id,
            ),
        )
        db.commit()
        db.close()
        return redirect(f"/pfsense/{firewall_id}?message=Link+atualizado.")
    except Exception as exc:
        return render_template(
            "pfsense_link_form.html", firewall={"id": firewall_id},
            link={"id": link_id}, error=str(exc),
        ), 400


@app.route("/pfsense/<int:firewall_id>/links/<int:link_id>/probe", methods=["POST"])
@login_required
@admin_required
def pfsense_link_probe_now(firewall_id, link_id):
    db = get_db()
    link = db.execute("SELECT * FROM pfsense_links WHERE id=? AND firewall_id=?", (link_id, firewall_id)).fetchone()
    if not link:
        db.close()
        return "Link nao encontrado", 404
    now = agora_sql()
    db.execute(
        "UPDATE pfsense_links SET probe_requested_at=?, last_probe_status='queued', updated_at=? WHERE id=?",
        (now, now, link_id),
    )
    db.commit()
    db.close()
    return redirect(f"/pfsense/{firewall_id}?message=Sonda+solicitada.+O+resultado+aparecera+em+instantes.")


@app.route("/pfsense/<int:firewall_id>/links/<int:link_id>/speedtest", methods=["POST"])
@login_required
@admin_required
def pfsense_link_speedtest_now(firewall_id, link_id):
    db = get_db()
    link = db.execute("SELECT * FROM pfsense_links WHERE id=? AND firewall_id=?", (link_id, firewall_id)).fetchone()
    if not link:
        db.close()
        return "Link nao encontrado", 404
    now = agora_sql()
    db.execute(
        "UPDATE pfsense_links SET speedtest_requested_at=?, last_speedtest_status='queued', updated_at=? WHERE id=?",
        (now, now, link_id),
    )
    db.commit()
    db.close()
    return redirect(f"/pfsense/{firewall_id}?message=Speedtest+solicitado.+O+resultado+aparecera+em+instantes.")


@app.route("/pfsense/<int:firewall_id>/internet-report")
@login_required
def pfsense_internet_report(firewall_id):
    try:
        days = int(request.args.get("days") or 30)
    except ValueError:
        days = 30
    if days not in (7, 30, 90):
        days = 30
    db = get_db()
    firewall = db.execute("SELECT id, name, address FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    if not firewall:
        db.close()
        return "Firewall nao encontrado", 404
    links, best = montar_relatorio_links(db, firewall_id, days)
    db.close()
    html = render_template(
        "pfsense_internet_report.html", firewall=firewall, links=links, best=best,
        days=days, generated_at=agora_sql(),
    )
    if request.args.get("download"):
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", firewall["name"]).strip("-") or "pfsense"
        return Response(
            html, mimetype="text/html",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}-internet-{days}d.html"'},
        )
    return html


@app.route("/pfsense/<int:firewall_id>/edit")
@login_required
@admin_required
def pfsense_edit(firewall_id):
    db = get_db()
    row = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not row:
        return "Firewall nao encontrado", 404
    firewall = dict(row)
    firewall["has_password"] = bool(firewall.pop("password_enc", None))
    firewall["has_private_key"] = bool(firewall.pop("private_key_enc", None))
    firewall.pop("username_enc", None)
    return render_template("pfsense_form.html", firewall=firewall, error=None)


@app.route("/pfsense/<int:firewall_id>/update", methods=["POST"])
@login_required
@admin_required
def pfsense_update(firewall_id):
    try:
        values = pfsense_form_values(request.form)
        db = get_db()
        current = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
        if not current:
            db.close()
            return "Firewall nao encontrado", 404
        password_enc = current["password_enc"]
        private_key_enc = current["private_key_enc"]
        if request.form.get("password"):
            password_enc = encrypt_secret(request.form.get("password"))
        if request.form.get("private_key", "").strip():
            private_key_enc = encrypt_secret(request.form.get("private_key"))
        if values["auth_type"] == "ssh_key" and not private_key_enc:
            raise ValueError("A chave privada SSH e obrigatoria.")
        if values["auth_type"] == "password" and not password_enc:
            raise ValueError("A senha SSH e obrigatoria.")
        if not values["host_key_fingerprint"]:
            values["host_key_fingerprint"] = current["host_key_fingerprint"]
        if not values["host_key_fingerprint"]:
            from worker.pfsense_agent import discover_host_key_fingerprint
            values["host_key_fingerprint"] = discover_host_key_fingerprint(
                values["address"], values["ssh_port"]
            )
        db.execute(
            """
            UPDATE pfsense_firewalls
            SET name=?, address=?, ssh_port=?, username_enc=?, password_enc=?, private_key_enc=?,
                auth_type=?, host_key_fingerprint=?, active=?, monitor_interval_minutes=?,
                backup_interval_hours=?, backup_retention_days=?, speedtest_enabled=?,
                speedtest_interval_hours=?, updated_at=?
            WHERE id=?
            """,
            (
                values["name"], values["address"], values["ssh_port"],
                encrypt_secret(values["username"]) if values["username"] else current["username_enc"],
                password_enc, private_key_enc,
                values["auth_type"], values["host_key_fingerprint"], values["active"],
                values["monitor_interval_minutes"], values["backup_interval_hours"],
                values["backup_retention_days"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], agora_sql(), firewall_id,
            ),
        )
        db.commit()
        db.close()
        return redirect(f"/pfsense/{firewall_id}?message=Cadastro+atualizado.")
    except Exception as exc:
        return render_template("pfsense_form.html", firewall={"id": firewall_id}, error=str(exc)), 400


@app.route("/pfsense/<int:firewall_id>/check", methods=["POST"])
@login_required
@admin_required
def pfsense_check_now(firewall_id):
    db = get_db()
    row = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not row:
        return "Firewall nao encontrado", 404
    from worker.pfsense_agent import run_firewall_check
    result = run_firewall_check(dict(row), force_backup=bool(request.form.get("backup")))
    message = "Teste+concluido." if result["status"] == "online" else "Teste+falhou.+Consulte+o+erro."
    return redirect(f"/pfsense/{firewall_id}?message={message}")


@app.route("/pfsense/<int:firewall_id>/speedtest", methods=["POST"])
@login_required
@admin_required
def pfsense_speedtest_now(firewall_id):
    db = get_db()
    row = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    if not row:
        db.close()
        return "Firewall nao encontrado", 404
    now = agora_sql()
    db.execute(
        "UPDATE pfsense_firewalls SET speedtest_requested_at=?, last_speedtest_status='queued', updated_at=? WHERE id=?",
        (now, now, firewall_id),
    )
    db.commit()
    db.close()
    return redirect(f"/pfsense/{firewall_id}?message=Teste+de+velocidade+solicitado.+O+resultado+aparecera+em+instantes.")


@app.route("/pfsense/<int:firewall_id>/toggle", methods=["POST"])
@login_required
@admin_required
def pfsense_toggle(firewall_id):
    db = get_db()
    db.execute(
        "UPDATE pfsense_firewalls SET active=CASE WHEN active=1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?",
        (agora_sql(), firewall_id),
    )
    db.commit()
    db.close()
    return redirect("/pfsense")


@app.route("/pfsense/<int:firewall_id>/backups/<int:backup_id>/upload", methods=["POST"])
@login_required
@admin_required
def pfsense_backup_upload(firewall_id, backup_id):
    db = get_db()
    try:
        backup = db.execute(
            "SELECT * FROM pfsense_backups WHERE id=? AND firewall_id=? AND status='success'",
            (backup_id, firewall_id),
        ).fetchone()
        firewall = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
        if not backup or not firewall:
            return "Backup nao encontrado", 404
        path = Path(backup["file_path"] or "")
        backup_root = Path(os.getenv("PFSENSE_BACKUP_DIR", "/data/pfsense-backups"))
        if not path.is_file() or backup_root not in path.parents:
            return "Arquivo de backup indisponivel", 404
        result = upload_backup_from_db(db, firewall, path)
        error = result.get("error")
        if result["status"] == "disabled":
            error = "Armazenamento FTP desativado ou nao configurado."
        db.execute(
            """
            UPDATE pfsense_backups
            SET remote_status=?, remote_path=?, remote_uploaded_at=?, remote_error=?
            WHERE id=? AND firewall_id=?
            """,
            (
                result["status"], result.get("remote_path"), result.get("uploaded_at"),
                error, backup_id, firewall_id,
            ),
        )
        db.commit()
        message = "Backup+enviado+ao+FTP." if result["status"] == "success" else "Falha+no+envio+FTP.+Consulte+o+status."
        return redirect(f"/pfsense/{firewall_id}?message={message}")
    finally:
        db.close()


@app.route("/pfsense/<int:firewall_id>/backups/<int:backup_id>/download")
@login_required
@admin_required
def pfsense_backup_download(firewall_id, backup_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM pfsense_backups WHERE id=? AND firewall_id=? AND status='success'",
        (backup_id, firewall_id),
    ).fetchone()
    firewall = db.execute("SELECT name FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not row or not firewall:
        return "Backup nao encontrado", 404
    path = Path(row["file_path"] or "")
    backup_root = Path(os.getenv("PFSENSE_BACKUP_DIR", "/data/pfsense-backups"))
    if not path.is_file() or backup_root not in path.parents:
        return "Arquivo de backup indisponivel", 404
    plaintext = decrypt_backup(path.read_bytes())
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", firewall["name"]).strip("-") or "pfsense"
    timestamp = re.sub(r"[^0-9]", "", row["created_at"] or "")[:14]
    return send_file(
        io.BytesIO(plaintext), mimetype="application/xml", as_attachment=True,
        download_name=f"{safe_name}-{timestamp}.config.xml",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
