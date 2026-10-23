"""API dos agentes Windows e dos coletores: ingestao de logs, eventos do Windows, batimento e consulta de log."""
import hashlib
import json
from datetime import datetime

from flask import Blueprint, jsonify, request

from agentes import AGENT_SETUP_URL, AGENT_SETUP_URL_WS2012, AGENT_UPDATE_URL, AGENT_UPDATE_URL_WS2012, LATEST_AGENT_VERSION, agent_package_sha256, api_key_autorizada_para_servidor, autenticar_api_key, comparar_versao_agent, detectar_status_log, extrair_api_token, garantir_servidor_recuperado, ler_json_tolerante, normalizar_data_evento_windows, recuperar_agent_api_key
from db import get_db
from util import hash_conteudo, normalizar_servidor

bp = Blueprint("api_agentes", __name__)


@bp.route("/api/logs/ingest", methods=["POST"])
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


@bp.route("/api/agent/windows-events", methods=["POST"])
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


@bp.route("/api/agent/heartbeat", methods=["POST"])
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


@bp.route("/api/logs/exists", methods=["POST"])
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


@bp.route("/health")
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
