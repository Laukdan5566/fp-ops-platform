"""Regras dos agentes Windows: versao atual, autenticacao por chave de API e recuperacao automatica de servidores."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import request

from db import get_db
from util import agora_sql, hash_token, normalizar_servidor

LATEST_AGENT_VERSION = "1.3.1"
AGENT_UPDATE_URL = "https://bkp.fpinformatica.com.br/static/backup-monitor-agent.zip"
AGENT_UPDATE_URL_WS2012 = "https://bkp.fpinformatica.com.br/static/backup-monitor-agent-legacy-ws2012.zip"
AGENT_SETUP_URL = "https://bkp.fpinformatica.com.br/static/BackupMonitorAgentSetup.exe"
AGENT_SETUP_URL_WS2012 = "https://bkp.fpinformatica.com.br/static/BackupMonitorAgentSetupLegacy2012.exe"
AUTO_RECOVER_AGENTS = int(os.getenv("AUTO_RECOVER_AGENTS", "0"))
_AGENT_PACKAGE_HASH_CACHE = {}


def agent_package_sha256(filename):
    path = Path(__file__).resolve().parent / "static" / filename
    try:
        stat = path.stat()
    except FileNotFoundError:
        # Pacote ausente: o batimento nao pode quebrar. Sem hash o agente recusa atualizar (ele exige o SHA-256).
        return None
    cached = _AGENT_PACKAGE_HASH_CACHE.get(filename)
    if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _AGENT_PACKAGE_HASH_CACHE[filename] = (stat.st_mtime_ns, stat.st_size, digest)
    return digest


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
