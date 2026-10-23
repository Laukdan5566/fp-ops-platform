"""Sessao de usuario: senha, criacao, validade e limpeza de sessoes."""
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta

from flask import request, session
from werkzeug.security import check_password_hash, generate_password_hash

from util import agora_sql

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


SESSION_IDLE_HOURS = int(os.getenv("SESSION_IDLE_HOURS", "8"))


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
