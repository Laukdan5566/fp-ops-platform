import json
from datetime import datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from db import get_db
from secret_store import decrypt_secret


MAX_ATTEMPTS = 5
MAX_PER_RUN = 20


def now_sql():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_error(exc):
    if isinstance(exc, HTTPError):
        return f"Ticketz retornou HTTP {exc.code}"
    if isinstance(exc, URLError):
        return f"Falha de conexao com Ticketz: {exc.reason}"
    return str(exc)[:500]


def send_text(config, token, recipient, body):
    payload = json.dumps({
        "number": recipient,
        "body": body,
        "saveOnTicket": bool(config["save_on_ticket"]),
        "linkPreview": bool(config["link_preview"]),
    }, ensure_ascii=False).encode("utf-8")
    req = Request(
        config["endpoint"], data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "FP-Ops/1.0",
        },
    )
    with urlopen(req, timeout=30) as response:
        response.read(65536)
        return int(response.status)


def process_notification_outbox():
    db = get_db()
    processed = {"sent": 0, "error": 0}
    try:
        config = db.execute("SELECT * FROM ticketz_config WHERE id=1").fetchone()
        if not config or not int(config["ativo"] or 0) or not config["token_enc"]:
            return processed
        token = decrypt_secret(config["token_enc"])
        rows = db.execute("""
            SELECT * FROM notification_outbox
            WHERE status IN ('pending','retry')
              AND attempts < ?
              AND datetime(available_at) <= datetime(?)
            ORDER BY id
            LIMIT ?
        """, (MAX_ATTEMPTS, now_sql(), MAX_PER_RUN)).fetchall()
        for row in rows:
            attempted_at = now_sql()
            try:
                code = send_text(config, token, row["recipient"], row["body"])
                db.execute("""
                    UPDATE notification_outbox
                    SET status='sent', attempts=attempts+1, last_attempt_at=?, sent_at=?,
                        response_code=?, error=NULL, updated_at=? WHERE id=?
                """, (attempted_at, attempted_at, code, attempted_at, row["id"]))
                db.execute("""
                    INSERT INTO notification_attempts (outbox_id, attempted_at, status, response_code)
                    VALUES (?, ?, 'sent', ?)
                """, (row["id"], attempted_at, code))
                processed["sent"] += 1
            except Exception as exc:
                error = safe_error(exc)
                attempts = int(row["attempts"] or 0) + 1
                status = "failed" if attempts >= MAX_ATTEMPTS else "retry"
                delay_minutes = min(60, 2 ** attempts)
                available_at = (datetime.now() + timedelta(minutes=delay_minutes)).strftime("%Y-%m-%d %H:%M:%S")
                response_code = exc.code if isinstance(exc, HTTPError) else None
                db.execute("""
                    UPDATE notification_outbox
                    SET status=?, attempts=?, last_attempt_at=?, available_at=?,
                        response_code=?, error=?, updated_at=? WHERE id=?
                """, (status, attempts, attempted_at, available_at, response_code, error, attempted_at, row["id"]))
                db.execute("""
                    INSERT INTO notification_attempts (outbox_id, attempted_at, status, response_code, error)
                    VALUES (?, ?, ?, ?, ?)
                """, (row["id"], attempted_at, status, response_code, error))
                processed["error"] += 1
            db.commit()
        return processed
    finally:
        db.close()
