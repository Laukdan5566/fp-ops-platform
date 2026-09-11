import email
import hashlib
import html
import imaplib
import os
import re
import json
import shutil
import sys
import time
import traceback
import unicodedata
from pathlib import Path
from datetime import datetime, timedelta
from email.header import decode_header
from email.utils import parsedate_to_datetime


sys.path.append(os.path.dirname(os.path.dirname(__file__)))
sys.path.append(os.path.dirname(__file__))
from db import DB_PATH, USING_POSTGRES, get_db, init_db
from zammad import avaliar_alertas
from pfsense_agent import run_due_firewalls, run_requested_firewall_speedtests
from pfsense_links import run_due_link_tests, run_requested_link_tests
from pfsense_storage import run_storage_cleanup
from ticketz_notifications import process_notification_outbox
from helpdesk_reminders import queue_internal_reminders


IMAP_CHECK_INTERVAL = int(os.getenv("IMAP_CHECK_INTERVAL", "300"))
MAX_EMAILS_PER_RUN = int(os.getenv("MAX_EMAILS_PER_RUN", "1000"))
IMAP_LOOKBACK_DAYS = int(os.getenv("IMAP_LOOKBACK_DAYS", "3"))
IMAP_TIMEOUT = int(os.getenv("IMAP_TIMEOUT", "30"))
RETENTION_CHECK_ENABLED = int(os.getenv("RETENTION_CHECK_ENABLED", "1"))
HELPDESK_REMINDER_CHECK_INTERVAL = int(os.getenv("HELPDESK_REMINDER_CHECK_INTERVAL", "60"))


def agora_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
    """, (agora_str(),))
    db.commit()
    return db.execute("SELECT * FROM retention_config WHERE id=1").fetchone()


def executar_retencao_automatica():
    if not RETENTION_CHECK_ENABLED:
        return

    init_db()
    db = get_db()
    run_id = None
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

        cur = db.execute("""
            INSERT INTO maintenance_runs (action, started_at, status, detail)
            VALUES ('retention', ?, 'running', 'auto-worker')
        """, (agora_str(),))
        run_id = cur.lastrowid
        db.commit()

        if USING_POSTGRES:
            backup_path = "postgres"
        else:
            backup_path = Path(DB_PATH).parent / f"backups-retention-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
        if not USING_POSTGRES and Path(DB_PATH).exists():
            shutil.copy2(DB_PATH, backup_path)

        logs_limite = (datetime.now() - timedelta(days=int(config["logs_full_days"] or 90))).strftime("%Y-%m-%d %H:%M:%S")
        unknown_limite = (datetime.now() - timedelta(days=int(config["unknown_logs_days"] or 30))).strftime("%Y-%m-%d %H:%M:%S")
        worker_limite = (datetime.now() - timedelta(days=int(config["worker_runs_days"] or 180))).strftime("%Y-%m-%d %H:%M:%S")
        zammad_limite = (datetime.now() - timedelta(days=int(config["zammad_alerts_days"] or 180))).strftime("%Y-%m-%d %H:%M:%S")
        heartbeat_limite = (datetime.now() - timedelta(days=int(config["heartbeat_history_days"] or 90))).strftime("%Y-%m-%d %H:%M:%S")
        session_limite = (datetime.now() - timedelta(days=int(config["session_history_days"] or 30))).strftime("%Y-%m-%d %H:%M:%S")

        stats = {}
        stats["logs_compactados"] = db.execute("""
            UPDATE logs_email
            SET conteudo_raw=NULL
            WHERE conteudo_raw IS NOT NULL
              AND datetime(data_email) < datetime(?)
        """, (logs_limite,)).rowcount
        stats["nao_cadastrados_removidos"] = db.execute("""
            DELETE FROM logs_nao_cadastrados
            WHERE datetime(COALESCE(created_at, data_email)) < datetime(?)
        """, (unknown_limite,)).rowcount
        stats["worker_runs_removidos"] = db.execute("""
            DELETE FROM worker_runs
            WHERE datetime(started_at) < datetime(?)
        """, (worker_limite,)).rowcount
        stats["zammad_alertas_removidos"] = db.execute("""
            DELETE FROM zammad_alertas
            WHERE datetime(COALESCE(updated_at, created_at)) < datetime(?)
        """, (zammad_limite,)).rowcount
        stats["heartbeat_history_removidos"] = db.execute("""
            DELETE FROM agent_heartbeat_history
            WHERE datetime(seen_at) < datetime(?)
        """, (heartbeat_limite,)).rowcount
        stats["sessoes_removidas"] = db.execute("""
            DELETE FROM user_sessions
            WHERE ativo=0
              AND datetime(COALESCE(logged_out_at, last_seen, created_at)) < datetime(?)
        """, (session_limite,)).rowcount

        detalhe = json.dumps({**stats, "backup": str(backup_path)}, ensure_ascii=False)
        db.execute("""
            UPDATE maintenance_runs
            SET finished_at=?, status='success', detail=?
            WHERE id=?
        """, (agora_str(), detalhe, run_id))
        db.commit()
        db.execute("VACUUM")
        print(f"Retencao automatica: {detalhe}", flush=True)
    except Exception as exc:
        if run_id:
            db.execute("""
                UPDATE maintenance_runs
                SET finished_at=?, status='error', detail=?
                WHERE id=?
            """, (agora_str(), str(exc), run_id))
            db.commit()
        print(f"Erro na retencao automatica: {exc}", flush=True)
    finally:
        db.close()


def decode_str(s):
    if not s:
        return ""

    result = ""
    for part, enc in decode_header(s):
        if isinstance(part, bytes):
            result += part.decode(enc or "utf-8", errors="ignore")
        else:
            result += part
    return result


def normalizar_servidor(nome):
    return re.sub(r"\s+", "_", nome.strip().upper())


def hash_conteudo(texto):
    return hashlib.sha256((texto or "").encode()).hexdigest()


def extrair_servidor(subject, body):
    subject = subject.upper()

    match = re.search(r"BACKUP.*?-\s*([A-Z0-9_ ]+)\s*-\s*IPERIUS", subject)
    if match:
        return normalizar_servidor(match.group(1))

    body_up = body.upper()
    match = re.search(r"RELATÓRIO DO IPERIUS BACKUP\s+([A-Z0-9_ ]+)", body_up)
    if match:
        return normalizar_servidor(match.group(1))

    return None


def detectar_status(texto):
    texto = unicodedata.normalize("NFKD", texto.lower())
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    texto_sem_zero_erros = re.sub(r"\b0\s+erros?\b", " ", texto)

    tem_sucesso = any(p in texto for p in (
        "backup concluido com sucesso",
        "backup conclu",
        "success",
        "successful",
        "sucesso na compactacao",
        "sucesso no envio",
        "sucesso na transferencia",
        "sucesso na transfer",
    ))

    if re.search(r"\b[1-9][0-9]*\s+erros?\b", texto_sem_zero_erros):
        return "error"

    if any(p in texto_sem_zero_erros for p in (
        "backup finalizado com erros",
        "backup finalizado com erro",
        "backup concluido com erros",
        "falha",
        "failed",
        "failure",
    )):
        return "error"

    if tem_sucesso:
        return "success"

    if "erro" in texto_sem_zero_erros:
        return "error"

    return "warning"


def limpar_html(texto):
    texto = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", texto)
    texto = re.sub(r"(?s)<[^>]+>", " ", texto)
    texto = html.unescape(texto)
    return re.sub(r"\s+", " ", texto).strip()


def decodificar_payload(part):
    payload = part.get_payload(decode=True)
    if not payload:
        return ""

    charset = part.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="ignore")


def extrair_body(msg):
    text_plain = []
    text_html = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disposition:
                continue

            if content_type == "text/plain":
                text_plain.append(decodificar_payload(part))
            elif content_type == "text/html":
                text_html.append(limpar_html(decodificar_payload(part)))
    else:
        content = decodificar_payload(msg)
        if msg.get_content_type() == "text/html":
            text_html.append(limpar_html(content))
        else:
            text_plain.append(content)

    body = "\n".join(p for p in text_plain if p).strip()
    if body:
        return body

    return "\n".join(p for p in text_html if p).strip()


def formatar_data_imap(data):
    meses = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{data.day:02d}-{meses[data.month - 1]}-{data.year}"


def ultima_data_processada(db):
    row = db.execute("""
        SELECT MAX(datetime(data_email)) AS ultima
        FROM logs_email
    """).fetchone()

    if not row or not row["ultima"]:
        return datetime.now() - timedelta(days=IMAP_LOOKBACK_DAYS)

    if isinstance(row["ultima"], datetime):
        return row["ultima"]

    try:
        return datetime.strptime(str(row["ultima"])[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.now() - timedelta(days=IMAP_LOOKBACK_DAYS)


def iniciar_execucao(db):
    cur = db.execute("""
        INSERT INTO worker_runs (started_at, status)
        VALUES (?, 'running')
    """, (agora_str(),))
    db.commit()
    return cur.lastrowid


def finalizar_execucao(db, run_id, status, stats, detalhe=None):
    db.execute("""
        UPDATE worker_runs
        SET finished_at=?,
            status=?,
            emails_encontrados=?,
            novos=?,
            duplicados=?,
            ignorados=?,
            erros=?,
            detalhe=?
        WHERE id=?
    """, (
        agora_str(),
        status,
        stats.get("encontrados", 0),
        stats.get("novos", 0),
        stats.get("duplicados", 0),
        stats.get("ignorados", 0),
        stats.get("erros", 0),
        detalhe,
        run_id,
    ))
    db.commit()


def conectar_imap(config):
    if int(config["usar_ssl"] or 0):
        return imaplib.IMAP4_SSL(
            config["imap_server"],
            int(config["imap_port"]),
            timeout=IMAP_TIMEOUT,
        )

    return imaplib.IMAP4(
        config["imap_server"],
        int(config["imap_port"]),
        timeout=IMAP_TIMEOUT,
    )


def mensagem_ja_processada(db, message_id):
    return db.execute(
        "SELECT 1 FROM logs_email WHERE message_id=?",
        (message_id,),
    ).fetchone() is not None


def log_ja_registrado_por_hash(db, servidor, conteudo_hash):
    if not conteudo_hash:
        return False

    return db.execute("""
        SELECT 1
        FROM logs_email
        WHERE UPPER(servidor_log)=? AND conteudo_hash=?
        LIMIT 1
    """, (servidor, conteudo_hash)).fetchone() is not None


def registrar_nao_cadastrado(db, servidor, data_email, message_id, subject, body):
    existe = db.execute("""
        SELECT 1
        FROM logs_nao_cadastrados
        WHERE UPPER(servidor_log)=?
    """, (servidor,)).fetchone()

    if existe:
        return

    db.execute("""
        INSERT INTO logs_nao_cadastrados
        (servidor_log, data_email, message_id, subject, conteudo_raw)
        VALUES (?,?,?,?,?)
    """, (servidor, data_email, message_id, subject, body))
    db.commit()


def processar_mensagem(db, imap, eid):
    _, header_data = imap.fetch(
        eid,
        "(BODY.PEEK[HEADER.FIELDS (DATE SUBJECT MESSAGE-ID)])",
    )
    if not header_data or not isinstance(header_data[0], tuple):
        return "ignorado"

    header_msg = email.message_from_bytes(header_data[0][1])
    subject = decode_str(header_msg.get("Subject", ""))
    message_id = (header_msg.get("Message-ID", "") or "").strip()

    if not message_id:
        message_id = f"imap-{eid.decode(errors='ignore')}"

    if mensagem_ja_processada(db, message_id):
        return "duplicado"

    _, msg_data = imap.fetch(eid, "(RFC822)")
    if not msg_data or not isinstance(msg_data[0], tuple):
        return "ignorado"

    msg = email.message_from_bytes(msg_data[0][1])

    try:
        data_email_dt = parsedate_to_datetime(msg["Date"])
        data_email = data_email_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        data_email = agora_str()

    body = extrair_body(msg)
    servidor = extrair_servidor(subject, body)
    conteudo_hash = hash_conteudo(body)

    if not servidor:
        return "ignorado"

    existe_servidor = db.execute("""
        SELECT id
        FROM servidores
        WHERE UPPER(nome_log)=?
    """, (servidor,)).fetchone()

    if not existe_servidor:
        registrar_nao_cadastrado(db, servidor, data_email, message_id, subject, body)
        return "ignorado"

    if log_ja_registrado_por_hash(db, servidor, conteudo_hash):
        return "duplicado"

    status_backup = detectar_status(f"{subject}\n{body}")

    cur = db.execute("""
        INSERT INTO logs_email
        (servidor_log, data_email, status, conteudo_raw, message_id, subject, origem, conteudo_hash)
        VALUES (?,?,?,?,?,?,?,?)
    """, (servidor, data_email, status_backup, body, message_id, subject, "email", conteudo_hash))
    db.commit()
    log_email_id = cur.lastrowid

    return "novo"


def processar_emails():
    init_db()

    db = get_db()
    run_id = iniciar_execucao(db)
    stats = {
        "encontrados": 0,
        "novos": 0,
        "duplicados": 0,
        "ignorados": 0,
        "erros": 0,
    }
    imap = None

    try:
        config = db.execute("SELECT * FROM config_email LIMIT 1").fetchone()

        if not config:
            finalizar_execucao(db, run_id, "warning", stats, "Configuração de e-mail não encontrada.")
            print("Configuração de e-mail não encontrada.", flush=True)
            return

        print("\n=== Verificando emails ===", flush=True)

        imap = conectar_imap(config)
        imap.login(config["email_user"], config["email_pass"])
        imap.select(config["pasta"] or "INBOX")

        desde = ultima_data_processada(db) - timedelta(days=IMAP_LOOKBACK_DAYS)
        desde_imap = formatar_data_imap(desde)

        status, messages = imap.search(None, "SINCE", desde_imap)
        if status != "OK":
            raise RuntimeError(f"Falha ao buscar e-mails no IMAP: {status}")

        email_ids = messages[0].split() if messages and messages[0] else []
        email_ids = email_ids[-MAX_EMAILS_PER_RUN:]
        stats["encontrados"] = len(email_ids)

        for eid in email_ids:
            try:
                resultado = processar_mensagem(db, imap, eid)
                if resultado == "novo":
                    stats["novos"] += 1
                elif resultado == "duplicado":
                    stats["duplicados"] += 1
                else:
                    stats["ignorados"] += 1
            except Exception:
                stats["erros"] += 1
                print(f"Erro ao processar e-mail {eid!r}:", flush=True)
                traceback.print_exc()

        zammad_resumo = avaliar_alertas(db)
        if zammad_resumo["status"] == "enabled":
            print(
                "Zammad: "
                f"{zammad_resumo['success']} chamados, "
                f"{zammad_resumo['duplicate']} duplicados, "
                f"{zammad_resumo['error']} erros de envio.",
                flush=True,
            )

        detalhe = (
            f"Busca desde {desde_imap}: {stats['encontrados']} e-mails, "
            f"{stats['novos']} novos, {stats['duplicados']} duplicados, "
            f"{stats['ignorados']} ignorados, {stats['erros']} erros."
        )
        status_final = "error" if stats["erros"] else "success"
        finalizar_execucao(db, run_id, status_final, stats, detalhe)
        print(detalhe, flush=True)
    except Exception as e:
        finalizar_execucao(db, run_id, "error", stats, str(e))
        raise
    finally:
        if imap:
            try:
                imap.logout()
            except Exception:
                pass
        db.close()


if __name__ == "__main__":
    next_full_run = 0.0
    next_helpdesk_reminder_run = 0.0
    while True:
        try:
            if time.monotonic() >= next_full_run:
                processar_emails()
                run_due_firewalls()
                run_due_link_tests()
                run_storage_cleanup()
                executar_retencao_automatica()
                next_full_run = time.monotonic() + IMAP_CHECK_INTERVAL
            run_requested_firewall_speedtests()
            run_requested_link_tests()
            if time.monotonic() >= next_helpdesk_reminder_run:
                queue_internal_reminders()
                next_helpdesk_reminder_run = time.monotonic() + HELPDESK_REMINDER_CHECK_INTERVAL
            process_notification_outbox()
        except Exception as e:
            print("Erro:", e, flush=True)
            traceback.print_exc()

        time.sleep(min(5, IMAP_CHECK_INTERVAL))
