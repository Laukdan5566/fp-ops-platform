import hashlib
from datetime import datetime

from db import get_db


MAX_TICKETS_IN_MESSAGE = 12


def parse_sql_datetime(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)


def age_label(minutes):
    minutes = max(0, int(minutes))
    if minutes < 60:
        return f"{minutes} min"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h"
    return f"{hours // 24}d {hours % 24}h"


def build_digest(recipient, tickets, base_url, now):
    lines = [
        f"FP Ops - pendencias do helpdesk ({now.strftime('%d/%m %H:%M')})",
        f"{len(tickets)} chamado(s) precisam de atencao:",
        "",
    ]
    for ticket in tickets[:MAX_TICKETS_IN_MESSAGE]:
        if ticket["reminder_kind"] == "unassigned":
            reason = f"sem responsavel ha {age_label(ticket['age_minutes'])}"
        else:
            reason = f"sem movimentacao ha {age_label(ticket['age_minutes'])}"
        client = ticket["cliente_nome"] or ticket["requester_name"] or "Sem cliente"
        lines.append(f"- {ticket['numero']} [{ticket['prioridade']}] {client}: {ticket['assunto']} ({reason})")
    remaining = len(tickets) - MAX_TICKETS_IN_MESSAGE
    if remaining > 0:
        lines.append(f"- e mais {remaining} chamado(s)")
    lines.extend([
        "",
        "Ao assumir ou movimentar o chamado, ele sai temporariamente desta cobranca.",
        f"Ver chamados: {base_url.rstrip('/')}/helpdesk?status=active",
    ])
    return "\n".join(lines)


def queue_internal_reminders(current_time=None):
    now = (current_time or datetime.now()).replace(tzinfo=None, second=0, microsecond=0)
    db = get_db()
    result = {"queued": 0, "recipients": 0, "tickets": 0}
    try:
        config = db.execute("SELECT * FROM helpdesk_reminder_config WHERE id=1").fetchone()
        ticketz = db.execute("SELECT ativo, token_enc FROM ticketz_config WHERE id=1").fetchone()
        if not config or not int(config["ativo"] or 0):
            return result
        if not ticketz or not int(ticketz["ativo"] or 0) or not ticketz["token_enc"]:
            return result
        if int(config["weekdays_only"] or 0) and now.weekday() >= 5:
            return result
        if not int(config["business_start_hour"]) <= now.hour < int(config["business_end_hour"]):
            return result

        recipients = db.execute("""
            SELECT n.*, u.username
            FROM helpdesk_staff_notifications n
            JOIN usuarios u ON u.id=n.user_id
            WHERE n.ativo=1 AND u.ativo=1
            ORDER BY n.id
        """).fetchall()
        tickets = db.execute("""
            SELECT t.*, c.nome_exibicao AS cliente_nome, u.username AS assignee_name
            FROM helpdesk_tickets t
            LEFT JOIN clientes c ON c.id=t.cliente_id
            LEFT JOIN usuarios u ON u.id=t.assignee_user_id
            WHERE t.status IN ('open', 'in_progress')
            ORDER BY CASE t.prioridade WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END,
                     t.created_at
            LIMIT 1000
        """).fetchall()
        interval = int(config["reminder_interval_minutes"] or 180)
        initial = int(config["unassigned_initial_minutes"] or 30)
        daily_limit = int(config["daily_limit"] or 3)

        for recipient in recipients:
            due = []
            for row in tickets:
                ticket = dict(row)
                created = parse_sql_datetime(ticket["created_at"])
                updated = parse_sql_datetime(ticket["updated_at"])
                if not ticket["assignee_user_id"] and ticket["status"] == "open":
                    age = (now - created).total_seconds() / 60 if created else 0
                    if age < initial or not int(recipient["notify_unassigned"] or 0):
                        continue
                    ticket["reminder_kind"] = "unassigned"
                else:
                    age = (now - updated).total_seconds() / 60 if updated else 0
                    own = ticket["assignee_user_id"] == recipient["user_id"] and int(recipient["notify_own"] or 0)
                    manager = int(recipient["notify_all_overdue"] or 0)
                    if age < interval or not (own or manager):
                        continue
                    ticket["reminder_kind"] = "stale"
                ticket["age_minutes"] = age
                due.append(ticket)
            if not due:
                continue
            result["recipients"] += 1
            result["tickets"] += len(due)

            last = db.execute("""
                SELECT created_at FROM notification_outbox
                WHERE staff_recipient_id=? AND event_type='internal_reminder_digest'
                ORDER BY id DESC LIMIT 1
            """, (recipient["id"],)).fetchone()
            if last:
                last_at = parse_sql_datetime(last["created_at"])
                if last_at and (now - last_at).total_seconds() < interval * 60:
                    continue
            sent_today = db.execute("""
                SELECT COUNT(*) AS total FROM notification_outbox
                WHERE staff_recipient_id=? AND event_type='internal_reminder_digest'
                  AND date(created_at)=date(?)
            """, (recipient["id"], now.strftime("%Y-%m-%d %H:%M:%S"))).fetchone()
            if int(sent_today["total"] or 0) >= daily_limit:
                continue

            slot = int(now.timestamp()) // (interval * 60)
            idempotency_key = hashlib.sha256(
                f"internal-digest|{recipient['id']}|{slot}".encode("utf-8")
            ).hexdigest()
            body = build_digest(recipient, due, config["base_url"], now)
            inserted = db.execute("""
                INSERT OR IGNORE INTO notification_outbox (
                    staff_recipient_id, recipient, event_type, body, status,
                    available_at, idempotency_key, created_at, updated_at
                ) VALUES (?, ?, 'internal_reminder_digest', ?, 'pending', ?, ?, ?, ?)
            """, (
                recipient["id"], recipient["telefone"], body,
                now.strftime("%Y-%m-%d %H:%M:%S"), idempotency_key,
                now.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S"),
            ))
            if inserted.rowcount:
                result["queued"] += 1
        db.commit()
        return result
    finally:
        db.close()
