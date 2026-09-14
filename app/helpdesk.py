import hashlib
import json
import re
import secrets
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import Blueprint, abort, jsonify, redirect, render_template, request, session

from db import get_db
from secret_store import encrypt_secret


bp = Blueprint("helpdesk", __name__)

VALID_STATUSES = {"open", "in_progress", "waiting_customer", "resolved", "closed"}
VALID_PRIORITIES = {"low", "normal", "high", "critical"}
VALID_CATEGORIES = {"backup", "server", "pfsense", "internet", "windows", "support", "other"}


def now_sql():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("tipo") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    token = session.get("helpdesk_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["helpdesk_csrf_token"] = token
    return token


def require_csrf():
    expected = session.get("helpdesk_csrf_token") or ""
    supplied = request.form.get("_csrf_token", "")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        abort(400, "Formulario expirado. Recarregue a pagina.")


@bp.app_context_processor
def inject_helpdesk_helpers():
    return {"helpdesk_csrf_token": csrf_token}


def normalize_phone(value):
    value = (value or "").strip()
    if value.endswith("@g.us"):
        return value
    digits = re.sub(r"\D", "", value)
    if len(digits) in (10, 11):
        digits = "55" + digits
    return digits[:20]


def clean_text(value, limit, required=False):
    value = re.sub(r"\x00", "", str(value or "")).strip()
    if required and not value:
        abort(400, "Campo obrigatorio ausente.")
    return value[:limit]


def clean_int(value):
    try:
        result = int(value)
        return result if result > 0 else None
    except (TypeError, ValueError):
        return None


def safe_source_url(value):
    value = clean_text(value, 500)
    if not value:
        return None
    parsed = urlparse(value)
    return value if parsed.scheme == "https" and parsed.netloc else None


def add_audit(db, ticket_id, action, actor_type, actor_user_id=None, actor_name=None, details=None):
    db.execute("""
        INSERT INTO helpdesk_audit_log (
            ticket_id, action, actor_type, actor_user_id, actor_name, details_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        ticket_id, action, actor_type, actor_user_id, clean_text(actor_name, 160) or None,
        json.dumps(details or {}, ensure_ascii=False), now_sql(),
    ))


def set_ticket_number(db, ticket_id):
    number = f"HD-{datetime.now().year}-{ticket_id:06d}"
    db.execute("UPDATE helpdesk_tickets SET numero=? WHERE id=?", (number, ticket_id))
    return number


STATUS_PT = {
    "open": "Aberto", "in_progress": "Em atendimento",
    "waiting_customer": "Aguardando o cliente", "resolved": "Resolvido",
    "closed": "Encerrado",
}
PRIORITY_PT = {"low": "Baixa", "normal": "Normal", "high": "Alta", "critical": "Crítica"}


def message_excerpt(value, limit=1200):
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.strip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if not text:
        return "Motivo não informado."
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def ticket_message(ticket, event_type):
    status = STATUS_PT.get(ticket["status"], ticket["status"])
    name = ticket["contact_name"] or ticket["requester_name"]
    hello = f"Olá, {name}.\n\n" if name else ""
    reason = message_excerpt(ticket["descricao"])
    if event_type == "ticket_opened":
        return (
            f"*FP Ops | CHAMADO RECEBIDO*\n\n{hello}"
            f"*Chamado:* {ticket['numero']}\n"
            f"*Assunto:* {ticket['assunto']}\n"
            f"*Prioridade:* {PRIORITY_PT.get(ticket['prioridade'], ticket['prioridade'])}\n"
            f"*Situação:* {status}\n\n"
            "*Motivo informado*\n"
            f"{reason}\n\n"
            "────────────\n"
            "Nossa equipe acompanhará o atendimento e você será informado sobre as atualizações importantes."
        )
    if event_type == "ticket_resolved":
        return (
            f"*FP Ops | CHAMADO SOLUCIONADO*\n\n{hello}"
            f"*Chamado:* {ticket['numero']}\n"
            f"*Assunto:* {ticket['assunto']}\n"
            f"*Situação:* {status}\n\n"
            "*Motivo original*\n"
            f"{reason}\n\n"
            "────────────\n"
            "Se o problema continuar, responda ao atendimento para que a equipe possa reavaliar."
        )
    return (
        f"*FP Ops | ATUALIZAÇÃO DE CHAMADO*\n\n{hello}"
        f"*Chamado:* {ticket['numero']}\n"
        f"*Assunto:* {ticket['assunto']}\n"
        f"*Situação atual:* {status}\n\n"
        "*Motivo original*\n"
        f"{reason}\n\n"
        "────────────\n"
        "Acompanhe o atendimento pelo canal em que o chamado foi aberto."
    )


def queue_notification(db, ticket_id, event_type):
    flag_by_event = {
        "ticket_opened": "notify_ticket_opened",
        "ticket_updated": "notify_ticket_updated",
        "ticket_resolved": "notify_ticket_resolved",
    }
    flag = flag_by_event.get(event_type)
    if not flag:
        return False
    config = db.execute("SELECT * FROM ticketz_config WHERE id=1").fetchone()
    if not config or not int(config["ativo"] or 0) or not config["token_enc"] or not int(config[flag] or 0):
        return False
    ticket = db.execute("""
        SELECT t.*, c.nome AS contact_name, c.telefone AS contact_phone,
               c.whatsapp_enabled, c.ativo AS contact_active
        FROM helpdesk_tickets t
        LEFT JOIN cliente_contatos c ON c.id=t.requester_contact_id
        WHERE t.id=?
    """, (ticket_id,)).fetchone()
    if not ticket:
        return False
    recipient = normalize_phone(ticket["contact_phone"] or ticket["requester_phone"])
    if not recipient or (ticket["requester_contact_id"] and not int(ticket["whatsapp_enabled"] or 0)):
        return False
    body = ticket_message(ticket, event_type)
    idempotency_key = hashlib.sha256(
        f"{ticket_id}|{event_type}|{ticket['updated_at']}|{recipient}".encode("utf-8")
    ).hexdigest()
    db.execute("""
        INSERT OR IGNORE INTO notification_outbox (
            ticket_id, contact_id, recipient, event_type, body, idempotency_key,
            status, available_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
    """, (
        ticket_id, ticket["requester_contact_id"], recipient, event_type, body,
        idempotency_key, now_sql(), now_sql(), now_sql(),
    ))
    return True


def queue_internal_new_ticket(db, ticket_id):
    ticketz = db.execute("SELECT ativo, token_enc FROM ticketz_config WHERE id=1").fetchone()
    reminder = db.execute("SELECT ativo, base_url FROM helpdesk_reminder_config WHERE id=1").fetchone()
    if not ticketz or not int(ticketz["ativo"] or 0) or not ticketz["token_enc"]:
        return 0
    if not reminder or not int(reminder["ativo"] or 0):
        return 0
    ticket = db.execute("""
        SELECT t.*, c.nome_exibicao AS cliente_nome
        FROM helpdesk_tickets t
        LEFT JOIN clientes c ON c.id=t.cliente_id
        WHERE t.id=?
    """, (ticket_id,)).fetchone()
    if not ticket:
        return 0
    recipients = db.execute("""
        SELECT n.id, n.telefone
        FROM helpdesk_staff_notifications n
        JOIN usuarios u ON u.id=n.user_id
        WHERE n.ativo=1 AND u.ativo=1
        ORDER BY n.id
    """).fetchall()
    client = ticket["cliente_nome"] or ticket["requester_name"] or "Sem cliente"
    reason = message_excerpt(ticket["descricao"])
    body = (
        "*FP Ops | NOVO CHAMADO*\n\n"
        f"*Chamado:* {ticket['numero']}\n"
        f"*Cliente:* {client}\n"
        f"*Solicitante:* {ticket['opened_by_name'] or ticket['requester_name'] or 'Sistema'}\n"
        f"*Assunto:* {ticket['assunto']}\n"
        f"*Prioridade:* {PRIORITY_PT.get(ticket['prioridade'], ticket['prioridade'])}\n\n"
        "*Motivo informado*\n"
        f"{reason}\n\n"
        "────────────\n"
        "*Situação:* Aguardando atendimento\n"
        f"*Abrir chamado:* {reminder['base_url'].rstrip('/')}/helpdesk/tickets/{ticket_id}"
    )
    queued = 0
    now = now_sql()
    for recipient in recipients:
        idempotency_key = hashlib.sha256(
            f"internal-new-ticket|{ticket_id}|{recipient['id']}".encode("utf-8")
        ).hexdigest()
        inserted = db.execute("""
            INSERT OR IGNORE INTO notification_outbox (
                ticket_id, staff_recipient_id, recipient, event_type, body,
                status, available_at, idempotency_key, created_at, updated_at
            ) VALUES (?, ?, ?, 'internal_ticket_opened', ?, 'pending', ?, ?, ?, ?)
        """, (
            ticket_id, recipient["id"], recipient["telefone"], body,
            now, idempotency_key, now, now,
        ))
        if inserted.rowcount:
            queued += 1
    return queued


def queue_internal_ticket_resolved(db, ticket_id, actor_name=None):
    ticketz = db.execute("SELECT ativo, token_enc FROM ticketz_config WHERE id=1").fetchone()
    reminder = db.execute("SELECT base_url FROM helpdesk_reminder_config WHERE id=1").fetchone()
    if not ticketz or not int(ticketz["ativo"] or 0) or not ticketz["token_enc"]:
        return 0
    ticket = db.execute("""
        SELECT t.*, c.nome_exibicao AS cliente_nome
        FROM helpdesk_tickets t LEFT JOIN clientes c ON c.id=t.cliente_id WHERE t.id=?
    """, (ticket_id,)).fetchone()
    if not ticket:
        return 0
    recipients = db.execute("""
        SELECT n.id, n.telefone FROM helpdesk_staff_notifications n
        JOIN usuarios u ON u.id=n.user_id
        WHERE n.ativo=1 AND u.ativo=1 ORDER BY n.id
    """).fetchall()
    base_url = (reminder["base_url"] if reminder else "https://bkp.fpinformatica.com.br").rstrip("/")
    reason = message_excerpt(ticket["descricao"])
    body = (
        "*FP Ops | CHAMADO CONCLUÍDO*\n\n"
        f"*Chamado:* {ticket['numero']}\n"
        f"*Cliente:* {ticket['cliente_nome'] or ticket['requester_name'] or 'Sem cliente'}\n"
        f"*Assunto:* {ticket['assunto']}\n\n"
        "*Motivo original*\n"
        f"{reason}\n\n"
        "────────────\n"
        f"*Situação:* {STATUS_PT.get(ticket['status'], ticket['status'])}\n"
        f"*Concluído por:* {actor_name or 'Equipe técnica'}\n"
        f"*Consultar:* {base_url}/helpdesk/tickets/{ticket_id}"
    )
    queued = 0
    now = now_sql()
    for recipient in recipients:
        key = hashlib.sha256(
            f"internal-ticket-resolved|{ticket_id}|{ticket['updated_at']}|{recipient['id']}".encode()
        ).hexdigest()
        result = db.execute("""
            INSERT OR IGNORE INTO notification_outbox (
                ticket_id, staff_recipient_id, recipient, event_type, body, status,
                available_at, idempotency_key, created_at, updated_at
            ) VALUES (?, ?, ?, 'internal_ticket_resolved', ?, 'pending', ?, ?, ?, ?)
        """, (ticket_id, recipient["id"], recipient["telefone"], body, now, key, now, now))
        queued += 1 if result.rowcount else 0
    return queued


def ticket_or_404(db, ticket_id):
    ticket = db.execute("""
        SELECT t.*, c.nome_exibicao AS cliente_nome, s.nome_log AS servidor_nome,
               p.name AS pfsense_nome, u.username AS assignee_name
        FROM helpdesk_tickets t
        LEFT JOIN clientes c ON c.id=t.cliente_id
        LEFT JOIN servidores s ON s.id=t.servidor_id
        LEFT JOIN pfsense_firewalls p ON p.id=t.pfsense_firewall_id
        LEFT JOIN usuarios u ON u.id=t.assignee_user_id
        WHERE t.id=?
    """, (ticket_id,)).fetchone()
    if not ticket:
        abort(404)
    return ticket


@bp.route("/helpdesk")
@login_required
def index():
    status = request.args.get("status", "active")
    priority = request.args.get("priority", "")
    search = clean_text(request.args.get("q"), 100)
    where = []
    params = []
    if status == "active":
        where.append("t.status NOT IN ('resolved', 'closed')")
    elif status in VALID_STATUSES:
        where.append("t.status=?")
        params.append(status)
    if priority in VALID_PRIORITIES:
        where.append("t.prioridade=?")
        params.append(priority)
    if search:
        where.append("(UPPER(t.numero) LIKE UPPER(?) OR UPPER(t.assunto) LIKE UPPER(?) OR UPPER(COALESCE(c.nome_exibicao,'')) LIKE UPPER(?))")
        term = f"%{search}%"
        params.extend((term, term, term))
    clause = "WHERE " + " AND ".join(where) if where else ""
    db = get_db()
    tickets = db.execute(f"""
        SELECT t.*, c.nome_exibicao AS cliente_nome, u.username AS assignee_name
        FROM helpdesk_tickets t
        LEFT JOIN clientes c ON c.id=t.cliente_id
        LEFT JOIN usuarios u ON u.id=t.assignee_user_id
        {clause}
        ORDER BY CASE t.prioridade WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END,
                 datetime(t.updated_at) DESC, t.id DESC
        LIMIT 500
    """, tuple(params)).fetchall()
    counts = db.execute("""
        SELECT
          SUM(CASE WHEN status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) AS active,
          SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open,
          SUM(CASE WHEN status='open' AND assignee_user_id IS NULL THEN 1 ELSE 0 END) AS unassigned,
          SUM(CASE WHEN status='in_progress' THEN 1 ELSE 0 END) AS in_progress,
          SUM(CASE WHEN status='waiting_customer' THEN 1 ELSE 0 END) AS waiting_customer,
          SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) AS resolved,
          SUM(CASE WHEN prioridade='critical' AND status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) AS critical,
          SUM(CASE WHEN status IN ('open','in_progress') AND datetime(updated_at)<=datetime('now','-3 hours') THEN 1 ELSE 0 END) AS stale
        FROM helpdesk_tickets
    """).fetchone()
    workload = db.execute("""
        SELECT COALESCE(u.username, 'Sem responsável') AS responsavel, COUNT(*) AS total,
               SUM(CASE WHEN t.prioridade IN ('critical','high') THEN 1 ELSE 0 END) AS priority
        FROM helpdesk_tickets t LEFT JOIN usuarios u ON u.id=t.assignee_user_id
        WHERE t.status NOT IN ('resolved','closed')
        GROUP BY u.id, u.username ORDER BY total DESC, responsavel
    """).fetchall()
    db.close()
    return render_template("helpdesk/index.html", tickets=tickets, counts=counts, workload=workload, selected_status=status, selected_priority=priority, search=search, title="Helpdesk")


@bp.route("/helpdesk/new")
@login_required
def new_ticket():
    db = get_db()
    clientes = db.execute("SELECT id, nome_exibicao FROM clientes WHERE ativo=1 ORDER BY nome_exibicao").fetchall()
    contatos = db.execute("SELECT id, cliente_id, nome, telefone FROM cliente_contatos WHERE ativo=1 ORDER BY nome").fetchall()
    servidores = db.execute("SELECT id, cliente_id, nome_log FROM servidores WHERE ativo=1 ORDER BY nome_log").fetchall()
    firewalls = db.execute("SELECT id, name FROM pfsense_firewalls WHERE active=1 ORDER BY name").fetchall()
    db.close()
    return render_template("helpdesk/new.html", clientes=clientes, contatos=contatos, servidores=servidores, firewalls=firewalls)


@bp.route("/helpdesk/tickets", methods=["POST"])
@login_required
def create_ticket():
    require_csrf()
    assunto = clean_text(request.form.get("assunto"), 200, required=True)
    descricao = clean_text(request.form.get("descricao"), 10000, required=True)
    categoria = request.form.get("categoria", "support")
    prioridade = request.form.get("prioridade", "normal")
    if categoria not in VALID_CATEGORIES or prioridade not in VALID_PRIORITIES:
        abort(400)
    db = get_db()
    now = now_sql()
    contact_id = clean_int(request.form.get("requester_contact_id"))
    contact = db.execute("SELECT * FROM cliente_contatos WHERE id=? AND ativo=1", (contact_id,)).fetchone() if contact_id else None
    client_id = clean_int(request.form.get("cliente_id"))
    if contact:
        client_id = client_id or contact["cliente_id"]
    cur = db.execute("""
        INSERT INTO helpdesk_tickets (
            cliente_id, servidor_id, pfsense_firewall_id, requester_contact_id,
            requester_name, requester_phone, requester_email, assunto, descricao,
            categoria, prioridade, status, assignee_user_id, opened_by_type,
            opened_by_user_id, opened_by_name, origem, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 'user', ?, ?, 'manual', ?, ?)
    """, (
        client_id, clean_int(request.form.get("servidor_id")), clean_int(request.form.get("pfsense_firewall_id")),
        contact_id, contact["nome"] if contact else None, contact["telefone"] if contact else None,
        contact["email"] if contact else None, assunto, descricao, categoria, prioridade,
        clean_int(request.form.get("assignee_user_id")), session["user_id"], session.get("username"), now, now,
    ))
    ticket_id = cur.lastrowid
    set_ticket_number(db, ticket_id)
    add_audit(db, ticket_id, "created", "user", session["user_id"], session.get("username"), {"origin": "manual"})
    queue_notification(db, ticket_id, "ticket_opened")
    queue_internal_new_ticket(db, ticket_id)
    db.commit()
    db.close()
    return redirect(f"/helpdesk/tickets/{ticket_id}")


@bp.route("/helpdesk/tickets/<int:ticket_id>")
@login_required
def show_ticket(ticket_id):
    db = get_db()
    ticket = ticket_or_404(db, ticket_id)
    comments = db.execute("SELECT * FROM helpdesk_comments WHERE ticket_id=? ORDER BY id", (ticket_id,)).fetchall()
    audit = db.execute("SELECT * FROM helpdesk_audit_log WHERE ticket_id=? ORDER BY id DESC LIMIT 100", (ticket_id,)).fetchall()
    users = db.execute("SELECT id, username FROM usuarios WHERE ativo=1 ORDER BY username").fetchall()
    db.close()
    return render_template("helpdesk/show.html", ticket=ticket, comments=comments, audit=audit, users=users)


@bp.route("/helpdesk/tickets/<int:ticket_id>/comments", methods=["POST"])
@login_required
def add_comment(ticket_id):
    require_csrf()
    body = clean_text(request.form.get("body"), 10000, required=True)
    internal = 1 if request.form.get("internal") == "1" else 0
    db = get_db()
    ticket_or_404(db, ticket_id)
    now = now_sql()
    db.execute("""
        INSERT INTO helpdesk_comments (ticket_id, user_id, author_type, author_name, body, internal, created_at)
        VALUES (?, ?, 'user', ?, ?, ?, ?)
    """, (ticket_id, session["user_id"], session.get("username"), body, internal, now))
    db.execute("UPDATE helpdesk_tickets SET updated_at=? WHERE id=?", (now, ticket_id))
    add_audit(db, ticket_id, "comment_added", "user", session["user_id"], session.get("username"), {"internal": bool(internal)})
    queue_notification(db, ticket_id, "ticket_updated")
    db.commit()
    db.close()
    return redirect(f"/helpdesk/tickets/{ticket_id}")


@bp.route("/helpdesk/tickets/<int:ticket_id>/update", methods=["POST"])
@login_required
def update_ticket(ticket_id):
    require_csrf()
    status = request.form.get("status", "")
    priority = request.form.get("prioridade", "")
    if status not in VALID_STATUSES or priority not in VALID_PRIORITIES:
        abort(400)
    assignee = clean_int(request.form.get("assignee_user_id"))
    db = get_db()
    old = ticket_or_404(db, ticket_id)
    now = now_sql()
    resolved_at = now if status == "resolved" and old["status"] != "resolved" else old["resolved_at"]
    closed_at = now if status == "closed" and old["status"] != "closed" else old["closed_at"]
    if status not in ("resolved", "closed"):
        closed_at = None
    db.execute("""
        UPDATE helpdesk_tickets
        SET status=?, prioridade=?, assignee_user_id=?, resolved_at=?, closed_at=?, updated_at=?
        WHERE id=?
    """, (status, priority, assignee, resolved_at, closed_at, now, ticket_id))
    add_audit(db, ticket_id, "ticket_updated", "user", session["user_id"], session.get("username"), {
        "from_status": old["status"], "to_status": status,
        "from_priority": old["prioridade"], "to_priority": priority,
        "assignee_user_id": assignee,
    })
    queue_notification(db, ticket_id, "ticket_resolved" if status in ("resolved", "closed") else "ticket_updated")
    if status in ("resolved", "closed") and old["status"] not in ("resolved", "closed"):
        queue_internal_ticket_resolved(db, ticket_id, session.get("username"))
    db.commit()
    db.close()
    return redirect(f"/helpdesk/tickets/{ticket_id}")


@bp.route("/helpdesk/contacts")
@login_required
def contacts():
    db = get_db()
    rows = db.execute("""
        SELECT cc.*, c.nome_exibicao AS cliente_nome
        FROM cliente_contatos cc LEFT JOIN clientes c ON c.id=cc.cliente_id
        ORDER BY cc.ativo DESC, c.nome_exibicao, cc.nome
    """).fetchall()
    clientes = db.execute("SELECT id, nome_exibicao FROM clientes WHERE ativo=1 ORDER BY nome_exibicao").fetchall()
    db.close()
    return render_template("helpdesk/contacts.html", contacts=rows, clientes=clientes)


@bp.route("/helpdesk/contacts", methods=["POST"])
@login_required
@admin_required
def add_contact():
    require_csrf()
    name = clean_text(request.form.get("nome"), 160, required=True)
    phone = normalize_phone(request.form.get("telefone"))
    if phone and not phone.endswith("@g.us") and not 12 <= len(phone) <= 15:
        abort(400, "Telefone deve incluir DDI e DDD.")
    db = get_db()
    now = now_sql()
    db.execute("""
        INSERT INTO cliente_contatos (
            cliente_id, nome, telefone, email, cargo, whatsapp_enabled, ativo, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
    """, (
        clean_int(request.form.get("cliente_id")), name, phone or None,
        clean_text(request.form.get("email"), 200).lower() or None,
        clean_text(request.form.get("cargo"), 120) or None,
        1 if request.form.get("whatsapp_enabled") == "1" else 0, now, now,
    ))
    db.commit()
    db.close()
    return redirect("/helpdesk/contacts")


@bp.route("/helpdesk/contacts/<int:contact_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_contact(contact_id):
    require_csrf()
    db = get_db()
    db.execute("UPDATE cliente_contatos SET ativo=CASE WHEN ativo=1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?", (now_sql(), contact_id))
    db.commit()
    db.close()
    return redirect("/helpdesk/contacts")


def reminder_settings_context(db):
    config = db.execute("SELECT * FROM helpdesk_reminder_config WHERE id=1").fetchone()
    recipients = db.execute("""
        SELECT n.*, u.username, u.is_technician
        FROM helpdesk_staff_notifications n
        JOIN usuarios u ON u.id=n.user_id
        ORDER BY n.ativo DESC, u.username
    """).fetchall()
    users = db.execute("""
        SELECT u.id, u.username, u.is_technician
        FROM usuarios u
        WHERE u.ativo=1
        ORDER BY u.username
    """).fetchall()
    ticketz = db.execute("SELECT ativo, token_enc FROM ticketz_config WHERE id=1").fetchone()
    return config, recipients, users, bool(ticketz and ticketz["ativo"] and ticketz["token_enc"])


@bp.route("/helpdesk/reminders")
@login_required
@admin_required
def reminders():
    db = get_db()
    config, recipients, users, ticketz_ready = reminder_settings_context(db)
    db.close()
    return render_template(
        "helpdesk/reminders.html", config=config, recipients=recipients,
        users=users, ticketz_ready=ticketz_ready,
    )


@bp.route("/helpdesk/reminders/config", methods=["POST"])
@login_required
@admin_required
def save_reminder_config():
    require_csrf()
    initial = max(10, min(1440, clean_int(request.form.get("unassigned_initial_minutes")) or 30))
    interval = max(60, min(1440, clean_int(request.form.get("reminder_interval_minutes")) or 180))
    daily_limit = max(1, min(8, clean_int(request.form.get("daily_limit")) or 3))
    start_hour = max(0, min(23, clean_int(request.form.get("business_start_hour")) or 8))
    end_hour = max(1, min(24, clean_int(request.form.get("business_end_hour")) or 18))
    if end_hour <= start_hour:
        abort(400, "O fim do expediente deve ser posterior ao inicio.")
    base_url = clean_text(request.form.get("base_url"), 500, required=True).rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        abort(400, "A URL do FP Ops deve usar HTTPS.")
    db = get_db()
    db.execute("""
        UPDATE helpdesk_reminder_config
        SET ativo=?, unassigned_initial_minutes=?, reminder_interval_minutes=?,
            daily_limit=?, business_start_hour=?, business_end_hour=?,
            weekdays_only=?, base_url=?, updated_at=?
        WHERE id=1
    """, (
        1 if request.form.get("ativo") == "1" else 0,
        initial, interval, daily_limit, start_hour, end_hour,
        1 if request.form.get("weekdays_only") == "1" else 0,
        base_url, now_sql(),
    ))
    db.commit()
    db.close()
    return redirect("/helpdesk/reminders")


@bp.route("/helpdesk/reminders/recipients", methods=["POST"])
@login_required
@admin_required
def save_reminder_recipient():
    require_csrf()
    user_id = clean_int(request.form.get("user_id"))
    phone = normalize_phone(request.form.get("telefone"))
    if not user_id or not phone or (not phone.endswith("@g.us") and not 12 <= len(phone) <= 15):
        abort(400, "Selecione o usuario e informe WhatsApp com DDI e DDD.")
    db = get_db()
    user = db.execute("SELECT id FROM usuarios WHERE id=? AND ativo=1", (user_id,)).fetchone()
    if not user:
        db.close()
        abort(400, "Usuario invalido.")
    existing = db.execute("SELECT id FROM helpdesk_staff_notifications WHERE user_id=?", (user_id,)).fetchone()
    values = (
        phone,
        1 if request.form.get("notify_unassigned") == "1" else 0,
        1 if request.form.get("notify_own") == "1" else 0,
        1 if request.form.get("notify_all_overdue") == "1" else 0,
        1 if request.form.get("notify_servers") == "1" else 0,
        1 if request.form.get("notify_backups") == "1" else 0,
        1 if request.form.get("notify_pfsense") == "1" else 0,
        now_sql(),
    )
    if existing:
        db.execute("""
            UPDATE helpdesk_staff_notifications
            SET telefone=?, notify_unassigned=?, notify_own=?, notify_all_overdue=?,
                notify_servers=?, notify_backups=?, notify_pfsense=?, ativo=1, updated_at=?
            WHERE id=?
        """, values + (existing["id"],))
    else:
        db.execute("""
            INSERT INTO helpdesk_staff_notifications (
                user_id, telefone, notify_unassigned, notify_own, notify_all_overdue,
                notify_servers, notify_backups, notify_pfsense,
                ativo, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, (user_id,) + values[:7] + (values[7], values[7]))
    db.commit()
    db.close()
    return redirect("/helpdesk/reminders")


@bp.route("/helpdesk/reminders/recipients/<int:recipient_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_reminder_recipient(recipient_id):
    require_csrf()
    db = get_db()
    db.execute("""
        UPDATE helpdesk_staff_notifications
        SET ativo=CASE WHEN ativo=1 THEN 0 ELSE 1 END, updated_at=?
        WHERE id=?
    """, (now_sql(), recipient_id))
    db.commit()
    db.close()
    return redirect("/helpdesk/reminders")


@bp.route("/helpdesk/settings")
@login_required
@admin_required
def settings():
    db = get_db()
    config = db.execute("SELECT * FROM ticketz_config WHERE id=1").fetchone()
    tokens = db.execute("SELECT id, nome, scopes, ativo, last_used_at, created_at, revoked_at FROM integration_tokens ORDER BY id DESC").fetchall()
    outbox = db.execute("SELECT status, COUNT(*) AS total FROM notification_outbox GROUP BY status ORDER BY status").fetchall()
    db.close()
    return render_template("helpdesk/settings.html", config=config, tokens=tokens, outbox=outbox, new_token=None, token_configured=bool(config and config["token_enc"]))


@bp.route("/helpdesk/settings/ticketz", methods=["POST"])
@login_required
@admin_required
def save_ticketz_settings():
    require_csrf()
    endpoint = clean_text(request.form.get("endpoint"), 500, required=True)
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        abort(400, "O endpoint Ticketz deve usar HTTPS.")
    db = get_db()
    current = db.execute("SELECT * FROM ticketz_config WHERE id=1").fetchone()
    raw_token = request.form.get("token", "").strip()
    token_enc = encrypt_secret(raw_token) if raw_token else (current["token_enc"] if current else None)
    active = 1 if request.form.get("ativo") == "1" else 0
    if active and not token_enc:
        abort(400, "Cadastre o token antes de ativar o Ticketz.")
    db.execute("""
        UPDATE ticketz_config SET ativo=?, endpoint=?, token_enc=?, save_on_ticket=?, link_preview=?,
            notify_ticket_opened=?, notify_ticket_updated=?, notify_ticket_resolved=?, updated_at=? WHERE id=1
    """, (
        active, endpoint, token_enc,
        1 if request.form.get("save_on_ticket") == "1" else 0,
        1 if request.form.get("link_preview") == "1" else 0,
        1 if request.form.get("notify_ticket_opened") == "1" else 0,
        1 if request.form.get("notify_ticket_updated") == "1" else 0,
        1 if request.form.get("notify_ticket_resolved") == "1" else 0,
        now_sql(),
    ))
    db.commit()
    db.close()
    return redirect("/helpdesk/settings")


@bp.route("/helpdesk/settings/integration-token", methods=["POST"])
@login_required
@admin_required
def create_integration_token():
    require_csrf()
    raw_token = secrets.token_urlsafe(48)
    db = get_db()
    db.execute("""
        INSERT INTO integration_tokens (nome, token_hash, scopes, ativo, created_at)
        VALUES (?, ?, 'tickets:create', 1, ?)
    """, (clean_text(request.form.get("nome"), 120) or "Ticketz", hashlib.sha256(raw_token.encode()).hexdigest(), now_sql()))
    db.commit()
    config = db.execute("SELECT * FROM ticketz_config WHERE id=1").fetchone()
    tokens = db.execute("SELECT id, nome, scopes, ativo, last_used_at, created_at, revoked_at FROM integration_tokens ORDER BY id DESC").fetchall()
    outbox = db.execute("SELECT status, COUNT(*) AS total FROM notification_outbox GROUP BY status ORDER BY status").fetchall()
    db.close()
    return render_template(
        "helpdesk/settings.html", config=config, tokens=tokens, outbox=outbox,
        new_token=raw_token, token_configured=bool(config and config["token_enc"]),
    )


@bp.route("/helpdesk/settings/integration-token/<int:token_id>/revoke", methods=["POST"])
@login_required
@admin_required
def revoke_integration_token(token_id):
    require_csrf()
    db = get_db()
    db.execute("UPDATE integration_tokens SET ativo=0, revoked_at=? WHERE id=?", (now_sql(), token_id))
    db.commit()
    db.close()
    return redirect("/helpdesk/settings")


def authenticate_integration(db):
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    token_row = db.execute("SELECT * FROM integration_tokens WHERE token_hash=? AND ativo=1 LIMIT 1", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not token_row or "tickets:create" not in (token_row["scopes"] or "").split(","):
        return None
    db.execute("UPDATE integration_tokens SET last_used_at=? WHERE id=?", (now_sql(), token_row["id"]))
    return token_row


@bp.route("/api/v1/integrations/ticketz/tickets", methods=["POST"])
def api_ticketz_create_ticket():
    db = get_db()
    try:
        integration = authenticate_integration(db)
        if not integration:
            db.rollback()
            return jsonify({"error": "unauthorized"}), 401
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            db.rollback()
            return jsonify({"error": "invalid_json"}), 400
        external_id = clean_text(payload.get("source_ticket_id"), 120, required=True)
        company_id = clean_text(payload.get("company_id"), 120)
        existing = db.execute("""
            SELECT t.id, t.numero FROM external_ticket_links l
            JOIN helpdesk_tickets t ON t.id=l.helpdesk_ticket_id
            WHERE l.source='ticketz' AND l.company_external_id=? AND l.ticket_external_id=?
        """, (company_id, external_id)).fetchone()
        if existing:
            db.commit()
            base = request.url_root.rstrip("/")
            return jsonify({"created": False, "ticket_id": existing["id"], "number": existing["numero"], "url": f"{base}/helpdesk/tickets/{existing['id']}"}), 200

        opened = payload.get("opened_by") if isinstance(payload.get("opened_by"), dict) else {}
        requester = payload.get("requester") if isinstance(payload.get("requester"), dict) else {}
        phone = normalize_phone(requester.get("number"))
        contact = db.execute("SELECT * FROM cliente_contatos WHERE telefone=? AND ativo=1 ORDER BY id LIMIT 1", (phone,)).fetchone() if phone else None
        client_id = clean_int(payload.get("client_id")) or (contact["cliente_id"] if contact else None)
        subject = clean_text(payload.get("subject"), 200, required=True)
        description = clean_text(payload.get("description"), 10000, required=True)
        priority = payload.get("priority", "normal")
        category = payload.get("category", "support")
        if priority not in VALID_PRIORITIES or category not in VALID_CATEGORIES:
            db.rollback()
            return jsonify({"error": "invalid_classification"}), 400
        messages = payload.get("messages") if isinstance(payload.get("messages"), list) else []
        if messages:
            lines = []
            for item in messages[-20:]:
                if isinstance(item, dict):
                    author = clean_text(item.get("author"), 80) or "Mensagem"
                    body = clean_text(item.get("body"), 1000)
                    if body:
                        lines.append(f"{author}: {body}")
            if lines:
                description = (description + "\n\nContexto do Ticketz:\n" + "\n".join(lines))[:10000]
        now = now_sql()
        cur = db.execute("""
            INSERT INTO helpdesk_tickets (
                cliente_id, requester_contact_id, requester_name, requester_phone, requester_email,
                assunto, descricao, categoria, prioridade, status, opened_by_type,
                opened_by_external_id, opened_by_name, origem, source_external_id,
                source_url, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 'ticketz_user', ?, ?, 'ticketz', ?, ?, ?, ?)
        """, (
            client_id, contact["id"] if contact else None, clean_text(requester.get("name"), 160) or None,
            phone or None, clean_text(requester.get("email"), 200).lower() or None,
            subject, description, category, priority, clean_text(opened.get("external_id"), 120) or None,
            clean_text(opened.get("name"), 160) or "Usuario Ticketz", external_id,
            safe_source_url(payload.get("source_url")), now, now,
        ))
        ticket_id = cur.lastrowid
        number = set_ticket_number(db, ticket_id)
        db.execute("""
            INSERT INTO external_ticket_links (
                source, company_external_id, ticket_external_id, conversation_uuid,
                helpdesk_ticket_id, created_at, updated_at
            ) VALUES ('ticketz', ?, ?, ?, ?, ?, ?)
        """, (company_id, external_id, clean_text(payload.get("source_ticket_uuid"), 120) or None, ticket_id, now, now))
        add_audit(db, ticket_id, "created", "ticketz_user", None, opened.get("name"), {
            "integration_token_id": integration["id"], "ticketz_user_id": opened.get("external_id"),
            "ticketz_company_id": company_id, "source_ticket_id": external_id,
        })
        queue_notification(db, ticket_id, "ticket_opened")
        queue_internal_new_ticket(db, ticket_id)
        db.commit()
        base = request.url_root.rstrip("/")
        return jsonify({"created": True, "ticket_id": ticket_id, "number": number, "status": "open", "url": f"{base}/helpdesk/tickets/{ticket_id}"}), 201
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
