import os
import re
import secrets
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask import Flask, redirect, render_template, request, session

from db import get_db, init_db


app = Flask(__name__)
secret_key = os.getenv("SECRET_KEY", "").strip()
if not secret_key:
    raise RuntimeError("SECRET_KEY must be configured")
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
BRASILIA_TZ = ZoneInfo("America/Sao_Paulo")


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


init_db()
from auth import admin_required, login_required
from sessao import criar_sessao_usuario, hash_password, limpar_sessoes_expiradas, sessao_atual_valida, verify_password
from util import agora_sql
from helpdesk import bp as helpdesk_blueprint
app.register_blueprint(helpdesk_blueprint)
from pfsense_web import bp as pfsense_blueprint
app.register_blueprint(pfsense_blueprint)
from monitoramento import bp as monitoramento_blueprint
app.register_blueprint(monitoramento_blueprint)
from admin_web import bp as admin_web_blueprint
app.register_blueprint(admin_web_blueprint)
from pacotes_agente import bp as pacotes_agente_blueprint
app.register_blueprint(pacotes_agente_blueprint)
from api_agentes import bp as api_agentes_blueprint
app.register_blueprint(api_agentes_blueprint)

# =========================
# HELPERS
# =========================


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

        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not request.path.startswith("/api/"):
            expected = session.get("helpdesk_csrf_token") or ""
            supplied = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not expected or not supplied or not secrets.compare_digest(expected, supplied):
                return "Formulário expirado. Recarregue a página e tente novamente.", 400

    return None


@app.context_processor
def inject_csrf_token():
    token = session.get("helpdesk_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["helpdesk_csrf_token"] = token
    return {"csrf_token": token}


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


@app.route("/clientes/delete/<int:id>", methods=["POST"])
@login_required
@admin_required
def delete_cliente(id):
    db = get_db()
    db.execute("DELETE FROM servidores WHERE cliente_id=?", (id,))
    db.execute("DELETE FROM clientes WHERE id=?", (id,))
    db.commit()
    return redirect("/")


@app.route("/clientes/toggle/<int:id>", methods=["POST"])
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


@app.route("/servidores/delete/<int:id>/<int:cliente_id>", methods=["POST"])
@login_required
@admin_required
def delete_servidor(id, cliente_id):

    db = get_db()
    db.execute("DELETE FROM servidores WHERE id=?", (id,))
    db.commit()

    return redirect(f"/servidores/{cliente_id}")


@app.route("/servidores/toggle/<int:id>/<int:cliente_id>", methods=["POST"])
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


# =========================
# LOGS NÃO CADASTRADOS
# =========================


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


# =========================
# CONFIG E-MAIL
# =========================


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

@app.route("/agendamento/delete/<int:ag_id>/<int:servidor_id>", methods=["POST"])
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
