import io
import json
import os
import re
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import Flask, Response, redirect, render_template, request, session

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
from auth import admin_required, login_required, support_required
from retencao import executar_retencao, retention_config
from sessao import criar_sessao_usuario, hash_password, limpar_sessoes_expiradas, sessao_atual_valida, verify_password
from agentes import LATEST_AGENT_VERSION, comparar_versao_agent
from util import hash_token, normalizar_servidor
from util import agora_sql, enriquecer_uptime_pfsense, formatar_idade, parse_data
from helpdesk import bp as helpdesk_blueprint
app.register_blueprint(helpdesk_blueprint)
from pfsense_web import bp as pfsense_blueprint
app.register_blueprint(pfsense_blueprint)
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


@app.route("/api-keys/toggle/<int:key_id>", methods=["POST"])
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
