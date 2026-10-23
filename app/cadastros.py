"""Cadastros: clientes, servidores, agendamentos de backup, busca global e servidores detectados nos logs."""
import re

from flask import Blueprint, redirect, render_template, request

from auth import admin_required, login_required
from db import get_db


bp = Blueprint("cadastros", __name__)


@bp.route("/")
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


@bp.route("/search")
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


@bp.route("/clientes/add", methods=["POST"])
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


@bp.route("/clientes/<int:cliente_id>/windows-alerts", methods=["POST"])
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


@bp.route("/clientes/delete/<int:id>", methods=["POST"])
@login_required
@admin_required
def delete_cliente(id):
    db = get_db()
    db.execute("DELETE FROM servidores WHERE cliente_id=?", (id,))
    db.execute("DELETE FROM clientes WHERE id=?", (id,))
    db.commit()
    return redirect("/")


@bp.route("/clientes/toggle/<int:id>", methods=["POST"])
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


@bp.route("/servidores/<int:cliente_id>")
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


@bp.route("/servidores/add/<int:cliente_id>", methods=["POST"])
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


@bp.route("/servidores/delete/<int:id>/<int:cliente_id>", methods=["POST"])
@login_required
@admin_required
def delete_servidor(id, cliente_id):

    db = get_db()
    db.execute("DELETE FROM servidores WHERE id=?", (id,))
    db.commit()

    return redirect(f"/servidores/{cliente_id}")


@bp.route("/servidores/toggle/<int:id>/<int:cliente_id>", methods=["POST"])
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


@bp.route("/servidores/editar/<int:id>")
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


@bp.route("/servidores/update/<int:id>", methods=["POST"])
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


@bp.route("/logs-nao-cadastrados")
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


@bp.route("/servidores/novo/<nome_log>")
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


@bp.route("/servidores/salvar-detectado", methods=["POST"])
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


@bp.route("/agendamento/add/<int:servidor_id>", methods=["POST"])
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


@bp.route("/agendamento/update/<int:ag_id>", methods=["POST"])
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


@bp.route("/agendamento/delete/<int:ag_id>/<int:servidor_id>", methods=["POST"])
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
