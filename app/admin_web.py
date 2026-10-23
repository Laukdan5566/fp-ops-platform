"""Administracao: usuarios e sessoes, retencao, chaves de API, integracao Zammad e configuracao de e-mail."""
import secrets

from flask import Blueprint, redirect, render_template, request, session

from auth import admin_required, login_required
from db import get_db
from retencao import executar_retencao, retention_config
from sessao import hash_password, limpar_sessoes_expiradas
from util import agora_sql, hash_token, normalizar_servidor


bp = Blueprint("admin_web", __name__)


@bp.route("/admin")
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


@bp.route("/admin/users/add", methods=["POST"])
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


@bp.route("/admin/users/<int:user_id>/update", methods=["POST"])
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


@bp.route("/admin/users/<int:user_id>/sessions/clear", methods=["POST"])
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


@bp.route("/admin/retention/save", methods=["POST"])
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


@bp.route("/admin/retention/run", methods=["POST"])
@login_required
@admin_required
def admin_run_retention():
    executar_retencao(manual=True)
    return redirect("/admin")


@bp.route("/admin/retencao")
@login_required
@admin_required
def retencao_resumo():
    """Visao unica das regras de retencao: logs do banco, backups de firewall (disco) e FTP. Edicao fica nas telas de origem."""
    db = get_db()
    try:
        config = retention_config(db)
        ultima_execucao = db.execute("""
            SELECT started_at, finished_at, status, detail FROM maintenance_runs
            WHERE action='retention' ORDER BY id DESC LIMIT 1
        """).fetchone()
        firewalls = db.execute("""
            SELECT f.id, f.name, f.backup_retention_days, COUNT(b.id) AS total,
                   MIN(b.created_at) AS mais_antigo, MAX(b.created_at) AS mais_novo
            FROM pfsense_firewalls f LEFT JOIN pfsense_backups b ON b.firewall_id=f.id
            WHERE f.active=1 GROUP BY f.id, f.name, f.backup_retention_days ORDER BY f.name
        """).fetchall()
        storage = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
    finally:
        db.close()
    regras_logs = [
        ("Logs de backup (conteudo completo)", config["logs_full_days"]),
        ("Logs de servidores nao cadastrados", config["unknown_logs_days"]),
        ("Historico do worker", config["worker_runs_days"]),
        ("Alertas do Zammad", config["zammad_alerts_days"]),
        ("Historico de batimentos dos agentes", config["heartbeat_history_days"]),
        ("Sessoes encerradas", config["session_history_days"]),
    ]
    return render_template(
        "retencao_resumo.html", config=config, regras_logs=regras_logs, ultima_execucao=ultima_execucao,
        firewalls=firewalls, storage=storage,
    )


@bp.route("/zammad-config")
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


@bp.route("/zammad-config/save", methods=["POST"])
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


@bp.route("/api-keys")
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


@bp.route("/api-keys/create", methods=["POST"])
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


@bp.route("/api-keys/toggle/<int:key_id>", methods=["POST"])
@login_required
@admin_required
def toggle_api_key(key_id):
    db = get_db()
    key = db.execute("SELECT ativo FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if key:
        db.execute("UPDATE api_keys SET ativo=? WHERE id=?", (0 if key["ativo"] else 1, key_id))
        db.commit()
    return redirect("/api-keys")


@bp.route("/email-config")
@login_required
@admin_required
def email_config():

    db = get_db()
    config = db.execute("SELECT * FROM config_email LIMIT 1").fetchone()

    return render_template("email_config.html", config=config)


@bp.route("/email-config/save", methods=["POST"])
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
