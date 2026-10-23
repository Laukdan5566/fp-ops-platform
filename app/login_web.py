"""Entrada e saida do painel: login com limite de sessoes simultaneas, logout e favicon."""
from flask import Blueprint, redirect, render_template, request, session

from db import get_db
from sessao import criar_sessao_usuario, hash_password, limpar_sessoes_expiradas, verify_password
from util import agora_sql


bp = Blueprint("login_web", __name__)


@bp.route("/login", methods=["GET", "POST"])
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


@bp.route("/logout")
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


@bp.route("/favicon.ico")
def favicon():
    return redirect("/static/favicon.svg")
