import os
import secrets
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask import Flask, redirect, request, session

from db import get_db, init_db
from sessao import sessao_atual_valida


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


@app.before_request
def preparar_requisicao():
    """Valida a sessao e o token CSRF de toda requisicao de navegador (a API dos agentes usa chave propria)."""
    endpoint = request.endpoint or ""
    if endpoint.startswith("static") or endpoint in ("login_web.login", "login_web.favicon"):
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


# Telas e APIs ficam em modulos proprios; aqui so se monta o aplicativo.
init_db()
from admin_web import bp as admin_web_bp  # noqa: E402
from api_agentes import bp as api_agentes_bp  # noqa: E402
from cadastros import bp as cadastros_bp  # noqa: E402
from helpdesk import bp as helpdesk_bp  # noqa: E402
from login_web import bp as login_web_bp  # noqa: E402
from monitoramento import bp as monitoramento_bp  # noqa: E402
from pacotes_agente import bp as pacotes_agente_bp  # noqa: E402
from pfsense_web import bp as pfsense_web_bp  # noqa: E402

for modulo in (login_web_bp, cadastros_bp, monitoramento_bp, admin_web_bp, pacotes_agente_bp, api_agentes_bp, pfsense_web_bp, helpdesk_bp):
    app.register_blueprint(modulo)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
