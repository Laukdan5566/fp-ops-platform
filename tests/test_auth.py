"""Decoradores compartilhados de acesso (auth.py): sem login vai para /login; papel errado recebe 403 "Acesso negado"."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from flask import Flask, session

from auth import admin_required, login_required, support_required

app = Flask(__name__)
app.secret_key = "teste"


@app.route("/logado")
@login_required
def logado():
    return "ok"


@app.route("/admin")
@admin_required
def admin():
    return "ok"


@app.route("/suporte")
@support_required
def suporte():
    return "ok"


cliente = app.test_client()
r = cliente.get("/logado")
assert r.status_code == 302 and r.headers["Location"].endswith("/login")

for tipo, admin_ok, suporte_ok in (("admin", True, True), ("operador", False, True), ("leitor", False, False)):
    with cliente.session_transaction() as s:
        s.update(user_id=1, tipo=tipo)
    assert cliente.get("/logado").status_code == 200
    r = cliente.get("/admin")
    assert (r.status_code == 200) == admin_ok, (tipo, r.status_code)
    if not admin_ok:
        assert r.status_code == 403 and "Acesso negado" in r.get_data(as_text=True)
    assert (cliente.get("/suporte").status_code == 200) == suporte_ok, tipo
print("OK: decoradores de acesso")
