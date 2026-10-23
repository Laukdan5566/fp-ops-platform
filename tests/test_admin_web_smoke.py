"""Telas de administracao (admin_web.py): abrem para admin, negam operador (403) e pedem login quando deslogado."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-admin-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db
from main import app, hash_password

db = get_db()
ids = {}
for nome, tipo in (("adm", "admin"), ("ope", "operador")):
    ids[nome] = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES (?, ?, ?, 1)", (nome, hash_password("x"), tipo)).lastrowid
    db.execute(
        "INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)",
        ("s-" + nome, ids[nome], nome),
    )
db.commit()
db.close()

PAGINAS = ("/admin", "/api-keys", "/zammad-config", "/email-config")

anonimo = app.test_client()
for url in PAGINAS:
    r = anonimo.get(url)
    assert r.status_code == 302 and "/login" in r.headers["Location"], (url, r.status_code)


def logado(nome, tipo):
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(user_id=ids[nome], username=nome, tipo=tipo, session_id="s-" + nome)
    return c


admin = logado("adm", "admin")
for url in PAGINAS:
    r = admin.get(url)
    assert r.status_code == 200, (url, r.status_code)

operador = logado("ope", "operador")
for url in PAGINAS:
    r = operador.get(url)
    assert r.status_code == 403, (url, r.status_code)
print("OK: telas de administracao")
