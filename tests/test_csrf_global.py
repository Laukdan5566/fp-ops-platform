import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet


temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-csrf-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("DB_PATH", str(temp_dir / "test.db"))
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db
from main import app, hash_password


db = get_db()
user_id = db.execute(
    "INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES (?, ?, 'admin', 1)",
    ("csrf-admin", hash_password("unused")),
).lastrowid
client_id = db.execute("INSERT INTO clientes (nome_exibicao, ativo) VALUES ('Cliente CSRF', 1)").lastrowid
db.execute(
    "INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) "
    "VALUES ('csrf-session', ?, 'csrf-admin', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)",
    (user_id,),
)
db.commit()
db.close()

http = app.test_client()
with http.session_transaction() as sess:
    sess.update(user_id=user_id, username="csrf-admin", tipo="admin", session_id="csrf-session")

# Renderizar uma pagina gera o token de sessao usado pelos formularios.
page = http.get("/")
assert page.status_code == 200
assert 'data-post="/clientes/toggle/%d"' % client_id in page.get_data(as_text=True)
with http.session_transaction() as sess:
    token = sess["helpdesk_csrf_token"]

# Acoes destrutivas nao aceitam mais GET.
assert http.get("/clientes/delete/%d" % client_id).status_code == 405
assert http.get("/clientes/toggle/%d" % client_id).status_code == 405

# POST sem token e recusado e nada muda.
assert http.post("/clientes/toggle/%d" % client_id).status_code == 400
assert http.post("/clientes/toggle/%d" % client_id, data={"_csrf_token": "errado"}).status_code == 400
db = get_db()
assert db.execute("SELECT ativo FROM clientes WHERE id=?", (client_id,)).fetchone()["ativo"] == 1
db.close()

# POST com token (campo ou cabecalho) funciona.
assert http.post("/clientes/toggle/%d" % client_id, data={"_csrf_token": token}).status_code == 302
db = get_db()
assert db.execute("SELECT ativo FROM clientes WHERE id=?", (client_id,)).fetchone()["ativo"] == 0
db.close()
assert http.post("/clientes/toggle/%d" % client_id, headers={"X-CSRF-Token": token}).status_code == 302

# Endpoints de API (token de maquina) continuam fora do CSRF de navegador.
assert http.post("/api/logs/exists", json={}).status_code != 400

print("csrf-global-ok")
