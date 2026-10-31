"""Download da configuracao do agente por cliente (pacotes_agente.py): admin baixa o JSON com os servidores ativos."""
import json
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-pacote-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "")
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db
from main import app
from sessao import hash_password

db = get_db()
admin_id = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES ('adm', ?, 'admin', 1)", (hash_password("x"),)).lastrowid
db.execute(
    "INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) "
    "VALUES ('s1', ?, 'adm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)",
    (admin_id,),
)
cliente = db.execute("INSERT INTO clientes (nome_exibicao, ativo) VALUES ('Cliente Pacote', 1)").lastrowid
db.execute("INSERT INTO servidores (cliente_id, nome_log, backups_semana, ativo) VALUES (?, 'SRV-UM', 7, 1)", (cliente,))
db.execute("INSERT INTO servidores (cliente_id, nome_log, backups_semana, ativo) VALUES (?, 'SRV-INATIVO', 7, 0)", (cliente,))
db.commit()
db.close()

anonimo = app.test_client()
r = anonimo.get(f"/api-keys/config/cliente/{cliente}")
assert r.status_code == 302 and "/login" in r.headers["Location"]

http = app.test_client()
with http.session_transaction() as s:
    s.update(user_id=admin_id, username="adm", tipo="admin", session_id="s1")
r = http.get(f"/api-keys/config/cliente/{cliente}")
assert r.status_code == 200 and r.mimetype == "application/json", (r.status_code, r.get_data(as_text=True)[:200])
assert "attachment" in r.headers["Content-Disposition"] and "cliente_pacote" in r.headers["Content-Disposition"].lower()
jobs = json.loads(r.get_data(as_text=True))["jobs"]
assert [j["servidor_log"] for j in jobs] == ["SRV-UM"], jobs
assert http.get("/api-keys/config/cliente/9999").status_code == 404
print("OK: configuracao do agente por cliente")
