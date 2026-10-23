"""Login e logout (sem token CSRF no login), sessao unica por usuario e logout que encerra a sessao."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-login-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db
from main import app
from sessao import hash_password

db = get_db()
db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo, max_sessoes) VALUES ('maria', ?, 'admin', 1, 1)", (hash_password("segredo-certo"),))
db.commit()
db.close()

http = app.test_client()
assert http.get("/login").status_code == 200
assert http.get("/favicon.ico").status_code == 302

r = http.post("/login", data={"username": "maria", "senha": "errada"})
assert r.status_code == 200 and "invalidos" in r.get_data(as_text=True)

r = http.post("/login", data={"username": "maria", "senha": "segredo-certo"})
assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard"), (r.status_code, r.headers.get("Location"))
assert http.get("/dashboard").status_code == 200

# limite de 1 login simultaneo: segundo navegador e recusado
outro = app.test_client()
r = outro.post("/login", data={"username": "maria", "senha": "segredo-certo"})
assert r.status_code == 200 and "Limite de 1 login" in r.get_data(as_text=True)

# logout encerra a sessao e libera novo login
assert http.get("/logout").status_code == 302
assert http.get("/dashboard").status_code == 302
r = outro.post("/login", data={"username": "maria", "senha": "segredo-certo"})
assert r.status_code == 302
print("OK: login e logout")
