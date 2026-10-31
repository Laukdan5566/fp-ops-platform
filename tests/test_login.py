"""Login e logout (sem token CSRF no login), sessao unica por usuario e logout que encerra a sessao."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-login-test-"))
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

# ---------- limite de tentativas ----------
from datetime import datetime, timedelta  # noqa: E402
import login_limite as ll  # noqa: E402

db = get_db()
db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo, max_sessoes) VALUES ('joao', ?, 'admin', 1, 3)", (hash_password("senha-do-joao"),))
db.commit()
db.close()

# o usuario correto, depois de errar menos que o limite, entra e zera as falhas
tentativa = app.test_client()
for _ in range(ll.LIMITE_POR_USUARIO - 1):
    assert tentativa.post("/login", data={"username": "joao", "senha": "errada"}).status_code == 200
assert tentativa.post("/login", data={"username": "joao", "senha": "senha-do-joao"}).status_code == 302
db = get_db()
assert db.execute("SELECT COUNT(*) c FROM login_falhas WHERE username='joao'").fetchone()["c"] == 0
db.close()
tentativa.get("/logout")

# chegou ao limite: ate a senha CERTA e recusada (429) durante a janela, e o bloqueio nao se estende com novas tentativas
for _ in range(ll.LIMITE_POR_USUARIO):
    assert app.test_client().post("/login", data={"username": "joao", "senha": "errada"}).status_code == 200
r = app.test_client().post("/login", data={"username": "JOAO", "senha": "senha-do-joao"})  # maiusculas contam como o mesmo usuario
assert r.status_code == 429 and "Muitas tentativas" in r.get_data(as_text=True), r.status_code
db = get_db()
assert db.execute("SELECT COUNT(*) c FROM login_falhas WHERE username='joao'").fetchone()["c"] == ll.LIMITE_POR_USUARIO
espera = ll.segundos_bloqueado(db, "joao", "10.0.0.1")
assert 0 < espera <= ll.JANELA_MIN * 60, espera
# passada a janela, libera
futuro = datetime.now() + timedelta(minutes=ll.JANELA_MIN, seconds=5)
assert ll.segundos_bloqueado(db, "joao", "10.0.0.1", agora=futuro) == 0
# outro usuario nao e afetado pelo bloqueio de 'joao'
assert ll.segundos_bloqueado(db, "maria", "10.0.0.1") == 0
# limite por IP: muitos usuarios diferentes da mesma origem
for i in range(ll.LIMITE_POR_IP):
    ll.registrar_falha(db, f"usuario{i}", "203.0.113.9")
assert ll.segundos_bloqueado(db, "qualquer", "203.0.113.9") > 0 and ll.segundos_bloqueado(db, "qualquer", "203.0.113.10") == 0
# falhas velhas sao apagadas
ll.registrar_falha(db, "x", "1.1.1.1", agora=datetime.now() - timedelta(days=5))
ll.registrar_falha(db, "y", "1.1.1.1")
assert db.execute("SELECT COUNT(*) c FROM login_falhas WHERE username='x'").fetchone()["c"] == 0
db.close()

# IP do cliente: atras do proxy interno vale o ultimo item de X-Forwarded-For; de fora, so o endereco da conexao
class Req:
    def __init__(self, remoto, xff=""):
        self.remote_addr, self.headers = remoto, {"X-Forwarded-For": xff} if xff else {}
assert ll.ip_do_cliente(Req("10.11.11.12", "9.9.9.9, 200.1.2.3")) == "200.1.2.3"
assert ll.ip_do_cliente(Req("10.11.11.12", "lixo")) == "10.11.11.12"
assert ll.ip_do_cliente(Req("8.8.4.4", "1.2.3.4")) == "8.8.4.4"  # de fora (IP publico) nao confia no cabecalho
assert ll.ip_do_cliente(Req("127.0.0.1")) == "127.0.0.1"
print("OK: login e logout")
