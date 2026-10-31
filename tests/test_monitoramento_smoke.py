"""Paineis de monitoramento (monitoramento.py): abrem com dados reais minimos (cliente, servidor, log, batimento, firewall)."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-monit-test-"))
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
adm = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES ('adm', ?, 'admin', 1)", (hash_password("x"),)).lastrowid
db.execute("INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) VALUES ('s1', ?, 'adm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)", (adm,))
cliente = db.execute("INSERT INTO clientes (nome_exibicao, ativo) VALUES ('Cliente Painel', 1)").lastrowid
db.execute("INSERT INTO servidores (cliente_id, nome_log, backups_semana, ativo) VALUES (?, 'SRV-PAINEL', 7, 1)", (cliente,))
db.execute("INSERT INTO agent_heartbeats (servidor_log, hostname, status, last_seen) VALUES ('SRV-PAINEL', 'srv', 'online', CURRENT_TIMESTAMP)")
db.execute("INSERT INTO logs_email (servidor_log, status, data_email, conteudo_raw, message_id) VALUES ('SRV-PAINEL', 'success', '2026-10-23 03:00:00', 'Backup concluido', 'p1')")
db.execute("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, last_status) VALUES ('FW Painel', '192.0.2.70', 'x', 'fp', 1, 'online')")
db.commit()
db.close()

anonimo = app.test_client()
http = app.test_client()
with http.session_transaction() as s:
    s.update(user_id=adm, username="adm", tipo="admin", session_id="s1")

PAGINAS = ("/dashboard", "/backups", "/disponibilidade", "/tempo-online", "/tempo-online/relatorio", "/historico", "/servidor/SRV-PAINEL", "/status", "/windows-events")
for url in PAGINAS:
    r = anonimo.get(url)
    assert r.status_code == 302 and "/login" in r.headers["Location"], (url, r.status_code)
    r = http.get(url)
    if url == "/tempo-online":  # pagina antiga: redireciona para /disponibilidade
        assert r.status_code == 302 and r.headers["Location"].endswith("/disponibilidade"), r.status_code
        continue
    assert r.status_code == 200, (url, r.status_code)
assert "Cliente Painel" in http.get("/dashboard").get_data(as_text=True) or "SRV-PAINEL" in http.get("/backups").get_data(as_text=True)
print("OK: paineis de monitoramento")
