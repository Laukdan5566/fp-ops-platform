"""As telas de pfSense (modulo pfsense_web.py) abrem logado como admin e pedem login quando deslogado."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-pfweb-test-"))
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
user_id = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES ('adm', ?, 'admin', 1)", (hash_password("x"),)).lastrowid
db.execute(
    "INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) "
    "VALUES ('s1', ?, 'adm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)",
    (user_id,),
)
firewall_id = db.execute(
    "INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, last_status) "
    "VALUES ('FW Smoke', '192.0.2.60', 'x', 'fp', 1, 'online')"
).lastrowid
db.commit()
db.close()

anonimo = app.test_client()
for url in ("/pfsense", "/pfsense/new", "/pfsense/storage", f"/pfsense/{firewall_id}"):
    r = anonimo.get(url)
    assert r.status_code == 302 and "/login" in r.headers["Location"], (url, r.status_code)

http = app.test_client()
with http.session_transaction() as s:
    s.update(user_id=user_id, username="adm", tipo="admin", session_id="s1")
for url in ("/pfsense", "/pfsense/new", "/pfsense/storage", f"/pfsense/{firewall_id}", f"/pfsense/{firewall_id}/internet-report"):
    r = http.get(url)
    assert r.status_code == 200, (url, r.status_code)
assert "FW Smoke" in http.get("/pfsense").get_data(as_text=True)

# relatorio tecnico de internet: abre mesmo sem dados coletados, aceita periodo, baixa HTML e pede login
rel = f"/pfsense/{firewall_id}/relatorio-tecnico"
assert anonimo.get(rel).status_code == 302
r = http.get(rel)
pagina = r.get_data(as_text=True)
assert r.status_code == 200 and "Diagnóstico da conexão de internet" in pagina and "FW Smoke" in pagina, r.status_code
assert http.get(rel + "?days=30").status_code == 200 and http.get(rel + "?days=abc").status_code == 200
assert http.get(rel + "?inicio=2026-10-26&fim=2026-10-30").status_code == 200
assert http.get(rel + "?inicio=2020-01-01&fim=2026-10-30").status_code == 200  # periodo longo demais: cai no padrao
baixar = http.get(rel + "?download=1")
assert baixar.status_code == 200 and "attachment" in baixar.headers["Content-Disposition"] and ".html" in baixar.headers["Content-Disposition"]
assert http.get("/pfsense/99999/relatorio-tecnico").status_code == 404
print("OK: telas de pfSense abrem")
