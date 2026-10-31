"""Tela unica de retencao (/admin/retencao): mostra as 3 regras (logs, backups de firewall local e FTP) e a ultima execucao de cada uma."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-retres-test-"))
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
ope = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES ('ope', ?, 'operador', 1)", (hash_password("x"),)).lastrowid
for uid, nome in ((adm, "adm"), (ope, "ope")):
    db.execute("INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)", ("s-" + nome, uid, nome))
fw = db.execute("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, backup_retention_days) VALUES ('FW Resumo', '192.0.2.80', 'x', 'fp', 1, 30)").lastrowid
for dia in ("2026-09-01", "2026-10-20"):
    db.execute("INSERT INTO pfsense_backups (firewall_id, created_at, config_hash, file_path, status) VALUES (?, ?, 'h', '/x', 'success')", (fw, dia + " 10:00:00"))
db.execute(
    "INSERT INTO pfsense_storage (id, protocol, host, port, username_enc, password_enc, remote_dir, active, retention_enabled, retention_days, last_cleanup_at, last_cleanup_status, last_cleanup_deleted) "
    "VALUES (1, 'ftp', '192.0.2.90', 21, 'x', 'x', '/ftp/___FIREWALLS', 1, 1, 90, '2026-10-22 23:45:32', 'success', 7)"
)
db.execute("INSERT INTO maintenance_runs (action, started_at, finished_at, status, detail) VALUES ('retention', '2026-10-23 01:00:00', '2026-10-23 01:00:05', 'success', 'auto')")
db.commit()
db.close()


def logado(nome, tipo):
    c = app.test_client()
    with c.session_transaction() as s:
        s.update(user_id=adm if nome == "adm" else ope, username=nome, tipo=tipo, session_id="s-" + nome)
    return c


assert app.test_client().get("/admin/retencao").status_code == 302
assert logado("ope", "operador").get("/admin/retencao").status_code == 403

pagina = logado("adm", "admin").get("/admin/retencao").get_data(as_text=True)
assert "FW Resumo" in pagina and "30 dias" in pagina, "regra local por firewall"
assert "2026-09-01" in pagina or "01/09/2026" in pagina, "backup mais antigo do firewall"
assert "90 dias" in pagina and "7 apagado" in pagina and "/ftp/___FIREWALLS" in pagina, "regra do FTP e ultima limpeza"
assert "Logs de backup" in pagina and "90 dias" in pagina, "regra dos logs"
assert "22/10/2026 22:00" in pagina, "ultima execucao dos logs (01:00 UTC = 22:00 em Brasilia)"
print("OK: resumo de retencao")
