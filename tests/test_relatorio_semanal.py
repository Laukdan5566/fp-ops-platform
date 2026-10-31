"""Relatorio semanal: gera sozinho na segunda depois das 7h (semana anterior), uma vez so, e a tela lista e abre o guardado."""
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-semanal-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "")
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import get_db  # noqa: E402
from main import app  # noqa: E402
from relatorio_semanal import run_due_weekly_reports, semana_anterior  # noqa: E402
from sessao import hash_password  # noqa: E402

# semana anterior de uma terca 03/11/2026: segunda 26/10 00:00 ate domingo 01/11 23:59
ini, fim, segunda = semana_anterior(datetime(2026, 11, 3, 10, 0))
assert (ini, fim, segunda) == (datetime(2026, 10, 26, 0, 0), datetime(2026, 11, 1, 23, 59), datetime(2026, 11, 2, 0, 0)), (ini, fim, segunda)

db = get_db()
com_links = db.execute("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active) VALUES ('Com links', '192.0.2.1', 'x', 'fp', 1)").lastrowid
sem_links = db.execute("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active) VALUES ('Sem links', '192.0.2.2', 'x', 'fp', 1)").lastrowid
inativo = db.execute("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active) VALUES ('Inativo', '192.0.2.3', 'x', 'fp', 0)").lastrowid
for fw in (com_links, inativo):
    db.execute("INSERT INTO pfsense_links (firewall_id, name, provider, interface_key, device_name, gateway_name, active) VALUES (?, 'LINK1', 'L1', 'wan', 'igb0', 'WAN_L1', 1)", (fw,))
db.commit()

# segunda-feira antes das 7h: ainda nao gera
assert run_due_weekly_reports(db, datetime(2026, 11, 2, 6, 59)) == []
# segunda 07:00: gera so para quem esta ativo e tem links
gerados = run_due_weekly_reports(db, datetime(2026, 11, 2, 7, 0))
assert [fw for fw, _ in gerados] == [com_links], gerados
# no mesmo dia (e nos seguintes) nao repete
assert run_due_weekly_reports(db, datetime(2026, 11, 2, 7, 5)) == [] and run_due_weekly_reports(db, datetime(2026, 11, 4, 12, 0)) == []
linha = db.execute("SELECT * FROM pfsense_reports WHERE firewall_id=?", (com_links,)).fetchone()
assert linha["kind"] == "semanal" and linha["period_start"] == "2026-10-26 00:00:00" and linha["period_end"] == "2026-11-01 23:59:00", dict(linha)
assert "Diagnóstico da conexão de internet" in linha["html"] and "Com links" in linha["html"] and "26/10 00:00" in linha["html"], "periodo/cliente fora do HTML guardado"
# na semana seguinte gera de novo
assert [fw for fw, _ in run_due_weekly_reports(db, datetime(2026, 11, 9, 8, 0))] == [com_links]
assert db.execute("SELECT COUNT(*) c FROM pfsense_reports WHERE firewall_id=?", (com_links,)).fetchone()["c"] == 2

user_id = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES ('adm', ?, 'admin', 1)", (hash_password("x"),)).lastrowid
db.execute("INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) VALUES ('s1', ?, 'adm', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)", (user_id,))
db.commit()
primeiro = db.execute("SELECT id FROM pfsense_reports WHERE firewall_id=? ORDER BY id LIMIT 1", (com_links,)).fetchone()["id"]
db.close()

anonimo = app.test_client()
assert anonimo.get(f"/pfsense/{com_links}/relatorios").status_code == 302 and anonimo.get(f"/pfsense/relatorio/{primeiro}").status_code == 302
http = app.test_client()
with http.session_transaction() as s:
    s.update(user_id=user_id, username="adm", tipo="admin", session_id="s1")
lista = http.get(f"/pfsense/{com_links}/relatorios")
assert lista.status_code == 200 and "26/10 a 01/11/2026" in lista.get_data(as_text=True), lista.get_data(as_text=True)[:400]
aberto = http.get(f"/pfsense/relatorio/{primeiro}")
assert aberto.status_code == 200 and "Diagnóstico da conexão de internet" in aberto.get_data(as_text=True)
assert "attachment" in http.get(f"/pfsense/relatorio/{primeiro}?download=1").headers["Content-Disposition"]
assert http.get("/pfsense/relatorio/99999").status_code == 404 and http.get("/pfsense/99999/relatorios").status_code == 404
assert "Ainda não há relatório" in http.get(f"/pfsense/{sem_links}/relatorios").get_data(as_text=True)
print("OK: relatorio semanal gera sozinho na segunda, uma vez, e a tela lista e abre")
