"""Incidente de infraestrutura que continua aberto gera lembrete a cada 24 h.

Antes o tecnico recebia UMA mensagem na hora da queda (ex.: FAE AUTO PECAS, 22/09 04:26, de madrugada)
e nunca mais: firewall fora do ar por um mes ficava esquecido.
Rodar: PYTHONPATH=app:worker python tests/test_infra_incident_reminder.py
"""
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-reminder-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "")
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db, init_db
from secret_store import encrypt_secret
from infrastructure_notifications import process_infrastructure_notifications

init_db()
db = get_db()
user_id = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo, is_technician) VALUES ('tec', 'x', 'admin', 1, 1)").lastrowid
db.execute(
    "INSERT INTO helpdesk_staff_notifications (user_id, telefone, notify_pfsense, ativo) VALUES (?, '5511999999999', 1, 1)",
    (user_id,),
)
db.execute("UPDATE ticketz_config SET ativo=1, token_enc=? WHERE id=1", (encrypt_secret("t"),))
firewall_id = db.execute(
    "INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, last_status) "
    "VALUES ('FW Esquecido', '192.0.2.30', 'x', 'fp', 1, 'online')"
).lastrowid
db.commit()
db.close()


def mensagens(tipo):
    d = get_db()
    linhas = [r["body"] for r in d.execute("SELECT body FROM notification_outbox WHERE event_type=? ORDER BY id", (tipo,)).fetchall()]
    d.close()
    return linhas


def firewall_cai():
    d = get_db()
    d.execute("UPDATE pfsense_firewalls SET last_status='error', last_error='timed out' WHERE id=?", (firewall_id,))
    d.commit()
    d.close()


t0 = datetime(2026, 9, 22, 4, 0, 0)
process_infrastructure_notifications(t0)                          # 1a leitura: so registra o estado
firewall_cai()
process_infrastructure_notifications(t0 + timedelta(minutes=1))   # 1a confirmacao
process_infrastructure_notifications(t0 + timedelta(minutes=2))   # 2a confirmacao -> incidente
assert len(mensagens("internal_infrastructure_incident")) == 1
assert mensagens("internal_infrastructure_reminder") == []

process_infrastructure_notifications(t0 + timedelta(hours=23))    # ainda dentro das 24 h
assert mensagens("internal_infrastructure_reminder") == [], "nao deve lembrar antes de 24 h"

process_infrastructure_notifications(t0 + timedelta(hours=25))    # passou de 24 h
lembretes = mensagens("internal_infrastructure_reminder")
assert len(lembretes) == 1, lembretes
assert "FW Esquecido" in lembretes[0] and "continua" in lembretes[0].lower()

process_infrastructure_notifications(t0 + timedelta(hours=26))    # logo depois: nada novo
assert len(mensagens("internal_infrastructure_reminder")) == 1, "nao repetir lembrete antes de mais 24 h"

process_infrastructure_notifications(t0 + timedelta(hours=50))    # +24 h do ultimo lembrete
assert len(mensagens("internal_infrastructure_reminder")) == 2

assert len(mensagens("internal_infrastructure_incident")) == 1, "lembrete nao e um novo incidente"
print("OK: incidente aberto gera lembrete a cada 24 h")
