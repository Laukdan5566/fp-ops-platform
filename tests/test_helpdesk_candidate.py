import hashlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet


temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-helpdesk-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("DB_PATH", str(temp_dir / "test.db"))
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db
from main import app, hash_password
from secret_store import encrypt_secret


db = get_db()
user_id = db.execute(
    "INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES (?, ?, 'admin', 1)",
    ("test-admin", hash_password("unused")),
).lastrowid
client_id = db.execute(
    "INSERT INTO clientes (nome_exibicao, ativo) VALUES (?, 1)", ("Cliente Teste",)
).lastrowid
contact_id = db.execute(
    """
    INSERT INTO cliente_contatos (cliente_id, nome, telefone, whatsapp_enabled, ativo)
    VALUES (?, 'Contato Teste', '5511999999999', 1, 1)
    """,
    (client_id,),
).lastrowid
db.commit()
db.close()

http = app.test_client()
with http.session_transaction() as sess:
    sess["user_id"] = user_id
    sess["username"] = "test-admin"
    sess["tipo"] = "admin"
    sess["session_id"] = "test-session"
    sess["helpdesk_csrf_token"] = "csrf-test"

db = get_db()
db.execute(
    """
    INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo)
    VALUES ('test-session', ?, 'test-admin', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)
    """,
    (user_id,),
)
db.commit()
db.close()

for path in (
    "/dashboard", "/search?q=Cliente", "/", "/backups", "/disponibilidade",
    "/pfsense", "/windows-events", "/status", "/helpdesk", "/helpdesk/new",
    "/helpdesk/contacts", "/helpdesk/reminders", "/helpdesk/settings",
):
    response = http.get(path)
    assert response.status_code == 200, (path, response.get_data(as_text=True))

dashboard_body = http.get("/dashboard").get_data(as_text=True)
assert "Central de operações" in dashboard_body
assert "Visão por módulo" in dashboard_body
assert app.jinja_env.filters["br_datetime"]("2026-09-12 03:00:00") == "12/09/2026 00:00"

menu_body = http.get("/helpdesk").get_data(as_text=True)
assert "Relatórios e logs" in menu_body
assert "Administração" in menu_body
assert "Configurações" in menu_body
assert "Zammad (legado)" in menu_body
assert 'id="sidebarPinButton"' in menu_body
assert "fpOpsSidebarPinned" in menu_body

generated = http.post(
    "/helpdesk/settings/integration-token",
    data={"_csrf_token": "csrf-test", "nome": "Token descartavel"},
)
assert generated.status_code == 200
generated_body = generated.get_data(as_text=True)
assert "Copie agora" in generated_body
with http.session_transaction() as sess:
    assert "helpdesk_new_integration_token" not in sess
db = get_db()
generated_hash = db.execute(
    "SELECT token_hash FROM integration_tokens WHERE nome='Token descartavel'"
).fetchone()["token_hash"]
assert generated_hash not in generated_body
assert "Token descartavel" in generated_body
db.close()

created = http.post(
    "/helpdesk/tickets",
    data={
        "_csrf_token": "csrf-test",
        "cliente_id": str(client_id),
        "requester_contact_id": str(contact_id),
        "assunto": "Teste manual",
        "descricao": "Validacao do helpdesk",
        "categoria": "support",
        "prioridade": "normal",
    },
)
assert created.status_code == 302
assert "/helpdesk/tickets/" in created.headers["Location"]

raw_token = "ticketz-test-token"
db = get_db()
db.execute(
    """
    INSERT INTO integration_tokens (nome, token_hash, scopes, ativo)
    VALUES ('Ticketz teste', ?, 'tickets:create', 1)
    """,
    (hashlib.sha256(raw_token.encode()).hexdigest(),),
)
db.execute(
    """
    UPDATE ticketz_config SET ativo=1, token_enc=?, notify_ticket_opened=1 WHERE id=1
    """,
    (encrypt_secret("outbound-test-token"),),
)
db.commit()
db.close()

recipient_saved = http.post(
    "/helpdesk/reminders/recipients",
    data={
        "_csrf_token": "csrf-test",
        "user_id": str(user_id),
        "telefone": "5511888888888",
        "notify_unassigned": "1",
        "notify_own": "1",
    },
)
assert recipient_saved.status_code == 302
config_saved = http.post(
    "/helpdesk/reminders/config",
    data={
        "_csrf_token": "csrf-test",
        "ativo": "1",
        "unassigned_initial_minutes": "30",
        "reminder_interval_minutes": "180",
        "daily_limit": "3",
        "business_start_hour": "8",
        "business_end_hour": "18",
        "weekdays_only": "1",
        "base_url": "https://ops.example.test",
    },
)
assert config_saved.status_code == 302

payload = {
    "source_ticket_id": "1845",
    "source_ticket_uuid": "example-uuid",
    "company_id": "1",
    "client_id": client_id,
    "opened_by": {"external_id": "27", "name": "Joao Ticketz"},
    "requester": {"name": "Contato Teste", "number": "5511999999999"},
    "subject": "Servidor indisponivel",
    "description": "Chamado criado pelo atendimento",
    "priority": "high",
    "category": "server",
    "source_url": "https://chat.example.test/tickets/example-uuid",
    "messages": [{"author": "Cliente", "body": "Nao consigo acessar"}],
}
headers = {"Authorization": f"Bearer {raw_token}"}
api_created = http.post("/api/v1/integrations/ticketz/tickets", json=payload, headers=headers)
assert api_created.status_code == 201, api_created.get_data(as_text=True)
api_result = api_created.get_json()
assert api_result["created"] is True
assert api_result["number"].startswith("HD-")

duplicate = http.post("/api/v1/integrations/ticketz/tickets", json=payload, headers=headers)
assert duplicate.status_code == 200
assert duplicate.get_json()["created"] is False
assert duplicate.get_json()["ticket_id"] == api_result["ticket_id"]

db = get_db()
ticket = db.execute("SELECT * FROM helpdesk_tickets WHERE id=?", (api_result["ticket_id"],)).fetchone()
assert ticket["opened_by_type"] == "ticketz_user"
assert ticket["opened_by_external_id"] == "27"
assert ticket["opened_by_name"] == "Joao Ticketz"
assert ticket["requester_contact_id"] == contact_id
assert db.execute("SELECT COUNT(*) AS c FROM external_ticket_links").fetchone()["c"] == 1
assert db.execute("SELECT COUNT(*) AS c FROM notification_outbox WHERE status='pending'").fetchone()["c"] == 2
internal_opened = db.execute("SELECT * FROM notification_outbox WHERE event_type='internal_ticket_opened'").fetchone()
assert internal_opened and internal_opened["recipient"] == "5511888888888"
db.close()

import worker.ticketz_notifications as notifications

notifications.send_text = lambda config, token, recipient, body, **kwargs: 200
result = notifications.process_notification_outbox()
assert result == {"sent": 2, "error": 0}
db = get_db()
assert db.execute("SELECT COUNT(*) AS c FROM notification_outbox WHERE status='sent'").fetchone()["c"] == 2
db.execute("UPDATE helpdesk_tickets SET created_at='2026-09-11 05:00:00', updated_at='2026-09-11 05:00:00'")
db.commit()
db.close()

from worker.helpdesk_reminders import queue_internal_reminders

reminders = queue_internal_reminders(datetime(2026, 9, 11, 13, 0, 0, tzinfo=timezone.utc))
assert reminders == {"queued": 1, "recipients": 1, "tickets": 2}
duplicate_reminder = queue_internal_reminders(datetime(2026, 9, 11, 10, 1, 0))
assert duplicate_reminder["queued"] == 0
assert queue_internal_reminders(datetime(2026, 9, 11, 13, 1, 0))["queued"] == 1
assert queue_internal_reminders(datetime(2026, 9, 11, 16, 2, 0))["queued"] == 1
db = get_db()
digest = db.execute("SELECT * FROM notification_outbox WHERE event_type='internal_reminder_digest'").fetchone()
assert digest
assert digest["recipient"] == "5511888888888"
assert "2 chamado(s)" in digest["body"]
assert "ops.example.test/helpdesk" in digest["body"]
assert db.execute("SELECT COUNT(*) AS c FROM notification_outbox WHERE event_type='internal_reminder_digest'").fetchone()["c"] == 3
db.execute("UPDATE helpdesk_reminder_config SET business_end_hour=24")
db.commit()
db.close()
assert queue_internal_reminders(datetime(2026, 9, 11, 19, 3, 0))["queued"] == 0
assert queue_internal_reminders(datetime(2026, 9, 12, 10, 0, 0))["queued"] == 0
result = notifications.process_notification_outbox()
assert result == {"sent": 3, "error": 0}

print("helpdesk-candidate-ok")
