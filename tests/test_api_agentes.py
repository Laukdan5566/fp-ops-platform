"""API dos agentes (api_agentes.py): sem chave 401; chave de outro cliente 403; heartbeat e log de backup entram no banco."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-apiag-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db
from main import app
from util import hash_token

db = get_db()
cliente = db.execute("INSERT INTO clientes (nome_exibicao, ativo) VALUES ('Cliente API', 1)").lastrowid
outro = db.execute("INSERT INTO clientes (nome_exibicao, ativo) VALUES ('Outro Cliente', 1)").lastrowid
db.execute("INSERT INTO servidores (cliente_id, nome_log, backups_semana, ativo) VALUES (?, 'SRV-API', 7, 1)", (cliente,))
db.execute("INSERT INTO api_keys (nome, token_hash, cliente_id, ativo) VALUES ('ok', ?, ?, 1)", (hash_token("token-ok"), cliente))
db.execute("INSERT INTO api_keys (nome, token_hash, cliente_id, ativo) VALUES ('alheia', ?, ?, 1)", (hash_token("token-alheio"), outro))
db.commit()
db.close()

app.config["PROPAGATE_EXCEPTIONS"] = True
http = app.test_client()
auth = {"Authorization": "Bearer token-ok"}

assert http.get("/health").status_code == 200

# sem chave / chave errada
assert http.post("/api/agent/heartbeat", json={"servidor_log": "SRV-API"}).status_code == 401
assert http.post("/api/agent/heartbeat", json={"servidor_log": "SRV-API"}, headers={"X-API-Key": "errada"}).status_code == 401
# chave de outro cliente nao fala por este servidor e a recusa fica no log (para achar o agente mal configurado)
import logging


class Captura(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.mensagens = []

    def emit(self, registro):
        self.mensagens.append(registro.getMessage())


captura = Captura()
logging.getLogger("api_agentes").addHandler(captura)
assert http.post("/api/agent/heartbeat", json={"servidor_log": "SRV-API"}, headers={"Authorization": "Bearer token-alheio"}).status_code == 403
assert any("SRV-API" in m and "heartbeat" in m and "chave" in m for m in captura.mensagens), captura.mensagens
assert "token-alheio" not in " ".join(captura.mensagens), "nunca registrar o token"

# batimento valido grava e devolve a versao atual do agente
r = http.post("/api/agent/heartbeat", json={"servidor_log": "srv-api", "hostname": "srv-api", "agent_version": "1.0.0"}, headers=auth)
assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
db = get_db()
assert db.execute("SELECT COUNT(*) AS c FROM agent_heartbeats WHERE UPPER(servidor_log)='SRV-API'").fetchone()["c"] == 1
db.close()

# servidor nao cadastrado: 202 e nao grava batimento
db = get_db()
db.execute("INSERT INTO api_keys (nome, token_hash, ativo) VALUES ('livre', ?, 1)", (hash_token("token-livre"),))
db.commit()
db.close()
assert http.post("/api/agent/heartbeat", json={"servidor_log": "NAO-EXISTE"}, headers={"Authorization": "Bearer token-livre"}).status_code == 202

# log de backup: entra, e repetir o mesmo conteudo e duplicado (nao grava de novo)
corpo = {"servidor_log": "SRV-API", "conteudo_raw": "Backup concluido com sucesso", "data_email": "2026-10-23 10:00:00"}
r = http.post("/api/logs/ingest", json=corpo, headers=auth)
assert r.status_code in (200, 201), (r.status_code, r.get_data(as_text=True))
assert r.get_json().get("status") != "duplicate"
r2 = http.post("/api/logs/ingest", json=corpo, headers=auth)
assert r2.status_code == 200 and r2.get_json()["status"] == "duplicate", r2.get_data(as_text=True)
db = get_db()
assert db.execute("SELECT COUNT(*) AS c FROM logs_email WHERE UPPER(servidor_log)='SRV-API'").fetchone()["c"] == 1
db.close()
assert http.post("/api/logs/ingest", json=corpo, headers={"Authorization": "Bearer token-alheio"}).status_code == 403
print("OK: API dos agentes")
