"""API dos agentes (api_agentes.py): sem chave 401; chave de outro cliente 403; heartbeat e log de backup entram no banco."""
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-apiag-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "")
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
# chave de outro cliente nao fala por este servidor
assert http.post("/api/agent/heartbeat", json={"servidor_log": "SRV-API"}, headers={"Authorization": "Bearer token-alheio"}).status_code == 403

# batimento valido grava e devolve a versao atual do agente
r = http.post("/api/agent/heartbeat", json={"servidor_log": "srv-api", "hostname": "srv-api", "agent_version": "1.0.0"}, headers=auth)
assert r.status_code == 200, (r.status_code, r.get_data(as_text=True))
db = get_db()
assert db.execute("SELECT COUNT(*) AS c FROM agent_heartbeats WHERE UPPER(servidor_log)='SRV-API'").fetchone()["c"] == 1
db.close()

# historico enxuto: batimentos seguidos (o agente manda a cada ~45 s) viram 1 linha; mudar o status grava na hora
def linhas_historico():
    d = get_db()
    try:
        return d.execute("SELECT COUNT(*) AS c FROM agent_heartbeat_history WHERE UPPER(servidor_log)='SRV-API'").fetchone()["c"]
    finally:
        d.close()

assert linhas_historico() == 1
for _ in range(3):
    assert http.post("/api/agent/heartbeat", json={"servidor_log": "srv-api", "agent_version": "1.0.0"}, headers=auth).status_code == 200
assert linhas_historico() == 1, "batimentos seguidos nao devem gerar linhas novas"
assert http.post("/api/agent/heartbeat", json={"servidor_log": "srv-api", "status": "warning"}, headers=auth).status_code == 200
assert linhas_historico() == 2, "mudanca de status precisa ser registrada"
db = get_db()
db.execute("UPDATE agent_heartbeat_history SET seen_at='2000-01-01 00:00:00'")  # passou o intervalo minimo
db.commit(); db.close()
assert http.post("/api/agent/heartbeat", json={"servidor_log": "srv-api", "status": "warning"}, headers=auth).status_code == 200
assert linhas_historico() == 3

# o tempo online calculado com o historico enxuto e igual ao do historico completo (1 sinal a cada 45 s por 3 h, com 40 min de queda)
from datetime import datetime, timedelta  # noqa: E402
from api_agentes import HISTORICO_INTERVALO_MIN_S  # noqa: E402
from monitoramento import calcular_uptime_por_eventos, calcular_streak_agent  # noqa: E402
inicio = datetime(2026, 10, 30, 8, 0, 0)
completo = []
for i in range(0, 3 * 3600, 45):
    quando = inicio + timedelta(seconds=i)
    if not (timedelta(minutes=60) <= quando - inicio < timedelta(minutes=100)):
        completo.append({"seen_at": quando.strftime("%Y-%m-%d %H:%M:%S"), "status": "online"})
enxuto, ultimo = [], None
for ev in completo:
    atual = datetime.strptime(ev["seen_at"], "%Y-%m-%d %H:%M:%S")
    if ultimo is None or (atual - ultimo).total_seconds() >= HISTORICO_INTERVALO_MIN_S:
        enxuto.append(ev)
        ultimo = atual
assert len(enxuto) < len(completo) / 4
fim = inicio + timedelta(hours=3)
a, b = calcular_uptime_por_eventos(completo, inicio, fim), calcular_uptime_por_eventos(enxuto, inicio, fim)
assert abs(a["online_min"] - b["online_min"]) <= 5 and abs(a["percentual"] - b["percentual"]) < 3, (a, b)
assert calcular_streak_agent(completo, fim)["estado"] == calcular_streak_agent(enxuto, fim)["estado"] == "online"

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
