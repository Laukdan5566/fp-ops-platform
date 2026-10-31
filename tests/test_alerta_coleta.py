"""Alerta ativo de coleta atrasada: tarefa do worker que parou de fechar ciclos e leitura de telemetria sem sucesso ha horas
viram incidente (mesmo caminho dos alertas de firewall/servidor: 2 confirmacoes, aviso, normalizacao).
Rodar: PYTHONPATH=app:worker python tests/test_alerta_coleta.py
"""
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-alerta-coleta-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "")
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

import db as banco
from db import get_db, init_db
from secret_store import encrypt_secret
from infrastructure_notifications import process_infrastructure_notifications

TXT = "%Y-%m-%d %H:%M:%S"
t0 = datetime(2026, 10, 31, 12, 0, 0)

init_db()
db = get_db()
user_id = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo, is_technician) VALUES ('tec', 'x', 'admin', 1, 1)").lastrowid
db.execute("INSERT INTO helpdesk_staff_notifications (user_id, telefone, notify_servers, notify_pfsense, ativo) VALUES (?, '5511999999999', 1, 1, 1)", (user_id,))
db.execute("UPDATE ticketz_config SET ativo=1, token_enc=? WHERE id=1", (encrypt_secret("t"),))
for nome, intervalo in (("firewalls", 300), ("fila-whatsapp", 5)):
    db.execute("INSERT INTO worker_tarefas (nome, intervalo_s, ciclos, erros, ultimo_ciclo_em) VALUES (?, ?, 5, 0, ?)", (nome, intervalo, t0.strftime(TXT)))
fw = db.execute(
    "INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, last_status, telemetry_at, telemetry_ok_at) "
    "VALUES ('FW Coleta', '192.0.2.40', 'x', 'fp', 1, 'online', ?, ?)", (t0.strftime(TXT), t0.strftime(TXT)),
).lastrowid
db.commit()
db.close()


def mensagens(tipo):
    d = get_db()
    try:
        return [r["body"] for r in d.execute("SELECT body FROM notification_outbox WHERE event_type=? ORDER BY id", (tipo,)).fetchall()]
    finally:
        d.close()


def sql(comando, *args):
    parametros = args[0] if len(args) == 1 and isinstance(args[0], tuple) else args  # aceita sql(cmd, a, b) e sql(cmd, (a, b))
    d = get_db()
    d.execute(comando, parametros)
    d.commit()
    d.close()


def avalia(minutos):
    return process_infrastructure_notifications(t0 + timedelta(minutes=minutos))


def mantem_tarefas_em_dia(minutos):
    sql("UPDATE worker_tarefas SET ultimo_ciclo_em=?", (t0 + timedelta(minutes=minutos)).strftime(TXT))


# tudo em dia: nada de aviso (a 1a leitura so registra o estado)
avalia(0)
mantem_tarefas_em_dia(4); avalia(5)
assert mensagens("internal_infrastructure_incident") == []

# tarefa lenta mas dentro do limite (3 x 300 s = 15 min) nao alerta
for minuto in (6, 7):
    sql("UPDATE worker_tarefas SET ultimo_ciclo_em=? WHERE nome='firewalls'", (t0 + timedelta(minutes=minuto) - timedelta(minutes=14)).strftime(TXT))
    avalia(minuto)
assert mensagens("internal_infrastructure_incident") == []

# a tarefa 'firewalls' trava (sem ciclo ha 40 min; a outra segue em dia): 2 confirmacoes -> 1 aviso, citando so a que parou
sql("UPDATE worker_tarefas SET ultimo_ciclo_em=? WHERE nome='firewalls'", (t0 + timedelta(minutes=10) - timedelta(minutes=40)).strftime(TXT))
sql("UPDATE worker_tarefas SET ultimo_ciclo_em=? WHERE nome='fila-whatsapp'", (t0 + timedelta(minutes=10)).strftime(TXT))
avalia(10)
assert mensagens("internal_infrastructure_incident") == [], "1a confirmacao ainda nao avisa"
avalia(11)
avisos = mensagens("internal_infrastructure_incident")
assert len(avisos) == 1 and "Coleta atrasada" in avisos[0] and "firewalls (sem ciclo há" in avisos[0] and "fila-whatsapp" not in avisos[0], avisos
avalia(12)
assert len(mensagens("internal_infrastructure_incident")) == 1, "sem repetir o aviso"

# voltou: mensagem de normalizacao
mantem_tarefas_em_dia(20); avalia(20)
assert len(mensagens("internal_infrastructure_recovered")) == 1 and "Tarefas do worker normalizadas" in mensagens("internal_infrastructure_recovered")[0]

# telemetria: uma falha recente com leitura boa ha 30 min NAO alerta; so passa de 3 h sem leitura boa
sql("UPDATE pfsense_firewalls SET telemetry_error='timed out', telemetry_ok_at=?, telemetry_at=? WHERE id=?",
    (t0 + timedelta(minutes=20) - timedelta(minutes=30), (t0 + timedelta(minutes=20)).strftime(TXT), fw))
mantem_tarefas_em_dia(21); avalia(21); mantem_tarefas_em_dia(22); avalia(22)
assert [m for m in mensagens("internal_infrastructure_incident") if "Leitura de tráfego" in m] == []
sql("UPDATE pfsense_firewalls SET telemetry_ok_at=? WHERE id=?", ((t0 - timedelta(hours=5)).strftime(TXT), fw))
mantem_tarefas_em_dia(30); avalia(30); mantem_tarefas_em_dia(31); avalia(31)
leitura = [m for m in mensagens("internal_infrastructure_incident") if "Leitura de tráfego" in m]
assert len(leitura) == 1 and "FW Coleta" in leitura[0] and "Coleta atrasada" in leitura[0], leitura

# firewall que nao responde ja tem o proprio alerta (pfsense_offline): a telemetria dele nao gera aviso extra
sql("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, last_status, telemetry_at, telemetry_ok_at, telemetry_error) "
    "VALUES ('FW Fora', '192.0.2.41', 'x', 'fp', 1, 'error', ?, ?, 'timed out')", (t0.strftime(TXT), (t0 - timedelta(days=9)).strftime(TXT)))
mantem_tarefas_em_dia(40); avalia(40); mantem_tarefas_em_dia(41); avalia(41)
assert not any("FW Fora" in m and "Leitura de tráfego" in m for m in mensagens("internal_infrastructure_incident"))

# migracao 2: a ultima leitura boa nasce da leitura que ja existia (sem erro) e nao inventa leitura boa onde havia erro
d = get_db()
d.execute("UPDATE pfsense_firewalls SET telemetry_ok_at=NULL")
d.commit()
banco._migracao_telemetry_ok_at(d.cursor())
d.commit()
ok = {r["name"]: r["telemetry_ok_at"] for r in d.execute("SELECT name, telemetry_ok_at FROM pfsense_firewalls").fetchall()}
d.close()
assert ok["FW Coleta"] is None and ok["FW Fora"] is None, ok  # os dois tinham telemetry_error
print("OK: alerta ativo de coleta atrasada (worker e telemetria)")
