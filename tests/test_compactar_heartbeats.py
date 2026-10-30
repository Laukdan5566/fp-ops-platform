"""Compactacao do historico de batimentos: tira as linhas repetidas, guarda as mudancas de status e nao muda o tempo online."""
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-compactar-test-"))
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ops"))

from db import get_db, init_db  # noqa: E402
import compactar_heartbeats as c  # noqa: E402

init_db()
db = get_db()
agora = datetime(2026, 10, 30, 12, 0, 0)
inicio = agora - timedelta(hours=6)


def grava(servidor, quando, status):
    db.execute("INSERT INTO agent_heartbeat_history (servidor_log, status, seen_at) VALUES (?, ?, ?)", (servidor, status, quando.strftime("%Y-%m-%d %H:%M:%S")))


# SRV-A: 1 sinal a cada 45 s por 6 h, com uma queda de 40 min (sem sinais) e 3 sinais "warning" no meio
# SRV-B: so sinais esparsos (a cada 20 min) - nada a apagar
quando = inicio
while quando < agora:
    if not (inicio + timedelta(hours=2) <= quando < inicio + timedelta(hours=2, minutes=40)):
        grava("SRV-A", quando, "warning" if inicio + timedelta(hours=4) <= quando < inicio + timedelta(hours=4, seconds=100) else "online")
    quando += timedelta(seconds=45)
quando = inicio
while quando < agora:
    grava("SRV-B", quando, "online")
    quando += timedelta(minutes=20)
db.commit()

total_a = db.execute("SELECT COUNT(*) c FROM agent_heartbeat_history WHERE servidor_log='SRV-A'").fetchone()["c"]
total_b = db.execute("SELECT COUNT(*) c FROM agent_heartbeat_history WHERE servidor_log='SRV-B'").fetchone()["c"]
antes = c.tempo_online(db, agora, horas=6)

# sem --aplicar nao altera nada
total, a_apagar = c.compactar(db, aplicar=False, avisar=lambda _: None)
assert total == total_a + total_b and a_apagar > 0
assert db.execute("SELECT COUNT(*) c FROM agent_heartbeat_history").fetchone()["c"] == total

total, apagadas = c.compactar(db, aplicar=True, avisar=lambda _: None)
assert apagadas == a_apagar
restam_a = db.execute("SELECT COUNT(*) c FROM agent_heartbeat_history WHERE servidor_log='SRV-A'").fetchone()["c"]
assert restam_a < total_a / 5, (restam_a, total_a)  # ~1 por faixa de 5 min (5 h 20 min de sinais = ~64 faixas) + mudancas de status
assert db.execute("SELECT COUNT(*) c FROM agent_heartbeat_history WHERE servidor_log='SRV-B'").fetchone()["c"] == total_b  # esparso: intacto
# toda mudanca de status foi mantida (entra em warning e volta para online)
status = [r["status"] for r in db.execute("SELECT status FROM agent_heartbeat_history WHERE servidor_log='SRV-A' ORDER BY seen_at, id").fetchall()]
assert "warning" in status and status.count("warning") >= 1
assert sum(1 for x, y in zip(status, status[1:]) if x != y) == 2, status  # online->warning->online
# a queda de 40 min continua sendo queda e o tempo online nao mudou (tolerancia de 10 min por sinal)
depois = c.tempo_online(db, agora, horas=6)
assert all(abs(antes[n] - depois[n]) <= 5 for n in antes), (antes, depois)
# rodar de novo nao apaga mais nada
assert c.compactar(db, aplicar=False, avisar=lambda _: None)[1] == 0
db.close()
print("OK: compactacao do historico de batimentos")
