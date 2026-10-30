"""Agenda do worker: tarefas independentes (uma lenta ou com erro nao atrasa as outras) e deteccao de tarefa travada."""
import os
import tempfile
import threading
import time
from pathlib import Path

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-agenda-test-"))
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")

import agenda  # noqa: E402
from agenda import Tarefa, iniciar  # noqa: E402

# erro em um passo nao impede os seguintes nem derruba a tarefa
vistos = []
def quebra():
    raise RuntimeError("falha de teste")
t = Tarefa("t", [("quebra", quebra), ("segue", lambda: vistos.append(1))], 1)
t.rodar_ciclo(); t.rodar_ciclo()
assert vistos == [1, 1] and t.erros == 2 and t.ciclos == 2 and t.ultimo_ciclo is not None

# tarefa lenta nao atrasa a rapida (antes tudo rodava em fila num laco so)
rapida_vezes, lenta_vezes = [], []
def lenta():
    lenta_vezes.append(1)
    time.sleep(1.2)
rapida = Tarefa("rapida", [("conta", lambda: rapida_vezes.append(time.monotonic()))], 0.05)
devagar = Tarefa("lenta", [("dorme", lenta)], 0.05)
threads, parar = iniciar([devagar, rapida])
time.sleep(1.0)
parar.set()
assert len(lenta_vezes) == 1, "a lenta ainda esta no primeiro ciclo"
assert len(rapida_vezes) >= 8, f"a rapida deveria rodar varias vezes enquanto a lenta dorme: {len(rapida_vezes)}"
for th in threads:
    th.join(timeout=3)
assert not any(th.is_alive() for th in threads)

# tarefa travada: sem ciclo completo por muito mais que o intervalo
t = Tarefa("x", [], 300)
base = time.monotonic()
t.iniciada_em = base
assert not t.parada(base + 60)
assert not t.parada(base + 1199) and t.parada(base + 1201)   # 4 x 300 s
t.ultimo_ciclo = base + 1000
assert not t.parada(base + 1500)
curta = Tarefa("c", [], 5)
curta.iniciada_em = base
assert not curta.parada(base + 599) and curta.parada(base + 601)  # minimo de 10 min

# o worker real monta as tarefas esperadas, com e-mail e alertas separados do SSH dos firewalls
import worker  # noqa: E402
tarefas = {x.nome: x for x in worker.montar_tarefas()}
assert set(tarefas) == {"email", "firewalls", "pedidos-pfsense", "telemetria", "manutencao", "alertas", "lembretes", "fila-whatsapp"}, set(tarefas)
assert all(callable(passo) for x in tarefas.values() for _, passo in x.passos)
nomes_dos_passos = {nome: [rotulo for rotulo, _ in x.passos] for nome, x in tarefas.items()}
assert nomes_dos_passos["email"] == ["e-mails e Zammad"] and nomes_dos_passos["alertas"] == ["alertas de infraestrutura"]
assert tarefas["pedidos-pfsense"].intervalo_s == 5 and tarefas["fila-whatsapp"].intervalo_s == 5

# init_db chamado de varias threads ao mesmo tempo (cada tarefa chama no seu ciclo) nao quebra
from db import init_db  # noqa: E402
erros = []
def chama():
    try:
        init_db()
    except Exception as e:  # noqa: BLE001
        erros.append(e)
ths = [threading.Thread(target=chama) for _ in range(6)]
[th.start() for th in ths]
[th.join() for th in ths]
assert not erros, erros
print("OK: agenda do worker (tarefas independentes, erro isolado, tarefa travada detectada)")
