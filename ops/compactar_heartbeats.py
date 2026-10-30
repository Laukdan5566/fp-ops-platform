"""Compacta agent_heartbeat_history: fica 1 sinal por faixa de 5 min por servidor, mais todo sinal em que o status mudou.

O tempo online (monitoramento.calcular_uptime_por_eventos) conta no maximo 10 min por sinal, entao isso nao muda o resultado;
so tira as linhas repetidas que o agente gerava a cada ~45 s. O script mede o tempo online de cada servidor antes e depois.

Uso (dentro do container web, em /app):
    python ops/compactar_heartbeats.py            # so mostra o que apagaria (nao altera nada)
    python ops/compactar_heartbeats.py --aplicar  # apaga; depois rode VACUUM FULL para devolver o espaco ao disco
"""
import os
import sys
from datetime import datetime, timedelta

sys.path[:0] = [os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."), os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")]

from db import USING_POSTGRES, get_db  # noqa: E402
from monitoramento import calcular_uptime_por_eventos  # noqa: E402

LOTE = 2000
FAIXA = "substr(seen_at, 1, 13) || ':' || CAST(CAST(substr(seen_at, 15, 2) AS INTEGER) / 5 AS TEXT)"
# repetido = nao e o primeiro da faixa de 5 min e o status e igual ao do sinal anterior
SQL_REPETIDOS = f"""
    SELECT id FROM (
        SELECT id, status,
               LAG(status) OVER (ORDER BY seen_at, id) AS anterior,
               ROW_NUMBER() OVER (PARTITION BY {FAIXA} ORDER BY seen_at, id) AS posicao
        FROM agent_heartbeat_history WHERE servidor_log=?
    ) t WHERE posicao > 1 AND anterior = status
"""


def servidores(db):
    return [r["servidor_log"] for r in db.execute("SELECT DISTINCT servidor_log FROM agent_heartbeat_history ORDER BY servidor_log").fetchall()]


def tempo_online(db, agora, horas=720):
    """{servidor: online_min} nas ultimas `horas`, com o mesmo calculo da tela de disponibilidade."""
    inicio = agora - timedelta(hours=horas)
    resultado = {}
    for nome in servidores(db):
        eventos = db.execute(
            "SELECT status, seen_at FROM agent_heartbeat_history WHERE servidor_log=? AND seen_at >= ? ORDER BY seen_at",
            (nome, inicio.strftime("%Y-%m-%d %H:%M:%S")),
        ).fetchall()
        resultado[nome] = calcular_uptime_por_eventos(eventos, inicio, agora)["online_min"]
    return resultado


def compactar(db, aplicar=False, avisar=print):
    """Devolve (total_antes, apagadas). Sem `aplicar`, so conta."""
    total = db.execute("SELECT COUNT(*) AS c FROM agent_heartbeat_history").fetchone()["c"]
    apagadas = 0
    for nome in servidores(db):
        ids = [r["id"] for r in db.execute(SQL_REPETIDOS, (nome,)).fetchall()]
        if aplicar:
            for i in range(0, len(ids), LOTE):
                parte = ids[i:i + LOTE]
                db.execute(f"DELETE FROM agent_heartbeat_history WHERE id IN ({','.join('?' * len(parte))})", parte)
            db.commit()
        apagadas += len(ids)
        avisar(f"  {nome}: {len(ids)} linhas repetidas")
    return total, apagadas


def main(aplicar):
    db = get_db()
    try:
        agora = datetime.now()
        antes = tempo_online(db, agora)
        total, apagadas = compactar(db, aplicar)
        print(f"{'APAGADAS' if aplicar else 'Apagaria'}: {apagadas} de {total} linhas ({apagadas * 100 // max(total, 1)}%)")
        if not aplicar:
            return 0
        depois = tempo_online(db, agora)
        maior = max((abs(antes[n] - depois.get(n, 0)) for n in antes), default=0)
        print(f"Tempo online (30 dias): maior diferenca por servidor = {maior} min")
        if USING_POSTGRES:
            print("Para devolver o espaco ao disco: VACUUM FULL agent_heartbeat_history;")
        return 0 if maior <= 15 else 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main("--aplicar" in sys.argv))
