"""Relatorio tecnico de internet gerado sozinho: toda semana, para cada firewall com links, e guardado em pfsense_reports.
O HTML guardado e a pagina completa (CSS e graficos embutidos), entao abre igual depois, mesmo que os dados mudem."""
import json
from datetime import datetime, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from relatorio_dados import BRT, coletar_dados
from relatorio_pagina import contexto_pagina
from relatorio_tecnico import montar_relatorio

HORA_DE_GERAR = 7  # segunda-feira, depois das 7h (Brasilia)
_ambiente = Environment(loader=FileSystemLoader(str(Path(__file__).resolve().parent / "templates")), autoescape=True)


def agora_brt():
    return datetime.now(BRT).replace(tzinfo=None, second=0, microsecond=0)


def semana_anterior(agora):
    """(inicio, fim) da semana que acabou: de segunda 00:00 ate domingo 23:59, e o inicio da semana atual."""
    segunda_atual = (agora - timedelta(days=agora.weekday())).replace(hour=0, minute=0)
    return segunda_atual - timedelta(days=7), segunda_atual - timedelta(minutes=1), segunda_atual


def renderizar(dados, dias_periodo=7, voltar=None):
    relatorio = montar_relatorio(dados)
    return _ambiente.get_template("pfsense_tech_report.html").render(**contexto_pagina(relatorio, dias_periodo, voltar)), relatorio


def resumo_json(relatorio):
    return json.dumps({
        "kpis": relatorio["kpis"], "situacao": [{"item": n, "cor": c, "texto": t} for n, c, t in relatorio["situacao"]],
        "criticos": [d["titulo"] for d in relatorio["diagnosticos"] if d["sev"] == "critico"],
        "acoes": len(relatorio["plano"]),
    }, ensure_ascii=False)


def gerar_e_guardar(db, firewall_id, inicio, fim, tipo="semanal", emitido_em=None):
    """Gera o relatorio do periodo e grava. Devolve o id, ou None se o firewall nao existe ou nao tem links."""
    dados = coletar_dados(db, firewall_id, inicio, fim, emitido_em=emitido_em or agora_brt())
    if dados is None or not dados["links"]:
        return None
    html, relatorio = renderizar(dados, 7)
    utc = lambda d: d.strftime("%Y-%m-%d %H:%M:%S")
    cursor = db.execute(
        "INSERT INTO pfsense_reports (firewall_id, period_start, period_end, kind, generated_at, summary, html) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (firewall_id, utc(inicio), utc(fim), tipo, utc(dados["emitido_em"]), resumo_json(relatorio), html),
    )
    db.commit()
    return cursor.lastrowid


def run_due_weekly_reports(db, agora=None):
    """Chamado pelo worker: na segunda-feira (depois das 7h) ou no primeiro ciclo depois disso, gera o da semana anterior
    para cada firewall ativo que ainda nao tem. Devolve a lista de (firewall_id, id_do_relatorio)."""
    agora = agora or agora_brt()
    inicio, fim, segunda_atual = semana_anterior(agora)
    if agora < segunda_atual.replace(hour=HORA_DE_GERAR):
        return []
    gerados = []
    for firewall in db.execute(
        "SELECT f.id FROM pfsense_firewalls f WHERE f.active=1 AND EXISTS (SELECT 1 FROM pfsense_links l WHERE l.firewall_id=f.id AND l.active=1) ORDER BY f.id"
    ).fetchall():
        ja_tem = db.execute("SELECT 1 FROM pfsense_reports WHERE firewall_id=? AND kind='semanal' AND period_start=?",
                            (firewall["id"], inicio.strftime("%Y-%m-%d %H:%M:%S"))).fetchone()
        if ja_tem:
            continue
        try:
            novo = gerar_e_guardar(db, firewall["id"], inicio, fim, "semanal", agora)
        except Exception as erro:  # noqa: BLE001 - um firewall com problema nao pode impedir os outros
            print(f"Relatorio semanal do firewall {firewall['id']}: {erro}", flush=True)
            continue
        if novo:
            gerados.append((firewall["id"], novo))
    return gerados
