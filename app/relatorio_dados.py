"""Monta o `dados` do relatorio tecnico de internet (ver relatorio_tecnico.montar_relatorio) a partir do banco do FP Ops.

O banco guarda horarios em UTC; o relatorio trabalha em Brasilia. Fontes, da mais para a menos confiavel:
- historico de trafego do firewall (pfsense_traffic_hourly) e log de gateways (pfsense_gateway_events), lidos por SSH pelo worker;
- sondas de cada link a cada 5 min e speedtests (pfsense_link_probes / pfsense_link_speedtests);
- historico de verificacoes do firewall (pfsense_checks), de onde saem os reinicios (uptime) e a carga.
Quando o log de gateways nao existe, as oscilacoes saem das sondas (menos detalhe: oscilacao curta pode nao aparecer).
"""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from relatorio_tecnico import LIMITES

BRT = ZoneInfo("America/Sao_Paulo")
PERDA_OSCILACAO_PCT = 15  # sonda com perda a partir disso conta como oscilacao
ALARME_FORA_PCT = 95      # perda a partir disso = link fora do ar


def utc_para_brt(texto):
    if not texto:
        return None
    try:
        bruto = datetime.strptime(str(texto)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return bruto.replace(tzinfo=timezone.utc).astimezone(BRT).replace(tzinfo=None)


def brt_para_utc_texto(dt):
    return dt.replace(tzinfo=BRT).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _expediente(texto):
    try:
        inicio, fim = str(texto or "8-18").split("-")
        return int(inicio), int(fim)
    except ValueError:
        return 8, 18


def _media(valores):
    valores = [v for v in valores if v is not None]
    return sum(valores) / len(valores) if valores else None


def _links(db, firewall_id, ini_utc, fim_utc):
    linhas = db.execute("SELECT * FROM pfsense_links WHERE firewall_id=? AND active=1 ORDER BY id", (firewall_id,)).fetchall()
    links = []
    for linha in linhas:
        link = dict(linha)
        testes = db.execute(
            "SELECT download_mbps, upload_mbps FROM pfsense_link_speedtests WHERE link_id=? AND status='success' "
            "AND datetime(tested_at)>=datetime(?) AND datetime(tested_at)<=datetime(?)", (link["id"], ini_utc, fim_utc),
        ).fetchall()
        if not testes:  # sem teste no periodo: usa os ultimos conhecidos
            testes = db.execute(
                "SELECT download_mbps, upload_mbps FROM pfsense_link_speedtests WHERE link_id=? AND status='success' ORDER BY id DESC LIMIT 3",
                (link["id"],),
            ).fetchall()
        sondas = db.execute(
            "SELECT status, latency_ms, packet_loss_percent FROM pfsense_link_probes WHERE link_id=? "
            "AND datetime(probed_at)>=datetime(?) AND datetime(probed_at)<=datetime(?)", (link["id"], ini_utc, fim_utc),
        ).fetchall()
        online = [s for s in sondas if s["status"] == "online"]
        links.append({
            "id": link["id"], "nome": link["name"], "gateway": link["gateway_name"], "traffic_key": link["traffic_key"] or link["interface_key"],
            "role": link["role"], "preferred": bool(link["preferred"]),
            "down_mbps": _media([t["download_mbps"] for t in testes]), "up_mbps": _media([t["upload_mbps"] for t in testes]),
            "contratado_down_mbps": link["contracted_down_mbps"], "contratado_up_mbps": link["contracted_up_mbps"],
            "entrega_minima_pct": link["minimum_delivery_percent"],
            "latencia_ms": _media([s["latency_ms"] for s in online]), "perda_pct": _media([s["packet_loss_percent"] for s in online]),
        })
    # papeis: o operador define em `role`; sem isso, o link preferencial (tier 1 do failover) e o principal
    if not any(l["role"] for l in links):
        preferido = next((l for l in links if l["preferred"]), links[0] if links else None)
        for l in links:
            l["role"] = "principal" if l is preferido else "reserva"
    for l in links:
        l["funcao"] = l["role"] if l["role"] in ("principal", "reserva") else "reserva"
        l["preferencial"] = l["preferred"]
        if len(links) == 1:
            l["preferencial"] = True
    return links


def _trafego(db, firewall_id, chave, ini_utc, fim_utc):
    return db.execute(
        "SELECT bucket_start, in_avg_bps, out_avg_bps FROM pfsense_traffic_hourly WHERE firewall_id=? AND interface_key=? "
        "AND datetime(bucket_start)>=datetime(?) AND datetime(bucket_start)<=datetime(?) ORDER BY bucket_start",
        (firewall_id, chave, ini_utc, fim_utc),
    ).fetchall()


def _serie_horaria(linhas, inicio, fim, campo="in_avg_bps"):
    """Serie hora a hora (Brasilia) em Mbps, com None onde nao ha dado (aparece como falha no grafico)."""
    por_hora = {}
    for linha in linhas:
        hora = utc_para_brt(linha["bucket_start"])
        if hora is not None and linha[campo] is not None:
            por_hora[hora.replace(minute=0, second=0)] = linha[campo] / 1_000_000
    serie, hora = [], inicio.replace(minute=0, second=0, microsecond=0)
    while hora <= fim:
        serie.append((hora, por_hora.get(hora)))
        hora += timedelta(hours=1)
    return serie


def _redes(db, firewall_id, ini_utc, fim_utc):
    redes = []
    for rede in db.execute("SELECT * FROM pfsense_networks WHERE firewall_id=? AND include_in_report=1 ORDER BY id", (firewall_id,)).fetchall():
        linhas = _trafego(db, firewall_id, rede["interface_key"], ini_utc, fim_utc)
        # download da rede = o que o firewall entregou PARA ela (saida da interface interna)
        bytes_total = sum((l["out_avg_bps"] or 0) * 3600 / 8 for l in linhas)
        redes.append({"nome": rede["name"], "tipo": rede["kind"], "cidr": rede["cidr"], "vlan": rede["vlan"], "gb_down": bytes_total / 1e9})
    return [r for r in redes if r["gb_down"] > 0] if any(r["gb_down"] > 0 for r in redes) else []


def _eventos_do_log(db, firewall_id, links, ini_utc, fim_utc):
    por_gateway = {l["gateway"]: l["nome"] for l in links if l["gateway"]}
    linhas = db.execute(
        "SELECT gateway_name, event_at, kind, loss_percent FROM pfsense_gateway_events WHERE firewall_id=? "
        "AND datetime(event_at)>=datetime(?) AND datetime(event_at)<=datetime(?) ORDER BY event_at, id",
        (firewall_id, ini_utc, fim_utc),
    ).fetchall()
    eventos, abertos, omissoes = [], {}, {}
    for linha in linhas:
        quando = utc_para_brt(linha["event_at"])
        gateway = linha["gateway_name"]
        if linha["kind"] == "alarm":
            abertos[gateway] = (quando, linha["loss_percent"])
        elif linha["kind"] == "omit":
            omissoes.setdefault(gateway, []).append(quando)
        elif linha["kind"] == "clear" and gateway in abertos:
            inicio, perda = abertos.pop(gateway)
            nome = por_gateway.get(gateway)
            if nome is None:
                continue
            duracao = max(1, int((quando - inicio).total_seconds()))
            if perda is not None and perda >= ALARME_FORA_PCT:
                eventos.append({"tipo": "link_fora", "link": nome, "quando": inicio, "duracao_s": duracao})
            else:
                troca = next((o for o in omissoes.get(gateway, []) if 0 <= (o - inicio).total_seconds() <= 30), None)
                eventos.append({"tipo": "oscilacao", "link": nome, "quando": inicio, "perda_pct": perda, "duracao_s": duracao,
                                "failover_s": (troca - inicio).total_seconds() if troca else None})
    return eventos


def _eventos_das_sondas(db, links, ini_utc, fim_utc):
    """Plano B: sondas de 5 em 5 min com perda alta viram oscilacao; sondas seguidas sem resposta viram link fora."""
    eventos = []
    for link in links:
        sondas = db.execute(
            "SELECT probed_at, status, packet_loss_percent FROM pfsense_link_probes WHERE link_id=? "
            "AND datetime(probed_at)>=datetime(?) AND datetime(probed_at)<=datetime(?) ORDER BY probed_at",
            (link["id"], ini_utc, fim_utc),
        ).fetchall()
        grupo = []
        def fechar():
            if not grupo:
                return
            inicio = utc_para_brt(grupo[0]["probed_at"])
            fim = utc_para_brt(grupo[-1]["probed_at"])
            duracao = int((fim - inicio).total_seconds()) + 300
            if all(s["status"] != "online" for s in grupo):
                eventos.append({"tipo": "link_fora", "link": link["nome"], "quando": inicio, "duracao_s": duracao})
            else:
                perdas = [s["packet_loss_percent"] for s in grupo if s["packet_loss_percent"] is not None]
                eventos.append({"tipo": "oscilacao", "link": link["nome"], "quando": inicio,
                                "perda_pct": round(max(perdas)) if perdas else None, "duracao_s": min(duracao, 300), "failover_s": None})
            grupo.clear()
        for sonda in sondas:
            ruim = sonda["status"] != "online" or (sonda["packet_loss_percent"] or 0) >= PERDA_OSCILACAO_PCT
            if ruim:
                # sondas ruins separadas por mais de 10 min (ou por uma boa) sao episodios diferentes
                if grupo and (utc_para_brt(sonda["probed_at"]) - utc_para_brt(grupo[-1]["probed_at"])).total_seconds() > 600:
                    fechar()
                grupo.append(sonda)
            else:
                fechar()
        fechar()
    return eventos


def _queda_de_energia(db, firewall_id, inicio, ini_utc, fim_utc):
    """Reinicios do firewall (uptime que volta atras) com uma lacuna longa antes: o firewall ficou fora de verdade."""
    ampla = brt_para_utc_texto(inicio - timedelta(days=1))
    linhas = db.execute(
        "SELECT checked_at, metrics_json FROM pfsense_checks WHERE firewall_id=? AND status IN ('online', 'success') "
        "AND datetime(checked_at)>=datetime(?) AND datetime(checked_at)<=datetime(?) ORDER BY checked_at",
        (firewall_id, ampla, fim_utc),
    ).fetchall()
    pontos = []
    for linha in linhas:
        try:
            uptime = int(json.loads(linha["metrics_json"] or "{}").get("UPTIME_SECONDS"))
        except (TypeError, ValueError):
            continue
        pontos.append((utc_para_brt(linha["checked_at"]), uptime))
    quedas = []
    for (antes, up_antes), (depois, up_depois) in zip(pontos, pontos[1:]):
        if up_depois < up_antes:  # o contador de uptime reiniciou: houve boot
            boot = depois - timedelta(seconds=up_depois)
            inicio_queda = antes
            if (boot - inicio_queda).total_seconds() >= LIMITES["energia_minima_s"] and boot >= inicio:
                quedas.append((inicio_queda, boot))
    return quedas


def _carga(db, firewall_id, ini_utc, fim_utc):
    linhas = db.execute(
        "SELECT load1, cpu_count FROM pfsense_checks WHERE firewall_id=? AND status IN ('online', 'success') AND load1 IS NOT NULL "
        "AND datetime(checked_at)>=datetime(?) AND datetime(checked_at)<=datetime(?)", (firewall_id, ini_utc, fim_utc),
    ).fetchall()
    cargas = [l["load1"] * 100 / (l["cpu_count"] or 1) for l in linhas]
    return {"cpu_pico_pct": max(cargas)} if cargas else None


def coletar_dados(db, firewall_id, inicio, fim, emitido_em=None):
    """`inicio`/`fim` em Brasilia (naive). Devolve o dicionario para montar_relatorio, ou None se o firewall nao existe."""
    firewall = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    if not firewall:
        return None
    ini_utc, fim_utc = brt_para_utc_texto(inicio), brt_para_utc_texto(fim)
    links = _links(db, firewall_id, ini_utc, fim_utc)
    trafego, limitacoes = {}, []
    for link in links:
        if link["traffic_key"]:
            trafego[link["nome"]] = _serie_horaria(_trafego(db, firewall_id, link["traffic_key"], ini_utc, fim_utc), inicio, fim)
    # link sem nenhuma medicao no periodo (ex.: cadastrado e nunca usado) nao entra: "estavel" sem dado seria mentira
    com_dado = [l for l in links if l["down_mbps"] is not None or l["up_mbps"] is not None or l["latencia_ms"] is not None
                or any(v is not None for _, v in trafego.get(l["nome"], []))]
    if com_dado and len(com_dado) < len(links):
        limitacoes.extend(f"O link {l['nome']} ficou fora do relatório: sem nenhuma medição no período." for l in links if l not in com_dado)
        links = com_dado
        trafego = {nome: serie for nome, serie in trafego.items() if nome in {l["nome"] for l in links}}
    if not trafego:
        limitacoes.append("Ainda não há histórico de tráfego deste firewall: os gráficos de uso aparecem quando a coleta começar.")
    eventos = _eventos_do_log(db, firewall_id, links, ini_utc, fim_utc)
    if not eventos and not db.execute("SELECT 1 FROM pfsense_gateway_events WHERE firewall_id=? LIMIT 1", (firewall_id,)).fetchone():
        eventos = _eventos_das_sondas(db, links, ini_utc, fim_utc)
        limitacoes.append("As oscilações foram detectadas pelas sondas de 5 em 5 minutos; oscilações mais curtas que isso podem não aparecer.")
    failover = {}
    try:
        info = json.loads(firewall["failover_info"] or "{}")
    except ValueError:
        info = {}
    if len(links) >= 2 and info:
        osc = [e for e in eventos if e["tipo"] == "oscilacao"]
        funcionou = sum(1 for e in osc if e.get("failover_s") is not None)
        failover = {"configurado": bool(info.get("configurado")), "acionou": len(osc), "funcionou": funcionou, "verificado": funcionou > 0}
    dados = {
        "cliente": firewall["name"], "inicio": inicio, "fim": fim, "emitido_em": emitido_em or fim,
        "fonte": "Firewall pfSense", "expediente": _expediente(firewall["report_expediente"]),
        "links": links, "trafego_links": trafego, "redes": _redes(db, firewall_id, ini_utc, fim_utc),
        "eventos": eventos, "sem_energia": _queda_de_energia(db, firewall_id, inicio, ini_utc, fim_utc),
        "failover": failover or None, "firewall": _carga(db, firewall_id, ini_utc, fim_utc), "limitacoes": limitacoes,
        "observacoes": [t for t in (firewall["report_notes"] or "").splitlines() if t.strip()],
    }
    return dados
