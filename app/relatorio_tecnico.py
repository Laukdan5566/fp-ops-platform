"""Relatorio tecnico de internet de um firewall (modelo MK).

Funcoes puras: nada aqui le banco, rede ou relogio. Tudo entra por `dados` (ver `montar_relatorio`) e sai um dicionario
com o texto, os numeros e as series prontos para a tela e para os graficos. As regras (limites) ficam em `LIMITES`.
Horarios sao "naive" ja em Brasilia (quem coleta converte).
"""
from datetime import datetime, timedelta
from statistics import median, pstdev

DIAS_SEMANA = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]
DIA_EXTENSO = ["segunda", "terça", "quarta", "quinta", "sexta", "sábado", "domingo"]

LIMITES = {
    "uso_apertado_pct": 60,        # pico de 1 h acima disso: capacidade apertada
    "uso_insuficiente_pct": 85,    # pico de 1 h acima disso: falta banda
    "upload_minimo_mbps": 20,      # upload medido abaixo disso (e muito abaixo do download) = problema
    "upload_razao_minima": 0.25,   # upload / download abaixo disso = assimetria suspeita
    "oscilacoes_alerta": 3,        # a partir de N oscilacoes no periodo o link e "instavel"
    "link_fora_critico_s": 300,    # link fora por mais que isso = dia critico
    "energia_minima_s": 1800,      # lacuna de firewall e links de pelo menos 30 min = falta de energia
    "intervalo_regular": 0.15,     # desvio/mediana dos intervalos abaixo disso = periodico
    "wifi_latencia_ms": 40,        # celular no Wi-Fi acima disso = vale avaliar o Wi-Fi
    "dhcp_alerta_pct": 80,         # faixa DHCP acima disso
}

SEVERIDADES = {"critico": "Crítico", "alto": "Alto", "medio": "Médio", "verificar": "Verificar", "positivo": "Positivo", "baixo": "Baixo"}
CHIPS = {"ok": "ok", "atencao": "atencao", "ruim": "ruim"}


# ---------- formatacao ----------
def num(valor, casas=1):
    """12.5 -> '12,5' (padrao brasileiro)."""
    if valor is None:
        return "-"
    texto = f"{valor:.{casas}f}"
    return texto.replace(".", ",")


def plural(n, singular, plural_):
    return f"{n} {singular if n == 1 else plural_}"


def na_dia(dt):
    """'na terça', 'no sábado' (dia da semana por extenso, com artigo)."""
    return f"{'no' if dt.weekday() >= 5 else 'na'} {DIA_EXTENSO[dt.weekday()]}"


def dia_curto(dt):
    return f"{DIAS_SEMANA[dt.weekday()]} {dt.day}"


def dia_data(dt):
    return f"{DIAS_SEMANA[dt.weekday()]} {dt.day:02d}/{dt.month:02d}"


def quando(dt):
    return f"{dia_curto(dt)} · {dt:%H:%M}"


def duracao_texto(segundos):
    segundos = int(segundos)
    if segundos < 90:
        return f"{segundos} s"
    minutos = round(segundos / 60)
    if minutos < 90:
        return f"{minutos} min"
    horas = segundos / 3600
    return f"~{num(horas, 0)} h" if horas >= 9.5 else f"~{num(horas, 1)} h"


def intervalo_texto(segundos):
    """3h49 vira 3h50: e um valor aproximado, entao arredonda de 5 em 5 minutos."""
    minutos = int(round(segundos / 60 / 5)) * 5
    return f"{minutos // 60}h{minutos % 60:02d}"


def periodo_texto(inicio, fim):
    if inicio.month == fim.month:
        return f"{inicio.day} a {fim.day}/{fim.month:02d}"
    return f"{inicio.day:02d}/{inicio.month:02d} a {fim.day:02d}/{fim.month:02d}"


def dentro_expediente(dt, expediente):
    return dt.weekday() < 5 and expediente[0] <= dt.hour < expediente[1]


# ---------- partes do relatorio ----------
def resumo_dos_links(dados):
    """Capacidade medida x uso por link (pico e media de 1 h)."""
    resultado = []
    for link in dados["links"]:
        serie = [mbps for _, mbps in dados.get("trafego_links", {}).get(link["nome"], []) if mbps is not None]
        capacidade = link.get("down_mbps")
        pico = max(serie) if serie else None
        media = sum(serie) / len(serie) if serie else None
        resultado.append({
            **link,
            "pico_hora_mbps": pico,
            "media_mbps": media,
            "pico_pct": round(pico * 100 / capacidade) if pico is not None and capacidade else None,
        })
    return resultado


def eventos_por_tipo(dados, tipo, link=None):
    return [e for e in dados.get("eventos", []) if e["tipo"] == tipo and (link is None or e.get("link") == link)]


def link_principal(dados):
    for link in dados["links"]:
        if link.get("funcao") == "principal":
            return link
    return dados["links"][0] if dados["links"] else None


def link_preferencial(dados):
    for link in dados["links"]:
        if link.get("preferencial"):
            return link
    return None


def energia_total_s(dados):
    return sum((fim - inicio).total_seconds() for inicio, fim in dados.get("sem_energia", []))


def oscilacoes_por_link(dados):
    contagem = {}
    for evento in eventos_por_tipo(dados, "oscilacao"):
        contagem.setdefault(evento["link"], []).append(evento)
    return contagem


def link_mais_instavel(dados):
    por_link = oscilacoes_por_link(dados)
    if not por_link:
        return None, []
    nome = max(por_link, key=lambda k: len(por_link[k]))
    return nome, sorted(por_link[nome], key=lambda e: e["quando"])


def upload_problematico(link):
    up, down = link.get("up_mbps"), link.get("down_mbps")
    if up is None:
        return False
    contratado = link.get("contratado_up_mbps")
    minimo = (link.get("entrega_minima_pct") or 80) / 100
    if contratado:
        return up < contratado * minimo
    if down:
        return up < LIMITES["upload_minimo_mbps"] and up / down < LIMITES["upload_razao_minima"]
    return up < LIMITES["upload_minimo_mbps"]


def kpis(dados, links):
    com_pico = [link for link in links if link["pico_pct"] is not None]
    cards = []
    if com_pico:
        topo = max(com_pico, key=lambda link: link["pico_pct"])
        cards.append({
            "valor": f"{topo['pico_pct']}%",
            "texto": f"Maior uso da capacidade em 1 hora na semana ({num(topo['pico_hora_mbps'], 0)} de ~{num(topo['down_mbps'], 0)} Mbps)",
        })
    principal = link_principal(dados)
    if principal and principal.get("up_mbps") is not None:
        cards.append({"valor": f"~{num(principal['up_mbps'], 0)} Mbps", "texto": f"Upload medido no link principal ({principal['nome']})"})
    nome, lista = link_mais_instavel(dados)
    if nome:
        total = len(lista)
        acionou = sum(1 for e in lista if e.get("failover_s") is not None)
        cards.append({
            "valor": str(total),
            "texto": f"Oscilações na {nome}; o failover agiu em {'todas' if acionou == total else f'{acionou}'}",
        })
    else:
        cards.append({"valor": "0", "texto": "Oscilações nos links no período"})
    energia = energia_total_s(dados)
    if energia:
        inicio, fim = max(dados["sem_energia"], key=lambda i: (i[1] - i[0]).total_seconds())
        cards.append({"valor": duracao_texto(energia), "texto": f"Sem energia: {DIAS_SEMANA[inicio.weekday()].lower()} {inicio:%H:%M} até {DIAS_SEMANA[fim.weekday()].lower()} {fim:%H:%M}"})
    else:
        cards.append({"valor": "0 h", "texto": "Sem queda de energia no período"})
    return cards


def situacao_por_item(dados, links):
    itens = []
    com_pico = [link for link in links if link["pico_pct"] is not None]
    if com_pico:
        pior = max(link["pico_pct"] for link in com_pico)
        if pior >= LIMITES["uso_insuficiente_pct"]:
            itens.append(("Velocidade de download × uso", "ruim", "Insuficiente"))
        elif pior >= LIMITES["uso_apertado_pct"]:
            itens.append(("Velocidade de download × uso", "atencao", "Apertada"))
        else:
            itens.append(("Velocidade de download × uso", "ok", "Adequada"))
    failover = dados.get("failover")
    if len(dados["links"]) >= 2 and failover:
        if not failover.get("configurado"):
            itens.append(("Failover entre os links", "ruim", "Não configurado"))
        elif failover.get("acionou", 0) > failover.get("funcionou", 0):
            itens.append(("Failover entre os links", "ruim", "Falhou em trocas"))
        else:
            itens.append(("Failover entre os links", "ok", "Funcionando"))
    firewall = dados.get("firewall") or {}
    if firewall.get("cpu_pico_pct") is not None:
        pico = firewall["cpu_pico_pct"]
        itens.append(("Desempenho do firewall", "ok" if pico < 70 else "atencao", "Adequado" if pico < 70 else "Sobrecarregado"))
    lan = dados.get("lan") or {}
    if lan.get("latencia_ms") is not None:
        bom = lan["latencia_ms"] < 5 and not lan.get("perda_pct")
        itens.append(("Rede cabeada interna", "ok" if bom else "atencao", "Adequada" if bom else "Com perda/atraso"))
    por_link = oscilacoes_por_link(dados)
    for link in dados["links"]:
        lista = por_link.get(link["nome"], [])
        fora = [e for e in eventos_por_tipo(dados, "link_fora", link["nome"]) if e.get("duracao_s", 0) >= LIMITES["link_fora_critico_s"]]
        if fora:
            itens.append((f"Estabilidade do link {link['nome']}", "ruim", "Ficou fora do ar"))
        elif len(lista) >= LIMITES["oscilacoes_alerta"]:
            contagem = {}
            for e in lista:
                contagem[e["quando"].weekday()] = contagem.get(e["quando"].weekday(), 0) + 1
            dias = sorted(d for d, c in contagem.items() if c >= 2) or sorted(contagem)
            rotulo = "/".join(DIAS_SEMANA[d].lower() for d in dias[:3])
            itens.append((f"Estabilidade do link {link['nome']}", "atencao", f"Instável {rotulo}"))
        elif lista:
            itens.append((f"Estabilidade do link {link['nome']}", "atencao", plural(len(lista), "oscilação", "oscilações")))
        else:
            itens.append((f"Estabilidade do link {link['nome']}", "ok", "Estável"))
    principal = link_principal(dados)
    if principal and principal.get("up_mbps") is not None:
        ruim = upload_problematico(principal)
        itens.append((f"Upload do link principal ({principal['nome']})", "ruim" if ruim else "ok", f"~{num(principal['up_mbps'], 0)} Mbps" if ruim else "Adequado"))
    if energia_total_s(dados):
        itens.append(("Proteção contra falta de energia", "ruim", "Insuficiente"))
    return itens


def agrupar_oscilacoes(dados):
    """Oscilacoes em sequencia do mesmo link viram uma linha so (como no relatorio da MK).
    A sequencia quebra quando passa mais de 12 h sem ocorrencia; sequencias curtas ficam uma por linha."""
    grupos = []
    for nome, lista in oscilacoes_por_link(dados).items():
        sequencias, atual = [], []
        for evento in sorted(lista, key=lambda e: e["quando"]):
            if atual and (evento["quando"] - atual[-1]["quando"]).total_seconds() > 12 * 3600:
                sequencias.append(atual)
                atual = []
            atual.append(evento)
        if atual:
            sequencias.append(atual)
        for sequencia in sequencias:
            if len(sequencia) >= LIMITES["oscilacoes_alerta"]:
                grupos.append((nome, sequencia))
            else:
                grupos.extend((nome, [e]) for e in sequencia)
    return grupos


def texto_intervalo(lista):
    quandos = [e["quando"] for e in lista]
    if len(quandos) < 4:
        return None
    # intervalos dentro de uma mesma sequencia (descarta os saltos longos entre dias)
    difs = [(b - a).total_seconds() for a, b in zip(quandos, quandos[1:])]
    curtos = [d for d in difs if d < median(difs) * 1.6]
    if len(curtos) < 3:
        return None
    mediana = median(curtos)
    if mediana and pstdev(curtos) / mediana < LIMITES["intervalo_regular"]:
        return mediana
    return None


def ocorrencias(dados):
    """Linhas da tabela 'Detalhe das ocorrencias': {quando, partes[(texto, negrito)], impacto}."""
    expediente = dados["expediente"]
    linhas = []
    for nome, lista in agrupar_oscilacoes(dados):
        perdas = [e.get("perda_pct") for e in lista if e.get("perda_pct")]
        perda = round(sum(perdas) / len(perdas)) if perdas else None
        dentro = [e for e in lista if dentro_expediente(e["quando"], expediente)]
        horarios = []
        for evento in lista:
            horarios.append((f"{evento['quando']:%H:%M}", dentro_expediente(evento["quando"], expediente)))
        if len(lista) == 1:
            evento = lista[0]
            extra = f" (perda de até {num(evento['perda_pct'], 0)}% por {duracao_texto(evento.get('duracao_s', 120))})" if evento.get("perda_pct") else ""
            partes = [(f"Mais uma oscilação na {nome}" if nome else "Oscilação", False), (extra + ".", False)]
            impacto = "Dentro do expediente: travamento rápido e conexões reiniciadas." if dentro else "Fora do expediente."
            linhas.append({"quando": quando(evento["quando"]), "partes": partes, "impacto": impacto, "_ordem": evento["quando"]})
            continue
        ordenados = sorted(lista, key=lambda e: e["quando"])
        primeiro, ultimo = ordenados[0]["quando"], ordenados[-1]["quando"]
        rotulo = f"{dia_curto(primeiro)} e {dia_curto(ultimo)}" if primeiro.date() != ultimo.date() else dia_curto(primeiro)
        partes = [(f"{len(lista)} oscilações no link {nome}", True), (f", com ~{perda}% de perda de pacotes. Horários: " if perda else ". Horários: ", False)]
        for indice, (hora, destaque) in enumerate(horarios):
            partes.append((hora, destaque))
            if indice < len(horarios) - 1:
                partes.append((", ", False))
        intervalo = texto_intervalo(lista)
        if intervalo:
            partes.append((". Elas se repetiram a cada ", False))
            partes.append((f"~{intervalo_texto(intervalo)}", True))
            partes.append((", padrão típico de problema no equipamento ou na rede da operadora.", False))
        else:
            partes.append((".", False))
        failover = [e["failover_s"] for e in lista if e.get("failover_s") is not None]
        if failover:
            partes.append((f" Em todas, o failover passou para outro link em cerca de {num(max(failover), 0)} s e voltou cerca de 1 minuto depois.", False) if len(failover) == len(lista) else (" O failover agiu em parte delas.", False))
        impacto = f"As {len(dentro)} em negrito caíram no expediente: travamento rápido e conexões em andamento reiniciadas." if dentro else "Todas fora do expediente."
        linhas.append({"quando": rotulo, "partes": partes, "impacto": impacto, "_ordem": primeiro})
    for evento in eventos_por_tipo(dados, "link_fora"):
        linhas.append({
            "quando": quando(evento["quando"]),
            "partes": [(f"Link {evento['link']} fora por ~{duracao_texto(evento.get('duracao_s', 0))}.", True), (f" {evento.get('detalhe', '')}".rstrip(), False)],
            "impacto": evento.get("impacto") or "Verificar o que passava por esse link no horário.",
            "_ordem": evento["quando"],
        })
    for inicio, fim in dados.get("sem_energia", []):
        horas = duracao_texto((fim - inicio).total_seconds())
        linhas.append({
            "quando": quando(inicio),
            "partes": [("Os dois links e o firewall caíram juntos.", True), (f" Ficaram {horas} sem registro, até o firewall ser religado {na_dia(fim)} às {fim:%H:%M}. A causa mais provável é ", False), ("falta de energia", True), (".", False)],
            "impacto": "Sem internet durante todo esse período.",
            "_ordem": inicio,
        })
    for evento in eventos_por_tipo(dados, "ajuste"):
        linhas.append({"quando": quando(evento["quando"]), "partes": [(evento["texto"], False)], "impacto": "—", "_ordem": evento["quando"]})
    for linha in linhas:
        linha.setdefault("_ordem", datetime.max)
    linhas.sort(key=lambda l: l["_ordem"])
    return linhas


def dias_do_periodo(dados, links):
    inicio, fim = dados["inicio"], dados["fim"]
    expediente = dados["expediente"]
    por_hora = {}
    for serie in dados.get("trafego_links", {}).values():
        for hora, mbps in serie:
            if mbps is not None:
                por_hora[hora] = por_hora.get(hora, 0) + mbps
    linhas = []
    dia = inicio.replace(hour=0, minute=0, second=0, microsecond=0)
    while dia <= fim:
        horas = {h: v for h, v in por_hora.items() if h.date() == dia.date()}
        uteis = [v for h, v in horas.items() if dentro_expediente(h, expediente)]
        eventos = [e for e in dados.get("eventos", []) if e.get("quando") and e["quando"].date() == dia.date()]
        textos, gravidade = [], "ok"
        osc = {}
        for e in eventos:
            if e["tipo"] == "oscilacao":
                osc[e["link"]] = osc.get(e["link"], 0) + 1
        for nome, qtd in osc.items():
            ultimo = max(e["quando"] for e in eventos if e["tipo"] == "oscilacao" and e["link"] == nome)
            fora = all(not dentro_expediente(e["quando"], expediente) for e in eventos if e["tipo"] == "oscilacao" and e["link"] == nome)
            if qtd == 1 and fora:
                textos.append(f"1 oscilação às {ultimo:%H:%M} (fora do expediente)")
            else:
                textos.append(f"{plural(qtd, 'oscilação', 'oscilações')} na {nome}" + (" (failover acionado)" if all(e.get("failover_s") is not None for e in eventos if e["tipo"] == "oscilacao") else ""))
            gravidade = "atencao"
        for e in eventos:
            if e["tipo"] == "link_fora":
                textos.append(f"{e['link']} caiu às {e['quando']:%H:%M}")
                if e.get("duracao_s", 0) >= LIMITES["link_fora_critico_s"]:
                    gravidade = "critico"
        for inicio_e, fim_e in dados.get("sem_energia", []):
            if inicio_e.date() == dia.date():
                textos.append(f"queda de energia às {inicio_e:%H:%M}")
                gravidade = "critico"
            elif inicio_e.date() < dia.date() <= fim_e.date():
                textos.append(f"Sem energia até {fim_e:%H:%M} · firewall religado" if fim_e.date() == dia.date() else "Sem energia o dia todo")
                gravidade = "atencao" if gravidade == "ok" else gravidade
        texto = " · ".join(textos) if textos else ("Sem ocorrências" + (f" (até {fim:%H:%M})" if dia.date() == fim.date() else ""))
        linhas.append({
            "dia": dia_data(dia), "gravidade": gravidade,
            "uso_expediente": sum(uteis) / len(uteis) if uteis else None,
            "pico_hora": max(horas.values()) if horas else None,
            "volume_gb": sum(horas.values()) * 3600 / 8 / 1000 if horas else None,
            "ocorrencias": texto,
        })
        dia += timedelta(days=1)
    return linhas


def diagnosticos(dados, links):
    itens = []
    principal = link_principal(dados)
    if principal and principal.get("up_mbps") is not None and upload_problematico(principal):
        outro = next((link for link in dados["links"] if link is not principal and link.get("up_mbps")), None)
        comparacao = f" A {outro['nome']}, no mesmo teste, entregou cerca de {num(outro['up_mbps'], 0)} Mbps de upload." if outro else ""
        itens.append({
            "sev": "critico", "chave": "upload", "titulo": f"Upload muito baixo no link principal ({principal['nome']})",
            "texto": f"A {principal['nome']} entregou cerca de {num(principal['down_mbps'], 0)} Mbps de download, mas só cerca de {num(principal['up_mbps'], 0)} Mbps de upload.{comparacao}",
            "porque": f"Com a {principal['nome']} como principal, tudo o que a empresa envia para a internet (anexos de e-mail, arquivos para a nuvem, backups, notas fiscais, chamadas de vídeo, câmeras) disputa só {num(principal['up_mbps'], 0)} Mbps. Isso causa lentidão mesmo com o download sobrando. É preciso confirmar com a operadora se esse é o plano contratado ou um defeito.",
        })
    if energia_total_s(dados):
        inicio, fim = max(dados["sem_energia"], key=lambda i: (i[1] - i[0]).total_seconds())
        itens.append({
            "sev": "critico", "chave": "energia", "titulo": "Equipamentos sem proteção contra falta de energia",
            "texto": f"{na_dia(inicio).capitalize()}, às {inicio:%H:%M}, os links e o firewall pararam no mesmo instante e só voltaram {na_dia(fim)} às {fim:%H:%M}. Isso indica que firewall e modems não estão em um nobreak, ou que o nobreak não segurou.",
            "porque": "Qualquer queda de energia derruba toda a internet, e o retorno depende de alguém religar o equipamento.",
        })
    nome, lista = link_mais_instavel(dados)
    if nome and len(lista) >= LIMITES["oscilacoes_alerta"]:
        perdas = [e["perda_pct"] for e in lista if e.get("perda_pct")]
        faixa = f"{num(min(perdas), 0)} a {num(max(perdas), 0)}% de perda" if perdas else "perda de pacotes"
        intervalo = texto_intervalo(lista)
        periodico = f" Boa parte aconteceu em intervalos quase fixos de ~{intervalo_texto(intervalo)}." if intervalo else ""
        itens.append({
            "sev": "alto", "chave": "oscilacoes", "titulo": f"Oscilações periódicas no link {nome}" if intervalo else f"Oscilações no link {nome}",
            "texto": f"Foram {len(lista)} episódios no período, com {faixa}.{periodico}",
            "porque": ("Intervalos regulares indicam causa na operadora (equipamento, sinal ou renovação de conexão). " if intervalo else "") + "O failover reduziu o impacto, mas cada troca ainda é sentida pelos usuários.",
        })
    preferencial, padrao = link_preferencial(dados), link_principal(dados)
    if preferencial and padrao and preferencial is not padrao:
        itens.append({
            "sev": "medio", "chave": "preferencial", "titulo": "Link preferencial fora do padrão (ajuste temporário)",
            "texto": f"O padrão é a {padrao['nome']} como principal, mas o failover está com a {preferencial['nome']} como preferencial.",
            "porque": f"O ajuste faz sentido enquanto houver problema na {padrao['nome']}. Depois de normalizar, convém voltar ao padrão e documentar a configuração escolhida.",
        })
    redes_wifi = [r for r in dados.get("redes", []) if r.get("tipo") == "wifi"]
    wifi = dados.get("wifi") or {}
    if redes_wifi and (wifi.get("latencia_ms") or 0) >= LIMITES["wifi_latencia_ms"]:
        total = sum(r["gb_down"] for r in dados["redes"]) or 1
        parte = sum(r["gb_down"] for r in redes_wifi) * 100 / total
        itens.append({
            "sev": "verificar", "chave": "wifi", "titulo": "Qualidade do Wi-Fi",
            "texto": f"As redes Wi-Fi responderam por cerca de {num(parte, 0)}% do download do período. Os aparelhos no Wi-Fi responderam entre {num(wifi.get('latencia_min_ms', wifi['latencia_ms']), 0)} e {num(wifi.get('latencia_max_ms', wifi['latencia_ms']), 0)} ms, contra menos de 1 ms nos computadores por cabo.",
            "porque": "Parte dessa demora pode ser só a economia de bateria dos celulares. Mas, se as reclamações vierem principalmente de quem usa Wi-Fi, os aparelhos de Wi-Fi precisam ser avaliados. O firewall mostra o volume de tráfego, não a qualidade do sinal sem fio.",
        })
    failover = dados.get("failover") or {}
    if failover.get("configurado") and failover.get("acionou") and failover.get("funcionou") == failover.get("acionou"):
        itens.append({
            "sev": "positivo", "chave": "failover", "titulo": "Failover configurado e funcionando",
            "texto": f"O firewall tem grupos de failover entre os links. Nas {failover['acionou']} oscilações do período, ele trocou de link sozinho e voltou quando o link normalizou.",
            "porque": "Sem o failover, cada oscilação teria deixado a empresa sem internet até alguém intervir.",
        })
    dhcp = dados.get("dhcp")
    if dhcp and dhcp.get("total"):
        pct = dhcp["usados"] * 100 / dhcp["total"]
        if pct >= LIMITES["dhcp_alerta_pct"]:
            itens.append({
                "sev": "baixo", "chave": "dhcp", "titulo": "Faixa de endereços da rede principal perto do limite",
                "texto": f"{dhcp['usados']} dos {dhcp['total']} endereços automáticos (DHCP) estão em uso, ou {num(pct, 0)}% da faixa.",
                "porque": "Se a faixa esgotar, novos aparelhos não conseguem se conectar. Hoje ainda há folga.",
            })
    ordem = {k: i for i, k in enumerate(["critico", "alto", "medio", "verificar", "positivo", "baixo"])}
    itens.sort(key=lambda i: ordem[i["sev"]])
    return itens


def plano_de_acao(dados, itens, links):
    """Acoes derivadas dos diagnosticos (so os que pedem providencia)."""
    principal, preferencial = link_principal(dados), link_preferencial(dados)
    nome_oscilante, _ = link_mais_instavel(dados)
    modelos = {
        "upload": (f"Acionar a {principal['nome'] if principal else 'operadora'} sobre o upload de ~{num(principal.get('up_mbps') if principal else None, 0)} Mbps (confirmar o plano contratado ou abrir chamado técnico)", "Operador do cliente, com apoio do suporte", "critico", "Link principal com upload adequado"),
        "oscilacoes": (f"Abrir chamado na {nome_oscilante} com os horários das oscilações", "Operador do cliente, com apoio do suporte", "critico", "Link estável e sem trocas desnecessárias"),
        "energia": ("Ligar o firewall e os modems em um nobreak, ou testar o atual", "Cliente", "alto", "Internet mantida em quedas curtas de energia"),
        "preferencial": (f"Com o link {principal['nome'] if principal else 'principal'} normalizado, voltar a defini-lo como preferencial no failover", "Suporte de TI", "medio", "Configuração de volta ao padrão"),
        "wifi": ("Avaliar o Wi-Fi (posição, canais e interferência dos aparelhos) usando os dados das VLANs", "Suporte de TI", "medio", "Melhor experiência para quem usa Wi-Fi"),
        "dhcp": ("Ampliar a faixa de endereços automáticos da rede principal", "Suporte de TI", "baixo", "Folga para novos dispositivos"),
    }
    prioridade = {"critico": "Imediata", "alto": "Alta", "medio": "Média", "baixo": "Baixa"}
    ordem = ["critico", "alto", "medio", "baixo"]
    acoes = []
    for item in itens:
        modelo = modelos.get(item["chave"])
        if modelo:
            acoes.append({"acao": modelo[0], "responsavel": modelo[1], "prioridade": modelo[2], "prioridade_texto": prioridade[modelo[2]], "resultado": modelo[3]})
    acoes.sort(key=lambda a: ordem.index(a["prioridade"]))
    for indice, acao in enumerate(acoes, 1):
        acao["n"] = indice
    return acoes


def redes_com_percentual(dados):
    total = sum(r["gb_down"] for r in dados.get("redes", [])) or 0
    return [{**r, "pct": round(r["gb_down"] * 100 / total) if total else 0} for r in dados.get("redes", [])]


NUMERAL = {1: "um", 2: "dois", 3: "três", 4: "quatro", 5: "cinco", 6: "seis"}

GLOSSARIO = [
    ("Link", "cada conexão de internet contratada."),
    ("Mbps", "unidade de velocidade. Quanto maior, mais dados passam por segundo."),
    ("Download / upload", "receber dados da internet / enviar dados para a internet."),
    ("Latência", "tempo que um dado leva para ir e voltar. Abaixo de 30 ms é ótimo."),
    ("Perda de pacotes", "parte dos dados que se perde no caminho. O ideal é 0%."),
    ("Failover", "troca automática para o link reserva quando o principal falha."),
    ("Firewall", "equipamento que controla e protege a internet da empresa."),
    ("VLAN", "rede separada dentro da mesma estrutura física. Permite isolar e medir o tráfego de cada grupo, como o Wi-Fi."),
    ("Link preferencial", "o link que o failover usa primeiro, enquanto ele estiver saudável."),
    ("Nobreak", "bateria que mantém os equipamentos ligados na falta de energia."),
]


def resumo_executivo(dados, links, situacao, itens):
    """Texto de abertura e os 'fatores' que explicam a sensacao de internet ruim."""
    qtd = len(dados["links"])
    uso_ok = any(nome.startswith("Velocidade") and cor == "ok" for nome, cor, _ in situacao)
    failover_ok = any(nome.startswith("Failover") and cor == "ok" for nome, cor, _ in situacao)
    partes = [f"{dados['cliente']} tem {NUMERAL.get(qtd, qtd)} link{'s' if qtd != 1 else ''} de internet" + (" com velocidade de sobra para o uso da empresa" if uso_ok else "")]
    if qtd >= 2:
        partes.append(" e um failover configurado e funcionando: quando um link falha, o firewall passa automaticamente para o outro" if failover_ok else ", mas o failover entre eles precisa de atenção")
    texto = "".join(partes) + "."
    firewall_ok = any(nome.startswith("Desempenho") and cor == "ok" for nome, cor, _ in situacao)
    if firewall_ok:
        texto += " O firewall trabalhou folgado o período todo."
    fatores = []
    chaves = {item["chave"] for item in itens}
    nome_osc, lista = link_mais_instavel(dados)
    if "oscilacoes" in chaves:
        contagem = {}
        for e in lista:
            contagem[e["quando"].weekday()] = contagem.get(e["quando"].weekday(), 0) + 1
        fortes = sorted(d for d, c in contagem.items() if c >= 2) or sorted(contagem)
        quando_txt = " e ".join(f"na {DIA_EXTENSO[d]}" if d < 5 and d != 5 else f"no {DIA_EXTENSO[d]}" for d in fortes) if len(fortes) <= 3 else "ao longo do período"
        fatores.append([(f"Instabilidades no link {nome_osc}", True), (f" {quando_txt}", False)])
    if "energia" in chaves:
        inicio, _ = max(dados["sem_energia"], key=lambda i: (i[1] - i[0]).total_seconds())
        periodo = "madrugada" if inicio.hour < 6 else "manhã" if inicio.hour < 12 else "tarde" if inicio.hour < 18 else "noite"
        fatores.append([("uma falta de energia", True), (f" {'no' if inicio.weekday() >= 5 else 'na'} {DIA_EXTENSO[inicio.weekday()]} à {periodo}" if periodo != "manhã" else f" {'no' if inicio.weekday() >= 5 else 'na'} {DIA_EXTENSO[inicio.weekday()]} de manhã", False)])
    if "upload" in chaves:
        fatores.append([("o upload muito baixo do link principal", True), (f" ({link_principal(dados)['nome']})", False)])
    return {"abertura": texto, "fatores": fatores, "tem_ruim": bool(fatores)}


def termos_simples(dados):
    """Caixas 'Em termos simples' (so as que se aplicam)."""
    caixas = []
    if len(dados["links"]) >= 2:
        principal = link_principal(dados)
        reserva = next((l for l in dados["links"] if l is not principal), None)
        caixas.append({
            "onde": "montagem",
            "texto": f"A empresa tem duas \"estradas\" para a internet: a {principal['nome']}, que é a principal, e a {reserva['nome']}, que é a reserva. "
                     "O firewall funciona como um guarda de trânsito: se uma estrada trava, ele desvia todo mundo para a outra sozinho, em segundos. "
                     "Ainda assim, cada troca pode interromper por um instante o que estava em andamento, como uma chamada de vídeo ou um download.",
        })
    if eventos_por_tipo(dados, "oscilacao"):
        perdas = [e["perda_pct"] for e in eventos_por_tipo(dados, "oscilacao") if e.get("perda_pct")]
        perda = round(median(perdas)) if perdas else 20
        caixas.append({
            "onde": "estabilidade",
            "texto": f"Perder {perda}% dos pacotes é como uma ligação em que uma a cada cinco palavras não chega. O failover percebe isso e troca de link em segundos, "
                     "mas, nesse intervalo, páginas podem travar, chamadas de vídeo podem congelar e sistemas on-line podem pedir para tentar de novo. "
                     "Por isso as oscilações ainda são sentidas, mesmo com o failover funcionando.",
        })
    return caixas


def montar_relatorio(dados):
    """`dados`: cliente, inicio, fim, emitido_em, fonte, expediente=(8, 18), links=[...], trafego_links={nome: [(hora, mbps)]},
    redes=[{nome, tipo, cidr, vlan, gb_down}], eventos=[...], sem_energia=[(inicio, fim)], failover, firewall, lan, wifi, dhcp, topologia.
    """
    dados = {"expediente": (8, 18), "fonte": "Firewall pfSense", "eventos": [], "sem_energia": [], **dados}
    links = resumo_dos_links(dados)
    itens = diagnosticos(dados, links)
    situacao = situacao_por_item(dados, links)
    return {
        "cliente": dados["cliente"], "fonte": dados["fonte"], "emitido_em": dados["emitido_em"],
        "inicio": dados["inicio"], "fim": dados["fim"], "periodo": periodo_texto(dados["inicio"], dados["fim"]),
        "links": links, "kpis": kpis(dados, links), "situacao": situacao,
        "resumo": resumo_executivo(dados, links, situacao, itens), "termos": termos_simples(dados), "glossario": GLOSSARIO,
        "redes": redes_com_percentual(dados), "dias": dias_do_periodo(dados, links), "ocorrencias": ocorrencias(dados),
        "diagnosticos": itens, "plano": plano_de_acao(dados, itens, links),
        "tem_oscilacoes": bool(eventos_por_tipo(dados, "oscilacao")), "tem_energia": bool(dados.get("sem_energia")),
        "dados": dados,
    }
