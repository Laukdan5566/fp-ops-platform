"""Graficos do relatorio tecnico de internet, em SVG puro (sem biblioteca): funcionam no navegador, na impressao e em PDF.
Cada funcao recebe o relatorio montado por `relatorio_tecnico.montar_relatorio` e devolve uma string SVG."""
from datetime import timedelta
from html import escape

from relatorio_tecnico import dentro_expediente, dia_curto, num

AZUL, LARANJA, VERDE, CINZA, VERMELHO, AMARELO = "#2b6fd6", "#e8662f", "#1fa971", "#8a94a6", "#d64545", "#e8a317"
PALETA_LINKS = [AZUL, LARANJA, "#7a4fd1", "#0f9aa8"]
FUNDO_FAIXA = "#f0f2f6"
TEXTO, TEXTO_SUAVE = "#1c2b44", "#667085"


def _svg(largura, altura, corpo):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {largura} {altura}" width="100%" '
            f'font-family="Segoe UI, Arial, sans-serif" role="img">{corpo}</svg>')


def _texto(x, y, conteudo, tamanho=10, cor=TEXTO_SUAVE, ancora="start", peso="normal"):
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{tamanho}" fill="{cor}" text-anchor="{ancora}" '
            f'font-weight="{peso}">{escape(str(conteudo))}</text>')


def _teto(maximo):
    """Maior valor 'redondo' acima do maximo (para o eixo)."""
    if maximo <= 0:
        return 1
    for passo in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000):
        if maximo <= passo * 4:
            return passo * 4 if passo * 4 >= maximo else passo * 5
    return maximo


def grafico_capacidade(rel):
    """Barras: capacidade medida x maior media de 1 h x uso medio, por link."""
    links = [l for l in rel["links"] if l.get("down_mbps")]
    if not links:
        return ""
    largura, esquerda, direita, linha = 760, 44, 20, 46
    maximo = max(l["down_mbps"] for l in links) * 1.05
    escala = (largura - esquerda - direita) / maximo
    corpo = []
    altura = 24 + linha * len(links) + 26
    for i in range(0, int(maximo) + 1, 40):
        x = esquerda + i * escala
        corpo.append(f'<line x1="{x:.1f}" y1="10" x2="{x:.1f}" y2="{altura - 22}" stroke="#e5e8ee"/>')
        corpo.append(_texto(x, altura - 8, f"{i} Mbps", 9, "#98a2b3", "middle"))
    for n, link in enumerate(links):
        y = 18 + n * linha
        corpo.append(_texto(0, y + 19, link["nome"], 11, TEXTO, "start", "bold"))
        corpo.append(f'<rect x="{esquerda}" y="{y}" width="{link["down_mbps"] * escala:.1f}" height="26" rx="4" fill="#e3ecf8"/>')
        if link.get("pico_hora_mbps") is not None:
            corpo.append(f'<rect x="{esquerda}" y="{y}" width="{max(2, link["pico_hora_mbps"] * escala):.1f}" height="26" rx="4" fill="#8bb0e6"/>')
        if link.get("media_mbps") is not None:
            corpo.append(f'<rect x="{esquerda}" y="{y}" width="{max(2, link["media_mbps"] * escala):.1f}" height="26" rx="4" fill="{AZUL}"/>')
        if link.get("pico_hora_mbps") is not None:
            corpo.append(_texto(esquerda + max(2, link["pico_hora_mbps"] * escala) + 8, y + 17, f"pico/hora {num(link['pico_hora_mbps'])}", 9.5))
        corpo.append(_texto(esquerda + link["down_mbps"] * escala - 6, y + 17, f"capacidade ~{num(link['down_mbps'], 0)} Mbps", 9.5, TEXTO_SUAVE, "end"))
    return _svg(largura, altura, "".join(corpo))


def grafico_redes(rel):
    """Barras horizontais do volume de download por rede (cabeada, Wi-Fi, VPN)."""
    redes = rel["redes"]
    if not redes:
        return ""
    cores = {"cabeada": AZUL, "wifi": VERDE, "vpn": CINZA}
    largura, esquerda, direita, linha = 760, 240, 110, 28
    maximo = max(r["gb_down"] for r in redes) or 1
    escala = (largura - esquerda - direita) / maximo
    corpo = []
    for n, rede in enumerate(redes):
        y = 6 + n * linha
        detalhe = rede["cidr"] if rede.get("tipo") == "cabeada" and rede.get("cidr") else (f"VLAN {rede['vlan']}" if rede.get("vlan") else "")
        corpo.append(f'<text x="0" y="{y + 15}" font-size="10.5" fill="{TEXTO}">{escape(rede["nome"])}'
                     f'<tspan fill="#98a2b3" font-size="9"> {escape(str(detalhe))}</tspan></text>')
        corpo.append(f'<rect x="{esquerda}" y="{y}" width="{max(3, rede["gb_down"] * escala):.1f}" height="19" rx="3" fill="{cores.get(rede.get("tipo"), CINZA)}"/>')
        corpo.append(_texto(esquerda + max(3, rede["gb_down"] * escala) + 8, y + 14, f"{num(rede['gb_down'])} GB · {rede['pct']}%", 9.5))
    return _svg(largura, 14 + linha * len(redes), "".join(corpo))


def _faixas_de_fundo(rel, x_de, esquerda, topo, altura):
    """Sombreia o horario comercial (seg a sex, no expediente) e devolve o SVG."""
    dados = rel["dados"]
    expediente = dados["expediente"]
    partes = []
    dia = rel["inicio"].replace(hour=0, minute=0)
    while dia <= rel["fim"]:
        if dia.weekday() < 5:
            ini = max(dia.replace(hour=expediente[0]), rel["inicio"])
            fim = min(dia.replace(hour=expediente[1]), rel["fim"])
            if fim > ini:
                partes.append(f'<rect x="{x_de(ini):.1f}" y="{topo}" width="{x_de(fim) - x_de(ini):.1f}" height="{altura}" fill="{FUNDO_FAIXA}"/>')
        dia += timedelta(days=1)
    return "".join(partes)


def _rotulos_dias(rel, x_de, y):
    partes = []
    dia = rel["inicio"].replace(hour=0, minute=0)
    while dia <= rel["fim"]:
        meio = min(dia + timedelta(hours=12), rel["fim"])
        partes.append(_texto(x_de(meio), y, f"{dia_curto(dia)}/{dia.month:02d}", 9, "#98a2b3", "middle"))
        partes.append(f'<line x1="{x_de(dia):.1f}" y1="{y - 12}" x2="{x_de(dia):.1f}" y2="{y - 17}" stroke="#d0d5dd"/>')
        dia += timedelta(days=1)
    return "".join(partes)


def grafico_uso_semana(rel):
    """Linhas: download medio por hora de cada link, com expediente sombreado e a falta de energia em vermelho."""
    series = rel["dados"].get("trafego_links", {})
    valores = [v for s in series.values() for _, v in s if v is not None]
    if not valores:
        return ""
    largura, altura, esquerda, direita, topo, base = 760, 230, 40, 14, 22, 188
    total = (rel["fim"] - rel["inicio"]).total_seconds() or 1
    x_de = lambda dt: esquerda + (dt - rel["inicio"]).total_seconds() / total * (largura - esquerda - direita)
    teto = _teto(max(valores))
    y_de = lambda v: base - (v / teto) * (base - topo)
    corpo = [_faixas_de_fundo(rel, x_de, esquerda, topo, base - topo)]
    for inicio, fim in rel["dados"].get("sem_energia", []):
        corpo.append(f'<rect x="{x_de(inicio):.1f}" y="{topo}" width="{x_de(fim) - x_de(inicio):.1f}" height="{base - topo}" fill="#fbe4e4"/>')
        corpo.append(_texto((x_de(inicio) + x_de(fim)) / 2, topo + 12, "sem energia", 9, VERMELHO, "middle"))
    passo = teto / 4
    for i in range(5):
        valor = passo * i
        corpo.append(f'<line x1="{esquerda}" y1="{y_de(valor):.1f}" x2="{largura - direita}" y2="{y_de(valor):.1f}" stroke="#eceff4"/>')
        corpo.append(_texto(esquerda - 6, y_de(valor) + 3, num(valor, 0), 9, "#98a2b3", "end"))
    corpo.append(_texto(esquerda - 6, topo - 8, "Mbps", 9, "#98a2b3", "end"))
    corpo.append(_rotulos_dias(rel, x_de, base + 16))
    for n, (nome, serie) in enumerate(series.items()):
        cor = PALETA_LINKS[n % len(PALETA_LINKS)]
        trecho = []
        for hora, valor in serie:
            if valor is None:
                if len(trecho) > 1:
                    corpo.append(f'<polyline fill="none" stroke="{cor}" stroke-width="1.5" points="{" ".join(trecho)}"/>')
                trecho = []
            else:
                trecho.append(f"{x_de(hora):.1f},{y_de(valor):.1f}")
        if len(trecho) > 1:
            corpo.append(f'<polyline fill="none" stroke="{cor}" stroke-width="1.5" points="{" ".join(trecho)}"/>')
    return _svg(largura, altura, "".join(corpo))


def legenda_links(rel):
    """Cores das linhas do grafico de uso (para a legenda em HTML)."""
    return [{"nome": nome, "cor": PALETA_LINKS[n % len(PALETA_LINKS)]} for n, nome in enumerate(rel["dados"].get("trafego_links", {}))]


def faixa_disponibilidade(rel):
    """Tres faixas (um por link + energia/firewall) com os traços de oscilacao e os blocos de queda."""
    dados = rel["dados"]
    nomes = [l["nome"] for l in rel["links"]]
    largura, esquerda, direita, linha, topo = 760, 100, 14, 30, 6
    total = (rel["fim"] - rel["inicio"]).total_seconds() or 1
    x_de = lambda dt: esquerda + (dt - rel["inicio"]).total_seconds() / total * (largura - esquerda - direita)
    linhas = nomes + ["Energia / firewall"]
    altura = topo + linha * len(linhas) + 26
    corpo = [_faixas_de_fundo(rel, x_de, esquerda, topo, linha * len(linhas) - 6)]
    for n, rotulo in enumerate(linhas):
        y = topo + n * linha
        corpo.append(_texto(0, y + 14, rotulo, 10, TEXTO))
        corpo.append(f'<rect x="{esquerda}" y="{y}" width="{largura - esquerda - direita}" height="18" rx="2" fill="#cfe8d8"/>')
        for inicio, fim in dados.get("sem_energia", []):
            corpo.append(f'<rect x="{x_de(inicio):.1f}" y="{y}" width="{x_de(fim) - x_de(inicio):.1f}" height="18" fill="{VERMELHO}"/>')
        if rotulo in nomes:
            for evento in dados.get("eventos", []):
                if evento.get("link") != rotulo:
                    continue
                if evento["tipo"] == "oscilacao":
                    corpo.append(f'<rect x="{x_de(evento["quando"]) - 1:.1f}" y="{y}" width="2.4" height="18" fill="{AMARELO}"/>')
                elif evento["tipo"] == "link_fora":
                    largura_fora = max(3, (evento.get("duracao_s", 60) / total) * (largura - esquerda - direita))
                    corpo.append(f'<rect x="{x_de(evento["quando"]):.1f}" y="{y}" width="{largura_fora:.1f}" height="18" fill="{VERMELHO}"/>')
    corpo.append(_rotulos_dias(rel, x_de, altura - 6))
    return _svg(largura, altura, "".join(corpo))


def diagrama(rel):
    """Diagrama simplificado: links -> firewall -> redes (cabeada e Wi-Fi), como no modelo."""
    links, redes = rel["links"], [r for r in rel["redes"] if r.get("tipo") != "vpn"]
    largura = 760
    altura = 250
    corpo = []
    def caixa(x, y, w, h, titulo, sub, cor_borda="#cdd5e1", fundo="#ffffff", cor_titulo=TEXTO):
        return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" fill="{fundo}" stroke="{cor_borda}"/>'
                + _texto(x + w / 2, y + 20, titulo, 11, cor_titulo, "middle", "bold") + _texto(x + w / 2, y + 36, sub, 9.5, TEXTO_SUAVE if fundo == "#ffffff" else "#d7e1f3", "middle"))
    espaco = largura / max(1, len(links))
    for n, link in enumerate(links):
        x = n * espaco + espaco / 2 - 95
        funcao = "principal" if link.get("funcao") == "principal" else "reserva"
        medida = f"~{num(link.get('down_mbps'), 0)} / {num(link.get('up_mbps'), 0)} Mbps" if link.get("down_mbps") else "velocidade não medida"
        corpo.append(caixa(x, 6, 190, 46, f"Link {link['nome']}", f"{funcao} · {medida}"))
        corpo.append(f'<line x1="{x + 95:.1f}" y1="52" x2="{largura / 2}" y2="86" stroke="#98a2b3" stroke-width="1.4"/>')
    corpo.append(caixa(largura / 2 - 120, 86, 240, 50, "Firewall pfSense", "controla e protege a internet", "#10294a", "#10294a", "#ffffff"))
    espaco = largura / max(1, len(redes))
    for n, rede in enumerate(redes):
        x = n * espaco + espaco / 2 - 110
        sub = " · ".join(p for p in (f"VLAN {rede['vlan']}" if rede.get("vlan") else "", rede.get("cidr") or "") if p)
        corpo.append(f'<line x1="{largura / 2}" y1="136" x2="{x + 110:.1f}" y2="176" stroke="#98a2b3" stroke-width="1.4"/>')
        corpo.append(caixa(x, 176, 220, 50, rede["nome"], sub or rede.get("tipo", ""), VERDE if rede.get("tipo") == "wifi" else AZUL))
    return _svg(largura, altura, "".join(corpo))
