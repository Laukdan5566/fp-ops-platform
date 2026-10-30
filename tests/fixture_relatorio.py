"""Dados de exemplo: a semana da MK (26 a 30/10/2026), do relatorio feito a mao. Serve de gabarito para o gerador automatico."""
from datetime import datetime, timedelta


def _perfil(hora):
    # forma tipica do uso de um escritorio: nada de madrugada, sobe as 8h, almoco mais baixo, cai ate as 18h
    base = {8: .55, 9: 1.0, 10: .75, 11: .8, 12: .45, 13: .6, 14: .85, 15: .7, 16: .6, 17: .35, 18: .15, 19: .05}
    return base.get(hora, .03 if 6 <= hora < 22 else 0)


def dados_mk():
    inicio = datetime(2026, 10, 26, 0, 0)
    fim = datetime(2026, 10, 30, 12, 30)
    picos = {26: 14.4, 27: 9.7, 28: 10.7, 29: 18.0, 30: 9.1}  # pico de 1 h por dia (EXOS, que levou quase todo o trafego)
    sem_energia = [(datetime(2026, 10, 27, 21, 17), datetime(2026, 10, 28, 8, 4))]
    nwt_ativa = (datetime(2026, 10, 27, 16, 47), datetime(2026, 10, 28, 10, 48))  # NWT preferencial (ajuste manual)
    exos, nwt = [], []
    hora = inicio
    while hora <= fim:
        em_queda = any(a <= hora < b for a, b in sem_energia)
        no_nwt = nwt_ativa[0] <= hora < nwt_ativa[1]
        if em_queda:
            exos.append((hora, None)); nwt.append((hora, None))
        else:
            fator = _perfil(hora.hour) * picos[hora.day]
            if no_nwt:
                exos.append((hora, 0.3)); nwt.append((hora, round(min(6.1, fator * .6 + 0.4), 2)))
            else:
                exos.append((hora, round(fator, 2))); nwt.append((hora, 0.2))
        hora += timedelta(hours=1)
    # garante os picos conhecidos
    exos = [(h, 18.0 if (h.day == 29 and h.hour == 9) else v) for h, v in exos]
    nwt = [(h, 6.1 if (h.day == 27 and h.hour == 17) else v) for h, v in nwt]
    osc = [datetime(2026, 10, 26, 2, 16), datetime(2026, 10, 26, 6, 5), datetime(2026, 10, 26, 9, 53), datetime(2026, 10, 26, 13, 42),
           datetime(2026, 10, 26, 21, 25), datetime(2026, 10, 27, 1, 11), datetime(2026, 10, 27, 5, 6), datetime(2026, 10, 27, 8, 44),
           datetime(2026, 10, 27, 12, 34)]
    eventos = [{"tipo": "oscilacao", "link": "EXOS", "quando": q, "perda_pct": 22, "duracao_s": 120, "failover_s": 1.5} for q in osc]
    eventos.append({"tipo": "oscilacao", "link": "EXOS", "quando": datetime(2026, 10, 29, 22, 49), "perda_pct": 62, "duracao_s": 120, "failover_s": 1.5})
    eventos.append({"tipo": "link_fora", "link": "NWT", "quando": datetime(2026, 10, 27, 15, 2), "duracao_s": 180,
                    "detalhe": "A conexão física com o modem caiu e voltou 3 vezes em 40 s.", "impacto": "Baixo: naquele momento o tráfego estava na EXOS."})
    eventos.append({"tipo": "ajuste", "quando": datetime(2026, 10, 27, 16, 47), "texto": "Ajuste manual: a NWT voltou a ser a preferencial."})
    eventos.append({"tipo": "ajuste", "quando": datetime(2026, 10, 28, 10, 48), "texto": "Ajuste manual temporário: a EXOS passou a ser a preferencial."})
    return {
        "cliente": "MK", "inicio": inicio, "fim": fim, "emitido_em": datetime(2026, 10, 30, 12, 40), "fonte": "Firewall pfSense",
        "expediente": (8, 18),
        "links": [
            {"nome": "NWT", "funcao": "principal", "preferencial": False, "down_mbps": 90, "up_mbps": 5, "latencia_ms": 10.3, "perda_pct": 0.0,
             "descricao": "Principal no padrão da empresa"},
            {"nome": "EXOS", "funcao": "reserva", "preferencial": True, "down_mbps": 130, "up_mbps": 135, "latencia_ms": 13.6, "perda_pct": 0.1,
             "descricao": "Reserva. Nesta semana ficou como preferencial por um ajuste temporário e levou a maior parte do tráfego"},
        ],
        "trafego_links": {"EXOS": exos, "NWT": nwt},
        "redes": [
            {"nome": "Rede principal (cabeada)", "tipo": "cabeada", "cidr": "10.35.35.0/24", "vlan": None, "gb_down": 100.4},
            {"nome": "Wi-Fi Clientes", "tipo": "wifi", "cidr": "88.66.66.0/24", "vlan": 10, "gb_down": 34.2},
            {"nome": "Wi-Fi Escritório", "tipo": "wifi", "cidr": "88.67.67.0/24", "vlan": 11, "gb_down": 20.3},
            {"nome": "VPN (túnel IPsec)", "tipo": "vpn", "cidr": None, "vlan": None, "gb_down": 1.5},
        ],
        "eventos": eventos, "sem_energia": sem_energia,
        "failover": {"configurado": True, "acionou": 10, "funcionou": 10},
        "firewall": {"cpu_pico_pct": 12}, "lan": {"latencia_ms": 0.8, "perda_pct": 0},
        "wifi": {"latencia_ms": 70, "latencia_min_ms": 40, "latencia_max_ms": 100},
        "dhcp": {"usados": 85, "total": 106},
    }
