"""Junta o relatorio montado (relatorio_tecnico) com os graficos (relatorio_graficos) no contexto da pagina HTML."""
from relatorio_graficos import (
    diagrama, faixa_disponibilidade, grafico_capacidade, grafico_redes, grafico_uso_semana, legenda_links,
)
from relatorio_tecnico import SEVERIDADES, num

METODOLOGIA_BASE = (
    "Os dados vêm do próprio firewall: o histórico de tráfego e de qualidade dos links, medido continuamente, os registros de eventos "
    "e testes periódicos de velocidade, latência e perda. Nenhuma configuração do firewall é alterada. "
    "O histórico antigo do firewall guarda só médias de 1 hora, o que esconde picos curtos. "
    "O firewall não mede a qualidade do Wi-Fi nem dos switches internos."
)


def metodologia(rel):
    extra = rel["dados"].get("limitacoes") or []
    return " ".join([METODOLOGIA_BASE, *extra])


def contexto_pagina(rel, dias_periodo=7, voltar=None):
    return {
        "r": rel, "num": num, "sev_nome": SEVERIDADES, "dias_periodo": dias_periodo, "voltar": voltar,
        "diagrama": diagrama(rel), "graf_capacidade": grafico_capacidade(rel), "graf_redes": grafico_redes(rel),
        "graf_uso": grafico_uso_semana(rel), "legenda": legenda_links(rel), "graf_disp": faixa_disponibilidade(rel),
        "metodologia": metodologia(rel),
    }
