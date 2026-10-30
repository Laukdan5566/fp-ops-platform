"""Relatorio tecnico de internet: o gerador tem que chegar nos mesmos numeros e conclusoes do relatorio da MK feito a mao."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from datetime import datetime  # noqa: E402

from fixture_relatorio import dados_mk  # noqa: E402
from relatorio_tecnico import montar_relatorio  # noqa: E402

r = montar_relatorio(dados_mk())

# --- numeros de destaque
kpis = {k["valor"]: k["texto"] for k in r["kpis"]}
assert "14%" in kpis, kpis
assert "18 de ~130 Mbps" in kpis["14%"], kpis["14%"]
assert "~5 Mbps" in kpis, kpis
assert "10" in kpis and "Oscilações na EXOS" in kpis["10"] and "todas" in kpis["10"], kpis
assert "~11 h" in kpis, kpis

# --- semaforos
sit = {nome: (cor, texto) for nome, cor, texto in r["situacao"]}
assert sit["Velocidade de download × uso"] == ("ok", "Adequada"), sit
assert sit["Failover entre os links"] == ("ok", "Funcionando"), sit
assert sit["Desempenho do firewall"][0] == "ok" and sit["Rede cabeada interna"][0] == "ok", sit
assert sit["Estabilidade do link EXOS"][0] == "atencao" and "seg/ter" in sit["Estabilidade do link EXOS"][1], sit
assert sit["Estabilidade do link NWT"] == ("ok", "Estável"), sit
assert sit["Upload do link principal (NWT)"] == ("ruim", "~5 Mbps"), sit
assert sit["Proteção contra falta de energia"] == ("ruim", "Insuficiente"), sit

# --- tabela por dia
dias = {d["dia"]: d for d in r["dias"]}
assert [d["gravidade"] for d in r["dias"]] == ["atencao", "critico", "atencao", "atencao", "ok"], [d["gravidade"] for d in r["dias"]]
assert "5 oscilações na EXOS" in dias["Seg 26/10"]["ocorrencias"], dias["Seg 26/10"]
assert sit["Estabilidade do link EXOS"][1] == "Instável seg/ter", sit
assert "queda de energia às 21:17" in dias["Ter 27/10"]["ocorrencias"], dias["Ter 27/10"]
assert "Sem energia até 08:04" in dias["Qua 28/10"]["ocorrencias"], dias["Qua 28/10"]
assert "22:49" in dias["Qui 29/10"]["ocorrencias"] and "fora do expediente" in dias["Qui 29/10"]["ocorrencias"]
assert abs(dias["Qui 29/10"]["pico_hora"] - 18.0) < 0.5, dias["Qui 29/10"]  # soma dos links (o outro so tem trafego minimo)
assert dias["Sex 30/10"]["ocorrencias"].startswith("Sem ocorrências") and "12:30" in dias["Sex 30/10"]["ocorrencias"]

# --- diagnosticos e plano
sevs = [d["sev"] for d in r["diagnosticos"]]
assert sevs == ["critico", "critico", "alto", "medio", "verificar", "positivo", "baixo"], sevs
chaves = [d["chave"] for d in r["diagnosticos"]]
assert chaves[:2] == ["upload", "energia"] and "oscilacoes" in chaves and "preferencial" in chaves, chaves
osc = next(d for d in r["diagnosticos"] if d["chave"] == "oscilacoes")
assert "10 episódios" in osc["texto"] and "3h50" in osc["texto"] and "periódicas" in osc["titulo"], osc
acoes = r["plano"]
assert [a["prioridade_texto"] for a in acoes][:2] == ["Imediata", "Imediata"] and acoes[0]["n"] == 1 and len(acoes) == 6, acoes

# --- ocorrencias: grupo de 9, NWT fora, falta de energia, ajustes
linhas = r["ocorrencias"]
grupo = next(l for l in linhas if l["partes"][0][0].startswith("9 oscilações"))
texto = "".join(t for t, _ in grupo["partes"])
assert "02:16" in texto and "~3h50" in texto and ("09:53", True) in grupo["partes"], texto
assert grupo["impacto"].startswith("As 4 em negrito"), grupo["impacto"]
assert any("energia" in "".join(t for t, _ in l["partes"]) and l["quando"].startswith("Ter 27") for l in linhas)
assert [l["quando"] for l in linhas][:2] == ["Seg 26 e Ter 27", "Ter 27 · 15:02"], [l["quando"] for l in linhas]

# --- redes
assert [x["pct"] for x in r["redes"]] == [64, 22, 13, 1], r["redes"]

# --- periodos sem problema e dados minimos nao quebram
limpo = dados_mk()
limpo.update({"eventos": [], "sem_energia": [], "failover": {"configurado": True, "acionou": 0, "funcionou": 0}})
limpo["links"] = [{**limpo["links"][1], "preferencial": False, "funcao": "principal", "up_mbps": 135}, {**limpo["links"][0], "funcao": "reserva", "up_mbps": 90}]
rl = montar_relatorio(limpo)
assert all(d["gravidade"] == "ok" for d in rl["dias"]), rl["dias"]
assert not any(cor == "ruim" for _, cor, _ in rl["situacao"]), rl["situacao"]
assert "critico" not in [d["sev"] for d in rl["diagnosticos"]], rl["diagnosticos"]

minimo = {"cliente": "X", "inicio": datetime(2026, 10, 1), "fim": datetime(2026, 10, 2), "emitido_em": datetime(2026, 10, 2),
          "links": [{"nome": "UNICO", "funcao": "principal", "down_mbps": None, "up_mbps": None}]}
rm = montar_relatorio(minimo)
assert rm["diagnosticos"] == [] and rm["plano"] == [] and len(rm["dias"]) == 2, rm

print("OK: relatorio tecnico de internet reproduz os numeros e as conclusoes do relatorio da MK")
