"""Do banco do FP Ops ao relatorio: a semana da MK, gravada nas tabelas, tem que sair com os mesmos numeros do relatorio feito a mao.
Rodar: PYTHONPATH=app:worker python tests/test_relatorio_dados.py
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-relatorio-test-"))
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import get_db, init_db  # noqa: E402
from fixture_relatorio import dados_mk  # noqa: E402
from relatorio_dados import brt_para_utc_texto as utc, coletar_dados  # noqa: E402
from relatorio_tecnico import montar_relatorio  # noqa: E402

init_db()
db = get_db()
mk = dados_mk()
inicio, fim = mk["inicio"], mk["fim"]

fw = db.execute(
    "INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, failover_info, report_expediente) "
    "VALUES ('MK', '192.0.2.10', 'x', 'fp', 1, ?, '8-18')", (json.dumps({"configurado": True}),),
).lastrowid


def novo_link(nome, gateway, chave, down, up, preferido, role=None):
    link = db.execute(
        "INSERT INTO pfsense_links (firewall_id, name, provider, interface_key, device_name, gateway_name, active, role, preferred, traffic_key) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)", (fw, nome, nome, chave, chave, gateway, role, 1 if preferido else 0, chave),
    ).lastrowid
    db.execute("INSERT INTO pfsense_link_speedtests (link_id, tested_at, status, download_mbps, upload_mbps) VALUES (?, ?, 'success', ?, ?)",
               (link, utc(datetime(2026, 10, 30, 10, 0)), down, up))
    return link


# NWT e o principal "no padrao da empresa" (role definido pelo operador); a EXOS esta como preferencial
nwt = novo_link("NWT", "WAN_NWT", "wan", 90, 5, False, role="principal")
exos = novo_link("EXOS", "WAN_EXOS", "opt1", 130, 135, True, role="reserva")
# link cadastrado mas sem nenhuma medicao (como o NET do MK): nao pode aparecer como "estavel"
db.execute("INSERT INTO pfsense_links (firewall_id, name, provider, interface_key, device_name, gateway_name, active, traffic_key) "
           "VALUES (?, 'NET', 'NET', 'wan2', 'igb9', 'WAN_NET', 1, 'wan2')", (fw,))

# trafego por hora (Mbps -> bps), vindo do mesmo gabarito
for chave, nome in (("wan", "NWT"), ("opt1", "EXOS")):
    for hora, mbps in mk["trafego_links"][nome]:
        if mbps is not None:
            db.execute("INSERT INTO pfsense_traffic_hourly (firewall_id, interface_key, bucket_start, in_avg_bps, out_avg_bps) VALUES (?, ?, ?, ?, ?)",
                       (fw, chave, utc(hora), mbps * 1e6, mbps * 1e5))
# redes internas: volume de download = saida da interface, escolhido para dar os GB do gabarito em ~106 horas ativas
horas_com_dado = sum(1 for _, v in mk["trafego_links"]["EXOS"] if v is not None)
for chave, nome, tipo, vlan, gb in (("lan", "Rede principal (cabeada)", "cabeada", None, 100.4), ("opt2", "Wi-Fi Clientes", "wifi", 10, 34.2),
                                      ("opt3", "Wi-Fi Escritório", "wifi", 11, 20.3)):
    db.execute("INSERT INTO pfsense_networks (firewall_id, interface_key, name, kind, vlan) VALUES (?, ?, ?, ?, ?)", (fw, chave, nome, tipo, vlan))
    bps = gb * 1e9 * 8 / (horas_com_dado * 3600)
    hora = inicio
    while hora <= fim:
        if any(not (a <= hora < b) for a, b in mk["sem_energia"]):
            db.execute("INSERT INTO pfsense_traffic_hourly (firewall_id, interface_key, bucket_start, in_avg_bps, out_avg_bps) VALUES (?, ?, ?, 0, ?)",
                       (fw, chave, utc(hora), bps))
        hora += timedelta(hours=1)

# eventos do log de gateways: alarme -> troca (omit) 1,5 s depois -> normalizou 2 min depois
for e in mk["eventos"]:
    if e["tipo"] == "oscilacao":
        gw = "WAN_EXOS"
        db.execute("INSERT INTO pfsense_gateway_events (firewall_id, gateway_name, event_at, kind, loss_percent, event_key) VALUES (?, ?, ?, 'alarm', ?, ?)",
                   (fw, gw, utc(e["quando"]), e["perda_pct"], f"a{e['quando']}"))
        db.execute("INSERT INTO pfsense_gateway_events (firewall_id, gateway_name, event_at, kind, event_key) VALUES (?, ?, ?, 'omit', ?)",
                   (fw, gw, utc(e["quando"] + timedelta(seconds=1)), f"o{e['quando']}"))
        db.execute("INSERT INTO pfsense_gateway_events (firewall_id, gateway_name, event_at, kind, event_key) VALUES (?, ?, ?, 'clear', ?)",
                   (fw, gw, utc(e["quando"] + timedelta(minutes=2)), f"c{e['quando']}"))
    elif e["tipo"] == "link_fora":
        db.execute("INSERT INTO pfsense_gateway_events (firewall_id, gateway_name, event_at, kind, loss_percent, event_key) VALUES (?, 'WAN_NWT', ?, 'alarm', 100, ?)",
                   (fw, utc(e["quando"]), f"a{e['quando']}"))
        db.execute("INSERT INTO pfsense_gateway_events (firewall_id, gateway_name, event_at, kind, event_key) VALUES (?, 'WAN_NWT', ?, 'clear', ?)",
                   (fw, utc(e["quando"] + timedelta(seconds=e["duracao_s"])), f"c{e['quando']}"))

# verificacoes a cada 5 min: uptime continuo, exceto o reinicio da quarta 08:04 depois de horas fora
boot0 = datetime(2026, 9, 20, 0, 0)
boot1 = datetime(2026, 10, 28, 8, 4)
hora = inicio
while hora <= fim:
    if not (datetime(2026, 10, 27, 21, 17) <= hora < datetime(2026, 10, 28, 8, 5)):
        base = boot0 if hora < datetime(2026, 10, 27, 21, 17) else boot1
        db.execute("INSERT INTO pfsense_checks (firewall_id, checked_at, status, load1, cpu_count, metrics_json) VALUES (?, ?, 'online', 0.3, 4, ?)",  # 'online' e o status real das verificacoes em producao
                   (fw, utc(hora), json.dumps({"UPTIME_SECONDS": int((hora - base).total_seconds())})))
    # durante a queda o monitor registra erro (sem uptime): nao pode atrapalhar a deteccao
    if datetime(2026, 10, 27, 21, 17) <= hora < datetime(2026, 10, 28, 8, 5):
        db.execute("INSERT INTO pfsense_checks (firewall_id, checked_at, status, error) VALUES (?, ?, 'error', 'timeout')", (fw, utc(hora)))
    hora += timedelta(minutes=5)
db.commit()

# ---------- do banco ao relatorio ----------
dados = coletar_dados(db, fw, inicio, fim, emitido_em=mk["emitido_em"])
assert dados["cliente"] == "MK" and dados["expediente"] == (8, 18)
assert {l["nome"]: l["funcao"] for l in dados["links"]} == {"NWT": "principal", "EXOS": "reserva"}, dados["links"]  # NET (sem medicao) ficou de fora
assert any("NET ficou fora do relatório" in t for t in dados["limitacoes"]), dados["limitacoes"]
assert [l["nome"] for l in dados["links"] if l["preferencial"]] == ["EXOS"]
assert len(dados["sem_energia"]) == 1, dados["sem_energia"]
queda_ini, queda_fim = dados["sem_energia"][0]
assert queda_fim == boot1 and abs((queda_ini - datetime(2026, 10, 27, 21, 17)).total_seconds()) <= 300, dados["sem_energia"]
osc = [e for e in dados["eventos"] if e["tipo"] == "oscilacao"]
assert len(osc) == 10 and all(e["failover_s"] == 1 and e["link"] == "EXOS" for e in osc), osc
fora = [e for e in dados["eventos"] if e["tipo"] == "link_fora"]
assert len(fora) == 1 and fora[0]["link"] == "NWT" and fora[0]["duracao_s"] == 180, fora
assert dados["failover"] == {"configurado": True, "acionou": 10, "funcionou": 10, "verificado": True}, dados["failover"]
assert abs(sum(r["gb_down"] for r in dados["redes"]) - 155.0) < 1.5, dados["redes"]

r = montar_relatorio(dados)
kpis = {k["valor"]: k["texto"] for k in r["kpis"]}
assert "14%" in kpis and "~5 Mbps" in kpis and "~11 h" in kpis, kpis
assert "10" in kpis and "todas" in kpis["10"], kpis
sit = {nome: (cor, texto) for nome, cor, texto in r["situacao"]}
assert sit["Failover entre os links"] == ("ok", "Funcionando") and sit["Upload do link principal (NWT)"][0] == "ruim", sit
assert sit["Desempenho do firewall"] == ("ok", "Adequado"), sit
assert [d["gravidade"] for d in r["dias"]] == ["atencao", "critico", "atencao", "atencao", "ok"], [d["gravidade"] for d in r["dias"]]
assert [d["chave"] for d in r["diagnosticos"]][:2] == ["upload", "energia"], r["diagnosticos"]
assert [round(x["pct"]) for x in r["redes"]] == [65, 22, 13], r["redes"]

# ---------- plano B: sem o log de gateways, as oscilacoes saem das sondas ----------
db.execute("DELETE FROM pfsense_gateway_events WHERE firewall_id=?", (fw,))
for e in [x for x in mk["eventos"] if x["tipo"] == "oscilacao"]:
    db.execute("INSERT INTO pfsense_link_probes (link_id, probed_at, status, latency_ms, packet_loss_percent) VALUES (?, ?, 'online', 14, 22)",
               (exos, utc(e["quando"])))
db.execute("INSERT INTO pfsense_link_probes (link_id, probed_at, status, latency_ms, packet_loss_percent) VALUES (?, ?, 'online', 12, 0)",
           (exos, utc(datetime(2026, 10, 28, 12, 0))))
db.commit()
plano_b = coletar_dados(db, fw, inicio, fim)
osc_b = [e for e in plano_b["eventos"] if e["tipo"] == "oscilacao"]
assert len(osc_b) == 10 and all(e["failover_s"] is None for e in osc_b), osc_b
assert plano_b["failover"]["verificado"] is False and any("sondas" in t for t in plano_b["limitacoes"]), plano_b["failover"]
rb = montar_relatorio(plano_b)
sit_b = {nome: (cor, texto) for nome, cor, texto in rb["situacao"]}
assert sit_b["Failover entre os links"] == ("ok", "Configurado"), sit_b  # nao afirma "funcionando" sem prova
assert "failover agiu" not in " ".join(k["texto"] for k in rb["kpis"]), rb["kpis"]
assert not any(d["chave"] == "failover" for d in rb["diagnosticos"])

# firewall inexistente
assert coletar_dados(db, 9999, inicio, fim) is None
db.close()
print("OK: do banco ao relatorio da MK (log de gateways, plano B pelas sondas, queda de energia pelo uptime)")
