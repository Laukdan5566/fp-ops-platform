"""Coletor de telemetria do pfSense (trafego RRD, log de gateways, redes e failover), com um firewall falso.
ATENCAO: as amostras abaixo seguem o formato documentado do pfSense/rrdtool/dpinger, mas ainda NAO foram conferidas
contra um firewall real (ver docs/relatorio-tecnico-internet.md).
Rodar: PYTHONPATH=app:worker python tests/test_pfsense_telemetry.py
"""
import json
import os
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-telemetria-test-"))
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")

import pfsense_telemetry as t  # noqa: E402
from db import get_db, init_db  # noqa: E402

# ---------- rrdtool fetch ----------
def epoch(*args):
    return int(datetime(*args, tzinfo=timezone.utc).timestamp())

h1, h2, h3 = epoch(2026, 10, 28, 11), epoch(2026, 10, 28, 12), epoch(2026, 10, 28, 13)
amostra_rrd = f"""                          inpass            outpass            inblock           outblock

{h1 + 300}: 1.0000000000e+05 2.0000000000e+04 0.0000000000e+00 0.0000000000e+00
{h1 + 600}: 3.0000000000e+05 4.0000000000e+04 0.0000000000e+00 0.0000000000e+00
{h1 + 3600}: -nan -nan -nan -nan
{h2 + 3600}: 5.0000000000e+05 1.0000000000e+05 0.0000000000e+00 0.0000000000e+00
"""
colunas, linhas = t.parse_rrd_fetch(amostra_rrd)
assert colunas == ["inpass", "outpass", "inblock", "outblock"] and len(linhas) == 4, (colunas, linhas)
assert linhas[2][1]["inpass"] is None and linhas[0][1]["inpass"] == 1e5
horas = t.agrupar_por_hora(linhas)
# o instante do rrdtool e o FIM do intervalo: h1+300 e h1+600 caem na hora 11h (media 2e5 bytes/s = 1,6 Mbps);
# a linha 12h00 e nan (ignorada); a linha 13h00 cobre a hora 12h-13h e entra no balde das 12h
assert [h["bucket_start"] for h in horas] == ["2026-10-28 11:00:00", "2026-10-28 12:00:00"], horas
assert horas[0]["in_avg_bps"] == 2e5 * 8 and horas[0]["out_avg_bps"] == 3e4 * 8 and horas[1]["in_avg_bps"] == 5e5 * 8, horas
assert t.parse_rrd_fetch("") == ([], []) and t.parse_rrd_fetch("lixo sem formato")[1] == []

# ---------- log de gateways ----------
agora = datetime(2026, 10, 30, 15, 30)
log = """Oct 28 02:16:01 fw dpinger[12345]: WAN_EXOS 177.0.0.1: Alarm latency 15421us stddev 12000us loss 22%
Oct 28 02:16:02 fw php-fpm[345]: /rc.gateway_alarm: MONITOR: WAN_EXOS has packet loss, omitting from routing group GW_FAILOVER
Oct 28 02:18:01 fw dpinger[12345]: WAN_EXOS 177.0.0.1: Clear latency 10432us stddev 400us loss 0%
Oct 28 02:18:03 fw php-fpm[345]: /rc.gateway_alarm: MONITOR: WAN_EXOS is available now, adding to routing group GW_FAILOVER
Oct 27 15:02:10 fw dpinger[999]: WAN_NWT 200.0.0.1: Alarm latency 0us stddev 0us loss 100%
Oct 27 15:05:10 fw dpinger[999]: WAN_NWT 200.0.0.1: Clear latency 9000us stddev 100us loss 0%
Oct 28 03:00:00 fw sshd[1]: nada a ver com gateways
Dec 31 23:59:00 fw dpinger[12345]: WAN_EXOS 177.0.0.1: Alarm latency 1000us stddev 10us loss 50%
"""
eventos = t.parse_logs_gateway(log, agora, -180)  # firewall em UTC-3
tipos = [(e["kind"], e["gateway"]) for e in eventos]
assert tipos == [("alarm", "WAN_EXOS"), ("omit", "WAN_EXOS"), ("clear", "WAN_EXOS"), ("include", "WAN_EXOS"), ("alarm", "WAN_NWT"), ("clear", "WAN_NWT"), ("alarm", "WAN_EXOS")], tipos
assert eventos[0]["event_at"] == "2026-10-28 05:16:01" and eventos[0]["loss"] == 22.0 and abs(eventos[0]["latency_ms"] - 15.421) < 1e-6  # 02:16 (UTC-3) = 05:16 UTC
assert eventos[4]["loss"] == 100.0 and eventos[4]["event_at"] == "2026-10-27 18:02:10"
assert eventos[6]["event_at"] == "2026-01-01 02:59:00", eventos[6]  # "Dec 31 23:59" lido em outubro e do ano anterior; 23:59 em UTC-3 = 02:59 UTC de 01/01
assert len({e["key"] for e in eventos}) == 7
# formato com data ISO e fuso
iso = "2026-10-28T02:16:01.123456-03:00 fw dpinger[1]: WAN_EXOS 1.1.1.1: Alarm latency 5000us stddev 1us loss 40%"
assert t.parse_logs_gateway(iso, agora, 0)[0]["event_at"] == "2026-10-28 05:16:01"
assert t.offset_minutos("-0300") == -180 and t.offset_minutos("+0530") == 330 and t.offset_minutos("") == 0

# ---------- config.xml: redes, VLANs e failover ----------
config = ET.fromstring("""<pfsense>
 <interfaces>
  <wan><enable/><if>igb0</if><descr>WAN_NWT</descr><ipaddr>dhcp</ipaddr></wan>
  <opt1><enable/><if>igb1</if><descr>WAN_EXOS</descr><ipaddr>177.0.0.2</ipaddr><subnet>30</subnet><gateway>EXOS_GW</gateway></opt1>
  <lan><enable/><if>igb2</if><descr>Rede principal</descr><ipaddr>10.35.35.1</ipaddr><subnet>24</subnet></lan>
  <opt2><enable/><if>igb2.10</if><descr>Wi-Fi Clientes</descr><ipaddr>88.66.66.1</ipaddr><subnet>24</subnet></opt2>
  <opt3><if>igb2.12</if><descr>Desativada</descr><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></opt3>
 </interfaces>
 <vlans><vlan><if>igb2</if><tag>10</tag></vlan></vlans>
 <ipsec><phase1><ikeid>1</ikeid></phase1></ipsec>
 <gateways>
  <gateway_group><name>GW_FAILOVER</name><item>WAN_NWT|1|address</item><item>WAN_EXOS|2|address</item></gateway_group>
 </gateways>
</pfsense>""")
redes = t.descobrir_redes(config, {"wan", "opt1"})
assert [(r["interface_key"], r["kind"], r["cidr"], r["vlan"]) for r in redes] == [
    ("lan", "cabeada", "10.35.35.0/24", None), ("opt2", "wifi", "88.66.66.0/24", 10), ("ipsec", "vpn", None, None)], redes
info = t.info_failover(config)
assert info["configurado"] is True and t.gateways_preferenciais(info) == {"WAN_NWT"}, info
balanceado = ET.fromstring("<pfsense><gateways><gateway_group><name>LB</name><item>A|1|x</item><item>B|1|x</item></gateway_group></gateways></pfsense>")
assert t.info_failover(balanceado)["configurado"] is False and t.gateways_preferenciais(t.info_failover(balanceado)) == set()
assert t.info_failover(ET.fromstring("<pfsense/>")) == {"configurado": False, "grupos": [], "padrao": ""}

# ---------- coleta completa com firewall falso, e segunda coleta sem duplicar ----------
init_db()
db = get_db()
fw = db.execute("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active) VALUES ('FW', '192.0.2.1', 'x', 'fp', 1)").lastrowid
for nome, gw, chave in (("NWT", "WAN_NWT", "wan"), ("EXOS", "WAN_EXOS", "opt1")):
    db.execute("INSERT INTO pfsense_links (firewall_id, name, provider, interface_key, device_name, gateway_name, active) VALUES (?, ?, ?, ?, ?, ?, 1)",
               (fw, nome, nome, chave, "x", gw))
db.commit()
firewall = dict(db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (fw,)).fetchone())
db.close()

comandos = []


class ClienteFalso:
    def close(self):
        pass


def falso_run_shell(client, script, timeout=20):
    comandos.append(script)
    assert "@@TZ" in script, script  # so o script em lote e esperado
    partes = ["@@TZ", "-0300"]
    for interface in ("wan", "opt1", "lan", "opt2", "ipsec"):
        if f"@@RRD:{interface}'" in script:
            partes += [f"@@RRD:{interface}", amostra_rrd if interface == "wan" else ""]
    partes += ["@@LOGINFO", "-rw-r--r--  1 root  wheel  81234 Oct 30 12:00 /var/log/gateways.log", "@@LOG", log, "@@FIM"]
    return "\r\n".join(partes)  # o menu do pfSense devolve \r\n
t.connect_firewall = lambda fw_: ClienteFalso()
t.read_config = lambda client: ET.tostring(config)
t.run_shell = falso_run_shell

resumo = t.coletar_firewall(firewall, agora)
assert resumo["eventos_novos"] == 7 and resumo["redes"] == 3 and resumo["interfaces"] == 5, resumo  # wan, opt1, lan, opt2, ipsec
assert len(comandos) == 1, "deve usar UMA execucao so (firewall com shell de menu e lento por comando)"
assert "/var/db/rrd/ipsec-traffic.rrd" in comandos[0] and " -s -240h" in comandos[0]  # primeira coleta busca mais historico

db = get_db()
assert db.execute("SELECT COUNT(*) c FROM pfsense_traffic_hourly WHERE interface_key='wan'").fetchone()["c"] == 2
assert db.execute("SELECT COUNT(*) c FROM pfsense_networks WHERE firewall_id=?", (fw,)).fetchone()["c"] == 3
assert db.execute("SELECT preferred FROM pfsense_links WHERE gateway_name='WAN_NWT'").fetchone()["preferred"] == 1
assert db.execute("SELECT preferred FROM pfsense_links WHERE gateway_name='WAN_EXOS'").fetchone()["preferred"] == 0
assert db.execute("SELECT telemetry_error, telemetry_at FROM pfsense_firewalls WHERE id=?", (fw,)).fetchone()["telemetry_error"] is None
info_gravada = json.loads(db.execute("SELECT telemetry_info FROM pfsense_firewalls WHERE id=?", (fw,)).fetchone()["telemetry_info"])
assert info_gravada["eventos_lidos"] == 7 and info_gravada["alarmes_lidos"] == 3 and info_gravada["fuso"] == "-0300", info_gravada
assert info_gravada["linhas_dpinger_monitor"] == 8 and "dpinger" in info_gravada["amostra_dpinger"][0] and "MONITOR:" in info_gravada["amostra_monitor"][0], info_gravada
assert "gateways.log" in info_gravada["arquivos"]
# o operador renomeia uma rede; a proxima coleta nao sobrescreve
db.execute("UPDATE pfsense_networks SET name='Escritorio' WHERE interface_key='lan'")
db.commit(); db.close()
comandos.clear()
resumo2 = t.coletar_firewall(firewall, agora)
assert resumo2["eventos_novos"] == 0, resumo2  # eventos ja gravados nao duplicam
assert len(comandos) == 1 and " -s -12h" in comandos[0], comandos  # depois so revisa as ultimas horas
db = get_db()
assert db.execute("SELECT name FROM pfsense_networks WHERE interface_key='lan'").fetchone()["name"] == "Escritorio"
assert db.execute("SELECT COUNT(*) c FROM pfsense_traffic_hourly WHERE interface_key='wan'").fetchone()["c"] == 2  # upsert, sem duplicar
db.close()

# ---------- agendamento: respeita o intervalo e registra erro sem derrubar ----------
def conexao_quebrada(_fw):
    raise RuntimeError("timeout de teste")

t.connect_firewall = conexao_quebrada
db = get_db()
db.execute("UPDATE pfsense_firewalls SET telemetry_at=NULL WHERE id=?", (fw,)); db.commit(); db.close()
r = t.run_due_telemetry()
assert r and "erro" in r[0][1], r
db = get_db()
assert "timeout de teste" in db.execute("SELECT telemetry_error FROM pfsense_firewalls WHERE id=?", (fw,)).fetchone()["telemetry_error"]
db.close()
assert t.run_due_telemetry() == []  # acabou de tentar: espera o intervalo

# nome de interface malicioso nao entra no script; secoes e fim de linha do menu sao tratados
script = t.montar_script(["wan", "lan; rm -rf /", "opt 1", "opt2"], 12)
assert "rm -rf" not in script and "@@RRD:wan'" in script and "@@RRD:opt2'" in script and "opt 1" not in script, script
assert script.rstrip().endswith("true")  # o ultimo comando nunca falha, senao o agente acusa erro
secoes = t.dividir_secoes("lixo antes\r\n@@TZ\r\n-0300\r\n@@RRD:wan\r\nlinha1\r\nlinha2\r\n@@FIM\r\n")
assert secoes == {"TZ": "-0300", "RRD:wan": "linha1\nlinha2", "FIM": ""}, secoes
assert t.dividir_secoes("") == {} and t.dividir_secoes(None) == {}
assert "Gateway alarm" in script  # o grep tambem pede a acao do alarme

# ---------- aprendido na primeira leitura real (firewall MK): sem linhas MONITOR:, a acao do alarme prova a troca ----------
acao = ("Oct 28 02:16:03 fw rc.gateway_alarm[999]: >>> Gateway alarm: WAN_EXOS (Addr:177.0.0.1 Alarm:1 RTT:15.4ms RTTsd:12.0ms Loss:22%)\n"
        "Oct 28 02:18:03 fw rc.gateway_alarm[999]: >>> Gateway alarm: WAN_EXOS (Addr:177.0.0.1 Alarm:0 RTT:10.4ms RTTsd:0.4ms Loss:0%)")
ev = t.parse_logs_gateway(acao, agora, -180)
assert [(e["kind"], e["gateway"]) for e in ev] == [("omit", "WAN_EXOS"), ("include", "WAN_EXOS")], ev

# o grupo padrao do firewall (defaultgw4) decide o preferencial; VPN (wireguard/peer) nao vira rede cabeada
cfg2 = ET.fromstring("""<pfsense><interfaces>
 <opt1><enable/><if>wg0</if><descr>PEER_DANIEL</descr><ipaddr>10.99.0.1</ipaddr><subnet>24</subnet></opt1>
 <opt2><enable/><if>igb2.11</if><descr>MK_ESCRITORIO</descr><ipaddr>10.0.2.1</ipaddr><subnet>24</subnet></opt2></interfaces>
 <gateways><defaultgw4>FAILOVER_EXOS</defaultgw4>
  <gateway_group><name>FAILOVER_NWT</name><item>NWT|1|address</item><item>EXOS|2|address</item></gateway_group>
  <gateway_group><name>FAILOVER_EXOS</name><item>NWT|2|address</item><item>EXOS|1|address</item></gateway_group>
 </gateways></pfsense>""")
info2 = t.info_failover(cfg2)
assert info2["padrao"] == "FAILOVER_EXOS" and t.gateways_preferenciais(info2) == {"EXOS"}, info2
assert t.gateways_preferenciais({**info2, "padrao": ""}) == {"NWT"}  # sem padrao conhecido: primeiro grupo de failover
assert [(r["interface_key"], r["kind"]) for r in t.descobrir_redes(cfg2, set())] == [("opt1", "vpn"), ("opt2", "cabeada")]

# adaptador do banco: tabela sem coluna id nao pede SELECT LASTVAL() (no Postgres isso abortava a transacao inteira)
from db import _insert_uses_default_id  # noqa: E402
assert _insert_uses_default_id("INSERT INTO pfsense_traffic_hourly (firewall_id, interface_key, bucket_start) VALUES (?, ?, ?)") is False
assert _insert_uses_default_id("INSERT INTO pfsense_networks (firewall_id, interface_key) VALUES (?, ?)") is True
print("OK: telemetria do pfSense (RRD, log de gateways, redes, failover e agendamento)")
