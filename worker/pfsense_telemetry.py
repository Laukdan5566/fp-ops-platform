"""Coleta, so de leitura, do que o relatorio tecnico de internet precisa de cada pfSense:
- historico de trafego por interface (arquivos RRD que o proprio firewall mantem), agrupado por hora;
- alarmes e trocas de link (dpinger e MONITOR nos logs de gateways/sistema);
- redes/VLANs e grupos de failover (config.xml).
Nada e alterado no firewall. Os formatos de log variam entre versoes do pfSense, entao os leitores sao tolerantes e
cada coleta registra o erro (pfsense_firewalls.telemetry_error) em vez de derrubar o worker.
"""
import hashlib
import ipaddress
import json
import re
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from db import get_db
try:
    from pfsense_agent import connect_firewall, read_config, run_shell
except ImportError:
    from worker.pfsense_agent import connect_firewall, read_config, run_shell

NOME_SEGURO = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
RRDTOOL = "/usr/local/bin/rrdtool"
INTERVALO_MINUTOS = 60
HORAS_PRIMEIRA_COLETA = 240
HORAS_REVISAO = 12
MESES = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

LINHA_BSD = re.compile(r"^(?P<mes>[A-Z][a-z]{2})\s+(?P<dia>\d{1,2})\s+(?P<hora>\d{2}:\d{2}:\d{2})\s")
LINHA_ISO = re.compile(r"^(?P<data>\d{4}-\d{2}-\d{2})T(?P<hora>\d{2}:\d{2}:\d{2})(?:\.\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2})?\s")
DPINGER = re.compile(r"dpinger\[\d+\]:\s+(?P<gw>\S+)\s+\S+:\s+(?P<estado>Alarm|Clear)\s+latency\s+(?P<lat>\d+)us\s+stddev\s+\d+us\s+loss\s+(?P<perda>\d+)%")
OMIT = re.compile(r"MONITOR:\s+(?P<gw>\S+)\s+has\s+.*?omitting from routing group")
INCLUDE = re.compile(r"MONITOR:\s+(?P<gw>\S+)\s+is available now,\s+adding to routing group")


# ---------- leitura do historico (RRD) ----------
def parse_rrd_fetch(texto):
    """Saida de `rrdtool fetch`: cabecalho com os nomes das colunas e linhas 'epoch: v1 v2 ...' (nan = sem dado)."""
    colunas, linhas = None, []
    for bruto in (texto or "").splitlines():
        linha = bruto.strip()
        if not linha:
            continue
        if ":" not in linha:
            if colunas is None:
                colunas = linha.split()
            continue
        epoch, resto = linha.split(":", 1)
        if colunas is None or not epoch.strip().isdigit():
            continue
        valores = {}
        for nome, valor in zip(colunas, resto.split()):
            try:
                numero = float(valor)
            except ValueError:
                numero = None
            valores[nome] = None if numero is None or numero != numero else numero
        linhas.append((int(epoch), valores))
    return colunas or [], linhas


def agrupar_por_hora(linhas, entrada="inpass", saida="outpass"):
    """Media por hora cheia, em bits/s. O instante do rrdtool e o FIM do intervalo, por isso usa epoch-1 para achar a hora."""
    baldes = {}
    for epoch, valores in linhas:
        inicio = ((epoch - 1) // 3600) * 3600
        baldes.setdefault(inicio, []).append(valores)
    resultado = []
    for inicio in sorted(baldes):
        def media(campo):
            numeros = [v[campo] for v in baldes[inicio] if v.get(campo) is not None]
            return sum(numeros) * 8 / len(numeros) if numeros else None  # bytes/s -> bits/s
        entrada_bps, saida_bps = media(entrada), media(saida)
        if entrada_bps is None and saida_bps is None:
            continue
        resultado.append({"bucket_start": datetime.fromtimestamp(inicio, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                          "in_avg_bps": entrada_bps, "out_avg_bps": saida_bps})
    return resultado


def ler_trafego(client, interface, horas):
    if not NOME_SEGURO.match(interface or ""):
        return []
    arquivo = f"/var/db/rrd/{interface}-traffic.rrd"
    saida = run_shell(client, f"test -f {shlex.quote(arquivo)} && {RRDTOOL} fetch {shlex.quote(arquivo)} AVERAGE -r 3600 -s -{int(horas)}h || true", timeout=40)
    _, linhas = parse_rrd_fetch(saida)
    return agrupar_por_hora(linhas)


# ---------- leitura dos logs ----------
def offset_minutos(texto):
    """'-0300' (saida de `date +%z`) -> -180."""
    encontrado = re.search(r"([+-])(\d{2}):?(\d{2})", texto or "")
    if not encontrado:
        return 0
    minutos = int(encontrado.group(2)) * 60 + int(encontrado.group(3))
    return -minutos if encontrado.group(1) == "-" else minutos


def _quando_utc(linha, agora_utc, offset_min):
    iso = LINHA_ISO.match(linha)
    if iso:
        base = datetime.strptime(f"{iso['data']} {iso['hora']}", "%Y-%m-%d %H:%M:%S")
        fuso = iso["tz"]
        deslocamento = offset_minutos(fuso) if fuso and fuso != "Z" else (0 if fuso == "Z" else offset_min)
        return base - timedelta(minutes=deslocamento)
    bsd = LINHA_BSD.match(linha)
    if not bsd or bsd["mes"] not in MESES:
        return None
    hora = datetime.strptime(bsd["hora"], "%H:%M:%S")
    try:
        local = datetime(agora_utc.year, MESES[bsd["mes"]], int(bsd["dia"]), hora.hour, hora.minute, hora.second)
    except ValueError:
        return None
    utc = local - timedelta(minutes=offset_min)
    if utc > agora_utc + timedelta(days=1):  # o log nao tem ano: dezembro lido em janeiro
        utc = utc.replace(year=utc.year - 1)
    return utc


def parse_logs_gateway(texto, agora_utc, offset_min):
    """Linhas do gateways.log/system.log -> eventos normalizados: alarm, clear, omit (saiu do grupo = failover) e include."""
    eventos = []
    for linha in (texto or "").splitlines():
        achou = DPINGER.search(linha)
        if achou:
            tipo, gateway = achou["estado"].lower(), achou["gw"]
            perda, latencia = float(achou["perda"]), int(achou["lat"]) / 1000
        elif OMIT.search(linha):
            tipo, gateway, perda, latencia = "omit", OMIT.search(linha)["gw"], None, None
        elif INCLUDE.search(linha):
            tipo, gateway, perda, latencia = "include", INCLUDE.search(linha)["gw"], None, None
        else:
            continue
        quando = _quando_utc(linha, agora_utc, offset_min)
        if quando is None:
            continue
        momento = quando.strftime("%Y-%m-%d %H:%M:%S")
        chave = hashlib.sha1(f"{tipo}|{gateway}|{momento}|{perda}".encode()).hexdigest()[:24]
        eventos.append({"kind": tipo, "gateway": gateway, "event_at": momento, "loss": perda, "latency_ms": latencia, "key": chave})
    return eventos


# ---------- leitura da configuracao ----------
def info_failover(root):
    grupos = []
    for grupo in root.findall(".//gateways/gateway_group"):
        itens = []
        for item in grupo.findall("item"):
            partes = (item.text or "").split("|")
            if len(partes) >= 2 and partes[1].strip().isdigit():
                itens.append({"gateway": partes[0], "tier": int(partes[1])})
        grupos.append({"nome": grupo.findtext("name"), "itens": itens})
    configurado = any(len({i["tier"] for i in g["itens"]}) >= 2 for g in grupos)
    return {"configurado": configurado, "grupos": grupos}


def gateways_preferenciais(info):
    """Gateway de menor tier (e unico nele) do primeiro grupo de failover; load balance (tiers iguais) nao tem preferencial."""
    for grupo in info["grupos"]:
        tiers = {i["tier"] for i in grupo["itens"]}
        if len(tiers) < 2:
            continue
        melhor = min(tiers)
        primeiros = [i["gateway"] for i in grupo["itens"] if i["tier"] == melhor]
        if len(primeiros) == 1:
            return set(primeiros)
    return set()


def descobrir_redes(root, chaves_wan):
    """Interfaces internas (nao WAN) com nome, rede e VLAN; mais o tunel IPsec quando existe."""
    vlans = {f"{v.findtext('if')}.{v.findtext('tag')}": int(v.findtext("tag")) for v in root.findall(".//vlans/vlan") if (v.findtext("tag") or "").isdigit()}
    redes = []
    interfaces = root.find("interfaces")
    for no in (list(interfaces) if interfaces is not None else []):
        if no.tag in chaves_wan or no.find("enable") is None:
            continue
        ip, mascara = (no.findtext("ipaddr") or "").strip(), (no.findtext("subnet") or "").strip()
        try:
            cidr = str(ipaddress.ip_interface(f"{ip}/{mascara}").network)
        except ValueError:
            continue  # sem IPv4 fixo (dhcp/pppoe/none): nao e rede interna
        nome = (no.findtext("descr") or no.tag).strip()
        tipo = "wifi" if re.search(r"wi-?fi|wlan|wireless|sem fio", nome, re.I) else "cabeada"
        redes.append({"interface_key": no.tag, "name": nome, "kind": tipo, "cidr": cidr, "vlan": vlans.get((no.findtext("if") or "").strip())})
    if root.find(".//ipsec/phase1") is not None:
        redes.append({"interface_key": "ipsec", "name": "VPN (túnel IPsec)", "kind": "vpn", "cidr": None, "vlan": None})
    return redes


# ---------- gravacao ----------
def _agora_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def gravar(db, firewall_id, redes, info, preferenciais, trafego, eventos, agora_texto):
    existentes = {r["interface_key"] for r in db.execute("SELECT interface_key FROM pfsense_networks WHERE firewall_id=?", (firewall_id,)).fetchall()}
    for rede in redes:
        if rede["interface_key"] not in existentes:  # nao sobrescreve o que o operador editou
            db.execute("INSERT INTO pfsense_networks (firewall_id, interface_key, name, kind, cidr, vlan) VALUES (?, ?, ?, ?, ?, ?)",
                       (firewall_id, rede["interface_key"], rede["name"], rede["kind"], rede["cidr"], rede["vlan"]))
    db.execute("UPDATE pfsense_firewalls SET failover_info=? WHERE id=?", (json.dumps(info, ensure_ascii=False), firewall_id))
    for link in db.execute("SELECT id, gateway_name FROM pfsense_links WHERE firewall_id=?", (firewall_id,)).fetchall():
        db.execute("UPDATE pfsense_links SET preferred=? WHERE id=?", (1 if link["gateway_name"] in preferenciais else 0, link["id"]))
    for interface, linhas in trafego.items():
        for linha in linhas:
            db.execute(
                "INSERT INTO pfsense_traffic_hourly (firewall_id, interface_key, bucket_start, in_avg_bps, out_avg_bps, collected_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (firewall_id, interface_key, bucket_start) DO UPDATE SET in_avg_bps=excluded.in_avg_bps, out_avg_bps=excluded.out_avg_bps, collected_at=excluded.collected_at",
                (firewall_id, interface, linha["bucket_start"], linha["in_avg_bps"], linha["out_avg_bps"], agora_texto),
            )
    novos = 0
    for e in eventos:
        antes = db.execute("SELECT 1 FROM pfsense_gateway_events WHERE firewall_id=? AND event_key=?", (firewall_id, e["key"])).fetchone()
        if antes:
            continue
        db.execute("INSERT INTO pfsense_gateway_events (firewall_id, gateway_name, event_at, kind, loss_percent, latency_ms, event_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (firewall_id, e["gateway"], e["event_at"], e["kind"], e["loss"], e["latency_ms"], e["key"]))
        novos += 1
    return novos


def coletar_firewall(firewall, agora_utc=None):
    """Uma coleta completa de um firewall. Devolve um resumo; levanta erro se nao conseguir ler."""
    agora = agora_utc or _agora_utc()
    db = get_db()
    try:
        links = [dict(r) for r in db.execute("SELECT interface_key, traffic_key FROM pfsense_links WHERE firewall_id=? AND active=1", (firewall["id"],)).fetchall()]
        tem_historico = db.execute("SELECT 1 FROM pfsense_traffic_hourly WHERE firewall_id=? LIMIT 1", (firewall["id"],)).fetchone() is not None
    finally:
        db.close()
    chaves_wan = {l["traffic_key"] or l["interface_key"] for l in links}
    horas = HORAS_REVISAO if tem_historico else HORAS_PRIMEIRA_COLETA
    client = connect_firewall(firewall)
    try:
        root = ET.fromstring(read_config(client))
        offset = offset_minutos(run_shell(client, "date +%z", timeout=15))
        redes = descobrir_redes(root, chaves_wan)
        interfaces = sorted(chaves_wan | {r["interface_key"] for r in redes})
        trafego = {i: ler_trafego(client, i, horas) for i in interfaces}
        logs = run_shell(client, "cat /var/log/gateways.log /var/log/system.log 2>/dev/null | grep -E 'dpinger|MONITOR:' | tail -n 30000 || true", timeout=60)
    finally:
        client.close()
    info = info_failover(root)
    eventos = parse_logs_gateway(logs, agora, offset)
    db = get_db()
    try:
        novos = gravar(db, firewall["id"], redes, info, gateways_preferenciais(info), trafego, eventos, agora.strftime("%Y-%m-%d %H:%M:%S"))
        db.execute("UPDATE pfsense_firewalls SET telemetry_at=?, telemetry_error=NULL WHERE id=?", (agora.strftime("%Y-%m-%d %H:%M:%S"), firewall["id"]))
        db.commit()
    finally:
        db.close()
    return {"interfaces": len(interfaces), "horas_gravadas": sum(len(v) for v in trafego.values()), "eventos_novos": novos, "redes": len(redes)}


def _vencida(firewall, agora):
    ultima = firewall["telemetry_at"]
    if not ultima:
        return True
    try:
        return agora - datetime.strptime(str(ultima)[:19], "%Y-%m-%d %H:%M:%S") >= timedelta(minutes=INTERVALO_MINUTOS)
    except ValueError:
        return True


def run_due_telemetry():
    """Chamado pelo laco do worker; cada firewall e lido no maximo a cada INTERVALO_MINUTOS e um erro nao afeta os demais."""
    db = get_db()
    try:
        firewalls = [dict(r) for r in db.execute("SELECT * FROM pfsense_firewalls WHERE active=1 ORDER BY id").fetchall()]
    finally:
        db.close()
    agora, resultados = _agora_utc(), []
    for firewall in firewalls:
        if not _vencida(firewall, agora):
            continue
        try:
            resultados.append((firewall["id"], coletar_firewall(firewall, agora)))
        except Exception as erro:  # noqa: BLE001 - registra e segue para o proximo
            db = get_db()
            try:
                db.execute("UPDATE pfsense_firewalls SET telemetry_at=?, telemetry_error=? WHERE id=?",
                           (agora.strftime("%Y-%m-%d %H:%M:%S"), str(erro)[:300], firewall["id"]))
                db.commit()
            finally:
                db.close()
            resultados.append((firewall["id"], {"erro": str(erro)[:120]}))
    return resultados
