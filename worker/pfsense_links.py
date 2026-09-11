import hashlib
import json
import re
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

from db import get_db
try:
    from pfsense_agent import connect_firewall, read_config, run_shell
except ImportError:
    from worker.pfsense_agent import connect_firewall, read_config, run_shell


DEVICE_RE = re.compile(r"[A-Za-z0-9_.:-]+")
PROBE_TARGET = "1.1.1.1"


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _provider_name(description, gateway_name):
    text = (description or gateway_name or "Internet").replace("WAN_", "").replace("_DHCP", "")
    return text.replace("_", " ").strip().title() or "Internet"


def discover_links(firewall):
    client = connect_firewall(firewall)
    try:
        root = ET.fromstring(read_config(client))
    finally:
        client.close()
    interfaces = {node.tag: node for node in list(root.find("interfaces") or [])}
    discovered = []
    seen = set()
    for gateway in root.findall(".//gateways/gateway_item"):
        interface_key = (gateway.findtext("interface") or "").strip()
        gateway_name = (gateway.findtext("name") or "").strip()
        node = interfaces.get(interface_key)
        if node is None or interface_key in seen:
            continue
        device = (node.findtext("if") or "").strip()
        if not DEVICE_RE.fullmatch(device) or device.startswith("tun_wg"):
            continue
        description = (node.findtext("descr") or interface_key).strip()
        seen.add(interface_key)
        discovered.append({
            "name": description,
            "provider": _provider_name(description, gateway_name),
            "interface_key": interface_key,
            "device_name": device,
            "gateway_name": gateway_name,
        })
    return discovered


def sync_discovered_links(firewall):
    discovered = discover_links(firewall)
    db = get_db()
    now = now_text()
    created = 0
    try:
        for item in discovered:
            current = db.execute(
                "SELECT id FROM pfsense_links WHERE firewall_id=? AND interface_key=?",
                (firewall["id"], item["interface_key"]),
            ).fetchone()
            if current:
                db.execute(
                    """
                    UPDATE pfsense_links
                    SET device_name=?, gateway_name=?, updated_at=? WHERE id=?
                    """,
                    (item["device_name"], item["gateway_name"], now, current["id"]),
                )
            else:
                db.execute(
                    """
                    INSERT INTO pfsense_links
                        (firewall_id, name, provider, interface_key, device_name, gateway_name,
                         active, probe_enabled, speedtest_enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 1, 0, ?, ?)
                    """,
                    (
                        firewall["id"], item["name"], item["provider"], item["interface_key"],
                        item["device_name"], item["gateway_name"], now, now,
                    ),
                )
                created += 1
        db.commit()
        return {"status": "success", "found": len(discovered), "created": created}
    finally:
        db.close()


def _source_command(device, body):
    if not DEVICE_RE.fullmatch(device or ""):
        raise ValueError("Interface WAN invalida.")
    return f"""
source_ip=$(ifconfig {shlex.quote(device)} inet 2>/dev/null | awk '/inet / {{print $2; exit}}')
test -n "$source_ip" || exit 41
{body}
"""


def _firewall_for_link(db, link):
    return db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (link["firewall_id"],)).fetchone()


def run_link_probe(link, firewall):
    probed_at = now_text()
    db = get_db()
    client = None
    try:
        client = connect_firewall(firewall)
        body = rf"""
public_ip=$(/usr/local/bin/curl --interface "$source_ip" --connect-timeout 8 --max-time 15 -fsS https://cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '$1 == "ip" {{print $2; exit}}')
test -n "$public_ip" || exit 42
ping_output=$(ping -S "$source_ip" -c 4 -W 2000 {PROBE_TARGET} 2>&1 || true)
loss=$(printf '%s\n' "$ping_output" | sed -nE 's/.*, ([0-9.]+)% packet loss.*/\1/p' | tail -n 1)
average=$(printf '%s\n' "$ping_output" | sed -nE 's#.* = [0-9.]+/([0-9.]+)/.*#\1#p' | tail -n 1)
echo "PUBLIC_IP=$public_ip"
echo "LOSS=${{loss:-100}}"
echo "AVERAGE=${{average:-0}}"
"""
        output = run_shell(client, _source_command(link["device_name"], body), timeout=35)
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        route_id = hashlib.sha256(values["PUBLIC_IP"].encode()).hexdigest()[:12]
        loss = round(float(values.get("LOSS") or 100), 2)
        average_value = float(values.get("AVERAGE") or 0)
        latency = round(average_value, 2) if average_value > 0 else None
        status = "online"
        db.execute(
            """
            INSERT INTO pfsense_link_probes
                (link_id, probed_at, status, latency_ms, packet_loss_percent, target, route_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (link["id"], probed_at, status, latency, loss, PROBE_TARGET, route_id),
        )
        db.execute(
            """
            UPDATE pfsense_links SET last_probe_at=?, last_probe_status=?,
                last_probe_error=NULL, probe_requested_at=NULL, updated_at=? WHERE id=?
            """,
            (probed_at, status, probed_at, link["id"]),
        )
        db.commit()
        return {"status": status, "latency_ms": latency, "packet_loss_percent": loss, "route_id": route_id}
    except Exception as exc:
        db.rollback()
        error = str(exc)[:500]
        db.execute(
            "INSERT INTO pfsense_link_probes (link_id, probed_at, status, target, error) VALUES (?, ?, 'error', ?, ?)",
            (link["id"], probed_at, PROBE_TARGET, error),
        )
        db.execute(
            "UPDATE pfsense_links SET last_probe_at=?, last_probe_status='error', last_probe_error=?, probe_requested_at=NULL, updated_at=? WHERE id=?",
            (probed_at, error, probed_at, link["id"]),
        )
        db.commit()
        return {"status": "error", "error": error}
    finally:
        if client:
            client.close()
        db.close()


def run_link_speedtest(link, firewall):
    tested_at = now_text()
    db = get_db()
    client = None
    try:
        client = connect_firewall(firewall)
        body = '/bin/timeout 180 /usr/local/bin/speedtest-cli --source "$source_ip" --json --secure'
        output = run_shell(client, _source_command(link["device_name"], body), timeout=210)
        payload = next(
            (json.loads(line) for line in reversed(output.splitlines()) if line.lstrip().startswith("{")), None
        )
        if not payload:
            raise RuntimeError("O speedtest-cli nao retornou dados validos.")
        download = round(float(payload.get("download") or 0) / 1_000_000, 2)
        upload = round(float(payload.get("upload") or 0) / 1_000_000, 2)
        ping = round(float(payload.get("ping") or 0), 2)
        contracted_down = float(link["contracted_down_mbps"] or 0)
        contracted_up = float(link["contracted_up_mbps"] or 0)
        delivered_down = round(download * 100 / contracted_down, 2) if contracted_down else None
        delivered_up = round(upload * 100 / contracted_up, 2) if contracted_up else None
        server = payload.get("server") or {}
        public_ip = str((payload.get("client") or {}).get("ip") or "")
        route_id = hashlib.sha256(public_ip.encode()).hexdigest()[:12] if public_ip else None
        db.execute(
            """
            INSERT INTO pfsense_link_speedtests
                (link_id, tested_at, status, ping_ms, download_mbps, upload_mbps,
                 delivered_down_percent, delivered_up_percent, server_name,
                 server_sponsor, route_id)
            VALUES (?, ?, 'success', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                link["id"], tested_at, ping, download, upload, delivered_down,
                delivered_up, server.get("name"), server.get("sponsor"), route_id,
            ),
        )
        db.execute(
            """
            UPDATE pfsense_links SET last_speedtest_at=?, last_speedtest_status='success',
                last_speedtest_error=NULL, speedtest_requested_at=NULL, updated_at=? WHERE id=?
            """,
            (tested_at, tested_at, link["id"]),
        )
        db.commit()
        return {
            "status": "success", "download_mbps": download, "upload_mbps": upload,
            "ping_ms": ping, "delivered_down_percent": delivered_down,
            "delivered_up_percent": delivered_up, "route_id": route_id,
        }
    except Exception as exc:
        db.rollback()
        error = str(exc)[:500]
        db.execute(
            "INSERT INTO pfsense_link_speedtests (link_id, tested_at, status, error) VALUES (?, ?, 'error', ?)",
            (link["id"], tested_at, error),
        )
        db.execute(
            "UPDATE pfsense_links SET last_speedtest_at=?, last_speedtest_status='error', last_speedtest_error=?, speedtest_requested_at=NULL, updated_at=? WHERE id=?",
            (tested_at, error, tested_at, link["id"]),
        )
        db.commit()
        return {"status": "error", "error": error}
    finally:
        if client:
            client.close()
        db.close()


def _due(last_value, amount, unit):
    last = parse_time(last_value)
    delta = timedelta(minutes=amount) if unit == "minutes" else timedelta(hours=amount)
    return not last or datetime.now() - last >= delta


def run_due_link_tests():
    db = get_db()
    try:
        links = [dict(row) for row in db.execute("SELECT * FROM pfsense_links WHERE active=1 ORDER BY id").fetchall()]
        firewalls = {link["firewall_id"]: dict(_firewall_for_link(db, link)) for link in links}
    finally:
        db.close()
    results = []
    for link in links:
        firewall = firewalls[link["firewall_id"]]
        if link["probe_enabled"] and not link["probe_requested_at"] and _due(link["last_probe_at"], max(1, int(link["probe_interval_minutes"] or 5)), "minutes"):
            result = run_link_probe(link, firewall)
            results.append((link["id"], "probe", result["status"]))
        if link["speedtest_enabled"] and not link["speedtest_requested_at"] and _due(link["last_speedtest_at"], max(1, int(link["speedtest_interval_hours"] or 6)), "hours"):
            result = run_link_speedtest(link, firewall)
            results.append((link["id"], "speedtest", result["status"]))
    if results:
        print(f"pfSense links: {results}", flush=True)
    return results


def run_requested_link_tests():
    db = get_db()
    try:
        links = [dict(row) for row in db.execute(
            """
            SELECT * FROM pfsense_links
            WHERE active=1 AND (probe_requested_at IS NOT NULL OR speedtest_requested_at IS NOT NULL)
            ORDER BY id
            """
        ).fetchall()]
        firewalls = {link["firewall_id"]: dict(_firewall_for_link(db, link)) for link in links}
    finally:
        db.close()
    results = []
    for link in links:
        firewall = firewalls[link["firewall_id"]]
        if link["probe_requested_at"]:
            results.append((link["id"], "probe", run_link_probe(link, firewall)["status"]))
        if link["speedtest_requested_at"]:
            results.append((link["id"], "speedtest", run_link_speedtest(link, firewall)["status"]))
    if results:
        print(f"pfSense requested jobs: {results}", flush=True)
    return results
