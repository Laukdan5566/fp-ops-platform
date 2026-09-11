import base64
import hashlib
import io
import json
import os
import re
import secrets
import socket
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

import paramiko

from db import get_db
from pfsense_storage import upload_backup_from_db
from secret_store import decrypt_secret, encrypt_backup


BACKUP_ROOT = Path(os.getenv("PFSENSE_BACKUP_DIR", "/data/pfsense-backups"))


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def host_key_fingerprint(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def load_private_key(value):
    errors = []
    for key_type in (
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
    ):
        try:
            return key_type.from_private_key(io.StringIO(value))
        except Exception as exc:
            errors.append(type(exc).__name__)
    raise RuntimeError("Unsupported or invalid SSH private key")


def _read_server_host_key(address, port):
    probe = socket.create_connection((address, int(port)), timeout=10)
    transport = paramiko.Transport(probe)
    try:
        transport.start_client(timeout=10)
        return transport.get_remote_server_key()
    finally:
        transport.close()
        probe.close()


def discover_host_key_fingerprint(address, port):
    return host_key_fingerprint(_read_server_host_key(address, port))


def connect_firewall(firewall):
    address = firewall["address"]
    port = int(firewall["ssh_port"] or 22)
    username = decrypt_secret(firewall["username_enc"])
    password = decrypt_secret(firewall["password_enc"])
    private_key_text = decrypt_secret(firewall["private_key_enc"])
    expected_fingerprint = (firewall["host_key_fingerprint"] or "").strip()
    if not username:
        raise RuntimeError("SSH username is not configured")
    if not expected_fingerprint:
        raise RuntimeError("SSH host key fingerprint is not configured")

    server_key = _read_server_host_key(address, port)
    actual_fingerprint = host_key_fingerprint(server_key)
    if not secrets.compare_digest(actual_fingerprint, expected_fingerprint):
        raise RuntimeError("SSH host key fingerprint mismatch")

    host_name = f"[{address}]:{port}" if port != 22 else address
    host_keys = paramiko.HostKeys()
    host_keys.add(host_name, server_key.get_name(), server_key)
    client = paramiko.SSHClient()
    client._host_keys = host_keys
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    kwargs = {
        "hostname": address,
        "port": port,
        "username": username,
        "look_for_keys": False,
        "allow_agent": False,
        "timeout": 10,
        "auth_timeout": 10,
        "banner_timeout": 10,
    }
    auth_type = firewall["auth_type"] or ("ssh_key" if private_key_text else "password")
    if auth_type == "password" and password:
        kwargs["password"] = password
    elif auth_type == "ssh_key" and private_key_text:
        kwargs["pkey"] = load_private_key(private_key_text)
    else:
        raise RuntimeError(f"No SSH credential is configured for {auth_type} authentication")
    try:
        client.connect(**kwargs)
    except Exception:
        # Paramiko may already have started a Transport thread before an
        # authentication, banner or network error is raised.  If the client
        # is not returned to the caller, its usual finally block cannot close
        # that thread and repeated failures eventually exhaust the worker's
        # PID/thread limit.
        client.close()
        raise
    return client


def _uses_pfsense_menu_shell(client):
    cached = getattr(client, "_backup_monitor_menu_shell", None)
    if cached is not None:
        return cached
    username = client.get_transport().get_username()
    menu_shell = False
    sftp = client.open_sftp()
    try:
        with sftp.open("/etc/passwd", "rb") as handle:
            content = handle.read().decode("utf-8", "replace")
        record = next(
            (line for line in content.splitlines() if line.startswith(f"{username}:")), ""
        )
        menu_shell = bool(record and record.split(":")[-1] == "/etc/rc.initial")
    finally:
        sftp.close()
    client._backup_monitor_menu_shell = menu_shell
    return menu_shell


def _run_pfsense_menu_shell(client, script, timeout):
    token = "BM_" + secrets.token_hex(12).upper()
    begin_marker = f"{token}_BEGIN"
    end_prefix = f"{token}_END:"
    remote_path = f"/tmp/.backup-monitor-{token}.sh"
    wrapper = (
        "#!/bin/sh\n"
        f"printf '\\n{begin_marker}\\n'\n"
        f"{script}\n"
        "bm_status=$?\n"
        f"printf '\\n{end_prefix}%s\\n' \"$bm_status\"\n"
        "exit \"$bm_status\"\n"
    )
    sftp = client.open_sftp()
    try:
        with sftp.open(remote_path, "w") as handle:
            handle.write(wrapper)
        sftp.chmod(remote_path, 0o700)
    finally:
        sftp.close()
    command = f"/bin/sh {remote_path}; /bin/rm -f {remote_path}; exit\n"
    channel = client.invoke_shell(width=160, height=48)
    channel.settimeout(1)
    deadline = time.monotonic() + timeout
    output = ""
    try:
        while "Enter an option:" not in output and time.monotonic() < deadline:
            try:
                output += channel.recv(65535).decode("utf-8", "replace")
            except socket.timeout:
                pass
        if "Enter an option:" not in output:
            raise RuntimeError("pfSense console menu did not become ready")
        channel.send("8\n")
        time.sleep(0.3)
        channel.send(command)
        status_match = None
        while time.monotonic() < deadline:
            try:
                chunk = channel.recv(65535)
            except socket.timeout:
                continue
            if not chunk:
                break
            output += chunk.decode("utf-8", "replace")
            status_match = re.search(re.escape(end_prefix) + r"(\d+)", output)
            if status_match:
                break
        if not status_match:
            detail = output[-500:].replace("\r", " ").replace("\n", " ")
            raise RuntimeError(f"pfSense interactive shell command timed out: {detail}")
        begin_at = output.rfind(begin_marker, 0, status_match.start())
        if begin_at < 0:
            raise RuntimeError("pfSense interactive shell returned an invalid response")
        body = output[begin_at + len(begin_marker):status_match.start()].strip("\r\n")
        status = int(status_match.group(1))
        if status != 0:
            raise RuntimeError(f"Remote read command failed: {body[-300:] or f'exit {status}'}")
        return body.strip()
    finally:
        channel.close()
        try:
            sftp = client.open_sftp()
            try:
                sftp.remove(remote_path)
            finally:
                sftp.close()
        except OSError:
            pass


def run_shell(client, script, timeout=20):
    if _uses_pfsense_menu_shell(client):
        return _run_pfsense_menu_shell(client, script, timeout)
    payload = base64.b64encode(script.encode("utf-8")).decode("ascii")
    command = f"printf %s {payload} | /usr/bin/base64 -d | /bin/sh"
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace").strip()
    error = stderr.read().decode("utf-8", "replace").strip()
    status = stdout.channel.recv_exit_status()
    if status != 0:
        detail = error or output or f"exit {status}"
        raise RuntimeError(f"Remote read command failed: {detail[:300]}")
    return output


def parse_key_values(output):
    result = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def xml_inventory(data):
    root = ET.fromstring(data)
    interfaces = root.find("interfaces")
    dhcpd = root.find("dhcpd")
    return {
        "xml_root": root.tag,
        "interfaces_configured": len(list(interfaces)) if interfaces is not None else 0,
        "vlans": len(root.findall(".//vlans/vlan")),
        "firewall_rules": len(root.findall(".//filter/rule")),
        "gateways_configured": len(root.findall(".//gateways/gateway_item")),
        "openvpn_servers_configured": len(root.findall(".//openvpn/openvpn-server")),
        "openvpn_clients_configured": len(root.findall(".//openvpn/openvpn-client")),
        "ipsec_phase1": len(root.findall(".//ipsec/phase1")),
        "ipsec_phase2": len(root.findall(".//ipsec/phase2")),
        "dhcp_scopes": len(list(dhcpd)) if dhcpd is not None else 0,
        "certificates": len(root.findall(".//cert")),
        "certificate_authorities": len(root.findall(".//ca")),
    }


def collect_metrics(client):
    script = r'''
echo "HOSTNAME=$(hostname)"
if test -r /etc/version; then echo "VERSION=$(cat /etc/version)"; fi
echo "PLATFORM=$(uname -srm)"
echo "CPU_COUNT=$(sysctl -n hw.ncpu)"
echo "MEMORY_BYTES=$(sysctl -n hw.physmem)"
boot_epoch=$(sysctl -n kern.boottime | awk '{gsub(/,/, "", $4); print $4}')
now_epoch=$(date +%s)
case "$boot_epoch" in
  ''|*[!0-9]*) uptime_seconds=0 ;;
  *) uptime_seconds=$((now_epoch-boot_epoch)); [ "$uptime_seconds" -ge 0 ] || uptime_seconds=0 ;;
esac
echo "UPTIME_SECONDS=$uptime_seconds"
set -- $(uptime | sed -E 's/.*load averages?: //' | tr -d ',')
echo "LOAD1=${1:-0}"
echo "LOAD5=${2:-0}"
echo "LOAD15=${3:-0}"
set -- $(df -k / | tail -n 1)
echo "DISK_TOTAL_KB=$2"
echo "DISK_USED_KB=$3"
echo "DISK_PERCENT=$(echo "$5" | tr -d '%')"
interfaces=$(ifconfig -l)
echo "INTERFACES_TOTAL=$(echo "$interfaces" | wc -w | tr -d ' ')"
up=0
for interface in $interfaces; do
  if ifconfig "$interface" 2>/dev/null | head -n 1 | grep -q '<.*UP'; then up=$((up+1)); fi
done
echo "INTERFACES_UP=$up"
echo "GATEWAY_MONITORS=$(pgrep -f '/dpinger ' 2>/dev/null | wc -l | tr -d ' ')"
echo "OPENVPN_PROCESSES=$(pgrep -f '/openvpn ' 2>/dev/null | wc -l | tr -d ' ')"
echo "IPSEC_PROCESSES=$(pgrep -f '/charon' 2>/dev/null | wc -l | tr -d ' ')"
echo "WIREGUARD_INTERFACES=$(echo "$interfaces" | tr ' ' '\n' | grep -c '^tun_wg' || true)"
echo "UNBOUND_PROCESSES=$(pgrep -x unbound 2>/dev/null | wc -l | tr -d ' ')"
echo "NTP_PROCESSES=$(pgrep -x ntpd 2>/dev/null | wc -l | tr -d ' ')"
'''
    raw = parse_key_values(run_shell(client, script))
    integer_keys = {
        "CPU_COUNT", "MEMORY_BYTES", "UPTIME_SECONDS", "DISK_TOTAL_KB",
        "DISK_USED_KB", "DISK_PERCENT", "INTERFACES_TOTAL", "INTERFACES_UP",
        "GATEWAY_MONITORS", "OPENVPN_PROCESSES", "IPSEC_PROCESSES",
        "WIREGUARD_INTERFACES", "UNBOUND_PROCESSES", "NTP_PROCESSES",
    }
    float_keys = {"LOAD1", "LOAD5", "LOAD15"}
    for key in integer_keys:
        try:
            raw[key] = int(raw.get(key, 0))
        except (TypeError, ValueError):
            raw[key] = 0
    for key in float_keys:
        try:
            raw[key] = float(raw.get(key, 0))
        except (TypeError, ValueError):
            raw[key] = 0.0
    return raw


def read_config(client):
    sftp = client.open_sftp()
    try:
        remote = sftp.open("/conf/config.xml", "rb")
        try:
            data = remote.read()
        finally:
            remote.close()
    finally:
        sftp.close()
    if not data.startswith(b"<?xml") and b"<pfsense" not in data[:500]:
        raise RuntimeError("pfSense configuration is not valid XML")
    return data


def save_encrypted_backup(firewall, data, config_hash, changed):
    encrypted = encrypt_backup(data)
    directory = BACKUP_ROOT / str(firewall["id"])
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = directory / f"pfsense-{timestamp}-{config_hash[:12]}.xml.fernet"
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(encrypted)
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)
    return target, len(encrypted)


def prune_backups(db, firewall):
    cutoff = datetime.now() - timedelta(days=max(1, int(firewall["backup_retention_days"] or 30)))
    rows = db.execute(
        "SELECT id, created_at, file_path FROM pfsense_backups WHERE firewall_id=? ORDER BY id",
        (firewall["id"],),
    ).fetchall()
    for row in rows:
        created = parse_time(row["created_at"])
        if not created or created >= cutoff:
            continue
        path = Path(row["file_path"] or "")
        try:
            if path.is_file() and BACKUP_ROOT in path.parents:
                path.unlink()
        except OSError:
            continue
        db.execute("DELETE FROM pfsense_backups WHERE id=?", (row["id"],))


def backup_is_due(firewall):
    last_backup = parse_time(firewall["last_backup_at"])
    interval = max(1, int(firewall["backup_interval_hours"] or 24))
    return not last_backup or datetime.now() - last_backup >= timedelta(hours=interval)


def check_is_due(firewall):
    last_check = parse_time(firewall["last_check_at"])
    interval = max(1, int(firewall["monitor_interval_minutes"] or 5))
    return not last_check or datetime.now() - last_check >= timedelta(minutes=interval)


def speedtest_is_due(firewall):
    if not firewall["speedtest_enabled"] or firewall["speedtest_requested_at"]:
        return False
    last_test = parse_time(firewall["last_speedtest_at"])
    interval = max(1, int(firewall["speedtest_interval_hours"] or 6))
    return not last_test or datetime.now() - last_test >= timedelta(hours=interval)


def run_firewall_speedtest(firewall):
    tested_at = now_text()
    client = None
    db = get_db()
    try:
        client = connect_firewall(firewall)
        output = run_shell(
            client,
            "/bin/timeout 180 /usr/local/bin/speedtest-cli --json --secure",
            timeout=210,
        )
        payload = next(
            (json.loads(line) for line in reversed(output.splitlines()) if line.lstrip().startswith("{")),
            None,
        )
        if not payload:
            raise RuntimeError("O speedtest-cli nao retornou dados JSON validos.")
        server = payload.get("server") or {}
        ping_ms = round(float(payload.get("ping") or 0), 2)
        download_mbps = round(float(payload.get("download") or 0) / 1_000_000, 2)
        upload_mbps = round(float(payload.get("upload") or 0) / 1_000_000, 2)
        db.execute(
            """
            INSERT INTO pfsense_speedtests
                (firewall_id, tested_at, status, ping_ms, download_mbps, upload_mbps,
                 server_id, server_name, server_sponsor)
            VALUES (?, ?, 'success', ?, ?, ?, ?, ?, ?)
            """,
            (
                firewall["id"], tested_at, ping_ms, download_mbps, upload_mbps,
                str(server.get("id") or ""), server.get("name"), server.get("sponsor"),
            ),
        )
        db.execute(
            """
            UPDATE pfsense_firewalls
            SET last_speedtest_at=?, last_speedtest_status='success',
                last_speedtest_error=NULL, speedtest_requested_at=NULL, updated_at=?
            WHERE id=?
            """,
            (tested_at, tested_at, firewall["id"]),
        )
        db.commit()
        return {
            "status": "success", "ping_ms": ping_ms,
            "download_mbps": download_mbps, "upload_mbps": upload_mbps,
        }
    except Exception as exc:
        db.rollback()
        error = str(exc)[:500]
        db.execute(
            """
            INSERT INTO pfsense_speedtests (firewall_id, tested_at, status, error)
            VALUES (?, ?, 'error', ?)
            """,
            (firewall["id"], tested_at, error),
        )
        db.execute(
            """
            UPDATE pfsense_firewalls
            SET last_speedtest_at=?, last_speedtest_status='error',
                last_speedtest_error=?, speedtest_requested_at=NULL, updated_at=?
            WHERE id=?
            """,
            (tested_at, error, tested_at, firewall["id"]),
        )
        db.commit()
        return {"status": "error", "error": error}
    finally:
        if client:
            client.close()
        db.close()


def run_firewall_check(firewall, force_backup=False):
    started = time.monotonic()
    checked_at = now_text()
    client = None
    created_backup_path = None
    db = get_db()
    try:
        client = connect_firewall(firewall)
        metrics = collect_metrics(client)
        config_data = read_config(client)
        config_hash = hashlib.sha256(config_data).hexdigest()
        metrics.update(xml_inventory(config_data))
        metrics["config_size_bytes"] = len(config_data)
        metrics["config_hash"] = config_hash
        changed = bool(firewall["last_config_hash"] and firewall["last_config_hash"] != config_hash)
        should_backup = force_backup or changed or backup_is_due(firewall)
        backup_at = firewall["last_backup_at"]
        if should_backup:
            path, encrypted_size = save_encrypted_backup(firewall, config_data, config_hash, changed)
            created_backup_path = path
            remote = upload_backup_from_db(db, firewall, path)
            backup_at = checked_at
            db.execute(
                """
                INSERT INTO pfsense_backups
                    (firewall_id, created_at, config_hash, file_path, size_bytes, changed, status,
                     remote_status, remote_path, remote_uploaded_at, remote_error)
                VALUES (?, ?, ?, ?, ?, ?, 'success', ?, ?, ?, ?)
                """,
                (
                    firewall["id"], checked_at, config_hash, str(path), encrypted_size,
                    1 if changed else 0, remote.get("status"), remote.get("remote_path"),
                    remote.get("uploaded_at"), remote.get("error"),
                ),
            )
        latency_ms = int((time.monotonic() - started) * 1000)
        db.execute(
            """
            INSERT INTO pfsense_checks
                (firewall_id, checked_at, status, latency_ms, hostname, version,
                 load1, load5, load15, cpu_count, memory_total, disk_percent,
                 interfaces_total, interfaces_up, gateway_monitors, openvpn_processes,
                 wireguard_interfaces, metrics_json)
            VALUES (?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                firewall["id"], checked_at, latency_ms, metrics.get("HOSTNAME"),
                metrics.get("VERSION"), metrics.get("LOAD1"), metrics.get("LOAD5"),
                metrics.get("LOAD15"), metrics.get("CPU_COUNT"), metrics.get("MEMORY_BYTES"),
                metrics.get("DISK_PERCENT"), metrics.get("INTERFACES_TOTAL"),
                metrics.get("INTERFACES_UP"), metrics.get("GATEWAY_MONITORS"),
                metrics.get("OPENVPN_PROCESSES"), metrics.get("WIREGUARD_INTERFACES"),
                json.dumps(metrics, ensure_ascii=False),
            ),
        )
        db.execute(
            """
            UPDATE pfsense_firewalls
            SET last_check_at=?, last_status='online', last_error=NULL,
                last_backup_at=?, last_config_hash=?, updated_at=?
            WHERE id=?
            """,
            (checked_at, backup_at, config_hash, checked_at, firewall["id"]),
        )
        prune_backups(db, firewall)
        db.commit()
        created_backup_path = None
        return {"status": "online", "metrics": metrics, "backup_created": should_backup}
    except Exception as exc:
        db.rollback()
        if created_backup_path:
            try:
                created_backup_path.unlink(missing_ok=True)
            except OSError:
                pass
        latency_ms = int((time.monotonic() - started) * 1000)
        error = str(exc)[:500]
        db.execute(
            """
            INSERT INTO pfsense_checks (firewall_id, checked_at, status, latency_ms, error)
            VALUES (?, ?, 'error', ?, ?)
            """,
            (firewall["id"], checked_at, latency_ms, error),
        )
        db.execute(
            """
            UPDATE pfsense_firewalls
            SET last_check_at=?, last_status='error', last_error=?, updated_at=?
            WHERE id=?
            """,
            (checked_at, error, checked_at, firewall["id"]),
        )
        db.commit()
        return {"status": "error", "error": error}
    finally:
        if client:
            client.close()
        db.close()


def run_due_firewalls():
    db = get_db()
    try:
        firewalls = [dict(row) for row in db.execute(
            "SELECT * FROM pfsense_firewalls WHERE active=1 ORDER BY id"
        ).fetchall()]
    finally:
        db.close()
    results = []
    for firewall in firewalls:
        if check_is_due(firewall):
            result = run_firewall_check(firewall)
            results.append((firewall["id"], "check", result["status"]))
        if speedtest_is_due(firewall):
            result = run_firewall_speedtest(firewall)
            results.append((firewall["id"], "speedtest", result["status"]))
    if results:
        print(f"pfSense agent: {results}", flush=True)
    return results


def run_requested_firewall_speedtests():
    db = get_db()
    try:
        firewalls = [dict(row) for row in db.execute(
            "SELECT * FROM pfsense_firewalls WHERE active=1 AND speedtest_requested_at IS NOT NULL ORDER BY id"
        ).fetchall()]
    finally:
        db.close()
    return [(firewall["id"], run_firewall_speedtest(firewall)["status"]) for firewall in firewalls]
