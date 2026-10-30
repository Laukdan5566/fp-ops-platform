"""Telas e acoes de firewall pfSense: lista, detalhe, links de internet, armazenamento FTP e backups."""
import io
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from flask import Blueprint, Response, redirect, render_template, request, send_file

from auth import admin_required, login_required
from db import get_db
from pfsense_storage import (
    cleanup_storage,
    normalize_remote_dir,
    test_storage_connection,
    upload_backup_from_db,
)
from secret_store import decrypt_backup, encrypt_secret
from util import agora_sql, enriquecer_uptime_pfsense
from relatorio_dados import BRT, coletar_dados
from relatorio_pagina import contexto_pagina
from relatorio_tecnico import montar_relatorio


bp = Blueprint("pfsense_web", __name__)

# =========================
# PFSENSE AGENT
# =========================

def pfsense_form_values(form, require_username=True):
    name = (form.get("name") or "").strip()
    address = (form.get("address") or "").strip()
    username = (form.get("username") or "").strip()
    auth_type = (form.get("auth_type") or "password").strip()
    fingerprint = (form.get("host_key_fingerprint") or "").strip()
    if not name or not address or (require_username and not username):
        raise ValueError("Nome, endereco e usuario sao obrigatorios.")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", address):
        raise ValueError("Endereco invalido.")
    if auth_type not in ("ssh_key", "password"):
        raise ValueError("Metodo de autenticacao invalido.")
    if fingerprint and not fingerprint.startswith("SHA256:"):
        raise ValueError("Informe o fingerprint SHA256 da chave SSH do pfSense.")
    port = int(form.get("ssh_port") or 22)
    if not 1 <= port <= 65535:
        raise ValueError("Porta SSH invalida.")
    return {
        "name": name,
        "address": address,
        "ssh_port": port,
        "username": username,
        "auth_type": auth_type,
        "host_key_fingerprint": fingerprint,
        "monitor_interval_minutes": max(1, min(1440, int(form.get("monitor_interval_minutes") or 5))),
        "backup_interval_hours": max(1, min(720, int(form.get("backup_interval_hours") or 24))),
        "backup_retention_days": max(1, min(3650, int(form.get("backup_retention_days") or 30))),
        "speedtest_enabled": 1 if form.get("speedtest_enabled") else 0,
        "speedtest_interval_hours": max(1, min(168, int(form.get("speedtest_interval_hours") or 6))),
        "active": 1 if form.get("active") else 0,
    }


def pfsense_link_form_values(form):
    name = (form.get("name") or "").strip()
    provider = (form.get("provider") or "").strip()
    link_type = (form.get("link_type") or "broadband").strip()
    interface_key = (form.get("interface_key") or "").strip()
    device_name = (form.get("device_name") or "").strip()
    gateway_name = (form.get("gateway_name") or "").strip()
    if not name or not provider or not interface_key or not device_name:
        raise ValueError("Nome, operadora, interface e dispositivo sao obrigatorios.")
    if link_type not in ("dedicated", "broadband"):
        raise ValueError("Tipo de link invalido.")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface_key) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", device_name):
        raise ValueError("Interface WAN invalida.")
    down = float(form.get("contracted_down_mbps") or 0)
    up = float(form.get("contracted_up_mbps") or 0)
    if down <= 0 or up <= 0 or down > 100000 or up > 100000:
        raise ValueError("Informe download e upload contratados em Mbps.")
    return {
        "name": name, "provider": provider, "link_type": link_type,
        "interface_key": interface_key, "device_name": device_name,
        "gateway_name": gateway_name, "contracted_down_mbps": down,
        "contracted_up_mbps": up,
        "minimum_delivery_percent": max(1, min(100, int(form.get("minimum_delivery_percent") or 80))),
        "active": 1 if form.get("active") else 0,
        "probe_enabled": 1 if form.get("probe_enabled") else 0,
        "probe_interval_minutes": max(1, min(1440, int(form.get("probe_interval_minutes") or 5))),
        "speedtest_enabled": 1 if form.get("speedtest_enabled") else 0,
        "speedtest_interval_hours": max(1, min(168, int(form.get("speedtest_interval_hours") or 6))),
    }


def montar_relatorio_links(db, firewall_id, days):
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    links = []
    for row in db.execute(
        "SELECT * FROM pfsense_links WHERE firewall_id=? AND active=1 ORDER BY name",
        (firewall_id,),
    ).fetchall():
        link = dict(row)
        probes = db.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='online' THEN 1 ELSE 0 END) AS online,
                   AVG(CASE WHEN status='online' THEN latency_ms END) AS latency_avg,
                   AVG(CASE WHEN status='online' THEN packet_loss_percent END) AS loss_avg
            FROM pfsense_link_probes WHERE link_id=? AND datetime(probed_at)>=datetime(?)
            """,
            (link["id"], since),
        ).fetchone()
        speeds = db.execute(
            """
            SELECT COUNT(*) AS total,
                   AVG(download_mbps) AS download_avg, MIN(download_mbps) AS download_min,
                   MAX(download_mbps) AS download_max, AVG(upload_mbps) AS upload_avg,
                   MIN(upload_mbps) AS upload_min, MAX(upload_mbps) AS upload_max,
                   AVG(ping_ms) AS ping_avg, AVG(delivered_down_percent) AS delivery_down_avg,
                   AVG(delivered_up_percent) AS delivery_up_avg
            FROM pfsense_link_speedtests
            WHERE link_id=? AND status='success' AND datetime(tested_at)>=datetime(?)
            """,
            (link["id"], since),
        ).fetchone()
        probe_total = int(probes["total"] or 0)
        probe_online = int(probes["online"] or 0)
        availability = round(probe_online * 100.0 / probe_total, 2) if probe_total else None
        delivery_values = [
            float(value) for value in (speeds["delivery_down_avg"], speeds["delivery_up_avg"])
            if value is not None
        ]
        delivery = min(delivery_values) if delivery_values else None
        latency = float(probes["latency_avg"]) if probes["latency_avg"] is not None else None
        components = []
        weights = []
        if availability is not None:
            components.append(min(100, availability) * 0.5); weights.append(0.5)
        if delivery is not None:
            components.append(min(100, delivery) * 0.35); weights.append(0.35)
        if latency is not None:
            components.append(max(0, 100 - latency) * 0.15); weights.append(0.15)
        score = round(sum(components) / sum(weights), 1) if weights else None
        diagnostics = []
        if not link["contracted_down_mbps"] or not link["contracted_up_mbps"]:
            diagnostics.append("Preencha a velocidade contratada para calcular a entrega do provedor.")
        if availability is None:
            diagnostics.append("Ainda nao ha sondas suficientes para medir disponibilidade.")
        elif availability < 99:
            diagnostics.append(f"Disponibilidade de {availability:.2f}% no periodo, abaixo de 99%.")
        if delivery is not None and delivery < float(link["minimum_delivery_percent"] or 80):
            diagnostics.append(
                f"Entrega media minima de {delivery:.1f}% do contratado, abaixo do limite de {link['minimum_delivery_percent']}%."
            )
        if speeds["ping_avg"] is not None and float(speeds["ping_avg"]) > 80:
            diagnostics.append(f"Ping medio elevado nos speedtests: {float(speeds['ping_avg']):.1f} ms.")
        if probes["loss_avg"] is not None and float(probes["loss_avg"]) > 5:
            diagnostics.append(
                f"Perda/bloqueio medio de ICMP em {float(probes['loss_avg']):.1f}%; a disponibilidade HTTPS e avaliada separadamente."
            )
        if not diagnostics:
            diagnostics.append("Link dentro dos parametros cadastrados no periodo analisado.")
        link.update({
            "probe_total": probe_total, "probe_online": probe_online,
            "availability": availability,
            "latency_avg": round(latency, 2) if latency is not None else None,
            "loss_avg": round(float(probes["loss_avg"]), 2) if probes["loss_avg"] is not None else None,
            "speed_total": int(speeds["total"] or 0),
            "download_avg": round(float(speeds["download_avg"]), 2) if speeds["download_avg"] is not None else None,
            "download_min": round(float(speeds["download_min"]), 2) if speeds["download_min"] is not None else None,
            "download_max": round(float(speeds["download_max"]), 2) if speeds["download_max"] is not None else None,
            "upload_avg": round(float(speeds["upload_avg"]), 2) if speeds["upload_avg"] is not None else None,
            "upload_min": round(float(speeds["upload_min"]), 2) if speeds["upload_min"] is not None else None,
            "upload_max": round(float(speeds["upload_max"]), 2) if speeds["upload_max"] is not None else None,
            "ping_avg": round(float(speeds["ping_avg"]), 2) if speeds["ping_avg"] is not None else None,
            "delivery_down_avg": round(float(speeds["delivery_down_avg"]), 2) if speeds["delivery_down_avg"] is not None else None,
            "delivery_up_avg": round(float(speeds["delivery_up_avg"]), 2) if speeds["delivery_up_avg"] is not None else None,
            "score": score, "diagnostics": diagnostics,
        })
        links.append(link)
    links.sort(key=lambda item: (-1 if item["score"] is None else -item["score"], item["name"]))
    best = next((link for link in links if link["score"] is not None), None)
    return links, best


@bp.route("/pfsense")
@login_required
def pfsense_list():
    db = get_db()
    rows = db.execute("""
        WITH latest_checks AS (
            SELECT pc.*, ROW_NUMBER() OVER (PARTITION BY firewall_id ORDER BY id DESC) AS rn
            FROM pfsense_checks pc
        ), backup_counts AS (
            SELECT firewall_id, COUNT(*) AS total
            FROM pfsense_backups WHERE status='success' GROUP BY firewall_id
        )
        SELECT f.*, lc.latency_ms, lc.version, lc.hostname, lc.disk_percent,
               lc.interfaces_total, lc.interfaces_up, COALESCE(bc.total,0) AS backup_count
        FROM pfsense_firewalls f
        LEFT JOIN latest_checks lc ON lc.firewall_id=f.id AND lc.rn=1
        LEFT JOIN backup_counts bc ON bc.firewall_id=f.id
        ORDER BY f.active DESC, f.name
    """).fetchall()
    firewalls = [dict(row) for row in rows]
    summary = {
        "total": sum(1 for item in firewalls if item["active"]),
        "online": sum(1 for item in firewalls if item["active"] and item["last_status"] == "online"),
        "error": sum(1 for item in firewalls if item["active"] and item["last_status"] == "error"),
        "waiting": sum(1 for item in firewalls if item["active"] and not item["last_status"]),
        "backups": sum(int(item["backup_count"] or 0) for item in firewalls),
    }
    links_summary = db.execute("""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN last_probe_status='online' THEN 1 ELSE 0 END) AS online,
               SUM(CASE WHEN last_probe_status IN ('offline','error') THEN 1 ELSE 0 END) AS error,
               SUM(CASE WHEN contracted_down_mbps IS NULL OR contracted_up_mbps IS NULL THEN 1 ELSE 0 END) AS incomplete
        FROM pfsense_links WHERE active=1
    """).fetchone()
    storage_row = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
    storage = dict(storage_row) if storage_row else None
    if storage:
        storage.pop("username_enc", None)
        storage.pop("password_enc", None)
    db.close()
    return render_template(
        "pfsense_list.html", firewalls=firewalls, storage=storage, summary=summary,
        links_summary=links_summary, message=request.args.get("message"), title="pfSense e Internet",
    )


@bp.route("/pfsense/storage", methods=["GET", "POST"])
@login_required
@admin_required
def pfsense_storage_settings():
    db = get_db()
    try:
        current_row = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
        current = dict(current_row) if current_row else None
        if request.method == "POST":
            protocol = (request.form.get("protocol") or "ftps").lower()
            if protocol not in ("ftps", "ftp"):
                raise ValueError("Protocolo invalido.")
            host = (request.form.get("host") or "").strip()
            if not host or len(host) > 255 or any(char.isspace() for char in host):
                raise ValueError("Informe um endereco FTP valido.")
            port = int(request.form.get("port") or 21)
            if port < 1 or port > 65535:
                raise ValueError("Porta FTP invalida.")
            username = request.form.get("username") or ""
            password = request.form.get("password") or ""
            username_enc = current["username_enc"] if current and not username else encrypt_secret(username)
            password_enc = current["password_enc"] if current and not password else encrypt_secret(password)
            if not username_enc or not password_enc:
                raise ValueError("Usuario e senha FTP sao obrigatorios.")
            remote_dir = normalize_remote_dir(request.form.get("remote_dir"))
            retention_days = int(request.form.get("retention_days") or 90)
            if retention_days < 1 or retention_days > 3650:
                raise ValueError("A retencao FTP deve ficar entre 1 e 3650 dias.")
            now = agora_sql()
            db.execute(
                """
                INSERT INTO pfsense_storage
                    (id, protocol, host, port, username_enc, password_enc, remote_dir,
                     passive, verify_tls, active, retention_enabled, retention_days,
                     created_at, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    protocol=excluded.protocol, host=excluded.host, port=excluded.port,
                    username_enc=excluded.username_enc, password_enc=excluded.password_enc,
                    remote_dir=excluded.remote_dir, passive=excluded.passive,
                    verify_tls=excluded.verify_tls, active=excluded.active,
                    retention_enabled=excluded.retention_enabled,
                    retention_days=excluded.retention_days,
                    last_status=NULL, last_error=NULL, updated_at=excluded.updated_at
                """,
                (
                    protocol, host, port, username_enc, password_enc, remote_dir,
                    1 if request.form.get("passive") else 0,
                    1 if request.form.get("verify_tls") else 0,
                    1 if request.form.get("active") else 0,
                    1 if request.form.get("retention_enabled") else 0,
                    retention_days, now, now,
                ),
            )
            db.commit()
            return redirect("/pfsense/storage?message=Armazenamento+salvo.+Execute+o+teste+de+conexao.")
        if current:
            current["has_username"] = bool(current.pop("username_enc", None))
            current["has_password"] = bool(current.pop("password_enc", None))
        return render_template(
            "pfsense_storage.html", storage=current, error=None,
            message=request.args.get("message"),
        )
    except Exception as exc:
        db.rollback()
        submitted = {
            "protocol": request.form.get("protocol") or "ftps",
            "host": request.form.get("host") or "",
            "port": request.form.get("port") or 21,
            "remote_dir": request.form.get("remote_dir") or "/pfsense-backups",
            "passive": bool(request.form.get("passive")),
            "verify_tls": bool(request.form.get("verify_tls")),
            "active": bool(request.form.get("active")),
            "retention_enabled": bool(request.form.get("retention_enabled")),
            "retention_days": request.form.get("retention_days") or 90,
            "has_username": bool(current and current.get("username_enc")),
            "has_password": bool(current and current.get("password_enc")),
        }
        return render_template("pfsense_storage.html", storage=submitted, error=str(exc), message=None), 400
    finally:
        db.close()


@bp.route("/pfsense/storage/test", methods=["POST"])
@login_required
@admin_required
def pfsense_storage_test():
    db = get_db()
    try:
        storage = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
        if not storage:
            return redirect("/pfsense/storage?message=Salve+a+configuracao+antes+do+teste.")
        result = test_storage_connection(storage)
        now = agora_sql()
        db.execute(
            "UPDATE pfsense_storage SET last_test_at=?, last_status=?, last_error=?, updated_at=? WHERE id=1",
            (now, result["status"], result.get("error"), now),
        )
        db.commit()
        message = "Conexao+FTP+testada+com+sucesso." if result["status"] == "success" else "Falha+no+teste+FTP.+Consulte+o+erro."
        return redirect(f"/pfsense/storage?message={message}")
    finally:
        db.close()


@bp.route("/pfsense/storage/cleanup", methods=["POST"])
@login_required
@admin_required
def pfsense_storage_cleanup():
    db = get_db()
    try:
        result = cleanup_storage(db, force=True)
        db.commit()
        if result["status"] == "success":
            message = f"Limpeza+FTP+concluida.+{result.get('deleted', 0)}+arquivo(s)+removido(s)."
        elif result["status"] == "disabled":
            message = "Retencao+FTP+desativada."
        else:
            message = "Falha+na+limpeza+FTP.+Consulte+o+erro."
        return redirect(f"/pfsense/storage?message={message}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@bp.route("/pfsense/new")
@login_required
@admin_required
def pfsense_new():
    return render_template("pfsense_form.html", firewall=None, error=None)


@bp.route("/pfsense/add", methods=["POST"])
@login_required
@admin_required
def pfsense_add():
    try:
        values = pfsense_form_values(request.form)
        password = request.form.get("password") or ""
        private_key = request.form.get("private_key") or ""
        if values["auth_type"] == "ssh_key" and not private_key.strip():
            raise ValueError("A chave privada SSH e obrigatoria.")
        if values["auth_type"] == "password" and not password:
            raise ValueError("A senha SSH e obrigatoria.")
        if not values["host_key_fingerprint"]:
            from worker.pfsense_agent import discover_host_key_fingerprint
            values["host_key_fingerprint"] = discover_host_key_fingerprint(
                values["address"], values["ssh_port"]
            )
        db = get_db()
        db.execute(
            """
            INSERT INTO pfsense_firewalls
                (name, address, ssh_port, username_enc, password_enc, private_key_enc,
                 auth_type, host_key_fingerprint, active, monitor_interval_minutes,
                 backup_interval_hours, backup_retention_days, speedtest_enabled,
                 speedtest_interval_hours, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                values["name"], values["address"], values["ssh_port"],
                encrypt_secret(values["username"]), encrypt_secret(password),
                encrypt_secret(private_key), values["auth_type"],
                values["host_key_fingerprint"], values["active"],
                values["monitor_interval_minutes"], values["backup_interval_hours"],
                values["backup_retention_days"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], agora_sql(), agora_sql(),
            ),
        )
        db.commit()
        db.close()
        return redirect("/pfsense?message=Firewall+cadastrado.+Execute+Testar+agora.")
    except Exception as exc:
        return render_template("pfsense_form.html", firewall=None, error=str(exc)), 400


@bp.route("/pfsense/<int:firewall_id>")
@login_required
def pfsense_detail(firewall_id):
    db = get_db()
    firewall = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    if not firewall:
        db.close()
        return "Firewall nao encontrado", 404
    checks = db.execute(
        "SELECT * FROM pfsense_checks WHERE firewall_id=? ORDER BY id DESC LIMIT 100",
        (firewall_id,),
    ).fetchall()
    backups = db.execute(
        "SELECT * FROM pfsense_backups WHERE firewall_id=? ORDER BY id DESC LIMIT 100",
        (firewall_id,),
    ).fetchall()
    speedtests = db.execute(
        "SELECT * FROM pfsense_speedtests WHERE firewall_id=? ORDER BY id DESC LIMIT 100",
        (firewall_id,),
    ).fetchall()
    links = []
    for link_row in db.execute(
        "SELECT * FROM pfsense_links WHERE firewall_id=? ORDER BY name", (firewall_id,)
    ).fetchall():
        link = dict(link_row)
        link["latest_probe"] = db.execute(
            "SELECT * FROM pfsense_link_probes WHERE link_id=? ORDER BY id DESC LIMIT 1",
            (link["id"],),
        ).fetchone()
        link["latest_speedtest"] = db.execute(
            "SELECT * FROM pfsense_link_speedtests WHERE link_id=? ORDER BY id DESC LIMIT 1",
            (link["id"],),
        ).fetchone()
        links.append(link)
    latest_metrics = {}
    if checks and checks[0]["metrics_json"]:
        try:
            latest_metrics = json.loads(checks[0]["metrics_json"])
        except (TypeError, ValueError):
            pass
    latest_metrics = enriquecer_uptime_pfsense(
        latest_metrics, checks[0]["checked_at"] if checks else None
    )
    result = dict(firewall)
    result["has_password"] = bool(result.pop("password_enc", None))
    result["has_private_key"] = bool(result.pop("private_key_enc", None))
    result.pop("username_enc", None)
    db.close()
    return render_template(
        "pfsense_detail.html", firewall=result, checks=checks, backups=backups,
        speedtests=speedtests, latest_speedtest=speedtests[0] if speedtests else None,
        links=links,
        metrics=latest_metrics, message=request.args.get("message"),
    )


@bp.route("/pfsense/<int:firewall_id>/links/discover", methods=["POST"])
@login_required
@admin_required
def pfsense_links_discover(firewall_id):
    db = get_db()
    firewall = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not firewall:
        return "Firewall nao encontrado", 404
    from worker.pfsense_links import sync_discovered_links
    result = sync_discovered_links(dict(firewall))
    return redirect(
        f"/pfsense/{firewall_id}?message={result['found']}+interfaces+WAN+encontradas.+{result['created']}+adicionadas."
    )


@bp.route("/pfsense/<int:firewall_id>/links/new")
@login_required
@admin_required
def pfsense_link_new(firewall_id):
    db = get_db()
    firewall = db.execute("SELECT id, name FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not firewall:
        return "Firewall nao encontrado", 404
    return render_template("pfsense_link_form.html", firewall=firewall, link=None, error=None)


@bp.route("/pfsense/<int:firewall_id>/links/add", methods=["POST"])
@login_required
@admin_required
def pfsense_link_add(firewall_id):
    try:
        values = pfsense_link_form_values(request.form)
        now = agora_sql()
        db = get_db()
        db.execute(
            """
            INSERT INTO pfsense_links
                (firewall_id, name, provider, link_type, interface_key, device_name,
                 gateway_name, contracted_down_mbps, contracted_up_mbps,
                 minimum_delivery_percent, active, probe_enabled, probe_interval_minutes,
                 speedtest_enabled, speedtest_interval_hours, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                firewall_id, values["name"], values["provider"], values["link_type"],
                values["interface_key"], values["device_name"], values["gateway_name"],
                values["contracted_down_mbps"], values["contracted_up_mbps"],
                values["minimum_delivery_percent"], values["active"], values["probe_enabled"],
                values["probe_interval_minutes"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], now, now,
            ),
        )
        db.commit()
        db.close()
        return redirect(f"/pfsense/{firewall_id}?message=Link+de+Internet+cadastrado.")
    except Exception as exc:
        return render_template("pfsense_link_form.html", firewall={"id": firewall_id}, link=None, error=str(exc)), 400


@bp.route("/pfsense/<int:firewall_id>/links/<int:link_id>/edit")
@login_required
@admin_required
def pfsense_link_edit(firewall_id, link_id):
    db = get_db()
    firewall = db.execute("SELECT id, name FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    link = db.execute("SELECT * FROM pfsense_links WHERE id=? AND firewall_id=?", (link_id, firewall_id)).fetchone()
    db.close()
    if not firewall or not link:
        return "Link nao encontrado", 404
    return render_template("pfsense_link_form.html", firewall=firewall, link=link, error=None)


@bp.route("/pfsense/<int:firewall_id>/links/<int:link_id>/update", methods=["POST"])
@login_required
@admin_required
def pfsense_link_update(firewall_id, link_id):
    try:
        values = pfsense_link_form_values(request.form)
        db = get_db()
        db.execute(
            """
            UPDATE pfsense_links SET name=?, provider=?, link_type=?, interface_key=?,
                device_name=?, gateway_name=?, contracted_down_mbps=?, contracted_up_mbps=?,
                minimum_delivery_percent=?, active=?, probe_enabled=?, probe_interval_minutes=?,
                speedtest_enabled=?, speedtest_interval_hours=?, updated_at=?
            WHERE id=? AND firewall_id=?
            """,
            (
                values["name"], values["provider"], values["link_type"],
                values["interface_key"], values["device_name"], values["gateway_name"],
                values["contracted_down_mbps"], values["contracted_up_mbps"],
                values["minimum_delivery_percent"], values["active"], values["probe_enabled"],
                values["probe_interval_minutes"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], agora_sql(), link_id, firewall_id,
            ),
        )
        db.execute(
            """
            UPDATE pfsense_link_speedtests
            SET delivered_down_percent=CASE
                    WHEN ? IS NOT NULL AND ? > 0
                    THEN ROUND(CAST(download_mbps * 100.0 / ? AS NUMERIC), 2)
                    ELSE NULL
                END,
                delivered_up_percent=CASE
                    WHEN ? IS NOT NULL AND ? > 0
                    THEN ROUND(CAST(upload_mbps * 100.0 / ? AS NUMERIC), 2)
                    ELSE NULL
                END
            WHERE link_id=? AND status='success'
            """,
            (
                values["contracted_down_mbps"], values["contracted_down_mbps"],
                values["contracted_down_mbps"], values["contracted_up_mbps"],
                values["contracted_up_mbps"], values["contracted_up_mbps"], link_id,
            ),
        )
        db.commit()
        db.close()
        return redirect(f"/pfsense/{firewall_id}?message=Link+atualizado.")
    except Exception as exc:
        return render_template(
            "pfsense_link_form.html", firewall={"id": firewall_id},
            link={"id": link_id}, error=str(exc),
        ), 400


@bp.route("/pfsense/<int:firewall_id>/links/<int:link_id>/probe", methods=["POST"])
@login_required
@admin_required
def pfsense_link_probe_now(firewall_id, link_id):
    db = get_db()
    link = db.execute("SELECT * FROM pfsense_links WHERE id=? AND firewall_id=?", (link_id, firewall_id)).fetchone()
    if not link:
        db.close()
        return "Link nao encontrado", 404
    now = agora_sql()
    db.execute(
        "UPDATE pfsense_links SET probe_requested_at=?, last_probe_status='queued', updated_at=? WHERE id=?",
        (now, now, link_id),
    )
    db.commit()
    db.close()
    return redirect(f"/pfsense/{firewall_id}?message=Sonda+solicitada.+O+resultado+aparecera+em+instantes.")


@bp.route("/pfsense/<int:firewall_id>/links/<int:link_id>/speedtest", methods=["POST"])
@login_required
@admin_required
def pfsense_link_speedtest_now(firewall_id, link_id):
    db = get_db()
    link = db.execute("SELECT * FROM pfsense_links WHERE id=? AND firewall_id=?", (link_id, firewall_id)).fetchone()
    if not link:
        db.close()
        return "Link nao encontrado", 404
    now = agora_sql()
    db.execute(
        "UPDATE pfsense_links SET speedtest_requested_at=?, last_speedtest_status='queued', updated_at=? WHERE id=?",
        (now, now, link_id),
    )
    db.commit()
    db.close()
    return redirect(f"/pfsense/{firewall_id}?message=Speedtest+solicitado.+O+resultado+aparecera+em+instantes.")


@bp.route("/pfsense/<int:firewall_id>/internet-report")
@login_required
def pfsense_internet_report(firewall_id):
    try:
        days = int(request.args.get("days") or 30)
    except ValueError:
        days = 30
    if days not in (7, 30, 90):
        days = 30
    db = get_db()
    firewall = db.execute("SELECT id, name, address FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    if not firewall:
        db.close()
        return "Firewall nao encontrado", 404
    links, best = montar_relatorio_links(db, firewall_id, days)
    db.close()
    html = render_template(
        "pfsense_internet_report.html", firewall=firewall, links=links, best=best,
        days=days, generated_at=agora_sql(),
    )
    if request.args.get("download"):
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", firewall["name"]).strip("-") or "pfsense"
        return Response(
            html, mimetype="text/html",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}-internet-{days}d.html"'},
        )
    return html


def _periodo_do_relatorio(args):
    """?days=7|14|30 (ate agora) ou ?inicio=AAAA-MM-DD&fim=AAAA-MM-DD (dias inteiros, em Brasilia)."""
    agora = datetime.now(BRT).replace(tzinfo=None, second=0, microsecond=0)
    try:
        inicio = datetime.strptime(args.get("inicio", ""), "%Y-%m-%d")
        fim = datetime.strptime(args.get("fim", ""), "%Y-%m-%d").replace(hour=23, minute=59)
        if inicio < fim and (fim - inicio).days <= 92:
            return inicio, min(fim, agora), None
    except ValueError:
        pass
    try:
        dias = int(args.get("days") or 7)
    except ValueError:
        dias = 7
    dias = dias if dias in (7, 14, 30) else 7
    return agora - timedelta(days=dias), agora, dias


@bp.route("/pfsense/<int:firewall_id>/relatorio-tecnico")
@login_required
def pfsense_relatorio_tecnico(firewall_id):
    inicio, fim, dias = _periodo_do_relatorio(request.args)
    db = get_db()
    dados = coletar_dados(db, firewall_id, inicio, fim, emitido_em=datetime.now(BRT).replace(tzinfo=None))
    db.close()
    if dados is None:
        return "Firewall nao encontrado", 404
    html = render_template("pfsense_tech_report.html", **contexto_pagina(montar_relatorio(dados), dias or 0, f"/pfsense/{firewall_id}"))
    if request.args.get("download"):
        nome = re.sub(r"[^A-Za-z0-9_.-]+", "-", dados["cliente"]).strip("-") or "pfsense"
        return Response(html, mimetype="text/html", headers={
            "Content-Disposition": f'attachment; filename="{nome}-relatorio-internet-{inicio:%Y%m%d}-{fim:%Y%m%d}.html"'})
    return html


@bp.route("/pfsense/<int:firewall_id>/edit")
@login_required
@admin_required
def pfsense_edit(firewall_id):
    db = get_db()
    row = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not row:
        return "Firewall nao encontrado", 404
    firewall = dict(row)
    firewall["has_password"] = bool(firewall.pop("password_enc", None))
    firewall["has_private_key"] = bool(firewall.pop("private_key_enc", None))
    firewall.pop("username_enc", None)
    return render_template("pfsense_form.html", firewall=firewall, error=None)


@bp.route("/pfsense/<int:firewall_id>/update", methods=["POST"])
@login_required
@admin_required
def pfsense_update(firewall_id):
    try:
        values = pfsense_form_values(request.form)
        db = get_db()
        current = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
        if not current:
            db.close()
            return "Firewall nao encontrado", 404
        password_enc = current["password_enc"]
        private_key_enc = current["private_key_enc"]
        if request.form.get("password"):
            password_enc = encrypt_secret(request.form.get("password"))
        if request.form.get("private_key", "").strip():
            private_key_enc = encrypt_secret(request.form.get("private_key"))
        if values["auth_type"] == "ssh_key" and not private_key_enc:
            raise ValueError("A chave privada SSH e obrigatoria.")
        if values["auth_type"] == "password" and not password_enc:
            raise ValueError("A senha SSH e obrigatoria.")
        if not values["host_key_fingerprint"]:
            values["host_key_fingerprint"] = current["host_key_fingerprint"]
        if not values["host_key_fingerprint"]:
            from worker.pfsense_agent import discover_host_key_fingerprint
            values["host_key_fingerprint"] = discover_host_key_fingerprint(
                values["address"], values["ssh_port"]
            )
        db.execute(
            """
            UPDATE pfsense_firewalls
            SET name=?, address=?, ssh_port=?, username_enc=?, password_enc=?, private_key_enc=?,
                auth_type=?, host_key_fingerprint=?, active=?, monitor_interval_minutes=?,
                backup_interval_hours=?, backup_retention_days=?, speedtest_enabled=?,
                speedtest_interval_hours=?, updated_at=?
            WHERE id=?
            """,
            (
                values["name"], values["address"], values["ssh_port"],
                encrypt_secret(values["username"]) if values["username"] else current["username_enc"],
                password_enc, private_key_enc,
                values["auth_type"], values["host_key_fingerprint"], values["active"],
                values["monitor_interval_minutes"], values["backup_interval_hours"],
                values["backup_retention_days"], values["speedtest_enabled"],
                values["speedtest_interval_hours"], agora_sql(), firewall_id,
            ),
        )
        db.commit()
        db.close()
        return redirect(f"/pfsense/{firewall_id}?message=Cadastro+atualizado.")
    except Exception as exc:
        return render_template("pfsense_form.html", firewall={"id": firewall_id}, error=str(exc)), 400


@bp.route("/pfsense/<int:firewall_id>/check", methods=["POST"])
@login_required
@admin_required
def pfsense_check_now(firewall_id):
    db = get_db()
    row = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not row:
        return "Firewall nao encontrado", 404
    from worker.pfsense_agent import run_firewall_check
    result = run_firewall_check(dict(row), force_backup=bool(request.form.get("backup")))
    message = "Teste+concluido." if result["status"] == "online" else "Teste+falhou.+Consulte+o+erro."
    return redirect(f"/pfsense/{firewall_id}?message={message}")


@bp.route("/pfsense/<int:firewall_id>/speedtest", methods=["POST"])
@login_required
@admin_required
def pfsense_speedtest_now(firewall_id):
    db = get_db()
    row = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    if not row:
        db.close()
        return "Firewall nao encontrado", 404
    now = agora_sql()
    db.execute(
        "UPDATE pfsense_firewalls SET speedtest_requested_at=?, last_speedtest_status='queued', updated_at=? WHERE id=?",
        (now, now, firewall_id),
    )
    db.commit()
    db.close()
    return redirect(f"/pfsense/{firewall_id}?message=Teste+de+velocidade+solicitado.+O+resultado+aparecera+em+instantes.")


@bp.route("/pfsense/<int:firewall_id>/toggle", methods=["POST"])
@login_required
@admin_required
def pfsense_toggle(firewall_id):
    db = get_db()
    db.execute(
        "UPDATE pfsense_firewalls SET active=CASE WHEN active=1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?",
        (agora_sql(), firewall_id),
    )
    db.commit()
    db.close()
    return redirect("/pfsense")


@bp.route("/pfsense/<int:firewall_id>/backups/<int:backup_id>/upload", methods=["POST"])
@login_required
@admin_required
def pfsense_backup_upload(firewall_id, backup_id):
    db = get_db()
    try:
        backup = db.execute(
            "SELECT * FROM pfsense_backups WHERE id=? AND firewall_id=? AND status='success'",
            (backup_id, firewall_id),
        ).fetchone()
        firewall = db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
        if not backup or not firewall:
            return "Backup nao encontrado", 404
        path = Path(backup["file_path"] or "")
        backup_root = Path(os.getenv("PFSENSE_BACKUP_DIR", "/data/pfsense-backups"))
        if not path.is_file() or backup_root not in path.parents:
            return "Arquivo de backup indisponivel", 404
        result = upload_backup_from_db(db, firewall, path)
        error = result.get("error")
        if result["status"] == "disabled":
            error = "Armazenamento FTP desativado ou nao configurado."
        db.execute(
            """
            UPDATE pfsense_backups
            SET remote_status=?, remote_path=?, remote_uploaded_at=?, remote_error=?
            WHERE id=? AND firewall_id=?
            """,
            (
                result["status"], result.get("remote_path"), result.get("uploaded_at"),
                error, backup_id, firewall_id,
            ),
        )
        db.commit()
        message = "Backup+enviado+ao+FTP." if result["status"] == "success" else "Falha+no+envio+FTP.+Consulte+o+status."
        return redirect(f"/pfsense/{firewall_id}?message={message}")
    finally:
        db.close()


@bp.route("/pfsense/<int:firewall_id>/backups/<int:backup_id>/download")
@login_required
@admin_required
def pfsense_backup_download(firewall_id, backup_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM pfsense_backups WHERE id=? AND firewall_id=? AND status='success'",
        (backup_id, firewall_id),
    ).fetchone()
    firewall = db.execute("SELECT name FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone()
    db.close()
    if not row or not firewall:
        return "Backup nao encontrado", 404
    path = Path(row["file_path"] or "")
    backup_root = Path(os.getenv("PFSENSE_BACKUP_DIR", "/data/pfsense-backups"))
    if not path.is_file() or backup_root not in path.parents:
        return "Arquivo de backup indisponivel", 404
    plaintext = decrypt_backup(path.read_bytes())
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", firewall["name"]).strip("-") or "pfsense"
    timestamp = re.sub(r"[^0-9]", "", row["created_at"] or "")[:14]
    return send_file(
        io.BytesIO(plaintext), mimetype="application/xml", as_attachment=True,
        download_name=f"{safe_name}-{timestamp}.config.xml",
    )
