import hashlib
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from db import get_db


BRASILIA = ZoneInfo("America/Sao_Paulo")
PROBLEM_STATES = {
    "server_offline", "backup_error", "backup_warning", "backup_overdue", "pfsense_offline"
}
PREFERENCE_BY_TYPE = {
    "server": "notify_servers",
    "backup": "notify_backups",
    "pfsense": "notify_pfsense",
}


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def sql_time(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (TypeError, ValueError):
        return None


def br_time(value):
    value = value.replace(tzinfo=timezone.utc).astimezone(BRASILIA)
    return value.strftime("%d/%m/%Y às %H:%M")


def duration_label(started, finished):
    if not started:
        return None
    minutes = max(0, int((finished - started).total_seconds() // 60))
    if minutes < 60:
        return f"{minutes} min"
    hours, rest = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {rest}min"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def translated_detail(detail):
    text = re.sub(r"\s+", " ", str(detail or "")).strip()[:260]
    replacements = (
        (r"authentication failed|auth fail", "falha de autenticação SSH"),
        (r"connection refused", "conexão recusada pelo equipamento"),
        (r"no route to host", "sem rota de rede até o equipamento"),
        (r"timed? out|timeout", "tempo limite de comunicação excedido"),
        (r"name or service not known", "endereço do equipamento não localizado"),
    )
    for pattern, replacement in replacements:
        if re.search(pattern, text, re.I):
            return replacement
    return text or "A sonda não apresentou detalhes adicionais."


def state_label(state):
    return {
        "healthy": "Operacional",
        "server_offline": "Servidor indisponível",
        "backup_error": "Backup concluído com erro",
        "backup_warning": "Backup concluído com alerta",
        "backup_overdue": "Backup atrasado ou não recebido",
        "pfsense_offline": "Firewall pfSense indisponível",
    }.get(state, state)


def incident_message(resource, detected_at):
    actions = {
        "server": "Verificar energia, conectividade e o serviço do agente FP Ops no servidor.",
        "backup": "Analisar o último log, o destino do backup, espaço disponível e a rotina agendada.",
        "pfsense": "Validar o link de Internet, energia e acesso SSH ao firewall antes de intervir.",
    }
    impacts = {
        "server": "O monitor deixou de receber sinais do servidor e não consegue confirmar sua disponibilidade.",
        "backup": "A proteção dos dados pode estar fora da janela esperada até a rotina ser validada.",
        "pfsense": "O FP Ops não consegue confirmar a disponibilidade ou coletar dados do firewall.",
    }
    client = f"Cliente: {resource['client']}\n" if resource.get("client") else ""
    return (
        f"*FP Ops | INCIDENTE — {state_label(resource['state'])}*\n\n"
        f"{client}Equipamento: {resource['name']}\n"
        f"Detectado em: {br_time(detected_at)} (Brasília)\n"
        f"Detalhes: {translated_detail(resource.get('detail'))}\n\n"
        f"Impacto: {impacts[resource['type']]}\n"
        f"Ação recomendada: {actions[resource['type']]}\n\n"
        "Uma nova mensagem será enviada quando o serviço for normalizado."
    )


def recovery_message(resource, resolved_at, opened_at):
    client = f"Cliente: {resource['client']}\n" if resource.get("client") else ""
    duration = duration_label(opened_at, resolved_at)
    duration_line = f"Duração aproximada: {duration}\n" if duration else ""
    return (
        f"*FP Ops | NORMALIZADO — {resource['title']}*\n\n"
        f"{client}Equipamento: {resource['name']}\n"
        f"Normalizado em: {br_time(resolved_at)} (Brasília)\n"
        f"{duration_line}Situação atual: Operacional\n\n"
        "O monitoramento voltou a receber evidências válidas. O incidente foi encerrado automaticamente."
    )


def latest_backup_state(db, server, now):
    last_log = db.execute("""
        SELECT data_email, status FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        ORDER BY datetime(data_email) DESC, id DESC LIMIT 1
    """, (server["name"],)).fetchone()
    schedules = db.execute("""
        SELECT dias_execucao, hora_execucao, tolerancia_min FROM agendamentos_backup
        WHERE servidor_id=? AND ativo=1
    """, (server["id"],)).fetchall()
    last_at = parse_time(last_log["data_email"]) if last_log else None
    expected = None
    tolerance = 120
    for schedule in schedules:
        try:
            hour, minute = [int(part) for part in schedule["hora_execucao"].split(":")[:2]]
        except (AttributeError, TypeError, ValueError):
            continue
        weekdays = {int(day.strip()) for day in (schedule["dias_execucao"] or "").split(",") if day.strip().isdigit()}
        for offset in range(15):
            day = now.date() - timedelta(days=offset)
            candidate = datetime.combine(day, datetime.min.time()).replace(hour=hour, minute=minute)
            if day.weekday() in weekdays and candidate <= now:
                if expected is None or candidate > expected:
                    expected = candidate
                    tolerance = int(schedule["tolerancia_min"] or 120)
                break
    if expected:
        if last_at and last_at >= expected:
            if last_log["status"] == "error":
                return "backup_error", "A execução prevista retornou erro."
            if last_log["status"] == "warning":
                return "backup_warning", "A execução prevista retornou um alerta."
            return "healthy", "Último backup previsto recebido com sucesso."
        if now > expected + timedelta(minutes=tolerance):
            return "backup_overdue", f"O backup esperado para {br_time(expected)} não foi recebido dentro da tolerância."
        return None, None
    if not last_log:
        return None, None
    if last_log["status"] == "error":
        return "backup_error", "O último log de backup recebido contém erro."
    if last_log["status"] == "warning":
        return "backup_warning", "O último log de backup recebido contém alerta."
    if last_at and now - last_at > timedelta(hours=48):
        return "backup_overdue", "Nenhum novo log de backup foi recebido nas últimas 48 horas."
    return "healthy", "Último backup recebido com sucesso."


def collect_resources(db, now):
    resources = []
    servers = db.execute("""
        SELECT s.id, s.nome_log AS name, c.nome_exibicao AS client,
               h.last_seen, h.status AS agent_status, h.detalhe
        FROM servidores s JOIN clientes c ON c.id=s.cliente_id
        LEFT JOIN agent_heartbeats h ON UPPER(h.servidor_log)=UPPER(s.nome_log)
        WHERE s.ativo=1 AND c.ativo=1 ORDER BY s.id
    """).fetchall()
    for server in servers:
        if server["last_seen"]:
            last_seen = parse_time(server["last_seen"])
            offline = not last_seen or now - last_seen > timedelta(minutes=10)
            resources.append({
                "type": "server", "id": server["id"], "name": server["name"],
                "client": server["client"], "state": "server_offline" if offline else "healthy",
                "title": "Servidor disponível novamente",
                "detail": (f"Último sinal recebido em {br_time(last_seen)}." if offline and last_seen else server["detalhe"]),
            })
        backup_state, detail = latest_backup_state(db, server, now)
        if backup_state:
            resources.append({
                "type": "backup", "id": server["id"], "name": server["name"],
                "client": server["client"], "state": backup_state,
                "title": "Backup normalizado", "detail": detail,
            })
    firewalls = db.execute("""
        SELECT id, name, last_status, last_error FROM pfsense_firewalls
        WHERE active=1 AND last_status IS NOT NULL ORDER BY id
    """).fetchall()
    for firewall in firewalls:
        resources.append({
            "type": "pfsense", "id": firewall["id"], "name": firewall["name"],
            "client": None, "state": "healthy" if firewall["last_status"] == "online" else "pfsense_offline",
            "title": "Firewall pfSense disponível novamente", "detail": firewall["last_error"],
        })
    return resources


def queue_for_technicians(db, resource, body, event_type, changed_at):
    preference = PREFERENCE_BY_TYPE[resource["type"]]
    recipients = db.execute(f"""
        SELECT n.id, n.telefone FROM helpdesk_staff_notifications n
        JOIN usuarios u ON u.id=n.user_id
        WHERE n.ativo=1 AND u.ativo=1 AND u.is_technician=1 AND n.{preference}=1
        ORDER BY n.id
    """).fetchall()
    queued = 0
    now_text = sql_time(changed_at)
    for recipient in recipients:
        key = hashlib.sha256(
            f"infra|{resource['type']}|{resource['id']}|{event_type}|{now_text}|{recipient['id']}".encode()
        ).hexdigest()
        result = db.execute("""
            INSERT OR IGNORE INTO notification_outbox (
                staff_recipient_id, recipient, event_type, body, status, available_at,
                idempotency_key, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
        """, (recipient["id"], recipient["telefone"], event_type, body, now_text, key, now_text, now_text))
        queued += 1 if result.rowcount else 0
    return queued


def process_infrastructure_notifications(now=None):
    now = now or utc_now()
    if now.tzinfo:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)
    db = get_db()
    result = {"queued": 0, "incidents": 0, "recoveries": 0, "resources": 0}
    try:
        ticketz = db.execute("SELECT ativo, token_enc FROM ticketz_config WHERE id=1").fetchone()
        enabled = bool(ticketz and int(ticketz["ativo"] or 0) and ticketz["token_enc"])
        for resource in collect_resources(db, now):
            result["resources"] += 1
            state = db.execute("""
                SELECT * FROM infrastructure_notification_state
                WHERE resource_type=? AND resource_id=?
            """, (resource["type"], resource["id"])).fetchone()
            now_text = sql_time(now)
            is_problem = resource["state"] in PROBLEM_STATES
            if not state:
                db.execute("""
                    INSERT OR IGNORE INTO infrastructure_notification_state (
                        resource_type, resource_id, current_state, pending_count,
                        incident_opened_at, last_change_at, last_detail, created_at, updated_at
                    ) VALUES (?, ?, ?, 0, NULL, ?, ?, ?, ?)
                """, (resource["type"], resource["id"], resource["state"], now_text, resource["detail"], now_text, now_text))
                continue
            old_problem = state["current_state"] in PROBLEM_STATES
            if resource["state"] == state["current_state"]:
                db.execute("""
                    UPDATE infrastructure_notification_state
                    SET pending_state=NULL, pending_count=0, last_detail=?, updated_at=? WHERE id=?
                """, (resource["detail"], now_text, state["id"]))
                continue
            if old_problem and is_problem:
                db.execute("""
                    UPDATE infrastructure_notification_state
                    SET current_state=?, pending_state=NULL, pending_count=0,
                        last_detail=?, updated_at=? WHERE id=?
                """, (resource["state"], resource["detail"], now_text, state["id"]))
                continue
            if old_problem and not is_problem:
                opened_at = parse_time(state["incident_opened_at"])
                if opened_at and enabled:
                    result["queued"] += queue_for_technicians(
                        db, resource, recovery_message(resource, now, opened_at),
                        "internal_infrastructure_recovered", now,
                    )
                    result["recoveries"] += 1
                db.execute("""
                    UPDATE infrastructure_notification_state SET current_state='healthy',
                        pending_state=NULL, pending_count=0, incident_opened_at=NULL,
                        last_change_at=?, last_detail=?, updated_at=? WHERE id=?
                """, (now_text, resource["detail"], now_text, state["id"]))
                continue
            confirmations = 1 if resource["state"] in ("backup_error", "backup_warning") else 2
            pending_count = int(state["pending_count"] or 0) + 1 if state["pending_state"] == resource["state"] else 1
            if pending_count < confirmations:
                db.execute("""
                    UPDATE infrastructure_notification_state SET pending_state=?, pending_count=?,
                        last_detail=?, updated_at=? WHERE id=?
                """, (resource["state"], pending_count, resource["detail"], now_text, state["id"]))
                continue
            queued_now = 0
            if enabled:
                queued_now = queue_for_technicians(
                    db, resource, incident_message(resource, now),
                    "internal_infrastructure_incident", now,
                )
                result["queued"] += queued_now
                result["incidents"] += 1 if queued_now else 0
            opened_at = now_text if queued_now else None
            db.execute("""
                UPDATE infrastructure_notification_state SET current_state=?, pending_state=NULL,
                    pending_count=0, incident_opened_at=?, last_change_at=?, last_detail=?, updated_at=?
                WHERE id=?
            """, (resource["state"], opened_at, now_text, resource["detail"], now_text, state["id"]))
        db.commit()
        return result
    finally:
        db.close()
