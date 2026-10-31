"""Painel de monitoramento: dashboard, backups, disponibilidade e tempo online, historico, status do sistema e eventos do Windows."""
import json
import re
from datetime import datetime, timedelta

from flask import Blueprint, Response, redirect, render_template, request

from agentes import LATEST_AGENT_VERSION, comparar_versao_agent
from auth import login_required, support_required
from db import get_db
from util import enriquecer_uptime_pfsense, formatar_idade, parse_data


bp = Blueprint("monitoramento", __name__)


def ultimo_horario_previsto(agendamento, agora):
    hora_txt = (agendamento["hora_execucao"] or "").strip()
    try:
        hora = datetime.strptime(hora_txt, "%H:%M").time()
    except ValueError:
        return None

    dias = [d.strip() for d in (agendamento["dias_execucao"] or "").split(",") if d.strip()]
    if not dias:
        return None

    for offset in range(0, 15):
        dia = agora.date() - timedelta(days=offset)
        if str(dia.weekday()) in dias:
            previsto = datetime.combine(dia, hora)
            if previsto <= agora:
                return previsto

    return None


def montar_linha_backup_servidor(servidor, agora, ultimo_log=None, heartbeat=None, agendamentos=None):
    agendamentos = agendamentos or []
    agente = formatar_status_agente(heartbeat, agora)

    ultimo_dt = parse_data(ultimo_log["data_email"]) if ultimo_log else None
    idade_min = None
    if ultimo_dt:
        idade_min = max(0, int((agora - ultimo_dt).total_seconds() // 60))

    status = "sem_agenda"
    detalhe = "Sem agendamento ativo"
    previsto = None
    prazo = None

    if agendamentos:
        candidatos = []
        for agendamento in agendamentos:
            previsto_ag = ultimo_horario_previsto(agendamento, agora)
            if previsto_ag:
                tolerancia = int(agendamento["tolerancia_min"] or 120)
                candidatos.append((previsto_ag, tolerancia))

        if candidatos:
            previsto, tolerancia = max(candidatos, key=lambda item: item[0])
            prazo = previsto + timedelta(minutes=tolerancia)

            if ultimo_dt and ultimo_dt >= previsto:
                if ultimo_log["status"] == "error":
                    status = "erro"
                    detalhe = "Ultimo backup previsto chegou com erro"
                elif ultimo_log["status"] == "warning":
                    status = "alerta"
                    detalhe = "Ultimo backup previsto chegou como alerta"
                else:
                    status = "ok"
                    detalhe = "Ultimo backup previsto recebido"
            elif agora <= prazo:
                status = "aguardando"
                detalhe = "Dentro da tolerancia do horario previsto"
            else:
                status = "atrasado"
                detalhe = "Backup previsto ainda nao chegou"
        else:
            status = "sem_agenda"
            detalhe = "Agendamento sem horario valido"

    if not agendamentos:
        if not ultimo_dt:
            status = "sem_log"
            detalhe = "Nenhum log recebido"
        elif ultimo_log["status"] == "error":
            status = "erro"
            detalhe = "Ultimo log recebido com erro"
        elif idade_min > 48 * 60:
            status = "atrasado"
            detalhe = "Ultimo log recebido ha mais de 48 horas"
        else:
            status = "ok"
            detalhe = "Ultimo log recente"

    return {
        "cliente": servidor["nome_exibicao"],
        "nome_log": servidor["nome_log"],
        "status": status,
        "detalhe": detalhe,
        "ultimo_log": ultimo_log["data_email"] if ultimo_log else None,
        "ultimo_status": ultimo_log["status"] if ultimo_log else None,
        "origem": ultimo_log["origem"] if ultimo_log else None,
        "idade_min": idade_min,
        "previsto": previsto.strftime("%Y-%m-%d %H:%M:%S") if previsto else None,
        "prazo": prazo.strftime("%Y-%m-%d %H:%M:%S") if prazo else None,
        "agente": agente,
    }


def calcular_disponibilidade_servidor(db, servidor, agora):
    ultimo_log = db.execute("""
        SELECT data_email, status, origem
        FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        ORDER BY datetime(data_email) DESC, id DESC
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()

    heartbeat = db.execute("""
        SELECT hostname, ip_local, agent_version, last_seen, status, detalhe
        FROM agent_heartbeats
        WHERE UPPER(servidor_log)=UPPER(?)
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()

    agendamentos = db.execute("""
        SELECT dias_execucao, hora_execucao, tolerancia_min
        FROM agendamentos_backup
        WHERE servidor_id=? AND ativo=1
    """, (servidor["id"],)).fetchall()

    return montar_linha_backup_servidor(servidor, agora, ultimo_log, heartbeat, agendamentos)


def formatar_status_agente(heartbeat, agora, limite_online_min=10):
    if not heartbeat:
        return {
            "status": "sem_agente",
            "label": "Sem agente",
            "idade_min": None,
            "last_seen": None,
            "hostname": None,
            "ip_local": None,
            "version": None,
            "detalhe": None,
        }

    last_seen_dt = parse_data(heartbeat["last_seen"])
    idade_min = None
    online = False
    if last_seen_dt:
        idade_min = max(0, int((agora - last_seen_dt).total_seconds() // 60))
        online = idade_min <= limite_online_min

    heartbeat_status = heartbeat["status"] or ""
    if online and heartbeat_status == "online_no_evidence":
        status = "online_no_evidence"
        label = "Online sem log local"
    else:
        status = "online" if online else "offline"
        label = "Online" if online else "Offline"

    version = heartbeat["agent_version"]
    return {
        "status": status,
        "label": label,
        "idade_min": idade_min,
        "last_seen": heartbeat["last_seen"],
        "hostname": heartbeat["hostname"],
        "ip_local": heartbeat["ip_local"],
        "version": version,
        "detalhe": heartbeat["detalhe"],
        "latest_version": LATEST_AGENT_VERSION,
        "update_available": comparar_versao_agent(version, LATEST_AGENT_VERSION) < 0,
    }


def status_agent_disponivel(status):
    return status in ("online", "online_no_evidence")


def calcular_uptime_por_eventos(eventos, inicio, fim, tolerancia_min=10):
    if not eventos:
        return {
            "observado_min": 0,
            "online_min": 0,
            "offline_min": 0,
            "percentual": None,
        }

    pontos = []
    for evento in eventos:
        visto = parse_data(evento["seen_at"])
        if visto:
            pontos.append((visto, evento["status"] or "online"))

    if not pontos:
        return {
            "observado_min": 0,
            "online_min": 0,
            "offline_min": 0,
            "percentual": None,
        }

    pontos.sort(key=lambda item: item[0])
    inicio_observado = min(max(pontos[0][0], inicio), fim)
    online_seg = 0
    tolerancia_seg = tolerancia_min * 60

    for idx, (quando, status) in enumerate(pontos):
        if quando < inicio:
            quando = inicio
        if quando > fim:
            continue

        proximo = pontos[idx + 1][0] if idx + 1 < len(pontos) else fim
        proximo = min(proximo, fim)
        if proximo <= quando:
            continue

        duracao = (proximo - quando).total_seconds()
        if status_agent_disponivel(status):
            online_seg += min(duracao, tolerancia_seg)

    observado_seg = max(0, (fim - inicio_observado).total_seconds())
    online_min = int(online_seg // 60)
    observado_min = int(observado_seg // 60)
    offline_min = max(0, observado_min - online_min)
    percentual = round((online_min / observado_min) * 100, 2) if observado_min else None

    return {
        "observado_min": observado_min,
        "online_min": online_min,
        "offline_min": offline_min,
        "percentual": percentual,
    }


def calcular_streak_agent(eventos, agora, tolerancia_min=10):
    pontos = []
    for evento in eventos:
        visto = parse_data(evento["seen_at"])
        if visto:
            pontos.append((visto, evento["status"] or "online"))

    if not pontos:
        return {"estado": "sem_dados", "desde_min": None}

    pontos.sort(key=lambda item: item[0])
    ultimo_quando, ultimo_status = pontos[-1]
    idade_min = max(0, int((agora - ultimo_quando).total_seconds() // 60))
    if idade_min > tolerancia_min or not status_agent_disponivel(ultimo_status):
        return {"estado": "offline", "desde_min": idade_min}

    inicio = ultimo_quando
    anterior = ultimo_quando
    for quando, status in reversed(pontos[:-1]):
        gap_min = (anterior - quando).total_seconds() / 60
        if gap_min > tolerancia_min or not status_agent_disponivel(status):
            break
        inicio = quando
        anterior = quando

    return {
        "estado": "online",
        "desde_min": max(0, int((agora - inicio).total_seconds() // 60)),
    }


@bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    try:
        agora = datetime.now()
        backups_data = montar_dados_backups(db)
        availability = montar_dados_tempo_online(db, "", 24)
        pfsense_rows, pfsense_summary = montar_disponibilidade_pfsense(db, availability["agora"], 24)
        ticket_summary = db.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) AS active,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open,
                   SUM(CASE WHEN status='open' AND assignee_user_id IS NULL THEN 1 ELSE 0 END) AS unassigned,
                   SUM(CASE WHEN status='in_progress' THEN 1 ELSE 0 END) AS in_progress,
                   SUM(CASE WHEN status='waiting_customer' THEN 1 ELSE 0 END) AS waiting,
                   SUM(CASE WHEN prioridade='critical' AND status NOT IN ('resolved','closed') THEN 1 ELSE 0 END) AS critical
            FROM helpdesk_tickets
        """).fetchone()
        windows_summary = db.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN event_id IN (41,6008) THEN 1 ELSE 0 END) AS unexpected,
                   SUM(CASE WHEN event_id IN (41,6008) AND datetime(occurred_at)>=datetime('now','-24 hours') THEN 1 ELSE 0 END) AS unexpected_24h,
                   COUNT(DISTINCT hostname) AS hosts
            FROM windows_events
            WHERE datetime(occurred_at)>=datetime('now','-30 days')
        """).fetchone()
        estate = db.execute("""
            SELECT (SELECT COUNT(*) FROM clientes WHERE ativo=1) AS clients,
                   (SELECT COUNT(*) FROM servidores WHERE ativo=1) AS servers,
                   (SELECT COUNT(*) FROM notification_outbox WHERE status IN ('pending','retry')) AS notifications_pending,
                   (SELECT COUNT(*) FROM logs_nao_cadastrados) AS unknown_logs
        """).fetchone()
        latest_tickets = db.execute("""
            SELECT t.id, t.numero, t.assunto, t.prioridade, t.status, t.created_at,
                   c.nome_exibicao AS cliente_nome, u.username AS assignee_name
            FROM helpdesk_tickets t
            LEFT JOIN clientes c ON c.id=t.cliente_id
            LEFT JOIN usuarios u ON u.id=t.assignee_user_id
            WHERE t.status NOT IN ('resolved','closed')
            ORDER BY CASE t.prioridade WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                     datetime(t.created_at) DESC LIMIT 6
        """).fetchall()
        windows_recent = db.execute("""
            SELECT we.id, we.hostname, we.event_id, we.occurred_at, we.initiated_by,
                   c.nome_exibicao AS cliente_nome
            FROM windows_events we JOIN clientes c ON c.id=we.cliente_id
            WHERE we.event_id IN (41,6008,1074)
            ORDER BY datetime(we.occurred_at) DESC, we.id DESC LIMIT 5
        """).fetchall()
        backup_attention = [row for row in backups_data["linhas"] if row["status"] in ("erro", "atrasado", "alerta", "sem_log")][:7]
        agent_attention = [row for row in availability["linhas"] if row["streak"]["estado"] != "online"][:7]
        firewall_attention = [row for row in pfsense_rows if row["estado"] != "online" or row["backup_problem"] or row["ftp_problem"] or row["link_problem"] or row["speedtest_problem"]][:6]
        attention_total = (
            int(backups_data["resumo"]["problemas"] or 0)
            + int(availability["resumo"]["offline"] or 0)
            + len(firewall_attention)
            + int(ticket_summary["unassigned"] or 0)
            + int(windows_summary["unexpected_24h"] or 0)
            + int(estate["notifications_pending"] or 0)
        )
        return render_template(
            "dashboard.html", backups=backups_data, availability=availability,
            pfsense_rows=pfsense_rows, pfsense=pfsense_summary, tickets=ticket_summary,
            windows=windows_summary, estate=estate, latest_tickets=latest_tickets,
            windows_recent=windows_recent, backup_attention=backup_attention,
            agent_attention=agent_attention, firewall_attention=firewall_attention,
            attention_total=attention_total, now=agora, formatar_idade=formatar_idade,
            title="Central de operações",
        )
    finally:
        db.close()


def montar_dados_backups(db):
    agora = datetime.now()

    servidores = db.execute("""
        SELECT s.id, s.nome_log, c.nome_exibicao
        FROM servidores s
        JOIN clientes c ON c.id = s.cliente_id
        WHERE s.ativo = 1 AND c.ativo = 1
        ORDER BY c.nome_exibicao, s.nome_log
    """).fetchall()

    ultimos_logs = {
        (row["servidor_log"] or "").upper(): row
        for row in db.execute("""
            SELECT servidor_log, data_email, status, origem
            FROM (
                SELECT
                    servidor_log,
                    data_email,
                    status,
                    origem,
                    ROW_NUMBER() OVER (
                        PARTITION BY UPPER(servidor_log)
                        ORDER BY datetime(data_email) DESC, id DESC
                    ) AS rn
                FROM logs_email
            ) ranked
            WHERE rn=1
        """).fetchall()
    }
    heartbeats = {
        (row["servidor_log"] or "").upper(): row
        for row in db.execute("""
            SELECT servidor_log, hostname, ip_local, agent_version, last_seen, status, detalhe
            FROM agent_heartbeats
        """).fetchall()
    }
    agendamentos_por_servidor = {}
    for row in db.execute("""
        SELECT servidor_id, dias_execucao, hora_execucao, tolerancia_min
        FROM agendamentos_backup
        WHERE ativo=1
    """).fetchall():
        agendamentos_por_servidor.setdefault(row["servidor_id"], []).append(row)

    linhas = [
        montar_linha_backup_servidor(
            servidor,
            agora,
            ultimos_logs.get((servidor["nome_log"] or "").upper()),
            heartbeats.get((servidor["nome_log"] or "").upper()),
            agendamentos_por_servidor.get(servidor["id"], []),
        )
        for servidor in servidores
    ]

    ordem_status = {
        "erro": 0,
        "atrasado": 1,
        "alerta": 2,
        "aguardando": 3,
        "sem_log": 4,
        "sem_agenda": 5,
        "ok": 6,
    }
    linhas.sort(key=lambda item: (ordem_status.get(item["status"], 9), item["cliente"], item["nome_log"]))

    resumo = {
        "ok": sum(1 for item in linhas if item["status"] == "ok"),
        "problemas": sum(1 for item in linhas if item["status"] in ("erro", "atrasado")),
        "aguardando": sum(1 for item in linhas if item["status"] == "aguardando"),
        "sem_agenda": sum(1 for item in linhas if item["status"] == "sem_agenda"),
        "sem_log": sum(1 for item in linhas if item["status"] == "sem_log"),
        "total": len(linhas),
    }

    ultimo_worker = db.execute("""
        SELECT *
        FROM worker_runs
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 1
    """).fetchone()

    worker_fresh = False
    worker_age_min = None
    if ultimo_worker:
        worker_ref = parse_data(ultimo_worker["finished_at"]) or parse_data(ultimo_worker["started_at"])
        if worker_ref:
            worker_age_min = max(0, int((agora - worker_ref).total_seconds() // 60))
            worker_fresh = worker_age_min <= 15 and ultimo_worker["status"] in ("success", "running")

    origem_24h = db.execute("""
        SELECT COALESCE(origem, 'email') AS origem, COUNT(*) AS total
        FROM logs_email
        WHERE datetime(data_email) >= datetime('now', '-24 hours')
        GROUP BY COALESCE(origem, 'email')
        ORDER BY total DESC
    """).fetchall()

    recentes = db.execute("""
        SELECT servidor_log, data_email, status, origem, subject
        FROM logs_email
        ORDER BY datetime(data_email) DESC, id DESC
        LIMIT 12
    """).fetchall()

    return {
        "linhas": linhas,
        "resumo": resumo,
        "ultimo_worker": ultimo_worker,
        "worker_fresh": worker_fresh,
        "worker_age": formatar_idade(worker_age_min),
        "origem_24h": origem_24h,
        "recentes": recentes,
        "agora": agora,
    }


@bp.route("/backups")
@login_required
def backups():
    db = get_db()
    dados = montar_dados_backups(db)
    db.close()
    return render_template(
        "backups.html",
        linhas=dados["linhas"],
        resumo=dados["resumo"],
        ultimo_worker=dados["ultimo_worker"],
        worker_fresh=dados["worker_fresh"],
        worker_age=dados["worker_age"],
        origem_24h=dados["origem_24h"],
        recentes=dados["recentes"],
        agora=dados["agora"].strftime("%Y-%m-%d %H:%M:%S"),
        formatar_idade=formatar_idade,
        title="Backups",
    )


def montar_dados_tempo_online(db, cliente_id="", periodo_horas=24):
    agora = datetime.now()
    if periodo_horas not in (24, 168, 720):
        periodo_horas = 24

    clientes = db.execute("""
        SELECT id, nome_exibicao
        FROM clientes
        WHERE ativo=1
        ORDER BY nome_exibicao
    """).fetchall()

    params = []
    filtro_cliente = ""
    if cliente_id:
        filtro_cliente = "AND c.id=?"
        params.append(cliente_id)

    servidores = db.execute(f"""
        SELECT s.id, s.nome_log, c.id AS cliente_id, c.nome_exibicao
        FROM servidores s
        JOIN clientes c ON c.id = s.cliente_id
        WHERE s.ativo=1 AND c.ativo=1
        {filtro_cliente}
        ORDER BY c.nome_exibicao, s.nome_log
    """, params).fetchall()

    periodo_key = {24: "24h", 168: "7d", 720: "30d"}[periodo_horas]
    inicio_periodo = agora - timedelta(hours=periodo_horas)
    inicio_periodo_sql = inicio_periodo.strftime("%Y-%m-%d %H:%M:%S")
    nomes_servidores = {(servidor["nome_log"] or "").upper() for servidor in servidores}
    heartbeats = {
        (row["servidor_log"] or "").upper(): row
        for row in db.execute("""
            SELECT servidor_log, hostname, ip_local, agent_version, last_seen, status, detalhe
            FROM agent_heartbeats
        """).fetchall()
        if (row["servidor_log"] or "").upper() in nomes_servidores
    }
    eventos_por_servidor = {}
    for row in db.execute("""
        SELECT servidor_log, status, seen_at
        FROM agent_heartbeat_history
        WHERE datetime(seen_at) >= datetime(?)
        ORDER BY UPPER(servidor_log), datetime(seen_at)
    """, (inicio_periodo_sql,)).fetchall():
        nome = (row["servidor_log"] or "").upper()
        if nome in nomes_servidores:
            eventos_por_servidor.setdefault(nome, []).append(row)

    linhas = []

    for servidor in servidores:
        nome_key = (servidor["nome_log"] or "").upper()
        heartbeat = heartbeats.get(nome_key)
        eventos = list(eventos_por_servidor.get(nome_key, []))

        eventos_status_atual = list(eventos)
        if heartbeat and heartbeat["last_seen"]:
            eventos_status_atual.append({
                "status": heartbeat["status"] or "online",
                "seen_at": heartbeat["last_seen"],
            })

        periodo_metricas = calcular_uptime_por_eventos(eventos_status_atual, inicio_periodo, agora)
        metricas = {
            "24h": periodo_metricas if periodo_key == "24h" else {"percentual": None, "online_min": 0, "offline_min": 0, "observado_min": 0},
            "7d": periodo_metricas if periodo_key == "7d" else {"percentual": None, "online_min": 0, "offline_min": 0, "observado_min": 0},
            "30d": periodo_metricas if periodo_key == "30d" else {"percentual": None, "online_min": 0, "offline_min": 0, "observado_min": 0},
        }
        streak = calcular_streak_agent(eventos_status_atual, agora)

        agente = formatar_status_agente(heartbeat, agora) if heartbeat else {
            "status": "sem_agente",
            "label": "Sem agente",
            "idade_min": None,
            "last_seen": None,
            "hostname": None,
            "ip_local": None,
            "version": None,
            "detalhe": None,
            "latest_version": LATEST_AGENT_VERSION,
            "update_available": False,
        }

        linhas.append({
            "cliente": servidor["nome_exibicao"],
            "nome_log": servidor["nome_log"],
            "agente": agente,
            "metricas": metricas,
            "periodo": metricas[periodo_key],
            "streak": streak,
            "eventos": len(eventos),
        })

    linhas.sort(key=lambda item: (
        999 if item["periodo"]["percentual"] is None else item["periodo"]["percentual"],
        item["cliente"],
        item["nome_log"],
    ))

    resumo = {
        "total": len(linhas),
        "online": sum(1 for item in linhas if item["streak"]["estado"] == "online"),
        "offline": sum(1 for item in linhas if item["streak"]["estado"] == "offline"),
        "sem_dados": sum(1 for item in linhas if item["streak"]["estado"] == "sem_dados"),
    }
    percentuais = [item["periodo"]["percentual"] for item in linhas if item["periodo"]["percentual"] is not None]
    resumo["media"] = round(sum(percentuais) / len(percentuais), 2) if percentuais else None

    cliente_nome = "Todos os clientes"
    if cliente_id:
        cliente = next((item for item in clientes if str(item["id"]) == str(cliente_id)), None)
        if cliente:
            cliente_nome = cliente["nome_exibicao"]

    return {
        "clientes": clientes,
        "cliente_id": cliente_id,
        "cliente_nome": cliente_nome,
        "horas": periodo_horas,
        "linhas": linhas,
        "resumo": resumo,
        "agora": agora,
    }


def montar_disponibilidade_pfsense(db, agora, periodo_horas):
    inicio = (agora - timedelta(hours=periodo_horas)).strftime("%Y-%m-%d %H:%M:%S")
    storage = db.execute("SELECT active FROM pfsense_storage WHERE id=1").fetchone()
    storage_active = bool(storage and storage["active"])
    firewalls = db.execute("""
        SELECT f.*,
               c.hostname, c.version, c.latency_ms, c.interfaces_total, c.interfaces_up,
               c.disk_percent, c.metrics_json, c.checked_at AS latest_checked_at,
               b.created_at AS latest_backup_created_at, b.remote_status,
               b.remote_uploaded_at, b.remote_error,
               s.tested_at AS latest_speedtest_tested_at, s.status AS latest_speedtest_result,
               s.ping_ms, s.download_mbps, s.upload_mbps, s.error AS speedtest_error
        FROM pfsense_firewalls f
        LEFT JOIN pfsense_checks c ON c.id=(
            SELECT pc.id FROM pfsense_checks pc
            WHERE pc.firewall_id=f.id ORDER BY pc.id DESC LIMIT 1
        )
        LEFT JOIN pfsense_backups b ON b.id=(
            SELECT pb.id FROM pfsense_backups pb
            WHERE pb.firewall_id=f.id ORDER BY pb.id DESC LIMIT 1
        )
        LEFT JOIN pfsense_speedtests s ON s.id=(
            SELECT ps.id FROM pfsense_speedtests ps
            WHERE ps.firewall_id=f.id ORDER BY ps.id DESC LIMIT 1
        )
        WHERE f.active=1
        ORDER BY f.name
    """).fetchall()

    linhas = []
    for row in firewalls:
        latest_metrics = {}
        if row["metrics_json"]:
            try:
                latest_metrics = json.loads(row["metrics_json"])
            except (TypeError, ValueError):
                pass
        uptime = enriquecer_uptime_pfsense(latest_metrics, row["latest_checked_at"])
        last_check = parse_data(row["last_check_at"] or row["latest_checked_at"])
        idade_min = max(0, int((agora - last_check).total_seconds() // 60)) if last_check else None
        limite_min = max(10, int(row["monitor_interval_minutes"] or 5) * 3)
        if not last_check:
            estado, label, classe = "sem_dados", "SEM DADOS", "secondary"
            detalhe = "aguardando primeira verificacao"
        elif row["last_status"] != "online":
            estado, label, classe = "offline", "DOWN", "danger"
            detalhe = row["last_error"] or "ultima verificacao falhou"
        elif idade_min > limite_min:
            estado, label, classe = "atrasado", "ATRASADO", "danger"
            detalhe = f"sem verificacao ha {formatar_idade(idade_min)}"
        else:
            estado, label, classe = "online", "UP", "success"
            detalhe = f"verificado ha {formatar_idade(idade_min)}"

        periodo = db.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='online' THEN 1 ELSE 0 END) AS online
            FROM pfsense_checks
            WHERE firewall_id=? AND datetime(checked_at) >= datetime(?)
        """, (row["id"], inicio)).fetchone()
        total_checks = int(periodo["total"] or 0)
        online_checks = int(periodo["online"] or 0)
        percentual = round((online_checks * 100.0) / total_checks, 2) if total_checks else None

        last_backup = parse_data(row["last_backup_at"] or row["latest_backup_created_at"])
        backup_idade_min = max(0, int((agora - last_backup).total_seconds() // 60)) if last_backup else None
        backup_limite_min = int(row["backup_interval_hours"] or 24) * 60 + limite_min
        backup_problem = not last_backup or backup_idade_min > backup_limite_min
        ftp_problem = storage_active and row["remote_status"] != "success"
        speedtest_problem = bool(row["speedtest_enabled"]) and row["last_speedtest_status"] == "error"
        internet_links = []
        for link_row in db.execute("""
            SELECT l.*,
                   p.status AS probe_status, p.latency_ms AS probe_latency_ms,
                   p.packet_loss_percent,
                   s.status AS speed_status, s.download_mbps, s.upload_mbps,
                   s.delivered_down_percent, s.delivered_up_percent
            FROM pfsense_links l
            LEFT JOIN pfsense_link_probes p ON p.id=(
                SELECT lp.id FROM pfsense_link_probes lp WHERE lp.link_id=l.id ORDER BY lp.id DESC LIMIT 1
            )
            LEFT JOIN pfsense_link_speedtests s ON s.id=(
                SELECT ls.id FROM pfsense_link_speedtests ls WHERE ls.link_id=l.id ORDER BY ls.id DESC LIMIT 1
            )
            WHERE l.firewall_id=? AND l.active=1 ORDER BY l.name
        """, (row["id"],)).fetchall():
            item = dict(link_row)
            below = bool(
                item["speed_status"] == "success"
                and item["delivered_down_percent"] is not None
                and (
                    float(item["delivered_down_percent"]) < float(item["minimum_delivery_percent"] or 80)
                    or float(item["delivered_up_percent"]) < float(item["minimum_delivery_percent"] or 80)
                )
            )
            item["problem"] = (
                item["probe_status"] in ("offline", "error")
                or (item["packet_loss_percent"] is not None and float(item["packet_loss_percent"]) > 20)
                or item["speed_status"] == "error" or below
            )
            internet_links.append(item)
        link_problem = any(item["problem"] for item in internet_links)

        linhas.append({
            "id": row["id"], "name": row["name"], "address": row["address"],
            "ssh_port": row["ssh_port"], "estado": estado, "label": label,
            "classe": classe, "detalhe": detalhe, "idade_min": idade_min,
            "hostname": row["hostname"], "version": row["version"],
            "latency_ms": row["latency_ms"], "interfaces_total": row["interfaces_total"],
            "interfaces_up": row["interfaces_up"], "disk_percent": row["disk_percent"],
            "uptime_label": uptime["UPTIME_LABEL"], "boot_at": uptime["BOOT_AT"],
            "recent_reboot": uptime["RECENT_REBOOT"],
            "periodo_total": total_checks, "periodo_online": online_checks,
            "periodo_percentual": percentual,
            "last_backup_at": row["last_backup_at"] or row["latest_backup_created_at"],
            "backup_idade_min": backup_idade_min, "backup_problem": backup_problem,
            "remote_status": row["remote_status"], "remote_uploaded_at": row["remote_uploaded_at"],
            "remote_error": row["remote_error"], "ftp_problem": ftp_problem,
            "storage_active": storage_active,
            "speedtest_enabled": bool(row["speedtest_enabled"]),
            "speedtest_status": row["latest_speedtest_result"],
            "speedtest_at": row["latest_speedtest_tested_at"],
            "speedtest_ping_ms": row["ping_ms"],
            "speedtest_download_mbps": row["download_mbps"],
            "speedtest_upload_mbps": row["upload_mbps"],
            "speedtest_error": row["speedtest_error"] or row["last_speedtest_error"],
            "speedtest_problem": speedtest_problem,
            "internet_links": internet_links, "link_problem": link_problem,
        })

    resumo = {
        "total": len(linhas),
        "online": sum(1 for item in linhas if item["estado"] == "online"),
        "offline": sum(1 for item in linhas if item["estado"] in ("offline", "atrasado")),
        "sem_dados": sum(1 for item in linhas if item["estado"] == "sem_dados"),
        "problemas_backup": sum(1 for item in linhas if item["backup_problem"] or item["ftp_problem"]),
        "problemas_speedtest": sum(1 for item in linhas if item["speedtest_problem"]),
        "problemas_links": sum(1 for item in linhas if item["link_problem"]),
        "storage_active": storage_active,
    }
    return linhas, resumo


@bp.route("/disponibilidade")
@login_required
def disponibilidade():
    db = get_db()
    cliente_id = request.args.get("cliente_id", "").strip()
    try:
        periodo_horas = int(request.args.get("horas") or 24)
    except ValueError:
        periodo_horas = 24
    dados = montar_dados_tempo_online(db, cliente_id, periodo_horas)
    pfsense_linhas, pfsense_resumo = montar_disponibilidade_pfsense(
        db, dados["agora"], dados["horas"]
    )
    db.close()

    agente_alertas = []
    for row in dados["linhas"]:
        agente = row["agente"]
        estado = row["streak"]["estado"]
        update_only = agente.get("update_available") and estado == "online"
        if estado == "online" and not update_only:
            continue

        if estado == "offline":
            label = "Offline"
            classe = "danger"
            detalhe = f"off ha {formatar_idade(row['streak'].get('desde_min'))}"
            prioridade = 0
        elif estado == "sem_dados":
            label = "Sem dados"
            classe = "secondary"
            detalhe = "sem historico de heartbeat"
            prioridade = 1
        else:
            label = "Atualizar"
            classe = "info"
            detalhe = f"v{agente.get('version')} -> {agente.get('latest_version')}"
            prioridade = 2

        agente_alertas.append({
            "cliente": row["cliente"],
            "nome_log": row["nome_log"],
            "label": label,
            "classe": classe,
            "detalhe": detalhe,
            "hostname": agente.get("hostname"),
            "ip_local": agente.get("ip_local"),
            "prioridade": prioridade,
            "desde_min": row["streak"].get("desde_min"),
            "href": f"/servidor/{row['nome_log']}",
        })

    for firewall in pfsense_linhas:
        if firewall["estado"] == "online" and not firewall["backup_problem"] and not firewall["ftp_problem"] and not firewall["speedtest_problem"] and not firewall["link_problem"]:
            continue
        if firewall["estado"] in ("offline", "atrasado"):
            label, classe, prioridade = firewall["label"], "danger", 0
            detalhe = firewall["detalhe"]
        elif firewall["estado"] == "sem_dados":
            label, classe, prioridade = "Sem dados", "secondary", 1
            detalhe = firewall["detalhe"]
        elif firewall["ftp_problem"]:
            label, classe, prioridade = "FTP", "warning", 1
            detalhe = firewall["remote_error"] or "ultimo backup ainda nao foi enviado"
        elif firewall["speedtest_problem"]:
            label, classe, prioridade = "Internet", "warning", 1
            detalhe = firewall["speedtest_error"] or "teste de velocidade falhou"
        elif firewall["link_problem"]:
            label, classe, prioridade = "Link WAN", "warning", 1
            detalhe = "uma ou mais Internets apresentam falha ou entrega abaixo do limite"
        else:
            label, classe, prioridade = "Backup", "warning", 1
            detalhe = "backup ausente ou atrasado"
        agente_alertas.append({
            "cliente": "pfSense",
            "nome_log": firewall["name"],
            "label": label,
            "classe": classe,
            "detalhe": detalhe,
            "hostname": firewall["hostname"],
            "ip_local": firewall["address"],
            "prioridade": prioridade,
            "desde_min": firewall["idade_min"],
            "href": f"/pfsense/{firewall['id']}",
        })

    agente_alertas.sort(key=lambda item: (
        item["prioridade"],
        -(item["desde_min"] or 0),
        item["cliente"],
        item["nome_log"],
    ))
    dados["resumo"]["atencao"] = len(agente_alertas)

    return render_template(
        "disponibilidade.html",
        clientes=dados["clientes"],
        cliente_id=dados["cliente_id"],
        cliente_nome=dados["cliente_nome"],
        horas=dados["horas"],
        linhas=dados["linhas"],
        resumo=dados["resumo"],
        agente_alertas=agente_alertas,
        pfsense_linhas=pfsense_linhas,
        pfsense_resumo=pfsense_resumo,
        agora=dados["agora"].strftime("%Y-%m-%d %H:%M:%S"),
        formatar_idade=formatar_idade,
        title="Disponibilidade",
    )


@bp.route("/tempo-online")
@login_required
def tempo_online():
    destino = "/disponibilidade"
    if request.query_string:
        destino += "?" + request.query_string.decode("utf-8", errors="ignore")
    return redirect(destino)


@bp.route("/disponibilidade/relatorio")
@bp.route("/tempo-online/relatorio")
@login_required
def tempo_online_relatorio():
    db = get_db()
    cliente_id = request.args.get("cliente_id", "").strip()
    try:
        periodo_horas = int(request.args.get("horas") or 24)
    except ValueError:
        periodo_horas = 24
    dados = montar_dados_tempo_online(db, cliente_id, periodo_horas)
    db.close()

    html = render_template(
        "tempo_online_relatorio.html",
        cliente_nome=dados["cliente_nome"],
        horas=dados["horas"],
        linhas=dados["linhas"],
        resumo=dados["resumo"],
        agora=dados["agora"].strftime("%Y-%m-%d %H:%M:%S"),
        formatar_idade=formatar_idade,
    )
    periodo_label = {24: "24h", 168: "7dias", 720: "30dias"}.get(dados["horas"], "24h")
    cliente_slug = re.sub(r"[^A-Za-z0-9_-]+", "_", dados["cliente_nome"]).strip("_").lower() or "clientes"
    filename = f"relatorio-disponibilidade-{cliente_slug}-{periodo_label}.html"
    headers = {}
    if request.args.get("download") == "1":
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(html, headers=headers, mimetype="text/html; charset=utf-8")


@bp.route("/servidor/<nome_log>")
@login_required
def historico_servidor(nome_log):

    db = get_db()

    logs = db.execute("""
        SELECT data_email, status, conteudo_raw
        FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        ORDER BY data_email DESC
        LIMIT 200
    """, (nome_log,)).fetchall()

    return render_template(
        "historico_servidor.html",
        nome_log=nome_log,
        logs=logs
    )


@bp.route("/historico")
@login_required
def historico():

    db = get_db()

    servidor = request.args.get("servidor", "")
    inicio = request.args.get("inicio", "")
    fim = request.args.get("fim", "")

    query = """
        SELECT l.*, s.nome_log, c.nome_exibicao
        FROM logs_email l
        JOIN servidores s ON UPPER(s.nome_log)=UPPER(l.servidor_log)
        JOIN clientes c ON c.id = s.cliente_id
        WHERE 1=1
    """

    params = []

    if servidor:
        query += " AND UPPER(l.servidor_log)=UPPER(?)"
        params.append(servidor)

    if inicio:
        query += " AND date(l.data_email) >= ?"
        params.append(inicio)

    if fim:
        query += " AND date(l.data_email) <= ?"
        params.append(fim)

    query += " ORDER BY l.data_email DESC LIMIT 200"

    logs = db.execute(query, params).fetchall()

    servidores = db.execute("""
        SELECT DISTINCT nome_log FROM servidores ORDER BY nome_log
    """).fetchall()

    return render_template(
        "historico_geral.html",
        logs=logs,
        servidores=servidores,
        servidor_filtro=servidor,
        inicio=inicio,
        fim=fim
    )


def _idade_min(texto, agora):
    quando = parse_data(texto)
    return max(0, int((agora - quando).total_seconds() // 60)) if quando else None


def saude_das_coletas(db, agora=None):
    """Tarefas do worker e coleta de cada firewall, cada uma com a idade do ultimo ciclo e `atrasada` quando passou muito do
    esperado (3 x o intervalo, minimo 10 min). Mostra o que parou em silencio, que antes so aparecia no `docker logs`."""
    agora = agora or datetime.now()
    tarefas = []
    for t in db.execute("SELECT * FROM worker_tarefas ORDER BY nome").fetchall():
        idade = _idade_min(t["ultimo_ciclo_em"], agora)
        esperado = max(10, 3 * (t["intervalo_s"] or 300) // 60)
        tarefas.append({"nome": t["nome"], "idade_min": idade, "ciclos": t["ciclos"], "erros": t["erros"],
                        "ultimo_erro": t["ultimo_erro"], "ultimo_erro_em": t["ultimo_erro_em"],
                        "atrasada": idade is None or idade > esperado})
    firewalls = []
    for f in db.execute("SELECT name, last_check_at, last_status, last_error, telemetry_at, telemetry_error FROM pfsense_firewalls WHERE active=1 ORDER BY id").fetchall():
        check, telemetria = _idade_min(f["last_check_at"], agora), _idade_min(f["telemetry_at"], agora)
        firewalls.append({"nome": f["name"], "check_min": check, "status": f["last_status"], "erro": f["last_error"],
                          "telemetria_min": telemetria, "telemetria_erro": f["telemetry_error"],
                          "atrasado": check is None or check > 30 or f["last_status"] not in ("online", "success")})
    return tarefas, firewalls


@bp.route("/status")
@login_required
def status_sistema():
    db = get_db()

    ultimo_worker = db.execute("""
        SELECT *
        FROM worker_runs
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 1
    """).fetchone()

    historico_worker = db.execute("""
        SELECT *
        FROM worker_runs
        ORDER BY datetime(started_at) DESC, id DESC
        LIMIT 20
    """).fetchall()

    email_config = db.execute("""
        SELECT imap_server, imap_port, email_user, pasta, usar_ssl
        FROM config_email
        LIMIT 1
    """).fetchone()

    totais = {
        "clientes": db.execute("SELECT COUNT(*) AS c FROM clientes WHERE ativo=1").fetchone()["c"],
        "servidores": db.execute("SELECT COUNT(*) AS c FROM servidores WHERE ativo=1").fetchone()["c"],
        "logs": db.execute("SELECT COUNT(*) AS c FROM logs_email").fetchone()["c"],
        "nao_cadastrados": db.execute("""
            SELECT COUNT(*) AS c
            FROM logs_nao_cadastrados l
            LEFT JOIN servidores s ON UPPER(l.servidor_log)=UPPER(s.nome_log)
            WHERE s.id IS NULL
        """).fetchone()["c"],
        "notificacoes_pendentes": db.execute("SELECT COUNT(*) AS c FROM notification_outbox WHERE status IN ('pending','retry')").fetchone()["c"],
        "notificacoes_falhas": db.execute("SELECT COUNT(*) AS c FROM notification_outbox WHERE status='failed'").fetchone()["c"],
    }
    ticketz = db.execute("SELECT ativo, CASE WHEN token_enc IS NULL OR token_enc='' THEN 0 ELSE 1 END AS token_ok FROM ticketz_config WHERE id=1").fetchone()
    storage = db.execute("SELECT active, last_status, last_test_at, last_cleanup_at FROM pfsense_storage WHERE id=1").fetchone()
    agent_versions = db.execute("SELECT COALESCE(agent_version,'desconhecida') AS version, COUNT(*) AS total FROM agent_heartbeats GROUP BY COALESCE(agent_version,'desconhecida') ORDER BY total DESC").fetchall()
    worker_ref = parse_data(ultimo_worker["finished_at"] or ultimo_worker["started_at"]) if ultimo_worker else None
    worker_age = max(0, int((datetime.now() - worker_ref).total_seconds() // 60)) if worker_ref else None
    worker_fresh = worker_age is not None and worker_age <= 15 and ultimo_worker["status"] in ("success", "running")
    tarefas, firewalls_saude = saude_das_coletas(db)
    db.close()

    return render_template(
        "status.html",
        ultimo_worker=ultimo_worker,
        historico_worker=historico_worker,
        email_config=email_config,
        totais=totais,
        ticketz=ticketz, storage=storage, agent_versions=agent_versions,
        worker_age=worker_age, worker_fresh=worker_fresh,
        tarefas=tarefas, firewalls_saude=firewalls_saude,
        title="Saúde da plataforma",
    )


@bp.route("/windows-events")
@login_required
@support_required
def windows_events():
    db = get_db()
    cliente_id = request.args.get("cliente_id", "").strip()
    event_id = request.args.get("event_id", "").strip()
    busca = request.args.get("q", "").strip()
    where = []
    params = []
    if cliente_id.isdigit():
        where.append("we.cliente_id=?")
        params.append(int(cliente_id))
    if event_id.isdigit():
        where.append("we.event_id=?")
        params.append(int(event_id))
    if busca:
        where.append("(UPPER(we.hostname) LIKE UPPER(?) OR UPPER(COALESCE(we.initiated_by,'')) LIKE UPPER(?) OR UPPER(COALESCE(we.message,'')) LIKE UPPER(?))")
        term = f"%{busca[:80]}%"
        params.extend([term, term, term])
    where_sql = " WHERE " + " AND ".join(where) if where else ""
    eventos = db.execute(f"""
        SELECT we.*, c.nome_exibicao, c.responsavel_nome,
               c.responsavel_email, c.alertar_eventos_windows
        FROM windows_events we
        JOIN clientes c ON c.id=we.cliente_id
        {where_sql}
        ORDER BY datetime(we.occurred_at) DESC, we.id DESC
        LIMIT 500
    """, params).fetchall()
    clientes = db.execute("""
        SELECT id, nome_exibicao FROM clientes WHERE ativo=1 ORDER BY nome_exibicao
    """).fetchall()
    resumo = db.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN event_id=1074 THEN 1 ELSE 0 END) AS planejados,
            SUM(CASE WHEN event_id IN (41,6008) THEN 1 ELSE 0 END) AS inesperados,
            COUNT(DISTINCT hostname) AS hosts
        FROM windows_events
        WHERE datetime(occurred_at) >= datetime('now', '-30 days')
    """).fetchone()
    db.close()
    return render_template(
        "windows_events.html",
        eventos=eventos,
        clientes=clientes,
        resumo=resumo,
        filtros={"cliente_id": cliente_id, "event_id": event_id, "q": busca},
        title="Eventos Windows",
    )
