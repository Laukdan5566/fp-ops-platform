import base64
import json
import re
import socket
from datetime import datetime, timedelta
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


ERROS_SEGUIDOS_PARA_ALERTA = 3
BACKUPS_NAO_RECEBIDOS_PARA_ALERTA = 3
MAX_LOG_ATTACHMENT_BYTES = 1024 * 1024
AGENT_ONLINE_GRACE_MINUTES = 10


def normalizar_base_url(base_url):
    base_url = (base_url or "").strip()
    if not base_url:
        return ""

    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    return base_url.rstrip("/") + "/"


def carregar_config(db):
    return db.execute("""
        SELECT *
        FROM zammad_config
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()


def configurado(config):
    return (
        config
        and int(config["ativo"] or 0) == 1
        and config["base_url"]
        and config["token"]
        and config["grupo"]
        and config["customer_email"]
    )


def alerta_ja_enviado(db, alerta_key):
    return db.execute("""
        SELECT 1
        FROM zammad_alertas
        WHERE alerta_key=?
        AND status_envio='success'
    """, (alerta_key,)).fetchone() is not None


def registrar_alerta(db, alerta_key, log_email_id, servidor, status_backup, status_envio, ticket=None, erro=None):
    ticket = ticket or {}

    db.execute("""
        INSERT INTO zammad_alertas
        (alerta_key, log_email_id, servidor_log, status_backup, zammad_ticket_id,
         zammad_ticket_number, status_envio, erro, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        alerta_key,
        log_email_id,
        servidor,
        status_backup,
        ticket.get("id"),
        ticket.get("number"),
        status_envio,
        erro,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))
    db.commit()


def montar_corpo(servidor, data_ref, status_backup, subject, body):
    trecho = (body or "").strip()
    if len(trecho) > 3500:
        trecho = trecho[:3500] + "\n\n[log truncado]"

    if status_backup == "windows_shutdown":
        titulo = "Alerta de desligamento Windows"
    elif status_backup in ("agent_offline", "agent_online"):
        titulo = "Alerta de disponibilidade"
    else:
        titulo = "Alerta de backup"
    return (
        f"{titulo}: {status_backup}\n"
        f"Servidor: {servidor}\n"
        f"Referencia: {data_ref}\n"
        f"Resumo: {subject or '-'}\n\n"
        f"Detalhes:\n{trecho}"
    )


def preparar_conteudo_anexo(conteudo):
    dados = (conteudo or "").encode("utf-8", errors="replace")
    if len(dados) <= MAX_LOG_ATTACHMENT_BYTES:
        return dados

    aviso = (
        "\n\n[Anexo truncado pelo monitor: "
        f"log original tinha {len(dados)} bytes.]"
    ).encode("utf-8")
    return dados[:MAX_LOG_ATTACHMENT_BYTES] + aviso


def montar_anexo_log(servidor, data_ref, conteudo):
    if not conteudo:
        return None

    nome_servidor = re.sub(r"[^A-Za-z0-9_-]+", "_", servidor).strip("_")
    data_limpa = re.sub(r"[^0-9]+", "", data_ref or "")[:14] or datetime.now().strftime("%Y%m%d%H%M%S")
    dados = preparar_conteudo_anexo(conteudo)

    return {
        "filename": f"{nome_servidor}_{data_limpa}_ultimo_log.txt",
        "data": base64.b64encode(dados).decode("ascii"),
        "mime-type": "text/plain",
    }


def criar_ticket(config, servidor, data_ref, status_backup, subject, body, attachments=None, customer_email=None):
    base_url = normalizar_base_url(config["base_url"])
    url = urljoin(base_url, "api/v1/tickets")
    if status_backup == "windows_shutdown":
        prefixo = "[Windows]"
    elif status_backup in ("agent_offline", "agent_online"):
        prefixo = "[Disponibilidade]"
    else:
        prefixo = "[Backup]"
    titulo = f"{prefixo} {servidor} - {subject or status_backup}"
    customer_id = buscar_customer_id(config, customer_email=customer_email)

    article = {
        "subject": subject or titulo,
        "body": montar_corpo(servidor, data_ref, status_backup, subject, body),
        "type": "note",
        "internal": False,
        "content_type": "text/plain",
    }

    attachments = [anexo for anexo in (attachments or []) if anexo]
    if attachments:
        article["attachments"] = attachments

    prioridade = config["prioridade"] or "2 normal"
    if status_backup in ("agent_offline", "windows_shutdown"):
        prioridade = config["prioridade_agent_offline"] or "3 high"

    payload = {
        "title": titulo,
        "group": config["grupo"],
        "customer_id": customer_id,
        "priority": prioridade,
        "article": article,
    }

    data = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={
            "Authorization": f"Token token={config['token']}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=20) as resp:
            response_data = resp.read().decode("utf-8", errors="replace")
            if resp.status not in (200, 201):
                raise RuntimeError(f"Zammad retornou HTTP {resp.status}: {response_data[:500]}")
            return json.loads(response_data)
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Zammad retornou HTTP {e.code}: {detail[:500]}") from e
    except (URLError, socket.timeout) as e:
        raise RuntimeError(f"Falha ao conectar no Zammad: {e}") from e


def fechar_ticket(config, ticket_id, servidor, body):
    base_url = normalizar_base_url(config["base_url"])
    url = urljoin(base_url, f"api/v1/tickets/{ticket_id}")
    payload = {
        "state": "closed",
        "article": {
            "subject": f"Agent voltou online - {servidor}",
            "body": body,
            "type": "note",
            "internal": False,
            "content_type": "text/plain",
        },
    }

    data = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={
            "Authorization": f"Token token={config['token']}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="PUT",
    )

    try:
        with urlopen(req, timeout=20) as resp:
            response_data = resp.read().decode("utf-8", errors="replace")
            if resp.status not in (200, 201):
                raise RuntimeError(f"Zammad retornou HTTP {resp.status}: {response_data[:500]}")
            return json.loads(response_data)
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Zammad retornou HTTP {e.code} ao fechar ticket: {detail[:500]}") from e
    except (URLError, socket.timeout) as e:
        raise RuntimeError(f"Falha ao fechar ticket no Zammad: {e}") from e


def buscar_customer_id(config, customer_email=None):
    base_url = normalizar_base_url(config["base_url"])
    target_email = (customer_email or config["customer_email"] or "").strip()
    query = urlencode({"query": target_email})
    url = urljoin(base_url, f"api/v1/users/search?{query}")
    req = Request(
        url,
        headers={
            "Authorization": f"Token token={config['token']}",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urlopen(req, timeout=20) as resp:
            response_data = resp.read().decode("utf-8", errors="replace")
            if resp.status != 200:
                raise RuntimeError(f"Zammad retornou HTTP {resp.status}: {response_data[:500]}")
            users = json.loads(response_data)
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Zammad retornou HTTP {e.code} ao buscar cliente: {detail[:500]}") from e
    except (URLError, socket.timeout) as e:
        raise RuntimeError(f"Falha ao buscar cliente no Zammad: {e}") from e

    email = target_email.lower()
    for user in users:
        if (user.get("email") or "").lower() == email:
            return user["id"]

    if users and not customer_email:
        return users[0]["id"]

    raise RuntimeError(f"Cliente Zammad não encontrado: {target_email}")


def enviar_alerta(db, config, alerta_key, servidor, data_ref, status_backup, subject, body, log_email_id=None, attachments=None, customer_email=None):
    if alerta_ja_enviado(db, alerta_key):
        return "duplicate"

    try:
        ticket = criar_ticket(
            config, servidor, data_ref, status_backup, subject, body,
            attachments=attachments, customer_email=customer_email,
        )
        registrar_alerta(db, alerta_key, log_email_id, servidor, status_backup, "success", ticket=ticket)
        return "success"
    except Exception as e:
        registrar_alerta(db, alerta_key, log_email_id, servidor, status_backup, "error", erro=str(e))
        return "error"


def avaliar_erros_seguidos(db, config, servidor):
    if int(config["criar_chamado_erro"] or 0) != 1:
        return None

    logs = db.execute("""
        SELECT id, status, data_email, subject, conteudo_raw
        FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        ORDER BY datetime(data_email) DESC, id DESC
        LIMIT 20
    """, (servidor["nome_log"],)).fetchall()

    sequencia = []
    for log in logs:
        if log["status"] != "error":
            break
        sequencia.append(log)

    if len(sequencia) < ERROS_SEGUIDOS_PARA_ALERTA:
        return None

    primeiro = sequencia[-1]
    ultimo = sequencia[0]
    alerta_key = f"zammad:errors3:{servidor['nome_log']}:{primeiro['id']}"
    subject = f"{len(sequencia)} backups com erro seguidos"
    body = (
        f"O servidor {servidor['nome_log']} esta com {len(sequencia)} backups com erro seguidos.\n"
        f"Primeiro erro da sequencia: {primeiro['data_email']}\n"
        f"Ultimo erro: {ultimo['data_email']}\n\n"
        f"Ultimo assunto: {ultimo['subject'] or '-'}\n\n"
        f"Ultimo log:\n{ultimo['conteudo_raw'] or ''}"
    )

    return enviar_alerta(
        db,
        config,
        alerta_key,
        servidor["nome_log"],
        ultimo["data_email"],
        "3_errors",
        subject,
        body,
        log_email_id=ultimo["id"],
        attachments=[montar_anexo_log(servidor["nome_log"], ultimo["data_email"], ultimo["conteudo_raw"])],
    )


def parse_hora(hora):
    try:
        partes = (hora or "").split(":")
        return int(partes[0]), int(partes[1])
    except Exception:
        return None


def datas_esperadas(agendamento, agora, dias=21):
    hora = parse_hora(agendamento["hora_execucao"])
    if not hora:
        return []

    dias_execucao = {
        int(dia)
        for dia in (agendamento["dias_execucao"] or "").split(",")
        if dia.strip().isdigit()
    }
    if not dias_execucao:
        return []

    resultado = []
    inicio = agora.date() - timedelta(days=dias)
    for offset in range(dias + 1):
        dia = inicio + timedelta(days=offset)
        if dia.weekday() not in dias_execucao:
            continue

        esperado = datetime.combine(dia, datetime.min.time()).replace(hour=hora[0], minute=hora[1])
        tolerancia = timedelta(minutes=int(agendamento["tolerancia_min"] or 120))
        if esperado + tolerancia <= agora:
            resultado.append((esperado, tolerancia))

    return resultado


def backup_chegou(db, servidor_log, esperado, tolerancia):
    inicio = esperado - timedelta(minutes=30)
    fim = esperado + tolerancia

    return db.execute("""
        SELECT 1
        FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        AND datetime(data_email) >= ?
        AND datetime(data_email) <= ?
        LIMIT 1
    """, (
        servidor_log,
        inicio.strftime("%Y-%m-%d %H:%M:%S"),
        fim.strftime("%Y-%m-%d %H:%M:%S"),
    )).fetchone() is not None


def parse_data(valor):
    if not valor:
        return None

    for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(valor)[:19], formato)
        except ValueError:
            pass

    return None


def avaliar_backups_nao_recebidos(db, config, servidor):
    if int(config["criar_chamado_nao_recebido"] or 0) != 1:
        return None

    agendamentos = db.execute("""
        SELECT *
        FROM agendamentos_backup
        WHERE servidor_id=? AND ativo=1
    """, (servidor["id"],)).fetchall()

    agora = datetime.now()
    eventos = []
    for agendamento in agendamentos:
        eventos.extend(datas_esperadas(agendamento, agora))

    eventos.sort(key=lambda item: item[0])

    sequencia = []
    for esperado, tolerancia in eventos:
        if backup_chegou(db, servidor["nome_log"], esperado, tolerancia):
            sequencia = []
        else:
            sequencia.append(esperado)

    if len(sequencia) < BACKUPS_NAO_RECEBIDOS_PARA_ALERTA:
        return None

    primeiro = sequencia[0]
    ultimo = sequencia[-1]
    alerta_key = f"zammad:missing3:{servidor['nome_log']}:{primeiro:%Y%m%d%H%M}"
    subject = f"{len(sequencia)} backups esperados sem recebimento"
    ultimo_log = db.execute("""
        SELECT data_email, conteudo_raw
        FROM logs_email
        WHERE UPPER(servidor_log)=UPPER(?)
        ORDER BY datetime(data_email) DESC, id DESC
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()

    body = (
        f"O servidor {servidor['nome_log']} esta com {len(sequencia)} backups esperados sem recebimento.\n"
        f"Primeiro backup nao recebido: {primeiro:%Y-%m-%d %H:%M:%S}\n"
        f"Ultimo backup nao recebido: {ultimo:%Y-%m-%d %H:%M:%S}\n"
        f"Regra atual: abre chamado ao atingir {BACKUPS_NAO_RECEBIDOS_PARA_ALERTA} ocorrencias.\n"
        f"Ultimo log recebido: {ultimo_log['data_email'] if ultimo_log else 'nenhum'}."
    )

    return enviar_alerta(
        db,
        config,
        alerta_key,
        servidor["nome_log"],
        ultimo.strftime("%Y-%m-%d %H:%M:%S"),
        "3_missing",
        subject,
        body,
        attachments=[
            montar_anexo_log(
                servidor["nome_log"],
                ultimo_log["data_email"],
                ultimo_log["conteudo_raw"],
            )
            if ultimo_log else None
        ],
    )


def avaliar_agent_offline(db, config, servidor):
    if int(config["criar_chamado_agent_offline"] or 0) != 1:
        return None

    tolerancia_min = max(10, int(config["agent_offline_minutos"] or 60))
    heartbeat = db.execute("""
        SELECT hostname, ip_local, agent_version, last_seen, status, detalhe
        FROM agent_heartbeats
        WHERE UPPER(servidor_log)=UPPER(?)
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()
    if not heartbeat:
        return None

    last_seen = parse_data(heartbeat["last_seen"])
    if not last_seen:
        return None

    agora = datetime.now()
    idade_min = int((agora - last_seen).total_seconds() // 60)
    if idade_min < tolerancia_min:
        return None

    if idade_min <= AGENT_ONLINE_GRACE_MINUTES and (heartbeat["status"] or "") in ("online", "online_no_evidence"):
        return None

    queda_ref = last_seen.strftime("%Y%m%d%H%M%S")
    alerta_key = f"zammad:agent_offline:{servidor['nome_log']}:{queda_ref}"
    subject = f"Agent offline ha {idade_min} minutos"
    body = (
        f"O agent do servidor {servidor['nome_log']} esta offline.\n"
        f"Ultimo heartbeat: {heartbeat['last_seen']}\n"
        f"Tempo sem contato: {idade_min} minutos\n"
        f"Tolerancia configurada: {tolerancia_min} minutos\n"
        f"Hostname: {heartbeat['hostname'] or '-'}\n"
        f"IP local: {heartbeat['ip_local'] or '-'}\n"
        f"Versao do agent: {heartbeat['agent_version'] or '-'}\n"
        f"Ultimo status informado: {heartbeat['status'] or '-'}\n"
        f"Detalhe: {heartbeat['detalhe'] or '-'}"
    )

    return enviar_alerta(
        db,
        config,
        alerta_key,
        servidor["nome_log"],
        heartbeat["last_seen"],
        "agent_offline",
        subject,
        body,
    )


def avaliar_agent_online(db, config, servidor):
    if int(config["fechar_chamado_agent_online"] or 0) != 1:
        return None

    heartbeat = db.execute("""
        SELECT hostname, ip_local, agent_version, last_seen, status, detalhe
        FROM agent_heartbeats
        WHERE UPPER(servidor_log)=UPPER(?)
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()
    if not heartbeat:
        return None

    last_seen = parse_data(heartbeat["last_seen"])
    if not last_seen:
        return None

    idade_min = int((datetime.now() - last_seen).total_seconds() // 60)
    if idade_min > AGENT_ONLINE_GRACE_MINUTES or (heartbeat["status"] or "") not in ("online", "online_no_evidence"):
        return None

    chamado_offline = db.execute("""
        SELECT id, alerta_key, zammad_ticket_id, zammad_ticket_number, created_at
        FROM zammad_alertas
        WHERE UPPER(servidor_log)=UPPER(?)
          AND status_backup='agent_offline'
          AND status_envio='success'
          AND zammad_ticket_id IS NOT NULL
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 1
    """, (servidor["nome_log"],)).fetchone()
    if not chamado_offline:
        return None

    alerta_key = f"zammad:agent_online:{servidor['nome_log']}:{chamado_offline['zammad_ticket_id']}"
    if alerta_ja_enviado(db, alerta_key):
        return "duplicate"

    body = (
        f"O agent do servidor {servidor['nome_log']} voltou online.\n"
        f"Heartbeat atual: {heartbeat['last_seen']}\n"
        f"Tempo desde o ultimo heartbeat: {idade_min} minutos\n"
        f"Hostname: {heartbeat['hostname'] or '-'}\n"
        f"IP local: {heartbeat['ip_local'] or '-'}\n"
        f"Versao do agent: {heartbeat['agent_version'] or '-'}\n"
        f"Ticket offline relacionado: {chamado_offline['zammad_ticket_number'] or chamado_offline['zammad_ticket_id']}"
    )

    try:
        ticket = fechar_ticket(config, chamado_offline["zammad_ticket_id"], servidor["nome_log"], body)
        registrar_alerta(
            db,
            alerta_key,
            None,
            servidor["nome_log"],
            "agent_online",
            "success",
            ticket=ticket,
        )
        return "success"
    except Exception as e:
        registrar_alerta(
            db,
            alerta_key,
            None,
            servidor["nome_log"],
            "agent_online",
            "error",
            ticket={
                "id": chamado_offline["zammad_ticket_id"],
                "number": chamado_offline["zammad_ticket_number"],
            },
            erro=str(e),
        )
        return "error"


def avaliar_eventos_windows(db, config):
    eventos = db.execute("""
        SELECT we.*, c.nome_exibicao, c.responsavel_nome, c.responsavel_email
        FROM windows_events we
        JOIN clientes c ON c.id=we.cliente_id
        WHERE c.ativo=1
          AND c.alertar_eventos_windows=1
          AND we.is_historical=0
          AND we.event_id IN (1074, 6008)
          AND NOT EXISTS (
              SELECT 1 FROM zammad_alertas za
              WHERE za.alerta_key=('zammad:windows:' || we.id)
                AND za.status_envio='success'
          )
        ORDER BY datetime(we.occurred_at), we.id
        LIMIT 20
    """).fetchall()

    resultados = []
    for evento in eventos:
        alerta_key = f"zammad:windows:{evento['id']}"
        usuario = evento["initiated_by"] or "nao identificado"
        processo = evento["process_name"] or "nao identificado"
        if int(evento["event_id"]) == 1074:
            subject = f"Desligamento/reinicio por {usuario} em {evento['hostname']}"
            diagnostico = "Evento planejado registrado pelo Windows (1074)."
        else:
            subject = f"Desligamento inesperado em {evento['hostname']}"
            diagnostico = "O Windows informou encerramento inesperado (6008); pode ser energia, reset ou travamento."

        body = (
            f"{diagnostico}\n"
            f"Cliente: {evento['nome_exibicao']}\n"
            f"Servidor/hostname: {evento['hostname']}\n"
            f"Cadastro de backup: {evento['servidor_log'] or '-'}\n"
            f"Data do evento (UTC): {evento['occurred_at']}\n"
            f"Event ID: {evento['event_id']}\n"
            f"Usuario responsavel: {usuario}\n"
            f"Processo: {processo}\n"
            f"Motivo: {evento['reason'] or '-'}\n"
            f"Codigo do motivo: {evento['reason_code'] or '-'}\n"
            f"Comentario: {evento['comment'] or '-'}\n"
            f"Responsavel cadastrado: {evento['responsavel_nome'] or '-'} <{evento['responsavel_email'] or '-'}>\n\n"
            f"Mensagem original:\n{evento['message'] or '-'}"
        )
        resultados.append(enviar_alerta(
            db,
            config,
            alerta_key,
            evento["servidor_log"] or evento["hostname"],
            evento["occurred_at"],
            "windows_shutdown",
            subject,
            body,
            customer_email=evento["responsavel_email"],
        ))
    return resultados


def avaliar_alertas(db):
    config = carregar_config(db)
    if not configurado(config):
        return {"status": "disabled", "success": 0, "error": 0, "duplicate": 0}

    servidores = db.execute("""
        SELECT id, nome_log
        FROM servidores
        WHERE ativo=1
    """).fetchall()

    resumo = {"status": "enabled", "success": 0, "error": 0, "duplicate": 0}
    for servidor in servidores:
        for avaliador in (avaliar_erros_seguidos, avaliar_backups_nao_recebidos, avaliar_agent_offline, avaliar_agent_online):
            resultado = avaliador(db, config, servidor)
            if resultado in resumo:
                resumo[resultado] += 1

    for resultado in avaliar_eventos_windows(db, config):
        if resultado in resumo:
            resumo[resultado] += 1

    return resumo
