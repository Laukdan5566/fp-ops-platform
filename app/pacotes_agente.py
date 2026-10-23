"""Pacotes e configuracoes do agente Windows para download: ZIP, instalador e arquivo de configuracao por cliente."""
import io
import json
import os
import secrets
import zipfile
from datetime import datetime

from flask import Blueprint, Response, request

from auth import admin_required, login_required, support_required
from db import get_db
from util import hash_token, normalizar_servidor


bp = Blueprint("pacotes_agente", __name__)


DEFAULT_AGENT_LOG_PATHS = [
    "C:\\ProgramData\\IperiusBackup\\Logs",
    "C:\\ProgramData\\Iperius Backup\\Logs",
    "C:\\Program Files\\Iperius Backup\\Logs",
    "C:\\Program Files (x86)\\Iperius Backup\\Logs",
    "C:\\Users\\*\\AppData\\Local\\Temp\\IperiusTemp",
]


def montar_job_config(nome_log, log_path=None, usar_filtro_conteudo=True):
    nome_log = normalizar_servidor(nome_log)
    if log_path:
        log_paths = [log_path]
    else:
        log_paths = DEFAULT_AGENT_LOG_PATHS

    job = {
        "servidor_log": nome_log,
        "log_paths": log_paths,
        "patterns": ["*.txt", "*.log", "*.html", "*.htm"],
        "include_patterns": ["*"],
        "exclude_patterns": [],
        "exclude_content_patterns": [],
    }

    if usar_filtro_conteudo:
        job["content_patterns"] = [
            f"*{nome_log}*",
            f"*{nome_log.replace('_', ' ')}*",
        ]
    else:
        job["content_patterns"] = []

    return job


def responder_agent_config(filename, jobs):
    config = montar_agent_config(jobs)

    body = json.dumps(config, ensure_ascii=False, indent=2)
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


def montar_agent_config(jobs, api_key="COLE_A_CHAVE_API_AQUI"):
    return {
        "monitor_url": "https://bkp.fpinformatica.com.br",
        "api_key": api_key,
        "jobs": jobs,
        "email_grace_minutes": 10,
        "scan_interval_seconds": 30,
        "heartbeat_interval_seconds": 300,
        "recent_hours_on_start": 72,
        "windows_event_monitoring_enabled": True,
        "windows_event_recent_hours_on_start": 168,
        "auto_update_enabled": True,
        "state_path": "C:\\ProgramData\\BackupMonitorAgent\\state.json",
        "log_path": "C:\\ProgramData\\BackupMonitorAgent\\agent.log",
    }


def criar_api_key_cliente(db, cliente_id, nome):
    token = secrets.token_urlsafe(32)
    db.execute("""
        INSERT INTO api_keys (nome, token_hash, cliente_id, servidor_log, ativo)
        VALUES (?,?,?,?,1)
    """, (nome, hash_token(token), cliente_id, None))
    db.commit()
    return token


def buscar_cliente_jobs(cliente_id, log_path=None, usar_filtro_conteudo=True):
    db = get_db()
    cliente = db.execute("""
        SELECT id, nome_exibicao
        FROM clientes
        WHERE id=? AND ativo=1
    """, (cliente_id,)).fetchone()
    if not cliente:
        return None, None

    servidores = db.execute("""
        SELECT nome_log
        FROM servidores
        WHERE cliente_id=? AND ativo=1
        ORDER BY nome_log
    """, (cliente_id,)).fetchall()

    jobs = [
        montar_job_config(s["nome_log"], log_path, usar_filtro_conteudo)
        for s in servidores
    ]
    return cliente, jobs


def montar_zip_agent_bytes(filename, config_json, legacy=False):
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(app_dir)
    static_dir = os.path.join(app_dir, "static")
    agent_dir = os.path.join(app_dir, "agents")
    if not os.path.isdir(agent_dir):
        agent_dir = os.path.join(project_root, "agents")

    files = [
        (os.path.join(agent_dir, "BackupMonitorAgentService.exe"), "BackupMonitorAgentService.exe"),
        (os.path.join(agent_dir, "windows-backup-agent.ps1"), "windows-backup-agent.ps1"),
        (os.path.join(agent_dir, "install-windows-agent.ps1"), "install-windows-agent.ps1"),
        (os.path.join(agent_dir, "enable-agent-auto-update.ps1"), "enable-agent-auto-update.ps1"),
        (os.path.join(agent_dir, "test-agent-compatibility.ps1"), "test-agent-compatibility.ps1"),
        (os.path.join(agent_dir, "README.md"), "README.md"),
    ]
    if legacy:
        files.extend([
            (os.path.join(static_dir, "BackupMonitorAgentSetupLegacy2012.exe"), "BackupMonitorAgentSetupLegacy2012.exe"),
            (os.path.join(agent_dir, "install-legacy-ws2012.ps1"), "install-legacy-ws2012.ps1"),
            (os.path.join(agent_dir, "Instalar-Legacy-WS2012.cmd"), "Instalar-Legacy-WS2012.cmd"),
        ])
        instalar_cmd = """@echo off
setlocal
cd /d "%~dp0"
echo Backup Monitor Agent Legacy - Windows Server 2012
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-legacy-ws2012.ps1" -RunNow
echo.
pause
"""
        instrucoes = f"""Backup Monitor Agent Legacy - Windows Server 2012

1. Extraia este ZIP em uma pasta simples, por exemplo C:\\bkp-agent.
2. Execute INSTALAR.cmd como Administrador.

Se preferir pelo PowerShell, rode:

   cd "C:\\bkp-agent"
   Get-ChildItem -Recurse | Unblock-File
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\install-legacy-ws2012.ps1 -RunNow

4. Confira:

   Get-Service -Name BackupMonitorAgent
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\agent.log" -Tail 50
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\service.log" -Tail 50

Config incluida: {filename}
A chave API deste cliente ja esta embutida na config.
"""
    else:
        files.extend([
            (os.path.join(static_dir, "BackupMonitorAgentSetup.exe"), "BackupMonitorAgentSetup.exe"),
            (os.path.join(agent_dir, "setup-wizard.ps1"), "setup-wizard.ps1"),
        ])
        instalar_cmd = f"""@echo off
setlocal
cd /d "%~dp0"
echo Backup Monitor Agent
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows-agent.ps1" -ConfigTemplate "%~dp0{filename}" -InstallMode Service -SkipTest -RunNow
echo.
pause
"""
        instrucoes = f"""Backup Monitor Agent

1. Extraia este ZIP em uma pasta simples, por exemplo C:\\bkp-agent.
2. Execute INSTALAR.cmd como Administrador.

Se preferir pelo PowerShell, rode:

   cd "C:\\bkp-agent"
   Get-ChildItem -Recurse | Unblock-File
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\install-windows-agent.ps1 -ConfigTemplate ".\\{filename}" -InstallMode Service -SkipTest -RunNow

4. Confira:

   Get-Service -Name BackupMonitorAgent
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\agent.log" -Tail 50
   Get-Content "C:\\ProgramData\\BackupMonitorAgent\\service.log" -Tail 50

Config incluida: {filename}
A chave API deste cliente ja esta embutida na config.
"""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, config_json)
        zf.writestr("config-name.txt", filename)
        zf.writestr("install-mode.txt", "legacy" if legacy else "normal")
        zf.writestr("LEIA-ME-INSTALAR.txt", instrucoes)
        zf.writestr("INSTALAR.cmd", instalar_cmd)
        for path, arcname in files:
            if os.path.exists(path):
                zf.write(path, arcname)

    buffer.seek(0)
    return buffer.getvalue()


def montar_agent_exe_bytes(filename, config_json, legacy=False):
    app_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(app_dir)
    agent_dir = os.path.join(app_dir, "agents")
    if not os.path.isdir(agent_dir):
        agent_dir = os.path.join(project_root, "agents")

    stub_path = os.path.join(agent_dir, "BackupMonitorAgentInstallerStub.exe")
    if not os.path.exists(stub_path):
        raise FileNotFoundError("BackupMonitorAgentInstallerStub.exe nao encontrado")

    with open(stub_path, "rb") as f:
        stub = f.read()

    payload = montar_zip_agent_bytes(filename, config_json, legacy=legacy)
    marker = b"\n--BACKUP_MONITOR_AGENT_PAYLOAD_V1--\n"
    return stub + marker + payload


def montar_jobs_customizados():
    db = get_db()

    servidor_ids = request.form.getlist("servidor_ids")
    if not servidor_ids:
        return None, None, ("Selecione pelo menos um servidor", 400)

    placeholders = ",".join(["?"] * len(servidor_ids))
    servidores = db.execute(f"""
        SELECT s.id, s.nome_log, c.nome_exibicao
        FROM servidores s
        JOIN clientes c ON c.id = s.cliente_id
        WHERE s.id IN ({placeholders}) AND s.ativo=1 AND c.ativo=1
        ORDER BY c.nome_exibicao, s.nome_log
    """, servidor_ids).fetchall()

    if not servidores:
        return None, None, ("Nenhum servidor valido selecionado", 400)

    log_path = request.form.get("log_path", "").strip() or "C:\\ProgramData\\IperiusBackup\\Logs"
    usar_filtro_conteudo = request.form.get("usar_filtro_conteudo") == "1"
    jobs = [
        montar_job_config(s["nome_log"], log_path, usar_filtro_conteudo)
        for s in servidores
    ]

    nome_pacote = request.form.get("nome_pacote", "").strip()
    if not nome_pacote:
        nomes_clientes = sorted({s["nome_exibicao"] or "cliente" for s in servidores})
        nome_pacote = nomes_clientes[0] if len(nomes_clientes) == 1 else "personalizado"

    filename = f"agent.config.{normalizar_servidor(nome_pacote).lower()}.json"
    return filename, jobs, None


@bp.route("/api-keys/config/custom", methods=["POST"])
@login_required
@admin_required
def download_custom_agent_config():
    filename, jobs, erro = montar_jobs_customizados()
    if erro:
        return erro

    return responder_agent_config(filename, jobs)


@bp.route("/api-keys/package/legacy-ws2012", methods=["POST"])
@login_required
@admin_required
def download_legacy_ws2012_package():
    filename, jobs, erro = montar_jobs_customizados()
    if erro:
        return erro

    config = montar_agent_config(jobs)
    config_json = json.dumps(config, ensure_ascii=False, indent=2)
    data = montar_zip_agent_bytes(filename, config_json, legacy=True)
    package_name = filename.replace("agent.config.", "backup-monitor-agent-legacy-ws2012-").replace(".json", ".zip")
    return Response(
        data,
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename={package_name}"},
    )


@bp.route("/clientes/<int:cliente_id>/agent-package")
@login_required
@support_required
def download_cliente_agent_package(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_zip_agent_bytes(filename, config_json, legacy=False)
    return Response(
        data,
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename=backup-monitor-agent-{filename_base}.zip"},
    )


@bp.route("/clientes/<int:cliente_id>/agent-exe")
@login_required
@support_required
def download_cliente_agent_exe(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent EXE {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    config_filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_agent_exe_bytes(config_filename, config_json, legacy=False)
    return Response(
        data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=BackupMonitorAgent-{filename_base}.exe"},
    )


@bp.route("/clientes/<int:cliente_id>/agent-package/legacy-ws2012")
@login_required
@support_required
def download_cliente_agent_package_legacy(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent WS2012 {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_zip_agent_bytes(filename, config_json, legacy=True)
    return Response(
        data,
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename=backup-monitor-agent-ws2012-{filename_base}.zip"},
    )


@bp.route("/clientes/<int:cliente_id>/agent-exe/legacy-ws2012")
@login_required
@support_required
def download_cliente_agent_exe_legacy(cliente_id):
    db = get_db()
    cliente, jobs = buscar_cliente_jobs(cliente_id)
    if not cliente:
        return "Cliente nao encontrado", 404
    if not jobs:
        return "Cliente sem servidores/logs ativos", 400

    token = criar_api_key_cliente(
        db,
        cliente_id,
        f"Agent EXE WS2012 {cliente['nome_exibicao']} {datetime.now().strftime('%Y-%m-%d %H:%M')}",
    )
    filename_base = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    config_filename = f"agent.config.{filename_base}.json"
    config_json = json.dumps(montar_agent_config(jobs, token), ensure_ascii=False, indent=2)
    data = montar_agent_exe_bytes(config_filename, config_json, legacy=True)
    return Response(
        data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=BackupMonitorAgent-WS2012-{filename_base}.exe"},
    )


@bp.route("/api-keys/config/cliente/<int:cliente_id>")
@login_required
@admin_required
def download_cliente_agent_config(cliente_id):
    db = get_db()
    cliente = db.execute("""
        SELECT id, nome_exibicao
        FROM clientes
        WHERE id=? AND ativo=1
    """, (cliente_id,)).fetchone()
    if not cliente:
        return "Cliente nao encontrado", 404

    servidores = db.execute("""
        SELECT nome_log
        FROM servidores
        WHERE cliente_id=? AND ativo=1
        ORDER BY nome_log
    """, (cliente_id,)).fetchall()

    jobs = []
    for servidor in servidores:
        jobs.append(montar_job_config(servidor["nome_log"]))

    filename = normalizar_servidor(cliente["nome_exibicao"] or f"cliente_{cliente_id}").lower()
    return responder_agent_config(f"agent.config.{filename}.json", jobs)
