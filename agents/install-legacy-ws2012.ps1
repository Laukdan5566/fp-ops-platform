param(
    [string]$InstallDir = "$env:ProgramData\BackupMonitorAgent",
    [string]$ApiKey,
    [string]$ConfigTemplate,
    [switch]$RunNow
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator"
    )
}

function Find-ClientConfigs {
    return @(Get-ChildItem -Path $PSScriptRoot -Filter "agent.config*.json" -ErrorAction SilentlyContinue |
        Where-Object { @("agent.config.example.json", "agent.config.multi.example.json") -notcontains $_.Name })
}

if (-not (Test-Admin)) {
    throw "Execute este instalador como Administrador."
}

Write-Host ""
Write-Host "Backup Monitor Agent Legacy - Windows Server 2012"
Write-Host "================================================"
Write-Host ""

if (-not $ConfigTemplate) {
    $configs = Find-ClientConfigs
    if ($configs.Count -eq 1) {
        $ConfigTemplate = $configs[0].FullName
        Write-Host "Config detectada: $ConfigTemplate"
    } elseif ($configs.Count -gt 1) {
        Write-Host "Configs encontradas:"
        for ($i = 0; $i -lt $configs.Count; $i++) {
            Write-Host ("[{0}] {1}" -f ($i + 1), $configs[$i].Name)
        }
        $choice = Read-Host "Digite o numero da config"
        $index = [int]$choice - 1
        if ($index -lt 0 -or $index -ge $configs.Count) {
            throw "Opcao invalida."
        }
        $ConfigTemplate = $configs[$index].FullName
    } else {
        throw "Nenhuma config agent.config.<cliente>.json foi encontrada nesta pasta."
    }
}

if (-not (Test-Path $ConfigTemplate)) {
    throw "Config nao encontrada: $ConfigTemplate"
}

if (-not $ApiKey) {
    try {
        $template = Get-Content $ConfigTemplate -Raw | ConvertFrom-Json
        $templateKey = ""
        if ($template.PSObject.Properties.Name -contains "api_key") {
            $templateKey = [string]$template.api_key
        }
        if ($templateKey -and $templateKey -ne "COLE_A_CHAVE_API_AQUI") {
            $ApiKey = $templateKey
            Write-Host "Chave API detectada na config."
        }
    } catch {
    }
}

if (-not $ApiKey) {
    $ApiKey = Read-Host "Cole a chave API"
}
if (-not $ApiKey) {
    throw "Chave API nao informada."
}

$installer = Join-Path $PSScriptRoot "install-windows-agent.ps1"
if (-not (Test-Path $installer)) {
    throw "install-windows-agent.ps1 nao encontrado."
}

$wrapper = Join-Path $PSScriptRoot "BackupMonitorAgentService.exe"
if (-not (Test-Path $wrapper)) {
    throw "BackupMonitorAgentService.exe nao encontrado."
}

$logFile = Join-Path $env:TEMP "backup-monitor-agent-install-legacy.log"
Write-Host ""
Write-Host "Instalando como servico..."
Write-Host "Log do instalador: $logFile"
Write-Host ""

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$installer" `
    -ApiKey "$ApiKey" `
    -ConfigTemplate "$ConfigTemplate" `
    -InstallDir "$InstallDir" `
    -InstallMode Service `
    -LegacyServiceInstall `
    -SkipTest `
    -RunNow *>&1 | Tee-Object -FilePath $logFile

if ($LASTEXITCODE -ne 0) {
    throw "Instalador retornou codigo $LASTEXITCODE. Veja $logFile"
}

Write-Host ""
Write-Host "Instalacao finalizada."
Write-Host ""
Write-Host "Comandos para conferir:"
Write-Host 'Get-Service -Name BackupMonitorAgent'
Write-Host 'Get-ChildItem "C:\ProgramData\BackupMonitorAgent"'
Write-Host 'Get-Content "C:\ProgramData\BackupMonitorAgent\service.log" -Tail 50'
Write-Host 'Get-Content "C:\ProgramData\BackupMonitorAgent\agent.log" -Tail 50'
