param(
    [string]$ConfigPath = "$env:ProgramData\BackupMonitorAgent\agent.config.json"
)

$ErrorActionPreference = "Stop"
$installDir = Split-Path $ConfigPath -Parent
$logPath = Join-Path $installDir "bootstrap-update.log"

function Write-BootstrapLog([string]$Message) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    Add-Content -Path $logPath -Value $line -Encoding UTF8
}

function Enable-CompatibleTls {
    try {
        $protocols = 0
        foreach ($value in @(3072, 768, 192)) { $protocols = $protocols -bor $value }
        [Net.ServicePointManager]::SecurityProtocol = [enum]::ToObject([Net.SecurityProtocolType], $protocols)
        [Net.ServicePointManager]::Expect100Continue = $false
    } catch { }
}

function Get-FileSha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) { throw "Execute este script como Administrador." }
if (-not (Test-Path $ConfigPath)) { throw "Configuracao do agent nao encontrada: $ConfigPath" }

Enable-CompatibleTls
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$job = $null
if ($config.PSObject.Properties.Name -contains "jobs" -and @($config.jobs).Count -gt 0) {
    $job = @($config.jobs)[0]
}
$servidorLog = if ($job -and $job.servidor_log) { [string]$job.servidor_log } else { [string]$config.servidor_log }
$apiKey = if ($job -and $job.api_key) { [string]$job.api_key } else { [string]$config.api_key }
$monitorUrl = ([string]$config.monitor_url).TrimEnd("/")
if (-not $servidorLog -or -not $apiKey -or -not $monitorUrl) {
    throw "A configuracao nao contem monitor_url, api_key e servidor_log validos."
}

$payload = @{
    servidor_log = $servidorLog
    hostname = [System.Net.Dns]::GetHostName()
    agent_version = "bootstrap"
    status = "online"
    detalhe = "Verificando atualizacao automatica"
    metadata = @{ bootstrap_auto_update = $true }
} | ConvertTo-Json -Depth 8
$headers = @{ Authorization = "Bearer $apiKey" }
Write-BootstrapLog "Consultando versao no monitor..."
$result = Invoke-RestMethod -Uri "$monitorUrl/api/agent/heartbeat" -Method Post -Headers $headers -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 30

$legacy = $PSVersionTable.PSVersion.Major -le 4
$updateUrl = if ($legacy) { [string]$result.update_url_ws2012 } else { [string]$result.update_url }
$expectedSha256 = if ($legacy) { [string]$result.update_sha256_ws2012 } else { [string]$result.update_sha256 }
if (-not $updateUrl -or -not $expectedSha256) { throw "O monitor nao retornou URL e SHA-256 do pacote." }

$tempRoot = Join-Path $env:TEMP ("BackupMonitorBootstrap-" + [guid]::NewGuid().ToString("N"))
$zipPath = Join-Path $tempRoot "agent.zip"
$extractDir = Join-Path $tempRoot "agent"
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
Write-BootstrapLog "Baixando agent $($result.latest_agent_version)..."
Invoke-WebRequest -Uri $updateUrl -OutFile $zipPath -TimeoutSec 120
$actualSha256 = Get-FileSha256 $zipPath
if ($actualSha256 -ne $expectedSha256.ToLowerInvariant()) {
    throw "SHA-256 invalido; atualizacao cancelada."
}
Write-BootstrapLog "Pacote validado com SHA-256."

if ($config.PSObject.Properties.Name -contains "auto_update_enabled") {
    $config.auto_update_enabled = $true
} else {
    $config | Add-Member -NotePropertyName auto_update_enabled -NotePropertyValue $true
}
$config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
} else {
    $shell = New-Object -ComObject Shell.Application
    $zip = $shell.NameSpace($zipPath)
    $dest = $shell.NameSpace($extractDir)
    $dest.CopyHere($zip.Items(), 16)
    Start-Sleep -Seconds 3
}
$installer = Join-Path $extractDir "install-windows-agent.ps1"
if (-not (Test-Path $installer)) { throw "Instalador nao encontrado no pacote validado." }

Write-BootstrapLog "Instalando e ativando atualizacoes automaticas..."
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -ConfigTemplate $ConfigPath -InstallMode Service -SkipTest -RunNow
if ($LASTEXITCODE -ne 0) { throw "Instalador retornou codigo $LASTEXITCODE" }
Write-BootstrapLog "Atualizacao concluida. As proximas versoes serao instaladas automaticamente."
