param(
    [string]$InstallDir = "$env:ProgramData\BackupMonitorAgent",
    [string]$MonitorUrl = "https://bkp.fpinformatica.com.br",

    [string]$ApiKey,

    [string]$ServidorLog,

    [string]$ConfigTemplate,
    [ValidateSet("Task", "Service")]
    [string]$InstallMode = "Task",
    [string]$ServiceName = "BackupMonitorAgent",
    [string]$NssmPath,
    [switch]$LegacyServiceInstall,

    [string[]]$LogPaths = @(
        "C:\ProgramData\IperiusBackup\Logs",
        "C:\ProgramData\Iperius Backup\Logs",
        "C:\Program Files (x86)\Iperius Backup\Logs",
        "C:\Program Files\Iperius Backup\Logs",
        "$env:LOCALAPPDATA\Temp\IperiusTemp",
        "C:\Users\*\AppData\Local\Temp\IperiusTemp"
    ),

    [string]$TaskName = "Backup Monitor Agent",
    [int]$EmailGraceMinutes = 10,
    [int]$ScanIntervalSeconds = 30,
    [int]$HeartbeatIntervalSeconds = 300,
    [int]$RecentHoursOnStart = 72,
    [switch]$SkipTest,
    [switch]$RunNow
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "Execute este instalador como Administrador."
}

$scriptPath = Join-Path $PSScriptRoot "windows-backup-agent.ps1"
if (-not (Test-Path $scriptPath)) {
    throw "Arquivo nao encontrado: $scriptPath"
}

function Read-AgentConfigJson {
    param([string]$Path)

    $raw = Get-Content $Path -Raw
    try {
        return $raw | ConvertFrom-Json
    } catch {
        $fixed = $raw.Replace('\', '\\')
        try {
            Write-Host "Config JSON tinha barras simples. Corrigindo automaticamente para leitura..."
            return $fixed | ConvertFrom-Json
        } catch {
            throw "Nao consegui ler $Path como JSON. Em caminhos Windows, use barras duplas (C:\\Users\\...) ou barras normais (C:/Users/...). Erro original: $($_.Exception.Message)"
        }
    }
}

function ConvertTo-JsonCompatibleObject {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $dict = New-Object "System.Collections.Generic.Dictionary[string,object]"
        foreach ($key in $Value.Keys) {
            $dict[[string]$key] = ConvertTo-JsonCompatibleObject $Value[$key]
        }
        return $dict
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $Value) {
            [void]$list.Add((ConvertTo-JsonCompatibleObject $item))
        }
        return $list
    }

    if ($Value.PSObject -and $Value.PSObject.Properties) {
        $dict = New-Object "System.Collections.Generic.Dictionary[string,object]"
        foreach ($prop in $Value.PSObject.Properties) {
            $dict[$prop.Name] = ConvertTo-JsonCompatibleObject $prop.Value
        }
        return $dict
    }

    return $Value
}

function ConvertTo-AgentJson {
    param($Value)

    try {
        return $Value | ConvertTo-Json -Depth 20
    } catch {
        Add-Type -AssemblyName System.Web.Extensions
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = 67108864
        return $serializer.Serialize((ConvertTo-JsonCompatibleObject $Value))
    }
}

function Resolve-ServiceWrapper {
    $candidates = @(
        (Join-Path $PSScriptRoot "BackupMonitorAgentService.exe"),
        (Join-Path $InstallDir "BackupMonitorAgentService.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw "Para instalar como servico, o arquivo BackupMonitorAgentService.exe precisa estar na mesma pasta do instalador."
}

function Remove-AgentService {
    param([string]$Name)

    $existingService = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $existingService) {
        return
    }

    if ($existingService.Status -ne "Stopped") {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    }

    & sc.exe delete $Name | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
            return
        }
    }
}

function Invoke-ScCommand {
    param([string]$Arguments)

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = "sc.exe"
    $process.StartInfo.Arguments = $Arguments
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.CreateNoWindow = $true
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    return @{
        ExitCode = $process.ExitCode
        Output = ($stdout + "`r`n" + $stderr).Trim()
    }
}

function Install-AgentTask {
    param(
        [string]$TargetScript,
        [string]$ConfigFile,
        [string]$Name
    )

    Remove-AgentService -Name $ServiceName

    $actionArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$TargetScript`" -ConfigPath `"$ConfigFile`""
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $actionArgs
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Days 0) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $Name `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Force | Out-Null
}

function Install-AgentService {
    param(
        [string]$TargetScript,
        [string]$ConfigFile,
        [string]$Name,
        [string]$ServiceLogPath
    )

    if ($NssmPath) {
        Write-Host "Aviso: -NssmPath nao e mais necessario. O servico usa BackupMonitorAgentService.exe."
    }

    $wrapper = Resolve-ServiceWrapper
    $targetWrapper = Join-Path $InstallDir "BackupMonitorAgentService.exe"

    Remove-AgentService -Name $Name

    $wrapperFull = [System.IO.Path]::GetFullPath($wrapper)
    $targetWrapperFull = [System.IO.Path]::GetFullPath($targetWrapper)
    if ($wrapperFull -ne $targetWrapperFull) {
        Copy-Item -Path $wrapper -Destination $targetWrapper -Force
    }

    if (Get-Command "Get-ScheduledTask" -ErrorAction SilentlyContinue) {
        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    }

    $binaryPath = "`"$targetWrapper`" `"$TargetScript`" `"$ConfigFile`" `"$ServiceLogPath`" `"$Name`""
    if ($LegacyServiceInstall) {
        $wmi = [wmiclass]"Win32_Service"
        $result = $wmi.Create(
            $Name,
            "Backup Monitor Agent",
            $binaryPath,
            16,
            1,
            "Automatic",
            $false,
            "LocalSystem",
            $null,
            $null,
            $null,
            $null
        )
        if ($result.ReturnValue -ne 0) {
            Write-Host "Win32_Service.Create falhou com codigo $($result.ReturnValue). Tentando fallback com New-Service..."
            try {
                New-Service `
                    -Name $Name `
                    -BinaryPathName $binaryPath `
                    -DisplayName "Backup Monitor Agent" `
                    -StartupType Automatic | Out-Null
            } catch {
                throw "Falha ao criar servico. WMI codigo: $($result.ReturnValue). New-Service: $($_.Exception.Message)"
            }
        }
    } else {
        New-Service `
            -Name $Name `
            -BinaryPathName $binaryPath `
            -DisplayName "Backup Monitor Agent" `
            -StartupType Automatic | Out-Null
    }

    & sc.exe description $Name "FP Informatica Backup Monitor Agent" | Out-Null
    & sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
}

if (-not $ConfigTemplate -and -not $ServidorLog) {
    $configs = Get-ChildItem -Path $PSScriptRoot -Filter "agent.config*.json" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("agent.config.example.json", "agent.config.multi.example.json") }

    if ($configs.Count -eq 1) {
        $ConfigTemplate = $configs[0].FullName
        Write-Host "ConfigTemplate detectado: $ConfigTemplate"
    } elseif ($configs.Count -gt 1) {
        $nomes = ($configs | ForEach-Object { $_.Name }) -join ", "
        throw "Encontrei mais de uma config de cliente ($nomes). Informe -ConfigTemplate com o arquivo correto."
    }
}
if (-not $ServidorLog -and -not $ConfigTemplate) {
    throw "Informe -ServidorLog para instalacao simples ou -ConfigTemplate para instalacao com varios jobs."
}
if ($ConfigTemplate -and -not (Test-Path $ConfigTemplate)) {
    throw "ConfigTemplate nao encontrado: $ConfigTemplate"
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$targetScript = Join-Path $InstallDir "windows-backup-agent.ps1"
$configPath = Join-Path $InstallDir "agent.config.json"
$statePath = Join-Path $InstallDir "state.json"
$logPath = Join-Path $InstallDir "agent.log"
$serviceLogPath = Join-Path $InstallDir "service.log"

Copy-Item -Path $scriptPath -Destination $targetScript -Force

if ($ConfigTemplate) {
    $template = Read-AgentConfigJson -Path $ConfigTemplate
    if (-not $ApiKey) {
        $templateKey = ""
        if ($template.PSObject.Properties.Name -contains "api_key") {
            $templateKey = [string]$template.api_key
        }
        if ($templateKey -and $templateKey -ne "COLE_A_CHAVE_API_AQUI") {
            $ApiKey = $templateKey
        }
    }
    if (-not $ApiKey) {
        throw "Chave API nao informada. Informe -ApiKey ou use uma config com api_key preenchida."
    }
    if ($template.PSObject.Properties.Name -notcontains "monitor_url") { $template | Add-Member -NotePropertyName monitor_url -NotePropertyValue $MonitorUrl } else { $template.monitor_url = $MonitorUrl }
    if ($template.PSObject.Properties.Name -notcontains "api_key") { $template | Add-Member -NotePropertyName api_key -NotePropertyValue $ApiKey } else { $template.api_key = $ApiKey }
    if ($template.PSObject.Properties.Name -notcontains "state_path") { $template | Add-Member -NotePropertyName state_path -NotePropertyValue $statePath } else { $template.state_path = $statePath }
    if ($template.PSObject.Properties.Name -notcontains "log_path") { $template | Add-Member -NotePropertyName log_path -NotePropertyValue $logPath } else { $template.log_path = $logPath }
    if ($template.PSObject.Properties.Name -notcontains "scan_interval_seconds") { $template | Add-Member -NotePropertyName scan_interval_seconds -NotePropertyValue $ScanIntervalSeconds } elseif ($null -eq $template.scan_interval_seconds) { $template.scan_interval_seconds = $ScanIntervalSeconds }
    if ($template.PSObject.Properties.Name -notcontains "heartbeat_interval_seconds") { $template | Add-Member -NotePropertyName heartbeat_interval_seconds -NotePropertyValue $HeartbeatIntervalSeconds } elseif ($null -eq $template.heartbeat_interval_seconds) { $template.heartbeat_interval_seconds = $HeartbeatIntervalSeconds }
    if ($template.PSObject.Properties.Name -notcontains "email_grace_minutes") { $template | Add-Member -NotePropertyName email_grace_minutes -NotePropertyValue $EmailGraceMinutes } elseif ($null -eq $template.email_grace_minutes) { $template.email_grace_minutes = $EmailGraceMinutes }
    if ($template.PSObject.Properties.Name -notcontains "recent_hours_on_start") { $template | Add-Member -NotePropertyName recent_hours_on_start -NotePropertyValue $RecentHoursOnStart } elseif ($null -eq $template.recent_hours_on_start) { $template.recent_hours_on_start = $RecentHoursOnStart }
    if ($template.PSObject.Properties.Name -notcontains "windows_event_monitoring_enabled") { $template | Add-Member -NotePropertyName windows_event_monitoring_enabled -NotePropertyValue $true }
    if ($template.PSObject.Properties.Name -notcontains "windows_event_recent_hours_on_start") { $template | Add-Member -NotePropertyName windows_event_recent_hours_on_start -NotePropertyValue 168 }
    if ($template.PSObject.Properties.Name -notcontains "auto_update_enabled") { $template | Add-Member -NotePropertyName auto_update_enabled -NotePropertyValue $true }
    $config = $template
} else {
    if (-not $ApiKey) {
        throw "Chave API nao informada. Informe -ApiKey ou use -ConfigTemplate com api_key preenchida."
    }
    $config = [ordered]@{
        monitor_url = $MonitorUrl
        api_key = $ApiKey
        servidor_log = $ServidorLog
        log_paths = $LogPaths
        patterns = @("*.txt", "*.log", "*.html", "*.htm")
        email_grace_minutes = $EmailGraceMinutes
        scan_interval_seconds = $ScanIntervalSeconds
        heartbeat_interval_seconds = $HeartbeatIntervalSeconds
        recent_hours_on_start = $RecentHoursOnStart
        windows_event_monitoring_enabled = $true
        windows_event_recent_hours_on_start = 168
        auto_update_enabled = $true
        state_path = $statePath
        log_path = $logPath
    }
}

ConvertTo-AgentJson $config | Set-Content -Path $configPath -Encoding UTF8

if (-not $SkipTest) {
    Write-Host "Testando heartbeat agora..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$targetScript" -ConfigPath "$configPath" -HeartbeatOnly
    if ($LASTEXITCODE -ne 0) {
        throw "Teste de heartbeat falhou. Veja o log em $logPath."
    }
}

if ($InstallMode -eq "Service") {
    Install-AgentService -TargetScript $targetScript -ConfigFile $configPath -Name $ServiceName -ServiceLogPath $serviceLogPath
} else {
    Install-AgentTask -TargetScript $targetScript -ConfigFile $configPath -Name $TaskName
}

if ($RunNow) {
    if ($InstallMode -eq "Service") {
        Start-Service -Name $ServiceName
    } else {
        Start-ScheduledTask -TaskName $TaskName
    }
}

Write-Host "Instalado em: $InstallDir"
Write-Host "Configuracao: $configPath"
Write-Host "Log: $logPath"
if ($InstallMode -eq "Service") {
    Write-Host "Servico: $ServiceName"
    Write-Host "Log do servico: $serviceLogPath"
} else {
    Write-Host "Tarefa agendada: $TaskName"
}
Write-Host "Monitor: $MonitorUrl"
if ($ServidorLog) {
    Write-Host "ServidorLog: $ServidorLog"
} else {
    Write-Host "ConfigTemplate: $ConfigTemplate"
}
