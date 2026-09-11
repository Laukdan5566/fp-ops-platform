param(
    [string]$ConfigPath = "$PSScriptRoot\agent.config.json",
    [string]$MonitorUrl,
    [string]$ApiKey,
    [string]$ServidorLog,
    [string[]]$LogPaths,
    [string[]]$Patterns,
    [int]$EmailGraceMinutes = -1,
    [int]$ScanIntervalSeconds = -1,
    [int]$HeartbeatIntervalSeconds = -1,
    [int]$RecentHoursOnStart = -1,
    [string]$StatePath,
    [string]$LogPath,
    [switch]$HeartbeatOnly,
    [switch]$Once
)

$ErrorActionPreference = "Stop"
$AgentVersion = "1.3.1"
$AgentStartedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Enable-CompatibleTls {
    try {
        $protocols = 0
        foreach ($value in @(3072, 768, 192)) {
            $protocols = $protocols -bor $value
        }
        [Net.ServicePointManager]::SecurityProtocol = [enum]::ToObject([Net.SecurityProtocolType], $protocols)
        [Net.ServicePointManager]::Expect100Continue = $false
    } catch {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        } catch {
        }
    }
}

Enable-CompatibleTls

$DefaultLogPaths = @(
    "C:\ProgramData\IperiusBackup\Logs",
    "C:\ProgramData\Iperius Backup\Logs",
    "C:\Program Files (x86)\Iperius Backup\Logs",
    "C:\Program Files\Iperius Backup\Logs",
    "$env:LOCALAPPDATA\Temp\IperiusTemp",
    "C:\Users\*\AppData\Local\Temp\IperiusTemp"
)
$DefaultPatterns = @("*.txt", "*.log", "*.html", "*.htm")

function Get-ConfigValue {
    param([object]$Config, [string]$Name, $DefaultValue)

    if ($Config -and $Config.PSObject.Properties.Name -contains $Name -and $null -ne $Config.$Name) {
        return $Config.$Name
    }

    return $DefaultValue
}

function To-Array {
    param($Value, $DefaultValue)

    if ($null -eq $Value) {
        return @($DefaultValue)
    }

    if ($Value -is [array]) {
        return @($Value)
    }

    return @($Value)
}

function Add-DefaultLogPaths {
    param($Paths)

    $merged = New-Object System.Collections.ArrayList
    foreach ($path in @($Paths)) {
        if ($path -and -not $merged.Contains([string]$path)) {
            [void]$merged.Add([string]$path)
        }
    }
    foreach ($path in @($DefaultLogPaths)) {
        if ($path -and -not $merged.Contains([string]$path)) {
            [void]$merged.Add([string]$path)
        }
    }

    return @($merged)
}

function Write-AgentLog {
    param([string]$Message)

    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line

    if ($script:ResolvedLogPath) {
        try {
            $logDir = Split-Path $script:ResolvedLogPath -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            Add-Content -Path $script:ResolvedLogPath -Value $line -Encoding UTF8
        } catch {
            Write-Host "Could not write log file: $($_.Exception.Message)"
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

function Normalize-Url {
    param([string]$Url)
    return $Url.TrimEnd("/")
}

function Normalize-ServidorLog {
    param([string]$Value)

    if (-not $Value) {
        return $null
    }

    return (($Value.Trim().ToUpperInvariant()) -replace "\s+", "_")
}

function Load-Config {
    if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
        return $null
    }

    $raw = Get-Content $ConfigPath -Raw
    try {
        return $raw | ConvertFrom-Json
    } catch {
        $fixed = $raw.Replace('\', '\\')
        try {
            Write-AgentLog "Config JSON tinha barras simples. Corrigindo automaticamente para leitura..."
            return $fixed | ConvertFrom-Json
        } catch {
            throw "Nao consegui ler $ConfigPath como JSON. Em caminhos Windows, use barras duplas (C:\\Users\\...) ou barras normais (C:/Users/...). Erro original: $($_.Exception.Message)"
        }
    }
}

function Read-TextFile {
    param([string]$Path)

    try {
        $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
        return [System.IO.File]::ReadAllText($Path, $utf8Strict)
    } catch {
        return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::Default)
    }
}

function Get-TextSha256 {
    param([string]$Text)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function Load-State {
    if (-not (Test-Path $StatePath)) {
        return @{
            sent = @{}; skipped_by_email = @{}; failures = @{}; update_notices = @{}
            windows_event_pending = @{}; windows_event_cursor = 0; windows_event_initialized = $false
        }
    }

    try {
        $raw = Get-Content $StatePath -Raw | ConvertFrom-Json
        $state = @{
            sent = @{}; skipped_by_email = @{}; failures = @{}; update_notices = @{}
            windows_event_pending = @{}; windows_event_cursor = 0; windows_event_initialized = $false
        }

        foreach ($name in @("sent", "skipped_by_email", "failures", "update_notices", "windows_event_pending")) {
            if ($raw.$name) {
                foreach ($prop in $raw.$name.PSObject.Properties) {
                    $state[$name][$prop.Name] = $prop.Value
                }
            }
        }
        if ($raw.PSObject.Properties.Name -contains "windows_event_cursor") {
            $state.windows_event_cursor = [long]$raw.windows_event_cursor
        }
        if ($raw.PSObject.Properties.Name -contains "windows_event_initialized") {
            $state.windows_event_initialized = [bool]$raw.windows_event_initialized
        }

        return $state
    } catch {
        Write-AgentLog "State file could not be read, starting a new state: $($_.Exception.Message)"
        return @{
            sent = @{}; skipped_by_email = @{}; failures = @{}; update_notices = @{}
            windows_event_pending = @{}; windows_event_cursor = 0; windows_event_initialized = $false
        }
    }
}

function Save-State {
    param($State)

    $dir = Split-Path $StatePath -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    ConvertTo-AgentJson $State | Set-Content -Path $StatePath -Encoding UTF8
}

function Invoke-MonitorApi {
    param(
        [string]$Path,
        [hashtable]$Payload,
        [string]$Token
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $body = ConvertTo-AgentJson $Payload

    try {
        return Invoke-RestMethod `
            -Uri "$script:BaseUrl$Path" `
            -Method Post `
            -Headers $headers `
            -ContentType "application/json; charset=utf-8" `
            -Body $body `
            -TimeoutSec 30
    } catch {
        $status = ""
        $responseBody = ""
        try {
            if ($_.Exception.Response) {
                $status = "HTTP " + [int]$_.Exception.Response.StatusCode
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                $reader.Close()
            }
        } catch {
        }

        if ($responseBody) {
            throw "$Path failed $status - $responseBody"
        }
        throw "$Path failed $status - $($_.Exception.Message)"
    }
}

function Write-UpdateHelper {
    param(
        [string]$UpdateUrl,
        [string]$LatestVersion,
        [string]$ExpectedSha256
    )

    if (-not $UpdateUrl) {
        return $null
    }

    $installDir = Split-Path $script:ResolvedLogPath -Parent
    if (-not $installDir) {
        $installDir = "$env:ProgramData\BackupMonitorAgent"
    }
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    $psPath = Join-Path $installDir "AtualizarBackupMonitorAgent.ps1"
    $cmdPath = Join-Path $installDir "AtualizarBackupMonitorAgent.cmd"
    $escapedUrl = $UpdateUrl.Replace("'", "''")
    $escapedSha256 = ([string]$ExpectedSha256).Replace("'", "''").ToLowerInvariant()

    $psContent = @"
param()
`$ErrorActionPreference = "Stop"

function Enable-CompatibleTls {
    try {
        `$protocols = 0
        foreach (`$value in @(3072, 768, 192)) {
            `$protocols = `$protocols -bor `$value
        }
        [Net.ServicePointManager]::SecurityProtocol = [enum]::ToObject([Net.SecurityProtocolType], `$protocols)
        [Net.ServicePointManager]::Expect100Continue = `$false
    } catch {
    }
}

Enable-CompatibleTls

`$installDir = "`$env:ProgramData\BackupMonitorAgent"
`$configPath = Join-Path `$installDir "agent.config.json"
`$logPath = Join-Path `$installDir "update.log"
`$updateUrl = '$escapedUrl'
`$expectedSha256 = '$escapedSha256'
`$tempRoot = Join-Path `$env:TEMP ("BackupMonitorAgentUpdate-" + [guid]::NewGuid().ToString("N"))
`$zipPath = Join-Path `$tempRoot "agent.zip"
`$extractDir = Join-Path `$tempRoot "agent"

function Write-UpdateLog([string]`$message) {
    `$line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), `$message
    Write-Host `$line
    Add-Content -Path `$logPath -Value `$line -Encoding UTF8
}

function Get-FileSha256([string]`$path) {
    `$stream = [System.IO.File]::OpenRead(`$path)
    `$sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ((`$sha.ComputeHash(`$stream) | ForEach-Object { `$_.ToString("x2") }) -join "")
    } finally {
        `$sha.Dispose()
        `$stream.Dispose()
    }
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "Execute este atualizador como Administrador."
}
if (-not (Test-Path `$configPath)) {
    throw "Config atual nao encontrada: `$configPath"
}

New-Item -ItemType Directory -Path `$extractDir -Force | Out-Null
Write-UpdateLog "Baixando Backup Monitor Agent $LatestVersion..."
Invoke-WebRequest `$updateUrl -OutFile `$zipPath
if (-not `$expectedSha256) {
    throw "O monitor nao forneceu o SHA-256 do pacote; atualizacao cancelada."
}
`$actualSha256 = Get-FileSha256 `$zipPath
if (`$actualSha256 -ne `$expectedSha256) {
    throw "SHA-256 invalido. Esperado=`$expectedSha256 recebido=`$actualSha256"
}
Write-UpdateLog "Pacote validado com SHA-256."

Write-UpdateLog "Extraindo pacote..."
try {
    Expand-Archive -Path `$zipPath -DestinationPath `$extractDir -Force
} catch {
    `$shell = New-Object -ComObject Shell.Application
    `$zip = `$shell.NameSpace(`$zipPath)
    `$dest = `$shell.NameSpace(`$extractDir)
    `$dest.CopyHere(`$zip.Items(), 16)
    Start-Sleep -Seconds 2
}

`$installer = Join-Path `$extractDir "install-windows-agent.ps1"
if (-not (Test-Path `$installer)) {
    throw "Instalador nao encontrado no pacote baixado."
}

Write-UpdateLog "Instalando atualizacao preservando a config atual..."
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$installer -ConfigTemplate `$configPath -InstallMode Service -SkipTest -RunNow
if (`$LASTEXITCODE -ne 0) {
    throw "Instalador retornou codigo `$LASTEXITCODE"
}

Write-UpdateLog "Atualizacao finalizada."
"@

    Set-Content -Path $psPath -Value $psContent -Encoding UTF8

    $cmdContent = @"
@echo off
title Atualizar Backup Monitor Agent
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ProgramData%\BackupMonitorAgent\AtualizarBackupMonitorAgent.ps1"
echo.
pause
"@
    Set-Content -Path $cmdPath -Value $cmdContent -Encoding ASCII
    return @{ ps1 = $psPath; cmd = $cmdPath }
}

function Get-LocalAdministratorNames {
    $names = New-Object System.Collections.ArrayList
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $account = $sid.Translate([System.Security.Principal.NTAccount]).Value
        $groupName = $account.Split("\")[-1]
        $group = [ADSI]"WinNT://./$groupName,group"
        foreach ($member in $group.psbase.Invoke("Members")) {
            $name = $member.GetType().InvokeMember("Name", "GetProperty", $null, $member, $null)
            if ($name -and -not $names.Contains([string]$name)) {
                [void]$names.Add([string]$name)
            }
        }
    } catch {
        Write-AgentLog "Could not read local administrators for update notification: $($_.Exception.Message)"
    }

    return @($names)
}

function Get-InteractiveAdminSessionIds {
    $adminNames = @(Get-LocalAdministratorNames | ForEach-Object { $_.ToLowerInvariant() })
    if (@($adminNames).Count -eq 0) {
        return @()
    }

    $sessionIds = New-Object System.Collections.ArrayList
    try {
        $lines = @(quser 2>$null)
        foreach ($line in $lines) {
            $clean = ($line -replace "^\s*>", "").Trim()
            if (-not $clean -or $clean -match "USERNAME|USUARIO|NOME") {
                continue
            }

            $parts = @($clean -split "\s+" | Where-Object { $_ })
            if ($parts.Count -lt 2) {
                continue
            }

            $username = [string]$parts[0]
            $shortName = $username.Split("\")[-1].ToLowerInvariant()
            if ($adminNames -notcontains $shortName -and $adminNames -notcontains $username.ToLowerInvariant()) {
                continue
            }

            $sessionId = $null
            foreach ($part in $parts[1..($parts.Count - 1)]) {
                if ($part -match "^\d+$") {
                    $sessionId = $part
                    break
                }
            }

            if ($sessionId -and -not $sessionIds.Contains([string]$sessionId)) {
                [void]$sessionIds.Add([string]$sessionId)
            }
        }
    } catch {
        Write-AgentLog "Could not enumerate interactive sessions for update notification: $($_.Exception.Message)"
    }

    return @($sessionIds)
}

function Show-UpdateNotificationToAdmins {
    param([string]$Message)

    $sent = 0
    foreach ($sessionId in @(Get-InteractiveAdminSessionIds)) {
        try {
            & msg.exe $sessionId /TIME:300 $Message 2>$null
            if ($LASTEXITCODE -eq 0) {
                $sent += 1
            }
        } catch {
        }
    }

    return $sent
}

function Notify-UpdateAvailable {
    param(
        [hashtable]$Job,
        $Result,
        [hashtable]$State
    )

    if (-not $Result.update_available) {
        return
    }

    $latest = [string]$Result.latest_agent_version
    $updateUrl = [string]$Result.update_url
    $updateSha256 = [string]$Result.update_sha256
    if ($PSVersionTable.PSVersion.Major -le 4 -and $Result.update_url_ws2012) {
        $updateUrl = [string]$Result.update_url_ws2012
        $updateSha256 = [string]$Result.update_sha256_ws2012
    }
    if (-not $latest) {
        return
    }

    $noticeKey = "agent-update-$latest"
    $now = Get-Date
    if (-not $State.ContainsKey("update_notices")) {
        $State.update_notices = @{}
    }

    if ($State.update_notices.ContainsKey($noticeKey)) {
        $last = $null
        if ([datetime]::TryParse([string]$State.update_notices[$noticeKey].notified_at, [ref]$last)) {
            if (($now - $last).TotalHours -lt 6) {
                return
            }
        }
    }

    $helper = Write-UpdateHelper -UpdateUrl $updateUrl -LatestVersion $latest -ExpectedSha256 $updateSha256
    $cmdPath = if ($helper) { [string]$helper.cmd } else { "" }
    $psPath = if ($helper) { [string]$helper.ps1 } else { "" }
    Write-AgentLog "Update available for $($Job.servidor_log): agent $AgentVersion -> $latest. Atualizador: $cmdPath"

    if ($cmdPath) {
        $message = if ($AutoUpdateEnabled) {
            "Backup Monitor Agent: atualizacao automatica $latest sera instalada. Log: $env:ProgramData\BackupMonitorAgent\update.log"
        } else {
            "Backup Monitor Agent: atualizacao $latest disponivel. Execute como Administrador: $cmdPath"
        }
        try {
            $notified = Show-UpdateNotificationToAdmins -Message $message
            if ($notified -gt 0) {
                Write-AgentLog "Update notification shown to $notified administrator session(s)."
            } else {
                Write-AgentLog "No administrator session found for update notification. Atualizador: $cmdPath"
            }
        } catch {
            Write-AgentLog "Update notification to administrators could not be shown: $($_.Exception.Message). Atualizador: $cmdPath"
        }
    }

    $State.update_notices[$noticeKey] = @{
        version = $latest
        notified_at = $now.ToString("yyyy-MM-dd HH:mm:ss")
        update_url = $updateUrl
        update_sha256 = $updateSha256
        updater = $cmdPath
        automatic = $AutoUpdateEnabled
    }
    Save-State -State $State

    if ($AutoUpdateEnabled -and $psPath) {
        try {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
            if (-not $isAdmin) {
                throw "o processo do agent nao esta executando como Administrador/SYSTEM"
            }
            $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$psPath`""
            Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -WindowStyle Hidden
            Write-AgentLog "Automatic update $latest started in a detached process."
        } catch {
            Write-AgentLog "Automatic update could not start: $($_.Exception.Message). Execute manualmente: $cmdPath"
        }
    }
}

function Get-LocalIp {
    try {
        $hostname = [System.Net.Dns]::GetHostName()
        $addresses = [System.Net.Dns]::GetHostAddresses($hostname) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString }

        return ($addresses | Select-Object -First 1)
    } catch {
        return $null
    }
}

function New-AgentJob {
    param(
        [string]$Servidor,
        [string]$Token,
        $Paths,
        $FilePatterns,
        $IncludePatterns,
        $ExcludePatterns,
        [int]$GraceMinutes,
        [int]$RecentHours,
        $ContentPatterns,
        $ExcludeContentPatterns
    )

    $normalizedServidor = Normalize-ServidorLog -Value $Servidor
    if (-not $normalizedServidor) {
        throw "Job sem servidor_log configurado."
    }
    if (-not $Token) {
        throw "Job $normalizedServidor sem api_key configurada."
    }

    $resolvedPaths = Add-DefaultLogPaths -Paths (To-Array -Value $Paths -DefaultValue $DefaultLogPaths)

    return @{
        servidor_log = $normalizedServidor
        api_key = $Token
        log_paths = $resolvedPaths
        patterns = @(To-Array -Value $FilePatterns -DefaultValue $DefaultPatterns)
        include_patterns = @(To-Array -Value $IncludePatterns -DefaultValue @("*"))
        exclude_patterns = @(To-Array -Value $ExcludePatterns -DefaultValue @())
        content_patterns = @(To-Array -Value $ContentPatterns -DefaultValue @())
        exclude_content_patterns = @(To-Array -Value $ExcludeContentPatterns -DefaultValue @())
        email_grace_minutes = $GraceMinutes
        recent_hours_on_start = $RecentHours
    }
}

function Build-Jobs {
    param([object]$Config)

    $jobs = @()
    $globalApiKey = $ApiKey
    if (-not $globalApiKey) {
        $globalApiKey = Get-ConfigValue -Config $Config -Name "api_key" -DefaultValue $null
    }

    $globalServidor = $ServidorLog
    if (-not $globalServidor) {
        $globalServidor = Get-ConfigValue -Config $Config -Name "servidor_log" -DefaultValue $null
    }

    $globalPaths = $LogPaths
    if (-not $globalPaths -or $globalPaths.Count -eq 0) {
        $globalPaths = Get-ConfigValue -Config $Config -Name "log_paths" -DefaultValue $DefaultLogPaths
    }

    $globalPatterns = $Patterns
    if (-not $globalPatterns -or $globalPatterns.Count -eq 0) {
        $globalPatterns = Get-ConfigValue -Config $Config -Name "patterns" -DefaultValue $DefaultPatterns
    }

    $hasConfigJobs = $Config -and ($Config.PSObject.Properties.Name -contains "jobs") -and $Config.jobs

    if ($hasConfigJobs) {
        foreach ($jobConfig in @($Config.jobs)) {
            $jobApiKey = Get-ConfigValue -Config $jobConfig -Name "api_key" -DefaultValue $globalApiKey
            $jobPaths = Get-ConfigValue -Config $jobConfig -Name "log_paths" -DefaultValue $globalPaths
            $jobPatterns = Get-ConfigValue -Config $jobConfig -Name "patterns" -DefaultValue $globalPatterns
            $jobInclude = Get-ConfigValue -Config $jobConfig -Name "include_patterns" -DefaultValue @("*")
            $jobExclude = Get-ConfigValue -Config $jobConfig -Name "exclude_patterns" -DefaultValue @()
            $jobContent = Get-ConfigValue -Config $jobConfig -Name "content_patterns" -DefaultValue @()
            $jobExcludeContent = Get-ConfigValue -Config $jobConfig -Name "exclude_content_patterns" -DefaultValue @()
            $jobGrace = [int](Get-ConfigValue -Config $jobConfig -Name "email_grace_minutes" -DefaultValue $EmailGraceMinutes)
            $jobRecent = [int](Get-ConfigValue -Config $jobConfig -Name "recent_hours_on_start" -DefaultValue $RecentHoursOnStart)

            $jobs += New-AgentJob `
                -Servidor (Get-ConfigValue -Config $jobConfig -Name "servidor_log" -DefaultValue $null) `
                -Token $jobApiKey `
                -Paths $jobPaths `
                -FilePatterns $jobPatterns `
                -IncludePatterns $jobInclude `
                -ExcludePatterns $jobExclude `
                -GraceMinutes $jobGrace `
                -RecentHours $jobRecent `
                -ContentPatterns $jobContent `
                -ExcludeContentPatterns $jobExcludeContent
        }
    } else {
        $jobs += New-AgentJob `
            -Servidor $globalServidor `
            -Token $globalApiKey `
            -Paths $globalPaths `
            -FilePatterns $globalPatterns `
            -IncludePatterns @("*") `
            -ExcludePatterns @() `
            -GraceMinutes $EmailGraceMinutes `
            -RecentHours $RecentHoursOnStart `
            -ContentPatterns @() `
            -ExcludeContentPatterns @()
    }

    return @($jobs)
}

function Test-FileMatch {
    param(
        [System.IO.FileInfo]$File,
        [hashtable]$Job
    )

    $target = "$($File.FullName)|$($File.Name)"
    $included = $false
    foreach ($pattern in $Job.include_patterns) {
        if ($target -like $pattern -or $File.Name -like $pattern) {
            $included = $true
            break
        }
    }

    if (-not $included) {
        return $false
    }

    foreach ($pattern in $Job.exclude_patterns) {
        if ($target -like $pattern -or $File.Name -like $pattern) {
            return $false
        }
    }

    return $true
}

function Normalize-JobToken {
    param([string]$Value)

    if (-not $Value) {
        return ""
    }

    return (($Value.Trim().ToUpperInvariant()) -replace "\s+", "_")
}

function Get-IperiusReportJobNames {
    param([string]$Content)

    $names = New-Object System.Collections.ArrayList
    $patterns = @(
        "(?is)Relat.rio\s+de\s+backup\s*\[([^\]]+)\]",
        "(?is)Relat.rio\s+do\s+Iperius\s+Backup\s+([^<\r\n]+)"
    )

    foreach ($pattern in $patterns) {
        foreach ($match in [regex]::Matches($Content, $pattern)) {
            $name = Normalize-JobToken -Value $match.Groups[1].Value
            if ($name -and -not $names.Contains($name)) {
                [void]$names.Add($name)
            }
        }
    }

    return @($names)
}

function Test-ExactJobNameInContent {
    param(
        [string]$Content,
        [hashtable]$Job
    )

    $jobName = Normalize-JobToken -Value $Job.servidor_log
    if (-not $jobName) {
        return $false
    }

    $reportNames = Get-IperiusReportJobNames -Content $Content
    if (@($reportNames).Count -gt 0) {
        return (@($reportNames) -contains $jobName)
    }

    $escapedUnderscore = [regex]::Escape($jobName)
    $escapedSpace = [regex]::Escape($jobName.Replace("_", " "))
    $patterns = @(
        "(?i)(?<![A-Z0-9_])$escapedUnderscore(?![A-Z0-9_])",
        "(?i)(?<![A-Z0-9_])$escapedSpace(?![A-Z0-9_])"
    )

    foreach ($pattern in $patterns) {
        if ([regex]::IsMatch($Content, $pattern)) {
            return $true
        }
    }

    return $false
}

function Test-ContentMatch {
    param(
        [string]$Content,
        [hashtable]$Job,
        [string]$FileName = ""
    )

    if ($FileName -and ($FileName -ieq "Exceptions.log" -or $FileName -like "tmp_*")) {
        return $false
    }

    if ($Job.content_patterns.Count -gt 0) {
        if (-not (Test-ExactJobNameInContent -Content $Content -Job $Job)) {
            return $false
        }
    }

    foreach ($pattern in $Job.exclude_content_patterns) {
        if ($Content -like $pattern) {
            return $false
        }
    }

    return $true
}

function Send-Heartbeat {
    param(
        [hashtable]$Job,
        [bool]$HasEvidence = $true,
        [hashtable]$State
    )

    try {
        $status = "online"
        $detalhe = "Heartbeat OK"
        if (-not $HasEvidence) {
            $status = "online_no_evidence"
            $detalhe = "Agent online, mas nenhum log local compativel foi encontrado"
        }

        $payload = @{
            servidor_log = $Job.servidor_log
            hostname = [System.Net.Dns]::GetHostName()
            ip_local = Get-LocalIp
            agent_version = $AgentVersion
            status = $status
            detalhe = $detalhe
            started_at = $AgentStartedAt
            metadata = @{
                log_paths = $Job.log_paths
                patterns = $Job.patterns
                include_patterns = $Job.include_patterns
                exclude_patterns = $Job.exclude_patterns
                content_patterns = $Job.content_patterns
                exclude_content_patterns = $Job.exclude_content_patterns
                scan_interval_seconds = $ScanIntervalSeconds
                heartbeat_interval_seconds = $HeartbeatIntervalSeconds
                email_grace_minutes = $Job.email_grace_minutes
                windows_event_monitoring_enabled = $WindowsEventMonitoringEnabled
                auto_update_enabled = $AutoUpdateEnabled
            }
        }

        $result = Invoke-MonitorApi -Path "/api/agent/heartbeat" -Payload $payload -Token $Job.api_key
        Write-AgentLog "Heartbeat sent for $($Job.servidor_log): $($result.status) ($status)"
        if ($result.update_available) {
            Notify-UpdateAvailable -Job $Job -Result $result -State $State
        }
        return $true
    } catch {
        Write-AgentLog "Heartbeat failed for $($Job.servidor_log): $($_.Exception.Message)"
        return $false
    }
}

function Get-WindowsEventData {
    param($Event)

    $values = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($node in @($xml.Event.EventData.Data)) {
            if ($null -eq $node) {
                continue
            }
            $name = [string]$node.GetAttribute("Name")
            if (-not $name) {
                $name = "value$($values.Count + 1)"
            }
            $values[$name] = [string]$node.InnerText
        }
    } catch {
        Write-AgentLog "Could not parse Windows event $($Event.Id)/$($Event.RecordId): $($_.Exception.Message)"
    }
    return $values
}

function Convert-WindowsShutdownEvent {
    param($Event, [bool]$Historical)

    $data = Get-WindowsEventData -Event $Event
    $message = ""
    try { $message = [string]$Event.Message } catch { }
    $eventType = "system_event"
    $initiatedBy = ""
    $processName = ""
    $reasonCode = ""
    $reason = ""
    $comment = ""

    switch ([int]$Event.Id) {
        1074 {
            $shutdownType = [string]$data["param5"]
            $eventType = if ($shutdownType -match "restart|reiniciar") { "restart_planned" } else { "shutdown_planned" }
            $processName = [string]$data["param1"]
            $reason = [string]$data["param3"]
            $reasonCode = [string]$data["param4"]
            $comment = [string]$data["param6"]
            $initiatedBy = [string]$data["param7"]
            if (-not $initiatedBy -and $message -match "(?i)(?:on behalf of user|em nome do usu[aá]rio)\s+(.+?)\s+(?:for reason|pelo seguinte motivo)") {
                $initiatedBy = $Matches[1].Trim()
            }
            if (-not $processName -and $message -match "(?i)(?:the process|o processo)\s+(.+?)\s+(?:has initiated|iniciou)") {
                $processName = $Matches[1].Trim()
            }
        }
        1076 {
            $eventType = "unexpected_shutdown_reason"
            $initiatedBy = [string]$data["param1"]
            $reason = [string]$data["param2"]
            $reasonCode = [string]$data["param3"]
            $comment = [string]$data["param4"]
        }
        6008 { $eventType = "shutdown_unexpected" }
        6006 { $eventType = "event_log_stopped" }
        41 { $eventType = "kernel_power" }
    }

    return @{
        channel = [string]$Event.LogName
        record_id = [string]$Event.RecordId
        event_id = [int]$Event.Id
        provider = [string]$Event.ProviderName
        level = [string]$Event.LevelDisplayName
        event_type = $eventType
        occurred_at = $Event.TimeCreated.ToUniversalTime().ToString("o")
        initiated_by = $initiatedBy
        process_name = $processName
        reason_code = $reasonCode
        reason = $reason
        comment = $comment
        message = $message
        event_data = $data
        is_historical = $Historical
    }
}

function Collect-WindowsShutdownEvents {
    param([hashtable]$State, [int]$RecentHours)

    $wasInitialized = [bool]$State.windows_event_initialized
    $cursor = [long]$State.windows_event_cursor
    $startTime = (Get-Date).AddHours(-1 * [Math]::Max(1, $RecentHours))
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = "System"
            Id = @(41, 1074, 1076, 6006, 6008)
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | Sort-Object RecordId)

        $changed = $false
        foreach ($event in $events) {
            $recordId = [long]$event.RecordId
            if ($wasInitialized -and $recordId -le $cursor) {
                continue
            }
            $key = "System|$recordId"
            if (-not $State.windows_event_pending.ContainsKey($key)) {
                $State.windows_event_pending[$key] = Convert-WindowsShutdownEvent -Event $event -Historical (-not $wasInitialized)
                $changed = $true
            }
            if ($recordId -gt [long]$State.windows_event_cursor) {
                $State.windows_event_cursor = $recordId
                $changed = $true
            }
        }
        if (-not $State.windows_event_initialized) {
            $State.windows_event_initialized = $true
            $changed = $true
        }
        if ($changed) {
            Save-State -State $State
        }
    } catch {
        Write-AgentLog "Windows event collection failed: $($_.Exception.Message)"
    }
}

function Send-WindowsShutdownEvents {
    param([hashtable]$Job, [hashtable]$State)

    $keys = @($State.windows_event_pending.Keys | Select-Object -First 50)
    if ($keys.Count -eq 0) {
        return $true
    }
    $events = @($keys | ForEach-Object { $State.windows_event_pending[$_] })
    $payload = @{
        servidor_log = $Job.servidor_log
        hostname = [System.Net.Dns]::GetHostName()
        agent_version = $AgentVersion
        events = $events
    }
    try {
        $result = Invoke-MonitorApi -Path "/api/agent/windows-events" -Payload $payload -Token $Job.api_key
        foreach ($key in $keys) {
            $State.windows_event_pending.Remove($key)
        }
        Save-State -State $State
        Write-AgentLog "Windows events sent: created=$($result.created), duplicates=$($result.duplicates), rejected=$($result.rejected)"
        return $true
    } catch {
        Write-AgentLog "Windows event send failed, queue preserved: $($_.Exception.Message)"
        return $false
    }
}

function Get-LogFiles {
    param([hashtable]$Job)

    $cutoff = (Get-Date).ToUniversalTime().AddHours(-1 * $Job.recent_hours_on_start)
    $files = @()

    foreach ($path in $Job.log_paths) {
        if (-not (Test-Path $path)) {
            continue
        }

        foreach ($pattern in $Job.patterns) {
            $files += Get-ChildItem -Path $path -Filter $pattern -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTimeUtc -ge $cutoff -and (Test-FileMatch -File $_ -Job $Job) }
        }
    }

    return $files | Sort-Object FullName -Unique
}

function Get-MatchingLogFiles {
    param(
        [hashtable]$Job,
        [switch]$FirstOnly
    )

    $matchedFiles = @()
    foreach ($file in Get-LogFiles -Job $Job) {
        if ($Job.content_patterns.Count -gt 0 -or $Job.exclude_content_patterns.Count -gt 0) {
            try {
                $content = Read-TextFile -Path $file.FullName
                if (-not (Test-ContentMatch -Content $content -Job $Job -FileName $file.Name)) {
                    continue
                }
            } catch {
                Write-AgentLog "Could not inspect content for $($Job.servidor_log): $($file.FullName) - $($_.Exception.Message)"
                continue
            }
        }

        $matchedFiles += $file
        if ($FirstOnly) {
            break
        }
    }

    return @($matchedFiles)
}

function Test-JobHasLocalEvidence {
    param([hashtable]$Job)

    $matches = Get-MatchingLogFiles -Job $Job -FirstOnly
    return (@($matches).Count -gt 0)
}

function Queue-LogFile {
    param(
        [System.IO.FileInfo]$File,
        [hashtable]$Job,
        [hashtable]$Pending
    )

    $key = "$($Job.servidor_log)|$($File.FullName.ToLowerInvariant())"
    if ($Pending.ContainsKey($key)) {
        return
    }

    $due = $File.LastWriteTimeUtc.AddMinutes($Job.email_grace_minutes)
    $Pending[$key] = @{
        path = $File.FullName
        job = $Job
        due_utc = $due
        size = $File.Length
        last_write_utc = $File.LastWriteTimeUtc
    }
}

function Process-Pending {
    param(
        [hashtable]$Pending,
        [hashtable]$State
    )

    $now = (Get-Date).ToUniversalTime()
    $ready = @($Pending.Keys | Where-Object { $Pending[$_].due_utc -le $now })

    foreach ($key in $ready) {
        $item = $Pending[$key]
        $path = $item.path
        $job = $item.job
        $servidor = $job.servidor_log

        try {
            if (-not (Test-Path $path)) {
                $Pending.Remove($key)
                continue
            }

            $file = Get-Item $path
            if ($file.Length -eq 0) {
                $Pending[$key].due_utc = $now.AddMinutes(1)
                continue
            }

            $content = Read-TextFile -Path $path
            if (-not (Test-ContentMatch -Content $content -Job $job -FileName $file.Name)) {
                $Pending.Remove($key)
                continue
            }

            $contentHash = Get-TextSha256 -Text $content
            $stateKey = "$servidor|$contentHash"

            if ($State.sent.ContainsKey($stateKey) -or $State.skipped_by_email.ContainsKey($stateKey)) {
                $Pending.Remove($key)
                continue
            }

            $messageId = "local-$servidor-$contentHash"
            $existsPayload = @{
                servidor_log = $servidor
                conteudo_hash = $contentHash
                message_id = $messageId
            }
            $exists = Invoke-MonitorApi -Path "/api/logs/exists" -Payload $existsPayload -Token $job.api_key

            if ($exists.exists -and ($exists.origens -contains "email")) {
                $State.skipped_by_email[$stateKey] = @{
                    path = $path
                    servidor_log = $servidor
                    checked_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
                Save-State -State $State
                $Pending.Remove($key)
                Write-AgentLog "Skipped for ${servidor}, already received by email: $path"
                continue
            }

            if ($exists.exists) {
                $State.sent[$stateKey] = @{
                    path = $path
                    servidor_log = $servidor
                    status = "already_registered"
                    checked_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
                Save-State -State $State
                $Pending.Remove($key)
                Write-AgentLog "Skipped for ${servidor}, already registered: $path"
                continue
            }

            $payload = @{
                servidor_log = $servidor
                data_backup = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                subject = "Log local - $servidor - $($file.Name)"
                conteudo_raw = $content
                conteudo_hash = $contentHash
                message_id = $messageId
                origem = "agent"
            }

            $result = Invoke-MonitorApi -Path "/api/logs/ingest" -Payload $payload -Token $job.api_key
            $State.sent[$stateKey] = @{
                path = $path
                servidor_log = $servidor
                status = $result.status
                sent_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            if ($State.failures.ContainsKey($stateKey)) {
                $State.failures.Remove($stateKey)
            }
            Save-State -State $State
            $Pending.Remove($key)
            Write-AgentLog "Sent local log for ${servidor}: $path"
        } catch {
            $State.failures[$key] = @{
                path = $path
                servidor_log = $servidor
                error = $_.Exception.Message
                failed_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            Save-State -State $State
            $Pending[$key].due_utc = $now.AddMinutes(2)
            Write-AgentLog "Send failed for ${servidor}, will retry: $path - $($_.Exception.Message)"
        }
    }
}

$config = Load-Config

if (-not $MonitorUrl) {
    $MonitorUrl = Get-ConfigValue -Config $config -Name "monitor_url" -DefaultValue "https://bkp.fpinformatica.com.br"
}
if ($EmailGraceMinutes -lt 0) {
    $EmailGraceMinutes = [int](Get-ConfigValue -Config $config -Name "email_grace_minutes" -DefaultValue 10)
}
if ($ScanIntervalSeconds -lt 0) {
    $ScanIntervalSeconds = [int](Get-ConfigValue -Config $config -Name "scan_interval_seconds" -DefaultValue 30)
}
if ($HeartbeatIntervalSeconds -lt 0) {
    $HeartbeatIntervalSeconds = [int](Get-ConfigValue -Config $config -Name "heartbeat_interval_seconds" -DefaultValue 300)
}
if ($RecentHoursOnStart -lt 0) {
    $RecentHoursOnStart = [int](Get-ConfigValue -Config $config -Name "recent_hours_on_start" -DefaultValue 72)
}
$windowsEventSetting = Get-ConfigValue -Config $config -Name "windows_event_monitoring_enabled" -DefaultValue $true
$WindowsEventMonitoringEnabled = ($windowsEventSetting -eq $true -or [string]$windowsEventSetting -match "^(?i:true|1|yes|sim)$")
$WindowsEventRecentHours = [int](Get-ConfigValue -Config $config -Name "windows_event_recent_hours_on_start" -DefaultValue 168)
$autoUpdateSetting = Get-ConfigValue -Config $config -Name "auto_update_enabled" -DefaultValue $true
$AutoUpdateEnabled = ($autoUpdateSetting -eq $true -or [string]$autoUpdateSetting -match "^(?i:true|1|yes|sim)$")
if (-not $StatePath) {
    $StatePath = Get-ConfigValue -Config $config -Name "state_path" -DefaultValue "$env:ProgramData\BackupMonitorAgent\state.json"
}
if (-not $LogPath) {
    $LogPath = Get-ConfigValue -Config $config -Name "log_path" -DefaultValue "$env:ProgramData\BackupMonitorAgent\agent.log"
}

$script:BaseUrl = Normalize-Url -Url $MonitorUrl
$script:ResolvedLogPath = $LogPath
$jobs = Build-Jobs -Config $config

if (-not $jobs -or $jobs.Count -eq 0) {
    throw "Nenhum job configurado."
}

$state = Load-State
$pending = @{}
$lastHeartbeatUtc = [datetime]::MinValue
$lastNoEvidenceLogUtc = [datetime]::MinValue

Write-AgentLog "Backup Monitor Agent $AgentVersion started at $script:BaseUrl"
Write-AgentLog "Jobs: $((@($jobs) | ForEach-Object { $_.servidor_log }) -join ', ')"

if ($HeartbeatOnly) {
    $ok = $true
    foreach ($job in @($jobs)) {
        $hasEvidence = Test-JobHasLocalEvidence -Job $job
        if (-not (Send-Heartbeat -Job $job -HasEvidence $hasEvidence -State $state)) {
            $ok = $false
        }
    }
    if ($ok) {
        exit 0
    }
    exit 1
}

do {
    $nowUtc = (Get-Date).ToUniversalTime()

    $activeJobs = @()
    foreach ($job in @($jobs)) {
        $matchingFiles = Get-MatchingLogFiles -Job $job
        if (@($matchingFiles).Count -eq 0) {
            continue
        }

        $activeJobs += $job
        foreach ($file in @($matchingFiles)) {
            Queue-LogFile -File $file -Job $job -Pending $pending
        }
    }

    if ($lastHeartbeatUtc -eq [datetime]::MinValue -or ($nowUtc - $lastHeartbeatUtc).TotalSeconds -ge $HeartbeatIntervalSeconds) {
        $allHeartbeatsOk = $true
        $activeJobNames = @{}
        foreach ($job in @($activeJobs)) {
            $activeJobNames[$job.servidor_log] = $true
        }

        foreach ($job in @($jobs)) {
            $hasEvidence = $activeJobNames.ContainsKey($job.servidor_log)
            if (-not (Send-Heartbeat -Job $job -HasEvidence $hasEvidence -State $state)) {
                $allHeartbeatsOk = $false
            }
        }
        if ($allHeartbeatsOk -or @($activeJobs).Count -eq 0) {
            $lastHeartbeatUtc = $nowUtc
        }
    }

    if (@($activeJobs).Count -eq 0 -and ($lastNoEvidenceLogUtc -eq [datetime]::MinValue -or ($nowUtc - $lastNoEvidenceLogUtc).TotalSeconds -ge 300)) {
        Write-AgentLog "No matching local log evidence for configured jobs. Checked jobs: $((@($jobs) | ForEach-Object { $_.servidor_log }) -join ', ')"
        Write-AgentLog "Checked log paths: $((@($jobs) | ForEach-Object { $_.log_paths } | Sort-Object -Unique) -join '; ')"
        $lastNoEvidenceLogUtc = $nowUtc
    }

    Process-Pending -Pending $pending -State $state

    if ($WindowsEventMonitoringEnabled) {
        Collect-WindowsShutdownEvents -State $state -RecentHours $WindowsEventRecentHours
        [void](Send-WindowsShutdownEvents -Job (@($jobs)[0]) -State $state)
    }

    if ($Once) {
        break
    }

    Start-Sleep -Seconds $ScanIntervalSeconds
} while ($true)
