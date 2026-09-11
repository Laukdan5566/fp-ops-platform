param(
    [string]$OutputPath = "$PSScriptRoot\BackupMonitorAgentService.exe"
)

$ErrorActionPreference = "Stop"

$source = Join-Path $PSScriptRoot "service-wrapper\BackupMonitorAgentService.cs"
if (-not (Test-Path $source)) {
    throw "Fonte do servico nao encontrado: $source"
}

$candidates = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

$csc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) {
    throw "csc.exe do .NET Framework 4 nao encontrado."
}

& $csc `
    /nologo `
    /target:exe `
    /platform:anycpu `
    /optimize+ `
    /reference:System.ServiceProcess.dll `
    /out:$OutputPath `
    $source

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutputPath)) {
    throw "Falha ao gerar $OutputPath"
}

Get-Item $OutputPath
