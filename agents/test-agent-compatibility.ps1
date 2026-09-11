param(
    [string]$MonitorUrl = "https://bkp.fpinformatica.com.br"
)

$ErrorActionPreference = "Continue"

function Enable-CompatibleTls {
    try {
        $protocols = 0
        foreach ($value in @(3072, 768, 192)) {
            $protocols = $protocols -bor $value
        }
        [Net.ServicePointManager]::SecurityProtocol = [enum]::ToObject([Net.SecurityProtocolType], $protocols)
        [Net.ServicePointManager]::Expect100Continue = $false
    } catch {
        Write-Host "Falha ao configurar TLS: $($_.Exception.Message)"
    }
}

Enable-CompatibleTls

Write-Host "Backup Monitor Agent - diagnostico"
Write-Host "Windows: $([Environment]::OSVersion.VersionString)"
Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
Write-Host ".NET Runtime: $([Environment]::Version)"
Write-Host "TLS configurado: $([Net.ServicePointManager]::SecurityProtocol)"
Write-Host ""

try {
    $response = Invoke-RestMethod `
        -Uri "$($MonitorUrl.TrimEnd('/'))/health" `
        -Method Get `
        -TimeoutSec 30

    Write-Host "HTTPS/health: OK"
    $response | ConvertTo-Json -Depth 5
    exit 0
} catch {
    Write-Host "HTTPS/health: FALHOU"
    Write-Host $_.Exception.Message
    if ($_.Exception.InnerException) {
        Write-Host $_.Exception.InnerException.Message
    }
    exit 1
}
