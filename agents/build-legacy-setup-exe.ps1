param(
    [string]$OutputDir = "$PSScriptRoot\dist",
    [string]$OutputName = "BackupMonitorAgentSetupLegacy2012.exe"
)

$ErrorActionPreference = "Stop"

$iexpress = Get-Command "iexpress.exe" -ErrorAction SilentlyContinue
if (-not $iexpress) {
    throw "iexpress.exe nao encontrado neste Windows."
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$serviceWrapper = Join-Path $PSScriptRoot "BackupMonitorAgentService.exe"
if (-not (Test-Path $serviceWrapper)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build-service-wrapper.ps1") | Out-Null
}

$buildRoot = Join-Path $env:TEMP "BMASetupLegacy2012Build"
$sourceDir = Join-Path $buildRoot "src"
if (Test-Path $buildRoot) {
    Remove-Item -Path $buildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $sourceDir -Force | Out-Null

$files = @(
    "windows-backup-agent.ps1",
    "enable-agent-auto-update.ps1",
    "install-windows-agent.ps1",
    "install-legacy-ws2012.ps1",
    "Instalar-Legacy-WS2012.cmd",
    "test-agent-compatibility.ps1",
    "build-service-wrapper.ps1",
    "BackupMonitorAgentService.exe",
    "agent.config.example.json",
    "agent.config.multi.example.json",
    "README.md"
)

foreach ($file in $files) {
    Copy-Item -Path (Join-Path $PSScriptRoot $file) -Destination (Join-Path $sourceDir $file) -Force
}
Copy-Item -Path (Join-Path $PSScriptRoot "setup-wizard-legacy.ps1") -Destination (Join-Path $sourceDir "setup-wizard.ps1") -Force

$setupCmd = @"
@echo off
call "%~dp0Instalar-Legacy-WS2012.cmd"
"@
$setupCmd | Set-Content -Path (Join-Path $sourceDir "setup.cmd") -Encoding ASCII

$allFiles = Get-ChildItem -Path $sourceDir | Where-Object { -not $_.PSIsContainer } | Sort-Object Name
$sourceList = ""
$stringList = ""
$index = 0
foreach ($file in $allFiles) {
    $sourceList += "%FILE$index%= `r`n"
    $stringList += "FILE$index=`"$($file.Name)`"`r`n"
    $index += 1
}

$buildOutputPath = Join-Path $buildRoot $OutputName
$outputPath = Join-Path $OutputDir $OutputName
$sedPath = Join-Path $buildRoot "backup-monitor-agent-legacy-2012.sed"
$sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$buildOutputPath
FriendlyName=Backup Monitor Agent Legacy 2012 Setup
AppLaunched=setup.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
SourceFiles=SourceFiles
[SourceFiles]
SourceFiles0=$sourceDir
[SourceFiles0]
$sourceList
[Strings]
$stringList
"@
$sed | Set-Content -Path $sedPath -Encoding ASCII

& $iexpress.Source /N $sedPath | Out-Null

if (-not (Test-Path $buildOutputPath)) {
    throw "Falha ao gerar $buildOutputPath"
}

Copy-Item -Path $buildOutputPath -Destination $outputPath -Force

Get-Item $outputPath
