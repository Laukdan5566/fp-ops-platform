param(
    [string]$DefaultInstallDir = "$env:ProgramData\BackupMonitorAgent"
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Test-Admin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator"
    )
}

function Find-Configs {
    $configs = Get-ChildItem -Path $PSScriptRoot -Filter "agent.config*.json" -ErrorAction SilentlyContinue |
        Where-Object { @("agent.config.example.json", "agent.config.multi.example.json") -notcontains $_.Name }
    return @($configs)
}

function Find-ServiceWrapper {
    $candidates = @(
        (Join-Path $PSScriptRoot "BackupMonitorAgentService.exe"),
        (Join-Path $DefaultInstallDir "BackupMonitorAgentService.exe")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return ""
}

if (-not (Test-Admin)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Execute este instalador como Administrador.",
        "Backup Monitor Agent Legacy",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    exit 1
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Backup Monitor Agent Legacy - Windows Server 2012"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(640, 455)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = "Instalar Backup Monitor Agent Legacy"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(20, 18)
$form.Controls.Add($title)

$lblApi = New-Object System.Windows.Forms.Label
$lblApi.Text = "Chave API"
$lblApi.AutoSize = $true
$lblApi.Location = New-Object System.Drawing.Point(20, 70)
$form.Controls.Add($lblApi)

$txtApi = New-Object System.Windows.Forms.TextBox
$txtApi.Location = New-Object System.Drawing.Point(155, 66)
$txtApi.Size = New-Object System.Drawing.Size(430, 24)
$form.Controls.Add($txtApi)

$lblConfig = New-Object System.Windows.Forms.Label
$lblConfig.Text = "Config do cliente"
$lblConfig.AutoSize = $true
$lblConfig.Location = New-Object System.Drawing.Point(20, 110)
$form.Controls.Add($lblConfig)

$cmbConfig = New-Object System.Windows.Forms.ComboBox
$cmbConfig.Location = New-Object System.Drawing.Point(155, 106)
$cmbConfig.Size = New-Object System.Drawing.Size(350, 24)
$cmbConfig.DropDownStyle = "DropDownList"
$form.Controls.Add($cmbConfig)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Procurar"
$btnBrowse.Location = New-Object System.Drawing.Point(515, 104)
$btnBrowse.Size = New-Object System.Drawing.Size(70, 27)
$form.Controls.Add($btnBrowse)

$configs = Find-Configs
foreach ($config in $configs) {
    [void]$cmbConfig.Items.Add($config.FullName)
}
if ($cmbConfig.Items.Count -gt 0) {
    $cmbConfig.SelectedIndex = 0
}

$lblInstallDir = New-Object System.Windows.Forms.Label
$lblInstallDir.Text = "Instalar em"
$lblInstallDir.AutoSize = $true
$lblInstallDir.Location = New-Object System.Drawing.Point(20, 150)
$form.Controls.Add($lblInstallDir)

$txtInstallDir = New-Object System.Windows.Forms.TextBox
$txtInstallDir.Location = New-Object System.Drawing.Point(155, 146)
$txtInstallDir.Size = New-Object System.Drawing.Size(430, 24)
$txtInstallDir.Text = $DefaultInstallDir
$form.Controls.Add($txtInstallDir)

$chkRunNow = New-Object System.Windows.Forms.CheckBox
$chkRunNow.Text = "Iniciar servico apos instalar"
$chkRunNow.Location = New-Object System.Drawing.Point(155, 185)
$chkRunNow.Size = New-Object System.Drawing.Size(260, 24)
$chkRunNow.Checked = $true
$form.Controls.Add($chkRunNow)

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text = "Legacy instala como servico e pula o teste inicial de heartbeat. Depois confira agent.log e service.log."
$lblInfo.ForeColor = [System.Drawing.Color]::DimGray
$lblInfo.AutoSize = $false
$lblInfo.Location = New-Object System.Drawing.Point(155, 220)
$lblInfo.Size = New-Object System.Drawing.Size(430, 45)
$form.Controls.Add($lblInfo)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Location = New-Object System.Drawing.Point(20, 285)
$txtOutput.Size = New-Object System.Drawing.Size(565, 75)
$txtOutput.Multiline = $true
$txtOutput.ReadOnly = $true
$txtOutput.ScrollBars = "Vertical"
$form.Controls.Add($txtOutput)

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text = "Instalar"
$btnInstall.Location = New-Object System.Drawing.Point(405, 375)
$btnInstall.Size = New-Object System.Drawing.Size(85, 30)
$form.Controls.Add($btnInstall)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "Fechar"
$btnClose.Location = New-Object System.Drawing.Point(500, 375)
$btnClose.Size = New-Object System.Drawing.Size(85, 30)
$form.Controls.Add($btnClose)

$btnBrowse.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Config JSON|agent.config*.json|JSON|*.json|Todos|*.*"
    $dialog.InitialDirectory = $PSScriptRoot
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        if (-not $cmbConfig.Items.Contains($dialog.FileName)) {
            [void]$cmbConfig.Items.Add($dialog.FileName)
        }
        $cmbConfig.SelectedItem = $dialog.FileName
    }
})

$btnClose.Add_Click({ $form.Close() })

$btnInstall.Add_Click({
    try {
        $apiKey = $txtApi.Text.Trim()
        if (-not $apiKey) {
            throw "Informe a chave API."
        }
        if (-not $cmbConfig.SelectedItem) {
            throw "Selecione a config do cliente."
        }
        if (-not (Find-ServiceWrapper)) {
            throw "BackupMonitorAgentService.exe nao foi encontrado na pasta do instalador."
        }

        $installer = Join-Path $PSScriptRoot "install-windows-agent.ps1"
        if (-not (Test-Path $installer)) {
            throw "install-windows-agent.ps1 nao encontrado."
        }

        $logFile = Join-Path $env:TEMP "backup-monitor-agent-install-legacy.log"
        $args = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$installer`"",
            "-ApiKey", "`"$apiKey`"",
            "-ConfigTemplate", "`"$($cmbConfig.SelectedItem)`"",
            "-InstallDir", "`"$($txtInstallDir.Text.Trim())`"",
            "-InstallMode", "Service",
            "-LegacyServiceInstall",
            "-SkipTest"
        )
        if ($chkRunNow.Checked) {
            $args += "-RunNow"
        }

        $txtOutput.Text = "Instalando..."
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.FileName = "powershell.exe"
        $process.StartInfo.Arguments = ($args -join " ")
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.CreateNoWindow = $true
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        ($stdout + "`r`n" + $stderr) | Set-Content -Path $logFile -Encoding UTF8

        if ($process.ExitCode -ne 0) {
            throw "Instalador retornou codigo $($process.ExitCode). Log: $logFile`r`n$stderr"
        }

        $txtOutput.Text = "Instalacao concluida.`r`nLog: $logFile"
        [System.Windows.Forms.MessageBox]::Show(
            "Backup Monitor Agent Legacy instalado com sucesso.",
            "Backup Monitor Agent Legacy",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } catch {
        $txtOutput.Text = $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            "Backup Monitor Agent Legacy",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
})

[void]$form.ShowDialog()
