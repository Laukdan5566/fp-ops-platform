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
    $configs = Get-ChildItem -Path $PSScriptRoot -Filter "agent.config*.json" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("agent.config.example.json", "agent.config.multi.example.json") }
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
        "Backup Monitor Agent",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    exit 1
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Backup Monitor Agent - Instalador"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(620, 430)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

$font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Font = $font

$title = New-Object System.Windows.Forms.Label
$title.Text = "Instalar Backup Monitor Agent"
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
$txtApi.Location = New-Object System.Drawing.Point(150, 66)
$txtApi.Size = New-Object System.Drawing.Size(420, 24)
$form.Controls.Add($txtApi)

$lblConfig = New-Object System.Windows.Forms.Label
$lblConfig.Text = "Config do cliente"
$lblConfig.AutoSize = $true
$lblConfig.Location = New-Object System.Drawing.Point(20, 110)
$form.Controls.Add($lblConfig)

$cmbConfig = New-Object System.Windows.Forms.ComboBox
$cmbConfig.Location = New-Object System.Drawing.Point(150, 106)
$cmbConfig.Size = New-Object System.Drawing.Size(340, 24)
$cmbConfig.DropDownStyle = "DropDownList"
$form.Controls.Add($cmbConfig)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Procurar"
$btnBrowse.Location = New-Object System.Drawing.Point(500, 104)
$btnBrowse.Size = New-Object System.Drawing.Size(70, 27)
$form.Controls.Add($btnBrowse)

$configs = Find-Configs
foreach ($config in $configs) {
    [void]$cmbConfig.Items.Add($config.FullName)
}
if ($cmbConfig.Items.Count -gt 0) {
    $cmbConfig.SelectedIndex = 0
}

$lblMode = New-Object System.Windows.Forms.Label
$lblMode.Text = "Modo"
$lblMode.AutoSize = $true
$lblMode.Location = New-Object System.Drawing.Point(20, 150)
$form.Controls.Add($lblMode)

$cmbMode = New-Object System.Windows.Forms.ComboBox
$cmbMode.Location = New-Object System.Drawing.Point(150, 146)
$cmbMode.Size = New-Object System.Drawing.Size(180, 24)
$cmbMode.DropDownStyle = "DropDownList"
[void]$cmbMode.Items.Add("Task")
[void]$cmbMode.Items.Add("Service")
$cmbMode.SelectedIndex = 0
$form.Controls.Add($cmbMode)

$lblInstallDir = New-Object System.Windows.Forms.Label
$lblInstallDir.Text = "Instalar em"
$lblInstallDir.AutoSize = $true
$lblInstallDir.Location = New-Object System.Drawing.Point(20, 190)
$form.Controls.Add($lblInstallDir)

$txtInstallDir = New-Object System.Windows.Forms.TextBox
$txtInstallDir.Location = New-Object System.Drawing.Point(150, 186)
$txtInstallDir.Size = New-Object System.Drawing.Size(420, 24)
$txtInstallDir.Text = $DefaultInstallDir
$form.Controls.Add($txtInstallDir)

$chkRunNow = New-Object System.Windows.Forms.CheckBox
$chkRunNow.Text = "Iniciar agora apos instalar"
$chkRunNow.Location = New-Object System.Drawing.Point(150, 225)
$chkRunNow.Size = New-Object System.Drawing.Size(240, 24)
$chkRunNow.Checked = $true
$form.Controls.Add($chkRunNow)

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text = "Modo Service instala um servico automatico do Windows. Use quando o Agendador falhar."
$lblInfo.ForeColor = [System.Drawing.Color]::DimGray
$lblInfo.AutoSize = $false
$lblInfo.Location = New-Object System.Drawing.Point(150, 255)
$lblInfo.Size = New-Object System.Drawing.Size(420, 38)
$form.Controls.Add($lblInfo)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Location = New-Object System.Drawing.Point(20, 305)
$txtOutput.Size = New-Object System.Drawing.Size(550, 45)
$txtOutput.Multiline = $true
$txtOutput.ReadOnly = $true
$txtOutput.ScrollBars = "Vertical"
$form.Controls.Add($txtOutput)

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text = "Instalar"
$btnInstall.Location = New-Object System.Drawing.Point(390, 360)
$btnInstall.Size = New-Object System.Drawing.Size(85, 30)
$form.Controls.Add($btnInstall)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "Fechar"
$btnClose.Location = New-Object System.Drawing.Point(485, 360)
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

        if ($cmbMode.SelectedItem -eq "Service" -and -not (Find-ServiceWrapper)) {
            throw "Modo servico selecionado, mas BackupMonitorAgentService.exe nao foi encontrado."
        }

        $installer = Join-Path $PSScriptRoot "install-windows-agent.ps1"
        if (-not (Test-Path $installer)) {
            throw "install-windows-agent.ps1 nao encontrado."
        }

        $args = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$installer`"",
            "-ApiKey", "`"$apiKey`"",
            "-ConfigTemplate", "`"$($cmbConfig.SelectedItem)`"",
            "-InstallDir", "`"$($txtInstallDir.Text.Trim())`"",
            "-InstallMode", $cmbMode.SelectedItem
        )
        if ($chkRunNow.Checked) {
            $args += "-RunNow"
        }

        $txtOutput.Text = "Instalando..."
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -ne 0) {
            throw "Instalador retornou codigo $($process.ExitCode). Confira agent.log/service.log."
        }

        $txtOutput.Text = "Instalacao concluida."
        [System.Windows.Forms.MessageBox]::Show(
            "Backup Monitor Agent instalado com sucesso.",
            "Backup Monitor Agent",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } catch {
        $txtOutput.Text = $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            "Backup Monitor Agent",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
})

[void]$form.ShowDialog()
