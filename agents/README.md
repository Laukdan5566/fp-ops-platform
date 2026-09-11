# Backup Monitor Agent

Agente leve para rodar no Windows do cliente e enviar logs locais quando o e-mail nao chegar.

Endereco padrao do monitor:

```text
https://bkp.fpinformatica.com.br
```

## Como funciona

1. O script varre as pastas configuradas a cada 30 segundos.
2. Envia heartbeat para `/api/agent/heartbeat` a cada 5 minutos.
3. Quando encontra um log novo, espera `email_grace_minutes` minutos para dar tempo do e-mail chegar.
4. Consulta o monitor pelo endpoint `/api/logs/exists`.
5. Se o mesmo log ja chegou por e-mail, nao envia.
6. Se nao chegou, envia para `/api/logs/ingest` usando a chave API.
7. Guarda estado em `C:\ProgramData\BackupMonitorAgent\state.json` para nao reenviar o mesmo arquivo.

## Instalar em um servidor

1. No monitor, acesse `/api-keys`.
2. Gere uma chave limitada ao `Servidor autorizado`.
3. Copie a pasta `agents` para o servidor Windows.
4. Abra PowerShell como Administrador.
5. Rode:

```powershell
.\install-windows-agent.ps1 `
  -ApiKey "SUA_CHAVE_API" `
  -ServidorLog "CONAUD_SISTEMA" `
  -LogPaths "C:\ProgramData\IperiusBackup\Logs" `
  -RunNow
```

O instalador copia o agente para `C:\ProgramData\BackupMonitorAgent`, cria `agent.config.json` e registra a tarefa agendada `Backup Monitor Agent` para iniciar junto com o Windows.
Durante a instalacao ele tambem testa o heartbeat na hora. Se falhar, confira `C:\ProgramData\BackupMonitorAgent\agent.log`.

## Windows Server 2012

Antes de instalar em Windows Server 2012, rode o diagnostico como Administrador:

```powershell
.\test-agent-compatibility.ps1
```

Se retornar `HTTPS/health: OK`, a comunicacao com o monitor esta funcionando. Se falhar com erro de SSL/TLS ou certificado, atualize o Windows/.NET e os certificados raiz do servidor. O agent força TLS 1.2, mas o Windows 2012 sem atualizacoes pode nao confiar no certificado HTTPS atual.

Para Windows Server 2012, prefira o download `backup-monitor-agent-legacy-ws2012.zip` ou `BackupMonitorAgentSetupLegacy2012.exe`. Esse instalador:

- instala direto como servico;
- usa criacao de servico via `sc.exe`;
- pula o teste inicial de heartbeat para nao deixar a instalacao pela metade quando o HTTPS do servidor antigo estiver instavel;
- grava o resultado em `%TEMP%\backup-monitor-agent-install-legacy.log`.

Se o EXE legacy nao abrir a tela, extraia o ZIP legacy e execute como Administrador:

```text
Instalar-Legacy-WS2012.cmd
```

Esse modo usa console, pede a chave API e mostra qualquer erro na propria janela.

## Instalador com tela

Para o suporte, gere um EXE com interface simples:

```powershell
.\build-setup-exe.ps1
```

O arquivo sai em `dist\BackupMonitorAgentSetup.exe`. Coloque o EXE e o `agent.config.<cliente>.json` na mesma pasta do servidor cliente, execute como Administrador, cole a chave API e clique em instalar. O modo servico ja vai empacotado no instalador.

## Kit de instalacao

O arquivo `backup-monitor-agent.zip` deve ir para o suporte. Ele contem o EXE, os scripts e exemplos. Para instalar em um cliente:

1. Extraia o ZIP em uma pasta.
2. Baixe a config personalizada do cliente no monitor.
3. Coloque `agent.config.<cliente>.json` na mesma pasta extraida.
4. Execute `BackupMonitorAgentSetup.exe` como Administrador.
5. Cole a chave API e instale.

## EXE unico por cliente

No monitor, em `Clientes`, use `Agent EXE` ou `EXE WS2012`. Esse download gera um instalador unico com a config e a chave API do cliente embutidas. O suporte pode executar o arquivo como Administrador e o servidor deve aparecer no dashboard depois do heartbeat.

O EXE unico usa um payload ZIP anexado ao final do instalador. Ao executar, ele extrai os arquivos para `%TEMP%`, copia o agent para `C:\ProgramData\BackupMonitorAgent`, cria o servico e inicia.

Como a chave API vai embutida no EXE, trate esse arquivo como credencial do cliente. Se ele for enviado para o lugar errado, desative a chave criada no menu `Chaves API` e gere outro agent.

## Instalar como servico

Quando o Agendador do Windows nao for confiavel, instale como servico. O kit ja inclui `BackupMonitorAgentService.exe`, entao nao precisa instalar dependencia extra.

```powershell
.\install-windows-agent.ps1 `
  -ApiKey "SUA_CHAVE_API" `
  -ConfigTemplate ".\agent.config.cliente.json" `
  -InstallMode Service `
  -RunNow
```

Para verificar:

```powershell
Get-Service -Name BackupMonitorAgent
Get-Content "C:\ProgramData\BackupMonitorAgent\agent.log" -Tail 50
Get-Content "C:\ProgramData\BackupMonitorAgent\service.log" -Tail 50
```

Para voltar ao Agendador, rode o instalador sem `-InstallMode Service`.

Para um servidor com mais de uma tarefa de backup, instale uma vez e edite `C:\ProgramData\BackupMonitorAgent\agent.config.json` usando a chave `jobs`.

Tambem da para baixar no monitor uma configuracao pronta por cliente em `/api-keys`. Ela ja vem com os `servidor_log` cadastrados daquele cliente e a chave fica para preencher na instalacao.

## Configuracao por arquivo

O agente le `agent.config.json`. Modelo:

```json
{
  "monitor_url": "https://bkp.fpinformatica.com.br",
  "api_key": "SUA_CHAVE_API",
  "servidor_log": "CONAUD_SISTEMA",
  "log_paths": [
    "C:\\ProgramData\\IperiusBackup\\Logs"
  ],
  "patterns": [
    "*.txt",
    "*.log",
    "*.html",
    "*.htm"
  ],
  "email_grace_minutes": 10,
  "scan_interval_seconds": 30,
  "heartbeat_interval_seconds": 300,
  "recent_hours_on_start": 72,
  "state_path": "C:\\ProgramData\\BackupMonitorAgent\\state.json",
  "log_path": "C:\\ProgramData\\BackupMonitorAgent\\agent.log"
}
```

Tambem existe um arquivo pronto para copiar: `agent.config.example.json`.

## Varios backups no mesmo servidor

Use `jobs` quando o mesmo Windows tiver mais de uma tarefa de backup. O agente roda uma vez so e separa os logs por filtro de arquivo ou por texto dentro do log. Quando os arquivos do Iperius tiverem nomes genericos, como `LogFile.htm`, prefira `content_patterns`.

Instalacao usando config pronta do cliente:

```powershell
.\install-windows-agent.ps1 `
  -ApiKey "SUA_CHAVE_API_DO_CLIENTE" `
  -ConfigTemplate ".\agent.config.borplast.json" `
  -RunNow
```

Se a pasta tiver apenas uma config de cliente, como `agent.config.borplast.json`, o instalador detecta sozinho:

```powershell
.\install-windows-agent.ps1 `
  -ApiKey "SUA_CHAVE_API_DO_CLIENTE" `
  -RunNow
```

```json
{
  "monitor_url": "https://bkp.fpinformatica.com.br",
  "api_key": "SUA_CHAVE_API",
  "jobs": [
    {
      "servidor_log": "BORPLAST_DADOS",
      "log_paths": [
        "C:\\ProgramData\\IperiusBackup\\Logs"
      ],
      "include_patterns": [
        "*DADOS*"
      ],
      "content_patterns": [
        "*BORPLAST_DADOS*",
        "*BORPLAST DADOS*"
      ]
    },
    {
      "servidor_log": "BORPLAST_VV",
      "log_paths": [
        "C:\\ProgramData\\IperiusBackup\\Logs"
      ],
      "include_patterns": [
        "*VV*"
      ],
      "content_patterns": [
        "*BORPLAST_VV*",
        "*BORPLAST VV*"
      ]
    }
  ],
  "email_grace_minutes": 10,
  "scan_interval_seconds": 30,
  "heartbeat_interval_seconds": 300,
  "recent_hours_on_start": 72,
  "state_path": "C:\\ProgramData\\BackupMonitorAgent\\state.json",
  "log_path": "C:\\ProgramData\\BackupMonitorAgent\\agent.log"
}
```

Se a chave API global for restrita a um servidor especifico, use uma chave por job:

```json
{
  "servidor_log": "BORPLAST_DADOS",
  "api_key": "CHAVE_DESSE_BACKUP",
  "log_paths": ["C:\\ProgramData\\IperiusBackup\\Logs"],
  "content_patterns": ["*BORPLAST_DADOS*", "*BORPLAST DADOS*"]
}
```

Quando `jobs` existe, o agente ignora `servidor_log` e `log_paths` do topo para envio dos logs, usando os valores de cada job.

## Testar sem instalar

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows-backup-agent.ps1 `
  -MonitorUrl "https://bkp.fpinformatica.com.br" `
  -ApiKey "SUA_CHAVE_API" `
  -ServidorLog "CONAUD_SISTEMA" `
  -LogPaths "C:\ProgramData\IperiusBackup\Logs" `
  -Once
```

Use uma chave API limitada ao servidor do cliente sempre que possivel.

## Diagnostico rapido no servidor

Para testar apenas o heartbeat:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\BackupMonitorAgent\windows-backup-agent.ps1" `
  -ConfigPath "C:\ProgramData\BackupMonitorAgent\agent.config.json" `
  -HeartbeatOnly
```

Para ver o ultimo log do agente:

```powershell
Get-Content "C:\ProgramData\BackupMonitorAgent\agent.log" -Tail 50
```

Para ver se a tarefa esta rodando:

```powershell
Get-ScheduledTask -TaskName "Backup Monitor Agent" | Get-ScheduledTaskInfo
```

## Atualizacao automatica

Agents 1.3.1 ou superiores verificam a versao durante o heartbeat. Quando existe
uma atualizacao, o pacote e baixado por HTTPS, validado pelo SHA-256 informado
pelo monitor e instalado preservando `agent.config.json` e `state.json`.

Para migrar uma instalacao 1.2.x uma unica vez, execute como Administrador:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\enable-agent-auto-update.ps1
```

Depois dessa migracao, `auto_update_enabled` fica habilitado e as proximas
versoes nao exigem acesso manual ao servidor.
