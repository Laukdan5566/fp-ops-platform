# Mapa do FP Ops (Backup Monitor)

Gerado em 23/10/2026 a partir da cópia viva do servidor `10.11.11.4` (`~/backup-monitor`), sem `data/`, `.env` nem chaves.
Mapa de código completo (grafo): gerado localmente com graphify (`graphify-out/`, fora do git); para refazer veja o fim deste arquivo.

## Em uma frase
Flask + Postgres (3 containers: `web`, `worker`, `postgres`) que recebe e-mails/agentes de backup, monitora firewalls pfSense, links, eventos Windows e tem um helpdesk que conversa com o Ticketz (WhatsApp) e o Zammad.

## Peças

| Peça | Onde | O que faz | Tamanho |
|---|---|---|---|
| Painel web | `app/main.py` | dashboard, clientes, servidores, uptime, usuários, API dos agentes (pfSense já saiu para `pfsense_web.py`) | ~3.400 linhas |
| Telas de pfSense | `app/pfsense_web.py` (Blueprint) | lista, detalhe, links de internet, armazenamento FTP, download de backup | 820 |
| Acesso | `app/auth.py` | `login_required`, `admin_required`, `support_required` (único para painel e helpdesk) | |
| Utilitários | `app/util.py` | datas, idade, uptime do pfSense (funções puras) | |
| Helpdesk | `app/helpdesk.py`, `app/templates/helpdesk/` | chamados, contatos, SLA, auditoria, API para o Ticketz criar chamado | 858 |
| Banco | `app/db.py` | schema, migrações "se faltar coluna" e camada que faz o Postgres parecer SQLite (`?`, `AUTOINCREMENT`) | 1.131 |
| Segredos | `app/secret_store.py` | Fernet para senhas/chaves e para os backups de firewall | |
| Armazenamento FTP | `app/pfsense_storage.py` | envia backup de firewall ao FTP `10.11.11.2:10050` e limpa o que passa de N dias | 231 |
| Worker | `worker/worker.py` | laço de 5 s; a cada 300 s: lê e-mails IMAP, Zammad, retenção, firewalls, alertas | 553 |
| pfSense | `worker/pfsense_agent.py` | SSH no firewall, métricas, baixa `config.xml`, cifra, grava, limpa local | 595 |
| Links de internet | `worker/pfsense_links.py` | sonda de links/gateways | 296 |
| Alertas | `worker/infrastructure_notifications.py`, `helpdesk_reminders.py` | fila de notificações (WhatsApp/Ticketz) | 309 |
| Zammad | `worker/zammad.py` | cria/atualiza chamados no Zammad | 672 |
| Agente Windows | `agents/windows-backup-agent.ps1` + instaladores `.ps1`/`.exe` | roda nos servidores dos clientes e envia batimento e logs | 1.335 |
| Backup do próprio monitor | `ops/backup-monitor-pg-backup.sh`, `...-db-backup.sh` | dump do Postgres | |

## Fluxo dos backups de firewall (o que mexemos hoje)
1. `run_due_firewalls` (worker) → para cada firewall ativo, se venceu o intervalo de checagem (5 min) → `run_firewall_check`.
2. Conecta por SSH, coleta métricas, lê `config.xml`; se mudou **ou** passou `backup_interval_hours` (24 h) → cifra e grava em `/data/pfsense-backups/<id>/` e registra em `pfsense_backups`.
3. Envia ao FTP (`upload_backup_from_db`) e marca `remote_status`.
4. **Retenção local** (`prune_backups`, por firewall, 30 dias) e **retenção no FTP** (`cleanup_storage`, global, 90 dias, 1x/24 h, só arquivos do monitor em `/ftp/___FIREWALLS`).

## Pontos de melhoria: situação (23/10/2026)

| # | Ponto | Situação |
|---|---|---|
| 1 | `main.py` fazia tudo | **Parcial**: telas de pfSense viraram Blueprint (4.245 → ~3.400 linhas), rotas congeladas em `tests/rotas_esperadas.txt`. Próximos blocos: API dos agentes (`/api/*`, `/health`), chaves de API, usuários/admin, relatórios de uptime. |
| 2 | Autenticação duplicada | **Feito** (`auth.py`). |
| 3 | Retenção espalhada | **Parcial**: teste para cada regra (local, FTP, offline). Falta a tela única de retenção. |
| 4 | Testes soltos | **Feito**: `python tests/run_all.py` + GitHub Actions. |
| 5 | Deploy manual | **Feito**: `ops/deploy.sh` e `ops/rollback.sh`. |
| 6 | Correção sem commit | **Feito**. |
| 7 | Disco | Cópias antigas do banco comprimidas (-190 MB). O grosso do disco do servidor é Docker (imagens/cache) e outros projetos. |
| 8 | FTP compartilhado | Relatório entregue ao Daniel; o monitor só administra `___FIREWALLS`. |
| 9 | Alerta de firewall fora do ar | O 1º aviso já existia; faltava **lembrete**: agora a cada 24 h enquanto durar. |
| 10 | Horário | Banco em UTC por padrão; telas de pfSense/sessões/chaves/Zammad passaram a mostrar Brasília. |
| 11 | `.exe` fora do git | Cópia guardada em `backup-monitor-artefatos/2026-10-23` (com SHA-256). |

## Como atualizar este mapa
```
cd C:\Users\CLIENTE\projetos\backup-monitor
GRAPHIFY_BACKEND=none graphify extract . --code-only
GRAPHIFY_BACKEND=none graphify cluster-only
```
