# Mapa do FP Ops (Backup Monitor)

Gerado em 23/10/2026 a partir da cópia viva do servidor `10.11.11.4` (`~/backup-monitor`), sem `data/`, `.env` nem chaves.
Mapa de código completo (grafo): gerado localmente com graphify (`graphify-out/`, fora do git); para refazer veja o fim deste arquivo.

## Em uma frase
Flask + Postgres (3 containers: `web`, `worker`, `postgres`) que recebe e-mails/agentes de backup, monitora firewalls pfSense, links, eventos Windows e tem um helpdesk que conversa com o Ticketz (WhatsApp) e o Zammad.

## Peças

`app/main.py` (101 linhas) só monta o aplicativo: configuração, cabeçalhos de segurança, checagem de sessão/CSRF e registro dos módulos abaixo. Tudo roda em `/app` dentro do container (`COPY app /app`).

| Módulo | O que faz | Linhas |
|---|---|---|
| `login_web.py` | login (limite de sessões simultâneas), logout, favicon | |
| `cadastros.py` | clientes, servidores, agendamentos de backup, busca global, servidores detectados nos logs | 412 |
| `monitoramento.py` | dashboard, backups, disponibilidade/tempo online, histórico, status do sistema, eventos do Windows | 1.086 |
| `admin_web.py` | usuários e sessões, retenção (edição e **resumo em `/admin/retencao`**), chaves de API, Zammad, e-mail | 368 |
| `pacotes_agente.py` | download do pacote/instalador/configuração do agente por cliente | 437 |
| `api_agentes.py` | API dos agentes: ingestão de logs, eventos do Windows, batimento, `/health` | 413 |
| `agentes.py` | regras dos agentes: versão atual, chave de API, recuperação de servidor, hash dos pacotes | 300 |
| `pfsense_web.py` | telas de pfSense: lista, detalhe, links, armazenamento FTP, download de backup | 840 |
| `helpdesk.py` + `templates/helpdesk/` | chamados, contatos, SLA, auditoria, API para o Ticketz | 840 |
| `sessao.py`, `auth.py`, `util.py` | sessão/senha, decoradores de acesso, funções puras de data e texto | |
| `retencao.py` | limpeza automática/manual dos logs do banco | 137 |
| `db.py`, `secret_store.py`, `pfsense_storage.py` | banco (SQLite/Postgres), cifra, envio e limpeza no FTP | |
| `worker/*` | laço de 5 s (a cada 300 s: e-mails IMAP, Zammad, retenção, firewalls, alertas), SSH no pfSense, links, notificações | |
| `agents/*` | agente Windows (PowerShell) e instaladores | |
| `ops/*` | backups do próprio monitor, `deploy.sh`, `rollback.sh` | |

## Fluxo dos backups de firewall (o que mexemos hoje)
1. `run_due_firewalls` (worker) → para cada firewall ativo, se venceu o intervalo de checagem (5 min) → `run_firewall_check`.
2. Conecta por SSH, coleta métricas, lê `config.xml`; se mudou **ou** passou `backup_interval_hours` (24 h) → cifra e grava em `/data/pfsense-backups/<id>/` e registra em `pfsense_backups`.
3. Envia ao FTP (`upload_backup_from_db`) e marca `remote_status`.
4. **Retenção local** (`prune_backups`, por firewall, 30 dias) e **retenção no FTP** (`cleanup_storage`, global, 90 dias, 1x/24 h, só arquivos do monitor em `/ftp/___FIREWALLS`).

## Pontos de melhoria: situação (23/10/2026)

| # | Ponto | Situação |
|---|---|---|
| 1 | `main.py` fazia tudo | **Feito**: 4.245 → 101 linhas; cada área virou um módulo/Blueprint. As rotas estão congeladas em `tests/rotas_esperadas.txt` (97). |
| 2 | Autenticação duplicada | **Feito** (`auth.py`). |
| 3 | Retenção espalhada | **Feito**: teste para cada regra e tela única `/admin/retencao` (logs, backups de firewall no disco e no FTP). |
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
