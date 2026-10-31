# Mapa do FP Ops (Backup Monitor)

Atualizado em 30/10/2026, a partir do código da `main` (`d0b4d92`) e de uma leitura somente-leitura do servidor de produção (`fp@10.11.11.4`, `~/backup-monitor`). Sem `.env`, chaves ou dados de clientes.

## 1. Em uma frase

Flask + Postgres, em 3 containers (`web`, `worker`, `postgres`), que recebe e-mails e agentes de backup, monitora firewalls pfSense e links de internet, gera relatórios técnicos e tem um helpdesk ligado ao Ticketz (WhatsApp) e ao Zammad.

## 2. Visão geral

```
 Agentes Windows (63) ──HTTP/API key──▶ ┌────────────── web (gunicorn, 2 workers, :5050) ──────────────┐
 (PowerShell: heartbeat, logs,          │ main.py monta o app: sessão, CSRF, cabeçalhos, 8 Blueprints │
  eventos do Windows)                   │ login_web · cadastros · monitoramento · admin_web            │
                                        │ pacotes_agente · api_agentes · pfsense_web · helpdesk        │
 Navegador (técnicos) ──sessão+CSRF───▶ └───────────────┬─────────────────────────────────────────────┘
                                                        │ SQL (adaptador SQLite→Postgres em db.py)
 Ticketz ──API v1 (chamados)──────────▶                 ▼
                                        ┌──────────── postgres 16 (42 tabelas, 3,3 GB) ───────────────┐
                                        └───────────────▲─────────────────────────────────────────────┘
                                                        │
 E-mail (IMAP) ──┐                      ┌────────── worker (laço único, serial) ──────────────────────┐
 Zammad ─────────┤◀───────────────────▶ │ a cada 5 s: pedidos de speedtest, lembretes, fila WhatsApp  │
 pfSense (SSH) ──┤                      │ a cada 5 min: IMAP, Zammad, firewalls, links, telemetria,   │
 FTP de backup ──┘                      │   relatório semanal, limpeza FTP, retenção, alertas         │
                                        └──────────────────────────────────────────────────────────────┘
 Cron do servidor: pg_dump a cada 6 h (ops/backup-monitor-pg-backup.sh) · deploy: ops/deploy.sh · volta: ops/rollback.sh
```

## 3. Módulos

| Onde | Para que serve | Linhas |
|---|---|---|
| `app/main.py` | monta o app (config, cabeçalhos de segurança, sessão/CSRF) e registra os Blueprints | 101 |
| `app/db.py` | conexão, adaptador SQLite→Postgres (`_translate_sql`), `init_db()` com as 42 tabelas, 66 migrações `add_column_if_missing` e 38 índices | 1.221 |
| `app/login_web.py`, `sessao.py`, `auth.py` | login, limite de sessões simultâneas, hash scrypt, decoradores de acesso | 79 / 95 / 35 |
| `app/cadastros.py` | clientes, servidores, agendamentos, busca global, servidores detectados | 409 |
| `app/monitoramento.py` | dashboard, backups, disponibilidade e tempo online, histórico, eventos do Windows | 1.086 |
| `app/admin_web.py` | usuários, sessões, retenção, chaves de API, Zammad, e-mail | 403 |
| `app/api_agentes.py`, `agentes.py`, `pacotes_agente.py` | API dos agentes (heartbeat, logs, eventos), chaves, pacote/instalador por cliente | 413 / 300 / 437 |
| `app/pfsense_web.py` (+ `pfsense_storage.py`) | telas de firewall, links, FTP, download de backup, relatórios | 1.001 / 231 |
| `app/relatorio_*.py` + `templates/pfsense_tech_report.html` | relatório técnico de internet (dados, regras, gráficos SVG, página, semanal). Ver `docs/relatorio-tecnico-internet.md` | ~1.200 |
| `app/helpdesk.py` + `templates/helpdesk/` | chamados, contatos, SLA, auditoria, API para o Ticketz | 840 |
| `app/retencao.py` | limpeza dos logs do banco (manual e resumo) | 137 |
| `worker/worker.py` | laço principal; leitura de e-mail (IMAP) e retenção automática | 567 |
| `worker/pfsense_agent.py` | SSH no pfSense: métricas, `config.xml`, backup cifrado, speedtest | 595 |
| `worker/pfsense_links.py` | sondas de 5 min e speedtests por link | 296 |
| `worker/pfsense_telemetry.py` | histórico de tráfego, bloqueios, logs de gateway, redes, failover (só leitura) | 372 |
| `worker/zammad.py`, `ticketz_notifications.py`, `infrastructure_notifications.py`, `helpdesk_reminders.py` | integrações e notificações (fila `notification_outbox`) | 672 / 102 / 344 / 168 |
| `agents/*.ps1` | agente Windows, instaladores, atualização automática | ~3.000 |
| `ops/*` | backup do Postgres, deploy, rollback, migração SQLite→Postgres | — |
| `tests/*` | 20 arquivos, ~1.900 linhas; `python tests/run_all.py`; CI no GitHub Actions | — |

Rotas: 101, congeladas em `tests/rotas_esperadas.txt`. Templates: 33 + 6 do helpdesk.

## 4. Fluxos principais

1. **Backup via agente**: agente → API (chave com hash) → `ingest_log` → `logs_email`/servidores → dashboard.
2. **Backup via e-mail**: worker lê IMAP (3 dias para trás, a cada 5 min) → `processar_mensagem` detecta servidor e status → mesma tabela. Dedupe por `message_id` e hash.
3. **Heartbeat**: agente → `agent_heartbeat` → atualiza o servidor **e grava uma linha em `agent_heartbeat_history`**.
4. **Firewall**: `run_due_firewalls` (5 min) → SSH → métricas + `config.xml` → backup cifrado em `/data/pfsense-backups` → FTP → retenção local (30 d) e FTP (90 d).
5. **Links**: sonda a cada 5 min e speedtest agendado → `pfsense_link_probes` / `pfsense_link_speedtests`.
6. **Telemetria e relatório**: `run_due_telemetry` (60 min) lê RRDs, logs e config → `pfsense_traffic_hourly` (inclui bloqueios), `pfsense_gateway_events`, `pfsense_networks` → relatório da semana toda segunda depois das 7h, guardado em `pfsense_reports`.
7. **Alertas**: mudanças de estado → `process_infrastructure_notifications` → fila → Ticketz (WhatsApp); lembrete de incidente a cada 24 h.
8. **Helpdesk**: Ticketz cria chamado por API (idempotente) → SLA, lembretes internos, comentários, auditoria.

## 5. Estado real hoje (produção, 30/10/2026)

Saudável: 3 containers `healthy`; 0 erros 5xx e 0 tracebacks no web em 24 h; dumps do Postgres a cada 6 h (89 MB, retenção funcionando); IMAP sem erros; relatórios do MK e do FP funcionando com dados reais.

Problemas que a leitura mostrou:

| # | Achado | Evidência |
|---|---|---|
| A | **Uma tabela é 95% do banco**: `agent_heartbeat_history` tem 10 milhões de linhas e 3,1 GB dos 3,3 GB. | 63 agentes geram ~121 mil linhas/dia (~1 batimento a cada 45 s por agente, e o servidor pede 300 s). Com retenção de 90 dias o banco se estabiliza perto de 11 M linhas / ~3,5 GB e cada dump já leva 89 MB. |
| B | **O laço do worker é serial**: um firewall lento atrasa e-mail, alertas, fila de WhatsApp e lembretes. | A busca IMAP deveria rodar a cada 5 min e roda a cada ~6,8 min. O firewall FAE está fora do ar e custa `timed out` (até 150 s na telemetria, mais a checagem) a cada ciclo. |
| C | **Os testes não exercitam o Postgres de produção.** O app é escrito em SQLite e traduzido em tempo de execução; testes e CI rodam em SQLite. | O bug do `LASTVAL()` que abortava transações só apareceu em produção. Há 154 trechos com sintaxe específica de SQLite (`datetime(`, `INSERT OR`, `PRAGMA`...). |
| D | **Sem proteção contra tentativa de senha** no login (sem limite de tentativas nem bloqueio temporário). A porta 5050 escuta em `0.0.0.0`. | `app/login_web.py`: só a mensagem "usuário ou senha inválidos". |
| E | **`init_db()` tem 971 linhas** e roda a cada início: cria tabelas, aplica 66 migrações e índices, tudo misturado, sem versão de esquema. | `app/db.py`. |
| F | **Retenção duplicada**: o mesmo `DELETE` existe em `worker/worker.py` e em `app/retencao.py`. | Mudar uma regra exige lembrar das duas. |
| G | **Erros engolidos e sem log de verdade**: 43 `except Exception`, 29 `print()` e nenhum uso de `logging`. | Falhas viram uma linha solta no `docker logs`; ninguém é avisado se a coleta de um firewall para em silêncio. |
| H | **Arquivos grandes demais**: `monitoramento.py` (1.086) e `pfsense_web.py` (1.001) misturam consulta, regra e tela; funções de 100 a 140 linhas. | `montar_disponibilidade_pfsense` (141), `montar_dados_tempo_online` (125). |
| I | **Documentação desatualizada**: o `README.md` ainda diz que o repositório "contém inicialmente a documentação"; `docs/architecture.md` descreve uma arquitetura proposta, não a real. | — |
| J | **Cobertura desigual**: sem teste direto para `cadastros`, `login_web` e os gráficos; o agente PowerShell (1.335 linhas) não tem teste automático. | `tests/`. |
| K | **Implantação dependente de pessoa**: deploy manual via VPN; senhas em texto puro em `/opt/fp-comercial` (outro projeto, mesma máquina). | memória do projeto. |
| L | **Firewall FAE offline desde setembro** continua ativo e gera erro todo ciclo. | `pfsense_firewalls.id=3`. |

## 6. Plano para ficar 100%

Ordem sugerida: primeiro o que protege e estabiliza, depois o que facilita mudar.

**Andamento (30/10/2026):** fase 1 feita e em produção, exceto a porta 5050 (precisa regra de firewall), o backoff de firewall com erro (as tarefas separadas já isolam o problema) e a decisão sobre o FAE. Fase 2 feita (PR #10): a suíte roda também em Postgres no CI, `/status` mostra tarefas e coleta dos firewalls com o que está atrasado, migrações numeradas (`MIGRACOES` em `app/db.py`; o `init_db()` antigo continua como base, não foi reescrito), retenção única e `print` do worker virou `logging`. Faltam as fases 3 e 4. Alerta ativo quando uma coleta atrasa (hoje só aparece na tela) ficou para depois.

**Fase 1 — Estabilidade (poucos dias, baixo risco)**
1. **Heartbeat enxuto (A)**: gravar histórico só quando o estado muda ou no máximo 1 por 5 min por agente. Reduz o banco de 3,3 GB para algumas centenas de MB e o dump de 89 MB para poucos MB. Exige backup antes de compactar o histórico antigo.
2. **Worker em tarefas independentes (B)**: cada trabalho (IMAP, firewalls, links, telemetria, notificações) com seu horário e tempo máximo; firewall com erro entra em espera crescente (backoff) em vez de travar tudo.
3. **Login protegido (D)**: limite de tentativas por usuário e por IP com bloqueio temporário, registro das falhas e porta 5050 só na rede interna/atrás do proxy.
4. **FAE (L)**: decidir se desativa até voltar.

**Fase 2 — Confiança no que roda (1 a 2 semanas)**
5. **Testar no Postgres de verdade (C)**: subir um Postgres no CI e rodar a suíte nos dois bancos. É o que mais evita surpresa em produção.
6. **Logging e alerta de falha silenciosa (G)**: trocar `print` por `logging` com nível e contexto; painel de saúde com a última coleta bem-sucedida de cada firewall/job e aviso quando passar do esperado.
7. **Esquema com versão (E)**: trocar o `init_db()` gigante por migrações numeradas (tabela `schema_version`), cada uma aplicada uma vez.
8. **Uma só regra de retenção (F)**: o worker chama `app/retencao.py`.

**Fase 3 — Código fácil de mudar**
9. Quebrar `monitoramento.py` e `pfsense_web.py` em dados / regra / rota, como já foi feito no relatório técnico (funções puras testadas) (H).
10. Testes para `cadastros`, `login_web` e um teste de fumaça do agente PowerShell (J).
11. Reescrever `README.md` e `docs/architecture.md` para o que existe (I) e manter este mapa.

**Fase 4 — Produto**
12. Relatório técnico: PDF no servidor, aviso por e-mail/WhatsApp quando o semanal sai, DHCP e Wi-Fi, ignorar links offline.
13. Deploy com um comando a partir do GitHub e aviso de saúde pós-deploy.

## 7. Como testar e publicar hoje

```
python tests/run_all.py            # 20 arquivos, um processo cada, SQLite temporário
ops/deploy.sh main                 # no servidor, em ~/backup-monitor (guarda :rollback das imagens)
ops/rollback.sh                    # volta às imagens anteriores
```

Fluxo: branch → PR → CI → merge → deploy. As rotas congeladas em `tests/rotas_esperadas.txt` precisam ser atualizadas quando uma rota nova é criada.
