# Relatório técnico de internet (modelo MK)

O FP Ops passou a gerar sozinho, para cada firewall pfSense com links cadastrados, um relatório como o da MK de 26 a 30/10/2026: resumo executivo com semáforos, números de destaque, capacidade × uso, tráfego por rede/VLAN, estabilidade (linha do tempo, tabela por dia e ocorrências), diagnóstico por gravidade, plano de ação, glossário e metodologia.

## Como funciona

| Etapa | Onde | O que faz |
|---|---|---|
| Coleta | `worker/pfsense_telemetry.py` (a cada 60 min por firewall) | Só leitura por SSH: histórico de tráfego (`rrdtool fetch` nos RRD do próprio firewall), alarmes e trocas de link (`dpinger` e `MONITOR:` nos logs), redes/VLANs e grupos de failover (`config.xml`). Grava em `pfsense_traffic_hourly`, `pfsense_gateway_events`, `pfsense_networks` e `pfsense_firewalls.failover_info`. Erro fica em `pfsense_firewalls.telemetry_error`. |
| Dados | `app/relatorio_dados.py` | Junta tudo do banco (UTC → Brasília): links, speedtests, sondas, tráfego, redes, eventos, quedas de energia, failover. |
| Regras e texto | `app/relatorio_tecnico.py` | Função pura. Limites em `LIMITES`. Gera semáforos, KPIs, ocorrências, diagnósticos e plano de ação. Sem IA: texto de modelos fixos. |
| Gráficos e página | `app/relatorio_graficos.py`, `app/relatorio_pagina.py`, `app/templates/pfsense_tech_report.html` | SVG embutido; CSS de impressão (A4, rodapé com página x de y). |
| Geração sozinha | `app/relatorio_semanal.py` (no worker) | Segunda-feira, depois das 7h (Brasília): relatório da semana anterior de cada firewall ativo com links, guardado em `pfsense_reports`. |
| Telas | `app/pfsense_web.py` | `/pfsense/<id>/relatorio-tecnico` (agora: `?days=7\|14\|30` ou `?inicio=&fim=`), `/pfsense/<id>/relatorios` (lista), `/pfsense/relatorio/<id>` (abre o guardado). Botões na tela do firewall. |

## De onde vem cada coisa

- **Queda de energia**: sem coleta nova. O histórico de verificações já guarda o uptime; uptime que volta atrás + lacuna de pelo menos 30 min antes do boot = firewall e links fora. O texto diz "causa mais provável: falta de energia" (pode ser outra causa).
- **Oscilações**: do log de gateways (alarme → normalizou). Se o log ainda não foi lido, plano B pelas sondas de 5 em 5 min (oscilação curta pode não aparecer; o relatório avisa na metodologia).
- **Failover**: o relatório só diz "funcionando" quando viu a troca no log (`MONITOR: ... omitting from routing group`). Sem essa prova, diz "Configurado".
- **Link principal × preferencial**: o preferencial é o de menor tier do grupo de failover (lido do `config.xml`). O principal "no padrão da empresa" é o campo `pfsense_links.role` (`principal`/`reserva`); sem ele, o preferencial é tratado como principal. Quando o operador marca outro como principal, aparece o diagnóstico "link preferencial fora do padrão".
- **Download de cada rede**: saída da interface interna (o que o firewall entregou para ela).
- **Proteção (bloqueios)**: o coletor lê `/var/db/rrd/<interface>-packets.rrd` só dos links de internet (WAN), coluna `inblock` (+ `inblock6`), em pacotes/s, média por hora → `pfsense_traffic_hourly.in_block_pps`. O relatório soma `pps × 3600` por hora/dia/link e mostra a seção "Proteção: o que o firewall barrou" (só aparece quando o firewall entregou o dado). É contagem de **pacotes** de entrada bloqueados, não de conexões nem de atacantes distintos; o texto do relatório diz isso. Na primeira leitura de bloqueios busca 240 h de histórico; depois revisa as últimas 12 h. Informativo: não gera ação no plano.

## Ajustes (tela)

Na tela do firewall, botão **Ajustes do relatório** (só administrador): horário de expediente, qual link é o principal (padrão da empresa), nome/tipo (cabeada, Wi-Fi, VPN) e inclusão de cada rede, e observações do técnico (aparecem no relatório). Valores inválidos não gravam nada. Vale para os próximos relatórios; os guardados não mudam.

## Ainda NÃO validado num firewall real

Tudo abaixo foi escrito pelo formato documentado do pfSense e testado só com amostras (`tests/test_pfsense_telemetry.py`). Conferir num firewall real (somente leitura) antes de confiar nos números:

1. `ls /var/db/rrd | head -60` e `/usr/local/bin/rrdtool fetch /var/db/rrd/wan-traffic.rrd AVERAGE -r 3600 -s -6h` (colunas `inpass`/`outpass`; nomes dos arquivos por interface: `wan`, `lan`, `opt1`, `ipsec`).
2. `grep -E 'dpinger|MONITOR:' /var/log/gateways.log | tail` e `grep MONITOR /var/log/system.log | tail` (em que arquivo cada linha aparece; formato da data: BSD ou ISO).
3. `date +%z` (fuso do firewall) e o formato dos `<item>` de `gateway_group` no `config.xml` (`NOME|tier|endereço`).
4. `/usr/local/bin/rrdtool fetch /var/db/rrd/wan-packets.rrd AVERAGE -r 3600 -s -6h` (existe o arquivo? a coluna `inblock` tem valores plausíveis?) e comparar com Status > Monitoring > Packets > Block do pfSense.
5. Rodar uma coleta e comparar tráfego e horários de oscilação com o painel do próprio pfSense (Status > Monitoring).

## Próximos passos

- **PDF no servidor** (a imagem não tem biblioteca de PDF): hoje o PDF sai pelo navegador ("Imprimir / salvar PDF"). Ideal: WeasyPrint na imagem, testado em build separado.
- **Envio**: avisar por e-mail/WhatsApp quando o relatório semanal sai, com link.
- **DHCP e Wi-Fi**: ocupação da faixa DHCP e latência de aparelhos no Wi-Fi (o relatório da MK tinha; já há regra em `relatorio_tecnico.py`, falta coletar).
- **Ajustes manuais**: detectar "link preferencial mudou" comparando os backups de `config.xml`.
- **CPU do firewall**: hoje é aproximada pela carga (`load1` ÷ CPUs) das verificações.

## Testes

`python tests/run_all.py` — novos: `test_relatorio_tecnico.py` (gabarito da MK), `test_relatorio_dados.py` (banco → relatório), `test_pfsense_telemetry.py` (coletor com firewall falso), `test_relatorio_semanal.py`, além da tela em `test_pfsense_web_smoke.py`.
