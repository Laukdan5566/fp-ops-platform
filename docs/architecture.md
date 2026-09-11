# Arquitetura proposta

## Domínios

### Monitoramento

Recebe heartbeats, evidências de backup, eventos Windows, estado de pfSense, gateways, interfaces, VPNs e medições de links.

### Incidentes

Transforma eventos técnicos em ocorrências deduplicadas. Um incidente possui início, severidade, estado, origem, equipamento afetado, recuperação e linha do tempo.

### Helpdesk

Gerencia chamados automáticos e manuais, filas, responsáveis, participantes, prioridades, SLA, comentários, anexos, resolução e auditoria.

### Notificações

Entrega mensagens de forma assíncrona por WhatsApp e outros canais. Controla consentimento, destinatários, idempotência, retentativas e histórico.

### Integrações

Expõe uma API versionada e adaptadores independentes. O Ticketz é o primeiro adaptador, mas o helpdesk não deve depender de estruturas internas dele.

## Fluxo Ticketz para FP Ops

1. O usuário autenticado abre o menu da conversa no Ticketz.
2. O Ticketz valida se esse usuário pode acessar o atendimento.
3. O backend do Ticketz envia os dados à API do FP Ops.
4. O FP Ops valida o token, o escopo e a chave de idempotência.
5. O FP Ops cria ou retorna o chamado já associado à conversa.
6. O Ticketz grava uma anotação interna com número e link do chamado.

Identidades distintas devem ser preservadas:

- `requester`: cliente ou contato que solicitou ajuda;
- `opened_by`: usuário autenticado do Ticketz;
- `assignee`: técnico responsável no FP Ops;
- `origin`: integração, monitor ou usuário que originou o chamado.

## API inicial

```text
POST /api/v1/integrations/ticketz/tickets
GET  /api/v1/tickets/{id}
POST /api/v1/tickets/{id}/comments
POST /api/v1/tickets/{id}/assign
POST /api/v1/tickets/{id}/resolve
POST /api/v1/tickets/{id}/reopen
```

Cada criação externa deve possuir uma chave de idempotência. Para o Ticketz, a identidade natural é composta por empresa e ID da conversa.

## Modelo inicial

```text
customers
customer_contacts
assets
monitor_events
incidents
tickets
ticket_comments
ticket_attachments
ticket_participants
ticket_audit_log
integration_credentials
external_ticket_links
notification_rules
notification_outbox
notification_attempts
```

## Segurança da integração

- token de máquina separado da sessão dos usuários;
- escopos mínimos, como `tickets:create`;
- segredo criptografado em repouso;
- TLS obrigatório;
- timestamp e assinatura de requisição quando possível;
- limite de requisições;
- auditoria sem conteúdo sensível;
- permissão específica no Ticketz para abrir chamado;
- restrição única que impeça duplicidade por conversa.

## Migração do Zammad

1. Implementar o helpdesk sem desligar a integração atual.
2. Validar criação manual e automática em ambiente de teste.
3. Preservar referências dos chamados legados.
4. Ativar o FP Ops para um grupo piloto.
5. Desativar novas aberturas no Zammad.
6. Remover configurações e código legado somente após o período de validação.
