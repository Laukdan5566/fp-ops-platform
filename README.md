# FP Ops

Plataforma própria da FP Informática para monitoramento, backups, infraestrutura e helpdesk.

## Visão do produto

O FP Ops reúne em um único ambiente:

- monitoramento de backups e disponibilidade;
- agentes Windows com atualização segura;
- monitoramento e backup de pfSense;
- acompanhamento de links de internet;
- eventos e incidentes;
- helpdesk próprio;
- notificações por WhatsApp através do Ticketz;
- clientes, contatos, ativos, SLA e auditoria.

## Integração com o Ticketz

O Ticketz continuará sendo o canal de atendimento e WhatsApp. A gestão dos chamados ficará no FP Ops.

O atendente autenticado no Ticketz poderá abrir um chamado no FP Ops a partir da conversa. O chamado registrará separadamente:

- o cliente ou contato solicitante;
- o usuário do Ticketz que abriu o chamado;
- a conversa de origem;
- o responsável atual no helpdesk;
- todas as mudanças e notificações.

## Estado do repositório

Este repositório contém inicialmente a documentação e as proteções para receber uma cópia sanitizada da aplicação atual. A importação do código de produção só deve ocorrer depois de:

1. obter uma cópia atual;
2. remover dados e segredos;
3. validar o inventário de arquivos;
4. criar um backup e plano de rollback;
5. executar os testes fora de produção.

Consulte [docs/architecture.md](docs/architecture.md) para a arquitetura proposta.

## Segurança

Credenciais, tokens, bancos, arquivos de clientes, backups e configurações de produção não pertencem ao Git. Consulte [SECURITY.md](SECURITY.md).
