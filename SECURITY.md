# Segurança do FP Ops

## Comunicação de vulnerabilidades

Vulnerabilidades e incidentes não devem ser publicados em issues abertas. Use o canal interno de segurança da FP Informática.

## Regras para segredos

- Nunca versionar senhas, tokens, chaves privadas, cookies ou API keys.
- Usar uma chave mestra externa ao banco e ao repositório para criptografar segredos da aplicação.
- Exibir segredos somente durante a criação; depois, permitir apenas substituir ou revogar.
- Remover credenciais de mensagens de erro, auditoria e logs.
- Usar credenciais distintas por integração e ambiente.
- Rotacionar imediatamente qualquer credencial que tenha sido publicada ou compartilhada de modo inseguro.

## Dados de clientes

Backups, bancos, logs integrais, configurações de firewall e pacotes personalizados de agentes não devem entrar no repositório.

## Processo de publicação

Toda alteração de produção precisa de:

1. backup verificável;
2. plano de rollback;
3. teste em ambiente isolado;
4. revisão de migração de banco;
5. validação de saúde após o deploy.
