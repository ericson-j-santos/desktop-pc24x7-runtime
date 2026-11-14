# Ponte API governada — inventário Lenovo (Issue #151)

**Data-base:** 14/11/2026. **Escopo:** somente ericson-j-santos/desktop-pc24x7-runtime, main, lenovo-installed-inventory-readonly.yml, DEV.

## Decisão de arquitetura

O workflow existente exige que GitHub actor e triggering_actor sejam ericson-j-santos. Um token de INSTALAÇÃO da GitHub App atuaria como bot e seria recusado. Portanto, esta ponte exige token TEMPORÁRIO de USUÁRIO da GitHub App, obtido via autorização OAuth do proprietário, mantendo a identidade e os gates atuais. **O workflow não foi alterado.**

GitHub App, restrita a um único repositório:
- Metadata: read (implícito);
- Contents: read;
- Actions: write;
- Variables: write;
- Administration, Secrets, Contents write, Deployments e Issues write: não conceder.

O token de usuário expira tipicamente em oito horas. O serviço autenticador externo deve cuidar da renovação e rotacionar o refresh token em armazenamento seguro, nunca em código, issues, logs ou artefatos.

## Contrato do script

Arquivo: scripts/lenovo_inventory_api_bridge.py. Dependência usada no CI: cryptography.

Preflight é somente leitura: valida conta autorizada, repositório público, SHA exato da main e um único run de CI push no SHA, com os jobs Windows e Linux concluídos com testes aprovados.

Dispatch exige, adicionalmente:
1. Ticket assinado com Ed25519 por um autorizador externo autenticado. O ticket tem validade máxima de dez minutos, SHA/usuário/escopo fixos, chave de idempotência e atestado de custo zero com referência de evidência.
2. A chave PRIVADA de assinatura nunca deve ficar no host da ponte. O host usa somente chave pública em REQSYS_BRIDGE_APPROVER_PUBLIC_KEY (hex). O autorizador deve comprovar a decisão humana atual e a certificação independente de custo; texto de issue, chat copiado e booleano não são prova.
3. Token temporário de usuário GitHub App em REQSYS_GITHUB_APP_USER_TOKEN, não token de instalação nem PAT permanente.
4. Arquivo SQLite protegido, persistente e exclusivo de UM executor. Reserva com BEGIN IMMEDIATE e chave única antes de qualquer alteração. Em resultado incerto, o replay é bloqueado; não apagar o estado.
5. PATCH apenas da variável REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA, GET de confirmação, nova comparação da main e POST apenas de lenovo-installed-inventory-readonly.yml com inputs fixos, ref main e return_run_details=true.
6. Validação do workflow_run_id e URL; persistir recibo. A mesma chave retorna o mesmo run_id sem novo POST.

Status retorna metadados de execução e runner, mas **nunca** declara inventário físico provado: faltam recibo autenticado do Command Gateway, SESSION_LAUNCH_OK, SHA instalado e digests verificados de forma independente.

A ponte não altera o PC, não atualiza software, não concede permissão, não faz merge, deploy, limpeza de segredos nem inicia tarefa sem ticket.

## Comandos de referência (NÃO executar antes de concluir a instalação e a autorização)

    python scripts/lenovo_inventory_api_bridge.py preflight --sha <SHA-exato>

    python scripts/lenovo_inventory_api_bridge.py dispatch \
      --sha <SHA-exato> \
      --ticket <arquivo-ticket-assinado> \
      --database <pasta-duravel-protegida>/state.sqlite

    python scripts/lenovo_inventory_api_bridge.py status --sha <SHA-exato> --run-id <ID>

Credenciais somente por variáveis de ambiente carregadas de um cofre seguro, sem digitá-las no chat ou nos comandos.

## Pendências antes da operação

- Os componentes nativos de Device Flow e emissão condicionada de ticket Ed25519 agora possuem código e testes isolados, mas NÃO estão instalados ou habilitados. A fonte autenticada de decisão do proprietário, a atestação independente de custo, o cofre do assinador e o OAuth real ainda não foram qualificados. Configuração de App, credenciais, armazenamento e deploy exigem autorização específica e preflight próprio.
- Custo incremental máximo R$ 0,00. Repositórios públicos têm runners padrão gratuitos conforme documentação GitHub, mas a prova de custo zero aplicável ao DISPATCH, incluindo Billing/Budgets/hard stop quando exigido, é responsabilidade do autorizador independente; não assumir autorização pelo simples fato de o SHA estar no input.
- O TODO Global não pode ser gravado por esta App sem permissão adicional: resultado deve ser passado ao consumidor governado já autorizado; confirmar readback do TODO, não inferir pela aceitação de evento. Até integração, sincronização pendente.
- SQLite de um único host não oferece failover físico entre máquinas; não ativar dois executores até existir reserva central atômica e controle de posse.
- Execução real no DESKTOP-RP23OGS requer autorização própria e gates de identidade, runner, sessão, Gateway, host e prova física.

## Validação

A suíte tests/test_lenovo_inventory_api_bridge.py cobre ticket válido/adulterado/vencido, login/SHA/CI, rejeição de falhas, mudança de main, readback de variável, envio único, replay, resultado HTTP incerto, idempotência e distinção entre API e prova física. Teste isolado não substitui E2E no host.

Fontes oficiais:
- https://docs.github.com/en/rest/actions/workflows
- https://docs.github.com/en/rest/actions/variables
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
- https://docs.github.com/en/actions/concepts/billing-and-usage

## Etapa opcional preparada — Device Flow e ticket condicional (não operacional)

- `scripts/lenovo_bridge_device_oauth.py`: autenticação nativa por Device Flow para GitHub App autorizada, exige terminal interativo e consentimento oficial em `https://github.com/login/device`. Mantém o token `ghu_` somente em memória durante a chamada da ponte; verifica usuário, `app_id`, instalação única, `repository_selection=selected`, permissões exatas e apenas este repositório. Não cria App, não gera token sozinho e não altera direitos. Token de renovação descartado; a automação contínua exigirá um cofre externo autorizado e rotação separada. Não inserir códigos/tokens em chat ou logs.
- `scripts/lenovo_bridge_ticket_issuer.py`: função pura `issue_ticket` recebe **duas** evidências assinadas e válidas, de emissores independentes (autorização do proprietário e custo incremental R$ 0,00). Exige vínculo idempotente ao mesmo SHA, tarefa e pedido; recusa assinaturas falsas, divergência e vencimento. A chave privada é fornecida por serviço seguro EXTERNO e não fica no host da ponte. Esta função não implementa nem finge a existência dos dois emissores externos.
- Sem App instalada com consentimento, sem atestadores/autoridades externas reais, sem cofre protegido e sem confirmação de custo e runner, o fluxo real continua **BLOQUEADO**.
- Apenas após autorização: uso interativo de preflight somente leitura via `python scripts/lenovo_bridge_device_oauth.py preflight --sha <SHA-atual> --client-id <client-id-da-App> --app-id <app-id-da-App>`. Os argumentos são identificadores não secretos; nunca passar token em linha de comando.
- Um ticket real não pode ser produzido por parâmetro `--approved=true`, issue, chat ou referência de custo desacompanhada das assinaturas e comprovação independente.
- A ponte segue com SQLite de um único escritor. Failover entre PCs depende do Worker Pool com autoridade central, lease e checkpoint; os componentes aqui não implementam a operação física.

**Validação desta etapa:** testes isolados positivos e negativos em Python; não é OAuth real nem E2E físico.
