# Verificação sequencial governada do Desktop — DEV

**Estado:** automação proposta em branch, sem PR integrada, disparo real ou instalação física. Regras canônicas verificadas em `chatgpt-operational-rules/main@58dcd4200f412a866278027ba9e433439a03f3b3`, versão 1.6.21. Os comandos do proprietário validam o SHA corrente das regras na própria execução, sem aceitar SHA desatualizado.

## Problema que resolve

Os workflows anteriores de restauração de código isolada e estado DPAPI/SQLite exigiam dois acionamentos manuais independentes. Este coordenador unifica a avaliação em **uma única execução** acionável por comentário autorizado na issue #31 (via conector GitHub do chat), mantendo `workflow_dispatch` apenas como contingência; nenhum comando remoto arbitrário é aceito.

## Contrato do workflow

Arquivo `.github/workflows/desktop-orchestrator-sequential-recovery-readback.yml`:

- Gatilho principal `issue_comment.created` na **issue #31**, somente quando o autor e o ator forem `ericson-j-santos` e o texto corresponder **exatamente** ao contrato fixo; comentários comuns são ignorados antes de provisionar runner. `workflow_dispatch` owner-only permanece como contingência, sem `push`, `schedule` ou execução em PR.
- Admissão hospedada: proprietário `ericson-j-santos`, repo `desktop-pc24x7-runtime` público, `refs/heads/main`, SHA do evento igual à `main` atual e ao SHA exigido no comando, SHA corrente de `chatgpt-operational-rules/main` igual ao informado no comando. Comentário do proprietário é relido por API, rejeitando alteração e replay do mesmo `request_id`. `GITHUB_RUN_ATTEMPT > 1` no gatilho por comentário é rejeitado; para retomada após mudança real de precondição é necessário novo identificador de solicitação.
- Runner físico dedicado `DESKTOP-PDQK954-runtime`; checkout fixo, `SESSION_LAUNCH_OK`, `state_validated=true`, runner preflight e Command Gateway Risk2. Checkout deslocado para worktree exclusivo.
- Estágio A: snapshot de código e restauração em scratch; rejeita se não comprovar `ISOLATED_ROLLBACK_VERIFIED`.
- Estágio B: duas leituras do snapshot protegido DPAPI/SQLite, com replay e manifesto SHA-256 idêntico; rejeita falha.
- Estágio C: sobe e encerra **somente serviço sombra em loopback**; rejeita falha de saúde ou falta de encerramento/limpeza.
- Todos os scripts invocados com nome e `--confirm` fechados. `recovery_allowed=false`, `production_touched=false` em todas as etapas; não executa atualização do orquestrador, bootstrap, reboot, merge ou deploy.
- Resumo da execução registra apenas SHA, `correlation_id` e flags sanitizadas. O snapshot DPAPI e o SQLite ficam somente no Desktop; não há `upload-artifact`.

## Acionamento pelo chat, sem botão Run workflow (após integração autorizada)

1. O responsável solicita no chat: **"Execute o readback governado de backup do TODO-24"**. O chat relê os SHA correntes de `desktop-pc24x7-runtime/main` e `chatgpt-operational-rules/main`, visibilidade do repositório e bloqueios atuais de custo/runner; nenhuma emissão ocorre com SHA desconhecido ou custo incerto.
2. O conector GitHub do usuário registra **um único** comentário na [issue #31](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/issues/31), com este formato literal:

   ```text
   /todo24 verify-backups main=<SHA-40-ATUAL-DA-MAIN> rules=<SHA-40-ATUAL-DAS-REGRAS> request=TODO24-AAAA-MM-DD-01
   ```

   O `request` é identificador estável de uma solicitação, composto de 8 a 48 caracteres `A-Z`, `0-9` e `-`. Em reenvios da **mesma** intenção, preservar o identificador: o controlador rejeita repetição. Usar novo identificador só depois de documentar uma mudança material de precondição.
3. O GitHub `issue_comment.created` aciona a admissão hospedada. O porteiro valida conta, issue/autor/ator/comentário não alterado, comando exato, idempotência, `main`, regras, repositório público (compute R$ 0,00), antes de permitir o runner físico.
4. No `DESKTOP-PDQK954`, Session Launcher e Gateway Risk2 executam **em sequência**: backup de código/restauração isolada → DPAPI/SQLite → replay idempotente → serviço sombra `127.0.0.1`. Se qualquer prova falhar, a cadeia é interrompida.
5. Consultar `run_id`, `job_id`, `GITHUB_SHA`, `owner_comment_id`, `idempotency_key`, SHA de regras, resultado e manifesto nos logs/sumário sanitizados do Actions. O conector GitHub permite readback no chat para atualizar a issue #31 e o TODO-24 sem que o usuário use GUI. A automação não marca TODO como concluído por simples sucesso de CI ou HTTP 200.

O fluxo alternativo `workflow_dispatch` admite somente o proprietário, `main`, `expected_head_sha`, `expected_rules_sha` e a ação fechada `VERIFY-DESKTOP-RECOVERY-SEQUENTIAL-DEV`. Ele **não é necessário** para o caminho de chat.

**Controles negativos:** comentário de terceiro, issue errada, PR, comentário editado, comando inválido, SHA divergente, reexecução da mesma tentativa, duplicação do `request_id`, custo/visibilidade incompatível e políticas/Gateway não admitidos devem bloquear o trabalho físico.


## Aceite / bloqueios

- Pré-PR: validação YAML, positivo/negativos de admission real, sintaxe PowerShell e diff restrito, CI Linux/Windows no HEAD, Validator independente e READY_FOR_PR.
- Pós-merge: um comentário **owner-only** na issue #31 (ou `workflow_dispatch` de contingência), pickup físico no SHA corrente, confirmação de cada prova, readback independente, logs sanitizados e replay sem duplicidade.
- O snapshot isolado e o serviço sombra **não comprovam rollback do serviço vivo**. Instalação de bootstrap e recuperação ativa permanecem fases posteriores, sob autorização e testes próprios.
- O custo de compute de runner padrão em repositório público e runner self-hosted é descrito como gratuito pelo GitHub. Não provisionar runner maior, armazenamento, serviços externos nem aumentar quota/billing. Se custo atual não puder ser comprovado, falhar fechado.
- A validação independente deste workflow não certifica automaticamente `ready_for_work`, Worker Pool nativo nem E2E entre dois hosts.

**Rastreamento:** Desktop Issue #31 / TODO-24; Power BI Issue #27 permanece bloqueada para E2E físico até gates de admissão, SQL e do incremento.
