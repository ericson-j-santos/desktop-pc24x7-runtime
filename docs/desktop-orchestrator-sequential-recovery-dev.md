# Verificação sequencial governada do Desktop — DEV

**Estado:** código preparado em branch; sem execução física ou instalação. Regras canônicas `chatgpt-operational-rules/main@86abe65b22781c2f608a7d7286ce3a28cd48aaaf`, versão 1.6.20.

## Problema que resolve

Os workflows anteriores de restauração de código isolada e estado DPAPI/SQLite exigiam dois acionamentos manuais independentes. Este coordenador unifica a avaliação em **um único** `workflow_dispatch` do proprietário, sem disponibilizar execução remota arbitrária.

## Contrato do workflow

Arquivo `.github/workflows/desktop-orchestrator-sequential-recovery-readback.yml`:

- Somente `workflow_dispatch`; não atende `push`, `schedule`, `issue_comment`, PR nem texto de issue.
- Admissão hospedada: proprietário `ericson-j-santos`, repo `desktop-pc24x7-runtime` público, `refs/heads/main`, SHA do evento igual a `expected_head_sha` e à `main` atual, SHA canônico de regras igual a `expected_rules_sha`.
- Runner físico dedicado `DESKTOP-PDQK954-runtime`; checkout fixo, `SESSION_LAUNCH_OK`, `state_validated=true`, runner preflight e Command Gateway Risk2. Checkout deslocado para worktree exclusivo.
- Estágio A: snapshot de código e restauração em scratch; rejeita se não comprovar `ISOLATED_ROLLBACK_VERIFIED`.
- Estágio B: duas leituras do snapshot protegido DPAPI/SQLite, com replay e manifesto SHA-256 idêntico; rejeita falha.
- Estágio C: sobe e encerra **somente serviço sombra em loopback**; rejeita falha de saúde ou falta de encerramento/limpeza.
- Todos os scripts invocados com nome e `--confirm` fechados. `recovery_allowed=false`, `production_touched=false` em todas as etapas; não executa atualização do orquestrador, bootstrap, reboot, merge ou deploy.
- Resumo da execução registra apenas SHA, `correlation_id` e flags sanitizadas. O snapshot DPAPI e o SQLite ficam somente no Desktop; não há `upload-artifact`.

## Como acionar (apenas depois da integração autorizada)

1. Abrir GitHub Actions do repositório `ericson-j-santos/desktop-pc24x7-runtime`.
2. Selecionar `Desktop Orchestrator Sequential Recovery Readback DEV` > `Run workflow` > `main`.
3. Preencher `expected_head_sha` com SHA **atual** da `main`, `expected_rules_sha` com SHA **atual** de `chatgpt-operational-rules/main` e escolher `VERIFY-DESKTOP-RECOVERY-SEQUENTIAL-DEV`.
4. Executar uma vez, conferir contrato de admissão e resultado físico no mesmo `GITHUB_SHA`. Releitura independente do resumo e dos logs pela API GitHub.
5. Se falhar, registrar o estágio e a causa; **não tentar o próximo** ou repetir sem alterar a pré-condição.

## Aceite / bloqueios

- Pré-PR: validação YAML, positivo/negativos de admission real, sintaxe PowerShell e diff restrito, CI Linux/Windows no HEAD, Validator independente e READY_FOR_PR.
- Pós-merge: um `workflow_dispatch` owner-only no merge SHA, pickup físico certo, confirmação de todas as etapas, leitura independente/replay.
- O snapshot isolado e o serviço sombra **não comprovam rollback do serviço vivo**. Instalação de bootstrap e recuperação ativa permanecem fases posteriores, sob autorização e testes próprios.
- O custo de compute de runner padrão em repositório público e runner self-hosted é descrito como gratuito pelo GitHub. Não provisionar runner maior, armazenamento, serviços externos nem aumentar quota/billing. Se custo atual não puder ser comprovado, falhar fechado.
- A validação independente deste workflow não certifica automaticamente `ready_for_work`, Worker Pool nativo nem E2E entre dois hosts.

**Rastreamento:** Desktop Issue #31 / TODO-24; Power BI Issue #27 permanece bloqueada para E2E físico até gates de admissão, SQL e do incremento.
