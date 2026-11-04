# Runtime #134 — admissão do E2E físico da sonda PostgreSQL 15/main

**Estado desta versão:** preparado no código, **não executado**, sem autorização de merge/deploy/alteração de DB. Esta documentação não substitui `SESSION_LAUNCH_OK`, `state_validated=true`, lease/worktree exclusivo e readback independente.

## Escopo e precondições (falha fechada)

- Issue de feature [Runtime #134](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/issues/134), vinculada à #123 e ao ReqSys #3126. Sem substituição do E2E de DB, backup, restauração e publicador.
- O fluxo `.github/workflows/dedicated-runtime-runner-e2e.yml` só oferece a opção `native-wsl-postgres-cluster-readonly` **depois que a revisão/integração autorizada tiver incluído esse código na `main` e a CI da própria `main` no mesmo SHA estiver verde**. Uma PR draft com CI verde **não permite** despachar o workflow físico nesse SHA: o gate exige `refs/heads/main` e `inventory_source_sha == github.sha`.
- Ação do proprietário autorizada especificamente para um diagnóstico somente leitura, custo incremental comprovado R$0, sem Docker e sem credenciais. Não aceitar comando/host/SQL customizado, nem permitir mais de uma tentativa por `run_id` (workflow exige `GITHUB_RUN_ATTEMPT=1`).
- Runner `DESKTOP-PDQK954-runtime`/ID 2, host `DESKTOP-PDQK954`, único elegível e comprovadamente online/idle; revalidar registro e sessão no momento da operação. Falhar caso haja disputa, alteração da `main`, `rules_sha`, isolamento/cota indefinidos ou status de CI insuficiente.

## Acionamento governado (somente após gates)

No workflow **Dedicated Runtime Runner E2E**, selecionar branch **main** e preencher os inputs fixos:

| Input | Valor exigido |
| --- | --- |
| `diagnostic` | `native-wsl-postgres-cluster-readonly` |
| `inventory_source_sha` | SHA completo e atual da `main`, validado pela API na hora |
| `lenovo_control_plane_pickup` | `false` |
| `orchestrator_source_sha` | vazio |

**Não usar o workflow antigo nem `workflow_dispatch` em branch de PR para contornar o bloqueio.** Se o comando de despacho oficial não estiver disponível no conector, cabe ao proprietário executar a etapa no GitHub; não usar endpoint alternativo, GUI automatizada ou terminal irrestrito.

A cadeia já existente impõe: admissão por issue/repositório/autor/ref/tentativa, CI Windows/Linux de `main` verificada, rules SHA fixado, TTL de pickup até 300 s, runner exato, Session Launcher, preflight de versão e Command Gateway. O passo de sonda executa exclusivamente `python -B scripts/native_wsl_pg_cluster_probe.py` por Gateway `--risk 1`, `--expected-head` do checkout, sem aceitar comandos como inputs. A sonda faz `wsl.exe --exec /usr/bin/pg_lsclusters -h` e `wsl.exe --exec /usr/bin/pg_isready -h 127.0.0.1 -p 5432 -t 3` com retorno sanitizado.

## Efeito real e readback independente

Após a execução, um **Validator separado** deve reler pelo GitHub as informações do **run/job reais**, inclusive `run_id`, `run_attempt=1`, `runner_id=2`, `runner_name`, commit `head_sha`, regras, steps e os registros sanitizados. Confirmar que o JSON de saída corresponde ao contrato `native-wsl-pg-cluster-probe-v1`, `source_sha` e `rules_sha` esperados, `host_alias=authorized-primary`, `read_only=true`, e que todos os flags `database_identity_verified`, `database_target_qualified`, `network_isolation_verified`, `backup_restore_verified`, `ready_for_installation`, `configuration_changed`, `credentials_read`, `database_contents_read` e `cause_proven` permanecem **false**.

Um `cluster_ready=true` **não comprova identidade do banco ReqSys nem segurança do socket**; `pg_isready` pode responder por outro processo. Caso o binário não exista, a saída tenha esquema inválido ou um gate falhe, registrar `blocked` e parar. Não converter falha de infraestrutura em sucesso nem redisparar o mesmo pedido sem alteração da precondição e novo aceite.

Registrar no TODO Global e Issue #134: SHA, host, run_id/job_id, correlation_id, checks, classificação do resultado, bloqueio e próximo responsável; fazer readback de persistência. Não registrar caminhos de dados reais, segredos, SQL, tokens ou logs WSL crus. Reconciliar a Issue #123 apenas com o **resultado observado**, não declarar implantação pronta.

## Segurança e rollback

Este diagnóstico não deve modificar o serviço. Se um gate reprovar, não for comprovado ou houver efeitos imprevistos, interromper a coleta, preservar evidências mínimas e escalar à Engenharia Runtime; **não tentar reiniciar PostgreSQL, reiniciar WSL, alterar firewall, instalar pacotes nem compensar por GUI**. Corrigir a causa na mesma PR de integração, testar e somente então repetir mediante nova condição autorizada.

`correlation_id=reqsys-sdd-pilot-3126-20261103` · `idempotency_key=runtime-pg-cluster-readonly-feature-20261104`.
