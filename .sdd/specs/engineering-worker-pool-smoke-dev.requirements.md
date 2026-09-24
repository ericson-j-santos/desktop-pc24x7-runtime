# Smoke DEV do Engineering Worker Pool no Desktop PC24x7

## Objetivo

Executar no runner dedicado `DESKTOP-PDQK954-runtime` o harness standalone do
`ericson-j-santos/engineering-worker-pool`, preservando a separação entre lógica
genérica do Worker Pool e adaptação host-specific do Desktop.

## Requisitos

1. Ambiente restrito a local/DEV no host `DESKTOP-PDQK954`.
2. Runner obrigatório: `DESKTOP-PDQK954-runtime`.
3. Labels obrigatórias: `pc24x7`, `desktop-runtime`, `runtime-dev`.
4. O checkout do `engineering-worker-pool` deve usar SHA completo imutável.
5. O adaptador deve validar o SHA do próprio `desktop-pc24x7-runtime` e o SHA do
   checkout do Worker Pool antes do smoke.
6. O endpoint permitido é somente `http://127.0.0.1:8097`.
7. A descoberta Docker deve aceitar exatamente um container em execução com
   service label `codex-worker-pool` e binding exato
   `127.0.0.1:8097 -> 8097/tcp`.
8. O token deve ser fornecido exclusivamente pelo único bind mount com destination
   `/run/secrets/codex_worker_pool_api_token`.
9. O adaptador não deve ler, imprimir, persistir nem publicar o token ou o caminho
   do arquivo em evidência.
10. A lógica funcional de health, enqueue, replay, leitura independente e lane
    sintética deve permanecer no harness do `engineering-worker-pool`.
11. O resultado terminal positivo exige `WORKER_POOL_SMOKE_PASSED`, lane
    desabilitada, task `queued`, ausência de lease, replay sem duplicidade e
    leitura independente.
12. Falta, ambiguidade ou divergência de host, runner, SHA, container, endpoint,
    mount, arquivo, evidência ou resultado deve falhar fechado.
13. Produção, HML/STG, deploy e reboot ficam fora do escopo.
14. Antes do primeiro comando técnico local, o workflow deve executar o
    `session_launcher.py` das regras canônicas fixadas por SHA e exigir
    `SESSION_LAUNCH_OK` com `state_validated=true`.
15. Após o bootstrap, a execução do adaptador deve ocorrer exclusivamente por
    `command_gateway.py`, com `session_id`, `correlation_id`, HEAD da âncora
    validado e risco 2.
16. Invocação direta do adaptador por PowerShell/CMD/Python fora do Command
    Gateway é evidência inválida e deve falhar no teste de contrato do workflow.
17. O caminho de evidência repassado ao harness do Worker Pool deve ser absoluto
    para permanecer invariável quando o harness usar `cwd` próprio.
18. Se e somente se o harness retornar `worker_pool_http_401`, o adaptador deve
    executar a reconciliação de autenticação DEV do runtime e repetir o smoke uma vez.
19. A reconciliação não pode criar, substituir ou rotacionar segredo; somente um
    stale bind comprovado por comparação host/container pode recriar o serviço.
20. Após a reconciliação, a repetição do smoke só pode ocorrer após leitura
    autenticada independente do runtime; qualquer outra causa deve falhar fechado.
21. A evidência final deve registrar `auth_reconciled`, `service_recreated` e
    `smoke_attempts`, sem registrar token nem caminho sensível.
22. A reconciliação deve receber o compose canônico do Worker Pool a partir do
    `cwd` da sessão ReqSys governada; compose funcional duplicado no runtime não
    é aceito.
23. O smoke físico deve executar também em `pull_request` para `main`, mas
    somente quando o head do PR pertence ao próprio repositório. PR de fork não
    pode executar no runner self-hosted.

## Critérios de aceite

- testes positivos e negativos verdes no CI do SHA da PR;
- smoke físico pré-merge verde no SHA do PR para mudanças do contrato/runtime;
- contrato estático comprova presença de Session Launcher + Command Gateway e
  ausência de invocação direta do adaptador;
- bootstrap físico retorna `SESSION_LAUNCH_OK`, `state_validated=true` e HEAD
  exato da âncora canônica;
- workflow físico integrado na main;
- execução no runner dedicado concluída no SHA vigente do runtime;
- Worker Pool executado no SHA imutável informado;
- artifact sanitizado contém os dois SHAs, correlation_id e resultado terminal;
- em `401` por stale bind, a recuperação preserva o mesmo token/imagem/volume,
  comprova leitura autenticada e o smoke é repetido no mesmo SHA;
- `secrets_exposed=false`, `token_path_exposed=false`,
  `production_touched=false`, `deploy_executed=false` e
  `reboot_executed=false`;
- evidência vinculada à issue #8 e à migração
  `ericson-j-santos/reqsys-v2-enterprise-real#2020`.
