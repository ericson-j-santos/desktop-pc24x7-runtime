# Inventário seguro do Desktop para GitLab — implementação candidata

## Para que serve

Verifica, **sem instalar nada**, quantos processadores lógicos existem, a ocupação de CPU em **uma amostra**, a RAM total/livre e o espaço total/livre do volume de sistema. Funciona apenas no `DESKTOP-PDQK954`, por acionamento manual, usando Session Launcher e Command Gateway Risk 1, sem Docker.

**Uma amostra não homologa o computador para GitLab Runner.** O resultado `capacity_sample_complete=true` confirma apenas que os quatro dados puderam ser lidos; o campo `ready_for_gitlab_runner` fica obrigatoriamente `false` até serem comprovados os demais gates.

## Escopo e fonte

- Repositório de destino: `ericson-j-santos/desktop-pc24x7-runtime`, branch canônica `main`.
- SHA de origem inspecionado: `e0c40bccf0d99858a21beab0d62d0f143e969608`.
- Regras operacionais: `ericson-j-santos/chatgpt-operational-rules`, versão **1.6.19**, SHA `682bba2858e09c161e7d3a477896ba7e326e83bd`.
- GitHub/GitLab ReqSys: `4fbd2a9e2ad7ac41e0270b8271af08182aa4a514` na `main` de ambos na última verificação.
- Issue: [ReqSys #855](https://github.com/ericson-j-santos/reqsys-v2-enterprise-real/issues/855), TODO Global: [TODO-45](https://app.notion.com/p/4094c12bae7c8123a523f9e355347eb9).

## Como funciona

**Entrada:** somente `workflow_dispatch` do proprietário, com SHA completo da `main` do runtime, SHA completo das regras e escopo fixo `READ_ONLY_CAPACITY_NO_INSTALL`.

**Processamento:** verifica proprietário/repositório/branch/runner físico ID 2 e nomes exatos → checkout das duas versões → Session Launcher e verificação de versão do runner → criação de worktree isolado → Command Gateway `risk 1` → leitura nativa via APIs Windows → validação das evidências. Um watchdog independente cancela jobs sem pickup após 300 segundos. Não aceita tentativas automáticas, forks ou replay de tentativas.

**Saída:** JSON sanitizado no log e resumo do próprio job GitHub, contendo números de capacidade, SHA, horário e correlação. **Não** faz upload de artifact, instalação, registro de serviço, alteração em banco, deploy ou mudança de segurança.

## Gates anteriores à publicação e ao acionamento

1. Revalidar `main`, regras, identidade do runner e permissões contra o estado mais recente.
2. Verificar no Billing GitHub que não existe cobrança adicional para a operação planejada; o workflow só usa runner próprio existente e um job hospedado **padrão em repositório público**, sem upload de artifacts. Custos locais de energia/infraestrutura **não foram medidos**.
3. Publicar somente via branch e PR governadas, com validação independente do patch, testes obrigatórios, `READY_FOR_PR`, hash CAS durável e readback conforme regras do projeto. **Este pacote local não representa branch, commit, PR ou READY_FOR_PR.**
4. Após integração autorizada, acionar **uma vez**, na `main` exata, com os parâmetros atuais. Novo SHA invalida os anteriores.
5. Conferir o job e o registro `CAPACITY_MEASURED_NOT_RUNNER_APPROVED` via API independente, no mesmo SHA/host/runner e execução; não considerar HTTP 200 ou logs sem leitura independente como E2E.
6. Medir novamente em condição de carga pertinente, analisar CPU/RAM/disco e concorrência, isolamento, supervisão, custo e rollback **antes** de instalar ou registrar o GitLab Runner protegido.

## Riscos e limitação

- Os testes locais verificam código Python, configuração YAML, admissão de runner e watchdog por API simulada. **Não** testam PowerShell no Windows real, Session Launcher/Gateway de produção, nem execução física do novo job.
- O teste físico disponível é de outro workflow já integrado: [runtime canary #40994086914](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40994086914). O artifact ID `12950871001`, digest `sha256:c041c970a23c6e258d51bb5a68eeb47519745b12bc38b4cd4dc89116b68e4fb5`, foi baixado e validado. Prova runner/Session Launcher/Orchestrator/Worker Pool saudáveis **naquela execução**, mas não a capacidade livre.
- `GitLab project runner` ainda não foi registrado. O executor Shell tem isolamento reduzido; migrar o pipeline com `image:` e `services:` exige nova implementação e testes, sem contêineres.
- Repositórios GitHub e GitLab não devem ser usados em sincronização bidirecional; o GitHub continua canônico.

## Rollback

Como esta proposta apenas cria arquivos novos, o rollback de **código** é reverter a alteração por PR normal. Não há alteração física a reverter neste estágio. Se futuramente um job for admitido e falhar, não repetir sem mudança objetiva na precondição; o watchdog limita espera de pickup a cinco minutos. Nunca reiniciar serviços, limpar artifacts ou trocar permissões para encobrir falhas.
