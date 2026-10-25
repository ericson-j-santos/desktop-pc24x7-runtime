# Canário físico Agentic RAG no Dell (DEV, somente leitura)

## Objetivo e fontes

O canário isola a última lacuna da integração RAG: comprovar **no Dell físico**
o modelo Qwen2.5-Coder 7B recuperando uma fonte real da API GitHub via o
Agent Core, selecionando citação e tendo o efeito relido de forma independente.

Vínculos fixados (não reinterpretar como status da main corrente):
- Runtime Platform main de origem: a0437b0deb7db42fb91866fe8e77359844579cf6
- Worker Pool PR #49: cb42568c4b70faa0e3e05bb49d5a6e41b884281f
- Agent Core main: 1fc032d4c412bdb4ed202cf1193caf0cb49490ce
- Regras operacionais v1.6.19: 4e6091a133f8d7d157abe6f83c31ca597812e0a4
- Agent Core PR #9 (HEAD imutável da fonte): b083a23af7c55f96ee1c7f8daabbd51167bf4de6
- SHA-256 da fonte docs/PR_CONTEXT_RETRIEVAL.md: b3f7aceab1c5caf0e2aab532189ea4d970aa710120a459f111d7fc9026cfa706

O modelo opera exclusivamente em 127.0.0.1:11434 e deve comprovar o digest
GGUF prefixo dae161e27b0e. No Dell, sem Docker, sem baixar modelo, sem
nova identidade, sem API de inferência externa e sem edição de código.

## Admissão e acionamento único

A PR de preparação é inicialmente criada em **draft sem marcador de execução**.
Somente após CI Windows e Linux com testes realmente executados no SHA atual,
uma mudança explícita de corpo de PR pelo proprietário acrescenta o marcador
OWNER_RAG_DELL_READONLY_20261025_GIT_CONFIG_REPAIR_ONCE. O workflow detecta a transição
PR.body.before sem marcador -> PR.body.after com marcador. Eventos push,
schedule, synchronize, workflow_dispatch, reabertura ou edição posterior
sem essa transição não disparam o canário.

O gate de admissão, executado num runner GitHub hospedado, reconsulta o PR
e a main, confere o escopo exato dos quatro arquivos, confirma os checks
Windows/Linux do novo HEAD e verifica o Worker Pool PR #49/CI #40213815929
(incluindo a etapa real de RAG). Qualquer mudança de SHA/base, PR não draft
ou check skipped bloqueia o job físico.

O runner exigido é DESKTOP-PDQK954-runtime com labels específicas. O watchdog
hospedado cancela o run se não observar pickup comprovado em 300 segundos.
A indisponibilidade do runner não autoriza RDC, UAC ou shell alternativo.

## Execução física e evidência

1. Checkout separado e imutável de Runtime PR SHA, Worker Pool, Agent Core
   e regras, sem persistir credenciais nos checkouts.
2. Session Launcher governado com --require-runner-version-preflight,
   --expected-head, --sync-ref e sessão exclusiva. Só continua com
   SESSION_LAUNCH_OK, state_validated=true, snapshot_sha256 e worktree isolado.
3. Command Gateway, risco 2: criar venv no worktree da sessão e instalar
   apenas httpx==0.28.1, com pip check. Não alterar instalação global.
4. Command Gateway, risco 1: executar o script versionado no mesmo worktree
   com limite de 280 segundos e sem mudança de HEAD ou arquivos rastreados.
5. Preflight local: host, runner, sessão, SHA, remoto e árvore rastreada
   dos quatro checkouts. Injetar apenas fontes aprovadas no sys.path.
6. Controle negativo real: SHA propositalmente obsoleto bloqueado pela
   API GitHub antes da inferência, com model_calls=0.
7. Qwen local executa duas chamadas governadas (plano + seleção da citação)
   e recupera a declaração de read-only na linha 5 de documentação oficial
   do Agent Core, com o SHA e digest esperados.
8. Novo cliente GitHub independente reconsulta PR/head/base e bytes completos
   da fonte, valida Git blob SHA-1, SHA-256, citação e recibo canônico.
   Uma nova leitura Git local confirma integridade de runtime/worker/core/rules.
9. Job hospedado de readback independente confere runner_id/runner_name,
   etapas realmente executadas e integridade do conteúdo consultado.

O sucesso da chamada da API ou a existência de um log não bastam. O aceite
físico exige o script retornar RAG_PHYSICAL_E2E_VERIFIED em risco 1,
os jobs admission/physical/readback concluídos com success, os recibos e
a leitura independente pelo controlador no mesmo run/SHA.

## Limites e rollback

Este canário não integra RAG ao Builder/Validator de reparos, não realiza
claim de tarefa, não cria Git bundle, CAS, issue/PR, merge, deploy, instalação
de runner ou migração do ReqSys. O retorno do modelo é somente dado verificável.

A operação é reversível por interrupção do job; o ambiente venv temporário
fica sob worktree governado e não deve ser apagado à força se houver erro
de permissão. A falha prévia sandbox_cleanup_permission_denied do run
#40214413825 não é contornada. Nenhum cleanup destrutivo está programado.

Não declarar Agentic RAG operacional no Dell até o E2E físico real, bem-sucedido
e relido independentemente. Enquanto houver gate pendente, usar PARCIAL/BLOQUEADO.

## Revalidação do transporte após o primeiro bloqueio

O run físico #40218210768 comprovou pickup no Dell e falhou no Session Launcher,
na etapa `synchronize_base`, durante o segundo `git fetch` da cópia isolada
(`getsockname() failed with errno 10022`). Nenhum comando de inferência ocorreu.
Posteriormente, o mesmo Dell executou `git fetch`, Session Launcher e Gateway
com sucesso no canário #40220795820; isto demonstra nova condição de rede,
mas **não** garante que o segundo fetch esteja resolvido.

A primeira autorização `OWNER_RAG_DELL_READONLY_20261025_ONCE` foi consumida e
não pode disparar novamente. Apenas a transição explícita ao novo marcador
`OWNER_RAG_DELL_READONLY_20261025_GIT_CONFIG_REPAIR_ONCE` após CI em SHA corrente autoriza uma segunda
sonda física, com a mesma admissão e proibição de contornos. Nenhuma repetição
automática se o erro de socket voltar a ocorrer.

O branch da PR foi sincronizado com a `main` após as PRs #96/#97,
com merge não destrutivo e preservação dos quatro arquivos do canário.

## Verificador Git da sessão — correção proposta

O canário físico #40221384710 superou `SESSION_LAUNCH_OK`, o Gateway e a
instalação de dependências, mas o verificador do roteiro encerrou com o código
sanitizado `rag_readonly_git_failed` antes da inferência. A implementação
anterior explicitamente anulava as configurações `GIT_CONFIG_GLOBAL` e
`GIT_CONFIG_SYSTEM` nas consultas de leitura. Isso difere do ambiente governado
usado pelo Launcher/Gateway e pode ocultar as entradas protegidas
`safe.directory` do Git for Windows.

A correção preserva essas configurações (sem `safe.directory=*`), mantém apenas
três operações de Git totalmente autorizadas, força `GIT_OPTIONAL_LOCKS=0`,
bloqueia prompts e emite o nome fixo da operação que falhar. Testes negativos
verificam stderr sanitizado, status não zero, saída excessiva e comandos não
admitidos. A hipótese ainda necessita validação no mesmo Dell e SHA.

A terceira sonda é permitida somente por transição ao marcador único
`OWNER_RAG_DELL_READONLY_20261025_GIT_CONFIG_REPAIR_ONCE`, após CI real Windows/Linux no último SHA,
sem reutilizar os tokens anteriores.
