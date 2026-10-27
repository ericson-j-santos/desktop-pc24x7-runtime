# Plano somente leitura do runner exclusivo do orchestrator DEV

## Objetivo e limite

A capability scripts/orchestrator_dev_runner_preflight.py prepara, somente
por leitura, a identidade de um runner exclusivo para
ericson-j-santos/reqsys-engineering-orchestrator, no DESKTOP-PDQK954.

Ela reutiliza a validação de host e o cliente GitHub do bootstrap dedicado
existente. Não possui modo de aplicação, destino configurável ou comando livre.
Não solicita token de registro, baixa arquivo, registra runner, inicia listener,
altera tarefa Windows, muda o watchdog ou escreve recibo no host.
O resultado é emitido em JSON no stdout para o transporte governado preservá-lo.

## Verificações deste incremento

- Fonte Runtime no SHA informado, remoto correto e árvore rastreada limpa.
- Próprio probe e imports locais fixos rastreados pelo Git, no mesmo checkout.
- Git somente leitura com GIT_OPTIONAL_LOCKS=0.
- Windows x64 no DESKTOP-PDQK954.
- Todos os ancestrais existentes examinados por lstat, sem symlink/reparse,
  com tipo correto; cauda futura apenas planejada, sem criação de diretório.
- Inventário completo de runners do repositório de destino.
- Ausência de conflito entre registro remoto e metadata local pública.
- IDs positivos e aliases de nome/repositório consistentes; BOM Windows aceito.
- Readiness e worker Desktop fresco, autenticado, online e NORMAL no
  orchestrator local 127.0.0.1:8787.

A capability lê somente .runner quando necessário. Arquivos de credenciais do runner
não são lidos. O ambiente do listener persistente também exclui GH_TOKEN,
GITHUB_TOKEN e RUNNER_TRACKING_ID. O probe desabilita a escrita de bytecode dos
imports locais.

## Perfil fechado

- Repositório: ericson-j-santos/reqsys-engineering-orchestrator
- Ambiente: DEV
- Host: DESKTOP-PDQK954
- Nome: DESKTOP-PDQK954-orchestrator-dev
- Diretório: %LOCALAPPDATA%\EngineeringOrchestratorDEV\GitHubRunner
- Labels próprias: orchestrator-dev, desktop-pdqk954

O perfil e o runner Runtime atuais permanecem distintos.

## Critério de saída deste incremento

CI Windows e Linux deve executar compilação e testes positivos, negativos,
replay, ausência de mutação e isolamento das credenciais do processo filho.

Uma execução física somente leitura precisa usar Session Launcher,
SESSION_LAUNCH_OK, worktree exclusivo, Command Gateway e SHA exato.
O CI com respostas simuladas não substitui essa leitura física.

A saída READ_ONLY_PLAN_RECORDED_EXECUTION_PENDING confirma somente as leituras
descritas. execution_authorized permanece false. A versão e elegibilidade do
binário do novo runner NÃO são comprovadas aqui: runner_version_preflight e
a validação do pacote oficial continuam gates posteriores antes do cadastro.

O plano não autoriza cadastro e não comprova pickup ou operação 24x7.
Essas etapas continuam pendentes: autorização administrativa do alvo DEV,
registro exclusivo, pickup independente, scanner real e recuperação da
supervisão sem substituir o runner Runtime. Também não é comprovada nesta
capability a execução do handler de remediação até o resultado terminal.
