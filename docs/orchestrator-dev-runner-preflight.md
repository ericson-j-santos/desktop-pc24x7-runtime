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

## Rota governada de qualificação

O workflow existente dedicated-runtime-runner-e2e.yml oferece o diagnóstico
fechado orchestrator-runner-preflight. Selecionar a branch revisada e informar
orchestrator_source_sha com o HEAD completo atual. A admissão exige main atual
como ancestral, PR aberta do próprio repositório quando aplicável e a execução
mais recente do CI de push aprovada no mesmo SHA em Windows e Linux.

O contrato hosted executa os testes específicos antes de liberar o runner
Runtime ID 2. O primeiro passo físico revalida host, runner, HEAD, main, regras
e a janela de pickup de cinco minutos. Session Launcher e Gateway permanecem
obrigatórios. O novo modo limpa GH_TOKEN/GITHUB_TOKEN no transporte do probe
para usar a autenticação local existente do gh; falta de acesso bloqueia a
leitura, sem provisionar credenciais nem ampliar permissões.

O helper executa um SHA negativo e duas leituras iguais. Um job hosted separado
confere o recibo sanitizado, jobs e etapas reais, tentativa atual e a execução
mais recente do CI. Cancelamento do operador interrompe os jobs físicos.
O recibo não contém o caminho local planejado. Os uploads dos diagnósticos
anteriores e o bloco Lenovo permanecem preservados.

Esta rota comprova somente o preflight quando todas as verificações passarem.
Cadastro do novo runner, pickup do scanner, supervisão contínua e remediação
até estado terminal continuam gates separados.


## Preparação do cadastro exclusivo

O bootstrap existente oferece um destino adicional fechado `orchestrator-dev`.
A invocação Runtime anterior mantém o comportamento existente. O destino novo
exige modo explícito `--plan` ou `--apply`; não aceita repositório, diretório,
labels, executável ou token como parâmetros livres.

O perfil compartilhado fixa DEV, DESKTOP-PDQK954,
ericson-j-santos/reqsys-engineering-orchestrator,
DESKTOP-PDQK954-orchestrator-dev e
%LOCALAPPDATA%\EngineeringOrchestratorDEV\GitHubRunner.
As labels próprias são orchestrator-dev e desktop-pdqk954.

### Plano

O modo plan exige a confirmação textual PLAN-ORCHESTRATOR-DEV-RUNNER,
source-sha completo e correlation-id. Reexecuta o preflight somente leitura,
confere metadata oficial do pacote fixado e consulta a depreciação da versão
no repositório de destino. Usa somente a sessão local existente do GitHub CLI,
validada como ericson-j-santos, sem herdar GH_TOKEN/GITHUB_TOKEN do workflow.
Não efetua login, provisiona credencial, solicita token de registro, baixa
pacote, executa binário, cria diretório ou escreve evidência no host.

A saída inclui plan_sha256 vinculando fonte, correlação, perfil, home,
observação do registro, pacote e política de versão. O resultado
REGISTRATION_PLAN_READY_EXECUTION_PENDING permite revisar o efeito concreto;
não concede autorização administrativa. A versão real do futuro binário e o
pickup permanecem não comprovados.

O pacote proposto é actions-runner-win-x64-2.338.2.zip, publicado pelo projeto
oficial actions/runner, com 104210683 bytes e SHA-256
`a1f17aa987fc8158bc7521d284912267a0d01b7c2c4684b33c86783b5e8221cc`.
O pin do runner Runtime existente não é alterado por este perfil.

### Aplicação administrativa

A aplicação somente pode ocorrer depois da autorização administrativa aplicável,
por sessão governada no host correto, com CI e revisão no SHA atual. Exige a
confirmação textual REGISTER-ORCHESTRATOR-DEV-RUNNER e o digest exato do plano
relido. Custo adicional autorizado permanece R$ 0,00.

Sob lock Windows exclusivo no diretório do perfil, o aplicador relê o plano,
baixa o pacote oficial para staging temporário, comprova tamanho e SHA-256,
extrai sem escape de caminho e confere um manifesto de todos os arquivos e
diretórios, inclusive dependências. Links, reparse points e hardlinks são
rejeitados. Caminhos e tipos inesperados são rejeitados antes de ler conteúdo.
A sonda --version executa uma cópia temporária previamente conferida contra o
manifesto, pois o runner cria _diag durante a inicialização. O pacote original
é novamente conferido e somente esse payload íntegro pode ser instalado.
Versão inesperada, falha de execução ou depreciação inválida bloqueia o cadastro.
Não desabilita App Control ou outro controle do host.

O diretório de destino deve estar ausente ou vazio. A instalação usa rename
local após revalidação; repositório, fonte, host, arquivos do pacote e ausência
de registro concorrente são conferidos novamente antes do POST fixo de registro.
O token efêmero fica somente no ambiente do processo de configuração,
ACTIONS_RUNNER_INPUT_TOKEN, e é removido em finally. Todos os inputs herdados
ACTIONS_RUNNER_INPUT_* e tokens do workflow são excluídos desse ambiente.
RUNNER_PERFLOG e GITHUB_ACTIONS_RUNNER_HTTPTRACE herdados também são removidos
para impedir logs fora do staging e rastreamento de conteúdo sensível.
Processos temporários preservam RUNNER_TRACKING_ID para o encerramento pelo job.
A configuração chama diretamente Runner.Listener.exe configure, sem cmd.exe,
Unblock-File ou alteração de App Control. A remoção do tracking permanece
restrita ao listener persistente existente.
Não se utiliza --replace, configuração de serviço ou comando de start.
O runner oficial cria suas próprias credenciais de runtime; esses arquivos
não são lidos nem publicados pelo aplicador.

Sucesso deste estágio exige readback do vínculo local/remoto com o mesmo ID,
nome, repositório e labels. RUNNER_REGISTERED_ACTIVATION_PENDING comprova apenas
cadastro. Listener, tarefa Windows, watchdog, pickup, scanner e operação contínua
continuam pendentes. Repetição que encontre vínculo completo retorna
RUNNER_ALREADY_REGISTERED_ACTIVATION_PENDING como no-op somente leitura, informa
o digest atual e o solicitado e não atribui a criação a essa tentativa.

### Falha parcial e reversão

Falha antes do cadastro não autoriza apagar dados existentes. Staging temporário
é descartado; um pacote que já tenha sido instalado é preservado e reportado.
O efeito da instalação é registrado imediatamente após o rename, antes de
qualquer pós-check que possa falhar.
Se a configuração foi invocada e o efeito não puder ser comprovado,
registration_performed é null, e o ID remoto eventualmente observado é publicado
sem atribuir sua criação à tentativa. Não há DELETE ou unregister automático.
Diretório não vazio sem vínculo válido bloqueia novo cadastro cego.

Uma reversão administrativa deve ser vinculada ao recibo da tentativa e ao ID
exato, com releitura de host/home/registro e prova de que não há job em execução.
Somente o novo cadastro pode ser removido por operação específica autorizada;
o runner Runtime e sua tarefa/supervisão permanecem preservados. Sem prova de
proveniência ou diante de concorrência, manter o bloqueio e a evidência para
reconciliação, sem remover por nome.

### Gates ainda separados

- Autenticação local existente acessível à identidade que executa o probe;
  autorização para consultar depreciação e solicitar token no repositório alvo.
- Readiness real de /readyz e /v1/workers e identidade do host.
- CI Windows/Linux do candidato; o lock Windows é exercitado no job Windows.
- Inventário físico da tarefa/supervisão atual antes de qualquer handover.
- Ativação do listener e supervisão adicional por mecanismo governado próprio,
  preservando PID/ID do Runtime, com recuperação e leitura independente.
- Pickup real, scanner e remediação até resultado terminal no SHA aplicável.

Fontes oficiais: [release v2.338.2](https://github.com/actions/runner/releases/tag/v2.338.2),
[protocolo de configuração](https://github.com/actions/runner/blob/v2.338.2/src/Runner.Listener/CommandSettings.cs)
e [API de runners](https://docs.github.com/en/rest/actions/self-hosted-runners).


## Inventário local quando o preflight permanece bloqueado

Nos bloqueios fechados de autenticação ou readiness, o probe revalida fonte e
host e coleta observações locais independentes. Não realiza login, repete a
autenticação GitHub nem contorna o inventário remoto.

O watchdog fornece leitores fixos da instalação, estado, tarefa e processos.
As respostas de /readyz e /v1/workers são observadas separadamente. Uma falha
de componente não suprime os demais. Não há execução do Listener ou leitura
do conteúdo de .runner/arquivos de credenciais durante essa coleta.

O helper projeta o suplemento em esquema público fechado e imprime
ORCHESTRATOR_LOCAL_INVENTORY. Enums, booleanos, contagens, PID e hashes são
permitidos; paths de usuário, principal, SID, XML, metadata/status integrais
e respostas brutas não são publicados. O envelope do Gateway, SHA,
correlação, sessão, risco e ausência de mudança são validados antes da projeção.

O preflight continua bloqueado, sem recibo final de sucesso ou autorização.
Metadata ausente refere-se somente ao caminho fixo no LOCALAPPDATA da sessão;
não prova ausência em outros perfis do host. Consulta da tarefa indisponível
não distingue inexistência de acesso negado. Componentes não observados são
mantidos como desconhecidos, e nenhuma dessas leituras comprova operação
contínua, recuperação ou cadastro do novo runner.

## Autenticação local reaproveitada

O bootstrap mantém a rota GitHub CLI e, quando ela não valida o owner, admite o credential helper já configurado no Git para o repositório fixo do Orchestrator. A credencial fica somente na memória do processo, é validada em /user como ericson-j-santos e só pode atender os endpoints fechados do contrato DEV. Nenhum login, approve/erase, arquivo de token ou exportação ao listener é solicitado; o helper pode renovar sua própria credencial durante get.

A capability de diagnóstico consulta a tarefa RuntimeHealthSupervisor existente sem PyWin32 e compara principal/SID em memória. O dispatch excepcional desta correção é limitado ao commit filho de 7e51a578a59afa7ee955139c2f6bc3df72509ef6, exige HEAD/main/regras e os CIs de push/PR atuais aprovados, envia uma única requisição ao workflow físico existente e faz readback. Um POST de resultado incerto nunca é repetido. Esse dispatch não autoriza cadastro, instalação, restart ou alteração administrativa.
