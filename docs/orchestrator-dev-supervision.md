# Supervisão fechada do runner Orchestrator DEV

Este incremento estende o ciclo existente de desktop_control_plane_watchdog.py.
Não instala outro supervisor, não cria tarefa e não inicia processos ao ser publicado.

## Contrato admitido

A metadata existente pode acrescentar somente:

```json
{
  "additional_runner_profiles": ["orchestrator-dev"],
  "rdc_recovery_enabled": false
}
```


O runner_home primário permanece inalterado. O único alvo adicional é
DESKTOP-PDQK954-orchestrator-dev, ID21, no repositório
ericson-j-santos/reqsys-engineering-orchestrator e no diretório
%LOCALAPPDATA%/EngineeringOrchestratorDEV/GitHubRunner.

O ciclo recusa outro perfil, duplicação, host, diretório redirecionado e binding
.runner divergente. Não lê .credentials ou outros arquivos de autenticação.
A lista de variáveis herdadas pelo listener adicional é fechada em variáveis
normais do Windows; tokens, secrets, tracking e configuração de diagnóstico
do job não são herdados. O listener usa suas próprias credenciais oficiais.

A ausência de additional_runner_profiles mantém o comportamento Runtime atual.
rdc_recovery_enabled=false não chama a recuperação de RDC e registra a decisão
como disabled_by_owner. O valor precisa ser booleano. O padrão legado é
preservado para instalações que não adotarem esta configuração.

O estado diferencia o runner primário e o adicional. A falha do adicional impede
ok=true. Processo local observado não é apresentado como conectividade GitHub,
pickup do scanner ou conclusão da remediação.

## Qualificação conhecida e implantação pendente

O cadastro ID21 foi comprovado pelo run40618959829, tentativa1, em2.338.2.
O run40621636889, tentativa1, qualificou o Desktop por sessão/Gateway e readback:
Task Scheduler ativo; processo executor elevado; tarefas RuntimeWatchdog,
RuntimeHealthSupervisor e AdminBroker não encontradas tanto na consulta quanto
no caminho nativo (erro2). O broker tem heartbeat fresco, mas metadata antiga
ainda marca ativação UAC pendente. Isso não exige pedir UAC antes de testar a
rota administrativa já elegível.

A implantação deve reutilizar o nome \Automation\DesktopPc24x7RuntimeWatchdog,
preservar metadata/run.py anteriores em backup com digest, vincular a identidade
principal/SID em memória e rejeitar qualquer tarefa preexistente divergente.
Não sobrescrever uma tarefa com /F e não criar outro gerenciador paralelo.

Antes de ativar:

1. Integrar e revalidar a PR63 do Orchestrator, com labels exclusivas, main/SHA,
   runner ID21, Session Launcher e Gateway.
2. Produzir plano/digest de implantação da release e metadata no watchdog
   existente; preservar runner_home primário, Python e registro Runtime.
3. Usar uma ação Risk3 exata, vinculada ao script/HEAD/worktree e à autorização
   correspondente. Custo adicional máximo R$0, sem RDC pago.
4. Validar o pacote/runner e a tarefa S4U/boot; não iniciar uma cópia paralela do
   watchdog, que já possui lock exclusivo.
5. Provar online/pickup no ID21, versão e fonte atuais, scanner real e readback
   independente. Cancelar/reconciliar somente filas antigas do scanner segundo
   a política fechada; nenhuma operação sobre outros workflows.
6. Interromper de forma controlada apenas o listener novo quando o runner estiver
   idle e provar recuperação pelo mesmo supervisor. Preservar o Runtime.
7. Observar estado fresco e recorrência por uma janela definida; registrar a
   duração efetivamente observada e o limite de recuperação. Não prometer
   disponibilidade absoluta nem afirmar prova de reboot sem reboot observado.

Este incremento de código não comprova implantação, persistência, recuperação
física ou operação contínua. Cadastro, CI e handoff isolados não encerram as
TODO23/41.
