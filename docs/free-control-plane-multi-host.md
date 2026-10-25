# Plano de controle gratuito nos computadores autorizados

## Papéis e limites

| Host | Papel | Ativação deste pacote |
| --- | --- | --- |
| `DESKTOP-PDQK954` | Desktop principal | Runner dedicado e watchdog; a recuperação RDC legada permanece exclusiva deste host. |
| `DESKTOP-RP23OGS` | Desktop secundário | Runner dedicado e watchdog; não chama a recuperação RDC legada do Dell. |
| `NOTERI` | Notebook de controle | Usa `noteri-runtime`; o ativador de desktop rejeita este host. |

O Command Gateway e a sessão governada são pré-requisitos em cada computador.
`HOST_BOOTSTRAP_OK` ou `SESSION_LAUNCH_OK` não iniciam um listener remoto. Um
checkout, CI hospedado ou PR não instala o pacote no computador físico.

## Ativação única e recuperação permanente

`scripts/activate_desktop_free_control_plane.py` coordena os componentes já
versionados, sem replicar o instalador do runner ou do watchdog:

1. Confere Windows, papel desktop, SHA exato e checkout limpo. Recusa tarefa ou
   metadata de watchdog pré-existentes, que exigem upgrade separado.
2. Confere `pywin32` e uma sessão GitHub CLI local já autenticada para o owner.
   Não inicia login, não pede senha, não cria credenciais e não persiste token de
   registro em log ou artifact.
3. Reutiliza `bootstrap_dedicated_runtime_runner.py` para registrar/iniciar o
   runner em `%LOCALAPPDATA%\DesktopPC24x7\GitHubRunner`.
4. Reutiliza `desktop_control_plane_watchdog.py` para instalar a tarefa
   `AtStartup + S4U`. Quando o Windows exigir elevação, usa apenas o launcher
   UAC versionado, com aprovação local do proprietário.
5. Faz readback da tarefa. Retorna `CONTROL_PLANE_INSTALLED_PICKUP_PENDING`:
   o estado operacional ainda depende de um job físico independente no mesmo
   SHA, com Session Launcher, Gateway e artifact verificável.

O watchdog recupera o runner após boot independentemente do listener. No Dell,
o ciclo também recupera o RDC legado. No Lenovo, o ciclo não tenta operar a
tarefa RDC exclusiva do Dell. O runner e o watchdog instalados permanecem em
diretórios exclusivos e não substituem runners ou serviços do ReqSys.

## Recuperação e rollout

O primeiro computador precisa de um canal de execução local ou remoto já
autorizado. Gateway e sessão instalados, sozinhos, não oferecem endpoint de
rede nem recebem jobs. Se nenhum agente puder chamar o Gateway no Lenovo, a
ativação física fica bloqueada; não despachar jobs em fila como substituição.

Cada desktop recebe sua própria instalação, confirmação, SHA, evidência e job
de pickup. O Noteri é validado pelo seu repositório e contrato próprios. Nunca
inferir prontidão de um host a partir do CI ou da saúde de outro.

Para recuperação de instalação parcial, conservar diretórios e metadata e
inspecionar o estado antes de qualquer nova tentativa. A presença de tarefa ou
metadata existente faz o ativador falhar fechado; upgrade/rollback são uma
capability separada e não usam `--replace` implícito.
