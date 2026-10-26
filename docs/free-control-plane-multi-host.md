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

## Repair de instalação parcial

`scripts/repair_desktop_free_control_plane.py` é a capability separada para o
caso estrito em que o runner dedicado permanece online, a metadata do watchdog
existe e a tarefa `AtStartup + S4U` ainda não existe. Ela não registra, reinicia
ou substitui o runner. O repair exige SHA limpo da fonte, SHA anterior e digests
SHA-256 exatos dos scripts instalados, recusa tarefa preexistente e confirma que
o mesmo processo e o mesmo registro GitHub permanecem ativos antes/depois.

Antes da mutação, preserva metadata, launcher e recibos sanitizados em backup
idempotente; a release anterior permanece intocada. A nova release é montada em
diretório imutável próprio e recebe manifesto de arquivos. Se a tarefa não for
comprovada, metadata e launcher são restaurados. UAC continua exigindo aprovação
local e o sucesso do repair continua `PICKUP_PENDING` até job físico independente
no mesmo SHA. A capability não instala TODO Gateway, não cria credencial, não
reinicia serviço existente e não reinicia o computador.

Um replay explicitamente autorizado reutiliza o backup somente quando o manifesto
e todos os arquivos preservados continuam íntegros e a metadata e o launcher ativos
correspondem ao estado original. Recibos forenses produzidos por uma tentativa UAC
posterior podem divergir sem substituir o backup original; qualquer drift nos
arquivos necessários ao rollback continua falhando fechado.

Se o Task Scheduler não enumerar a tarefa, mas o arquivo exato existir em
`System32\Tasks`, o repair trata o estado como registro órfão. O filho elevado
só coloca esse arquivo em quarentena quando o XML ainda corresponde ao mesmo
nome, `BootTrigger`, `S4U`, Python e launcher instalados. O backup é endereçado
pelo SHA-256 do XML e preservado antes da remoção. XML estrangeiro, alterado ou
ambíguo bloqueia sem mutação. Depois do novo registro, o próprio processo
elevado executa um readback independente via Task Scheduler; o recibo UAC só
pode declarar `ok=true` quando esse readback comprovar `AtStartup + S4U`. O
chamador normal também precisa enumerar a mesma tarefa antes da finalização.

O registro também aplica uma DACL explícita à tarefa: `SYSTEM` e o grupo local
de Administradores mantêm controle total, enquanto somente o SID exato do
principal S4U recebe leitura e execução. A atualização usa o parâmetro SDDL de
`RegisterTaskDefinition` e reafirma o mesmo descritor no objeto registrado. Isso
evita recibo elevado positivo acompanhado de invisibilidade para o chamador
normal, sem conceder acesso a `Authenticated Users` ou alterar a ACL da pasta
compartilhada `\Automation`.

Executar primeiro com `--preflight-only` e com os quatro valores observados e
fixados (`--source-sha`, `--expected-installed-sha`,
`--expected-watchdog-sha256`, `--expected-uac-sha256`). A aplicação usa os
mesmos argumentos sem `--preflight-only` e exige confirmação literal
`REPAIR-DESKTOP-FREE-CONTROL-PLANE`. O preflight não escreve no host e a
confirmação não reduz nenhuma das verificações de identidade ou digest.

## Upgrade do launcher S4U e pickup do Lenovo

O launcher persistido precisa inserir o diretório `scripts` da release no
`sys.path` antes de executar o watchdog com `runpy`. Sem isso, a ação S4U encerra
com código `1` ao importar `pc24x7_host_policy`, antes de criar `state.json`.
`scripts/upgrade_desktop_free_control_plane.py` corrige esse estado sem registrar
novamente a tarefa e sem substituir ou reiniciar o runner. O upgrade exige o SHA
e os hashes observados do watchdog, launcher UAC e `run.py`, cria backup
idempotente, monta uma release imutável, inicia a tarefa existente e só finaliza
quando um `state.json` fresco no novo SHA comprova runner recovery e escopo
`rdc_required=false` no Lenovo.
O upgrade também normaliza `runtime_root` para o diretório físico que contém o
launcher registrado, evitando divergência entre a virtualização de
`LOCALAPPDATA` do aplicativo, o contexto S4U e o processo do runner. O pickup
deriva esse diretório da ação da própria tarefa e rejeita metadata apontando
para outro local.

Executar primeiro com `--preflight-only` e confirmação literal
`UPGRADE-DESKTOP-FREE-CONTROL-PLANE`. A execução física usa os mesmos argumentos
sem `--preflight-only`; não usa UAC porque preserva a tarefa AtStartup+S4U e sua
ACL já registradas.

O pickup independente usa a entrada booleana fixa
`lenovo_control_plane_pickup=true`, combinada somente com o diagnóstico
`runner-identity`, no workflow
`.github/workflows/dedicated-runtime-runner-e2e.yml`. O job requer a etiqueta
exclusiva `desktop-rp23ogs`, confirma hostname, nome do runner, SHA do workflow,
metadata, tarefa em execução e estado fresco, passa pelo Session Launcher e
Command Gateway e publica somente o artifact sanitizado
`lenovo-control-plane-pickup-<run>-<attempt>`. O watchdog hospedado cancela a
execução se o runner físico exato não fizer pickup em 300 segundos.
