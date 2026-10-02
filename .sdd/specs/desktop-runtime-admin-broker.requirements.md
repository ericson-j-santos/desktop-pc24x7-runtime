# Desktop PC24x7 Runtime — broker administrativo isolado

## Objetivo

Fornecer um canal administrativo outbound-only próprio do
`ericson-j-santos/desktop-pc24x7-runtime`, sem substituir o broker legado do ReqSys
durante a migração.

## Alvo e identidade

- host: `DESKTOP-PDQK954`;
- ambiente: local/DEV;
- issue de autorização: `desktop-pc24x7-runtime#2`;
- ator: `ericson-j-santos` com `author_association=OWNER`;
- tarefa futura: `\Automation\DesktopPc24x7AdminBroker`;
- runtime futuro: `%LOCALAPPDATA%\DesktopPC24x7\AdminBroker`;
- transporte: somente HTTPS outbound para comentários públicos da issue.

## Comandos desta fatia

Somente:

- `/desktop-runtime admin status`;
- `/desktop-runtime admin recover-rdc`;
- `/desktop-runtime admin recover-runner`;
- `/desktop-runtime admin recover-control-plane`;
- `/desktop-runtime admin activate-watchdog`.

Os comandos de watchdog usam exclusivamente a task
`\Automation\DesktopPc24x7RuntimeWatchdog` e o runtime
`%LOCALAPPDATA%\DesktopPC24x7\ControlPlaneWatchdog`. A task legada
`\Automation\ReqSysDesktopControlPlaneWatchdog` permanece fora do alcance deste broker.

## Runner

`recover-runner` deve chamar apenas
`scripts/activate_desktop_runtime_runner.py`, que registra
`DESKTOP-PDQK954-runtime` no repositório novo e usa o diretório dedicado
`%LOCALAPPDATA%\DesktopPC24x7\GitHubRunner`.

O runner legado do ReqSys não pode ser descoberto, parado, removido, registrado,
substituído ou ter suas labels alteradas por esta capacidade.

## Segurança

- comentários editados, antigos, de outro ator/associação ou fora da allowlist são ignorados;
- `comment_id` é chave de idempotência e é persistido antes do handler;
- nenhuma entrada pode fornecer shell, caminho, host, executável, repo, labels ou token;
- token de runner nunca é persistido/logado;
- sem listener inbound, reboot, shutdown, produção, deploy, force-push ou RBAC amplo;
- antes de registrar qualquer persistência, o broker deve copiar o runtime Python
  funcional para `%LOCALAPPDATA%\\DesktopPC24x7\\AdminBroker\\python-runtime\\<hash>`,
  validar SHA-256 do executável e versão por execução independente e persistir
  somente o executável dessa cópia imutável; Python global, virtualenv e
  executável transitório do runner não podem ser usados por Task Scheduler/HKCU;
- quando AtStartup + S4U não puder ser registrado sem elevação, o broker pode
  registrar fallback estrito em `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`,
  com valor fixo `DesktopPc24x7AdminBroker`, readback exato e início imediato
  por argv fixo com `shell=False`; o processo deve sobreviver à janela inicial
  de partida, caso contrário a instalação falha fechada;
- esse fallback é o canal operacional local/DEV enquanto AtStartup + S4U +
  highest não estiver comprovado; ele deve usar um supervisor per-user
  idempotente, manter heartbeat sanitizado e reiniciar o broker após falha,
  sem exigir nova UAC;
- esse fallback não satisfaz o critério final AtStartup + S4U + highest;
- a elevação da tarefa AtStartup + S4U continua exigindo autorização
  administrativa explícita; quando concluída, o fallback HKCU deve ser removido.

## Critérios de aceite de código

1. compilação e pytest verdes no SHA atual;
2. controles negativos de autorização e anti-replay verdes;
3. testes provam repo/issue/task/runtime fixos;
4. testes provam identidade própria do watchdog e ausência de descoberta do runner legado;
5. testes provam uso exclusivo do bootstrap do runner novo;
6. comandos de watchdog apontam apenas para task/runtime próprios;
7. fallback não administrativo usa somente HKCU do usuário corrente, comando
   fixo e `shell=False`, apontando exclusivamente para o Python persistido no
   runtime próprio; criação de processo não basta e morte imediata falha fechada;
8. o launcher per-user deve supervisionar o broker, reiniciar falhas transitórias
   com backoff limitado e publicar heartbeat sanitizado para readback independente;
8. testes provam cópia idempotente do runtime Python, hash/versão, rejeição de
   virtualenv e ausência do caminho Python transitório na metadata persistida;
9. CI de PR verde no HEAD exato.

## Critérios de aceite runtime

Somente após autorização administrativa específica:

1. tarefa `DesktopPc24x7AdminBroker` instalada como AtStartup + S4U + highest;
2. `status` consumido uma vez;
3. comando fora da allowlist sem efeito;
4. `recover-runner` produz runner `DESKTOP-PDQK954-runtime` online;
5. workflow do novo repositório faz pickup com label `desktop-runtime`;
6. runner legado do ReqSys continua disponível;
7. `recover-rdc` só é considerado funcional com leitura independente do transporte online.

Até essa prova, estado: `activation_pending`.
