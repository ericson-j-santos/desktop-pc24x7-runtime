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
- `/desktop-runtime admin recover-runner`.

`recover-control-plane` e `activate-watchdog` permanecem deliberadamente fora da
allowlist até o watchdog do novo repositório possuir task/runtime próprios. Isso impede
que a migração sobrescreva `\Automation\ReqSysDesktopControlPlaneWatchdog`.

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
- instalação da tarefa elevada não faz parte desta PR e exige autorização administrativa explícita.

## Critérios de aceite de código

1. compilação e pytest verdes no SHA atual;
2. controles negativos de autorização e anti-replay verdes;
3. testes provam repo/issue/task/runtime fixos;
4. testes provam ausência dos comandos de watchdog ainda não isolados;
5. testes provam uso exclusivo do bootstrap do runner novo;
6. CI de PR verde no HEAD exato.

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
