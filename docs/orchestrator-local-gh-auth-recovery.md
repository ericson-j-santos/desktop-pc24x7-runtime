# Recuperação local de autenticação GitHub para o Orchestrator DEV

Esta ação fixa recupera somente a autenticação do GitHub CLI no perfil Windows
`DESKTOP-PDQK954\windows`. Ela não instala ou ativa o runner ID21.

## Pré-condições

- Autorização do proprietário para recuperar a autenticação em DEV.
- Session Launcher com `SESSION_LAUNCH_OK`, `state_validated=true` e worktree
  limpo no SHA exato da versão revisada.
- Command Gateway na mesma sessão, risco 2, com `expected-head` igual ao SHA.
- Usuário presente no navegador do próprio Desktop para concluir o fluxo OAuth.

## Ação

O Gateway invoca `python -B scripts/orchestrator_local_gh_auth_recovery.py`
com `--expected-sha` e `--confirm RECOVER-ORCHESTRATOR-DEV-GITHUB-AUTH`.
O script fixa o host, o usuário Windows, o repositório, o perfil local e o
comando `gh auth login --hostname github.com --web --clipboard
--git-protocol https --scopes repo`. O código temporário fica somente na área
de transferência local; stdout/stderr do `gh` são suprimidos da evidência.
Não usar token de ambiente, PAT, sessão de outro host ou `--insecure-storage`.

## Leitura de resultado

`github_owner_validated` ou `owner_already_validated` exigem ainda um preflight
governado no mesmo perfil e SHA atual. `browser_authorization_incomplete`,
`browser_authorization_timeout` e demais estados bloqueados não autorizam
cadastro ou ativação do runner.

Depois do login, repetir `orchestrator_dev_runner_preflight.py` em modo somente
leitura. Somente após owner validado e demais gates verdes testar cadastro do
ID21 e obter readback independente. A ativação do runner é uma etapa separada.
