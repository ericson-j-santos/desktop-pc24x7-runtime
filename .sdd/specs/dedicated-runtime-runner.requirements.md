# Runner dedicado do Desktop PC24x7 Runtime

## Objetivo

Registrar um segundo GitHub Actions runner no host `DESKTOP-PDQK954` exclusivamente para `ericson-j-santos/desktop-pc24x7-runtime`, preservando o runner atual do ReqSys durante a migração.

## Requisitos

1. Host fixo `DESKTOP-PDQK954`, Windows x64 e ambiente DEV.
2. Repositório fixo `ericson-j-santos/desktop-pc24x7-runtime`.
3. Runner fixo `DESKTOP-PDQK954-runtime`.
4. Diretório dedicado sob `%LOCALAPPDATA%\\DesktopPC24x7Runtime\\GitHubRunner`.
5. Labels adicionais fixas: `pc24x7,desktop-runtime,runtime-dev`.
6. O runner atual do ReqSys não pode ser parado, removido, reconfigurado ou substituído.
7. Baixar somente o runner oficial 2.337.0 com SHA-256 fixado.
8. Preferir `GH_TOKEN` governado do workflow bootstrap. Se esse endpoint falhar, permitir somente fallback não interativo para a sessão local do GitHub CLI, após validar o login exato `ericson-j-santos` e remover `GH_TOKEN`/`GITHUB_TOKEN` do ambiente. O token de registro é efêmero, fica somente em memória e nunca é logado/persistido.
9. Registro remoto preexistente sem contrato local correspondente deve falhar fechado.
10. Replay com contrato local + registro remoto correto deve ser idempotente e não criar novo runner.
11. Sucesso local exige `Runner.Listener.exe` do diretório dedicado em execução e API GitHub com registro `online` + labels obrigatórias.
12. Sucesso terminal exige pickup real de workflow do próprio repositório pelo runner `DESKTOP-PDQK954-runtime`.
13. Produção, HML/STG e reboot ficam fora do escopo.

## Critérios de aceite

- CI e controles negativos verdes no SHA atual.
- Bootstrap publica evidência sanitizada.
- Registro remoto aparece exatamente uma vez.
- Job E2E executa no host e runner esperados, no mesmo SHA.
- Replay do bootstrap não duplica registro nem altera o runner do ReqSys.
