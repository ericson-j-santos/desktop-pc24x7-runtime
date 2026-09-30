# Desktop stable bootstrap — executor diagnóstico governado

## Objetivo

Executar uma única vez, pelo runner dedicado do Desktop, o arquivo local já
confirmado e hash-validado:

`C:\\dev\\chatgpt-workers\\reqsys-orchestrator-24x7-runtime\\scripts\\Activate-Desktop-Stable-Bootstrap.ps1`

Esta fatia existe somente para desbloquear a migração do supervisor legado para
o bootstrap estável. Não é uma capacidade genérica de shell.

## Guardrails

1. Host fixo: `DESKTOP-PDQK954`.
2. Ambiente local/DEV.
3. Caminho do PowerShell fixo em código; nenhum path externo é aceito.
4. SHA-256 obrigatório do arquivo local:
   `377188bd48bacdd588c59510d50be16cd6bb7c32f21d7fc55a1f24e9a566d5bb`.
5. Confirmação literal obrigatória:
   `EXECUTE-CONFIRMED-DESKTOP-STABLE-BOOTSTRAP`.
6. Workflow roda somente no runner dedicado com labels
   `pc24x7, desktop-runtime, runtime-dev`.
7. Antes da execução: Session Launcher no SHA exato e Command Gateway risco 2.
8. O adapter Python usa argv fixo, `shell=False` e Windows PowerShell do sistema.
9. Sem GUI, clipboard, UAC, reboot, produção ou segredo.
10. Saída persistida é sanitizada e limitada; sucesso exige exit code 0 e
    marcador `REQSYS_DESKTOP_BOOTSTRAP_OK`.
11. Ausência de pickup não é sucesso; o watchdog hospedado cancela a execução
    sem progresso.

## Evidência

Artifact do mesmo run contendo host, caminho, SHA-256 observado, exit code,
marcadores de sucesso/falha e invariantes de segurança.
