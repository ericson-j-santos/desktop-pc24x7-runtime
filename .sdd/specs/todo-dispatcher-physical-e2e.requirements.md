# TODO Dispatcher Physical E2E — Requirements

## Objetivo

Comprovar no `DESKTOP-PDQK954` o fluxo físico do dispatcher Pareto já implementado em
`ericson-j-santos/chatgpt-operational-rules`, sem duplicar lógica do Engineering
Control Plane no repositório de runtime.

## Fonte funcional

SHA imutável das regras operacionais:

`5d1f603241dde37a597d2b7bdc5e07425db7b451`

Harness canônico:

`scripts/github_schedule_bridge_e2e.py`

O runtime contém somente o adaptador host-specific e o workflow de execução física.

## Requisitos

1. Executar somente no runner dedicado do Desktop:
   `self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev`.
2. Validar `COMPUTERNAME=DESKTOP-PDQK954` e runner esperado.
3. Fazer checkout do runtime no SHA exato da execução.
4. Fazer checkout das regras no SHA imutável acima.
5. Inicializar sessão com `session_launcher.py` e exigir
   `SESSION_LAUNCH_OK` + `state_validated=true`.
6. Executar o adaptador somente por `command_gateway.py`.
7. Instalar dependência Python somente em `.tmp` da sessão governada.
8. Validar no harness:
   - P0 selecionado;
   - P2 não despachado no mesmo ciclo;
   - uma única continuação para o caso positivo;
   - replay sem nova continuação;
   - controle negativo sem continuação;
   - leitura independente do evento e da continuação.
9. Publicar artifact sanitizado sem token, segredo ou caminho de credencial.
10. Não executar deploy, produção, reboot ou mudança administrativa.
11. Se o runner não adquirir o job em 60 segundos, usar o watchdog canônico,
    falhar fechado e cancelar a execução estagnada.

## Critério de aceite

O incremento é validado operacionalmente somente quando o workflow físico concluir
com sucesso no mesmo SHA do runtime e das regras, e o artifact final indicar
`TODO_DISPATCHER_PHYSICAL_E2E_PASSED`, `independent_readback=true`,
`secrets_exposed=false`, `production_touched=false`,
`deploy_executed=false` e `reboot_executed=false`.

CI hospedado e testes unitários, isoladamente, não substituem essa evidência física.
