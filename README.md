# Desktop PC24x7 Runtime

Runtime físico e plano de controle do host `DESKTOP-PDQK954`.

## Escopo

Este repositório contém somente capacidades exclusivas do Desktop PC24x7:

- watchdog/recovery do plano de controle local;
- recuperação governada do Remote Desktop Commander;
- health/readiness e evidência do host;
- startup/recovery e mecanismos fail-closed;
- integração do host com runners/workers por contratos explícitos.

## Fora de escopo

- regras de negócio do ReqSys;
- CI/merge queue/worker pool genéricos do Engineering Control Plane;
- segredos, tokens ou credenciais;
- promoção/deploy de HML, STG ou PROD.

## Governança

Fonte canônica de regras: `ericson-j-santos/chatgpt-operational-rules`, especialmente
`projects/runtime-platform.md`.

Durante a migração, o código operacional existente no ReqSys permanece intacto até
haver equivalência validada neste repositório, incluindo testes e evidência runtime
no Desktop.

## Estado

Repositório inicializado. A primeira migração é o plano de controle autônomo do
Desktop (watchdog + recuperação RDC), preservando comportamento antes de qualquer
remoção na origem.
