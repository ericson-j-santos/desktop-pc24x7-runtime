# AGENTS.md

Este repositório implementa o runtime exclusivo do Desktop PC24x7.

Antes de qualquer alteração técnica:

1. consultar `ericson-j-santos/chatgpt-operational-rules` na branch `main`;
2. aplicar `README.md`, `AGENTS.md` e `projects/runtime-platform.md` da fonte canônica;
3. manter o host alvo fixo em `DESKTOP-PDQK954` para rotinas host-specific;
4. não introduzir lógica de negócio do ReqSys nem capacidades genéricas do Engineering Control Plane;
5. falhar fechado quando host, sessão, transporte, callback ou pós-condição não forem comprovados;
6. não registrar segredos, tokens ou credenciais;
7. exigir testes e evidência runtime no mesmo SHA antes de remover a implementação equivalente da origem.

Remote Desktop Commander é transporte, não terminal irrestrito nem fallback de GUI.
