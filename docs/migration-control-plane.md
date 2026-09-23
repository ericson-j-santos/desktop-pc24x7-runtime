# Migração — Desktop Control Plane

## Objetivo

Extrair do ReqSys o plano de controle exclusivo do host `DESKTOP-PDQK954`,
sem mudar comportamento e sem remover a implementação da origem antes da
validação equivalente neste repositório.

## Origem observada

Repositório: `ericson-j-santos/reqsys-v2-enterprise-real`, branch `main`.

| Arquivo | Blob SHA na origem |
| --- | --- |
| `scripts/desktop_control_plane_watchdog.py` | `4b4810063c54ad177d6364f0294ca0cbfbc73940` |
| `scripts/desktop_control_plane_watchdog_uac_launcher.py` | `161caaba4cc36e3e4bf08a7af16c89fc063fdb4a` |
| `scripts/pc24x7_rdc_recovery.py` | `446a24c52d6edc9b04ca0ba62cecdc4325f72fcf` |
| `.github/workflows/desktop-rdc-recovery.yml` | `51a42dab83bdf3256bb390ab466fbbc57c7dfddb` |
| `tests/test_desktop_control_plane_watchdog.py` | `9731c37ab4331733200cf29c0841173fd3fd53c6` |
| `tests/test_desktop_control_plane_watchdog_uac_launcher.py` | `ff58cbf3a6462796fca259a58b25d66c76de6e21` |
| `tests/test_pc24x7_rdc_recovery.py` | `4ed8f9a03805da046c5fcc683b11b2946f5eb1c9` |

## Limites desta fatia

Migrado agora:
- watchdog autônomo;
- launcher UAC restrito;
- recuperação RDC governada;
- testes e contrato do workflow.

Não migrado ainda:
- bootstrap/registro do GitHub Actions runner, pois hoje ele está acoplado ao
  repositório ReqSys;
- supervisor de containers/ingress do produto;
- lógica Teams/Cofre/ReqSys.

## Critério de conclusão

1. CI do código migrado verde no SHA corrente.
2. Workflow manual disponível no novo repositório.
3. Runner PC24x7 autorizado a executar o workflow deste repositório sem retirar
   prematuramente o acesso usado pelo ReqSys.
4. E2E no Desktop comprovando watchdog, recuperação RDC e pickup real.
5. Somente depois disso avaliar remoção/redirect da implementação na origem.

A referência histórica a `#1705` na especificação migrada continua pertencendo
ao gateway externo existente na origem até a etapa de desacoplamento desse contrato.


## Segundo runner isolado

A validação do novo repositório não pode reutilizar nem reconfigurar o runner repo-scoped
do ReqSys. A fatia `feat/isolated-runtime-runner` introduz um segundo runner com:

- repositório fixo: `ericson-j-santos/desktop-pc24x7-runtime`;
- nome fixo: `DESKTOP-PDQK954-runtime`;
- labels: `pc24x7,desktop-runtime`;
- diretório fixo: `%LOCALAPPDATA%\DesktopPC24x7\GitHubRunner`;
- sem descoberta de `C:\actions-runner`, `REQSYS_GITHUB_RUNNER_HOME` ou outros caminhos legados;
- sem instalação/substituição da tarefa watchdog existente;
- tokens de registro/remoção somente em memória.

A ativação real do runner permanece operação administrativa e não faz parte do merge de
código. O runner legado do ReqSys deve continuar funcionando até o E2E do runner isolado
no SHA atual e um cutover explícito posterior.
