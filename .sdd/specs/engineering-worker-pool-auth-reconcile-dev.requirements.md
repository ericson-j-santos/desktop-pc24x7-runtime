# Engineering Worker Pool — reconciliação de autenticação DEV

## Objetivo

Eliminar a falha recorrente de autenticação causada por bind mount de arquivo de
token que permaneceu apontando para conteúdo anterior após substituição atômica no
host, sem rotacionar segredo e sem ampliar o escopo do runtime.

## Requisitos

1. Executar somente no Desktop PC24x7 em DEV, dentro do fluxo já governado por
   Session Launcher + Command Gateway.
2. Descobrir exatamente um container em execução com service
   `codex-worker-pool`, binding `127.0.0.1:8097 -> 8097/tcp` e bind mount
   único para `/run/secrets/codex_worker_pool_api_token`.
3. O arquivo host deve existir, ser arquivo regular, conter token não vazio com
   comprimento mínimo e nunca ter seu valor enviado a stdout/stderr/artifact.
4. A variável interna do container deve apontar exatamente para o destino
   canônico do token.
5. Antes de qualquer mutação, validar `/health` e leitura autenticada de
   `/v1/snapshot`.
6. A reconciliação automática só é permitida quando a API retorna `401` e a
   comparação em memória provar que host e container possuem conteúdo diferente.
7. Se host e container já coincidirem e a API ainda responder `401`, falhar
   fechado como `worker_pool_auth_process_mismatch`.
8. O fluxo não pode criar, substituir nem rotacionar token. Arquivo ausente,
   vazio ou inválido deve bloquear.
9. A recriação deve preservar:
   - mesmo projeto Docker Compose;
   - mesma imagem imutável `sha256` já em execução;
   - mesmo volume nomeado de estado;
   - mesmo arquivo host de token;
   - mesmo `CODEX_WORKER_POOL_EXPECTED_RULES_SHA`.
10. Recriar somente o serviço `codex-worker-pool`, com
    `--force-recreate --no-deps --no-build --pull never`.
11. O compose de recuperação deste repositório deve ser host-specific e não
    incorporar código do Worker Pool.
12. Após recriar, aguardar readiness com timeout limitado e exigir
    `/health=200` + `/v1/snapshot=200` autenticado.
13. Evidência deve informar apenas flags sanitizadas; nunca token, caminho do
    segredo ou conteúdo sensível.
14. Produção, HML/STG, deploy, reboot e rotação de segredo ficam fora do escopo.

## Critérios de aceite

- testes positivos e negativos aprovados;
- token válido e runtime saudável resultam em no-op idempotente;
- `401` + conteúdo divergente recria somente o serviço, sem rotação;
- `401` + conteúdo igual falha fechado;
- imagem não imutável, identidade Compose ausente ou contrato inválido bloqueiam;
- readiness autenticado é comprovado após recriação;
- smoke físico subsequente no mesmo SHA conclui
  `WORKER_POOL_RUNTIME_SMOKE_PASSED`.
