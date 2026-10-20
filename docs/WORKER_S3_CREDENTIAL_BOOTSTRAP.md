# Bootstrap protegido da credencial S3 do Worker Pool

Este contrato prepara o runtime Desktop para consumir uma credencial S3 sem
persisti-la em texto claro, sem colocá-la em argumentos, logs ou variáveis
globais `AWS_*`. Ele não cria credenciais no provedor, não instala nem ativa o
Worker Pool e não comprova execução sob a identidade S4U.

## Limites do contrato

O script `scripts/desktop_worker_s3_credentials.py` aceita uma credencial
somente por `stdin` não interativo. A entrada é um objeto JSON UTF-8 com
esquema exato e versionado:

```json
{
  "aws_access_key_id": "<identificador>",
  "aws_secret_access_key": "<segredo>",
  "schema_version": "1.0.0"
}
```

`aws_session_token` é o único campo opcional. Campos desconhecidos, duplicados,
valores fora dos limites e versões diferentes são recusados. Os marcadores do
exemplo não são credenciais e não devem ser usados na instalação.

Um provisionador autorizado deve abrir o processo, escrever o documento no
`stdin` e fechá-lo. Ele não deve construir uma linha de comando com o valor,
salvar um arquivo intermediário, exportar `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` ou registrar o corpo recebido. O comando exige a
confirmação literal `INSTALL-DESKTOP-WORKER-S3-CREDENTIAL-V1`; a confirmação
não contém segredo.

O processo filho a ser aberto pelo provisionador é:

```powershell
python scripts/desktop_worker_s3_credentials.py install `
  --confirm INSTALL-DESKTOP-WORKER-S3-CREDENTIAL-V1
```

O documento deve ser enviado diretamente ao `stdin` desse processo por uma
fonte governada em memória. O estado pode ser verificado, sem fornecer `stdin`,
com:

```powershell
python scripts/desktop_worker_s3_credentials.py status
```

As APIs públicas não aceitam override do caminho da credencial. Testes usam
cores internos com dependências injetadas; a operação real usa somente o
destino canônico.

## Persistência e leitura

No host fixo `DESKTOP-PDQK954`, o destino canônico é:

```text
%LOCALAPPDATA%\ReqSys\EngineeringWorkerPool\protected-credentials\s3-credential-v1.json
```

O caminho fica fora do repositório. O conteúdo validado é protegido por DPAPI
no escopo `CurrentUser`, sempre com UI proibida. O envelope externo registra
contrato, versão, parâmetros de proteção e SHA-256 do ciphertext. Ele é escrito
em arquivo temporário exclusivo, recebe DACL protegida somente para o usuário
atual e `SYSTEM`, é descriptografado para readback e só então é publicado por
rename atômico. Uma credencial existente nunca é substituída.

Na leitura, o runtime recusa reparse points, hardlinks, envelope desconhecido,
ACL divergente, integridade inválida ou falha de DPAPI. O texto claro existe
somente em memória durante validação e criação do cliente. O status retorna
apenas campos fixos; ele nunca retorna identificador, segredo, token,
ciphertext, caminho ou endpoint.

Fora de Windows, no host errado ou sem `%LOCALAPPDATA%` absoluto, as APIs
públicas falham fechadas antes de ler a credencial.

## Composição explícita com o transporte

A rota S3 continua sendo configuração confiável do host, separada da
credencial. O chamador constrói `S3Route` e passa um callback explícito para
`run_with_s3_client`. A função descriptografa em memória, cria um cliente S3
com credenciais explícitas, TLS, SigV4, path-style, uma tentativa e sem herdar
endpoint configurado, chama o callback e fecha o cliente.

O adaptador do Worker Pool deve ser composto dentro desse callback:

```python
from app.s3_git_bundle_artifact import (
    S3ArtifactConfig,
    S3GitBundleArtifactTransport,
)
from desktop_worker_s3_credentials import S3Route, run_with_s3_client

route = S3Route(
    bucket="<bucket-confiavel-do-host>",
    region="<regiao-confiavel-do-host>",
    endpoint_url="https://<endpoint-confiavel-do-host>",
    key_prefix="codex-artifacts",
)

def execute_with_transport(client, selected_route):
    config = S3ArtifactConfig(
        bucket=selected_route.bucket,
        region=selected_route.region,
        key_prefix=selected_route.key_prefix,
        endpoint_url=selected_route.endpoint_url,
    )
    transport = S3GitBundleArtifactTransport(config, client)
    return execute_one_authorized_worker_operation(transport)

result = run_with_s3_client(route, execute_with_transport)
```

`execute_one_authorized_worker_operation` representa o chamador governado; não
é uma função fornecida por este repositório. O chamador não deve usar
`from_boto3`, `from_environment` nem copiar os valores da credencial para outro
objeto de longa duração.

## Status e rotação

`status` valida ACL, envelope, integridade e descriptografia sob a identidade do
processo atual. A saída positiva ainda registra
`s4u_identity_physically_validated: false`, pois uma execução interativa não
prova a identidade da tarefa agendada.

A instalação é deliberadamente create-only. Rotação exige um fluxo futuro que
grave uma nova versão em destino separado, faça preflight funcional, publique
atomicamente a referência ativa e só depois revogue a anterior. Apagar ou
substituir o arquivo manualmente não é um procedimento autorizado.

## Gate físico obrigatório

Com o Desktop disponível, a mesma release e SHA devem ser executadas pela
identidade S4U da tarefa que inicia o Worker Pool. A homologação deve provar:

1. `status` consegue descriptografar sem perfil interativo e sem UI;
2. o preflight S3 autorizado cria, lê, valida e remove apenas um objeto canário;
3. o Worker Pool constrói `S3GitBundleArtifactTransport` pelo callback explícito;
4. reinício do host e retomada continuam usando a mesma identidade e contrato;
5. controles negativos recusam outra identidade, ACL alterada, envelope
   adulterado, rota inválida e SHA diferente.

Até essa evidência existir, o bootstrap permanece implementado, mas não
instalado nem ativado. Uma falha S4U deve manter a rota bloqueada; ela não
autoriza fallback para segredo em arquivo claro, variável de ambiente ou sessão
interativa.
