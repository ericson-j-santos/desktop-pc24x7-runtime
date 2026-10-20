# TODO Global — backup da fonte atual, independente do Desktop

Estado: implementação na PR #73; captura real externa, custódia independente e execução agendada posterior ainda precisam de evidência. Correlação: `todo22-notion-backup-20261019-v1`.

## Fonte e escopo

A decisão [sem Neon](todo-without-neon.md) permanece vigente. O produtor lê somente a data source autorizada do TODO Global no Notion. Desktop, Noteri, runners locais, dot e Codex não participam da execução periódica do GitHub Actions. O destino operacional PostgreSQL próprio continua uma frente separada.

O snapshot preserva o schema da data source, IDs e metadados das páginas, propriedades completas, blocos aninhados e páginas filhas acessíveis. Inclui as identidades e correlações já existentes; não recria tarefas nem transforma o histórico em eventos novos. A restauração constrói uma projeção inerte em PostgreSQL 18 nativo, sob `todo_notion_restore`, sem filas, consumidores ou corte canônico.

A leitura inicial agregada de 19/10/2026 encontrou 37 tarefas, 37 chaves de idempotência distintas e nenhuma chave vazia. Esse inventário não é um backup. Os IDs privados da fonte são referências protegidas e não estão neste repositório. A fonte disponível não comprova equivalência aos 109 eventos históricos do Neon; `historical_neon_data_recovered=false` permanece explícito.

## Captura que recusa um resultado parcial

`scripts/todo_notion_snapshot.py` usa a API oficial em `api.notion.com/v1`, com versão fixada, destino fixo, respostas limitadas e mensagens de erro sem corpo da API ou credenciais. Captura páginas, propriedades paginadas e blocos, e repete a leitura completa. As duas leituras precisam coincidir. Isso detecta mudanças observadas, mas não cria uma transação atômica no Notion: alterações entre chamadas continuam sendo um limite da API.

Cursores repetidos, páginas duplicadas, resposta `request_status` incompleta, truncamento, mudança de schema/conteúdo, limite excedido ou cardinalidade abaixo da referência reprovam a captura antes de upload. Propriedades com mais de 25 pessoas/relações/textos são lidas pelo endpoint próprio; IDs repetidos de `property_item` não são confundidos com páginas duplicadas. A referência mínima conta tarefas raiz; páginas filhas não compensam tarefas ausentes.

Esta versão não é uma exportação integral do workspace. Comentários, histórico de versões, permissões, conteúdo de fontes relacionadas externas e histórico exclusivo de bancos aposentados ficam fora do escopo. Arquivos binários, URLs de download temporárias, tipos não suportados, bases filhas e blocos sincronizados externos bloqueiam a captura; o processo não trata um link expirável como cópia de arquivo. Relações externas preservam referências sem ampliar silenciosamente o alcance do token. Alterações legítimas de escopo/cardinalidade exigem conferir a fonte antes de ajustar a referência.

## Criptografia e armazenamento

`scripts/todo_notion_sealed.py` usa a família `TODO-NOTION-SEALED-V1`, distinta do envelope PostgreSQL legado. O manifesto inclui correlação, SHA-256 dos bytes exatos do snapshot e SHA completo do produtor. O conteúdo é cifrado em AES-256-GCM; a chave aleatória é encapsulada para o destinatário RSA-OAEP de pelo menos 3072 bits. O produtor recebe somente a chave pública.

`scripts/todo_notion_hosted_backup.py` reutiliza o transporte de Release em rascunho já revisado. O nome diário combina família, hash do escopo autorizado e data UTC. Só o arquivo `.sealed` é enviado. O produtor baixa os bytes novamente, confere digest e destinatário, relê os assets e por último a Release, exigindo IDs, SHA, tamanho, digest e `draft=true` estáveis. Não usa artifacts ou caches para dados do usuário.

Um rascunho é mutável por colaboradores com escrita. A criptografia protege o conteúdo caso ele seja publicado indevidamente, mas não fornece imutabilidade nem disponibilidade permanente. Uma única cópia fora do computador não protege contra perda da conta de armazenamento; a retenção e a custódia precisam fazer parte da operação.

Na repetição diária com asset válido, não há nova leitura do Notion nem novo upload. O recibo mantém `source_sha=null`, `source_kind=null` e `capture_executed=false`, porque o produtor não tem a chave privada para autenticar a proveniência interna da cópia anterior. O SHA da Release é observado como metadado, não como prova criptográfica. `ciphertext_authentication_verified=false`, `decrypted_provenance_verified=false` e `database_restore_verified=false` persistem até a recuperação independente correspondente.

## Configuração protegida para a primeira execução real

O workflow `.github/workflows/todo-notion-backup.yml` admite testes sem segredos em PR/push. O job real só admite o repositório esperado, a branch `main`, um teste de segurança aprovado e os eventos `push` da própria `main`, `workflow_dispatch` ou `schedule` explicitamente habilitado. O `push` de uma branch de PR não recebe segredos porque a guarda exige `refs/heads/main`. Usa runner padrão `ubuntu-24.04`, environment `todo-notion-backup` e `contents: write` apenas nesse job.

| Local | Referência | Conteúdo |
| --- | --- | --- |
| Environment, secret | `TODO_NOTION_READ_TOKEN` | Token de integração Notion limitado à leitura do conteúdo autorizado, disponibilizado por canal protegido |
| Environment, secret | `TODO_NOTION_DATABASE_ID` | ID do database aprovado |
| Environment, secret | `TODO_NOTION_DATA_SOURCE_ID` | ID da data source aprovada |
| Environment, variable | `TODO_NOTION_MIN_PAGES` | Piso conferido das tarefas raiz; atualizar após leitura independente, nunca apenas para fazer um teste passar |
| Environment, secret | `TODO_BACKUP_RECIPIENT_PEM_B64` | Chave pública RSA em PEM/base64; nunca chave privada |
| Environment, variable | `TODO_BACKUP_RECIPIENT_SHA256` | Fingerprint da chave pública conferido com a custódia |
| Environment, variable | `TODO_BACKUP_CUSTODY_APPROVAL` | `offhost-key-verified` somente após prova real de custódia/recuperação |
| Repository, variable | `TODO_NOTION_SCHEDULE_ENABLED` | Manter ausente/false até evidência de recuperação real; então `true` |

A variável de schedule é de repositório porque a condição do job é avaliada antes de iniciar o runner. O token temporário de armazenamento é o `github.token` do próprio job. Não copiar o token do conector do chat; uma sessão de leitura no chat não entrega uma credencial de execução ao GitHub.

A autorização de execução já foi recebida. O bloqueio observado é de capacidade: a integração desta sessão não expõe escrita de environments/secrets/variables. `github_fetch` só admite os GET documentados e exclui secrets/admin; não deve ser usado como rota alternativa. O estado dos segredos existentes não foi inspecionado e não é declarado como ausente. A operação exige uma integração de entrega protegida com a permissão apropriada (`Environments: write` para secret de environment) e a referência verificável de custódia. Não inserir dados reais ou chaves em código, corpo de PR, logs ou chat.

## Recuperação independente

Antes de integrar a revisão na `main`, configurar as referências protegidas e comprovar a custódia independente. O próprio `push` do merge passa a ser a primeira tentativa real, eliminando a dependência de um dispatch manual para o bootstrap. Se qualquer secret, variável, fingerprint ou aprovação de custódia estiver ausente ou inválida, o produtor falha fechado antes de ler o Notion e não cria backup; esse bloqueio não deve ser contornado reduzindo o preflight. `workflow_dispatch` permanece como rota manual de repetição quando um executor autorizado o disponibilizar. Conferir run, SHA executado, tag, Release/asset, digest e tamanho por leitura independente. Verificar também que o asset não pode ser baixado anonimamente; a listagem autenticada não prova essa restrição.

Em recuperador autorizado independente de Desktop/Noteri e do produtor, baixar esse mesmo asset e conservar a referência externa do digest e do SHA esperado. A identidade de recuperação mantém a chave privada em arquivo protegido, apontado por `TODO_RECOVERY_IDENTITY_FILE`. O produtor não precisa dessa chave.

Preparar PostgreSQL 18 nativo e um banco isolado vazio com nome `todo_restore_*`. A role deve possuir esse banco e não ter superuser, CREATEDB, CREATEROLE, REPLICATION ou BYPASSRLS. Fornecer `PGSERVICEFILE` com a seção `todo_recovery_target` e `PGPASSFILE`, ambos protegidos; host deve ser `127.0.0.1` ou `::1`. A execução no host segue Session Launcher/Gateway governados. O utilitário não cria roles, banco, serviço ou credenciais.

A tarefa de recuperação invoca `scripts/todo_notion_restore.py` com `--source` para o `.sealed` baixado, `--expected-sha256`, `--expected-producer-sha` e `--bin-dir` para PostgreSQL 18. Os argumentos contêm referências e hashes, não senhas. A rotina confere hash externo, autentica/decifra, valida manifesto/snapshot, confirma versão e role, aplica transação com guarda de alvo vazio e lê o resultado por outra conexão. O conteúdo privado viaja para psql pelo stdin, nunca por argumento ou variável de ambiente.

São preservados os bytes exatos do snapshot, seu manifesto, schema e documentos completos de todas as páginas. A leitura independente compara SHA, conjunto de relações, chaves persistidas das páginas e conteúdo integral. A guarda de alvo vazio também inspeciona schemas de usuário iniciados por `pg`, sem confundi-los com o prefixo reservado literal `pg_`. Repetição válida é somente leitura. Alvo ocupado, alteração da projeção, chave errada ou origem divergente bloqueiam sem substituir dados. O restore não reconstitui automaticamente o workspace Notion, não implanta a aplicação e não inicia workers.

Registrar a evidência real vinculada a run/SHA/asset/digest e à identidade de recuperação. O recibo local mantém `offhost_custody_verified=false` e `external_download_verified=false`: esses fatos pertencem à prova do operador/executor independente, não podem ser inferidos de um arquivo local ou de um teste.

## Agendamento e aceite

O cron proposto é `43 4 * * *` (04:43 UTC). Depois da primeira recuperação real, habilitar a variável de repositório de schedule e observar uma execução posterior disparada por `schedule`, sem Desktop, Noteri, dot ou Codex. Repetir o download/restore dessa nova cópia para comprovar continuidade. O primeiro sucesso do produtor, inclusive no push do merge, não comprova execução periódica.

GitHub Actions pode atrasar ou descartar um schedule sob carga e desativar schedules de repositório público após 60 dias sem atividade. Cron sozinho não garante RPO de 24 horas. A operação precisa acompanhar a idade da última cópia restaurável e ter uma rota de recuperação quando o schedule falhar.

A meta é permanecer nos recursos gratuitos existentes. Não há contratação ou upgrade automático. O fluxo não usa larger runners; mudança de visibilidade/plano deve ser reavaliada. Snapshot é limitado a 64 MiB, manifesto a 128 KiB, e a busca de Releases a 1.000. Não existe exclusão automática de backups. Definir retenção e margem das cotas antes de operação prolongada, sem eliminar a última cópia comprovadamente recuperável.

## Evidência de laboratório e seu limite

`tests/e2e_todo_notion_backup.py` percorre captura paginada sintética, criptografia real, transporte em memória, novo download, novo processo de recuperação, PostgreSQL 18 nativo e SQL administrativo separado. Restaura três páginas, incluindo uma filha, propriedades maiores que o resumo da API e blocos aninhados. Exercita replay e controles negativos, incluindo alteração isolada da chave da página, objetos preexistentes em `pgbackup` e a guarda transacional de alvo vazio. O workflow nativo publica apenas recibos JSON sintéticos.

Os resultados efetivamente executados são registrados no checkpoint da PR com SHA e links dos runs. Nenhum teste sintético comprova dados reais, armazenamento externo real, custódia independente ou execução periódica. O aceite completo exige essas quatro evidências separadas; até lá `backup_homologated=false` e o TODO permanece parcial.

## Referências primárias

- [Query de data source e paginação](https://developers.notion.com/reference/query-a-data-source)
- [Propriedades completas de páginas](https://developers.notion.com/reference/retrieve-a-page-property)
- [Secrets de environment](https://docs.github.com/en/rest/actions/secrets#create-or-update-an-environment-secret)
- [Releases e rascunhos](https://docs.github.com/en/rest/releases/releases)
- [Execução agendada](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [Cobrança de GitHub Actions](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
