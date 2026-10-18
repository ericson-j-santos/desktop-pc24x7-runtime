# TODO Global — backup independente do Desktop

O backup lógico do PostgreSQL pode ser executado por GitHub Actions hospedado, sem runner self-hosted e sem sessão Codex/dot. Esta mudança está na PR #73 e não autoriza migração física.

## Fluxo e custo

A origem fixa é Neon PostgreSQL 18, no banco de homologação `todo_global_bus_dev_ha`, por conexão direta (não pooled) com TLS `verify-full`. O script reutiliza `pc24x7_todo_recovery.py` para exportar um arquivo custom de PostgreSQL e `pc24x7_todo_sealed.py` para criptografar em AES-256-GCM com chave pública RSA-OAEP.

O job do Actions usa `ubuntu-latest` com o contêiner PostgreSQL 18 fixado por digest e é executado diariamente na main. Padrão GitHub hospedado em repositórios públicos não cobra minutos; o processo não utiliza armazenamento de artifacts ou caches. A cópia cifrada é armazenada apenas em uma *draft release* (rascunho não publicado) do GitHub, que exige acesso autorizado à conta. Somente ciphertext fica fora do runner; nenhum dump plaintext ou chave privada é publicado. O upload exige nova leitura e conferência SHA-256.

O executor constrói `PGPASSFILE` privado (0600) e `PGSERVICEFILE` com host fixo,
role limitada e CA do sistema. O comando `pg_dump -Fc` captura somente `todo_bus`
com snapshot consistente. Após armazenamento, `pg_restore` e a prova independente
de restore no PostgreSQL 18 continuam gates obrigatórios para a homologação.

## Provisionamento prévio obrigatório

O ambiente GitHub `todo-pg-backup` precisa ter referências protegidas:

- `TODO_BACKUP_PG_PASSWORD`: credencial já aprovada da role somente leitura `todo_backup_reader`, sem privilégios administrativos.
- `TODO_BACKUP_RECIPIENT_PEM_B64`: chave RSA **pública**, em PEM/base64, pertencente a uma identidade de recuperação independente.
- `TODO_BACKUP_RECIPIENT_SHA256`: fingerprint público dessa chave.
- `TODO_BACKUP_CUSTODY_APPROVAL`: literalmente `offhost-key-verified`, apenas após comprovação real de recuperação em ambiente independente.

Os controles não podem inventar secret, alterar permissões ou confiar em valor fictício. O script rejeita contexto fora da main, chaves não correspondentes, fontes diferentes, falta de credenciais e qualquer retorno de armazenamento sem confirmação independente. Não usar `GITHUB_TOKEN` em PRs; a permissão `contents:write` existe somente no job de backup na main.

## Comprovações

O pacote inclui `tests/test_todo_hosted_backup.py` com testes sintéticos positivos e negativos, replay de uma cópia já publicada sem novo upload, ausência de acesso à origem em repetição, rejeição de corrupção, resposta de release publicada em vez de draft e prevenção de redirecionamentos autenticados. O E2E PostgreSQL 18 da mesma PR testa captura e restauração sintéticas, mas não comprova ainda backup de dados reais ou download de Release real.

O recibo mantém `cutover_ready=false`, `database_restore_verified=false` e `offhost_custody_verified=false`. A autenticação e o armazenamento reais devem ser validados depois de configurar as referências; até lá não iniciar workers, não reprocessar eventos históricos, não apagar origens e não promover o primário. SEM restauração real independente, o serviço não está homologado.

## Repetição, destinatário e proveniência

O upload e a repetição inspecionam o envelope V1 completo: limites, JSON sem
campos duplicados, versão, fingerprint e tamanho da chave RSA encapsulada.
A chave pública aprovada deve corresponder ao destinatário do arquivo
baixado. Prefixo e checksum isolados não comprovam um envelope válido.

O recibo distingue `executor_sha` (código desta execução) de `source_sha`
(código que realizou a captura). No replay sem recibo de captura persistido e
vinculado ao ciphertext, `source_sha` e `source_db` ficam nulos;
`capture_executed=false`. O executor não atribui a versão atual a um backup
anterior e não reabre a origem nem cria upload para compensar divergência.

`envelope_structure_verified=true` e `recipient_matched=true` comprovam somente
estrutura e correspondência do destinatário. A inspeção não autentica AES-GCM,
não decifra o manifesto e não comprova posse da chave privada:
`ciphertext_authentication_verified=false` continua explícito. A homologação
exige autenticar/decifrar o asset baixado e restaurá-lo em PostgreSQL 18 isolado.

Uma draft release não é armazenamento imutável. A listagem de rascunhos é
restrita a identidades com permissão de push; a criptografia continua sendo a
proteção do conteúdo caso alguém com escrita publique o rascunho. O primeiro
E2E deve verificar também a restrição de acesso ao asset, com controle anônimo.

## Referências

- https://neon.com/docs/manage/backup-pg-dump
- https://docs.github.com/en/billing/concepts/product-billing/github-actions
- https://docs.github.com/en/rest/releases/releases
