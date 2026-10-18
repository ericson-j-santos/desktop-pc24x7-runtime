# TODO Global — backup independente do Desktop

O backup lógico do PostgreSQL pode ser executado por GitHub Actions hospedado, sem runner self-hosted e sem sessão Codex/dot. Esta mudança está na PR #73 e não autoriza migração física.

## Fluxo e custo

A origem fixa é Neon PostgreSQL 18, no banco de homologação `todo_global_bus_dev_ha`, por conexão direta (não pooled) com TLS `verify-full`. O script reutiliza `pc24x7_todo_recovery.py` para exportar um arquivo custom de PostgreSQL e `pc24x7_todo_sealed.py` para criptografar em AES-256-GCM com chave pública RSA-OAEP.

O job do Actions usa `ubuntu-latest` com o contêiner PostgreSQL 18 fixado por digest. O agendamento proposto é diário às 04:27 UTC e só passa a executar após o workflow estar na main e os pré-requisitos reais estarem atendidos. Padrão GitHub hospedado em repositórios públicos não cobra minutos; o processo não utiliza armazenamento de artifacts ou caches. A cópia cifrada é armazenada apenas em uma *draft release* (rascunho não publicado) do GitHub, cuja listagem exige identidade autenticada com acesso de push ao repositório. Somente ciphertext fica fora do runner; nenhum dump plaintext ou chave privada é publicado. O upload exige nova leitura e conferência SHA-256.

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

O pacote inclui `tests/test_todo_hosted_backup.py` com testes sintéticos positivos e negativos, replay de uma cópia já publicada sem novo upload, ausência de acesso à origem em repetição, rejeição de corrupção, resposta de release publicada em vez de draft e prevenção de redirecionamentos autenticados. O E2E PostgreSQL 18 da mesma PR também percorre `todo_hosted_backup.run()`: captura local real, seal, transporte em memória, download após a limpeza do diretório do produtor, unseal e restore em um segundo banco vazio. SQL independente exige três eventos e uma solicitação, incluindo a escrita que não existia no primeiro snapshot do laboratório. A origem continua sintética e o transporte se identifica como `in_memory_fake_release`; isso não comprova backup de dados reais, acesso ao Neon por esta role ou download de Release real.

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

## Verificação final do armazenamento e revisão do produtor

A criação do rascunho usa o SHA completo de 40 caracteres em `target_commitish`. O executor registra esse campo em `release_producer_sha`, mas trata-o como metadado mutável do GitHub, sem transformá-lo em prova de captura. O replay mantém `source_sha=null`, `source_db=null` e o `executor_sha` da verificação atual. Rascunhos antigos sem revisão exata bloqueiam a rotina para revisão; o script não os sobrescreve.

Uma captura nova inclui `producer_sha` dentro do manifesto antes de cifrá-lo. No ensaio de recuperação, a identidade de recuperação deve autenticar e decifrar o arquivo baixado e conferir esse SHA com a revisão esperada. A inspeção do cabeçalho pelo produtor não substitui essa prova.

Após o download, o script relê o conjunto de assets e confere nome único, ID, estado, tamanho e digest. Por último, relê a Release e exige o mesmo ID, tag, SHA e `draft=true`. Publicação do rascunho, troca de asset ou alteração da revisão durante a operação reprovam o recibo. `storage_private_draft=true` descreve a última leitura; não garante imutabilidade ou privacidade futura.

## Limites operacionais e custo zero

As condições abaixo precisam ser verificadas antes da ativação e durante a operação. Não há upgrade de plano ou contratação automática neste pacote.

- O uso de runner hospedado padrão em repositório público é gratuito nas regras documentadas do GitHub. Isso não se estende a larger runners ou mudança para repositório privado.
- O dump e o arquivo cifrado não são enviados a Actions artifacts ou caches. O workflow de laboratório envia apenas um recibo JSON sintético, separado do armazenamento de backups.
- Neon Free inclui 5 GB de transferência pública por projeto por mês e uma franquia de computação. Exportações e consultas compartilham essas cotas com o restante do projeto. O limite de 64 MiB do dump é conferido **depois** da captura e não limita a transferência de rede. Medir consumo e margem na primeira captura autorizada antes de liberar a frequência diária.
- `pg_database_size` não é tamanho do dump nem consumo mensal de transferência. O recibo de upload também não comprova saldo da franquia do Neon.
- O GitHub pode atrasar ou descartar execuções agendadas sob carga e desativar schedules em repositório público após 60 dias sem atividade. A operação deve acompanhar a idade do último backup válido; o cron sozinho não garante RPO de 24 horas.
- Este executor pagina até 1.000 Releases e bloqueia se atingir o limite da busca. Não existe exclusão automática de cópias antigas. A política de retenção e o acompanhamento de backup vencido precisam de definição antes de operação prolongada.

## Roteiro do primeiro backup e da recuperação independente

1. Aprovar o provisionamento somente no banco DEV `todo_global_bus_dev_ha`, projeto Neon `snowy-dust-42639584`, branch `br-shy-bread-acm9qxm9`. A role `todo_backup_reader` precisa de CONNECT no banco, USAGE no schema `todo_bus` e SELECT nas tabelas e sequences desse schema. Não conceder escrita, administração, propriedade, replicação ou BYPASSRLS. Reavaliar RLS e novos objetos antes de ampliar privilégios.
2. Confirmar uma identidade de recuperação com a chave privada fora de Desktop, Noteri e runner produtor. Conservar a referência de custódia e o fingerprint público, sem inserir a chave privada no GitHub ou em logs. Só registrar `offhost-key-verified` depois da prova correspondente.
3. Provisionar as duas referências de secrets e as duas variables do environment `todo-pg-backup` por canal protegido. A senha pertence à role limitada; o PEM fornecido ao produtor contém somente a chave pública. Uma execução de PR não é um teste válido dessas referências.
4. Após aprovação da publicação na main, executar manualmente uma captura real pelo workflow. Conferir o recibo, SHA executado, Release em rascunho, asset, tamanho e digest. Confirmar que acesso anônimo não permite obter o asset; a listagem autenticada não comprova esse controle negativo.
5. Em recuperador independente autorizado, baixar o mesmo asset com identidade de push e verificar seu SHA-256. Executar o comando `unseal` de `pc24x7_todo_sealed.py` com o digest esperado e a referência local protegida `TODO_RECOVERY_IDENTITY_FILE`. Somente essa etapa autentica o AES-GCM.
6. Ler o manifesto decifrado, conferir `producer_sha`, correlação, versão e fingerprints. Preparar PostgreSQL 18 isolado, banco vazio com nome `todo_restore_*` e role local sem superusuário. Fornecer `PGSERVICEFILE` e `PGPASSFILE` privados e executar `verify-restore` de `pc24x7_todo_recovery.py` com `--bin-dir`, `--bundle` e a `--correlation-id` do manifesto.
7. Comparar tabelas, contagens e fingerprints do destino com o manifesto, executar SQL independente e repetir a recuperação para provar que ela não restaura nem duplica dados de novo. Registrar a preservação da origem. O resultado usa os dados do snapshot; escritas posteriores no Neon não podem invalidar a comparação com o snapshot já cifrado.
8. Vincular o recibo real de restauração ao run, commit e asset. Registrar consumo observado e margem de cota antes de liberar operação periódica. Até essa prova, manter o estado parcial, sem promover o primário ou iniciar workers. SEM restauração real independente, o serviço não está homologado.

## Pré-verificação observada em 18/10/2026

A leitura do banco de origem retornou PostgreSQL 18.6, oito tabelas em `todo_bus`, 109 eventos e 50 solicitações. A role `todo_backup_reader` não existia nessa leitura. Não houve criação de role, concessão de privilégios, captura de dados reais ou restauração fora do laboratório nesta verificação.

A configuração dos secrets e variables do environment e a custódia privada independente permanecem não verificadas. Ausência de acesso à API de secrets não é evidência de que os secrets estejam ausentes. A PR #73 continua sendo o ponto de revisão do código e das evidências do CI.

## Referências

- https://neon.com/docs/manage/backup-pg-dump
- https://docs.github.com/en/billing/concepts/product-billing/github-actions
- https://docs.github.com/en/rest/releases/releases
- https://neon.com/docs/introduction/plans
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule
