# TODO Global — saída gratuita e recuperação independente do provedor

Estado: destino próprio aprovado; implementação/implantação e cutover não homologados.
Correlação: `todo22-free-recovery-20261016-v1`. Coordenação: TODO-22 existente.

## Decisão

### Destino definitivo aprovado em 18/10/2026

O proprietário aprovou seguir a recomendação de PostgreSQL próprio. O destino
definitivo é o PC24x7 elegível, com PostgreSQL 18 nativo, persistência sob controle
do proprietário e cópia portátil criptografada fora do host. Neon fica somente
como origem temporária dos dados atuais; consultar/exportar essa origem não é
contratar nem escolher o Neon como destino definitivo.

Reutilizar a transição [sem Docker já existente](dockerless-runtime-migration.md):
serviços permanentes em Linux Debian/Ubuntu Server com systemd, somente depois
de inventário de capacidade, compatibilidade e autorização do host. Funções
dependentes de Windows permanecem nos serviços/Agendador já governados.
Não reinstalar o sistema operacional, instalar um novo stack de contêineres,
reaproveitar volumes PG16 em PG18 ou interromper serviços existentes por esta
aprovação arquitetural. O Compose já versionado permanece legado/laboratório,
não é a instrução de implantação do novo destino nativo.

PDQ permanece o runtime canônico até corte autorizado. RP é candidato à
implantação Linux/recuperação após comprovação do inventário, não um destino
que já esteja instalado ou disponível. Noteri não vira dependência obrigatória.
Reaproveitar gateway, worker e ingestão; não criar outro scheduler ou outra fila.
O TODO Global continua sendo a fonte canônica de tarefas.

Aiven permanece apenas uma contingência gerenciada a avaliar se o destino próprio
não puder atender ao serviço. Não criar conta, banco ou migração na Aiven nesta
etapa, nem substituir um provedor por outro automaticamente. Não contratar
hosting, upgrade ou backup pago. PostgreSQL próprio elimina o prazo comercial
de um plano de hospedagem; energia, disco, rede, manutenção e atualizações
continuam necessários e não são uma garantia de custo total zero.

### Duas frentes independentes, sem recomeçar

**Preservação imediata:** usar o [backup hospedado existente](todo-hosted-backup.md)
para retirar uma cópia cifrada da origem acessível, quando acesso restrito e
custódia da chave estiverem habilitados. Esta frente não exige Desktop/Noteri
ligados. Não duplicar código, PR ou jobs; não reutilizar a conta proprietária como
atalho. A primeira cópia só conta após download, autenticação e restauração
independente, não após upload ou um teste com dados sintéticos.

**Destino definitivo:** preparar PostgreSQL nativo isolado no host autorizado,
sem redirecionar a aplicação nem iniciar consumidores. A configuração deve
manter autenticação protegida, conta de serviço limitada, porta restrita e
diretório de dados novo. Depois de restaurar, validar o esquema completo, dados,
persistência após restart autorizado e recuperação antes do corte.

A decisão aprova a direção e a preparação reversível. Criação/movimentação de
segredos, privilégios, troca de conexão, integração na main, migração de SO,
reboot, exclusão e ativação de consumidores continuam sujeitos à autorização
específica do alvo e ambiente. Nenhuma dessas ações é realizada por este documento.

### Inventário real de migração — leitura de 18/10/2026

Consultas pela integração oficial Neon em transações somente leitura retornaram:

| Propriedade | Valor observado |
| --- | --- |
| Servidor | PostgreSQL 18.6 |
| Banco completo, medido por pg_database_size | 9.003.008 bytes, aproximadamente 8,59 MiB |
| Relações de todo_bus, incluindo índices/TOAST e sequences | 770.048 bytes |
| Tabelas / sequences | 8 / 3 |
| Funções do schema | 15: 12 em plpgsql e 3 em SQL; nenhuma SECURITY DEFINER |
| Gatilhos não internos | 2 |
| Extensões instaladas | somente plpgsql 1.0 |
| Codificação e locale | UTF8, C.UTF-8, provedor builtin (b) |
| Eventos / solicitações | 109 / 50 |
| Role restrita todo_backup_reader | ausente na consulta |

Tamanho físico não equivale ao tamanho de pg_dump, RAM necessária ou consumo de
rede. As observações acima não são um backup nem certificam compatibilidade
completa: corpos das funções, dependências dinâmicas e execução de gatilhos não
foram testados nesta leitura. Preservar UTF8 e locale/provider na restauração;
não herdar automaticamente o locale padrão de outra instalação.

### Critério de corte e retorno

Restaurar primeiro em banco vazio todo_restore_*, com role não superusuária,
usando os utilitários da mesma PR/revisão. Além de contagens e hashes das tabelas,
conferir sequences, definições das 15 funções, dois gatilhos, constraints,
índices, proprietários e privilégios efetivos. Os fingerprints de linhas do
utilitário atual NÃO substituem essa validação de esquema e comportamento.

Conservar os eventos históricos sem replay. Provar um único evento novo
controlado na cadeia até o TODO Global, incluindo idempotência, em ambiente
isolado. Não liberar consumidores apenas porque as tabelas foram restauradas.

A troca para um único primário exige janela de escrita controlada e snapshot
final, leitura independente no destino e plano de retorno. Antes de aceitar
novas escritas no destino, pode-se manter/reapontar o cliente para a origem
inalterada; depois de novas escritas, o retorno exige reconciliá-las, nunca
apontar silenciosamente para uma cópia antiga. Não excluir Neon/Render,
backups ou volumes durante a migração.

A recuperação integral do histórico exclusivo do Render permanece separada.
Não fabricar equivalência, aprovações, leases ou histórico ausente.

Checkpoint: `todo22-own-postgres-decision-20261018-v1`. Estado da implantação:
PARCIAL; nenhum host instalado, dump real criado ou corte executado por este
incremento documental.

## Fonte e compatibilidade verificadas em 16/10/2026

A consulta somente leitura ao banco Neon `todo_global_bus_dev_ha` encontrou
PostgreSQL 18.6, oito tabelas `todo_bus`, 109 eventos, 50 solicitações,
109 registros de histórico de eventos e 195 de continuações. Os 109 eventos
estavam PENDING; solicitações: 35 COMPLETED, 14 HUMAN_GATE, 1 DLQ. Última
alteração dos eventos: 28/09; solicitações: 20/09. Não representa estado completo
atual do Notion nem equivalência ao Render; não ligar worker nessa cópia.
A branch Neon `preserve-todo22-20261016-v1` já existe. Reutilizá-la; não duplicar.

O Compose legado usa PG16 e volume `todo_global_pgdata`. O novo arquivo
`docker-compose.todo-recovery.yml` NÃO substitui esse Compose: usa PG18.6
por digest oficial, volume `todo_recovery_pg18`, porta loopback 55433 e
não contém gateway, ingestão ou workers. PG18 monta `/var/lib/postgresql`,
não o caminho de dados do PG16. Nenhum volume legado deve ser reutilizado.

## Implementação deste incremento

`scripts/pc24x7_todo_recovery.py` implementa somente `capture` e `verify-restore`.
Captura `todo_bus` por pg_dump custom com snapshot transacional exportado,
cria manifesto SHA-256 do arquivo e fingerprints ordenados de todas as linhas
por tabela. A origem é consultada em modo somente leitura. Uma escrita posterior
na origem não deve contaminar o snapshot. O dump é lógico, independente do Neon.

Restauração só aceita serviço local e banco `todo_restore_*` previamente criado,
vazio, com papel NÃO superusuário e versão compatível. `pg_restore` usa transação
única, sem `--clean`, sem criar/apagar banco, sem restaurar owners/ACLs antigos.
Depois, compara conjunto de tabelas, contagens e SHA-256 de conteúdo por nova
conexão. Repete por leitura do recibo + fingerprints, nunca por nova restauração.
Arquivo alterado, alvo ocupado, dados divergentes, versão antiga, concorrência
ou correlação diferente bloqueiam. Falhas de restauração não apagam o alvo;
manter isolamento, registrar a falha e revisar antes de tentar de novo.

Não é backup físico de cluster, exportação de roles/segredos/extensões fora de
`todo_bus`, prova de esquema completo, HA, autenticação da origem ou cutover.
Permissões devem ser reconstruídas por menor privilégio, não copiadas cegamente.
Manifesto verifica integridade; não é assinatura de autenticidade. Guardar junto
do dump em diretório protegido e fora de Git. O dump contém dados sensíveis.
Windows exige validação independente da ACL pelo preflight governado antes de uso.
O `PGPASSFILE` deve existir em caminho absoluto sem symlink/junction e, no Windows,
ter ACL protegida exclusivamente ao proprietário, conferida com os helpers
nativos `owner_sid`/`assert_private_acl`; herança ou falha de leitura bloqueia
antes da conexão com `PASSWORD_FILE_PERMISSIONS_UNSAFE`, sem alterar a ACL.
No Linux, permissões de grupo/outros também bloqueiam; o operador deve corrigir
o arquivo protegido por canal de segredos autorizado, nunca copiar senha ao chat.

## Execução sem comandos manuais recorrentes

Codex local, no host conectado e autorizado, é o executor de implantação.
Dot coordena e pode iniciar a tarefa local autorizada; não substitui permissões,
capacidade de host, Session Launcher ou Gateway. Codex Cloud serve para código
e laboratório PostgreSQL, não instala no PDQ offline. Esta conversa publica
código, testa e confere resultados por APIs; não é o servidor persistente.

Uma tarefa local deve consumir este commit e esta correlação, obter
`SESSION_LAUNCH_OK`, worktree exclusivo, inventário de portas/volumes, ferramentas
PostgreSQL aprovadas e arquivos de serviço/senha existentes em local protegido.
Não gerar segredos, cadastrar privilégios ou alterar serviços sem autorização
específica. `PGSERVICEFILE` define apenas `todo_recovery_source` e
`todo_recovery_target`: host, port, dbname, user e TLS. Senha é referência
`PGPASSFILE` protegida, nunca argumento/URL. Origem remota exige `sslmode=verify-full`.
Target usa IP loopback literal; nome `todo_restore_*`. A conexão de restauração
é dona desse banco isolado, não superusuária. O utilitário não provisiona esse papel.

Fluxo da tarefa: fonte preservada acessível -> capture -> dump/manifesto protegidos
-> destino isolado -> verify-restore -> leitura independente -> backup externo
criptografado e verificado no armazenamento autorizado -> revisão da reconciliação
com TODO Global. Só depois elaborar a promoção com primário único e rollback.
Não executar o Compose legado `up` para "testar": ele também inicia workers.
Não instalar PostgreSQL18 sobre os arquivos PG16. Não promover branch Neon.
O laboratório CI usa só dados sintéticos e não precisa de credenciais do usuário.

## Critérios de aceite e prevenção

Camada de código: controles positivos/negativos, corrupção, alvo incorreto,
PG16 incompatível, replay sem escrita, conflito de operação e erro sem segredo.
Camada PostgreSQL: snapshot sob escrita concorrente, dump real, restore real com
papel limitado, fingerprints, origem preservada, corrupção/drift rejeitados.
Camada física: repetir no host/SHA autorizado e dados preservados, verificar
backup externo restaurável. Camada produto: reconciliar lacunas, sem reexecutar
os 109 eventos históricos; provar um novo evento sintético controlado até Notion,
replay idempotente e retomada. Até lá `cutover_ready=false`.

O agendamento de backup e monitoramento de idade deve ser componente determinístico
local, não consumo contínuo de IA. A periodicidade, retenção e rota criptografada
externa são o próximo incremento, após esta restauração estar comprovada. Nenhum
agendamento ou instalação persistente é efetuado por estes arquivos.

## Referências primárias

- https://www.postgresql.org/docs/18/app-pgdump.html
- https://www.postgresql.org/docs/18/app-pgrestore.html
- https://hub.docker.com/_/postgres
- https://github.com/docker-library/repo-info/blob/master/repos/postgres/remote/18.6.md
- https://render.com/docs/free
- https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex
- https://help.openai.com/en/articles/20001530-getting-started-with-your-dot
