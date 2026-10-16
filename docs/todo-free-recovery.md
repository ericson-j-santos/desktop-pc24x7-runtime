# TODO Global — saída gratuita e recuperação independente do provedor

Estado inicial: implementação de recuperação isolada; não autoriza cutover.
Correlação: `todo22-free-recovery-20261016-v1`. Coordenação: TODO-22 existente.

## Decisão

Reaproveitar o PC24x7 e a arquitetura já versionada em
`chatgpt-operational-rules/docker-compose.pc24x7.yml`: PostgreSQL, gateway,
worker e ingestão. Não criar outro scheduler nem tornar Render necessário.
PDQ é o núcleo pretendido; RP executa desenvolvimento/validação e pode receber
cópia de recuperação quando seu inventário permitir. Noteri é opcional.
Custo incremental de licença/hosting: zero, utilizando hardware existente;
energia, internet, capacidade de armazenamento e cotas não são ilimitados.
Neon Free é fonte/cópia temporária acessível, não um novo primário automático.

Há três resultados diferentes: preservar o que está acessível, reconstruir a
operação, recuperar integralmente o histórico Render. Os dois primeiros não
precisam esperar por Render; o terceiro depende de dados originais ou backup.
Não fabricar equivalência, aprovações, leases, execução ou histórico ausente.

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
