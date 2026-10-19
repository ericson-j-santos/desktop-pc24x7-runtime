# Continuidade sem Neon — decisão de 19/10/2026

Checkpoint: `todo22-without-neon-20261019-v1`.
Esta direção substitui o uso de Neon, inclusive como pré-condição de exportação,
para a continuidade operacional. Não executa a mutação de privilégios que foi
bloqueada, não acessa o provedor por outra rota e não apaga os dados antigos.

## Operação imediata

O TODO Global no Notion continua sendo a fonte canônica. A coordenação já pode
ler e atualizar tarefas por seu conector autorizado, preservando a mesma página,
chave de idempotência e correlação. O atendimento ao suporte, a criação da role
Neon e o dump desse banco deixam de ser dependências dessa rota.

Isso é continuidade assistida; não é prova de um worker autônomo 24x7. Os
registros atualmente disponíveis no Notion são fatos canônicos, não cópias
comprovadamente equivalentes a todo o histórico exclusivo do banco anterior.

## Persistência própria sem recriar a plataforma

O repositório canônico de regras já possui `scripts/todo_event_bus.py`, com
`DurableSQLiteQueue`, `SQLiteTodoSink` e `process_batch`. A versão consultada
foi `8a34b2b0862affb98a9e094e89802fdc6df090c0` (v1.6.11), incluindo o recibo
atômico SQLite anterior ao ACK para replay. Reutilizar o núcleo existente
para ensaios locais de durabilidade; não copiar a implementação para este repo
nem criar uma segunda fila ativa concorrente.

SQLite serve como núcleo local de validação e possível spool isolado. Não
substitui silenciosamente o Notion nem o destino PostgreSQL próprio aprovado.
O serviço persistente não foi instalado nos computadores por esta alteração.
A implantação nativa permanece condicionada a host autorizado, sessão/Gateway,
isolamento, backup e verificação após restart, sem Docker novo.

## O que mudou no workflow

`todo-hosted-backup.yml` mantém apenas triggers push/pull_request para testes
sintéticos sem credenciais. Foram retirados schedule e workflow_dispatch.
O job histórico de captura possui guarda literal `false` e não deve alocar
runner, environment ou segredo. A preservação do código é histórica, não
autorização de reativação. A suíte de política detecta reintrodução dos triggers,
remoção da guarda e acesso privilegiado no job de teste.

Os utilitários de criptografia/recuperação continuam disponíveis para um destino
próprio futuro. Não executar o script antigo contra Neon para superar a recusa.

## Reconstrução, não replay

Preservar as identidades existentes no Notion e obter uma projeção verificável
do estado atual quando necessário. Não transformar tarefas antigas ou os 109
eventos históricos em comandos novos. O histórico exclusivo não acessível fica
classificado como não recuperado, sem fabricar aprovações, leases ou conclusões.

A primeira integração nova deve transportar somente um novo evento autorizado,
verificar a escrita por leitura independente e demonstrar replay sem duplicar.
Um protótipo local e um conector operado pelo chat não comprovam autonomia.

## Critério de aceite

1. Testes locais realmente persistem SQLite, com rede negada e sem Neon.
2. Nenhum job de captura externa pode iniciar neste workflow.
3. Mudança da rota no TODO-22 tem leitura independente e preserva sua identidade.
4. Serviço nativo e ciclo assíncrono completo ficam parciais até implantação e E2E
   no ambiente autorizado. Não marcar o projeto CONCLUÍDO por estes controles.

## Preservação da fonte atual — incremento na PR #73

O [backup Notion independente do Desktop](todo-notion-backup.md) captura schema,
propriedades completas, blocos e páginas acessíveis, cifra antes de armazenamento
externo e restaura uma projeção inerte em PostgreSQL 18 nativo. O produtor
hospedado não depende de Desktop, Noteri, dot ou Codex. Sua rotina é separada
do workflow Neon aposentado; os bloqueios daquele workflow permanecem ativos.

Este incremento não copia a fila SQLite nem cria outra fila canônica. As
identidades atuais são preservadas como dados, sem replay de eventos históricos.
O E2E usa fonte/transporte sintéticos e banco nativo real. Captura externa dos
dados reais, custódia independente e execução agendada posterior continuam
gates de aceite; o serviço não foi instalado por esta alteração.
