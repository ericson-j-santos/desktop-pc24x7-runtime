# Supervisor do runtime PC24x7

O supervisor consolida as precondicoes locais que mais causavam recuperacoes
manuais: runner dedicado, Engineering Orchestrator e Worker Pool. Ele nao executa
shell arbitrario e nunca transforma uma tentativa de restart em sucesso.

## Politica de recuperacao

1. Sonda o componente e registra evidencia sanitizada.
2. Aplica somente a acao declarativa permitida para o tipo do alvo.
3. Limita a tres tentativas por alvo.
4. Abre o circuit breaker por 15 minutos quando a precondicao nao muda.
5. Retorna `INFRA_UNAVAILABLE` ate uma nova sonda comprovar saude.

O canario em `.github/workflows/runtime-canary.yml` roda a cada cinco minutos e
prova pickup do runner, versao do runner, Docker/Worker Pool e readiness do
orquestrador. A evidencia inclui SHA e `correlation_id` do workflow.

## Instalacao no host

Copie `config/runtime-supervisor.example.json` para o diretorio operacional
`%LOCALAPPDATA%\DesktopPC24x7\RuntimeSupervisor\config.json`. A tarefa persistente
deve executar o script com `--apply` a cada minuto e no boot, sob S4U, usando o
Command Gateway/Admin Broker. A instalacao nao deve depender de logon interativo.

O exemplo referencia apenas caminhos e nomes canônicos observados no host
`DESKTOP-PDQK954`. Alteracoes de host, URL externa, comando ou executavel
arbitrario sao rejeitadas.

## Limites

- O supervisor local nao substitui o segundo host fisico de redundancia.
- Noteri deve manter seu proprio servico persistente; o Desktop comprova sua
  presenca pelo estado do orquestrador, sem tentar administrar o host remoto.
- Reinicio do Docker Desktop exige capability administrativa dedicada e nao e
  inferido de uma falha isolada de container.
