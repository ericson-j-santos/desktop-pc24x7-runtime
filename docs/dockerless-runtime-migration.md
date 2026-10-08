# Transição PC24x7 sem Docker — execução faseada (2026-10-08)

Estado: **PROPOSTO / NÃO IMPLANTADO**. Origem: issue [chatgpt-operational-rules#128](https://github.com/ericson-j-santos/chatgpt-operational-rules/issues/128).
Este documento descreve a migração da camada física do PC24x7. Ações e lógica transversais de CI, Builder/Validator, Governed Merge Queue e Worker Pool pertencem ao Engineering Control Plane/ReqSys e devem ser alteradas nos respectivos repositórios, nunca duplicadas aqui.

## Decisão de arquitetura

- Estado-alvo **sem Docker Engine, Docker Desktop, Docker Compose, Podman ou Kubernetes**.
- Serviços permanentes de aplicação no Linux Debian/Ubuntu Server, com gerência nativa por `systemd`, execução por usuário dedicado, instalações por release/SHA e ambiente isolado por linguagem (`venv`, artefatos Node compilados, `dotnet`/Java quando necessários).
- Funções dependentes do Windows permanecem em Windows Services/Agendador: GitHub runner Windows, Command Gateway, Admin Broker, controles UAC, automações PowerShell e perfil NORMAL/ESTUDO do Noteri.
- Preferir os PCs já existentes, custo adicional zero; não converter preferência de host em prova de capacidade. O requisito de PC24x7-first continua válido.
- **Regra de transição:** preservar os runtimes Docker existentes e os seus checks enquanto os substitutos não forem comprovados no mesmo SHA e ambiente. Em nenhuma circunstância desligar o runtime anterior para deixar a CI verde.
- Não ativar Fly.io, Render automático ou qualquer provedor pago como fallback implícito.
- Nenhuma alteração em PROD, reinstalação de SO, exclusão de volume, mudança de segredo, abertura de portas ou reboot sem autorização explícita por alvo e ambiente.

## Matriz inicial — evidência em repositórios, não inventário físico

| Componente | Origem versão atual | Alternativa nativa | Principal pendência |
| --- | --- | --- | --- |
| TODO Gateway | `chatgpt-operational-rules/docker-compose.pc24x7.yml` | `scripts/install_todo_gateway_debian_systemd.py` já versionado | Completar equivalência para gateway, continuation worker, ingest e Postgres; E2E real |
| TODO Postgres | Volume `todo_global_pgdata` no Compose | PostgreSQL serviço Linux, role mínima, backup/restauração | Garantir migração dos dados originais; validar readback |
| ReqSys API/UI | `reqsys-v2-enterprise-real/infra/self-hosted/compose.yml` | FastAPI/venv + frontend Vue compilado servido por Caddy/Nginx nativos | Persistência, TLS, Entra/Azure, filas, E2E e restart |
| Redis/filas | Compose ReqSys e runtime | Redis nativo como serviço, persistência AOF se requerida | Integridade da fila, replay, recuperação e consumidores |
| Codex Worker Pool | `docker-compose.pc24x7-codex-worker-pool.yml` | Python `uvicorn`, serviço nativo no destino + SQLite protegido | Arquivo de token, volume SQLite, locks e leases, watchdog |
| Orquestrador / supervisor | `docs/runtime-supervisor.md`, canário GitHub a cada 5 min | Health de serviços do SO + probe HTTP + readback funcional | Remover dependência de Docker do canário sem falso verde |
| GitHub Actions | workflows/scripts Docker e possíveis container/service actions | Python `venv`, `npm ci`, `dotnet test`, PostgreSQL/Redis nativos de teste | Auditoria exaustiva, isolamento e equivalência de gates |
| Noteri | Windows com NORMAL/ESTUDO, integração de controller | Preservar serviço Windows e executar apenas funções Linux quando justificadas | E2E NORMAL -> ESTUDO -> NORMAL; ausência de regressão |

Referências: [regras do runtime](https://github.com/ericson-j-santos/chatgpt-operational-rules/blob/main/projects/runtime-platform.md), [instalador Debian](https://github.com/ericson-j-santos/chatgpt-operational-rules/blob/main/scripts/install_todo_gateway_debian_systemd.py), [ReqSys sem Docker em DEV](https://github.com/ericson-j-santos/reqsys-v2-enterprise-real/blob/main/scripts/dev-local.sh), [supervisor do Desktop](runtime-supervisor.md).

## Gate P0: inventário observável por host (somente leitura)

Registrar no checkpoint `host`, `os`, `cpu`, `ram_total`, `ram_disponivel`, `disk_total`, `disk_livre`, `run_id`, `sha`, `correlation_id`, `capturado_em` e o estado do Gateway/preflight. Inventariar processos/serviços em execução, Docker usado de fato, contêineres, volumes, portas, jobs de runner, dependências de inicialização e consumidores. Nunca exportar credenciais, conteúdo de `.env`, chaves, dados pessoais ou arquivos de volume.

- `DESKTOP-PDQK954`: Windows principal / runtime canônico até cutover; não assumir que todo contêiner versionado está vivo.
- `DESKTOP-RP23OGS` (Lenovo): candidato ao Linux, relatado com i5-8500T, 16 GiB RAM e NVMe ~256 GB. Esses dados são baseline informado, **não medição de headroom ou uso real**. Coletar RAM livre, CPU de pico e percentil, disco livre, IO, disponibilidade de rede e custos de coexistência. **Não reinstalar o Windows nem formatar o SSD com base neste documento.**
- `NOTERI`: manter governança e ESTUDO, sem interromper processos reservados; validar controlador e Command Gateway separadamente.

A leitura local deve usar o Command Gateway após `SESSION_LAUNCH_OK/state_validated=true` ou API oficial existente. Não recorrer a terminal irrestrito/GUI para contornar bloqueios. Um controlador offline não prova que o host esteja desligado.

## Gate P1: padrão de serviço nativo

1. Cada serviço deve ter usuário dedicado, arquivos de configuração privados fora do Git, processo sem privilégios elevados, diretório de estado/backup independente de código e unit/service com dependências explícitas.
2. Registrar versões exatas e fontes verificáveis de OS, Python, Node, PostgreSQL, Redis, Caddy e bibliotecas; instalar com lockfile/hash ou pacote versionado quando possível. Não executar atualizações automáticas incompatíveis com o binário em execução.
3. Usar releases imutáveis por SHA e ponteiro atômico para release ativa; manter release anterior, migração de schema compatível e procedimento de rollback. Não reverter schema com perda de dados.
4. Restringir Postgres/Redis/APIs administrativas à rede local ou loopback; TLS ingress apenas via caminho explicitamente autorizado; segredos por cofre ou arquivos com permissões mínimas. Evitar Docker socket, shells arbitrários e exposição de tokens em unit/log.
5. Implementar readiness (dependências críticas), liveness (processo), monitor externo independente, logs com rotação e recuperação limitada por circuit breaker. Um `systemd active` sem efeito funcional não comprova serviço saudável.
6. Para serviços sem `systemd` no Windows, usar a tarefa/serviço já governado por Admin Broker/Command Gateway; não instalar scheduler paralelo sem necessidade.

## Gate P1: migração de CI sem container e sem falso verde

Inventariar por workflow: `jobs.<job>.container`, `jobs.<job>.services`, `docker://`, `docker build/run/compose/inspect`, `Dockerfile` e scripts próprios. Classificar cada ocorrência como **execução ativa**, **teste**, **configuração/legado** ou **documentação**; referências textuais não provam dependência operacional. Auditar GitLab também.

Para cada fluxo afetado, substituir pelo equivalente com mesma cobertura e isolamento: venv efêmero + versões fixadas de Python, `npm ci` para frontend, banco PostgreSQL nativo isolado por job e cleanup obrigatório, Redis de teste efêmero por job, `dotnet test`/Java nativos quando existentes. Não rodar PR não confiável com permissões do host nem usar banco compartilhado com DEV/PROD.

**Aceite do workflow:** executou no HEAD esperado (não `skipped`), validou caso positivo, caso negativo pertinente, replay/idempotência e leitura independente do efeito; saída atual, logs/auditoria, cleanup realizado mesmo com erro. Não trocar check obrigatório de nome nem desabilitar branch protection para forçar merge. Corrigir regressões no mesmo PR e revalidar novo HEAD.

## Fases executáveis com critérios objetivos

1. **Inventário e capacidade:** checkpoints somente leitura de todos os hosts e workflows; matriz por ambiente, serviço, persistência, porta e consumidor; decidir se Lenovo atende por medições reais.
2. **Piloto TODO DEV sem corte:** usar instalador Debian existente, mas provisionar instância separada, sem consumir volume/portas da origem e sem redirecionar clientes. Completar serviços auxiliares e teste E2E.
3. **Persistência validada:** snapshot consistente e restore em DB novo; conferência de schemas, contagens/amostras, operações de escrita, replay, negativo e auditoria; demonstrar sobrevivência a restart. Reboot do host apenas após autorização específica.
4. **Worker Pool:** serviço Python nativo com SQLite e token protegidos, recuperação de lease, DLQ, watchdog, Builder != Validator e leitura independente; preservar contratos do Engineering Control Plane.
5. **ReqSys DEV:** banco/Redis, API, UI, proxy/TLS e identidades nativos; executar E2E autenticado e observar carga antes de transitar consumidores.
6. **CI por lotes:** converter referências Docker ativas nos workflows apropriados, priorizando checks obrigatórios. Não usar canário Docker como evidência de runtime nativo.
7. **Corte autorizado serviço a serviço:** comparar anterior/novo no mesmo ambiente, janela de escritas controlada, última sincronização, mudança de consumer/ingress, teste externo independente, rollback definido e retenção de backup.
8. **Aposentadoria Docker:** somente com dependências **ativas** zeradas e gates verdes; desinstalação/reboot/exclusão de volumes exigem autorização explícita de host e ambiente. Manter histórico versionado de componentes legados como evidência.

## Evidência mínima do primeiro incremento

- Branch/SHA único e diff revisável.
- Uma matriz de dependências executáveis por repositório e por host; ocorrências textuais sinalizadas como candidatas, não resultado real.
- Dados reais de capacidade Lenovo antes de qualquer escolha de SO.
- Piloto sem substituição do runtime ativo, E2E e persistência em DB restaurado.
- Registros `host`, `sha`, `environment`, `run_id`, `correlation_id`, health, readback, controle negativo, rollback e segurança.
- Falta de E2E ou de acesso ao host: **PARCIAL/BLOQUEADO**, nunca concluído.

## Estado em 2026-10-08

Somente evidência de repositórios e hardware previamente relatado; nenhum serviço migrado, nenhum contêiner removido e nenhuma capacidade Linux validada. Próxima ação objetiva: inventário não destrutivo nos hosts pelo canal governado e auditoria exaustiva de workflows para definir o piloto real.