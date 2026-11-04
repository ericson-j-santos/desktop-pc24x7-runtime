# Sonda de cluster PostgreSQL 15/main — contrato de observabilidade DEV

- **Issue responsável:** [Runtime #134](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/issues/134).
- **Dependência do programa:** [Runtime #123](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/issues/123) e ReqSys Produto #3126.
- **Modalidade:** *feature* de coleta read-only, não reparo por IA. Não existe falha de `parse_clusters(raw)` comprovada no candidato que justifique inferência do Qwen.
- **Origem:** `scripts/native_wsl_pg_cluster_probe.py` e testes isolados, com reancoragem à `main` apenas após validação. O script não contém autorização de host nem dispatch de workflow; depende da admissão externa.
- **Execução permitida:** exclusivamente PC24x7 DEV autorizado, com `SESSION_LAUNCH_OK`, `state_validated=true`, sessão/worktree exclusivos, Command Gateway e SHA de origem exato. Sem Docker, sem custo adicional.

## Entrada → processamento → saída

**Entrada** — metadados oficiais de uma execução do runner, com autenticação e admissão verificadas pelo workflow e Gateway; não aceitar metadados vindos do usuário, issue ou relatório como prova externa. `GITHUB_SHA` e `RULES_SHA` devem corresponder ao SHA conferido pelo controlador.

**Processamento** — o `WslProbe._run` oficial só executa `wsl.exe --exec /usr/bin/pg_lsclusters -h` e `wsl.exe --exec /usr/bin/pg_isready -h 127.0.0.1 -p 5432 -t 3`, sem shell, sudo, consulta SQL, instalação, leitura de credenciais, alteração de configuração ou reinício. Saídas cruas e paths são descartados.

**Saída** — JSON sanitizado com estado do cluster 15/main, porta e disponibilidade observada. `cluster_ready` combina metadados do cluster e resposta local; não comprova que o socket consultado pertence ao cluster 15/main. Todos os flags `database_identity_verified`, `database_target_qualified`, `network_isolation_verified`, `backup_restore_verified` e `ready_for_installation` permanecem **false**.

## Matriz de validação

| Gate | Aceite | Evidência mínima |
| --- | --- | --- |
| Funcional local | cluster online/ausente/recusado, entrada inválida, duplicada e limite de saída | pytest separado, zero skipped |
| Integração real do código | interfaces `native_wsl_pg_qualification.WslProbe` e `native_windows_pg_inventory.provenance` de `main`, WSL simulado por transporte injetado | teste de integração com hashes das fontes reais |
| Sem falso sucesso | não ler secrets/SQL nem promover DB/rede/backup/deploy | controles negativos e revisão do comando fixo |
| Publicação | diff/ancestralidade, patch CAS SHA256, checkout independente, gates e PR draft governada | recibo Builder/Validator onde exigido; readback GitHub |
| E2E físico | runner elegível, Session Launcher, Gateway, SHA vigente e estado do banco não alterado | run_id + job_id + stdout sanitizado, releitura independente |

**Limites:** testes sintéticos (mesmo com módulos reais) não aprovam o E2E, implantação, identificação do banco ou backup/restauração. Uma execução de `pg_isready` com resposta positiva não estabelece titularidade. O fluxo de reparo por Llama/Ollama deve permanecer em trilha separada, condicionado a falha real versionada, modelo/digest comprovados e Validator independente. Não inventar baseline quebrado para obter `READY_FOR_PR`.

**Status inicial:** implementação e testes locais; integração/CI do SHA de publicação e E2E físico pendentes. Nenhum deploy/merge/autorização de risco 3 é dado por este documento.
