# Issue #8 — Dell native Qwen RAG preflight

This is a **read-only physical qualification** of the existing authorized issue #8. It does not implement or certify an autonomous patch, CAS publication or draft PR. It reuses `engineering-worker-pool@be69b27455f99606a03ce5cba6ca809e1082f2b4`, official owner authorization comment #6427072933, and `agent-core@1fc032d4c412bdb4ed202cf1193caf0cb49490ce`.

Noteri's latest physical canary [#40247590037](https://github.com/ericson-j-santos/noteri-runtime/actions/runs/40247590037) was fail-closed with `native_model_ambiguous_or_missing`. Do not install, rename or download a model to bypass attestation. Dell successfully executed native Qwen with the matching GGUF digest in [#40221994125](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40221994125). This experiment qualifies *issue-specific* evidence on that alternative host instead of repeating Noteri's known blocker.

Gate: PR draft, one-shot body marker `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_ONCE` added only **after** Windows/Linux required CI; hosted admission checks current repo main, Worker Pool main SHA, OWNER authorization, exact source blob, canonical rules and four-file scope. Physical runner must be DESKTOP-PDQK954-runtime (ID 2); exact SHA checkouts, Session Launcher `SESSION_LAUNCH_OK`, Command Gateway risk-2 isolated venv and risk-1 issue RAG, real 42-case baseline with failure, local Qwen with pinned GGUF digest, immutable GitHub citation and independent hosted readback. Watchdog blocks without pickup in 300 seconds. All artifact data bounded, no credentials in source/logs. GitHub artifact retention is 2 days.

No Docker on Dell, no cloud inference, no service install, no patch, no CAS write, no model-directed command, no merge/deploy. A failure requires evidence-based repair, not a blind retry. Even full success leaves the next task pending: one real Qwen patch -> CAS git bundle -> independent validator 42/42 + 52/52 -> exactly one agent-generated draft PR -> readback/replay.

SHA rule pin: 92e8b5c87684212964b24ff3597f9f9f8aea49a6. Correlation: `issue8-dell-native-rag-20261026`.

The hosted contract also installs pinned PyYAML. Admission now enforces
exactly five authorized paths including the CI syntax check, and GitHub GET
requests use only the existing bounded token supplied through Actions env.

## Result of first Dell issue-bound probe

Run [#40368039499](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40368039499) established the authenticated issue #8, physical runner ID 2, Session Launcher and Gateway, and actually invoked Qwen. It then blocked with `issue8_real_rag_not_verified` (the original combined condition did not isolate refusal, head drift, model process, readback or call count). Independent source readback was skipped as required.

This revision **does not relax** the RAG acceptance. It emits one of the finite reason codes under `issue8_rag_*`, including a model decision of insufficient evidence, while keeping the workflow fail-closed. The previous one-shot marker is consumed. Only a separate owner-only body transition to `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_PTBR_MERGED_ONCE`, after SHA-specific Windows/Linux CI and renewed admission, authorizes another physical diagnostic run. Do not retry if no material change was made.


## Próximo canário — correção PT-BR integrada em SHA autorizado

A pesquisa RAG da issue #8 no Dell falhou com evidência insuficiente no run
#40369704989. A PR Worker Pool #56 corrige apenas a pontuação dos trechos
portugueses; foi integrada à main no SHA `be69b27455f99606a03ce5cba6ca809e1082f2b4`, com
blob `7d27e62e296bafd3079ed37d72b4e817917a76fe` de `app/issue_rag_research.py`.
A fonte `app/portfolio_bridge.py` mantém o Git blob anterior, e o
proprietário publicou a autorização SHA-bound #6427072933 específica da nova
main. Este canário usa somente o código integrado na main e exige readback
da versão de pesquisa, sem segundo checkout experimental. O marcador físico
único é `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_PTBR_MERGED_ONCE`. A recusa do modelo continua bloqueando qualquer
aprovação, PR, CAS, merge ou deploy.


## Recuperação da consulta de CI remoto (26/10/2026)

O disparo de `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_PTBR_MERGED_ONCE`
produziu [run #40376199312](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40376199312): contrato aprovado,
mas a admissão hospedada falhou **antes de pickup do Dell** por HTTP 500 do
GitHub API `GET /commits/047c77b6.../check-runs`. Isso não é CI reprovado
nem falha de RAG. A nova leitura GET-only usa até três tentativas para 429 e
5xx transitórios, intervalos limitados e erro estático sanitizado em resposta
permanente ou após esgotar tentativas. Ela nunca substitui a verificação de
`completed/success` no SHA exato por uma aprovação presumida.

O teste executa o helper JavaScript com Node: 500→500→200, rejeição imediata
de 403, esgotamento de 503 e rejeição de resposta malformada. A recuperação
física exige novo marcador `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_HTTP500_RECOVERY_ONCE`, transição única após CI positivo
e todas as mesmas revalidações de owner, Worker Pool e custo. Não repetir
marcadores consumidos nem modificar serviços, patch, CAS ou produção.


## Recuperação de GET autenticados em admissão e readback (26/10)

O segundo run [#40377362575](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40377362575) passou no contrato, mas foi bloqueado **antes do Dell** por HTTP 500 ao ler o comentário OWNER via API GitHub. Isso confirma instabilidade transitória em mais de uma rota GET, não CI/owner reprovado.

Agora as dez consultas de admissão e as sete consultas de readback são **sequenciais** e usam tentativas limitadas (até três) para 429 e HTTP 500/502/503/504. Erros 403/404, respostas vazias, esgotamento das tentativas, SHA/OWNER divergente ou checks não executados falham fechado. Um teste Node executa controles positivos/negativos da função de retry, e o readback exige citação em fonte allowlisted antes do GET. Novo marcador de execução única: `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_API_GET_RECOVERY_ONCE` após CI aprovado no novo HEAD. Não repetir runs anteriores nem promover skips a sucesso.


## Diagnóstico sanitizado da recusa Qwen RAG — 26/10/2026

O run físico [#40378386092](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40378386092), SHA `427e8ea914e8fd1cf8de464e2e8c18131a46a5a5`, concluiu admissão, Session Launcher, Gateway e iniciou inferência local, mas falhou com `issue8_rag_insufficient_evidence` na fase `research`. A leitura independente de sucesso foi corretamente ignorada. A correção PT-BR da PR Worker Pool #56 não resolve comprovadamente essa recusa.

O diagnóstico não modifica `research_issue`, seleção, ranking, prompts ou respostas do Qwen. Se o recibo apresentar recusa, identidade e SHA atuais, hash íntegro e processo atestado, registra somente fontes allowlisted, quantidade de fontes, número de chamadas do modelo e número de seleções tentadas. O caso `no_candidate_snippet` significa que nenhuma seleção de citação foi solicitada. `model_declined_candidate` significa que houve ao menos uma seleção sem citação aceita. Esses estados não comprovam quais linhas individuais foram apresentadas; uma investigação de candidatos requer telemetria posterior na fonte do Worker Pool. Nenhum texto de documento, prompt ou resposta bruta é publicado.

A regra de recusa permanece FAIL-CLOSED: a etapa física falha, o readback de aprovação fica indisponível e não se publicam CAS, Validator ou PR de agente. A única nova autorização de teste via edição da PR é `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_INTEGRATED_SOURCE_ONCE`, após checks realmente executados no HEAD atualizado e revalidação de owner/rules/runner/custo. Sem Docker, Neon, merge, deploy ou custo incremental.

## Alinhamento de regras no preflight (26/10)

A regra canônica `chatgpt-operational-rules/main` avançou de `92e8b5c87684212964b24ff3597f9f9f8aea49a6` para `8af10e2cf85f18f14ba12fbbeb4afc8b8320bbe8` após a PR #181 (sonda WSL do Noteri); o pin atual de código e workflow foi atualizado para `8af10e2cf85f18f14ba12fbbeb4afc8b8320bbe8`. As versões históricas mencionadas acima permanecem apenas evidência das execuções anteriores. Nenhuma política foi ignorada nem relaxada.
