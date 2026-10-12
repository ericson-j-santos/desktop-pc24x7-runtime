# Orchestrator Desktop DEV — transação de cutover (preparação, sem ativação)

Checkpoint: 2026-10-12. Host permitido: `DESKTOP-PDQK954` e ambiente exclusivamente `DEV`.

## Estado de origem e destino

- Versão física antiga comprovada no último E2E: `33f312d0ac4c25d8420d4589fa0e8bc21d943ebd`.
- Head do Orchestrator lido no GitHub na preparação: `e23cc492827de6129ce78e9f4fc8bf592ce17ee8`. Este SHA é apenas **candidato de referência**; deve ser conferido novamente com a `main`, histórico aprovado e digest do artefato no momento do cutover.
- Código original: snapshot local com 36 arquivos e restauração isolada E2E validada pelo workflow #38297556070.
- Configurações e SQLite: backup local DPAPI e restauração em memória E2E, workflow #38308281308.
- Processo recuperado: servidor shadow local `127.0.0.1`, `/readyz` e `/healthz` válidos; teste do supervisor ativo e troca real ainda **não executados**.
- Job de reinstalação antiga #38188072157: **cancelled** sem pickup, após workflow de segurança #38309512448.
- `desktop-pc24x7-runtime/main` e `reqsys-engineering-orchestrator/main` sem proteção administrativa efetiva. No Orchestrator privado, a API de rulesets devolveu 403 com restrição do plano; no Desktop público, o conector não possui permissão de administração de proteção (403). Não trocar visibilidade, contratar plano ou contornar autorização.

## Portas obrigatórias antes de uma implantação de risco 3

1. Identidade física atual, runner e processos, version file, worker instance id e capacidades revalidados, com lease exclusivo e `SESSION_LAUNCH_OK` + Gateway.
2. Regras administrativas efetivas e verificadas nas duas `main`; CI obrigatória e impossibilidade de bypass, force-push e exclusão. Controles de CI que apenas reportam vermelho não equivalem a bloqueio real de merge.
3. SHA alvo pertencente à `main` no instante da execução, digest exato do archive por leitura independente, autorização específica de cutover DEV, reserva de manutenção sem jobs concorrentes.
4. Backup cifrado e íntegro do código, `service-config.json`, `worker-config.json`, `runtime-version.json`, Startup do usuário e SQLite consistente. Identidade da DPAPI e restore em memória conferidos sob o usuário do serviço.
5. Bootstrap de recuperação permanente separado do worker instalado e testado. Processo de rollback independente do ciclo do próprio worker atualizado.
6. Staging isolado da versão nova, testes de importação, schema e smoke em porta efêmera, sem migrar o banco original no preflight.
7. Gate antes do switch: versão anterior e snapshots imutáveis, estado journal durável, revisão do plano de restart, testes de falha e caminho de rollback praticado em ambiente descartável.
8. Corte físico **somente com executor risk 3 explicitamente autorizado**, usando compare-and-swap da versão anterior e lock. Verificar startup, readiness, identidade de processo nova, SHA efetivo, `worker_instance_id` renovado, capabilities e pickup independente. Em falha, rollback do código/config/SQLite/startup e revalidação do supervisor antigo antes de anunciar restauração.

## Evidência e limites do modelo

`scripts/desktop_orchestrator_cutover_model.py` tem apenas um exercício de transação em diretório temporário com sentinela de simulação. Ele usa journal, hash e controle de exclusividade, rejeita execução em diretório físico e **não possui CLI para instalar, reiniciar, interromper ou reverter serviços reais**.

O retorno `CUTOVER_REVIEWABLE` apenas considera um conjunto de fatos fornecidos para revisão; nenhum booleano informado por um caller pode autorizar a execução real. `recovery_allowed` é sempre `false`.

Falhas negativas exercitadas: SHA errado, host/ambiente errados, proteção administrativa ausente, risco 3 ausente, lock concorrente, journal incompleto, tentativa de replay adulterado, falta de sentinela de simulação, saúde insuficiente, troca parcial e rollback. O CI fornece evidência de **modelo**, não prova do cutover no Desktop.

## Ação administrativa pendente

Ativar branch protection/ruleset da `main` no Desktop público com CI materializável, `non_fast_forward`, `deletion`, revisões e proteção de administradores, e conferir `protected=true` pela API. No Orchestrator privado, resolver a indisponibilidade de regras do plano **sem tornar o código privado público por conveniência**; se o plano continuar sem enforcement, manter o cutover bloqueado ou aprovar explicitamente uma política compensatória com sua limitação (detecção pós-fato, não prevenção do merge).

Não usar o workflow antigo, registrar novo runner, repetir refresh expirado, reiniciar o Desktop ou acessar segredos em logs.
