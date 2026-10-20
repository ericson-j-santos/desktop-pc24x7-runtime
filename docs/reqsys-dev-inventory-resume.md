# Retomada do inventário DEV da PR #71

## Defeito e limite

No HEAD anterior `79ac56d8b99b2d654ec9f8ad38a4fe32e2f70652`, a admissão recusava qualquer `run_attempt != 1`, mesmo depois de um canário dedicado novo e válido. O workflow só recebe push na branch de trabalho; criar commits sem mudança funcional para repetir a tentativa não é recuperação.

Esta correção permite somente retomar um run que falhou na admissão e cujas tentativas anteriores nunca executaram nem alocaram os jobs físicos. Não libera repetição de inventário físico, recuperação administrativa, deploy, banco ou merge. `FRESH_DEDICATED_CANARY_REQUIRED` continua bloqueante quando não existe prova física nova.

## Condições cumulativas

1. Mesmo repositório, workflow, branch e SHA; HEAD da branch e main revalidados ao final da leitura.
2. Canário dedicado concluído, no SHA atual da main, runner exato e etapas obrigatórias executadas. Na retomada, o canário deve ser um `workflow_dispatch` novo, primeira tentativa, criado depois de todas as tentativas anteriores do inventário e concluído antes do início da retomada. Validade máxima de 15 minutos.
3. Histórico de runs paginado e completo, sem concorrência, duplicatas ou contagem variável. Limite de leitura: 1.000 runs; acima disso o gate falha fechado.
4. Metadados e jobs lidos pelos endpoints de cada tentativa. Todas as anteriores devem ter falhado na admissão, com inventário e watchdog `skipped`, sem runner nem etapas. Artefato anterior de inventário também bloqueia.
5. O contrato hospedado deve executar novamente na tentativa corrente. `run_attempt` sozinho não basta: timestamps do job e de cada etapa obrigatória devem pertencer à janela corrente. Repetir somente jobs falhos não substitui essa condição.
6. A saída `admitted_attempt` vincula a admissão ao número da tentativa. Os dois jobs dependentes verificam esse vínculo na condição do job e novamente no código executado antes da ação. Uma admissão herdada não autoriza rerun isolado do job físico.
7. Recibos preservam a correlação run/tentativa e artifacts usam nome exclusivo por run/tentativa. O inventário continua usando Session Launcher, preflight do runner e Command Gateway Risk 1.

As leituras têm limites e falham fechadas; nenhuma API de dispatch ou recuperação foi adicionada. O limite de 50 tentativas acompanha o limite documentado de reruns do GitHub e não recomenda repetição. Cada retomada exige nova pré-condição real.

## Prevenção e evidências

`tests/test_reqsys_dev_inventory_admission.cjs` inclui a suíte de retomada no entrypoint hospedado já existente. A regressão compara a implementação nova com o blob anterior exato `01045f0155d1af353ef4c19d1b3559ee2ae61906`, preservado somente como fixture e verificado pelo hash Git. Os controles cobrem canário reutilizado, evidência herdada, histórico incompleto, divergência de SHA/tentativa, falha de API, privacidade, idempotência, parsers e guardas exatas do workflow.

Os testes usam fixtures de API e processos descartáveis no runner hospedado. Não comprovam pickup do Desktop. CI e logs devem ser verificados no HEAD final; recuperação só pode ser declarada após canário e inventário reais, com leitura independente de recibo/artefato no mesmo SHA. Regras consultadas: `chatgpt-operational-rules/main@dc9dff3fa8f8c9bcb970d295120f7e8e264d15f7`, versão 1.6.12. O pin operacional anterior do inventário não foi alterado por este incremento.

Dependências existentes: Desktop Runtime #31 e ReqSys #2546. Não criar outra PR, fila ou tarefa para repetir esse diagnóstico.
