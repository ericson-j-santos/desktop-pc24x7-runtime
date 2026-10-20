# Continuidade do desenvolvimento sem afinidade física

## Aplicação na PR #71

Código, revisão, testes determinísticos e correções de CI não aguardam o Desktop,
o Noteri ou outro computador pessoal. A fonte de retomada é a mesma branch/PR
no GitHub e seu SHA exato, nunca um working tree deixado em outro executor.

O workflow `CI` executa a suíte Python completa e os controles Node de admissão,
retomada e watchdog em dois executores hospedados independentes: Linux e Windows.
A falha de um ambiente não cancela o diagnóstico do outro (`fail-fast: false`).
O nome do check Windows existente foi preservado. Os testes não recebem segredos,
não fazem claim de tarefas, dispatch físico, deploy ou merge.

`tests/test_ci_portable_continuity.py` impede reintroduzir afinidade física,
dependência de admission, supressão dos testes ou permissões de escrita no CI.
A verificação não substitui o parser YAML do GitHub nem a leitura dos logs no SHA
final. Resultados skipped continuam sendo lacunas explícitas, não testes aprovados.

## Fronteira que não muda

O inventário de um Desktop real continua sendo uma etapa específica daquele host.
Seu workflow separado conserva canário recente, identidade exata, Session Launcher,
preflight, Gateway e leitura independente. A etiqueta `desktop-pdqk954`, incorporada
na main durante este incremento, também é exigida no seletor desse inventário.
CI hospedado verde não produz `physical_ready`, não comprova recovery/cutover e
não autoriza integrar a PR #71.

O bloqueio dessa etapa física não interrompe o desenvolvimento portátil.
Não alterar registro de runners, falsificar hostname, repetir canário sem
pré-condição nova nem criar commits vazios para simular continuidade.

## Componentes compartilhados e limites de ativação

Regras consultadas: `chatgpt-operational-rules/main@a430688c499077f5472841560f224c40766b0b78`
(1.6.12). A PR #162 acrescenta perfil POSIX de Gateway com raízes explícitas;
isso não instala nem qualifica automaticamente um host novo.

A continuidade com lease/fencing, checkpoint durável e S3/CAS pertence à
`engineering-worker-pool#34`, não a este runtime. Na primeira leitura ela estava
aberta no SHA `5ef413c1c18996bd022c20987fb75dbb9ec47712`. A revalidação confirmou
merge em 20/10/2026 às 14:12:31 UTC, commit
`e14870f9af1771de16594415c59fea6ec78e9135`. Esse merge não foi executado por esta
frente. A capacidade compartilhada não foi duplicada nem provisionada aqui;
merge de código não comprova o handoff operacional completo A→B.

A PR #71 foi sincronizada com `main@644ee0f8702a94b4d7beb6aca331884bbd1182dd`,
preservando os incrementos concorrentes de S3, backup, readback e isolamento de
runners. O teste de bootstrap conserva tanto a nova etiqueta quanto o ambiente
LOCALAPPDATA temporário; os mocks de plataforma do broker são isolados por teste.
O teste de draft herdado da main valida agora a matriz hospedada em vez de exigir
um único runner Windows, mantendo todos os controles de admissão física.

TODO Global permanece a fonte de estado. Esta PR e os commits/logs são checkpoints
de engenharia, não uma fila paralela nem confirmação de atualização do TODO Global.
Para handoff de tarefa em andamento, aplicar o contrato compartilhado de posse,
fencing, integridade e readback antes de executar efeitos em outro worker.
