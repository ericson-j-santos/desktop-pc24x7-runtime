# Coleta governada da instalação Lenovo — DEV, somente leitura

**Escopo:** DESKTOP-RP23OGS / runner DESKTOP-RP23OGS-runtime. O DESKTOP-PDQK954 continua responsável pelo desenvolvimento; o Lenovo será Validator apenas após qualificação física. O Noteri não é fallback automático.

## Problema e correção

A PR [#148](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/pull/148) integrou o fluxo governado de upgrade, mas ele exige o SHA instalado e três hashes SHA-256 dos arquivos **já instalados**. Esses valores não podem ser inventados nem copiados de outra máquina. O runtime do runner GitHub pode executar como serviço LocalSystem e o watchdog como conta S4U diferente: usar \`LOCALAPPDATA\` do runner aponta para o perfil errado.

O novo coletor \`scripts/lenovo_control_plane_installed_inventory.py\` localiza a instalação **exclusivamente pela ação registrada da tarefa governada do Windows**, reutilizando \`lenovo_control_plane_pickup.task_runtime_readback()\`. Verifica launcher \`run.py\` e a árvore fixa \`DesktopPC24x7/ControlPlaneWatchdog\`; bloqueia redirecionamentos, caminhos externos e metadados incompatíveis. Lê duas vezes, sem alterar o disco, o \`metadata.json\`, o watchdog instalado, o UAC launcher e o \`run.py\`. Emite só SHA instalado, os três SHA-256 e hash da metadata; não imprime caminhos, perfil Windows ou credenciais.

## Intertravamento de perfil do atualizador (12/11/2026)

A revisão de código identificou **incompatibilidade potencial** entre a coleta e o atualizador da `main@2f1d6aa7487e3f2487d99c4859c486af305dd257`: o inventário resolve a pasta pela tarefa do Windows, mas `upgrade_desktop_free_control_plane.py::inspect_active_installation()` continua chamando `watchdog.default_runtime_root()`, derivado de `LOCALAPPDATA` do processo que o executa. `watchdog.load_installed_metadata()` também compara a pasta observada com esse padrão. Em execução do runner como LocalSystem e tarefa do watchdog sob outro usuário S4U, os caminhos podem divergir.

O inventário agora registra o booleano `upgrade_profile_root_aligned`, **sem revelar caminhos de usuário**. O valor é calculado sobre os caminhos físicos resolvidos: `false` quando não há `LOCALAPPDATA` confiável, a pasta não existe, há desvio de caminho ou a instalação da tarefa não corresponde ao perfil do executor. A coleta de SHA e dos três digests permanece somente leitura e pode funcionar com `upgrade_profile_root_aligned=false`.

**Um `true` não autoriza upgrade nem comprova identidade operacional; um `false` é bloqueio adicional do upgrade**, mesmo que os hashes tenham sido obtidos. Resolver por **reparo governado separado do atualizador**, com falha reproduzida, teste positivo e negativo, backup/rollback, sem mudar o perfil do runner ou afrouxar `watchdog.load_installed_metadata` para todos os hosts.

## Admissão e execução

Arquivo: \`.github/workflows/lenovo-installed-inventory-readonly.yml\`.

1. **Não disponível para dispatch enquanto estiver somente nesta branch.** Primeiro exigir pré-PR e PR draft com CI real do HEAD, revisão, controle de segurança e autorização de integração. O arquivo da branch não instala nem executa nada no PC.
2. Para uma execução futura, **antes de criar o run** confirmar por fonte independente que GitHub Actions tem hard stop de custo incremental de R$ 0,00. A condição \`vars.REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA == github.sha\` é um **bloqueio complementar**, não substitui prova de Billing, nem autoriza alterações em Settings. Valor ausente ou SHA diferente deixa o job inelegível.
3. O acionamento eventual tem somente \`expected_source_sha\` (SHA completo da \`main\` corrente) e confirmação fixa \`READ_ONLY_LENOVO_INVENTORY\`. Workflow manual, owner-only, tentativa 1, perfil DEV, labels exclusivas do runner Lenovo, gate de CI Windows + Linux do mesmo SHA e regras canônicas atuais.
4. Exigir \`SESSION_LAUNCH_OK\`, \`state_validated=true\`, Command Gateway com \`risk=1\` e \`--expected-head\` exato antes de executar o coletor fixo. Qualquer ausência bloqueia, sem RDC/GUI, Docker ou terminal genérico como alternativa.
5. A saída do job deve mostrar \`INSTALLED_INVENTORY_READ_ONLY\`, \`expected_installed_sha\`, \`expected_watchdog_sha256\`, \`expected_uac_sha256\`, \`expected_launcher_sha256\` e \`double_read_verified=true\`, com \`mutation_performed=false\` e \`upgrade_authorized=false\`. Confirmar job no runner físico por API GitHub, IDs de execução/runner, SHA, e releitura independente dos recibos e logs. Não aceitar apenas \`success\` ou texto de log como prova de origem.
6. Os valores podem alimentar o **preflight read-only** do upgrade existente, mas qualquer atualização continua a exigir **autorização específica**, backup, reversão e prova física posterior. A coleta não autoriza upgrade nem qualifica o Lenovo como Validator.
7. Não repetir job bloqueado se não mudou a condição: atualizar issue #147 com causa comprovada, dono e ação que desbloqueia.

## Validação conhecida, 12/11/2026

- Coletor e testes em branch isolada; **20/20 testes unitários locais executados antes do intertravamento; quatro novos testes de alinhamento de perfil adicionados, ainda aguardando execução independente**, com leitura GitHub dos mesmos blobs verificada.
- Workflows inspecionados por verificações estáticas de autorização, identidade, SHA, custo e risco, mas **CI GitHub e E2E físico ainda não executados** para esta branch.
- O workflow ainda não tem certificação operacional: \`PHYSICAL_INVENTORY_PENDING\` e \`COST_HARD_STOP_EVIDENCE_PENDING\`.
- Issue principal de recuperação: [Runtime #147](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/issues/147).
- Separação dos papéis e prevenção de colisões: [Regras #212](https://github.com/ericson-j-santos/chatgpt-operational-rules/issues/212).
- Certificação E2E das duas máquinas: [E2E Platform #10](https://github.com/ericson-j-santos/e2e-platform/issues/10).

**Dono técnico:** Runtime Platform. **Validação independente:** Engineering Control Plane e E2E Platform. **Nenhuma alteração administrativa, credencial, serviço ou runtime foi realizada na máquina física pela preparação deste código.**
