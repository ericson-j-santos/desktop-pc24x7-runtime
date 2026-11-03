# ReqSys DEV sem Docker — bloqueios para migração nativa

Evidência física de 03/11/2026: Dedicated Runtime Runner E2E #41698530586, runtime main 1603891f609916eb90a46d43c1188c21d2542802. Sessão governada e Gateway funcionaram, o WSL iniciou e o PostgreSQL estava ativo; isto não qualifica o banco ReqSys.

Bloqueios confirmados: systemd degradado, listener 5432 wildcard, identidade DB não validada, durabilidade, seleção de backup e restauração, restart e rollback sem evidência. A capacidade de armazenamento em outro volume é apenas uma possibilidade, não um backup aprovado.

O script scripts/reqsys_native_release_admission.py avalia um inventário sanitizado. Não executa comandos no host, nem Docker, não conecta ao banco e não autoriza deploy. O arquivo JSON é fonte declarativa, não prova externa de veracidade.

Ordem segura: examinar unidades systemd com falha por probe governado somente leitura; validar isolamento da porta; qualificar identidade real do DB com autorização e prova; validar armazenamento e backup com restauração fora da origem; comprovar retomada e rollback; implementar publicador com SHAs/digests imutáveis e lock idempotente; somente então executar E2E e readback independente do DEV em versão alvo, mediante autorização explícita.

A versão atual do ReqSys DEV continua independente desta proposta e não foi modificada.

## Sonda física de causa do systemd (incrementos nas PRs #125 e subsequentes)

A opção existente `native-wsl-postgres-qualification` executa, após a qualificação WSL normal, probes **somente de leitura** por Session Launcher e Command Gateway. O primeiro probe classifica as unidades falhas; `scripts/native_wsl_systemd_failure_details_probe.py` retorna nomes e propriedades fixas de `systemctl show`.

O `scripts/native_wsl_systemd_targeted_diagnosis_probe.py` acrescenta diagnóstico direcionado das unidades encontradas: lê somente propriedades fixas adicionais e até 24 registros de `journalctl --unit` em JSON. Mensagens brutas nunca são emitidas; são convertidas em códigos sanitizados, como `permission_denied`, `timeout`, `protocol_error`, `dependency_failed` e `process_exit`. A saída mantém `cause_proven=false` até existir evidência suficiente para afirmar causa-raiz.

Os probes nunca reiniciam, habilitam ou desabilitam serviços, executam SQL, consultam credenciais, alteram configuração, instalam pacotes, criam backup ou fazem deploy. Saída excedente, formato inesperado, unidade divergente ou journal de outra unidade bloqueiam a execução. O workflow não ganhou novo modo ou rota de dispatch; o diagnóstico físico continua exigindo integração autorizada e SHA atual de `main`.
