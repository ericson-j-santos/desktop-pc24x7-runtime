# Worker Pool — bootstrap protegido de credencial S3 no Desktop

## Objetivo

Permitir que um chamador Python governado construa o transporte S3 do Worker
Pool no host `DESKTOP-PDQK954`, sem persistir a credencial em texto claro, sem
exportar `AWS_*` e sem depender de uma sessão interativa.

## Requisitos

1. A única entrada suportada para provisionamento deve ser `stdin` não
   interativo; argumentos, ambiente, arquivo intermediário e prompt são
   proibidos para o material da credencial.
2. A entrada deve usar esquema JSON exato e versionado, com rejeição de campos
   desconhecidos ou duplicados e limites explícitos de tamanho e caracteres.
3. O runtime deve operar somente no host Windows fixo e falhar fechado antes de
   ler `stdin` em qualquer outro ambiente.
4. O texto claro validado deve ser protegido por DPAPI `CurrentUser` com UI
   proibida. Machine scope, chave em arquivo e fallback em texto claro são
   proibidos.
5. O envelope persistido deve declarar contrato, versão e parâmetros de
   proteção, além de validar a integridade do ciphertext antes da
   descriptografia.
6. O destino deve ficar fora do Git, sob `%LOCALAPPDATA%`, com DACL protegida
   somente para o usuário atual e `SYSTEM`.
7. A gravação deve usar arquivo temporário exclusivo, flush, proteção da ACL,
   readback e publicação atômica create-only. Um destino existente ou criado
   durante uma corrida nunca pode ser substituído.
8. Reparse points, hardlinks, ACL divergente, envelope alterado, versão
   desconhecida ou readback divergente devem bloquear a operação.
9. Status, stdout, exceções e evidências devem usar somente reason codes e
   campos fixos; nenhum valor, ciphertext, endpoint ou caminho sensível pode ser
   publicado.
10. A API suportada de consumo deve entregar um cliente S3 já construído a um
    callback Python explícito. Ela não deve devolver credenciais em claro nem
    modificar o ambiente do processo.
11. O cliente deve receber credenciais e rota explicitamente, exigir TLS e
    SigV4, usar path-style, ignorar endpoints herdados e limitar novas
    tentativas.
12. O callback deve conseguir construir
    `S3GitBundleArtifactTransport(S3ArtifactConfig(...), client)` e o cliente
    deve ser fechado ao final, inclusive após falha.
13. A implementação não pode criar, rotacionar, instalar ou ativar credencial,
    serviço ou tarefa agendada durante a entrega de código.
14. A execução sob a identidade S4U real, o acesso DPAPI após reinício e um
    preflight funcional S3 permanecem gates físicos obrigatórios no mesmo SHA.

## Critérios de aceite

- testes unitários positivos, negativos e de não vazamento aprovados;
- arquivo persistido não contém os valores de teste e passa readback protegido;
- controles negativos cobrem stdin interativo, esquema inválido, envelope
  alterado, ACL inválida, corrida de publicação, rota inválida e ambiente não
  Windows;
- composição do cliente comprova parâmetros explícitos e ausência de mutação em
  `AWS_*`;
- documentação operacional registra o gate S4U como não comprovado enquanto o
  Desktop estiver offline;
- homologação física posterior comprova DPAPI + transporte S3 + retomada após
  reinício sob a identidade S4U da tarefa agendada.
