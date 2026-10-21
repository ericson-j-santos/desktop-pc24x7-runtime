# Comprovação da custódia de chave para a recuperação gratuita do TODO

Este incremento faz parte da PR #73 do runtime PC24x7. **Não gera chave de acesso permanente, não altera o banco, não abre rede, não publica credenciais e não realiza backup.** Acrescenta apenas um protocolo criptográfico, limitado a quinze minutos, para verificar se uma identidade RSA previamente provisionada consegue responder a um desafio gerado pela chave pública usada nos backups `pc24x7_todo_sealed.py`.

## Contrato governado

1. **Emissor:** executor aprovado com a chave pública RSA de recuperação já existente em `TODO_RECOVERY_RECIPIENT_FILE`. Em um diretório de evidência já existente e protegido, a ação `issue` cria `challenge.json` e `issuer-receipt.json`. O recibo, que contém o HMAC esperado, nunca deve sair do ambiente do emissor. O desafio usa RSA-OAEP/SHA-256 com o mesmo identificador de destinatário e rótulo do formato de backup real.
2. **Recuperador:** **outro** executor governado e identificável, com acesso somente à chave privada correspondente em `TODO_RECOVERY_IDENTITY_FILE`, recebe `challenge.json` e o SHA-256 do desafio obtido do checkpoint confiável, nunca do próprio arquivo suspeito. A ação `answer` decifra um nonce efêmero e grava apenas `response.json` com HMAC do nonce vinculado ao desafio e à correlação; não grava nem imprime a chave privada ou nonce.
3. **Verificador:** o emissor recebe a resposta e a ação `verify` compara o HMAC contra seu recibo secreto, valida a identidade, a correlação e os quinze minutos de validade. A execução é idempotente, não executa restore nem produz evento de fila.

A CLI oferece ações `issue`, `answer` e `verify`, com caminhos absolutos, arquivos protegidos, rótulos e recibos JSON limitados. No host local executar **somente após** `SESSION_LAUNCH_OK` e por Command Gateway. O ator humano, dot ou Codex não pode inferir que é outro computador apenas por usar outra pasta: a **custódia fora da origem** exige evidência independente de identificadores distintos de host e sessão, com ACLs e cópia privada recuperável. **Por isso todo recibo criptográfico mantém `offhost_custody_verified=false` e `cutover_ready=false`.**

## Critérios de bloqueio e segurança

- Se a chave pública ou privada estiver ausente, com formato inválido, fraca (RSA inferior a 3072 bits) ou com ACL/mode incompatível, não iniciar nem prosseguir.
- O desafio deve estar dentro dos quinze minutos e seu SHA-256 deve vir de um registro independente e confiável. O recuperador rejeita arquivo adulterado, expiração, correlação inválida e chave de outro destinatário antes de criar resposta.
- Emissor conserva o recibo esperado em diretório protegido; resposta falsa, adulterada ou de outro desafio não comprova posse. Um desafio vencido não é renovado silenciosamente: usar outra correlação/diretório sob governança.
- A escrita usa criação exclusiva; arquivos parciais ficam intactos para investigação. Replay aceita somente identidade/correlação e conteúdo previamente verificados, sem renovar a janela ou sobrescrever recibos.
- O protocolo **não é autorização para exportar dados**, não substitui backup criptografado no Drive, `pg_dump`, teste real de restauração, segredo de conexão ou validação da continuidade física.
- Não anexar arquivos de desafio/recibo/identidade em repositório público, issues ou artefatos de CI. Testes CI utilizam apenas chaves e dados sintéticos dentro do runner descartável.

## Próxima etapa real

Confirmar a posse no recuperador autorizado **em host diferente** e retornar evidência autenticada de `host`, `session_id`, `repo_sha`, `correlation_id`, hash do desafio e do recibo — sem valores secretos. Registrar o gate como satisfeito somente após leitura independente de custódia fora da origem. Então usar os scripts já existentes de captura/cifragem/restauração sob a mesma PR/versão, armazenar arquivo cifrado no Drive privado, comparar SHA obtido por download e executar restore isolado sem iniciar consumidores. Nenhum papel, credencial, chave privada ou execução física é provisionado por esta documentação.
