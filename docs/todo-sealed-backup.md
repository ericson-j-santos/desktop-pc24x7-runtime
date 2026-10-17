# Backup portátil criptografado do TODO — incremento da PR #73

Estado: implementação e testes isolados; não é instalação física nem backup externo confirmado.
Integra `docs/todo-free-recovery.md`. Não substitui DPAPI, o Compose ou o primário existentes.

## Fluxo

O executor autorizado captura a origem com `pc24x7_todo_recovery.py`. Em seguida,
`pc24x7_todo_sealed.py` cifra somente `manifest.json` e `database.dump` em um arquivo
`.sealed`. O arquivo cifrado pode ser copiado para armazenamento privado autorizado.
Na recuperação, o executor confere o SHA-256 fixado no checkpoint confiável,
autentica e decifra para uma pasta nova e protegida e usa `verify-restore` no banco
isolado vazio. A chave privada nunca deve viajar com o backup.

A CLI aceita exclusivamente `seal` e `unseal`, com `--source` e `--destination`.
`unseal` exige `--expected-sha256`: esse valor vem do checkpoint independente,
não de um checksum reobtido do próprio arquivo suspeito. A CLI não acessa rede,
bancos, provedores, scheduler nem cria chave privada. Os caminhos devem ser
absolutos, sem links/junctions ou `..`, no worktree/diretório aprovado pelo Gateway.

## Referências existentes de chave

`TODO_RECOVERY_RECIPIENT_FILE` aponta para a chave pública RSA aprovada
(3072–8192 bits, expoente 65537). Só a pública é necessária para gerar a cópia.
`TODO_RECOVERY_IDENTITY_FILE` aponta para a chave privada correspondente já
provisionada em custódia separada, com permissões somente do proprietário.
Não passar material de chave no chat, argumento CLI, Git, log ou artefato.
A identidade PEM sem senha só é aceita dentro dessa proteção de arquivo;
PEM cifrado não é suportado nesta versão. Provisionamento/custódia real de chave
é um gate próprio e não foi realizado por esse incremento. Sem uma identidade
recuperável fora do host original, a cópia não pode ser aceita como backup de desastre.

Cada cifragem usa chave AES-256-GCM aleatória, nonce de 12 bytes e cabeçalho
autenticado; a chave de dados é envelopada com RSA-OAEP/SHA-256. A biblioteca
cryptography executa as primitivas. Não se trata de assinatura do produtor:
custódia da chave pública e do hash confiável continuam necessárias.
O formato suporta dump até 64 MiB e manifesto até 128 KiB. O processamento
usa memória; ao exceder os limites, interrompe em vez de truncar.

## Segurança, idempotência e recuperação

A origem não é apagada nem alterada. A trava `.operation.lock` é compartilhada
com a captura; outra trava protege a saída. Repetir `seal` só aceita os mesmos
bytes de entrada, destinatário e ciphertext já registrados no recibo. Repetir
`unseal` autentica novamente e compara os dois arquivos sem sobrescrevê-los.
Destino divergente, operação concorrente ou gravação parcial falham fechado.
Uma gravação interrompida pode deixar arquivos parciais para revisão; não há
limpeza automática de dados ou destravamento cego.

Antes de criar saída em claro, são verificados o SHA-256 esperado do ciphertext,
RSA, tag GCM, estrutura interna e digest do dump. A pasta e os arquivos recuperados
recebem acesso exclusivo do proprietário; no Windows são reutilizados os helpers
ACL já existentes e a proteção é relida. Não retornar plaintext nem erros de
criptografia com material sensível. O recibo local de cifragem não é prova de
upload: a cópia externa exige seu próprio readback, hash e exercício de restauração.

## Validação e limites de entrega

Os testes usam chaves e dados sintéticos. O E2E PostgreSQL existente é estendido
para capturar, cifrar pela CLI, copiar ciphertext, decifrar pela CLI, restaurar
exclusivamente o dump reaberto e ler as linhas por conexão independente.
Repetição, adulteração, hash incorreto e autenticação inválida são controles bloqueadores.
Só o recibo sanitizado do laboratório é publicado como artifact; chave e dumps não são.

Faltam aplicação no host/SHA autorizado, custódia de chave real, dump real cifrado,
armazenamento externo privado confirmado, restauração real, retenção agendada e
reconciliação do histórico antes de ligar consumidores. `cutover_ready=false`.
Codex/dot não foram despachados nem os hosts habilitados por este código.

## Referência primária

https://cryptography.io/en/stable/hazmat/primitives/aead/
