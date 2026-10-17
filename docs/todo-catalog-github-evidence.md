# Catálogo TODO Global — evidência versionada no GitHub, dados preservados fora do Git

Checkpoint operacional: `todo22-canonical-catalog-20261017-v1`.
Estado: catálogo de metadados comprovado; **não** equivale a backup PostgreSQL, exportação integral do Notion, restauração do host ou liberação do cutover.

## Distribuição de responsabilidades

- **TODO Global / Notion:** continua como fonte canônica. O catálogo é uma projeção histórica somente leitura.
- **Google Drive privado:** mantém o ZIP íntegro com os 37 registros e seu recibo. O arquivo não é cifrado pela aplicação; manter permissões restritas e não torná-lo público.
- **GitHub público (esta PR):** armazena apenas checksum, tamanho, distribuição de estados, validador e testes sintéticos. Não hospeda o ZIP original, os IDs/URLs das páginas, as chaves de idempotência ou os dados do PostgreSQL.
- **PC24x7/Codex local:** futura captura PostgreSQL cifrada e restauração isolada, somente após preflight, Session Launcher/Gateway e custódia da chave.
- **Dot:** coordena checkpoints e bloqueios. Não substitui executor físico nem atua sobre dados privados apenas por possuir a referência.

## Evidência publicável sem exposição do catálogo

O manifesto sanitizado está em `evidence/todo-global/catalog-20261017-checkpoint.json` e fixa hashes do ZIP e do conteúdo selecionado, total e contagem por estado. O script `scripts/verify_todo_catalog_archive.py` valida o ZIP local recebido por canal privado, recusa arquivos extras, links simbólicos, alterações no manifesto, divergência de identidade/contagem e indicações de despacho/cutover. Reconstrói todos os 37 registros **apenas na memória** e verifica leitura e replay sem escrita. Não acessa rede, não lê chaves e não publica conteúdo.

Um checksum comprova integridade em relação ao valor versionado; **não** comprova autoria do backup, atualização em tempo real do Notion ou equivalência aos dados do Render/Neon. Não interpretar `catalog_verified` como `postgresql_backup_verified`.

Para validar a cópia privada em um ambiente autorizado, utilizar o verificador com a opção `--archive` apontando para um arquivo obtido privadamente do Drive e `--checkpoint` apontando para o manifesto sanitizado. A saída é apenas um resumo sem registros. O arquivo bruto nunca deve ser anexado à issue, PR, log, Action público, artifact ou commit.

## Política para segunda cópia completa no GitHub

Não colocar o ZIP original em repositório público. Uma segunda cópia contendo dados só é admissível quando houver **conteúdo cifrado antes do upload**, chave privada recuperável sob custódia independente, hash e autenticação conferidos no destino e autorização explícita do repositório/destino. Não usar automaticamente o GitHub Actions artifacts como armazenamento de desastre (expiração e cota) nem Git LFS sem avaliar faturamento. Repositório privado sozinho também não substitui criptografia nem backup de recuperação testada.

Enquanto tais condições não existirem, o Drive privado mantém a cópia de metadados e o GitHub mantém sua prova técnica e instruções. A PR #73 continua bloqueada para instalação/merge até completar seus gates de segurança. Não repetir os 109 eventos históricos do PostgreSQL por ler este catálogo.
