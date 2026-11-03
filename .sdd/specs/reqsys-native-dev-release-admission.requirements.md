# Requisitos — admissão da publicação nativa ReqSys DEV (#3126)

## Evidência inicial
A execução física Dedicated Runtime Runner E2E 41698530586 comprovou sessão/Command Gateway, WSL Linux e PostgreSQL ativo no Desktop PC24x7. Também mostrou systemd degradado, PostgreSQL ouvindo em interface wildcard, identidade do banco ReqSys não qualificada e ausência de prova de durabilidade, backup, reinício e prontidão para instalação. Nenhuma implantação ocorreu.

## Critérios de aceite
1. Aceitar apenas o inventário sanitizado de WSL com SHA do runtime, SHA das regras, run_id, correlação e host fixos.
2. Falhar fechado para schema inválido, strings no lugar de booleanos, host/sha incorretos ou indicadores de acesso sensível/mutação.
3. Classificar os bloqueios materiais de systemd, isolamento de PostgreSQL, identidade DB, persistência, backup e restauração, recuperação e instalação.
4. Não tratar flags fornecidas no JSON como atestação externa. Mesmo flags todas verdadeiras não autorizam publicação.
5. Não executar Docker, serviço, SQL, rede ou comandos do host. O diagnóstico não aplica qualquer alteração nem gera autorizacao.
6. Testar caso realista, falso sucesso sintético, controles negativos, replay idempotente e saída sanitizada no CI Windows/Linux.
7. Para implantar depois: publicador nativo imutável, autorização específica, backup/restauração isolada, rollback, E2E físico, identidade da versão e readback independente. Este incremento não entrega essa implementação nem comprova o DEV atualizado.

## Próxima mudança responsável
Runtime Platform deve qualificar o banco e preparar publicador/recuperador nativo com os controles acima. Não desativar o serviço legado até migração provada. Custo incremental R$ 0,00.
