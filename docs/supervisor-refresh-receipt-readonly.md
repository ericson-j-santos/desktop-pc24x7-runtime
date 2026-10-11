# Coletor de recibo do supervisor — somente leitura

Escopo: exclusivamente o host `DESKTOP-PDQK954`, a tentativa `desktop-crlf-refresh-20261008-2116` e o SHA alvo `0426ea5283a511e7e98b8396e65fc6cf6cb1e620`.

`scripts/supervisor_refresh_receipt_probe.py` verifica arquivos de recibo do supervisor em uma raiz fixa de DEV, devolvendo apenas metadados estritamente limitados. Não aceita caminho/URL/correlação fornecidos pelo usuário. Não lê segredos, não altera arquivos, não tenta recuperação ou restart.

Limites de segurança:
- Os testes executados com arquivos temporários são sintéticos e não comprovam a leitura física do Desktop.
- O coletor ainda não foi instalado/registrado no Command Gateway nem no Admin Broker, e a raiz não foi verificada no host.
- O resultado é `trust=local_collection_unattested`, `authoritative_success=false`, `recovery_allowed=false`. Um digest SHA-256 não autentica quem produziu a evidência.
- A publicação no GitHub não autoriza execução no host. Para readback operacional é obrigatória uma sessão governada no Desktop com identidade comprovada, política explícita, segredo/assinatura de origem sob mecanismo aprovado e teste negativo.
- A validação Windows de CI verifica código e fixtures, não a recuperação do runtime. Não misturar com o retorno diagnóstico público do ntfy.
- Não promover a `main` antes de testes afetados, decisão de integração e readback autorizado.

Dependência: `reqsys-engineering-orchestrator#47`, `desktop-pc24x7-runtime#31`. Não repetir o refresh original sem recibo.
