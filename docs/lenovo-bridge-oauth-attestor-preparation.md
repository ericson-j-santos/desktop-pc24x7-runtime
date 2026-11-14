# Preparação nativa de OAuth e assinador Ed25519 (Issue #151)

**Situação:** código auxiliar na PR draft #152; sem App instalada, sem consentimento real, sem cofre/assinador operacional, sem custeio ou recibo físico. O manual CAS original `docs/lenovo-inventory-api-bridge.md` foi preservado byte a byte conforme contrato do validador independente.

**Versão de origem:** `74f911b14cbf601395e2ebb9ecf6941cad73c8e9`. **Regras:** `58dcd4200f412a866278027ba9e433439a03f3b3` (v1.6.21). **Custo adicional:** R$ 0,00, sem recursos pagos ou autorização de execução.

## Código preparado (não ativado)
- `scripts/lenovo_bridge_device_oauth.py`: autenticação nativa por Device Flow para GitHub App autorizada, exige terminal interativo e consentimento oficial em `https://github.com/login/device`. Mantém o token `ghu_` somente em memória durante a chamada da ponte; verifica usuário, `app_id`, instalação única, `repository_selection=selected`, permissões exatas e apenas este repositório. Não cria App, não gera token sozinho e não altera direitos. Token de renovação descartado; a automação contínua exigirá um cofre externo autorizado e rotação separada. Não inserir códigos/tokens em chat ou logs.
- `scripts/lenovo_bridge_ticket_issuer.py`: função pura `issue_ticket` recebe **duas** evidências assinadas e válidas, de emissores independentes (autorização do proprietário e custo incremental R$ 0,00). Exige vínculo idempotente ao mesmo SHA, tarefa e pedido; recusa assinaturas falsas, divergência e vencimento. A chave privada é fornecida por serviço seguro EXTERNO e não fica no host da ponte. Esta função não implementa nem finge a existência dos dois emissores externos.
- Sem App instalada com consentimento, sem atestadores/autoridades externas reais, sem cofre protegido e sem confirmação de custo e runner, o fluxo real continua **BLOQUEADO**.
- Apenas após autorização: uso interativo de preflight somente leitura via `python scripts/lenovo_bridge_device_oauth.py preflight --sha <SHA-atual> --client-id <client-id-da-App> --app-id <app-id-da-App>`. Os argumentos são identificadores não secretos; nunca passar token em linha de comando.
- Um ticket real não pode ser produzido por parâmetro `--approved=true`, issue, chat ou referência de custo desacompanhada das assinaturas e comprovação independente.
- A ponte segue com SQLite de um único escritor. Failover entre PCs depende do Worker Pool com autoridade central, lease e checkpoint; os componentes aqui não implementam a operação física.

**Validação desta etapa:** testes isolados positivos e negativos em Python; não é OAuth real nem E2E físico.
