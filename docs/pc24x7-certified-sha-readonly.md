# Conferência automática do SHA certificado — PC24x7

**Origem:** ericson-j-santos/desktop-pc24x7-runtime, main. **Regra global:** chatgpt-operational-rules/main `58dcd4200f412a866278027ba9e433439a03f3b3` (v1.6.21). **Implantação:** depende de PR e merge autorizados; não está operacional enquanto só existe em branch.

## Comportamento

O workflow `.github/workflows/pc24x7-certified-sha-readonly.yml` executa após cada atualização de `main`, diariamente às 11:23 UTC e por acionamento manual do proprietário. Lê o valor efetivo da variável `REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA` pelo contexto `vars` do próprio GitHub Actions, sem credencial privilegiada nem acesso à tela de Settings. Consulta `main` pela API do GitHub (GET) com permissão `contents: read`; não altera dados.

O job termina **verde** apenas quando: repositório/branch corretos, evento no SHA atual da `main`, variável presente, SHA hexadecimal completo e igualdade exata. Caso contrário termina **vermelho** com código `CERTIFIED_SHA_READONLY_*` (ausente, inválido, divergente, execução desatualizada ou proprietário incorreto em ação manual). Em *Step summary* mostra os SHAs válidos e o motivo, sempre com `Alteração de variável: NÃO` e `Disparo de inventário: NÃO`.

### Limites de segurança

- **Nunca altera** a variável; uma divergência requer autorização nova e específica, e execução governada separada. Não altera Secrets, permissões, budgets, runners, workflows de inventário ou hosts.
- A variável é lida como **snapshot efetivo do início do job**, não como prova de alteração persistida ou readback por REST após atualização. O workflow não certifica saldo, hard stop nem custo de inventário físico.
- Workflow somente na `main` depois do merge; um arquivo em PR não prova funcionamento real. Não há disparo físico automático, upload de artifacts, uso de cache ou acesso a segredos.
- Runner padrão `ubuntu-24.04` em repositório **público**, gratuitamente segundo GitHub Docs (referência verificada em 15/11/2026). Mudança para repositório privado, larger runner ou condição de billing não comprovada exige reavaliação e bloqueio.
- O GitHub pode atrasar/agendar irregularmente e desativar o `schedule` após 60 dias sem atividade em repositórios públicos. Notificações só ocorrerão conforme configuração do GitHub; falha do check não é prova de aviso recebido.

## Critérios de aceite da mudança

1. Código e contrato imutável de verificação somente leitura, sem credencial de escrita.
2. Teste positivo; negativos para ausente, inválido, divergente, execução antiga e proprietário incorreto; proteção contra escrita.
3. Commit/PR draft com SHA, CAS e releitura independente.
4. CI Windows/Linux e Validator independente no SHA final, sem ignorar falhas.
5. Merge aprovado e execução `push main` comprovada no GitHub Actions, com readback do SHA e do resultado.
6. Estado registrado no TODO Global com readback canônico; sem adaptador, **sincronização pendente**.

Dono: Runtime Platform. Custo adicional máximo: R$ 0,00. Nenhuma permissão de mutação de variável está incluída.
