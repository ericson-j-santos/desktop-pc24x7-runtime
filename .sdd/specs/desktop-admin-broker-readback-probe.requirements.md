# Desktop Admin Broker — hosted readback probe

## Objetivo

Eliminar a opacidade do Admin Broker residente no `DESKTOP-PDQK954` sem depender
do runner do Desktop, Noteri, RDC, GUI ou shell remoto.

## Contrato

1. O publisher do broker continua outbound-only e publica somente payload
   sanitizado `diagnostic_only`.
2. Publicação na URL fixa do tópico ntfy usa corpo textual; JSON estruturado não
   é enviado como `application/json` diretamente para a URL do tópico.
3. O probe usa exclusivamente
   `https://ntfy.sh/desktop-pc24x7-runtime-readback-v1-4c7d9a21b62f4e9a/json?poll=1&since=latest`.
4. Host, tópico e endpoint não aceitam input externo.
5. O probe só aceita `event=message`, host `DESKTOP-PDQK954`, SHA Git de 40
   caracteres, `trust=diagnostic_only`, `authoritative_success=false`,
   `production_touched=false` e `secrets_read=false`.
6. Mensagem fora da janela de frescor falha fechada.
7. Campos não allowlisted do resultado nunca são persistidos no artifact.
8. O probe é leitura pura; não comenta issue, não executa recovery, não toca
   produção, não lê segredos e não depende de self-hosted runner.

## Aceite

- testes positivos e negativos passam no SHA exato;
- workflow GitHub-hosted executa o probe real e publica artifact mesmo em falha;
- sucesso do probe prova somente readback diagnóstico recente, nunca recuperação
  funcional;
- ausência/falha do readback permanece estado bloqueado e não dispara retry de
  recovery automaticamente.

## Rota de execução independente do Desktop — 09/10/2026

Quando o conector não oferecer `workflow_dispatch` e a navegação do chat não
conseguir ler a saída diagnóstica, usar o evento `push` já previsto pelo workflow
`desktop-admin-broker-readback-probe.yml`, em branch isolada compatível com seu
filtro e com uma alteração documental de escopo explícito. Não modificar a main,
recriar a automação, aumentar permissões ou acionar o runner físico bloqueado.
O workflow existente executa testes de contrato e uma leitura HTTPS limitada
em `ubuntu-latest`; não executa comandos no Desktop.

Esta retomada está vinculada a Runtime #31 e Orchestrator #47, para investigar
por canal independente o bloqueio da tentativa
`desktop-crlf-refresh-20261008-2116`. A leitura do último diagnóstico não substitui
o recibo dessa tentativa: conferir `comment_id`, ação, frescor e SHA antes de
relacionar uma mensagem à atualização. Mensagem ausente, antiga ou de outra ação
não autoriza refresh, bootstrap ou repetição automática.

Checkpoint da tentativa hospedada: `todo-supervisor-hosted-readback-20261009`.
O resultado deve ser registrado com run/job/SHA na issue #31 após leitura dos
logs e do efeito observado, inclusive quando for bloqueio. Não considerar a
criação da branch ou a presença de um job como execução física concluída.
