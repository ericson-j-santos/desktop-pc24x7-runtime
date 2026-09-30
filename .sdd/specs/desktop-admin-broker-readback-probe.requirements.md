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

<!-- diagnostic-trigger: current-main-cbaffb561124d8a2a54f863a45312ac8cb8c10cb-20260929 -->
