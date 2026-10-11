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

## One-shot de verificação após atualização controlada — READBACK-REFRESH-20261011-C6105145352

O broker instalado recebeu um pedido exato `/desktop-runtime admin refresh-self`
na issue #2, comentário `6105145352`, após a CI pós-merge validar a revisão
`1e0b5b3e17d89910f05824b5b4174d6bc34ccaa0` do runtime. A publicação
deste documento em uma branch isolada apenas dispara a sonda HTTPS hospedada
já existente. Não cria novos comandos de manutenção, não altera o supervisor,
não lê segredos nem exige runner self-hosted.

**Aceite estrito do diagnóstico**: conferir `action=refresh-self`,
`comment_id=6105145352`, host e janela, e verificar que
`target_source_sha` corresponda ao SHA acima e que o broker tenha executado
o início da nova instância. O canal ntfy permanece `diagnostic_only`, sem
assinatura da origem e sem autoridade para recuperar ou declarar READY.

**Se ausente, divergente, falho ou antigo**: registrar bloqueio. Não repetir o
refresh nem usar o retorno público como prova de implantação. Somente o
readback autenticado pelo plano de controle e uma verificação independente
na máquina autorizada podem concluir a instalação.
