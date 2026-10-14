# Coleta de vínculo do KB no Desktop — parcial, sem ativação

Dependência de `ericson-j-santos/kb#5` e `kb#1`.

## Escopo

`reqsys_kb_route_binding_probe.py` separa a observação dos workflows de backup,
restauração, cutover e recuperação. Nenhum deles precisa ser disparado para
preparar este coletor. A implementação não oferece opção de instalação,
reinício, alteração de Compose, escrita em banco ou provisionamento de token.

O executor físico continua sendo o responsável atual pelo Desktop. Executar
somente depois de SESSION_LAUNCH_OK, no worktree exclusivo e SHA validados, por
Command Gateway risco 1. A CLI recebe correlation-id e o SHA esperado do coletor;
não verifica o checkout por conta própria: essa verificação pertence ao Gateway.
Não interpretar o SHA informado como atestado da versão executada.

Não há workflow de execução física nesta alteração. O workflow novo só valida
contratos em GitHub-hosted runner; portanto não cria fila para Desktop/Noteri,
não disputa o Codex e não requer actions:write ou credencial de runtime.

## Vínculo observado pelo coletor

1. Ler o locator público fixo, verificar Ed25519 com chave pública fixa, DEV,
   validade, contrato e origem permitida.
2. Identificar o container de túnel entre os quatro nomes já existentes,
   confrontando a origem assinada com seus logs. Somente os argv canônicos
   `tunnel --url http://host.docker.internal:8083` ou
   `tunnel --url http://caddy:80`, com prefixo opcional no-autoupdate, são aceitos.
3. Resolver a porta publicada ou o alias Docker, exigir destino único e projeto
   DEV permitido; localizar o gateway candidato e o KB nesse mesmo projeto.
4. Exportar IDs de containers/imagens e nomes de manifests obtidos por labels.
   Ler novamente metadados, destino e locator; mudança ou expiração bloqueia.

## Limites importantes

- O alias do serviço NÃO prova a configuração ativa do Caddy/Nginx.
- Labels Compose identificam arquivos usados na criação; NÃO provam seu conteúdo
  atual ou que uma alteração foi recarregada.
- O estado máximo é `route_identity_observed_config_pending`.
- `loaded_config_verified=false` e `host_inventory_complete=false` são
  deliberados. A verificação completa da cadeia continua pendente.
- Não existe leitura de Config.Env, bancos, segredos, conteúdo de manifests ou
  arquivos privados. As presenças KB_WRITE_TOKEN e KB_INGEST_ROOT ficam nulas.
- Não encontrar KB restringe a conclusão ao projeto Compose selecionado.
- A coleta não exporta a URL do túnel, caminhos completos, logs brutos ou IPs.
- O transporte Docker ainda necessita ensaio no Windows real, no mesmo SHA.
- A cota RDC positiva isolada não elimina bloqueio anterior sem renovação
  independente, conforme rules/tool-routing.md. Não usar esta rotina como bypass.

## Validação

Testes de contrato: assinatura real de teste e transporte Docker simulado.
Incluem negativo, replay, mudança de container/túnel, destino ambíguo, PROD,
expiração e exclusão de dados brutos. Não equivalem a coleta no Desktop.

O ensaio de Docker cria um container descartável, sem iniciá-lo, exclusivamente
em GitHub-hosted runner. Confere o template real, controle negativo, leitura
repetida e exclusão de token fictício. A limpeza exige ID e label próprios;
nenhum prune ou recurso do usuário é usado.

A dependência cryptography 50.0.2 reutiliza o pin já executado no coletor KB
0bca5e3abad8d786a5fdfc67618ccb6fedaccfb6. Não instala nada no Desktop.

## Próxima evidência necessária

Canal físico elegível + sessão governada no SHA desta alteração, coleta sem
efeitos no runtime e leitura independente. Depois, confirmar configuração
carregada e somente então avaliar uma correção de rota/serviço. Não apresentar
este incremento preparatório como solução do HTTP 404 do KB.
