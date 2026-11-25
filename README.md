# Auditoria de configuracao do Azure API Management

Script PowerShell para inventariar instancias do Azure API Management (APIM),
consultar configuracoes e, opcionalmente, testar a acessibilidade de URLs.

Arquivo utilizado nos exemplos: **`Invoke-ApimNetworkAuditv13.ps1`**.
O script nao altera configuracoes do Azure, mas grava relatorios locais.
Execute somente em recursos que voce tem autorizacao para consultar e testar.

## O que o script verifica

| Grupo | Verificacao |
| --- | --- |
| Rede | Modo `Internal`, `External`, `None` ou desconhecido. |
| Named Values | Contagens exclusivas de Plain, Secret e referencias Key Vault, sem recuperar valores secretos. |
| Subscriptions APIM | Contagem da All-access padrao (`master`) e das demais subscriptions customizadas, incluindo todos os estados. |
| APIs | Campo `subscriptionRequired`, contagens por API/revisao e nomes das APIs com exigencia confirmada de chave. |
| Provedores de identidade | Inventario de Identity Providers e OpenID Connect, sem consultar valores de client secrets. |
| URLs | DNS, TCP, TLS e HTTP GET para portais do desenvolvedor, portal legado e API direta de gerenciamento. |
| NSGs | Opcionalmente, subnets e regras inbound dos APIMs `Internal`, incluindo regioes adicionais. |

As URLs sao obtidas das configuracoes retornadas pelo Azure, incluindo os
hostnames customizados pertinentes. O script **nao testa o gateway das APIs nem
rotas/operacoes individuais**.

## Pre-requisitos

- PowerShell **7.4 ou superior**; no Azure Cloud Shell, selecione **PowerShell**.
- Modulo `Az.Accounts` para os modos `Full` e `Inventory`, com sessao autenticada.
- Ambiente Azure publico (`AzureCloud`); clouds soberanas nao sao suportadas.
- Permissoes de leitura nos escopos que deseja inventariar.
- Conectividade com o Azure Resource Manager e, quando habilitadas, com as URLs
  das sondagens.

As leituras abrangem subscriptions Azure, APIMs, configuracao de gerenciamento
direto, Named Values, subscriptions APIM, APIs, Identity Providers e OpenID
Connect. Com `-CheckNsg`, tambem e necessaria leitura das subnets e NSGs.
Uma funcao como `Reader`, nos escopos autorizados, pode ser utilizada conforme
as politicas de acesso da organizacao. Nao e necessario conceder escrita ou
permissao para recuperar segredos.

O script reutiliza a sessao existente e nao muda seu contexto de assinatura.
No modo `Probe`, le o inventario salvo e nao consulta configuracoes no Azure.

## Inicio rapido no Azure Cloud Shell

Envie o arquivo `.ps1` para o Cloud Shell e execute os comandos abaixo na mesma
sessao PowerShell. **Substitua os placeholders pelos GUIDs reais antes de executar.**
Nomes como `apim-exemplo-a` tambem sao apenas exemplos.

```powershell
$TenantId = '<TENANT-ID>'
Connect-AzAccount -Tenant $TenantId

.\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -MaxInstances 10 -SkipUrlTests
```

Esse comando analisa ate 10 APIMs acessiveis, sem testar URLs e sem consultar NSGs.
Os blocos individuais mostram a assinatura, a instancia e os metadados coletados.
O sumario final apresenta as contagens e a pasta dos relatorios.

## Parametros do script

| Parametro | Tipo / valores aceitos | Obrigatorio | Padrao | Finalidade |
| --- | --- | --- | --- | --- |
| `-TenantId` | GUID | Sim, em todos os modos | Nenhum | Tenant da sessao autenticada em `Full`/`Inventory`. Em `Probe`, deve corresponder ao tenant do JSON salvo. Nao autentica automaticamente. |
| `-SubscriptionIds` | Lista de GUIDs | Nao | Todas as assinaturas acessiveis | Restringe a coleta a uma ou mais assinaturas Azure. Nao se refere as subscriptions de consumo das APIs. Aceito em `Full` e `Inventory`; nao permitido em `Probe`. |
| `-ApimNames` | Lista de nomes de instancias | Nao | Todos os nomes | Seleciona nomes exatos de APIM, nao URLs ou IDs de recursos. Ignora maiusculas/minusculas, remove espacos externos e duplicatas. Nao interpreta curingas. Se informado, rejeita lista vazia e nomes vazios/nulos. Em `Probe`, filtra somente o arquivo salvo. |
| `-MaxInstances` | Inteiro entre `0` e `2147483647` | Nao | `0` | Limita o total de APIMs analisados, depois dos filtros de assinaturas e nomes. `0` ou omissao significa todos. Seleciona pela ordem de descoberta, nao por sorteio nem pela ordem dos nomes informados. |
| `-Mode` | `Full`, `Inventory` ou `Probe` | Nao | `Full` | Define se o script coleta metadados, testa URLs ou reutiliza um inventario anterior. Veja a tabela de modos abaixo. |
| `-InventoryPath` | Caminho de arquivo JSON | Somente em `Probe` | Nenhum | Seleciona um `apim-audit.json` compativel, gerado anteriormente para o mesmo tenant. Obrigatorio em `Probe` e nao permitido nos demais modos. |
| `-SkipUrlTests` | Switch | Nao | Desligado | Desativa todas as etapas DNS/TCP/TLS/HTTP. Preserva as consultas de configuracao e, se solicitado, NSG. Funciona tambem em `Probe` e nao muda o valor de `Mode`. |
| `-CheckNsg` | Switch | Nao | Desligado | Ativa a analise de subnets e NSGs somente de APIMs `Internal`. Em `Probe`, apenas exibe/exporta evidencias ja salvas; nao faz novas consultas. |
| `-PublicOrigin` | Switch | Nao | Desligado | Declara que a origem das sondagens e publica, sem VPN/VNet ou conectividade privada. Nao detecta, altera nem garante essa condicao. Sem a declaracao, as sondagens continuam com um aviso. Sem sondagens, esse aviso nao aparece. |
| `-OutputDirectory` | Caminho de pasta | Nao | Pasta `apim-audit` no diretorio atual | Define a pasta base dos relatorios. Cada execucao cria uma subpasta com data/hora UTC e identificador, sem substituir a execucao anterior. |
| `-TimeoutSeconds` | Inteiro entre `1` e `120` | Nao | `15` | Timeout em segundos de cada etapa das sondagens de URLs. Nao e um timeout global da execucao nem das consultas ARM. |
| `-ArmMaxRetries` | Inteiro entre `0` e `3` | Nao | `1` | Numero de tentativas adicionais das consultas ARM para respostas HTTP `429` e `5xx`. `0` desativa essas repeticoes. Nao repete as sondagens de URLs. |

Switches nao precisam de valor: use, por exemplo, `-CheckNsg -SkipUrlTests`.
Listas PowerShell podem ser informadas como `'apim-exemplo-a','apim-exemplo-b'` ou
por uma variavel de array. Os exemplos sao para PowerShell, nao Bash.

### Modos de execucao

| Modo | Configuracoes no Azure | URLs | Uso |
| --- | --- | --- | --- |
| `Full` | Consulta | Testa, salvo `-SkipUrlTests` | Inventario e sondagens na mesma execucao. |
| `Inventory` | Consulta | Nao testa | Coleta configuracoes para analisar ou reutilizar depois. |
| `Probe` | Nao consulta | Testa, salvo `-SkipUrlTests` | Reutiliza o JSON e executa as sondagens a partir da origem atual. |

Em `Probe`, os timestamps e metadados de configuracao continuam sendo os do
inventario original. Inventarios antigos sem determinadas checagens mostram
dados ausentes, nao contagens ficticias nem consultas automaticas para preenche-los.

### Interacao entre filtros

A selecao segue esta ordem: assinaturas, nomes de APIM e limite de instancias.
Sem `-SubscriptionIds`, os nomes sao procurados nas assinaturas acessiveis.
O script ainda precisa listar colecoes de APIMs para descobrir correspondencias,
mas coleta configuracoes detalhadas apenas das instancias selecionadas.
`-MaxInstances` nao e um limite do numero de chamadas ARM.

Nomes nao incluidos geram aviso e registro `ApimNameSelection` em `issues.csv`.
Isso pode decorrer de nome incorreto, filtros, permissoes, falha de coleta,
limite ou ausencia no inventario salvo. **Nao comprova inexistencia no tenant.**
No modo `Probe`, `-ApimNames` e aplicado antes de `-MaxInstances`, dentro do arquivo.

## Exemplos

Os exemplos abaixo usam `$TenantId` definido no inicio rapido.

### Uma ou mais assinaturas

```powershell
$SubscriptionIds = @('<SUBSCRIPTION-ID-1>', '<SUBSCRIPTION-ID-2>')
.\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -SubscriptionIds $SubscriptionIds -Mode Inventory
```

### Instancias especificas, sem conhecer suas assinaturas

```powershell
.\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -ApimNames 'apim-exemplo-a','apim-exemplo-b' -SkipUrlTests
```

O bloco de cada instancia e o `inventory.csv` mostram o nome e o ID da assinatura.
Para selecionar todas as instancias, omita `-ApimNames`; nao passe uma lista vazia.

### Combinar nomes, assinatura, limite e NSG

```powershell
.\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -SubscriptionIds '<SUBSCRIPTION-ID-1>' -ApimNames 'apim-exemplo-a','apim-exemplo-b' -MaxInstances 2 -CheckNsg -SkipUrlTests
```

### Testar URLs a partir de uma origem publica declarada

```powershell
.\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -MaxInstances 10 -PublicOrigin
```

Use `-PublicOrigin` somente se a origem realmente nao tiver conectividade privada.
O script nao verifica essa declaracao de forma independente.

### Personalizar saida, timeout, repeticoes e diagnostico

```powershell
$PastaSaida = Join-Path $PWD 'relatorios-apim'
.\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -MaxInstances 5 -OutputDirectory $PastaSaida -TimeoutSeconds 10 -ArmMaxRetries 2 -Verbose
```

### Coletar agora e testar o inventario depois

```powershell
$resultado = .\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -Mode Inventory -CheckNsg
$Inventario = Join-Path $resultado.OutputDirectory 'apim-audit.json'

.\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -Mode Probe -InventoryPath $Inventario -ApimNames 'apim-exemplo-a' -MaxInstances 1 -PublicOrigin -CheckNsg
```

Para executar a segunda etapa em outra sessao/maquina, copie o JSON, defina
`$TenantId` e ajuste `$Inventario` para o caminho real do arquivo.
`-CheckNsg` em `Probe` apenas reutiliza a analise existente.

### Consultar a ajuda do PowerShell

```powershell
Get-Help .\Invoke-ApimNetworkAuditv13.ps1 -Full
```

## Parametros comuns do PowerShell

O script usa `[CmdletBinding()]` e tambem aceita os parametros abaixo. Todos sao
opcionais e controlam os fluxos do PowerShell, nao o escopo dos recursos.
As preferencias da sessao e as configuracoes internas do script afetam seu
comportamento.

| Parametro | Alias | Finalidade |
| --- | --- | --- |
| `-Verbose` | `-vb` | Exibe detalhes da coleta e mensagens tecnicas adicionais. |
| `-Debug` | `-db` | Habilita mensagens de depuracao quando emitidas; nao adiciona novas checagens. |
| `-ErrorAction` | `-ea` | Solicita o tratamento de erros nao terminantes. O script define `$ErrorActionPreference = 'Stop'` internamente e trata falhas de coleta em seus proprios blocos. |
| `-WarningAction` | `-wa` | Controla avisos, por exemplo `Continue`, `SilentlyContinue` ou `Stop`. Ocultar avisos pode esconder falhas na tela. |
| `-InformationAction` | `-infa` | Controla o fluxo de informacao. `Write-Host` tem comportamento proprio e nao segue todos os valores dessa preferencia. |
| `-ProgressAction` | `-proga` | Controla mensagens de progresso quando emitidas. Disponivel no PowerShell 7.4 ou superior. |
| `-ErrorVariable` | `-ev` | Guarda registros de erro em uma variavel, sem `$` no nome: `-ErrorVariable erros`. |
| `-WarningVariable` | `-wv` | Guarda avisos em uma variavel: `-WarningVariable avisos`. |
| `-InformationVariable` | `-iv` | Guarda mensagens do fluxo de informacao em uma variavel: `-InformationVariable mensagens`. |
| `-OutVariable` | `-ov` | Guarda objetos do fluxo de saida em uma variavel; nao captura os blocos de `Write-Host`. |
| `-OutBuffer` | `-ob` | Controla o buffer de objetos enviados ao proximo comando do pipeline; nao altera os arquivos gerados. |
| `-PipelineVariable` | `-pv` | Disponibiliza o objeto de saida atual para os proximos comandos do pipeline; nao captura `Write-Host`. |

`-WhatIf` e `-Confirm` nao sao suportados. A auditoria nao implementa
`SupportsShouldProcess` e nao altera configuracoes do Azure.

## Interpretacao da saida

Cada APIM possui um bloco com assinatura, rede, contagens e detalhes relevantes.
APIs com subscription key obrigatoria aparecem em vermelho, com nome e ID, sem
listar endpoints. Revisoes do mesmo ID base sao agrupadas nessa lista; APIs com
IDs distintos permanecem separadas, mesmo com nomes de exibicao iguais.

O sumario e compacto: rede, Named Values, subscriptions APIM, identidade, OpenID
Connect, APIMs com exigencia de chave e, quando ativados, NSGs e URLs.

| Indicacao | Significado |
| --- | --- |
| `Acessivel` | Houve resposta HTTP, incluindo redirecionamentos, `401`, `403`, `404` ou `5xx`. Nao significa acesso autenticado ou liberacao das APIs. |
| `Nao acessivel` | A tentativa nao obteve resposta HTTP, por exemplo por falha DNS, TCP, TLS ou timeout. Vale somente para a origem e a execucao atuais. |
| `Nao testado` | Nao foi possivel testar aquele alvo, por exemplo por URL ausente/invalida. |
| `N/D` e `[parcial]` | Contagens indisponiveis ou cobertura incompleta; nao devem ser interpretadas como zero. |
| Vermelho | Criterio visual para APIM nao interno, resposta HTTP, API exigindo chave ou regra NSG de origem publica/ampla. Nao e, isoladamente, uma classificacao de vulnerabilidade. |
| Amarelo | Avisos, incertezas ou dados incompletos, conforme o bloco. |

## Relatorios

Cada execucao gera uma subpasta dentro de `-OutputDirectory`.

| Arquivo | Conteudo |
| --- | --- |
| `apim-audit.json` | Inventario, configuracoes, resultados, cobertura, ocorrencias e opcoes da execucao; entrada do modo `Probe`. |
| `inventory.csv` | Metadados dos APIMs e checagens. `IdentityProviderCheck` e `OpenIdConnectProviderCheck` contem JSON compacto com metadados selecionados. |
| `resumo-endpoints.csv` | Resumo por URL, classificacao de acessibilidade e HTTP. |
| `endpoints.csv` | Detalhes tecnicos das sondagens. |
| `named-values.csv` | Contagens de Plain, Secret e Key Vault por instancia. |
| `apim-subscriptions.csv` | Contagens de subscriptions APIM e de requisitos de chave nas APIs. |
| `apis-subscriptions.csv` | Configuracao de cada API/revisao, inclusive resultados indeterminados. |
| `subnets-nsg.csv` | Evidencias da consulta de subnets/NSGs, quando solicitada. |
| `regras-nsg.csv` | Regras inbound dos NSGs analisados. |
| `subscriptions.csv` | Cobertura por assinatura, incluindo limites e falhas. |
| `issues.csv` | Ocorrencias e erros, com escopo, etapa e data UTC. |

Os CSVs especializados de resumo de URLs, Named Values, subscriptions/APIs e NSGs
usam `;`; os CSVs tecnicos de inventario, endpoints, cobertura e ocorrencias usam
`,` como separador.
Com `-SkipUrlTests` ou `-Mode Inventory`, os CSVs de endpoints possuem somente
cabecalhos. Sem `-CheckNsg`, os CSVs de rede tambem possuem somente cabecalhos.
Isso nao significa que nao existam endpoints ou NSGs.

O script tambem retorna um objeto PowerShell com a pasta e os caminhos dos
relatorios, alem das contagens de APIMs, endpoints e ocorrencias. Por exemplo:

```powershell
$resultado = .\Invoke-ApimNetworkAuditv13.ps1 -TenantId $TenantId -Mode Inventory -MaxInstances 1
$resultado.OutputDirectory
$resultado.ApimCount
$resultado.IssueCount
```

## Limites das verificacoes

- **Cobertura:** somente assinaturas e recursos visiveis para a identidade. Nao
  garante cobertura integral do tenant; consulte `subscriptions.csv` e `issues.csv`.
- **Subscription keys:** conta subscriptions APIM, nao valores de chaves
  primarias/secundarias. O campo `subscriptionRequired` nao comprova autenticacao
  efetiva; produtos abertos e policies nao sao avaliados. As contagens de APIs
  incluem revisoes retornadas pelo ARM.
- **Provedores:** inventaria nomes, IDs, tipos e indicacao de client ID informado.
  Nao inspeciona `clientSecret` nem chama `listSecrets`. Presenca e validade do
  segredo permanecem `Nao determinado`; um client ID informado nao comprova que
  exista client secret.
- **NSG:** apenas configuracao inbound de APIMs `Internal`. Nao comprova
  acessibilidade efetiva, nao combina Denies parciais e nao expande todas as
  service tags/ASGs, rotas ou regras administrativas. Um alerta representa uma
  regra a revisar, nao uma prova de exposicao na Internet.
- **URLs:** sondagens sequenciais, sem credenciais, sem seguir redirecionamentos
  e sem salvar corpos HTTP. Nao validam tokens ou subscription keys.

## Cuidados antes de publicar no Git

Este README utiliza apenas placeholders e nomes genericos. O script nao precisa
de credenciais gravadas no codigo, mas os **relatorios e transcricoes podem conter
informacoes internas**, como tenant, assinaturas, nomes de recursos, URLs,
enderecos IP e regras de rede.

Publique somente os arquivos revisados. Nao inclua automaticamente a pasta de
saida, inventarios anteriores, transcricoes ou outros documentos locais.
Esta documentacao nao anonimiza arquivos ja existentes.
