# Auditoria de configuracao do Azure API Management

Script PowerShell para inventariar instancias do Azure API Management (APIM),
consultar configuracoes e, opcionalmente, testar a acessibilidade de URLs.

Arquivo utilizado nos exemplos: **`Invoke-ApimNetworkAuditv14.ps1`**.
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
| Backends cadastrados | Opcionalmente, com `-CheckBackends`, indicios de autenticacao por chave na configuracao, sem salvar valores de credenciais nem analisar policies. |
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
Connect. Com `-CheckBackends`, tambem e necessaria leitura dos backends cadastrados
(`Microsoft.ApiManagement/service/backends/read`). Com `-CheckNsg`, e necessaria
leitura das subnets e NSGs.
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

.\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -MaxInstances 10
```

Esse comando analisa ate 10 APIMs acessiveis, sem testar URLs e sem consultar NSGs.
Os blocos individuais mostram a assinatura, a instancia e os metadados coletados.
O sumario final apresenta as contagens e a pasta dos relatorios.
Por padrao, a origem e declarada publica e nenhum teste de URL e executado.
Use `-TestUrls` para ativar os testes e `-PrivateOrigin` se houver conectividade
privada. O script nao detecta a origem real da rede.
A checagem de backends tambem fica desligada por padrao; ative com `-CheckBackends`.

## Parametros do script

| Parametro | Tipo / valores aceitos | Obrigatorio | Padrao | Finalidade |
| --- | --- | --- | --- | --- |
| `-TenantId` | GUID | Sim, em todos os modos | Nenhum | Tenant da sessao autenticada em `Full`/`Inventory`. Em `Probe`, deve corresponder ao tenant do JSON salvo. Nao autentica automaticamente. |
| `-SubscriptionIds` | Lista de GUIDs | Nao | Todas as assinaturas acessiveis | Restringe a coleta a uma ou mais assinaturas Azure. Nao se refere as subscriptions de consumo das APIs. Aceito em `Full` e `Inventory`; nao permitido em `Probe`. |
| `-ApimNames` | Lista de nomes de instancias | Nao | Todos os nomes | Seleciona nomes exatos de APIM, nao URLs ou IDs de recursos. Ignora maiusculas/minusculas, remove espacos externos e duplicatas. Nao interpreta curingas. Se informado, rejeita lista vazia e nomes vazios/nulos. Em `Probe`, filtra somente o arquivo salvo. |
| `-MaxInstances` | Inteiro entre `0` e `2147483647` | Nao | `0` | Limita o total de APIMs analisados, depois dos filtros de assinaturas e nomes. `0` ou omissao significa todos. Seleciona pela ordem de descoberta, nao por sorteio nem pela ordem dos nomes informados. |
| `-Mode` | `Full`, `Inventory` ou `Probe` | Nao | `Full` | Define se o script coleta metadados, testa URLs ou reutiliza um inventario anterior. Veja a tabela de modos abaixo. |
| `-InventoryPath` | Caminho de arquivo JSON | Somente em `Probe` | Nenhum | Seleciona um `apim-audit.json` compativel, gerado anteriormente para o mesmo tenant. Obrigatorio em `Probe` e nao permitido nos demais modos. |
| `-TestUrls` | Switch | Nao | Desligado | Ativa DNS/TCP/TLS/HTTP em `Full` e `Probe`. Sem este parametro, somente inventario e checagens de configuracao sao executados. Nao muda `Mode`; `Inventory` nunca testa URLs. |
| `-CheckNsg` | Switch | Nao | Desligado | Ativa a analise de subnets e NSGs somente de APIMs `Internal`. Em `Probe`, apenas exibe/exporta evidencias ja salvas; nao faz novas consultas. |
| `-CheckBackends` | Switch | Nao | Desligado | Ativa a checagem dos backends cadastrados e suas contagens por instancia e no sumario. Sem este parametro, nao consulta backends nem exibe seus resultados. Em `Probe`, apenas reutiliza dados salvos, sem consultar o Azure. |
| `-PrivateOrigin` | Switch | Nao | Desligado (origem publica) | Declara origem privada, com VPN/VNet ou conectividade privada, em vez do padrao publico. Nao detecta, altera nem garante a rede real. |
| `-OutputDirectory` | Caminho de pasta | Nao | Pasta `apim-audit` no diretorio atual | Define a pasta base dos relatorios. Cada execucao cria uma subpasta com data/hora UTC e identificador, sem substituir a execucao anterior. |
| `-TimeoutSeconds` | Inteiro entre `1` e `120` | Nao | `15` | Timeout em segundos de cada etapa das sondagens de URLs. Nao e um timeout global da execucao nem das consultas ARM. |
| `-ArmMaxRetries` | Inteiro entre `0` e `3` | Nao | `1` | Numero de tentativas adicionais das consultas ARM para respostas HTTP `429` e `5xx`. `0` desativa essas repeticoes. Nao repete as sondagens de URLs. |

Switches nao precisam de valor: use, por exemplo, `-CheckNsg -TestUrls`.
Listas PowerShell podem ser informadas como `'apim-exemplo-a','apim-exemplo-b'` ou
por uma variavel de array. Os exemplos sao para PowerShell, nao Bash.

### Modos de execucao

| Modo | Configuracoes no Azure | URLs | Uso |
| --- | --- | --- | --- |
| `Full` | Consulta | Somente com `-TestUrls` | Inventario e, opcionalmente, sondagens na mesma execucao. |
| `Inventory` | Consulta | Nao testa | Coleta configuracoes para analisar ou reutilizar depois. |
| `Probe` | Nao consulta | Somente com `-TestUrls` | Reutiliza o JSON e, opcionalmente, executa sondagens a partir da origem atual. |

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

### Uma assinatura especifica

Substitua os placeholders pelos GUIDs reais. O nome abaixo corresponde ao
arquivo atual do script; ajuste-o se renomear o `.ps1`.

```powershell
.\Invoke-ApimNetworkAuditv14.ps1 -TenantId '<TENANT-ID>' -SubscriptionIds '<SUBSCRIPTION-ID>'
```

### Uma ou mais assinaturas

```powershell
$SubscriptionIds = @('<SUBSCRIPTION-ID-1>', '<SUBSCRIPTION-ID-2>')
.\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -SubscriptionIds $SubscriptionIds -Mode Inventory
```

### Instancias especificas, sem conhecer suas assinaturas

```powershell
.\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -ApimNames 'apim-exemplo-a','apim-exemplo-b'
```

O bloco de cada instancia e o `inventory.csv` mostram o nome e o ID da assinatura.
Para selecionar todas as instancias, omita `-ApimNames`; nao passe uma lista vazia.

### Combinar nomes, assinatura, limite e NSG

```powershell
.\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -SubscriptionIds '<SUBSCRIPTION-ID-1>' -ApimNames 'apim-exemplo-a','apim-exemplo-b' -MaxInstances 2 -CheckNsg
```

### Testar URLs a partir de uma origem publica declarada

```powershell
.\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -MaxInstances 10 -TestUrls
```

A origem e considerada publica por padrao. Acrescente `-PrivateOrigin` se houver
VPN/VNet ou outra conectividade privada; a declaracao nao e verificada pelo script.

### Personalizar saida, timeout, repeticoes e diagnostico

```powershell
$PastaSaida = Join-Path $PWD 'relatorios-apim'
.\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -MaxInstances 5 -OutputDirectory $PastaSaida -TimeoutSeconds 10 -ArmMaxRetries 2 -TestUrls -Verbose
```

### Coletar agora e testar o inventario depois

```powershell
$resultado = .\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -Mode Inventory -CheckNsg
$Inventario = Join-Path $resultado.OutputDirectory 'apim-audit.json'

.\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -Mode Probe -InventoryPath $Inventario -ApimNames 'apim-exemplo-a' -MaxInstances 1 -TestUrls -CheckNsg
```

Para executar a segunda etapa em outra sessao/maquina, copie o JSON, defina
`$TenantId` e ajuste `$Inventario` para o caminho real do arquivo.
`-CheckNsg` em `Probe` apenas reutiliza a analise existente.

### Consultar a ajuda do PowerShell

```powershell
Get-Help .\Invoke-ApimNetworkAuditv14.ps1 -Full
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
Connect, APIMs com exigencia de chave e, quando ativados, backends, NSGs e URLs.

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
| `inventory.csv` | Metadados dos APIMs e checagens. `IdentityProviderCheck`, `OpenIdConnectProviderCheck` e `BackendAuthCheck` contem JSON compacto com metadados selecionados. |
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
Sem `-TestUrls` ou com `-Mode Inventory`, os CSVs de endpoints possuem somente
cabecalhos. Sem `-CheckNsg`, os CSVs de rede tambem possuem somente cabecalhos.
Isso nao significa que nao existam endpoints ou NSGs.

O script tambem retorna um objeto PowerShell com a pasta e os caminhos dos
relatorios, alem das contagens de APIMs, endpoints e ocorrencias. Por exemplo:

```powershell
$resultado = .\Invoke-ApimNetworkAuditv14.ps1 -TenantId $TenantId -Mode Inventory -MaxInstances 1
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
- **Backends:** desligado por padrao; com `-CheckBackends`, examina somente
  entidades cadastradas em `service/backends`.
  Reconhece headers `api-key`, `x-api-key`, `Ocp-Apim-Subscription-Key` e
  `x-functions-key`; na query de credenciais ou da URL, reconhece `api-key`,
  `apikey`, `subscription-key`, `code` e `key`. Um campo reconhecido preenchido,
  inclusive com referencia a Named Value, gera **indicio de chave**, nao prova
  de uso efetivo ou validade. Campos reconhecidos vazios, credenciais com nomes
  desconhecidos, `authorization` e pools sem indicio direto ficam indeterminados.
  Nao resolve Named Values, nao percorre pools e nao avalia policies. **Sem
  indicio no cadastro nao significa backend sem autenticacao.** O GET pode
  retornar credenciais; somente nomes, status e locais dos indicios sao retidos,
  sem URLs de backend nem valores das credenciais nos relatorios.
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
