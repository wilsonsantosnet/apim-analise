#requires -Version 7.4
<#
.SYNOPSIS
Inventaria APIMs e verifica endpoints sem autenticacao (v12).
.DESCRIPTION
Usa a sessao Az.Accounts existente, sem alterar o contexto ou recursos.
Requer leitura das subscriptions Azure, APIMs, service/tenant, namedValues, subnets,
NSGs, service/subscriptions, service/apis, identityProviders e openidConnectProviders.
Exporta JSON, CSV tecnico e resumo-endpoints.csv (separado por ponto e virgula).
Mostra blocos por APIM com marcadores HTTP, DNS, TIMEOUT, TCP e TLS.
Nao coleta tokens nem corpos HTTP.
Destaca em vermelho APIMs nao internos, URLs com resposta HTTP e instancias
com pelo menos uma API configurada com subscriptionRequired=true.
Classifica as URLs como Acessivel, Nao acessivel ou Nao testado nesta execucao.
Com -CheckNsg, consulta subnet/NSG dos APIMs Internal, incluindo regioes adicionais.
Sem -CheckNsg, nao consulta subnets/NSGs e seus CSVs contem somente cabecalhos.
Coleta o inventario sem listagem intermediaria; exibe um bloco visual por APIM.
Sem -TestUrls, pula DNS/TCP/TLS/HTTP e preserva as demais checagens e relatorios.
A analise de regras NSG e de configuracao; nao substitui os testes de URLs.
Conta Named Values Plain, Secret e Key Vault separadamente, sem coletar valores.
Nao chama listSecrets nem consulta o Key Vault. Exporta named-values.csv por APIM.
Conta subscriptions APIM: padrao All-access (id master) e demais customizadas.
Conta todas as subscriptions, inclusive nao ativas, sem consultar suas chaves.
Lista subscriptionRequired por API/revisao; nao avalia produtos abertos ou policies.
Exporta apim-subscriptions.csv e apis-subscriptions.csv.
Inventaria provedores de identidade e OpenID Connect somente por GET.
Nao inspeciona clientSecret nem chama listSecrets; presenca/validade nao determinadas.
Salva somente metadados selecionados dos provedores no JSON e inventory.csv.
A origem e considerada publica por padrao; use -PrivateOrigin em origem privada.
Essa declaracao nao e uma verificacao independente da origem.
Sondagens sequenciais, uma tentativa por etapa e sem seguir redirecionamentos.
Use somente em recursos que voce tem autorizacao para consultar e testar.
.PARAMETER TenantId
ID do tenant da sessao autenticada. Obrigatorio em todos os modos.
.PARAMETER SubscriptionIds
Filtro opcional. O padrao e consultar todas as subscriptions acessiveis.
.PARAMETER ApimNames
Lista opcional de nomes exatos de instancias, sem distinguir maiusculas/minusculas.
Filtra antes das consultas detalhadas e de MaxInstances. Combina com SubscriptionIds.
Em Probe, seleciona somente recursos do inventario salvo, sem novas consultas.
.PARAMETER PrivateOrigin
Declara origem privada, com VPN/VNet ou conectividade privada, em vez do padrao publico.
.PARAMETER Mode
Full coleta e pode testar; Inventory apenas coleta; Probe reutiliza um JSON ja coletado.
Os testes de URLs exigem -TestUrls, inclusive no modo Probe.
.PARAMETER InventoryPath
Arquivo apim-audit.json gerado anteriormente. Usado somente no modo Probe.
.PARAMETER TimeoutSeconds
Timeout de cada etapa DNS, conexao TCP, TLS e HTTP. Nao e um timeout global.
.PARAMETER ArmMaxRetries
Repeticoes adicionais para respostas ARM 429 e 5xx. Nao repete sondagens.
.PARAMETER MaxInstances
Limite total de APIMs a analisar, somando as subscriptions. Omita ou use 0 para todos.
Seleciona os primeiros encontrados, sem sorteio, e gera os relatorios normalmente.
.PARAMETER CheckNsg
Ativa a checagem opcional de subnets/NSGs dos APIMs Internal. Desligada por padrao.
Requer leitura das subnets/NSGs. No modo Probe, apenas exibe/exporta dados salvos.
.PARAMETER TestUrls
Ativa testes de URLs (DNS, TCP, TLS e HTTP), desligados por padrao.
Sem este parametro, os CSVs de endpoints contem somente cabecalhos.
No modo Probe, testa o inventario salvo. No modo Inventory, nao testa URLs.
.EXAMPLE
.\Invoke-ApimNetworkAuditv12.ps1 -TenantId '<TENANT-ID>' -TestUrls
.EXAMPLE
.\Invoke-ApimNetworkAuditv12.ps1 -TenantId '<TENANT-ID>' -MaxInstances 5 -TestUrls -CheckNsg
.EXAMPLE
.\Invoke-ApimNetworkAuditv12.ps1 -TenantId '<TENANT-ID>' -MaxInstances 10
.EXAMPLE
.\Invoke-ApimNetworkAuditv12.ps1 -TenantId '<TENANT-ID>' -Mode Inventory
.EXAMPLE
.\Invoke-ApimNetworkAuditv12.ps1 -TenantId '<TENANT-ID>' -Mode Probe -InventoryPath '.\apim-audit.json' -TestUrls -CheckNsg
.EXAMPLE
.\Invoke-ApimNetworkAuditv12.ps1 -TenantId '<TENANT-ID>' -ApimNames 'apim-a','apim-b'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [guid[]]$SubscriptionIds = @(),
    [string]$OutputDirectory = (Join-Path $PWD 'apim-audit'),
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 15,
    [ValidateRange(0, 3)][int]$ArmMaxRetries = 1,
    [ValidateSet('Full', 'Inventory', 'Probe')][string]$Mode = 'Full',
    [string]$InventoryPath,
    [switch]$PrivateOrigin,
    [ValidateRange(0, 2147483647)][int]$MaxInstances = 0,
    [switch]$CheckNsg,
    [switch]$TestUrls,
    [ValidateNotNullOrEmpty()][ValidatePattern('\S')][string[]]$ApimNames = @()
)

$ErrorActionPreference = 'Stop'
$script:ArmBaseUri = 'https://management.azure.com'
$script:ApimApiVersion = '2024-05-01'
$script:NetworkApiVersion = '2023-09-01'

function Write-ApimAuditPlan {
    param([string]$Mode, [int]$MaxInstances = 0, [switch]$CheckNsg, [switch]$TestUrls, [string[]]$ApimNames = @())

    Write-Host "`n$('=' * 76)" -ForegroundColor Cyan
    Write-Host ' APIM | VERIFICACOES DESTA EXECUCAO' -ForegroundColor White
    Write-Host "$('-' * 76)" -ForegroundColor DarkCyan
    if ($ApimNames.Count -gt 0) {
        Write-Host " [FILTRO] Nomes exatos de APIM: $($ApimNames -join ', ')" -ForegroundColor Cyan
    }
    if ($MaxInstances -gt 0) {
        Write-Host " [AMOSTRA] Ate $MaxInstances APIM(s) no total, por ordem de descoberta, sem sorteio." -ForegroundColor Yellow
        Write-Host '           Ao atingir o limite, concluir os testes e gerar os CSVs.' -ForegroundColor Yellow
    }
    if ($Mode -eq 'Probe') {
        Write-Host ' [1] Ler inventario, NSGs, Named Values, subscriptions/APIs e provedores salvos.' -ForegroundColor Gray
        Write-Host '     Nenhuma configuracao sera consultada novamente no Azure.' -ForegroundColor Yellow
        if ($CheckNsg) {
            Write-Host ' [NSG] Exibir somente as checagens existentes no inventario salvo.' -ForegroundColor Gray
        }
        else {
            Write-Host ' [NSG] Desativado. Para incluir os resultados salvos, use -CheckNsg.' -ForegroundColor Gray
        }
    }
    else {
        Write-Host ' [1] Listar APIMs das subscriptions acessiveis e seu modo de rede.' -ForegroundColor Gray
        if ($CheckNsg) {
            Write-Host ' [2] Somente APIMs Internal: consultar subnets e NSGs associados.' -ForegroundColor Gray
            Write-Host '     Incluir regioes adicionais e regras inbound, inclusive padroes.' -ForegroundColor Gray
            Write-Host '     Comparar prioridades, origens, destinos, protocolos e portas.' -ForegroundColor Gray
            Write-Host '     Identificar origens internas, publicas e excecoes Azure.' -ForegroundColor Gray
        }
        else {
            Write-Host ' [2] NSG desativado. Para consultar subnets e NSGs, use -CheckNsg.' -ForegroundColor Gray
        }
        Write-Host ' [3] Todos os APIMs selecionados: contar Named Values por tipo.' -ForegroundColor Gray
        Write-Host '     Plain, Secret e Key Vault separados, sem coletar valores.' -ForegroundColor Gray
        Write-Host ' [4] Contar subscriptions APIM: All-access padrao e customizadas.' -ForegroundColor Gray
        Write-Host '     Incluir todos os estados, sem consultar chaves primaria/secundaria.' -ForegroundColor Gray
        Write-Host ' [5] Listar exigencia de subscription key por API/revisao.' -ForegroundColor Gray
        Write-Host '     Configuracao da API; produtos abertos e policies nao avaliados.' -ForegroundColor Gray
        Write-Host ' [6] Inventariar Identity Providers e OpenID Connect, sem consultar segredos.' -ForegroundColor Gray
        Write-Host '     Client ID informado nao comprova client secret; presenca/validade nao determinadas.' -ForegroundColor Gray
    }
    if (-not $TestUrls) {
        Write-Host ' [URL] Testes desativados por padrao: use -TestUrls para ativar DNS, TCP, TLS e HTTP.' -ForegroundColor Gray
    }
    elseif ($Mode -ne 'Inventory') {
        Write-Host ' [URL] APIMs selecionados: portal do desenvolvedor, legado e API de gestao.' -ForegroundColor Gray
        Write-Host '       DNS > TCP > TLS > HTTP GET, sem credenciais ou redirecionamentos.' -ForegroundColor Gray
    }
    else {
        Write-Host ' [URL] Modo Inventory: nenhuma URL sera testada.' -ForegroundColor Gray
    }
    Write-Host ' [CSV] Salvar URLs, subnet/NSG, Named Values e subscriptions/APIs.' -ForegroundColor Gray
    Write-Host ' Vermelho: APIM nao interno, URL com HTTP ou API exigindo chave.' -ForegroundColor Red
    if ($CheckNsg) {
        Write-Host ' NSG: regras com origem publica/ampla tambem aparecem em vermelho.' -ForegroundColor Red
        Write-Host ' NSG: analise de configuracao, nao uma afirmacao de acesso ao APIM.' -ForegroundColor Gray
    }
    Write-Host "$('=' * 76)" -ForegroundColor Cyan
}

function Invoke-ApimArmGet {
    param([string]$Uri, [object]$Context, [int]$MaxRetries)

    $parsed = [uri]$Uri
    if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'management.azure.com' -or
        $parsed.Port -ne 443 -or $parsed.UserInfo -or $parsed.Fragment) {
        throw "URL ARM nao permitida: $Uri"
    }
    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        $response = Invoke-AzRestMethod -Uri $parsed.AbsoluteUri -Method GET -DefaultProfile $Context -ErrorAction Stop
        $status = [int]$response.StatusCode
        if ($status -ge 200 -and $status -lt 300) {
            return ($response.Content | ConvertFrom-Json -AsHashtable -Depth 100)
        }
        if (($status -eq 429 -or $status -ge 500) -and $attempt -lt $MaxRetries) {
            Start-Sleep -Seconds ([math]::Min(10, [math]::Pow(2, $attempt + 1)))
            continue
        }
        $code = 'Unknown'
        if ($response.Content) {
            try {
                $body = $response.Content | ConvertFrom-Json -AsHashtable -Depth 100
                if ($body.error.code) { $code = [string]$body.error.code }
            }
            catch [System.ArgumentException] { $code = 'NonJsonErrorResponse' }
        }
        throw "ARM HTTP $status ($code): $Uri"
    }
}

function Get-ApimArmCollection {
    param([string]$Uri, [object]$Context, [int]$MaxRetries)

    $items = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $failure = $null
    try {
        while ($Uri) {
            if (-not $visited.Add($Uri)) { throw "Paginacao ARM repetiu uma URL: $Uri" }
            $page = Invoke-ApimArmGet -Uri $Uri -Context $Context -MaxRetries $MaxRetries
            if (-not $page.Contains('value') -or $null -eq $page.value) {
                throw "Resposta ARM sem a colecao value: $Uri"
            }
            foreach ($item in $page.value) { $items.Add($item) }
            $Uri = [string]$page.nextLink
        }
    }
    catch {
        $failure = $_.Exception.Message
    }
    [pscustomobject]@{ Items = $items.ToArray(); Complete = ($null -eq $failure); Error = $failure }
}

function Add-ApimIssue {
    param([object]$Issues, [string]$Scope, [string]$Stage, [string]$Message, [switch]$ConsoleReported)

    $Issues.Add([pscustomobject]@{
        Utc = [datetime]::UtcNow.ToString('o')
        Scope = $Scope
        Stage = $Stage
        Error = $Message
    })
    if ($ConsoleReported) {
        Write-Verbose "${Stage}: $Scope - $Message"
    }
    else {
        Write-Warning "${Stage}: $Scope - $Message"
    }
}

function Get-ApimInternalStatus {
    param([string]$NetworkType)

    switch ($NetworkType) {
        'Internal' { 'Sim' }
        'External' { 'Nao' }
        'None' { 'Nao' }
        default { 'Desconhecido' }
    }
}

function Write-ApimProbeHeader {
    param([object]$Resource, [int]$Index, [int]$Total)

    $internal = Get-ApimInternalStatus $Resource.VirtualNetworkType
    $networkColor = switch ($internal) {
        'Nao' { 'Red' }
        'Sim' { 'White' }
        default { 'Yellow' }
    }
    $color = if ($Resource.ApiSubscriptionCheck.RequiredCount -gt 0) { 'Red' } else { $networkColor }
    $mode = if ($Resource.VirtualNetworkType) { $Resource.VirtualNetworkType } else { 'Nao informado' }
    Write-Host "`n$('=' * 76)" -ForegroundColor Cyan
    Write-Host " ASSINATURA : $($Resource.SubscriptionName)" -ForegroundColor Cyan
    Write-Host " ID         : $($Resource.SubscriptionId)" -ForegroundColor Gray
    Write-Host "$('-' * 76)" -ForegroundColor DarkCyan
    Write-Host " APIM [$Index/$Total]: $($Resource.Name)" -ForegroundColor $color
    Write-Host " REDE       : $mode | Interno: $internal" -ForegroundColor $networkColor
    Write-Host " GRUPO      : $($Resource.ResourceGroup)" -ForegroundColor Gray
    Write-Host "$('-' * 76)" -ForegroundColor DarkCyan
}

function Write-ApimEndpointResult {
    param([object]$Summary)

    $color = if ($Summary.Acessibilidade -eq 'Acessivel') { 'Red' } else { 'Gray' }
    $badge = if ($Summary.Acessibilidade -eq 'Acessivel') { "[HTTP $($Summary.HTTP)]" }
        elseif ($Summary.Resultado -like 'Timeout *') { '[TIMEOUT]' }
        elseif ($Summary.Acessibilidade -eq 'Nao testado') { '[SKIP]' }
        elseif ($Summary.Resultado -like '*DNS*') { '[DNS]' }
        elseif ($Summary.Resultado -like '*TCP/TLS*') { '[TCP/TLS]' }
        elseif ($Summary.Resultado -like '*TLS*') { '[TLS]' }
        elseif ($Summary.Resultado -like '*TCP*') { '[TCP]' }
        else { '[HTTP]' }
    $url = if ($Summary.URL) { $Summary.URL } else { '(nao informada)' }
    $detail = $Summary.Resultado -replace '^HTTP \d+ - |^Nao testado - ', ''
    Write-Host "       URL: $url" -ForegroundColor $color
    Write-Host "       $badge $($Summary.Acessibilidade.ToUpperInvariant()) - $detail" -ForegroundColor $color
    if ($Summary.Redirecionamento) {
        Write-Host "       Destino: $($Summary.Redirecionamento)" -ForegroundColor Gray
    }
}

function Get-ApimTargets {
    param([object]$Properties, [object]$DirectAccess)

    $managementStatus = 'Unknown'
    if ($null -ne $DirectAccess -and $null -ne $DirectAccess.properties.enabled) {
        $managementStatus = if ($DirectAccess.properties.enabled) { 'Enabled' } else { 'Disabled' }
    }
    $definitions = @(
        @{ Type = 'DeveloperPortal'; Property = 'developerPortalUrl'; HostType = 'DeveloperPortal'; Status = $Properties.developerPortalStatus },
        @{ Type = 'LegacyPortal'; Property = 'portalUrl'; HostType = 'Portal'; Status = $Properties.legacyPortalStatus },
        @{ Type = 'ManagementApi'; Property = 'managementApiUrl'; HostType = 'Management'; Status = $managementStatus }
    )
    foreach ($definition in $definitions) {
        $status = if ($definition.Status) { [string]$definition.Status } else { 'Unknown' }
        $urls = [ordered]@{}
        $url = [string]$Properties[$definition.Property]
        if ($url) { $urls[$url] = "properties.$($definition.Property)" }
        foreach ($binding in $Properties.hostnameConfigurations) {
            if ($binding.type -eq $definition.HostType -and $binding.hostName) {
                $url = "https://$($binding.hostName)"
                if (-not $urls.Contains($url)) { $urls[$url] = "hostnameConfigurations.$($binding.type)" }
            }
        }
        if ($urls.Count -eq 0) {
            [pscustomobject]@{
                Type = $definition.Type; Url = $null
                Source = "properties.$($definition.Property) ausente"
                ConfigurationStatus = $status
            }
        }
        foreach ($entry in $urls.GetEnumerator()) {
            [pscustomobject]@{
                Type = $definition.Type; Url = $entry.Key; Source = $entry.Value
                ConfigurationStatus = $status
            }
        }
    }
}

function Test-ApimPrefixContains {
    param([string]$Outer, [string]$Inner)

    if ($Outer -eq '*' -or $Outer -eq $Inner) { return $true }
    $outerParts = $Outer.Split('/')
    $innerParts = $Inner.Split('/')
    $outerIp = $null; $innerIp = $null
    if (-not [ipaddress]::TryParse($outerParts[0], [ref]$outerIp) -or
        -not [ipaddress]::TryParse($innerParts[0], [ref]$innerIp)) { return $false }
    $outerBytes = $outerIp.GetAddressBytes(); $innerBytes = $innerIp.GetAddressBytes()
    if ($outerBytes.Length -ne $innerBytes.Length) { return $false }
    $width = $outerBytes.Length * 8
    $outerBits = $width; $innerBits = $width
    if ($outerParts.Count -gt 2 -or $innerParts.Count -gt 2) { return $false }
    if ($outerParts.Count -eq 2 -and -not [int]::TryParse($outerParts[1], [ref]$outerBits)) { return $false }
    if ($innerParts.Count -eq 2 -and -not [int]::TryParse($innerParts[1], [ref]$innerBits)) { return $false }
    if ($outerBits -lt 0 -or $innerBits -lt $outerBits -or $innerBits -gt $width) { return $false }
    for ($bit = 0; $bit -lt $outerBits; $bit++) {
        $index = [int][math]::Floor($bit / 8)
        $mask = 1 -shl (7 - ($bit % 8))
        if (($outerBytes[$index] -band $mask) -ne ($innerBytes[$index] -band $mask)) { return $false }
    }
    return $true
}

function Get-ApimNsgSourceKind {
    param([string]$Source)

    if ($Source -in @('*', 'Internet', '0.0.0.0/0', '::/0')) { return 'PublicaOuAmpla' }
    if ($Source -eq 'VirtualNetwork') { return 'Interna' }
    if ($Source -eq 'AzureLoadBalancer' -or $Source -eq 'ApiManagement' -or $Source -like 'ApiManagement.*') {
        return 'InfraestruturaAzure'
    }
    foreach ($private in @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')) {
        if (Test-ApimPrefixContains $private $Source) { return 'Interna' }
    }
    $ip = $null
    if ([ipaddress]::TryParse(($Source -split '/')[0], [ref]$ip)) {
        if (Test-ApimPublicAddress $ip) { return 'PublicaOuAmpla' }
    }
    return 'Revisar'
}

function Test-ApimNsgRuleCovers {
    param([object]$Outer, [object]$Inner)

    if ($Outer.Protocol -ne '*' -and $Outer.Protocol -ne $Inner.Protocol) { return $false }
    foreach ($field in @('Sources', 'Destinations', 'SourcePorts', 'DestinationPorts')) {
        foreach ($innerValue in $Inner.$field) {
            $covered = $false
            foreach ($outerValue in $Outer.$field) {
                if ($outerValue -eq '*' -or $outerValue -eq $innerValue) { $covered = $true; break }
                if ($field -in @('Sources', 'Destinations')) {
                    if (Test-ApimPrefixContains $outerValue $innerValue) { $covered = $true; break }
                }
                elseif ($outerValue -match '^\d+(-\d+)?$' -and $innerValue -match '^\d+(-\d+)?$') {
                    $outerRange = @($outerValue -split '-' | ForEach-Object { [int]$_ })
                    $innerRange = @($innerValue -split '-' | ForEach-Object { [int]$_ })
                    if ($outerRange[0] -le $innerRange[0] -and $outerRange[-1] -ge $innerRange[-1]) {
                        $covered = $true; break
                    }
                }
            }
            if (-not $covered) { return $false }
        }
    }
    return $true
}

function Get-ApimPublicNsgRules {
    param([object[]]$Rules)

    $Rules | Where-Object {
        $_.Access -eq 'Allow' -and -not $_.CoveredByDeny -and
        $_.SourceKind -eq 'PublicaOuAmpla' -and $_.DestinationScope -eq 'Subnet'
    } | Sort-Object Priority
}

function Get-ApimNsgAnalysis {
    param([object]$Nsg, [string[]]$SubnetPrefixes)

    if (-not $Nsg.properties) { throw 'Resposta NSG sem properties.' }
    $rules = @(
        foreach ($rule in (@($Nsg.properties.securityRules) + @($Nsg.properties.defaultSecurityRules))) {
            if (-not $rule) { continue }
            $p = $rule.properties
            if ($p.direction -eq 'Outbound') { continue }
            if ($p.direction -ne 'Inbound' -or $null -eq $p.priority -or $p.access -notin @('Allow', 'Deny')) {
                throw "Regra NSG '$($rule.name)' sem direcao, prioridade ou acao valida."
            }
            $sources = @($p.sourceAddressPrefix) + @($p.sourceAddressPrefixes) +
                @($p.sourceApplicationSecurityGroups | ForEach-Object { if ($_.id) { "ASG:$($_.id)" } })
            $destinations = @($p.destinationAddressPrefix) + @($p.destinationAddressPrefixes) +
                @($p.destinationApplicationSecurityGroups | ForEach-Object { if ($_.id) { "ASG:$($_.id)" } })
            $sources = @($sources | Where-Object { $_ } | Select-Object -Unique)
            $destinations = @($destinations | Where-Object { $_ } | Select-Object -Unique)
            $sourcePorts = @(@($p.sourcePortRange) + @($p.sourcePortRanges) | Where-Object { $_ })
            $destinationPorts = @(@($p.destinationPortRange) + @($p.destinationPortRanges) | Where-Object { $_ })
            if (-not $p.protocol -or $sources.Count -eq 0 -or $destinations.Count -eq 0 -or
                $sourcePorts.Count -eq 0 -or $destinationPorts.Count -eq 0) {
                throw "Regra NSG '$($rule.name)' sem protocolo, origens, destinos ou portas."
            }
            $sourceKinds = @($sources | ForEach-Object { Get-ApimNsgSourceKind $_ } | Select-Object -Unique)
            $kind = if ('PublicaOuAmpla' -in $sourceKinds) { 'PublicaOuAmpla' }
                elseif ('Revisar' -in $sourceKinds) { 'Revisar' }
                elseif ('InfraestruturaAzure' -in $sourceKinds) { 'InfraestruturaAzure' }
                else { 'Interna' }
            $destinationScope = 'ForaDaSubnet'
            foreach ($destination in $destinations) {
                if ($destination -in @('*', 'VirtualNetwork')) { $destinationScope = 'Subnet'; break }
                $ip = $null
                if ([ipaddress]::TryParse(($destination -split '/')[0], [ref]$ip) -and $SubnetPrefixes.Count -gt 0) {
                    foreach ($prefix in $SubnetPrefixes) {
                        if ((Test-ApimPrefixContains $prefix $destination) -or (Test-ApimPrefixContains $destination $prefix)) {
                            $destinationScope = 'Subnet'; break
                        }
                    }
                    if ($destinationScope -eq 'Subnet') { break }
                }
                else { $destinationScope = 'Revisar' }
            }
            [pscustomobject]@{
                Name = $rule.name; Priority = [int]$p.priority; Access = $p.access
                Protocol = $p.protocol; Sources = $sources; SourcePorts = $sourcePorts
                Destinations = $destinations; DestinationPorts = $destinationPorts
                SourceKind = $kind; DestinationScope = $destinationScope; CoveredByDeny = $null
            }
        }
    ) | Sort-Object Priority
    $earlierDenies = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $rules) {
        if ($rule.Access -eq 'Allow') {
            foreach ($deny in $earlierDenies) {
                if (Test-ApimNsgRuleCovers $deny $rule) { $rule.CoveredByDeny = $deny.Name; break }
            }
        }
        else { $earlierDenies.Add($rule) }
    }
    $allows = @($rules | Where-Object { $_.Access -eq 'Allow' -and -not $_.CoveredByDeny -and $_.DestinationScope -ne 'ForaDaSubnet' })
    $public = @(Get-ApimPublicNsgRules -Rules @($rules))
    $review = @($allows | Where-Object { $_.SourceKind -eq 'Revisar' -or $_.DestinationScope -eq 'Revisar' })
    $internet = @{
        Protocol = '*'; Sources = @('Internet'); SourcePorts = @('*')
        Destinations = if ($SubnetPrefixes.Count -gt 0) { $SubnetPrefixes } else { @('*') }
        DestinationPorts = @('*')
    }
    $broadDenies = @($rules | Where-Object { $_.Access -eq 'Deny' -and (Test-ApimNsgRuleCovers $_ $internet) })
    $result = if ($public.Count -gt 0) { 'Regra com origem publica/ampla - revisar' }
        elseif ($review.Count -gt 0) { 'Origens ou destinos a revisar' }
        elseif ($broadDenies.Count -gt 0) { 'Sem Allow publico explicito; bloqueio geral no NSG' }
        else { 'Bloqueio geral de Internet nao identificado' }
    [pscustomobject]@{
        Result = $result
        PublicAllowCount = $public.Count
        ReviewAllowCount = $review.Count
        BroadDeny = @($broadDenies.Name) -join ', '
        Rules = @($rules)
        Notes = 'Configuracao, nao teste de acesso. Cobertura por uma regra Deny anterior; sobreposicoes parciais exigem revisao. Nao expande service tags/ASGs nem avalia regras administrativas. VirtualNetwork pode incluir peerings/rotas. ApiManagement/AzureLoadBalancer sao excecoes Azure; portas listadas no CSV.'
    }
}

function Get-ApimSubnetNsgChecks {
    param([object]$Resource, [object]$Context, [int]$MaxRetries, [object]$Issues)

    if ($Resource.VirtualNetworkType -ne 'Internal') { return }
    $bindings = @($Resource.SubnetBindings | Where-Object { $_ })
    if ($bindings.Count -eq 0) { $bindings = @(@{ Region = $Resource.Location; SubnetId = $null }) }
    foreach ($binding in $bindings) {
        $check = [ordered]@{
            Region = $binding.Region; SubnetId = $binding.SubnetId; SubnetPrefixes = @()
            NsgId = $null; Result = 'Subnet nao informada'; CheckedUtc = [datetime]::UtcNow.ToString('o')
            PublicAllowCount = $null; ReviewAllowCount = $null; BroadDeny = $null; Rules = @(); Notes = $null; Error = $null
        }
        if ($binding.SubnetId) {
            $stage = 'Subnet'
            try {
                if ($binding.SubnetId -notmatch '^/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft.Network/virtualNetworks/[^/?#]+/subnets/[^/?#]+$') {
                    throw "ID de subnet invalido: $($binding.SubnetId)"
                }
                $subnet = Invoke-ApimArmGet -Uri "$script:ArmBaseUri$($binding.SubnetId)?api-version=$script:NetworkApiVersion" -Context $Context -MaxRetries $MaxRetries
                if (-not $subnet.properties) { throw 'Resposta da subnet sem properties.' }
                $check.SubnetPrefixes = @(@($subnet.properties.addressPrefix) + @($subnet.properties.addressPrefixes) | Where-Object { $_ } | Select-Object -Unique)
                $check.NsgId = $subnet.properties.networkSecurityGroup.id
                if (-not $check.NsgId) { $check.Result = 'Subnet sem NSG associado' }
                else {
                    $stage = 'NSG'
                    if ($check.NsgId -notmatch '^/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft.Network/networkSecurityGroups/[^/?#]+$') {
                        throw "ID de NSG invalido: $($check.NsgId)"
                    }
                    $nsg = Invoke-ApimArmGet -Uri "$script:ArmBaseUri$($check.NsgId)?api-version=$script:NetworkApiVersion" -Context $Context -MaxRetries $MaxRetries
                    $analysis = Get-ApimNsgAnalysis -Nsg $nsg -SubnetPrefixes $check.SubnetPrefixes
                    foreach ($key in @('Result', 'PublicAllowCount', 'ReviewAllowCount', 'BroadDeny', 'Rules', 'Notes')) { $check[$key] = $analysis.$key }
                }
            }
            catch {
                $check.Result = "Falha na consulta/analise de $stage"
                $check.Error = $_.Exception.Message
                Add-ApimIssue $Issues $Resource.ResourceId "SubnetNsg-$stage" $check.Error
            }
        }
        [pscustomobject]$check
    }
}

function Write-ApimSubnetNsgResult {
    param([object[]]$Checks)

    $Checks = @($Checks | Where-Object { $_ })
    Write-Host "`n [NSG] SUBNETS DO APIM INTERNAL" -ForegroundColor Cyan
    if ($Checks.Count -eq 0) {
        Write-Host '       [SKIP] Inventario sem checagem NSG; execute Full/Inventory para coletar.' -ForegroundColor Yellow
    }
    foreach ($check in $Checks) {
        $color = if ($check.PublicAllowCount -gt 0) { 'Red' }
            elseif ($check.Result -eq 'Sem Allow publico explicito; bloqueio geral no NSG') { 'Gray' }
            else { 'Yellow' }
        $subnet = if ($check.SubnetId) { ($check.SubnetId -split '/')[-1] } else { '(nao informada)' }
        $nsg = if ($check.NsgId) { ($check.NsgId -split '/')[-1] } else { '(nao associado ou nao consultado)' }
        Write-Host "       Regiao: $($check.Region) | Subnet: $subnet | NSG: $nsg" -ForegroundColor Gray
        Write-Host "       [NSG] $($check.Result)" -ForegroundColor $color
        if ($check.PublicAllowCount -gt 0) {
            $publicRules = @(Get-ApimPublicNsgRules -Rules @($check.Rules))
            if ($publicRules.Count -eq 0) {
                Write-Host '         [REGRA] Detalhes indisponiveis no inventario; execute Full/Inventory para coletar.' -ForegroundColor Yellow
            }
            foreach ($rule in $publicRules) {
                Write-Host "         [REGRA] $($rule.Name)" -ForegroundColor Red
                Write-Host "           Prioridade: $($rule.Priority) | Acao: $($rule.Access) | Protocolo: $($rule.Protocol)" -ForegroundColor Red
                Write-Host "           Origem: $($rule.Sources -join ', ') | Portas origem: $($rule.SourcePorts -join ', ')" -ForegroundColor Red
                Write-Host "           Destino: $($rule.Destinations -join ', ') | Portas destino: $($rule.DestinationPorts -join ', ')" -ForegroundColor Red
            }
        }
    }
}

function Get-ApimNamedValueCheck {
    param([object]$Resource, [object]$Context, [int]$MaxRetries, [object]$Issues)

    $check = [ordered]@{
        CheckedUtc = [datetime]::UtcNow.ToString('o')
        Result = 'Consultado'
        PlainCount = $null; SecretCount = $null; KeyVaultCount = $null; TotalCount = $null
        Error = $null
    }
    try {
        $page = Get-ApimArmCollection -Uri "$script:ArmBaseUri$($Resource.ResourceId)/namedValues?api-version=$script:ApimApiVersion" -Context $Context -MaxRetries $MaxRetries
        if (-not $page.Complete) { throw $page.Error }
        $plain = 0
        $secret = 0
        $keyVault = 0
        foreach ($item in $page.Items) {
            $properties = $item.properties
            if (-not $properties -or ($null -ne $properties.secret -and $properties.secret -isnot [bool])) {
                throw 'Named Value sem metadados properties/secret validos; contagem indisponivel.'
            }
            if ($null -ne $properties.keyVault) {
                if (-not $properties.keyVault.secretIdentifier) {
                    throw 'Named Value com referencia Key Vault incompleta; contagem indisponivel.'
                }
                $keyVault++
            }
            elseif ($properties.secret) { $secret++ }
            else { $plain++ }
        }
        $check.PlainCount = $plain
        $check.SecretCount = $secret
        $check.KeyVaultCount = $keyVault
        $check.TotalCount = $page.Items.Count
    }
    catch {
        $check.Result = 'Falha na consulta/classificacao de Named Values'
        $check.Error = $_.Exception.Message
        Add-ApimIssue $Issues $Resource.ResourceId 'NamedValues' $check.Error
    }
    [pscustomobject]$check
}

function Get-ApimProviderCheck {
    param(
        [object]$Resource, [object]$Context, [int]$MaxRetries, [object]$Issues,
        [ValidateSet('Identity', 'OpenIdConnect')][string]$Kind
    )

    $collection = if ($Kind -eq 'Identity') { 'identityProviders' } else { 'openidConnectProviders' }
    $check = [ordered]@{
        CheckedUtc = [datetime]::UtcNow.ToString('o'); Result = 'Consultado'
        ProviderCount = $null; SecretUnknownCount = $null; Providers = @()
        Notes = 'Somente inventario GET. Nao inspeciona clientSecret nem chama listSecrets. Client ID informado nao comprova presenca ou validade de client secret.'
        Error = $null
    }
    try {
        $page = Get-ApimArmCollection -Uri "$script:ArmBaseUri$($Resource.ResourceId)/$collection`?api-version=$script:ApimApiVersion" -Context $Context -MaxRetries $MaxRetries
        if (-not $page.Complete) { throw $page.Error }
        $providers = [System.Collections.Generic.List[object]]::new()
        foreach ($provider in $page.Items) {
            $properties = $provider.properties
            if ([string]::IsNullOrWhiteSpace([string]$provider.name) -or -not $properties -or
                ($null -ne $properties.clientId -and $properties.clientId -isnot [string])) {
                throw 'Provedor sem name/properties ou com clientId invalido; contagem indisponivel.'
            }
            $name = if ($Kind -eq 'OpenIdConnect' -and -not [string]::IsNullOrWhiteSpace([string]$properties.displayName)) {
                $properties.displayName
            } else { $provider.name }
            $type = if ($Kind -eq 'OpenIdConnect') { 'OpenID Connect' }
                elseif ($properties.type) { $properties.type } else { 'Nao informado' }
            $clientIdStatus = if ($null -eq $properties.clientId) { 'Nao determinado' }
                elseif ([string]::IsNullOrWhiteSpace($properties.clientId)) { 'Nao informado' } else { 'Informado' }
            $providers.Add([pscustomobject]@{
                ProviderId = [string]$provider.name; Name = [string]$name; Type = [string]$type
                ClientIdStatus = $clientIdStatus; ClientSecretStatus = 'Nao determinado'
            })
        }
        $check.Providers = $providers.ToArray()
        $check.ProviderCount = $providers.Count
        $check.SecretUnknownCount = $providers.Count
    }
    catch {
        $check.Result = 'Falha na consulta/classificacao de provedores'
        $check.Error = $_.Exception.Message
        Add-ApimIssue $Issues $Resource.ResourceId $collection $check.Error
    }
    [pscustomobject]$check
}

function Write-ApimProviderResult {
    param([object]$Check, [string]$Title)

    Write-Host "`n [$Title] CLIENT SECRETS - INVENTARIO" -ForegroundColor Cyan
    if (-not $Check) {
        Write-Host '       [SKIP] Inventario sem checagem de provedores; execute Full/Inventory para coletar.' -ForegroundColor Yellow
    }
    elseif ($Check.Error) {
        Write-Host "       $($Check.Result) | $($Check.Error)" -ForegroundColor Yellow
    }
    else {
        Write-Host "       Provedores: $($Check.ProviderCount) | Client secret nao determinado: $($Check.SecretUnknownCount)" -ForegroundColor Gray
        foreach ($provider in $Check.Providers) {
            Write-Host "         [PROVEDOR] $($provider.Name) (ID: $($provider.ProviderId)) | Tipo: $($provider.Type)" -ForegroundColor Gray
            Write-Host "           Client ID: $($provider.ClientIdStatus) | Client secret: $($provider.ClientSecretStatus)" -ForegroundColor Yellow
        }
    }
}

function Write-ApimNamedValueResult {
    param([object]$Check)

    Write-Host "`n [NAMED VALUES] CONTAGEM POR TIPO" -ForegroundColor Cyan
    if (-not $Check) {
        Write-Host '       [SKIP] Inventario sem checagem de Named Values; execute Full/Inventory para coletar.' -ForegroundColor Yellow
    }
    elseif ($Check.Error) {
        Write-Host "       $($Check.Result) | $($Check.Error)" -ForegroundColor Yellow
    }
    else {
        Write-Host "       Plain: $($Check.PlainCount) | Secret: $($Check.SecretCount) | Key Vault: $($Check.KeyVaultCount) | Total: $($Check.TotalCount)" -ForegroundColor Gray
    }
}

function Get-ApimSubscriptionCheck {
    param([object]$Resource, [object]$Context, [int]$MaxRetries, [object]$Issues)

    $check = [ordered]@{
        CheckedUtc = [datetime]::UtcNow.ToString('o'); Result = 'Consultado'
        DefaultCount = $null; CustomCount = $null; TotalCount = $null
        Notes = 'Subscriptions APIM, nao assinaturas Azure. Inclui todos os estados; nao indica uso ou validade das chaves.'
        Error = $null
    }
    try {
        $page = Get-ApimArmCollection -Uri "$script:ArmBaseUri$($Resource.ResourceId)/subscriptions?api-version=$script:ApimApiVersion" -Context $Context -MaxRetries $MaxRetries
        if (-not $page.Complete) { throw $page.Error }
        $defaultCount = 0
        $customCount = 0
        foreach ($item in $page.Items) {
            if ([string]::IsNullOrWhiteSpace([string]$item.name)) {
                throw 'Subscription APIM sem identificador name; contagem indisponivel.'
            }
            # O nome visivel e o escopo nao identificam a subscription embutida.
            if ($item.name -eq 'master') { $defaultCount++ }
            else { $customCount++ }
        }
        $check.DefaultCount = $defaultCount
        $check.CustomCount = $customCount
        $check.TotalCount = $page.Items.Count
    }
    catch {
        $check.Result = 'Falha na consulta/classificacao de subscriptions APIM'
        $check.Error = $_.Exception.Message
        Add-ApimIssue $Issues $Resource.ResourceId 'ApimSubscriptions' $check.Error
    }
    [pscustomobject]$check
}

function Get-ApimApiSubscriptionCheck {
    param([object]$Resource, [object]$Context, [int]$MaxRetries, [object]$Issues)

    $check = [ordered]@{
        CheckedUtc = [datetime]::UtcNow.ToString('o'); Result = 'Consultado'
        ApiCount = $null; RequiredCount = $null; NotRequiredCount = $null; UnknownCount = $null
        Apis = @()
        Notes = 'Campo subscriptionRequired da API. Inclui APIs/revisoes retornadas pelo ARM; nao avalia produtos abertos, policies ou acesso efetivo.'
        Error = $null
    }
    try {
        $page = Get-ApimArmCollection -Uri "$script:ArmBaseUri$($Resource.ResourceId)/apis?api-version=$script:ApimApiVersion" -Context $Context -MaxRetries $MaxRetries
        if (-not $page.Complete) { throw $page.Error }
        $apis = [System.Collections.Generic.List[object]]::new()
        foreach ($api in $page.Items) {
            if ([string]::IsNullOrWhiteSpace([string]$api.name) -or -not $api.properties) {
                throw 'API sem name ou properties; contagem indisponivel.'
            }
            $row = [pscustomobject]@{
                ApiId = [string]$api.name; Name = $api.properties.displayName
                Version = $api.properties.apiVersion; Revision = $api.properties.apiRevision
                IsCurrent = $api.properties.isCurrent; SubscriptionRequired = $null
                Result = 'Consultado'; Error = $null
            }
            try {
                $required = $api.properties.subscriptionRequired
                if ($required -isnot [bool]) {
                    $apiName = [uri]::EscapeDataString([string]$api.name)
                    $detail = Invoke-ApimArmGet -Uri "$script:ArmBaseUri$($Resource.ResourceId)/apis/$apiName`?api-version=$script:ApimApiVersion" -Context $Context -MaxRetries $MaxRetries
                    $required = $detail.properties.subscriptionRequired
                }
                if ($required -isnot [bool]) {
                    throw 'subscriptionRequired ausente ou invalido mesmo apos consultar a API individualmente.'
                }
                $row.SubscriptionRequired = $required
            }
            catch {
                $row.Result = 'Nao determinado'
                $row.Error = $_.Exception.Message
                Add-ApimIssue $Issues "$($Resource.ResourceId)/apis/$($api.name)" 'ApiSubscriptionRequired' $row.Error
            }
            $apis.Add($row)
        }
        $check.Apis = $apis.ToArray()
        $check.ApiCount = $apis.Count
        $check.RequiredCount = @($check.Apis | Where-Object { $_.SubscriptionRequired -eq $true }).Count
        $check.NotRequiredCount = @($check.Apis | Where-Object { $_.SubscriptionRequired -eq $false }).Count
        $check.UnknownCount = @($check.Apis | Where-Object { $null -eq $_.SubscriptionRequired }).Count
        if ($check.UnknownCount -gt 0) {
            $check.Result = 'Consultado com APIs nao determinadas'
            $check.Error = "subscriptionRequired nao determinado para $($check.UnknownCount) API(s)/revisao(oes); consulte issues.csv."
        }
    }
    catch {
        $check.Result = 'Falha na consulta/classificacao de APIs'
        $check.Error = $_.Exception.Message
        Add-ApimIssue $Issues $Resource.ResourceId 'ApiSubscriptions' $check.Error
    }
    [pscustomobject]$check
}

function Write-ApimSubscriptionResult {
    param([object]$SubscriptionCheck, [object]$ApiCheck)

    Write-Host "`n [SUBSCRIPTIONS APIM] PADRAO E CUSTOMIZADAS" -ForegroundColor Cyan
    if (-not $SubscriptionCheck) {
        Write-Host '       [SKIP] Inventario sem checagem de subscriptions; execute Full/Inventory.' -ForegroundColor Yellow
    }
    elseif ($SubscriptionCheck.Error) {
        Write-Host "       $($SubscriptionCheck.Result) | $($SubscriptionCheck.Error)" -ForegroundColor Yellow
    }
    else {
        Write-Host "       Padrao (All-access): $($SubscriptionCheck.DefaultCount) | Customizadas: $($SubscriptionCheck.CustomCount) | Total: $($SubscriptionCheck.TotalCount)" -ForegroundColor Gray
    }
    Write-Host ' [APIS] SUBSCRIPTION KEY NA CONFIGURACAO DA API' -ForegroundColor Cyan
    if (-not $ApiCheck) {
        Write-Host '       [SKIP] Inventario sem checagem de APIs; execute Full/Inventory.' -ForegroundColor Yellow
    }
    else {
        if ($ApiCheck.Error) {
            Write-Host "       $($ApiCheck.Result) | $($ApiCheck.Error)" -ForegroundColor Yellow
        }
        if ($null -ne $ApiCheck.ApiCount) {
            $color = if ($ApiCheck.RequiredCount -gt 0) { 'Red' } else { 'Gray' }
            Write-Host "       Exigem: $($ApiCheck.RequiredCount) | Nao exigem: $($ApiCheck.NotRequiredCount) | Nao determinado: $($ApiCheck.UnknownCount) | Total APIs/revisoes: $($ApiCheck.ApiCount)" -ForegroundColor $color
            if ($ApiCheck.RequiredCount -gt 0) {
                $requiredApis = @($ApiCheck.Apis | Where-Object {
                    $_.SubscriptionRequired -is [bool] -and $_.SubscriptionRequired
                } | Group-Object { [string]$_.ApiId -replace ';rev=[^;]+$', '' } | Sort-Object Name)
                if ($requiredApis.Count -eq 0) {
                    Write-Host '       [SKIP] Lista de APIs indisponivel no inventario; execute Full/Inventory para coletar.' -ForegroundColor Yellow
                }
                else {
                    Write-Host '       APIs com chave obrigatoria (em ao menos uma revisao):' -ForegroundColor Red
                    foreach ($group in $requiredApis) {
                        $api = $group.Group[0]
                        $name = if ([string]::IsNullOrWhiteSpace([string]$api.Name)) { $group.Name } else { $api.Name }
                        Write-Host "         [API] $name (ID: $($group.Name))" -ForegroundColor Red
                    }
                }
            }
        }
    }
}

function ConvertTo-ApimInventoryRecord {
    param([object]$Resource, [object]$Subscription, [guid]$Tenant, [object]$DirectAccess)

    if (-not $Resource.id -or -not $Resource.properties) {
        throw 'Recurso APIM sem id ou properties.'
    }
    $properties = $Resource.properties
    $privateEndpoints = @(
        foreach ($connection in $properties.privateEndpointConnections) {
            [pscustomobject]@{
                Id = $connection.id
                PrivateEndpointId = $connection.properties.privateEndpoint.id
                Status = $connection.properties.privateLinkServiceConnectionState.status
                ProvisioningState = $connection.properties.provisioningState
            }
        }
    )
    [pscustomobject]@{
        TenantId = $Tenant.ToString()
        SubscriptionId = $Subscription.subscriptionId
        SubscriptionName = $Subscription.displayName
        ResourceGroup = ($Resource.id -split '/')[4]
        Name = $Resource.name
        ResourceId = $Resource.id
        Location = $Resource.location
        Sku = $Resource.sku.name
        ProvisioningState = $properties.provisioningState
        VirtualNetworkType = $properties.virtualNetworkType
        PublicNetworkAccess = $properties.publicNetworkAccess
        DeveloperPortalStatus = $properties.developerPortalStatus
        LegacyPortalStatus = $properties.legacyPortalStatus
        DirectManagementApiEnabled = $DirectAccess.properties.enabled
        SubnetBindings = @(
            [pscustomobject]@{ Region = $Resource.location; SubnetId = $properties.virtualNetworkConfiguration.subnetResourceId }
            foreach ($region in $properties.additionalLocations) {
                [pscustomobject]@{ Region = $region.location; SubnetId = $region.virtualNetworkConfiguration.subnetResourceId }
            }
        )
        SubnetChecks = @()
        NamedValueCheck = $null
        IdentityProviderCheck = $null
        OpenIdConnectProviderCheck = $null
        SubscriptionCheck = $null
        ApiSubscriptionCheck = $null
        PrivateEndpoints = $privateEndpoints
        Hostnames = @(
            foreach ($binding in $properties.hostnameConfigurations) {
                [pscustomobject]@{ Type = $binding.type; HostName = $binding.hostName }
            }
        )
        Targets = @(Get-ApimTargets -Properties $properties -DirectAccess $DirectAccess)
    }
}

function Get-ApimInventory {
    param(
        [guid]$Tenant, [guid[]]$Subscriptions, [int]$MaxRetries, [object]$Issues,
        [ValidateRange(0, 2147483647)][int]$MaxInstances = 0,
        [switch]$CheckNsg,
        [string[]]$ApimNames = @()
    )

    if (-not (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue)) {
        throw 'Az.Accounts nao encontrado. Execute no PowerShell do Azure Cloud Shell.'
    }
    $context = Get-AzContext -ErrorAction Stop
    if (-not $context -or [string]$context.Tenant.Id -ne $Tenant.ToString()) {
        throw "Sessao ausente ou em outro tenant. Execute Connect-AzAccount -Tenant '$Tenant' e tente novamente."
    }
    if ($context.Environment.Name -ne 'AzureCloud') {
        throw 'Este script suporta somente Azure publico (AzureCloud), nao clouds soberanas.'
    }
    $resources = [System.Collections.Generic.List[object]]::new()
    $coverage = [System.Collections.Generic.List[object]]::new()
    $subscriptionPage = Get-ApimArmCollection -Uri "$script:ArmBaseUri/subscriptions?api-version=2022-12-01" -Context $context -MaxRetries $MaxRetries
    if (-not $subscriptionPage.Complete) {
        Add-ApimIssue $Issues $Tenant 'SubscriptionDiscovery' $subscriptionPage.Error
    }
    $requested = @($Subscriptions | ForEach-Object { $_.ToString() })
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $processedCount = 0
    foreach ($subscription in $subscriptionPage.Items) {
        $id = [string]$subscription.subscriptionId
        if ($requested.Count -gt 0 -and $id -notin $requested) { continue }
        if (-not $seen.Add($id)) { continue }
        $entry = [pscustomobject]@{
            SubscriptionId = $id; SubscriptionName = $subscription.displayName
            State = $subscription.state; InventoryStatus = 'Pending'; ApimCount = 0; Error = $null
        }
        $coverage.Add($entry)
        if ($MaxInstances -gt 0 -and $processedCount -ge $MaxInstances) {
            $entry.InventoryStatus = 'NotInventoriedLimit'
            continue
        }
        if ($subscription.state -ne 'Enabled') {
            $entry.InventoryStatus = 'Skipped'
            $entry.Error = "Subscription no estado $($subscription.state)."
            Add-ApimIssue $Issues $id 'SubscriptionSkipped' $entry.Error
            continue
        }
        Write-Verbose "Inventariando subscription: $($subscription.displayName) ($id)"
        $page = Get-ApimArmCollection -Uri "$script:ArmBaseUri/subscriptions/$id/providers/Microsoft.ApiManagement/service?api-version=$script:ApimApiVersion" -Context $context -MaxRetries $MaxRetries
        $entry.InventoryStatus = if ($page.Complete) { 'Complete' } else { 'PartialOrFailed' }
        $entry.Error = $page.Error
        if (-not $page.Complete) { Add-ApimIssue $Issues $id 'ApimDiscovery' $page.Error }
        if ($page.Complete -and $page.Items.Count -eq 0) {
            Write-Verbose 'Nenhum APIM encontrado nesta subscription.'
        }
        foreach ($resource in $page.Items) {
            if ($ApimNames.Count -gt 0 -and $resource.name -notin $ApimNames) { continue }
            if ($MaxInstances -gt 0 -and $processedCount -ge $MaxInstances) {
                if ($entry.InventoryStatus -eq 'Complete') { $entry.InventoryStatus = 'Limited' }
                break
            }
            $processedCount++
            $access = $null
            try {
                $access = Invoke-ApimArmGet -Uri "$script:ArmBaseUri$($resource.id)/tenant/access?api-version=$script:ApimApiVersion" -Context $context -MaxRetries $MaxRetries
            }
            catch {
                $entry.InventoryStatus = 'PartialOrFailed'
                if (-not $entry.Error) { $entry.Error = 'Falha ao ler configuracao de API direta; consulte issues.csv.' }
                Add-ApimIssue $Issues $resource.id 'DirectManagementConfiguration' $_.Exception.Message
            }
            try {
                $record = ConvertTo-ApimInventoryRecord -Resource $resource -Subscription $subscription -Tenant $Tenant -DirectAccess $access
                if ($CheckNsg -and $record.VirtualNetworkType -eq 'Internal') {
                    $record.SubnetChecks = @(Get-ApimSubnetNsgChecks -Resource $record -Context $context -MaxRetries $MaxRetries -Issues $Issues)
                }
                $record.NamedValueCheck = Get-ApimNamedValueCheck -Resource $record -Context $context -MaxRetries $MaxRetries -Issues $Issues
                if ($record.NamedValueCheck.Error) {
                    $entry.InventoryStatus = 'PartialOrFailed'
                    if (-not $entry.Error) { $entry.Error = 'Falha na checagem de Named Values; consulte issues.csv.' }
                }
                $record.SubscriptionCheck = Get-ApimSubscriptionCheck -Resource $record -Context $context -MaxRetries $MaxRetries -Issues $Issues
                $record.ApiSubscriptionCheck = Get-ApimApiSubscriptionCheck -Resource $record -Context $context -MaxRetries $MaxRetries -Issues $Issues
                if ($record.SubscriptionCheck.Error -or $record.ApiSubscriptionCheck.Error) {
                    $entry.InventoryStatus = 'PartialOrFailed'
                    if (-not $entry.Error) { $entry.Error = 'Falha na checagem de subscriptions/APIs; consulte issues.csv.' }
                }
                $record.IdentityProviderCheck = Get-ApimProviderCheck -Resource $record -Context $context -MaxRetries $MaxRetries -Issues $Issues -Kind Identity
                $record.OpenIdConnectProviderCheck = Get-ApimProviderCheck -Resource $record -Context $context -MaxRetries $MaxRetries -Issues $Issues -Kind OpenIdConnect
                if ($record.IdentityProviderCheck.Error -or $record.OpenIdConnectProviderCheck.Error) {
                    $entry.InventoryStatus = 'PartialOrFailed'
                    if (-not $entry.Error) { $entry.Error = 'Falha na checagem de provedores; consulte issues.csv.' }
                }
                $resources.Add($record)
                $entry.ApimCount++
            }
            catch {
                $entry.InventoryStatus = 'PartialOrFailed'
                Add-ApimIssue $Issues $resource.id 'ResourceInventory' $_.Exception.Message
            }
        }
    }
    foreach ($id in $requested) {
        if (-not $seen.Contains($id)) {
            $message = 'Subscription solicitada nao retornada para esta identidade no tenant.'
            $coverage.Add([pscustomobject]@{
                SubscriptionId = $id; SubscriptionName = $null; State = 'Unknown'
                InventoryStatus = 'NotVisible'; ApimCount = 0; Error = $message
            })
            Add-ApimIssue $Issues $id 'SubscriptionNotVisible' $message
        }
    }
    [pscustomobject]@{
        Resources = $resources.ToArray()
        Subscriptions = $coverage.ToArray()
        SubscriptionDiscoveryComplete = $subscriptionPage.Complete
    }
}

function Test-ApimPublicAddress {
    param([System.Net.IPAddress]$Address)

    if ($Address.IsIPv4MappedToIPv6) { $Address = $Address.MapToIPv4() }
    $bytes = $Address.GetAddressBytes()
    if ($bytes.Length -eq 4) {
        if ($bytes[0] -in @(0, 10, 127) -or $bytes[0] -ge 224) { return $false }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return $false }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $false }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $false }
        if ($bytes[0] -eq 192 -and (
            ($bytes[1] -eq 168) -or
            ($bytes[1] -eq 0 -and $bytes[2] -in @(0, 2)) -or
            ($bytes[1] -eq 88 -and $bytes[2] -eq 99))) { return $false }
        if ($bytes[0] -eq 198 -and ($bytes[1] -in @(18, 19) -or ($bytes[1] -eq 51 -and $bytes[2] -eq 100))) { return $false }
        if ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113) { return $false }
        return $true
    }
    # Conservador: somente unicast global, excluindo faixas especiais conhecidas.
    if (($bytes[0] -band 0xe0) -ne 0x20) { return $false }
    if ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and (
        $bytes[2] -le 1 -or ($bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8))) { return $false }
    if ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x02) { return $false }
    if ($bytes[0] -eq 0x3f -and $bytes[1] -eq 0xff -and $bytes[2] -lt 0x10) { return $false }
    return $true
}

function Resolve-ApimEndpoint {
    param([uri]$Uri, [int]$Timeout)

    $task = [System.Net.Dns]::GetHostAddressesAsync($Uri.DnsSafeHost)
    $addresses = $task.WaitAsync([timespan]::FromSeconds($Timeout)).GetAwaiter().GetResult()
    if ($addresses.Count -eq 0) { throw 'DNS nao retornou enderecos.' }
    foreach ($address in $addresses) {
        [pscustomobject]@{
            Address = $address.ToString()
            Scope = if (Test-ApimPublicAddress $address) { 'PublicCandidate' } else { 'PrivateOrReserved' }
        }
    }
}

function Invoke-ApimTransportProbe {
    param([uri]$Uri, [object[]]$Addresses, [int]$Timeout)

    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($address in $Addresses) {
        $client = [System.Net.Sockets.TcpClient]::new()
        $ssl = $null
        $connected = $false
        try {
            $task = $client.ConnectAsync([System.Net.IPAddress]::Parse($address.Address), $Uri.Port)
            $null = $task.WaitAsync([timespan]::FromSeconds($Timeout)).GetAwaiter().GetResult()
            $connected = $true
            $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
            $task = $ssl.AuthenticateAsClientAsync($Uri.DnsSafeHost)
            $null = $task.WaitAsync([timespan]::FromSeconds($Timeout)).GetAwaiter().GetResult()
            return [pscustomobject]@{
                TcpStatus = 'Connected'; TlsStatus = 'Validated'
                TlsProtocol = $ssl.SslProtocol.ToString(); ConnectedAddress = $address.Address
                ErrorStage = $null; Error = $null; TcpAttemptErrors = $errors.ToArray()
            }
        }
        catch {
            $message = $_.Exception.GetBaseException().Message
            if ($connected) {
                return [pscustomobject]@{
                    TcpStatus = 'Connected'; TlsStatus = 'Failed'
                    TlsProtocol = $null; ConnectedAddress = $address.Address
                    ErrorStage = 'TLS'; Error = $message; TcpAttemptErrors = $errors.ToArray()
                }
            }
            $errors.Add("$($address.Address): $message")
        }
        finally {
            if ($ssl) { $ssl.Dispose() }
            $client.Dispose()
        }
    }
    [pscustomobject]@{
        TcpStatus = 'Failed'; TlsStatus = 'NotTested'; TlsProtocol = $null
        ConnectedAddress = $null; ErrorStage = 'TCP'; Error = ($errors -join '; ')
        TcpAttemptErrors = $errors.ToArray()
    }
}

function Invoke-ApimHttpProbe {
    param([uri]$Uri, [int]$Timeout)

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $handler.UseDefaultCredentials = $false
    $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds($Timeout)
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
    $response = $null
    try {
        $task = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
        $response = $task.GetAwaiter().GetResult()
        $redirect = $null
        if ($response.Headers.Location) {
            $destination = [uri]::new($Uri, $response.Headers.Location)
            # Nao persistir query/fragment: podem conter estado de autenticacao.
            if ($destination.Scheme -in @('https', 'http')) {
                $builder = [System.UriBuilder]::new($destination)
                $builder.UserName = ''; $builder.Password = ''
                $builder.Query = ''; $builder.Fragment = ''
                $redirect = $builder.Uri.AbsoluteUri
            }
            else { $redirect = "$($destination.Scheme):[destino omitido]" }
        }
        [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            RedirectLocation = $redirect
            ServerHeader = [string]$response.Headers.Server
        }
    }
    finally {
        if ($response) { $response.Dispose() }
        $request.Dispose()
        $client.Dispose()
    }
}

function Invoke-ApimEndpointProbe {
    param([object]$Target, [int]$Timeout, [bool]$DeclaredPublicOrigin)

    $result = [ordered]@{
        EndpointType = $Target.Type; Url = $Target.Url; EndpointSource = $Target.Source
        ConfigurationStatus = $Target.ConfigurationStatus
        ProbeUtc = [datetime]::UtcNow.ToString('o'); PublicOriginDeclared = $DeclaredPublicOrigin
        DnsStatus = 'NotTested'; Addresses = @()
        TcpStatus = 'NotTested'; ConnectedAddress = $null; TcpAttemptErrors = @()
        TlsStatus = 'NotTested'; TlsProtocol = $null
        HttpStatusCode = $null; RedirectLocation = $null; ServerHeader = $null
        BackendAttribution = 'NotDetermined'
        Conclusion = 'Inconclusive'; ErrorStage = $null; Error = $null
    }
    if (-not $Target.Url) {
        $result.Conclusion = if ($Target.ConfigurationStatus -eq 'Disabled') { 'ConfiguredDisabledNoEndpoint' } else { 'EndpointNotIdentified' }
        return [pscustomobject]$result
    }
    $uri = $null
    if (-not [uri]::TryCreate($Target.Url, [System.UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        $result.ErrorStage = 'TargetValidation'
        $result.Error = 'Alvo deve ser HTTPS, sem credenciais, query ou fragment.'
        return [pscustomobject]$result
    }
    $stage = 'DNS'
    try {
        $result.Addresses = @(Resolve-ApimEndpoint -Uri $uri -Timeout $Timeout)
        $result.DnsStatus = 'Resolved'
        $stage = 'Transport'
        $transport = Invoke-ApimTransportProbe -Uri $uri -Addresses $result.Addresses -Timeout $Timeout
        foreach ($key in @('TcpStatus', 'TlsStatus', 'TlsProtocol', 'ConnectedAddress', 'TcpAttemptErrors', 'ErrorStage', 'Error')) {
            $result[$key] = $transport.$key
        }
        if ($transport.TlsStatus -ne 'Validated') { return [pscustomobject]$result }
        $stage = 'HTTP'
        $http = Invoke-ApimHttpProbe -Uri $uri -Timeout $Timeout
        $result.HttpStatusCode = $http.StatusCode
        $result.RedirectLocation = $http.RedirectLocation
        $result.ServerHeader = $http.ServerHeader
        $nonPublic = @($result.Addresses | Where-Object Scope -ne 'PublicCandidate')
        $result.Conclusion = if ($DeclaredPublicOrigin -and $nonPublic.Count -eq 0) {
            'HttpResponseFromDeclaredPublicOrigin'
        }
        else { 'HttpResponseObservedOriginUnconfirmed' }
    }
    catch {
        if ($stage -eq 'DNS') { $result.DnsStatus = 'Failed' }
        $result.ErrorStage = $stage
        $result.Error = $_.Exception.GetBaseException().Message
    }
    [pscustomobject]$result
}

function Export-ApimCsv {
    param([object[]]$Data, [string[]]$Columns, [string]$Path, [char]$Delimiter = ',')

    if ($Data.Count -eq 0) {
        $empty = [ordered]@{}
        foreach ($column in $Columns) { $empty[$column] = $null }
        ([pscustomobject]$empty | ConvertTo-Csv -NoTypeInformation -Delimiter $Delimiter)[0] | Set-Content -LiteralPath $Path -Encoding utf8BOM
        return
    }
    $Data | ForEach-Object {
        $row = [ordered]@{}
        foreach ($column in $Columns) {
            $value = $_.$column
            $row[$column] = if ($value -is [datetime]) { $value.ToUniversalTime().ToString('o') }
                elseif ($value -is [datetimeoffset]) { $value.UtcDateTime.ToString('o') }
                elseif ($null -ne $value -and $value -isnot [string] -and
                $value -isnot [ValueType]) { ConvertTo-Json -InputObject $value -Depth 30 -Compress } else { $value }
        }
        [pscustomobject]$row
    } | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8BOM -Delimiter $Delimiter
}

function ConvertTo-ApimEndpointSummary {
    param([object]$EndpointResult)

    $result = 'Nao testado'
    $accessibility = 'Nao testado'
    if ($null -ne $EndpointResult.HttpStatusCode) {
        $accessibility = 'Acessivel'
        $code = [int]$EndpointResult.HttpStatusCode
        $description = switch ($code) {
            401 { 'Autenticacao exigida'; break }
            403 { 'Acesso negado'; break }
            404 { 'Caminho nao encontrado'; break }
            { $_ -in @(300, 301, 302, 303, 305, 307, 308) } { 'Redirecionamento'; break }
            { $_ -ge 500 } { 'Erro no servidor'; break }
            { $_ -ge 400 } { 'Erro HTTP'; break }
            default { 'Resposta recebida' }
        }
        $result = "HTTP $code - $description"
    }
    elseif ($EndpointResult.Conclusion -eq 'ConfiguredDisabledNoEndpoint') {
        $result = 'Nao testado - Desabilitado'
    }
    elseif ($EndpointResult.Conclusion -eq 'EndpointNotIdentified') {
        $result = 'Nao testado - URL nao informada'
    }
    elseif ($EndpointResult.ErrorStage -eq 'TargetValidation') {
        $result = 'Nao testado - URL invalida'
    }
    elseif ($EndpointResult.ErrorStage -in @('DNS', 'TCP', 'TLS', 'HTTP', 'Transport')) {
        $accessibility = 'Nao acessivel'
        $failure = if ($EndpointResult.Error -match '(?i)timed?\s*out|timeout|tempo.*(limite|esgot)') { 'Timeout' } else { 'Falha' }
        $stage = if ($EndpointResult.ErrorStage -eq 'Transport') { 'TCP/TLS' } else { $EndpointResult.ErrorStage }
        $result = "$failure $stage"
    }

    [pscustomobject]@{
        Assinatura = $EndpointResult.SubscriptionName
        AssinaturaId = $EndpointResult.SubscriptionId
        APIM = $EndpointResult.Name
        ResourceGroup = $EndpointResult.ResourceGroup
        ModoRede = if ($EndpointResult.VirtualNetworkType) { $EndpointResult.VirtualNetworkType } else { 'Nao informado' }
        Interno = Get-ApimInternalStatus $EndpointResult.VirtualNetworkType
        Endpoint = $EndpointResult.EndpointType
        URL = $EndpointResult.Url
        Acessibilidade = $accessibility
        Resultado = $result
        HTTP = $EndpointResult.HttpStatusCode
        ConfiguracaoEndpoint = $EndpointResult.ConfigurationStatus
        Redirecionamento = $EndpointResult.RedirectLocation
        OrigemPublicaDeclarada = if ($EndpointResult.PublicOriginDeclared) { 'Sim' } else { 'Nao' }
        DataHoraUTC = $EndpointResult.ProbeUtc
        Erro = $EndpointResult.Error
    }
}

function Write-ApimMetadataSummary {
    param(
        [object[]]$Resources, [string]$Title, [string]$CheckProperty,
        [System.Collections.IDictionary]$CountLabels
    )

    $checks = @($Resources | ForEach-Object { $_.$CheckProperty } | Where-Object { $_ })
    $available = @($checks | Where-Object {
        $check = $_
        @($CountLabels.Keys | Where-Object { $null -eq $check.$_ }).Count -eq 0
    })
    $unavailable = $Resources.Count - $available.Count
    $incomplete = $unavailable -gt 0 -or @($checks | Where-Object Error).Count -gt 0
    $suffix = if ($incomplete) { ' [parcial]' } else { '' }
    $parts = foreach ($property in $CountLabels.Keys) {
        $value = if ($available.Count -eq 0 -and $Resources.Count -gt 0) { 'N/D' }
            else { ($available | Measure-Object -Property $property -Sum).Sum + 0 }
        "$($CountLabels[$property]): $value"
    }
    $color = if ($incomplete) { 'Yellow' } else { 'Gray' }
    Write-Host " $($Title.PadRight(15)) | $($parts -join ' | ')$suffix" -ForegroundColor $color
}

function Write-ApimNsgSummary {
    param([object]$Audit)

    if (-not $Audit.NsgCheckEnabled) { return }
    $origin = if ($Audit.Mode -eq 'Probe') { ' [inventario salvo]' } else { '' }
    $internal = @($Audit.Resources | Where-Object VirtualNetworkType -eq 'Internal')
    if ($internal.Count -eq 0) {
        Write-Host " NSG             | Nao aplicavel (nenhum APIM Internal).$origin" -ForegroundColor Gray
        return
    }
    $checks = @($internal | ForEach-Object { $_.SubnetChecks } | Where-Object { $_ })
    $missing = @($internal | Where-Object { @($_.SubnetChecks | Where-Object { $_ }).Count -eq 0 }).Count
    if ($checks.Count -eq 0) {
        Write-Host " NSG             | N/D (inventario sem evidencias).$origin" -ForegroundColor Yellow
        return
    }
    $analyzed = @($checks | Where-Object {
        $_.NsgId -and -not $_.Error -and $null -ne $_.PublicAllowCount -and $null -ne $_.ReviewAllowCount
    })
    $detailed = @($analyzed | Where-Object {
        $null -ne $_.Rules -and @($_.Rules).Count -ge ($_.PublicAllowCount + $_.ReviewAllowCount)
    })
    $analyzedNsgs = @($analyzed.NsgId | Where-Object { $_ } | Sort-Object -Unique).Count
    $withoutNsgChecks = @($checks | Where-Object Result -eq 'Subnet sem NSG associado')
    $withoutNsg = @($withoutNsgChecks |
        ForEach-Object SubnetId | Where-Object { $_ } | Sort-Object -Unique).Count
    $publicKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $reviewKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($check in $detailed) {
        foreach ($rule in $check.Rules) {
            $key = "$($check.NsgId)|$($rule.Name)"
            if ($rule.Access -eq 'Allow' -and -not $rule.CoveredByDeny -and
                $rule.DestinationScope -ne 'ForaDaSubnet' -and
                ($rule.SourceKind -eq 'Revisar' -or $rule.DestinationScope -eq 'Revisar')) {
                $null = $reviewKeys.Add($key)
            }
        }
        foreach ($rule in @(Get-ApimPublicNsgRules -Rules @($check.Rules))) {
            $null = $publicKeys.Add("$($check.NsgId)|$($rule.Name)")
        }
    }
    $incomplete = $missing -gt 0 -or $checks.Count -ne ($analyzed.Count + $withoutNsgChecks.Count) -or $analyzed.Count -ne $detailed.Count
    $suffix = if ($incomplete) { ' [parcial]' } else { '' }
    $hasRuleCounts = $detailed.Count -gt 0 -or -not $incomplete
    $public = if ($hasRuleCounts) { $publicKeys.Count } else { 'N/D' }
    $review = if ($hasRuleCounts) { $reviewKeys.Count } else { 'N/D' }
    $color = if ($publicKeys.Count -gt 0) { 'Red' }
        elseif ($incomplete -or $reviewKeys.Count -gt 0) { 'Yellow' } else { 'Gray' }
    Write-Host " NSG             | Analisados: $analyzedNsgs | Subnets sem NSG: $withoutNsg | Regras publicas/amplas: $public | A revisar: $review$suffix$origin" -ForegroundColor $color
}

function Write-ApimAuditSummary {
    param([object]$Audit, [object[]]$EndpointSummaries, [string]$Directory)

    Write-Host "`n$('=' * 76)" -ForegroundColor Cyan
    Write-Host " APIM | SUMARIO FINAL - $($Audit.Resources.Count) APIM(s)" -ForegroundColor White
    Write-Host "$('-' * 76)" -ForegroundColor DarkCyan
    $internal = @($Audit.Resources | Where-Object VirtualNetworkType -eq 'Internal').Count
    $external = @($Audit.Resources | Where-Object VirtualNetworkType -eq 'External').Count
    $none = @($Audit.Resources | Where-Object VirtualNetworkType -eq 'None').Count
    $unknownNetwork = @($Audit.Resources | Where-Object { $_.VirtualNetworkType -notin @('Internal', 'External', 'None') }).Count
    $color = if ($external + $none -gt 0) { 'Red' }
        elseif ($unknownNetwork -gt 0) { 'Yellow' } else { 'Gray' }
    Write-Host " REDE            | Internal: $internal | External: $external | None: $none | Desconhecido: $unknownNetwork" -ForegroundColor $color
    Write-ApimMetadataSummary -Resources @($Audit.Resources) -Title 'NAMED VALUES' -CheckProperty 'NamedValueCheck' -CountLabels ([ordered]@{
        PlainCount = 'Plain'; SecretCount = 'Secret'; KeyVaultCount = 'Key Vault'; TotalCount = 'Total'
    })
    Write-ApimMetadataSummary -Resources @($Audit.Resources) -Title 'SUBSCRIPTIONS' -CheckProperty 'SubscriptionCheck' -CountLabels ([ordered]@{
        DefaultCount = 'Padrao (All-access)'; CustomCount = 'Customizadas'; TotalCount = 'Total'
    })
    Write-ApimMetadataSummary -Resources @($Audit.Resources) -Title 'IDENTIDADE' -CheckProperty 'IdentityProviderCheck' -CountLabels ([ordered]@{
        ProviderCount = 'Provedores'; SecretUnknownCount = 'Client secret indeterminado'
    })
    Write-ApimMetadataSummary -Resources @($Audit.Resources) -Title 'OPENID CONNECT' -CheckProperty 'OpenIdConnectProviderCheck' -CountLabels ([ordered]@{
        ProviderCount = 'Provedores'; SecretUnknownCount = 'Client secret indeterminado'
    })
    $requiredApims = @($Audit.Resources | Where-Object { $_.ApiSubscriptionCheck.RequiredCount -gt 0 }).Count
    $unknownApims = @($Audit.Resources | Where-Object {
        $check = $_.ApiSubscriptionCheck
        -not ($check.RequiredCount -gt 0) -and
        ($null -eq $check.ApiCount -or $null -eq $check.RequiredCount -or $check.UnknownCount -gt 0)
    }).Count
    $suffix = if ($unknownApims -gt 0) { " | Indeterminados: $unknownApims" } else { '' }
    $requiredColor = if ($requiredApims -gt 0) { 'Red' }
        elseif ($unknownApims -gt 0) { 'Yellow' } else { 'Gray' }
    Write-Host " APIMS COM CHAVE | Ao menos uma API exige subscription key: $requiredApims$suffix" -ForegroundColor $requiredColor
    Write-ApimNsgSummary -Audit $Audit
    if ($Audit.UrlTestsEnabled) {
        $accessible = @($EndpointSummaries | Where-Object Acessibilidade -eq 'Acessivel').Count
        $notAccessible = @($EndpointSummaries | Where-Object Acessibilidade -eq 'Nao acessivel').Count
        $notTested = @($EndpointSummaries | Where-Object Acessibilidade -eq 'Nao testado').Count
        $accessibleColor = if ($accessible -gt 0) { 'Red' } else { 'Gray' }
        $origin = if ($Audit.PublicOriginDeclared) { 'origem publica declarada' } else { 'origem nao declarada' }
        $suffix = if ($Audit.Results.Count -eq 0) { ' [sem endpoints]' } else { '' }
        Write-Host " URLS            | Acessiveis: $accessible | Nao acessiveis: $notAccessible | Nao testadas: $notTested [$origin]$suffix" -ForegroundColor $accessibleColor
    }
    Write-Host "$('-' * 76)" -ForegroundColor DarkCyan
    Write-Host " Relatorios: $Directory" -ForegroundColor Cyan
    Write-Host "$('=' * 76)" -ForegroundColor Cyan
}

function Invoke-ApimAudit {
    [CmdletBinding()]
    param(
        [guid]$TenantId, [guid[]]$SubscriptionIds = @(),
        [string]$OutputDirectory = (Join-Path $PWD 'apim-audit'),
        [int]$TimeoutSeconds = 15, [int]$ArmMaxRetries = 1,
        [string]$Mode = 'Full', [string]$InventoryPath, [switch]$PrivateOrigin,
        [ValidateRange(0, 2147483647)][int]$MaxInstances = 0,
        [switch]$CheckNsg,
        [switch]$TestUrls,
        [ValidateNotNullOrEmpty()][ValidatePattern('\S')][string[]]$ApimNames = @()
    )

    if (($Mode -eq 'Probe') -ne [bool]$InventoryPath) {
        throw 'Informe InventoryPath somente e obrigatoriamente no modo Probe.'
    }
    if ($Mode -eq 'Probe' -and $SubscriptionIds.Count -gt 0) {
        throw 'SubscriptionIds filtra a coleta. No modo Probe, use um inventario previamente filtrado.'
    }
    $requestedApimNames = @($ApimNames | ForEach-Object { $_.Trim() } | Sort-Object -Unique)
    $declaredPublicOrigin = -not $PrivateOrigin
    $urlTestsEnabled = $Mode -ne 'Inventory' -and $TestUrls
    $urlSkipMessage = if (-not $TestUrls) { 'URLs nao testadas (padrao; use -TestUrls para ativar).' } else { 'Modo Inventory: URLs nao testadas.' }
    Write-ApimAuditPlan -Mode $Mode -MaxInstances $MaxInstances -CheckNsg:$CheckNsg -TestUrls:$TestUrls -ApimNames $requestedApimNames
    $issues = [System.Collections.Generic.List[object]]::new()
    $results = [System.Collections.Generic.List[object]]::new()
    $endpointSummaries = [System.Collections.Generic.List[object]]::new()
    $audit = [ordered]@{
        SchemaVersion = 1; ScriptVersion = '2.7.0'; TenantId = $TenantId.ToString()
        Mode = $Mode; InventoryUtc = $null; ProbeUtc = $null
        MaxInstances = $MaxInstances
        ApimNames = $requestedApimNames
        NsgCheckEnabled = [bool]$CheckNsg
        UrlTestsEnabled = $urlTestsEnabled
        PublicOriginDeclared = $declaredPublicOrigin
        Coverage = 'Somente subscriptions e recursos visiveis para a identidade. Nao comprova cobertura integral do tenant.'
        SubscriptionDiscoveryComplete = $false
        Subscriptions = @(); Resources = @(); Results = @(); Issues = @(); SubnetNsgChecks = @(); NamedValueChecks = @()
        ApimSubscriptionChecks = @(); ApiSubscriptionChecks = @()
    }
    if ($Mode -eq 'Probe') {
        $inputAudit = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
        if ($inputAudit.SchemaVersion -ne 1 -or $inputAudit.TenantId -ne $TenantId.ToString() -or
            -not $inputAudit.Contains('Resources')) {
            throw 'Inventario incompativel, sem Resources ou pertencente a outro tenant.'
        }
        foreach ($resource in $inputAudit.Resources) {
            if ($resource.TenantId -ne $TenantId.ToString() -or -not $resource.Contains('Targets')) {
                throw 'Recurso do inventario com tenant divergente ou sem Targets.'
            }
        }
        foreach ($key in @('InventoryUtc', 'Subscriptions', 'Resources', 'SubscriptionDiscoveryComplete')) {
            $audit[$key] = $inputAudit[$key]
        }
        if ($requestedApimNames.Count -gt 0) {
            $audit.Resources = @($audit.Resources | Where-Object { $_.Name -in $requestedApimNames })
        }
        if ($MaxInstances -gt 0) {
            $audit.Resources = @($audit.Resources | Select-Object -First $MaxInstances)
        }
        if ($inputAudit.MaxInstances -gt 0) {
            $audit.Coverage += " Inventario de origem coletado com limite de $($inputAudit.MaxInstances) APIM(s)."
        }
        if (@($inputAudit.ApimNames | Where-Object { $_ }).Count -gt 0) {
            $audit.Coverage += " Inventario de origem filtrado por nomes: $($inputAudit.ApimNames -join ', ')."
        }
        foreach ($issue in $inputAudit.Issues) { $issues.Add($issue) }
    }
    else {
        $inventory = Get-ApimInventory -Tenant $TenantId -Subscriptions $SubscriptionIds -MaxRetries $ArmMaxRetries -Issues $issues -MaxInstances $MaxInstances -CheckNsg:$CheckNsg -ApimNames $requestedApimNames
        $audit.InventoryUtc = [datetime]::UtcNow.ToString('o')
        $audit.Resources = @($inventory.Resources)
        $audit.Subscriptions = @($inventory.Subscriptions)
        $audit.SubscriptionDiscoveryComplete = $inventory.SubscriptionDiscoveryComplete
    }
    if ($MaxInstances -gt 0) {
        $audit.Coverage += " Execucao limitada a ate $MaxInstances APIM(s), por ordem de descoberta, sem sorteio."
    }
    if ($requestedApimNames.Count -gt 0) {
        $audit.Coverage += " Filtro por nomes exatos de APIM: $($requestedApimNames -join ', ')."
        foreach ($name in $requestedApimNames) {
            if ($name -in $audit.Resources.Name) { continue }
            $message = if ($Mode -eq 'Probe') { 'APIM solicitado nao incluido na selecao do inventario salvo.' }
                else { 'APIM solicitado nao incluido no inventario desta execucao. Verifique nomes, escopo/visibilidade das assinaturas e eventuais falhas de coleta.' }
            if ($MaxInstances -gt 0) { $message += " Considere tambem o limite MaxInstances=$MaxInstances." }
            $message += ' Isso nao comprova ausencia da instancia no tenant.'
            Add-ApimIssue $issues $name 'ApimNameSelection' $message
        }
    }
    if ($urlTestsEnabled) {
        if (-not $declaredPublicOrigin) {
            Write-Warning 'Origem publica nao declarada: resultados nao serao classificados como acesso publico.'
        }
        $audit.ProbeUtc = [datetime]::UtcNow.ToString('o')
    }
    $resourceIndex = 0
    foreach ($resource in $audit.Resources) {
        $resourceIndex++
        Write-ApimProbeHeader -Resource $resource -Index $resourceIndex -Total $audit.Resources.Count
        if ($CheckNsg -and $resource.VirtualNetworkType -eq 'Internal') {
            Write-ApimSubnetNsgResult -Checks @($resource.SubnetChecks)
        }
        Write-ApimNamedValueResult -Check $resource.NamedValueCheck
        Write-ApimSubscriptionResult -SubscriptionCheck $resource.SubscriptionCheck -ApiCheck $resource.ApiSubscriptionCheck
        Write-ApimProviderResult -Check $resource.IdentityProviderCheck -Title 'IDENTITY PROVIDERS'
        Write-ApimProviderResult -Check $resource.OpenIdConnectProviderCheck -Title 'OPENID CONNECT'
        if (-not $urlTestsEnabled) {
            Write-Host "`n [URL] $urlSkipMessage" -ForegroundColor Gray
            Write-Host "$('=' * 76)" -ForegroundColor Cyan
            continue
        }
        $resourceSummaries = [System.Collections.Generic.List[object]]::new()
        $targetIndex = 0
        foreach ($target in $resource.Targets) {
            $targetIndex++
            $endpointName = switch ($target.Type) {
                'DeveloperPortal' { 'Portal do desenvolvedor' }
                'LegacyPortal' { 'Portal legado' }
                'ManagementApi' { 'API de gerenciamento' }
                default { $target.Type }
            }
            Write-Host "`n [$targetIndex/$($resource.Targets.Count)] $endpointName" -ForegroundColor Cyan
            $probe = Invoke-ApimEndpointProbe -Target $target -Timeout $TimeoutSeconds -DeclaredPublicOrigin $declaredPublicOrigin
            $row = [ordered]@{}
            foreach ($key in @('TenantId', 'SubscriptionId', 'SubscriptionName', 'ResourceGroup', 'Name', 'ResourceId', 'Location', 'Sku', 'VirtualNetworkType', 'PublicNetworkAccess')) {
                $row[$key] = $resource.$key
            }
            foreach ($property in $probe.PSObject.Properties) { $row[$property.Name] = $property.Value }
            $endpointResult = [pscustomobject]$row
            $results.Add($endpointResult)
            $summary = ConvertTo-ApimEndpointSummary $endpointResult
            $endpointSummaries.Add($summary)
            $resourceSummaries.Add($summary)
            Write-ApimEndpointResult -Summary $summary
            if ($probe.Error) {
                Add-ApimIssue $issues "$($resource.ResourceId) [$($target.Type)]" $probe.ErrorStage $probe.Error -ConsoleReported
            }
        }
        $accessible = @($resourceSummaries.ToArray() | Where-Object Acessibilidade -eq 'Acessivel').Count
        $notAccessible = @($resourceSummaries.ToArray() | Where-Object Acessibilidade -eq 'Nao acessivel').Count
        $notTested = @($resourceSummaries.ToArray() | Where-Object Acessibilidade -eq 'Nao testado').Count
        $summaryColor = if ($accessible -gt 0) { 'Red' } else { 'Gray' }
        Write-Host "`n$('-' * 76)" -ForegroundColor DarkCyan
        Write-Host " RESUMO: Acessiveis: $accessible | Nao acessiveis: $notAccessible | Nao testados: $notTested" -ForegroundColor $summaryColor
        Write-Host "$('=' * 76)" -ForegroundColor Cyan
    }
    $audit.Results = $results.ToArray()
    $audit.Issues = $issues.ToArray()
    $nsgRows = [System.Collections.Generic.List[object]]::new()
    $nsgRuleRows = [System.Collections.Generic.List[object]]::new()
    $namedValueRows = [System.Collections.Generic.List[object]]::new()
    $subscriptionRows = [System.Collections.Generic.List[object]]::new()
    $apiRows = [System.Collections.Generic.List[object]]::new()
    foreach ($resource in $audit.Resources) {
        $subscriptionCheck = $resource.SubscriptionCheck
        $apiCheck = $resource.ApiSubscriptionCheck
        $subscriptionRows.Add([pscustomobject]@{
            Assinatura = $resource.SubscriptionName; AssinaturaId = $resource.SubscriptionId
            APIM = $resource.Name; ResourceGroup = $resource.ResourceGroup
            PadraoAllAccess = $subscriptionCheck.DefaultCount; Customizadas = $subscriptionCheck.CustomCount
            TotalSubscriptions = $subscriptionCheck.TotalCount
            ResultadoSubscriptions = if ($subscriptionCheck) { $subscriptionCheck.Result } else { 'Nao consultado - inventario sem checagem de subscriptions' }
            DataHoraSubscriptionsUTC = $subscriptionCheck.CheckedUtc; ObservacoesSubscriptions = $subscriptionCheck.Notes
            ErroSubscriptions = $subscriptionCheck.Error
            TotalAPIsRevisoes = $apiCheck.ApiCount; APIsExigemChave = $apiCheck.RequiredCount
            APIsNaoExigemChave = $apiCheck.NotRequiredCount; APIsNaoDeterminadas = $apiCheck.UnknownCount
            ResultadoAPIs = if ($apiCheck) { $apiCheck.Result } else { 'Nao consultado - inventario sem checagem de APIs' }
            DataHoraAPIsUTC = $apiCheck.CheckedUtc; ObservacoesAPIs = $apiCheck.Notes; ErroAPIs = $apiCheck.Error
        })
        foreach ($api in $apiCheck.Apis) {
            $apiRows.Add([pscustomobject]@{
                Assinatura = $resource.SubscriptionName; AssinaturaId = $resource.SubscriptionId
                APIM = $resource.Name; ResourceGroup = $resource.ResourceGroup
                APIId = $api.ApiId; API = $api.Name; Versao = $api.Version; Revisao = $api.Revision
                RevisaoAtual = $api.IsCurrent
                ExigeSubscriptionKey = if ($null -eq $api.SubscriptionRequired) { 'Nao determinado' }
                    elseif ($api.SubscriptionRequired) { 'Sim' } else { 'Nao' }
                Resultado = $api.Result; DataHoraUTC = $apiCheck.CheckedUtc
                Observacoes = $apiCheck.Notes; Erro = $api.Error
            })
        }
        $namedValueCheck = $resource.NamedValueCheck
        $namedValueRows.Add([pscustomobject]@{
            Assinatura = $resource.SubscriptionName; AssinaturaId = $resource.SubscriptionId
            APIM = $resource.Name; ResourceGroup = $resource.ResourceGroup
            Plain = $namedValueCheck.PlainCount; Secret = $namedValueCheck.SecretCount
            KeyVault = $namedValueCheck.KeyVaultCount; Total = $namedValueCheck.TotalCount
            Resultado = if ($namedValueCheck) { $namedValueCheck.Result } else { 'Nao consultado - inventario sem checagem de Named Values' }
            DataHoraUTC = $namedValueCheck.CheckedUtc; Erro = $namedValueCheck.Error
        })
        if (-not $CheckNsg -or $resource.VirtualNetworkType -ne 'Internal') { continue }
        $checks = @($resource.SubnetChecks | Where-Object { $_ })
        if ($checks.Count -eq 0) {
            $checks = @(@{ Region = $resource.Location; Result = 'Nao consultado - inventario sem checagem NSG' })
        }
        foreach ($check in $checks) {
            $nsgRows.Add([pscustomobject]@{
                Assinatura = $resource.SubscriptionName; AssinaturaId = $resource.SubscriptionId
                APIM = $resource.Name; ResourceGroup = $resource.ResourceGroup; Regiao = $check.Region
                SubnetId = $check.SubnetId; NSGId = $check.NsgId; Resultado = $check.Result
                RegrasOrigemPublica = $check.PublicAllowCount; RegrasARevisar = $check.ReviewAllowCount
                RegraBloqueioGeral = $check.BroadDeny; DataHoraUTC = $check.CheckedUtc
                Observacoes = $check.Notes; Erro = $check.Error
            })
            foreach ($rule in $check.Rules) {
                $nsgRuleRows.Add([pscustomobject]@{
                    Assinatura = $resource.SubscriptionName; AssinaturaId = $resource.SubscriptionId
                    APIM = $resource.Name; Regiao = $check.Region; SubnetId = $check.SubnetId; NSGId = $check.NsgId
                    Regra = $rule.Name; Prioridade = $rule.Priority; Acao = $rule.Access; Protocolo = $rule.Protocol
                    Origens = $rule.Sources; ClassificacaoOrigem = $rule.SourceKind; PortasOrigem = $rule.SourcePorts
                    Destinos = $rule.Destinations; EscopoDestino = $rule.DestinationScope; PortasDestino = $rule.DestinationPorts
                    CobertaPorDenyAnterior = $rule.CoveredByDeny
                })
            }
        }
    }
    $audit.SubnetNsgChecks = $nsgRows.ToArray()
    $audit.NamedValueChecks = $namedValueRows.ToArray()
    $audit.ApimSubscriptionChecks = $subscriptionRows.ToArray()
    $audit.ApiSubscriptionChecks = $apiRows.ToArray()
    $runName = '{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), [guid]::NewGuid().ToString('N').Substring(0, 8)
    $directory = Join-Path $OutputDirectory $runName
    $null = New-Item -ItemType Directory -Path $directory -Force
    ConvertTo-Json -InputObject $audit -Depth 100 | Set-Content -LiteralPath (Join-Path $directory 'apim-audit.json') -Encoding utf8
    $inventoryColumns = @('TenantId', 'SubscriptionId', 'SubscriptionName', 'ResourceGroup', 'Name', 'ResourceId', 'Location', 'Sku', 'ProvisioningState', 'VirtualNetworkType', 'PublicNetworkAccess', 'DeveloperPortalStatus', 'LegacyPortalStatus', 'DirectManagementApiEnabled', 'PrivateEndpoints', 'Hostnames', 'Targets', 'SubnetBindings', 'SubnetChecks', 'NamedValueCheck', 'SubscriptionCheck', 'ApiSubscriptionCheck', 'IdentityProviderCheck', 'OpenIdConnectProviderCheck')
    $resultColumns = @('TenantId', 'SubscriptionId', 'SubscriptionName', 'ResourceGroup', 'Name', 'ResourceId', 'Location', 'Sku', 'VirtualNetworkType', 'PublicNetworkAccess', 'EndpointType', 'Url', 'EndpointSource', 'ConfigurationStatus', 'ProbeUtc', 'PublicOriginDeclared', 'DnsStatus', 'Addresses', 'TcpStatus', 'ConnectedAddress', 'TcpAttemptErrors', 'TlsStatus', 'TlsProtocol', 'HttpStatusCode', 'RedirectLocation', 'ServerHeader', 'BackendAttribution', 'Conclusion', 'ErrorStage', 'Error')
    Export-ApimCsv -Data $audit.Resources -Columns $inventoryColumns -Path (Join-Path $directory 'inventory.csv')
    Export-ApimCsv -Data $audit.Results -Columns $resultColumns -Path (Join-Path $directory 'endpoints.csv')
    $summaryCsvPath = Join-Path $directory 'resumo-endpoints.csv'
    $summaryColumns = @('Assinatura', 'AssinaturaId', 'APIM', 'ResourceGroup', 'ModoRede', 'Interno', 'Endpoint', 'URL', 'Acessibilidade', 'Resultado', 'HTTP', 'ConfiguracaoEndpoint', 'Redirecionamento', 'OrigemPublicaDeclarada', 'DataHoraUTC', 'Erro')
    Export-ApimCsv -Data $endpointSummaries.ToArray() -Columns $summaryColumns -Path $summaryCsvPath -Delimiter ';'
    $nsgCsvPath = Join-Path $directory 'subnets-nsg.csv'
    $nsgRulesCsvPath = Join-Path $directory 'regras-nsg.csv'
    $namedValuesCsvPath = Join-Path $directory 'named-values.csv'
    $apimSubscriptionsCsvPath = Join-Path $directory 'apim-subscriptions.csv'
    $apiSubscriptionsCsvPath = Join-Path $directory 'apis-subscriptions.csv'
    Export-ApimCsv -Data $subscriptionRows.ToArray() -Columns @('Assinatura', 'AssinaturaId', 'APIM', 'ResourceGroup', 'PadraoAllAccess', 'Customizadas', 'TotalSubscriptions', 'ResultadoSubscriptions', 'DataHoraSubscriptionsUTC', 'ObservacoesSubscriptions', 'ErroSubscriptions', 'TotalAPIsRevisoes', 'APIsExigemChave', 'APIsNaoExigemChave', 'APIsNaoDeterminadas', 'ResultadoAPIs', 'DataHoraAPIsUTC', 'ObservacoesAPIs', 'ErroAPIs') -Path $apimSubscriptionsCsvPath -Delimiter ';'
    Export-ApimCsv -Data $apiRows.ToArray() -Columns @('Assinatura', 'AssinaturaId', 'APIM', 'ResourceGroup', 'APIId', 'API', 'Versao', 'Revisao', 'RevisaoAtual', 'ExigeSubscriptionKey', 'Resultado', 'DataHoraUTC', 'Observacoes', 'Erro') -Path $apiSubscriptionsCsvPath -Delimiter ';'
    Export-ApimCsv -Data $namedValueRows.ToArray() -Columns @('Assinatura', 'AssinaturaId', 'APIM', 'ResourceGroup', 'Plain', 'Secret', 'KeyVault', 'Total', 'Resultado', 'DataHoraUTC', 'Erro') -Path $namedValuesCsvPath -Delimiter ';'
    Export-ApimCsv -Data $nsgRows.ToArray() -Columns @('Assinatura', 'AssinaturaId', 'APIM', 'ResourceGroup', 'Regiao', 'SubnetId', 'NSGId', 'Resultado', 'RegrasOrigemPublica', 'RegrasARevisar', 'RegraBloqueioGeral', 'DataHoraUTC', 'Observacoes', 'Erro') -Path $nsgCsvPath -Delimiter ';'
    Export-ApimCsv -Data $nsgRuleRows.ToArray() -Columns @('Assinatura', 'AssinaturaId', 'APIM', 'Regiao', 'SubnetId', 'NSGId', 'Regra', 'Prioridade', 'Acao', 'Protocolo', 'Origens', 'ClassificacaoOrigem', 'PortasOrigem', 'Destinos', 'EscopoDestino', 'PortasDestino', 'CobertaPorDenyAnterior') -Path $nsgRulesCsvPath -Delimiter ';'
    Export-ApimCsv -Data $audit.Subscriptions -Columns @('SubscriptionId', 'SubscriptionName', 'State', 'InventoryStatus', 'ApimCount', 'Error') -Path (Join-Path $directory 'subscriptions.csv')
    Export-ApimCsv -Data $audit.Issues -Columns @('Utc', 'Scope', 'Stage', 'Error') -Path (Join-Path $directory 'issues.csv')
    Write-ApimAuditSummary -Audit $audit -EndpointSummaries $endpointSummaries.ToArray() -Directory $directory
    [pscustomobject]@{
        OutputDirectory = $directory; ApimCount = $audit.Resources.Count
        EndpointCount = $results.Count; IssueCount = $issues.Count; SummaryCsvPath = $summaryCsvPath
        SubnetNsgCsvPath = $nsgCsvPath; NsgRulesCsvPath = $nsgRulesCsvPath
        NamedValuesCsvPath = $namedValuesCsvPath
        ApimSubscriptionsCsvPath = $apimSubscriptionsCsvPath; ApiSubscriptionsCsvPath = $apiSubscriptionsCsvPath
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ApimAudit @PSBoundParameters
}
