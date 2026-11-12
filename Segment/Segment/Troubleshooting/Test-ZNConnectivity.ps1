#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-deployment network check from this machine to the Zero Networks cloud.
.DESCRIPTION
    Run this on the server whose network access you want to verify.
    Asks for the region and your customer prefix unless passed as parameters.

    Per endpoint it checks:
      TCP   outbound TCP 443 (hostnames and the regional IP addresses)
      TLS   handshake: protocol, cipher, certificate issuer and trust.
            An untrusted certificate or unexpected issuer usually means
            TLS inspection on a proxy or firewall.
      ALPN  whether HTTP/2 (h2) is negotiated.            PowerShell 7.4+ only
      gRPC  a real gRPC call over HTTP/2 to gRPC endpoints. PowerShell 7.4+ only
            Any grpc-status in the reply proves the gRPC path works.

    Runs on the Windows PowerShell 5.1 that comes with Windows (TCP, TLS, Cert).
    PowerShell 7.4+ (https://aka.ms/powershell) adds the ALPN and gRPC checks:
    recommended, not required.
.EXAMPLE
    .\Test-ZNConnectivity.ps1
.EXAMPLE
    pwsh .\Test-ZNConnectivity.ps1 -Region EU -CustomerPrefix contoso
#>
param(
    [string]$Region,
    [string]$CustomerPrefix
)

$ErrorActionPreference = 'Stop'

# Started in its own window ("Run with PowerShell", powershell -File): that window closes when the
# script ends, so wait for Enter first or the customer never sees the result or the error.
$hostArgs = [Environment]::GetCommandLineArgs()
$ownWindow = (($hostArgs -join ' ') -like "*$(Split-Path $PSCommandPath -Leaf)*") -and ($hostArgs -notcontains '-NonInteractive') -and -not $env:ZN_LAUNCHER  # Run-ZNCheck.cmd pauses itself
function Wait-BeforeClose { if ($ownWindow) { $null = Read-Host 'Press Enter to close this window' } }

trap {
    Write-Host ''
    Write-Host "ERROR: the check stopped: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "       (script line $($_.InvocationInfo.ScriptLineNumber), PowerShell $($PSVersionTable.PSVersion))" -ForegroundColor Red
    Write-Host 'Send this message to Zero Networks support if it is not clear what to do.'
    Wait-BeforeClose
    exit 1
}

Write-Host 'Zero Networks pre-deployment connectivity check' -ForegroundColor Cyan
$domain = 'zeronetworks.com'
# Organisation (O=) of the CA that issues our certificates. A TLS-inspecting proxy can never
# present a certificate from this CA, even when Windows trusts the proxy's own root via GPO.
# Update this when the certificate vendor changes.
$expectedIssuerOrgs = @('SSL Corporation')
$port = 443
$timeoutMs = 5000

# Per region: the regional activity-map host and the direct IP addresses.
$regions = @{
    EU = @{ ActivityMap = 'activity-map-eu-west12'; IPs = @('34.17.8.138', '34.149.192.110', '34.17.87.14', '34.17.5.190') }
    # US/AU/JP activity-map names found via DNS (resolve to that region's first IP); confirm with engineering.
    US = @{ ActivityMap = 'activity-map-us-east1'; IPs = @('34.74.201.149', '35.201.109.138', '35.190.190.87', '34.73.174.101') }
    AU = @{ ActivityMap = 'activity-map-australia'; IPs = @('34.40.178.138', '34.111.232.8', '34.116.120.249', '34.116.108.45') }
    JP = @{ ActivityMap = 'activity-map-asia-northeast1'; IPs = @('34.146.95.32', '8.232.98.163', '34.180.107.168', '34.104.231.115') }
}

# Tested in every region: register-cloud-connector.zeronetworks.com (installer, all customers) resolves here.
$globalIPs = @('34.74.201.149')

# Hostnames <prefix>-<service>.zeronetworks.com
$customerServices = @(
    'k8s-connector', 'cmdb', 'connectors', 'register-connectors', 'external-access', 'snow',
    'invite', 'register-connect-server', 'connect-auth', 'connect-client', 'cloud-connector-proxy',
    'download', 'monitor', 'segment-server', 'cloud-connector', 'connect-server',
    'register-segment-server', 'register-cloud-connector', 'admin', 'access', 'mfa', 'connect-download'
)
# Services that answer the gRPC call below (verified 11 Nov 2026); the other hosts route it to a REST API.
$grpcServices = @('cloud-connector', 'register-cloud-connector', 'cloud-connector-proxy')
# Same call the cloud connector installer makes to test gRPC (empty TestConnectivityRequest).
$grpcPath = '/api.agent.v1.AgentProvisionService/TestConnectivity'
# register-cloud-connector without prefix is what the cloud connector installer uses for every customer.
$sharedHosts = @('connect-selector', 'authenticate', 'register-cloud-connector')

if ($Region -notin $regions.Keys) {
    $choices = 'US', 'EU', 'AU', 'JP'
    $menu = [System.Management.Automation.Host.ChoiceDescription[]]@($choices | ForEach-Object { "&$_" })
    $Region = $choices[$Host.UI.PromptForChoice('Region', 'Select your Zero Networks region', $menu, -1)]  # -1: no default
}
while ($CustomerPrefix -notmatch '^[a-z0-9][a-z0-9-]*$') {
    $CustomerPrefix = "$(Read-Host 'Customer prefix (the part before -admin.zeronetworks.com)')".Trim().ToLower()
}
$CustomerPrefix = $CustomerPrefix.ToLower()
$cfg = $regions[$Region]
if (-not $cfg.IPs) { throw "Region $Region is not configured in this script yet." }
if ($cfg.ActivityMap) { $sharedHosts += $cfg.ActivityMap }

$full = $PSVersionTable.PSVersion -ge '7.4'  # sync SslStream with ALPN options needs .NET 7+
if (-not $full) {
    Write-Host 'Running in Windows PowerShell: checking TCP, TLS and TLS inspection. PowerShell 7.4+ (pwsh) adds HTTP/2 and gRPC checks.'
} else {
    $http = [System.Net.Http.HttpClient]::new()
    $http.Timeout = [timespan]::FromMilliseconds($timeoutMs)
}

$targets = @(
    foreach ($s in $customerServices) { [pscustomobject]@{ Name = "$CustomerPrefix-$s.$domain"; IsHost = $true; Grpc = $s -in $grpcServices } }
    foreach ($h in $sharedHosts) { [pscustomobject]@{ Name = "$h.$domain"; IsHost = $true; Grpc = $h -in $grpcServices } }
    foreach ($ip in @($cfg.IPs + $globalIPs | Select-Object -Unique)) { [pscustomobject]@{ Name = $ip; IsHost = $false; Grpc = $false } }
)

function Test-Endpoint($t) {
    $r = [ordered]@{ Target = $t.Name; RemoteIP = $null; TCP = '-'; TLS = '-'; Cipher = '-'; ALPN = '-'; Cert = '-'; Issuer = '-'; gRPC = '-' }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        try {
            if (-not $client.ConnectAsync($t.Name, $port).Wait($timeoutMs)) { $r.TCP = "FAIL - timed out after $timeoutMs ms"; return }
            $ip = $client.Client.RemoteEndPoint.Address
            $r.RemoteIP = if ($ip.IsIPv4MappedToIPv6) { $ip.MapToIPv4() } else { $ip }
            $r.TCP = 'PASS'
        } catch { $r.TCP = 'FAIL - ' + $_.Exception.GetBaseException().Message; return }

        if (-not $t.IsHost) { return }  # direct IPs: reachability only, no SNI for TLS

        try {
            $client.ReceiveTimeout = $client.SendTimeout = $timeoutMs
            $script:certErrors = $null
            $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { param($s, $c, $ch, $e) $script:certErrors = $e; $true })
            if ($full) {
                $opt = [System.Net.Security.SslClientAuthenticationOptions]::new()
                $opt.TargetHost = $t.Name
                $opt.ApplicationProtocols = [System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]]@(
                    [System.Net.Security.SslApplicationProtocol]::Http2, [System.Net.Security.SslApplicationProtocol]::Http11)
                $ssl.AuthenticateAsClient($opt)
                $r.Cipher = "$($ssl.NegotiatedCipherSuite)"
                $alpn = "$($ssl.NegotiatedApplicationProtocol)"
                $r.ALPN = if ($alpn -eq 'h2') { 'PASS - h2' } else { "FAIL - $(if ($alpn) { $alpn } else { 'none' }) (HTTP/2 blocked?)" }
            } else {
                # Windows PowerShell defaults to TLS 1.0 here, so ask for 1.2 explicitly.
                $ssl.AuthenticateAsClient($t.Name, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
                $r.Cipher = "$($ssl.CipherAlgorithm)$($ssl.CipherStrength)/$($ssl.HashAlgorithm)/$($ssl.KeyExchangeAlgorithm)"
            }
            $r.TLS = "PASS - $($ssl.SslProtocol)"
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            $r.Issuer = $cert.GetNameInfo('SimpleName', $true)
            $issuerOrg = [regex]::Match($cert.Issuer, '(?:^|,\s*)O=("[^"]*"|[^,]*)').Groups[1].Value.Trim('"')
            $r.Cert = if ("$script:certErrors" -ne 'None') { "FAIL - not trusted: $script:certErrors (TLS inspection?)" }
            elseif ($issuerOrg -notin $expectedIssuerOrgs) { "FAIL - issued by '$($cert.Issuer)', not by our CA: TLS inspection" }
            else { 'PASS' }
            $ssl.Dispose()
        } catch { $r.TLS = 'FAIL - ' + $_.Exception.GetBaseException().Message; return }

        if (-not ($full -and $t.Grpc)) { return }
        try {
            # Empty protobuf message: 1 byte compressed flag + 4 byte length, all zero.
            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "https://$($t.Name)$grpcPath")
            $req.Version = [version]'2.0'
            $req.VersionPolicy = [System.Net.Http.HttpVersionPolicy]::RequestVersionExact
            $req.Content = [System.Net.Http.ByteArrayContent]::new([byte[]]::new(5))
            $req.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/grpc')
            $req.Headers.TE.ParseAdd('trailers')
            $resp = $http.SendAsync($req).GetAwaiter().GetResult()
            $null = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()  # trailers arrive after the body
            $status = foreach ($h in $resp.Headers, $resp.TrailingHeaders) { $v = $null; if ($h.TryGetValues('grpc-status', [ref]$v)) { $v } }
            $r.gRPC = if ($status) { "PASS - grpc-status $(@($status)[0])" } else { "FAIL - HTTP/$($resp.Version) $([int]$resp.StatusCode), not a gRPC reply" }
        } catch { $r.gRPC = 'FAIL - ' + $_.Exception.GetBaseException().Message }
    } finally {
        $client.Dispose()
        [pscustomobject]$r
    }
}

Write-Host "Testing region $Region for customer '$CustomerPrefix'..."
$results = foreach ($t in $targets) { Test-Endpoint $t }

# Overview shows only PASS/FAIL per check; full details follow for failures.
$columns = @(@{ Name = "Target (*.$domain)"; Expression = { $_.Target -replace "\.$([regex]::Escape($domain))$" } }, 'RemoteIP') + @(foreach ($c in 'TCP', 'TLS', 'ALPN', 'Cert', 'gRPC') {
        @{ Name = $c; Expression = [scriptblock]::Create("(`$_.$c -split ' ')[0]") } })
$results | Format-Table -Property $columns -AutoSize
$first = $results | Where-Object { $_.TLS -like 'PASS*' } | Select-Object -First 1
if ($first) { Write-Host "TLS seen: $($first.TLS -replace '^PASS - '), $($first.Cipher), issuer $($first.Issuer)" }
$failed = @($results | Where-Object { $_.PSObject.Properties.Value -like 'FAIL*' })
Write-Host "$($results.Count - $failed.Count) of $($results.Count) endpoints passed all checks."
if ($failed) {
    Write-Host 'Details of failed endpoints:' -ForegroundColor Red
    $failed | Format-List
}

# Recognise wrong input before blaming the network.
$hasFail = { [bool]($args[0].PSObject.Properties.Value -like 'FAIL*') }
$customerRows = @($results | Where-Object { $_.Target -like "$CustomerPrefix-*" })
$sharedRows = @($results | Where-Object { $_.Target -in @($sharedHosts | ForEach-Object { "$_.$domain" }) })
$ipRegion = @{}
foreach ($k in $regions.Keys) { foreach ($ip in $regions[$k].IPs) { $ipRegion[$ip] = $k } }
$hostRegions = @($customerRows | Where-Object TCP -eq 'PASS' | ForEach-Object { $ipRegion["$($_.RemoteIP)"] } | Where-Object { $_ } | Select-Object -Unique)

Write-Host ''
if (-not @($results | Where-Object TCP -eq 'PASS')) {
    Write-Host 'CONCLUSION: FAIL - nothing could be reached on port 443.' -ForegroundColor Red
    Write-Host ' - This server has no outbound access to the internet on TCP 443, or DNS does not resolve public names.' -ForegroundColor Red
    Write-Host ' - Allow outbound TCP 443 to *.zeronetworks.com and the IP addresses for your region, and check DNS.' -ForegroundColor Red
} elseif ($customerRows -and -not @($customerRows | Where-Object { -not (& $hasFail $_) }) -and
          $sharedRows -and -not @($sharedRows | Where-Object { & $hasFail $_ })) {
    Write-Host "CONCLUSION: WRONG CUSTOMER PREFIX? - none of the $CustomerPrefix-*.$domain hosts work, but the shared Zero Networks hosts do." -ForegroundColor Red
    Write-Host " - Check the prefix: it is the first part of your portal address, e.g. 'contoso' for contoso-admin.$domain." -ForegroundColor Red
    Write-Host ' - Then run the check again.' -ForegroundColor Red
} elseif ($hostRegions -and $Region -notin $hostRegions) {
    Write-Host "CONCLUSION: WRONG REGION - your $CustomerPrefix-*.$domain hosts are in region $($hostRegions -join '/'), but you selected $Region." -ForegroundColor Red
    Write-Host " - Run the check again and select $($hostRegions -join ' or '). The IP addresses tested now are not yours." -ForegroundColor Red
} elseif (-not $failed) {
    Write-Host 'CONCLUSION: PASS - this server can reach Zero Networks. No network changes needed.' -ForegroundColor Green
    # Without TLS inspection (checked above) HTTP/2 almost never breaks, so 5.1 is enough for a PASS.
    if (-not $full) { Write-Host 'Tip: PowerShell 7.4+ (pwsh) also checks HTTP/2 and gRPC. Recommended, not required.' }
} else {
    Write-Host 'CONCLUSION: FAIL - this server is not ready yet. Fix the following and run the check again:' -ForegroundColor Red
    $advice = [ordered]@{
        TCP  = 'Outbound TCP 443 is blocked or a name does not resolve: allow 443 to *.zeronetworks.com and the IP addresses for your region, and check DNS.'
        TLS  = 'The TLS connection is blocked or altered by a device in the path: check TLS and protocol filtering on proxies and firewalls.'
        Cert = 'TLS inspection (SSL decryption) detected: exclude *.zeronetworks.com from TLS inspection.'
        ALPN = 'HTTP/2 does not get through: allow HTTP/2 to *.zeronetworks.com.'
        gRPC = 'gRPC traffic is blocked or rewritten: no TLS inspection and allow HTTP/2 to *.zeronetworks.com.'
    }
    foreach ($c in $advice.Keys) {
        if ($failed | Where-Object { $_.$c -like 'FAIL*' }) { Write-Host " - $($advice[$c])" -ForegroundColor Red }
    }
    Write-Host 'Need help? Send the full output to Zero Networks support (see README).'
}

Wait-BeforeClose
