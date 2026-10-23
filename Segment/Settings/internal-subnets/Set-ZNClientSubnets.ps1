<#
    .SYNOPSIS
    Add, remove, replace, or export Zero Networks client subnets (Settings > Internal Subnets > Client subnets).

    .DESCRIPTION
    Reads a CSV of IPv4 subnets in CIDR notation and updates the client subnets setting in the
    Zero Networks portal.

    Modes:
      (default)             Append the CSV subnets to the current client subnet list.
      -RemoveSubnets        Remove the CSV subnets from the current client subnet list.
      -ReplaceSubnets       Replace the entire client subnet list with the CSV subnets (requires typed confirmation).
      -ExportClientSubnets  Export the current client subnet list to a CSV in the same format this script accepts.

    The CSV should have a "Subnet" (or "CIDR") column. If neither column exists, the first column is used.
    A header-less file with one CIDR per line is also accepted.

    .PARAMETER CsvPath
    Input CSV of subnets. With -ExportClientSubnets this is the output path instead
    (default: ./client-subnets-export-<yyyyMMdd-HHmmss>.csv).

    .PARAMETER PortalBaseUrl
    Base URL of the portal, e.g. https://portal.zeronetworks.com or https://<org>-admin.zeronetworks.com.

    .PARAMETER ApiKey
    Zero Networks API key. If omitted, you will be prompted for it.

    .PARAMETER RemoveSubnets
    Remove the subnets listed in the CSV instead of adding them.

    .PARAMETER ReplaceSubnets
    Replace the whole client subnet list with the subnets listed in the CSV. You must type REPLACE to confirm.

    .PARAMETER ExportClientSubnets
    Export the current client subnet list to -CsvPath and make no changes.

    .PARAMETER Force
    With -ExportClientSubnets, overwrite -CsvPath if it already exists.

    .PARAMETER RaiseErrorOnInvalidSubnet
    Stop with an error on the first CSV entry that is not a valid CIDR, instead of warning and skipping it.

    .PARAMETER DryRun
    Show what would change (and the request body that would be sent) without changing anything.

    .EXAMPLE
    ./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -PortalBaseUrl https://portal.zeronetworks.com -ApiKey $key -DryRun

    .EXAMPLE
    ./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -ApiKey $key -RemoveSubnets

    .EXAMPLE
    ./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -ApiKey $key -ReplaceSubnets -Verbose

    .EXAMPLE
    ./Set-ZNClientSubnets.ps1 -ExportClientSubnets -CsvPath ./current-subnets.csv -ApiKey $key
#>
[CmdletBinding(DefaultParameterSetName = 'Append')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Append')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Replace')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Export')]
    [string]$CsvPath,

    [string]$PortalBaseUrl = 'https://portal.zeronetworks.com',

    [string]$ApiKey,

    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [switch]$RemoveSubnets,

    [Parameter(Mandatory = $true, ParameterSetName = 'Replace')]
    [switch]$ReplaceSubnets,

    [Parameter(Mandatory = $true, ParameterSetName = 'Export')]
    [switch]$ExportClientSubnets,

    [Parameter(ParameterSetName = 'Export')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Append')]
    [Parameter(ParameterSetName = 'Remove')]
    [Parameter(ParameterSetName = 'Replace')]
    [switch]$RaiseErrorOnInvalidSubnet,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$mode = $PSCmdlet.ParameterSetName

if ($PSBoundParameters['Verbose']) {
    $DebugPreference = 'Continue'
}

#region Helpers

function Get-MaskedKey([string]$Key) {
    if ($Key.Length -le 4) { return '****' }
    return ('*' * 8) + $Key.Substring($Key.Length - 4)
}

function ConvertTo-Array($Value) {
    # Avoid @($null) producing a one-element array when the API omits a list
    if ($null -eq $Value) { return , [string[]]@() }
    return , [string[]]@($Value)
}

function Test-Cidr {
    <#
        Returns a PSCustomObject: IsValid, Family ('IPv4'|'IPv6'), Normalized, Reason
    #>
    param([string]$Value)

    $result = [PSCustomObject]@{ IsValid = $false; Family = $null; Normalized = $null; Reason = $null }

    $parts = $Value.Split('/')
    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
        $result.Reason = "not in CIDR format (expected <address>/<prefix>)"
        return $result
    }

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) {
        $result.Reason = "'$($parts[0])' is not a valid IP address"
        return $result
    }

    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        # TryParse accepts shorthand like "10.1" - require a full dotted quad
        if ($parts[0] -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.Reason = "'$($parts[0])' is not a full dotted-quad IPv4 address"
            return $result
        }
        $result.Family = 'IPv4'
        $maxPrefix = 32
    }
    elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($ip.ScopeId -ne 0 -or $parts[0].Contains('%')) {
            $result.Reason = "IPv6 scope IDs are not allowed"
            return $result
        }
        $result.Family = 'IPv6'
        $maxPrefix = 128
    }
    else {
        $result.Reason = "unsupported address family"
        return $result
    }

    $prefix = 0
    if ($parts[1] -notmatch '^\d{1,3}$' -or -not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -gt $maxPrefix) {
        $result.Reason = "prefix '/$($parts[1])' is invalid for $($result.Family) (must be 0-$maxPrefix)"
        return $result
    }

    # Mask off host bits and make sure none were set
    $bytes = $ip.GetAddressBytes()
    $network = [byte[]]::new($bytes.Length)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bitsInByte = [Math]::Max(0, [Math]::Min(8, $prefix - ($i * 8)))
        $mask = [byte]((0xFF -shl (8 - $bitsInByte)) -band 0xFF)
        $network[$i] = $bytes[$i] -band $mask
    }
    $networkIp = [System.Net.IPAddress]::new($network)

    if (-not $networkIp.Equals($ip)) {
        $result.Reason = "host bits are set (did you mean $($networkIp.ToString())/${prefix}?)"
        return $result
    }

    $result.IsValid = $true
    $result.Normalized = "$($networkIp.ToString())/$prefix".ToLowerInvariant()
    return $result
}

function Read-SubnetCsv {
    <#
        Returns ordered, de-duplicated valid entries: PSCustomObject Value, Family, Line
    #>
    param([string]$Path, [switch]$ThrowOnInvalid)

    $lines = @(Get-Content -LiteralPath $Path)
    $firstIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if (-not [string]::IsNullOrWhiteSpace($lines[$i])) { $firstIndex = $i; break }
    }
    if ($firstIndex -lt 0) {
        throw "CSV file '$Path' is empty."
    }

    $firstLineFields = @($lines[$firstIndex].Split(','))
    $hasHeader = -not ($firstLineFields[0].Trim().Trim('"') -match '^[0-9A-Fa-f:.]+/\S*$')

    $headerNames = $null
    $columnIndex = 0
    $dataStart = $firstIndex
    if ($hasHeader) {
        $headerNames = @($firstLineFields | ForEach-Object { $_.Trim().Trim('"') })
        $columnIndex = -1
        foreach ($wanted in @('Subnet', 'CIDR')) {
            for ($c = 0; $c -lt $headerNames.Count; $c++) {
                if ($headerNames[$c] -ieq $wanted) { $columnIndex = $c; break }
            }
            if ($columnIndex -ge 0) { break }
        }
        if ($columnIndex -lt 0) {
            $columnIndex = 0
            Write-Warning "No 'Subnet' or 'CIDR' column found; using the first column '$($headerNames[0])'."
        }
        $dataStart = $firstIndex + 1
        Write-Verbose "CSV has a header row; using column '$($headerNames[$columnIndex])' (index $columnIndex)."
    }
    else {
        Write-Verbose "CSV has no header row; treating the first column of each line as the subnet."
    }

    $valid = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $invalidCount = 0

    for ($i = $dataStart; $i -lt $lines.Count; $i++) {
        $lineNumber = $i + 1
        if ([string]::IsNullOrWhiteSpace($lines[$i])) { continue }

        $row = $lines[$i] | ConvertFrom-Csv -Header (0..63 | ForEach-Object { "c$_" })
        $raw = $row."c$columnIndex"
        $value = if ($null -eq $raw) { '' } else { $raw.Trim() }
        if ($value -eq '') {
            Write-Verbose "Line ${lineNumber}: empty value, skipping."
            continue
        }

        $check = Test-Cidr -Value $value
        if ($check.IsValid -and $check.Family -eq 'IPv6') {
            # The client-subnets PUT endpoint rejects privateIpv6NetworksList
            $check.IsValid = $false
            $check.Reason = 'IPv6 is not supported for client subnets (IPv4 only)'
        }
        if (-not $check.IsValid) {
            $message = "Invalid subnet on line ${lineNumber}: '$value' - $($check.Reason)"
            if ($ThrowOnInvalid) {
                throw $message
            }
            Write-Warning "$message. Skipping."
            $invalidCount++
            continue
        }

        if (-not $seen.Add($check.Normalized)) {
            Write-Verbose "Line ${lineNumber}: '$value' is a duplicate of an earlier entry, skipping."
            continue
        }

        Write-Verbose "Line ${lineNumber}: '$value' -> $($check.Family) $($check.Normalized)"
        $valid.Add([PSCustomObject]@{ Value = $check.Normalized; Family = $check.Family; Line = $lineNumber })
    }

    Write-Verbose "Parsed $($valid.Count) valid subnet(s), $invalidCount invalid."
    return , $valid.ToArray()
}

function Invoke-ZNApi {
    param(
        [ValidateSet('Get', 'Put')][string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body
    )

    $logHeaders = @{}
    foreach ($k in $Headers.Keys) { $logHeaders[$k] = $Headers[$k] }
    $logHeaders['Authorization'] = Get-MaskedKey $Headers['Authorization']
    Write-Debug "$($Method.ToUpper()) $Uri"
    Write-Debug "Headers: $($logHeaders | ConvertTo-Json -Compress)"
    if ($Body) { Write-Debug "Body: $Body" }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $params = @{ Method = $Method; Uri = $Uri; Headers = $Headers }
        if ($Body) { $params['Body'] = $Body }
        $response = Invoke-RestMethod @params
    }
    catch {
        $stopwatch.Stop()
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        $detail = $_.ErrorDetails.Message
        if (-not $detail) { $detail = $_.Exception.Message }
        Write-Debug "$($Method.ToUpper()) failed after $($stopwatch.ElapsedMilliseconds) ms (HTTP $status)"
        throw "API $($Method.ToUpper()) $Uri failed (HTTP $status): $detail"
    }
    $stopwatch.Stop()
    Write-Debug "$($Method.ToUpper()) succeeded in $($stopwatch.ElapsedMilliseconds) ms"
    if ($null -ne $response -and "$response" -ne '') {
        Write-Debug "Response: $($response | ConvertTo-Json -Depth 5 -Compress)"
    }
    return $response
}

function Get-ClientSubnets {
    param([string]$Uri, [hashtable]$Headers)
    $response = Invoke-ZNApi -Method Get -Uri $Uri -Headers $Headers
    [PSCustomObject]@{
        IPv4 = ConvertTo-Array $response.config.privateIpv4NetworksList
        IPv6 = ConvertTo-Array $response.config.privateIpv6NetworksList
        Max  = $response.maxClientSubnets
    }
}

function Exit-WithError([string]$Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

#endregion

#region Setup

$PortalBaseUrl = ($PortalBaseUrl.Trim() -replace '/+$', '') -replace '/api/v1$', ''
$endpoint = "$PortalBaseUrl/api/v1/settings/system/internal-subnets/client-subnets"
Write-Verbose "Mode: $mode$(if ($DryRun) { ' (dry run)' })"
Write-Verbose "Portal base URL: $PortalBaseUrl"
Write-Verbose "Endpoint: $endpoint"

# Parse and validate the CSV before any API calls
$csvEntries = @()
if ($mode -ne 'Export') {
    if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
        Exit-WithError "CSV file not found: $CsvPath"
    }
    # Terminating error by design when -RaiseErrorOnInvalidSubnet is set
    $csvEntries = Read-SubnetCsv -Path $CsvPath -ThrowOnInvalid:$RaiseErrorOnInvalidSubnet
    if ($csvEntries.Count -eq 0) {
        Exit-WithError "No valid subnets found in '$CsvPath'. Nothing to do."
    }
    Write-Host "Read $($csvEntries.Count) valid subnet(s) from $CsvPath"
}
else {
    if (-not $CsvPath) {
        $CsvPath = "./client-subnets-export-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    }
    $CsvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)
    Write-Verbose "Export path: $CsvPath"
    if ((Test-Path -LiteralPath $CsvPath) -and -not $Force -and -not $DryRun) {
        Exit-WithError "Output file '$CsvPath' already exists. Use -Force to overwrite it."
    }
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    $secureKey = Read-Host -Prompt 'Enter your API Key' -AsSecureString
    $ApiKey = [System.Net.NetworkCredential]::new('', $secureKey).Password
    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Exit-WithError 'An API key is required.'
    }
}

$znHeaders = @{ 'Authorization' = $ApiKey; 'Content-Type' = 'application/json'; 'Accept' = 'application/json' }

#endregion

#region Main

try {
    $current = Get-ClientSubnets -Uri $endpoint -Headers $znHeaders
}
catch {
    Exit-WithError $_.Exception.Message
}
$currentTotal = $current.IPv4.Count + $current.IPv6.Count
Write-Host "Current client subnets: $($current.IPv4.Count) IPv4, $($current.IPv6.Count) IPv6 (max $($current.Max))"

# Export mode
if ($mode -eq 'Export') {
    $rows = @('Subnet') + $current.IPv4 + $current.IPv6
    if ($currentTotal -eq 0) {
        Write-Warning 'There are no client subnets configured; the export will only contain the header row.'
    }
    if ($DryRun) {
        Write-Host "[DryRun] Would write $currentTotal subnet(s) to $CsvPath :"
        $rows | ForEach-Object { Write-Host "  $_" }
        exit 0
    }
    [System.IO.File]::WriteAllLines($CsvPath, [string[]]$rows, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Exported $currentTotal client subnet(s) to $CsvPath" -ForegroundColor Green
    exit 0
}

# Build the new lists
$currentLookup = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($s in ($current.IPv4 + $current.IPv6)) { $null = $currentLookup.Add($s) }
$csvLookup = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($e in $csvEntries) { $null = $csvLookup.Add($e.Value) }

$toAdd = New-Object System.Collections.Generic.List[string]
$toRemove = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]

switch ($mode) {
    'Append' {
        $newIPv4 = New-Object System.Collections.Generic.List[string] (, $current.IPv4)
        $newIPv6 = New-Object System.Collections.Generic.List[string] (, $current.IPv6)
        foreach ($e in $csvEntries) {
            if ($currentLookup.Contains($e.Value)) {
                Write-Verbose "$($e.Value): already present, skipping."
                $skipped.Add($e.Value)
                continue
            }
            Write-Verbose "$($e.Value): will be added."
            $toAdd.Add($e.Value)
            if ($e.Family -eq 'IPv4') { $newIPv4.Add($e.Value) } else { $newIPv6.Add($e.Value) }
        }
    }
    'Remove' {
        $newIPv4 = New-Object System.Collections.Generic.List[string]
        $newIPv6 = New-Object System.Collections.Generic.List[string]
        foreach ($s in $current.IPv4) { if ($csvLookup.Contains($s)) { $toRemove.Add($s) } else { $newIPv4.Add($s) } }
        foreach ($s in $current.IPv6) { if ($csvLookup.Contains($s)) { $toRemove.Add($s) } else { $newIPv6.Add($s) } }
        foreach ($e in $csvEntries) {
            if ($currentLookup.Contains($e.Value)) {
                Write-Verbose "$($e.Value): will be removed."
            }
            else {
                Write-Verbose "$($e.Value): not in the current list, skipping."
                $skipped.Add($e.Value)
            }
        }
    }
    'Replace' {
        $newIPv4 = New-Object System.Collections.Generic.List[string]
        # IPv6 entries can't be written through this endpoint, so leave any existing ones untouched
        $newIPv6 = New-Object System.Collections.Generic.List[string] (, $current.IPv6)
        foreach ($e in $csvEntries) {
            $newIPv4.Add($e.Value)
            if ($currentLookup.Contains($e.Value)) {
                Write-Verbose "$($e.Value): already present, kept."
            }
            else {
                Write-Verbose "$($e.Value): will be added."
                $toAdd.Add($e.Value)
            }
        }
        foreach ($s in $current.IPv4) {
            if (-not $csvLookup.Contains($s)) {
                Write-Verbose "${s}: not in CSV, will be removed."
                $toRemove.Add($s)
            }
        }
    }
}

$newTotal = $newIPv4.Count + $newIPv6.Count

# Summary
Write-Host ''
foreach ($s in $toAdd) { Write-Host "  + $s" -ForegroundColor Green }
foreach ($s in $toRemove) { Write-Host "  - $s" -ForegroundColor Red }
if ($skipped.Count -gt 0) {
    $why = if ($mode -eq 'Remove') { 'not present' } else { 'already present' }
    foreach ($s in $skipped) { Write-Host "  = $s ($why)" -ForegroundColor DarkGray }
    if ($mode -eq 'Remove') {
        Write-Warning "$($skipped.Count) subnet(s) in the CSV were not in the current client subnet list."
    }
}
Write-Host ''
Write-Host "To add: $($toAdd.Count)  To remove: $($toRemove.Count)  Skipped: $($skipped.Count)  Resulting total: $newTotal"

if ($null -ne $current.Max) {
    Write-Verbose "Limit check: $newTotal of $($current.Max) allowed."
    if ($newTotal -gt [int]$current.Max) {
        Exit-WithError "The resulting list would have $newTotal subnets, which exceeds the portal maximum of $($current.Max). No changes made."
    }
}

if ($toAdd.Count -eq 0 -and $toRemove.Count -eq 0) {
    Write-Host 'No changes.' -ForegroundColor Yellow
    exit 0
}

# The API rejects a privateIpv6NetworksList key on PUT, so only the IPv4 list is sent
$body = [ordered]@{
    privateIpv4NetworksList = [string[]]$newIPv4.ToArray()
} | ConvertTo-Json -Depth 3

if ($DryRun) {
    Write-Host '[DryRun] No changes made. Request that would be sent:' -ForegroundColor Cyan
    Write-Host "PUT $endpoint"
    Write-Host $body
    exit 0
}

if ($mode -eq 'Replace') {
    Write-Host ''
    Write-Host "WARNING: This will OVERWRITE all $currentTotal existing client subnet(s) with the $newTotal subnet(s) in the CSV." -ForegroundColor Red
    Write-Host "$($toRemove.Count) existing subnet(s) will be removed." -ForegroundColor Red
    $answer = Read-Host -Prompt "Type REPLACE to confirm"
    if ($answer -cne 'REPLACE') {
        Write-Host 'Aborted. No changes made.' -ForegroundColor Yellow
        exit 1
    }
}

try {
    $null = Invoke-ZNApi -Method Put -Uri $endpoint -Headers $znHeaders -Body $body
    $after = Get-ClientSubnets -Uri $endpoint -Headers $znHeaders
}
catch {
    Exit-WithError $_.Exception.Message
}

Write-Host "Client subnets updated. Now: $($after.IPv4.Count) IPv4, $($after.IPv6.Count) IPv6 (max $($after.Max))" -ForegroundColor Green

#endregion
