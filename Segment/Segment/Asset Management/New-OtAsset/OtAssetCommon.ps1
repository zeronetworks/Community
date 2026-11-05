#Requires -Version 7

<#
    Shared helper functions for New-OtAsset.ps1 and Get-OtAssetTypes.ps1.

    This file is dot-sourced by New-OtAsset.ps1 and Get-OtAssetTypes.ps1 and must stay
    in the same folder as those scripts. It contains function definitions only; nothing
    runs when it is loaded.
#>

<#
.SYNOPSIS
    Builds the Zero Networks API base URL for a tenant.

.DESCRIPTION
    Returns https://<host>/api/v1. When -PortalUrl is supplied it is used as the host.
    Otherwise the host is taken from the API key (a JWT) using the claims api_url, tenant
    and aud, in that order. If no usable host is found, the default portal is used.

.PARAMETER ApiKey
    Zero Networks API key. Its JWT payload is inspected for a tenant host when -PortalUrl is not given.

.PARAMETER PortalUrl
    Optional portal address. Accepts https://host, host, https://host/ or https://host/api/v1.

.OUTPUTS
    System.String. The base URL with no trailing slash.

.NOTES
    Throws when -PortalUrl is given but is not a valid URL or hostname. Decoding problems in the
    API key never throw; they fall back to https://portal.zeronetworks.com/api/v1.
#>
function Get-ApiBaseUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $false)][string]$PortalUrl
    )

    $hostPattern = '^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$'

    if (-not [string]::IsNullOrWhiteSpace($PortalUrl)) {
        $candidate = $PortalUrl.Trim() -replace '^[A-Za-z][A-Za-z0-9+.-]*://', ''
        $candidate = [string](($candidate -split '/', 2)[0])
        if (-not [regex]::IsMatch($candidate, $hostPattern)) {
            throw "PortalUrl '$PortalUrl' is not a valid URL or hostname"
        }
        return "https://$candidate/api/v1"
    }

    $hostName = $null
    try {
        $parts = $ApiKey.Split('.')
        if ($parts.Count -ge 2) {
            $b64 = $parts[1].Replace('-', '+').Replace('_', '/')
            $pad = (4 - ($b64.Length % 4)) % 4
            $b64 = $b64 + ('=' * $pad)
            $payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
            $claims = $payloadJson | ConvertFrom-Json -ErrorAction Stop
            if ($claims -is [pscustomobject]) {
                foreach ($claimName in @('api_url', 'tenant', 'aud')) {
                    $prop = $claims.PSObject.Properties[$claimName]
                    if ($null -eq $prop -or $prop.Value -isnot [string]) { continue }
                    $claimHost = $prop.Value -replace '^[A-Za-z][A-Za-z0-9+.-]*://', ''
                    $claimHost = [string](($claimHost -split '/', 2)[0])
                    if ([regex]::IsMatch($claimHost, $hostPattern)) {
                        $hostName = $claimHost
                        break
                    }
                }
            }
        }
    }
    catch {
        $hostName = $null
    }

    if ($hostName) {
        return "https://$hostName/api/v1"
    }
    return 'https://portal.zeronetworks.com/api/v1'
}

<#
.SYNOPSIS
    Calls the Zero Networks REST API and converts failures into ZnApiError records.

.DESCRIPTION
    Builds the request URI from the base URL, path and query, then calls Invoke-RestMethod.
    Query keys are sorted and escaped. Boolean values are sent as lowercase true/false.
    A request body is serialized to JSON when it is not already a string.

.PARAMETER Method
    HTTP method. GET or POST.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl, with no trailing slash.

.PARAMETER ApiKey
    API key sent in the Authorization header. It is never written to output or verbose logs.

.PARAMETER Path
    API path that begins with '/', for example '/assets/ot'.

.PARAMETER Query
    Optional query string parameters as a hashtable.

.PARAMETER Body
    Optional request body. Strings are sent as-is; other objects are converted to compact JSON.

.OUTPUTS
    The response object from Invoke-RestMethod, unchanged.

.NOTES
    On failure, throws a terminating ErrorRecord with ErrorId 'ZnApiError'. Its TargetObject has
    StatusCode, ApiError, ApiMessage, Method and Path properties.
#>
function Invoke-ZnRestMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][hashtable]$Query,
        [Parameter(Mandatory = $false)][object]$Body
    )

    $uri = $ApiBaseUrl + $Path
    if ($null -ne $Query -and $Query.Count -gt 0) {
        $pairs = foreach ($queryKey in ($Query.Keys | Sort-Object)) {
            $queryValue = $Query[$queryKey]
            if ($queryValue -is [bool] -or $queryValue -is [System.Management.Automation.SwitchParameter]) {
                $text = ([bool]$queryValue).ToString().ToLowerInvariant()
            }
            else {
                $text = [string]$queryValue
            }
            [System.Uri]::EscapeDataString([string]$queryKey) + '=' + [System.Uri]::EscapeDataString($text)
        }
        $uri = $uri + '?' + ($pairs -join '&')
    }

    Write-Verbose "$Method $uri"

    $json = $null
    if ($null -ne $Body) {
        if ($Body -is [string]) {
            $json = $Body
        }
        else {
            $json = $Body | ConvertTo-Json -Depth 10 -Compress
        }
    }

    try {
        if ($null -ne $Body) {
            return Invoke-RestMethod -Uri $uri -Method $Method -Headers @{ Authorization = $ApiKey; Accept = 'application/json' } -Body $json -ContentType 'application/json' -ErrorAction Stop
        }
        return Invoke-RestMethod -Uri $uri -Method $Method -Headers @{ Authorization = $ApiKey; Accept = 'application/json' } -ErrorAction Stop
    }
    catch {
        $err = $_
        $statusCode = 0
        $response = $err.Exception.Response
        if ($null -ne $response) {
            $statusCode = [int]$response.StatusCode
        }

        $apiError = ''
        $apiMessage = ''
        $raw = $err.ErrorDetails.Message
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $parsed = $null
            try {
                $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $parsed = $null
            }
            if ($parsed -is [pscustomobject]) {
                $apiError = [string]$parsed.error
                $apiMessage = [string]$parsed.message
            }
            else {
                $apiMessage = if ($raw.Length -gt 500) { $raw.Substring(0, 500) } else { $raw }
            }
        }
        else {
            $apiMessage = [string]$err.Exception.Message
        }

        $target = [pscustomobject]@{
            StatusCode = [int]$statusCode
            ApiError   = [string]$apiError
            ApiMessage = [string]$apiMessage
            Method     = $Method
            Path       = $Path
        }

        if ($statusCode -eq 0) {
            $summary = 'no HTTP response'
        }
        else {
            $summary = "HTTP $statusCode"
        }
        if ($apiError) { $summary += " $apiError" }
        if ($apiMessage) { $summary += ": $apiMessage" }
        $message = "API $Method $Path failed: $summary"
        $message = $message -replace '\s{2,}', ' '

        $record = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new($message),
            'ZnApiError',
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $target
        )
        $PSCmdlet.ThrowTerminatingError($record)
    }
}

<#
.SYNOPSIS
    Normalizes a type name for comparison.

.DESCRIPTION
    Lowercases the value, replaces each run of characters other than a-z and 0-9 with a single
    space, and trims the result.

.PARAMETER Value
    The text to normalize. $null and empty strings are allowed.

.OUTPUTS
    System.String.

.NOTES
    Example: 'Ip-CAMERA' becomes 'ip camera'.
#>
function ConvertTo-NormalizedKey {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Value)

    return (([string]$Value).ToLowerInvariant() -replace '[^a-z0-9]+', ' ').Trim()
}

<#
.SYNOPSIS
    Returns the tenant's OT/IoT asset type list.

.DESCRIPTION
    Reads the 'type' filter from GET /assets/ot/filters and keeps the usable selections. A
    selection is kept when its ID is an integer in the range 4-999 or equal to 1001, and its
    name is not blank. Results are de-duplicated by ID and sorted by ID. The list is cached in
    script scope until -Force is given.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl.

.PARAMETER ApiKey
    API key for the tenant.

.PARAMETER Force
    Ignore the cached list and call the API again.

.OUTPUTS
    Array of pscustomobject with Id ([int]) and Name ([string]) properties.

.NOTES
    Throws when the 'type' filter is missing or has no usable selections. ZnApiError from the
    API call is not caught here.
#>
function Get-OtAssetTypeList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $false)][switch]$Force
    )

    if (-not $Force -and $null -ne $script:OtTypeList) {
        return $script:OtTypeList
    }

    $response = Invoke-ZnRestMethod -Method GET -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -Path '/assets/ot/filters'

    $typeFilter = @($response.filters | Where-Object { $_.id -eq 'type' }) | Select-Object -First 1
    $selections = @()
    if ($null -ne $typeFilter) {
        $selections = @($typeFilter.selections)
    }

    $seen = @{}
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($selection in $selections) {
        if ($null -eq $selection) { continue }

        $idValue = 0
        if (-not [int]::TryParse([string]$selection.id, [ref]$idValue)) { continue }

        $name = [string]$selection.name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        if (-not (($idValue -ge 4 -and $idValue -le 999) -or $idValue -eq 1001)) { continue }

        if ($seen.ContainsKey($idValue)) { continue }
        $seen[$idValue] = $true

        $list.Add([pscustomobject]@{ Id = [int]$idValue; Name = $name })
    }

    if ($list.Count -eq 0) {
        throw "The tenant's OT/IoT asset type list (GET /assets/ot/filters, filter 'type') was missing or empty."
    }

    $sorted = @($list | Sort-Object -Property Id)
    $script:OtTypeList = $sorted
    return $sorted
}

<#
.SYNOPSIS
    Converts an OT/IoT type name or numeric ID into a type ID.

.DESCRIPTION
    A value made only of digits is treated as an ID and must exist in TypeList. Any other value
    is compared with the type names after normalization. The comparison is exact and never fuzzy.
    One match returns its ID. Several matches, or none, throw an error. An error for no match
    includes up to five close suggestions.

.PARAMETER Value
    The type name or numeric ID to resolve.

.PARAMETER TypeList
    Type list returned by Get-OtAssetTypeList.

.OUTPUTS
    System.Int32.

.NOTES
    Throws plain string messages without a row prefix. Callers add the row context. Writes a warning
    when the result is 1001, the generic OT/IoT type.
#>
function Resolve-OtAssetType {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][object[]]$TypeList
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw 'type is blank; use an OT/IoT type name or numeric ID (run Get-OtAssetTypes.ps1 to list them)'
    }

    $trimmed = $Value.Trim()

    if ($trimmed -match '^\d+$') {
        $number = 0
        if ([int]::TryParse($trimmed, [ref]$number)) {
            $byId = $TypeList | Where-Object { [int]$_.Id -eq $number } | Select-Object -First 1
            if ($null -ne $byId) {
                if ($number -eq 1001) {
                    Write-Warning "type 1001 ('$($byId.Name)') is the generic OT/IoT type, which the portal does not offer in its type picker; consider a more specific type."
                }
                return $number
            }
        }
        throw "type $trimmed is not a valid OT/IoT type ID for this tenant (run Get-OtAssetTypes.ps1 to list valid types)"
    }

    $key = ConvertTo-NormalizedKey -Value $Value
    $hits = @()
    if ($key -ne '') {
        $hits = @($TypeList | Where-Object { (ConvertTo-NormalizedKey -Value ([string]$_.Name)) -eq $key } | Sort-Object -Property Id)
    }

    if ($hits.Count -eq 1) {
        $id = [int]$hits[0].Id
        if ($id -eq 1001) {
            Write-Warning "type 1001 ('$($hits[0].Name)') is the generic OT/IoT type, which the portal does not offer in its type picker; consider a more specific type."
        }
        return $id
    }

    if ($hits.Count -gt 1) {
        $described = @($hits | ForEach-Object { "'$($_.Name)' (id $($_.Id))" })
        throw "type '$Value' is ambiguous; it matches: $($described -join ', '). Use the numeric ID instead"
    }

    $suggestions = [System.Collections.Generic.List[object]]::new()
    if ($key -ne '') {
        foreach ($candidate in @($TypeList | Sort-Object -Property Id)) {
            $candidateKey = ConvertTo-NormalizedKey -Value ([string]$candidate.Name)
            if ($candidateKey -eq '') { continue }
            if ($candidateKey.Contains($key) -or $key.Contains($candidateKey)) {
                $suggestions.Add($candidate)
                if ($suggestions.Count -ge 5) { break }
            }
        }
    }

    $message = "type '$Value' is not a recognized OT/IoT type for this tenant."
    if ($suggestions.Count -gt 0) {
        $quoted = @($suggestions | ForEach-Object { "'$($_.Name)'" })
        $message += " Did you mean: $($quoted -join ', ')?"
    }
    $message += ' Run Get-OtAssetTypes.ps1 to list valid names.'
    throw $message
}
