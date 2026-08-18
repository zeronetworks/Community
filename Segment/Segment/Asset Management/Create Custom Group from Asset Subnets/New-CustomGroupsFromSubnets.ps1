<#
.SYNOPSIS
    Creates Zero Networks custom groups from subnet mappings and populates them with matching assets.

.DESCRIPTION
    Reads a CSV of subnet-to-custom-group-name mappings, creates any custom groups that do not
    already exist, and populates each group with every client/server asset whose last known IP
    address falls within the mapped subnet. Assets already present in a group are skipped.

    A local JSON record file tracks every group created (or found), its subnet mapping, and the
    assets assigned to it. This record can be used to re-run the assignment workflow against a
    single, already-known group by name instead of re-reading the CSV (-TargetGroupName).

    The Zero Networks API key is never passed on the command line - it is read from a `.env` file
    (ZN_API_KEY=<key>) stored next to this script. The tenant portal URL is derived automatically
    from the `aud` claim of that API key, which is a JWT.

.PARAMETER SubnetCsvPath
    Path to the CSV file containing Subnet -> Custom Group Name mappings. Defaults to
    ".\subnet-group-mappings.csv". Required columns: "Subnet" (IPv4 CIDR), "Custom Group Name".

.PARAMETER TargetGroupName
    Name of a single, already-known custom group to (re-)process. Its subnet mapping is looked up
    in the local JSON record file rather than the CSV. Required for the ByGroupName parameter set.

.PARAMETER Client
    Include assetType Client (1) assets when matching a subnet. At least one of -Client / -Server
    is required.

.PARAMETER Server
    Include assetType Server (2) assets when matching a subnet. At least one of -Client / -Server
    is required.

.PARAMETER DryRun
    Preview changes (group creation, member assignment) without calling any mutating API endpoint.

.PARAMETER MaxConcurrentBatches
    Maximum number of subnet-batch asset resolution requests to run concurrently. Defaults to 5.
    Set to 1 to force fully sequential behavior. No documented Zero Networks API rate limit exists,
    so raise cautiously.

.PARAMETER EnableDebug
    Enables debug output. When provided, sets $DebugPreference to Continue. When not provided, sets
    $DebugPreference to SilentlyContinue.

.NOTES
    Requires PowerShell 7.0 or higher.
    Requires a `.env` file next to this script containing `ZN_API_KEY=<your api key>`. See
    `.env.example` for a template.
    The local JSON record file (`<envName>-CustomGroupSubnetRecord.json`) and the `logs\` directory
    are both created next to this script and are gitignored.

.EXAMPLE
    .\New-CustomGroupsFromSubnets.ps1 -Client -Server
    Creates/updates all custom groups described in .\subnet-group-mappings.csv, matching both
    client and server assets.

.EXAMPLE
    .\New-CustomGroupsFromSubnets.ps1 -Server -SubnetCsvPath .\my-mappings.csv -DryRun
    Previews what would happen for a custom mapping CSV, matching server assets only.

.EXAMPLE
    .\New-CustomGroupsFromSubnets.ps1 -Client -Server -TargetGroupName "TEST-SERVERS-FLOOR"
    Re-runs asset discovery/assignment for a single already-known group, using the subnet recorded
    for it in the local JSON record file.
#>

<#PSScriptInfo
.VERSION 1.0
.AUTHOR Thomas Obarowski (https://www.linkedin.com/in/tjobarow/)
.TAGS Automation Scripts
#>

#requires -Version 7.0

[CmdletBinding(DefaultParameterSetName = "BySubnetCsv")]
param(
    [Parameter(ParameterSetName = "BySubnetCsv", Mandatory = $false)]
    [string]$SubnetCsvPath = ".\subnet-group-mappings.csv",

    [Parameter(ParameterSetName = "ByGroupName", Mandatory = $true)]
    [string]$TargetGroupName,

    # At least one of -Client / -Server is required (enforced below - CmdletBinding cannot express
    # an "at least one of" constraint declaratively across a parameter set).
    [Parameter(ParameterSetName = "BySubnetCsv", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByGroupName", Mandatory = $false)]
    [switch]$Client,

    [Parameter(ParameterSetName = "BySubnetCsv", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByGroupName", Mandatory = $false)]
    [switch]$Server,

    [Parameter(ParameterSetName = "BySubnetCsv", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByGroupName", Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(ParameterSetName = "BySubnetCsv", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByGroupName", Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]$MaxConcurrentBatches = 5,

    [Parameter(ParameterSetName = "BySubnetCsv", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByGroupName", Mandatory = $false)]
    [switch]$EnableDebug
)
$ErrorActionPreference = "Stop"

if ($EnableDebug) {
    $DebugPreference = "Continue"
    Write-Debug "Debug output enabled"
}
else {
    $DebugPreference = "SilentlyContinue"
}

if (-not $Client -and -not $Server) {
    throw "At least one of -Client or -Server must be specified - the script needs to know which asset type(s) to match against the subnet(s)."
}

# Number of host addresses to include per /assets/monitored filter query when resolving
# assets by subnet. Not exposed as a script parameter - internal tunable only.
$script:SUBNET_BATCH_SIZE = 100

# assetType codes (see ZeroNetworks-openapi.yaml #/components/schemas/assetType) that qualify as
# "client/server type asset" per the requirements. 1 = Client, 2 = Server. Driven by -Client/-Server.
$script:QUALIFYING_ASSET_TYPES = @(
    if ($Client) { 1 }
    if ($Server) { 2 }
)

<#
This section of the script is responsible for
resolving the API key and portal URL, and initializing the API context.
#>

<#
    .SYNOPSIS
        Reads the Zero Networks API key from a local .env file next to this script.
    .OUTPUTS
        Returns the API key string.
    .NOTES
        Expects a "ZN_API_KEY=<key>" line in a `.env` file at $PSScriptRoot\.env. Blank lines and
        lines starting with '#' are ignored. Throws a descriptive error if the file or key is missing.
    #>
function Get-ApiKeyFromEnvFile {
    $EnvFilePath = Join-Path -Path $PSScriptRoot -ChildPath ".env"

    if (-not (Test-Path -Path $EnvFilePath)) {
        throw "Could not find a .env file at '$EnvFilePath'. Create one containing a line 'ZN_API_KEY=<your api key>' (see .env.example)."
    }

    $EnvLines = Get-Content -Path $EnvFilePath
    $ApiKey = $null
    foreach ($line in $EnvLines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }
        $parts = $trimmed -split '=', 2
        if ($parts.Count -eq 2 -and $parts[0].Trim() -eq 'ZN_API_KEY') {
            $ApiKey = $parts[1].Trim().Trim('"').Trim("'")
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        throw "'.env' file at '$EnvFilePath' does not contain a ZN_API_KEY=<key> entry."
    }

    Write-Debug "Loaded API key from .env file"
    return $ApiKey
}

<#
    .SYNOPSIS
        Derives the Zero Networks tenant portal URL from the API key.
    .PARAMETER ApiKey
        The Zero Networks API key (a JWT).
    .OUTPUTS
        Returns the portal base URL (e.g. "https://tenant-admin.zeronetworks.com").
    .NOTES
        Zero Networks API keys are JWTs. The payload segment is base64url-encoded JSON containing
        an "aud" claim that is exactly the tenant admin host. Throws a descriptive error if the key
        is not a well-formed JWT or has no "aud" claim.
    #>
function Get-PortalUrlFromApiKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )
    $segments = $ApiKey -split '\.'
    if ($segments.Count -ne 3) {
        throw "ZN_API_KEY does not look like a valid JWT (expected 3 dot-separated segments, found $($segments.Count)). Cannot derive the portal URL."
    }

    # base64url -> base64: swap URL-safe characters back and restore padding
    $payloadSegment = $segments[1].Replace('-', '+').Replace('_', '/')
    switch ($payloadSegment.Length % 4) {
        2 { $payloadSegment += '==' }
        3 { $payloadSegment += '=' }
    }

    try {
        $payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payloadSegment))
        $payload = $payloadJson | ConvertFrom-Json
    }
    catch {
        throw "Failed to decode ZN_API_KEY JWT payload: $_"
    }

    if ([string]::IsNullOrWhiteSpace($payload.aud)) {
        throw "ZN_API_KEY JWT payload does not contain an 'aud' claim. Cannot derive the portal URL."
    }

    $PortalUrl = "https://$($payload.aud)"
    Write-Debug "Derived portal URL from API key: $PortalUrl"
    return $PortalUrl
}

<#
    .SYNOPSIS
        Initializes the API context (headers, base URL) for Zero Networks API requests.
    .OUTPUTS
        None. Sets $script:Headers, $script:ApiBaseUrl, and $script:PortalUrl.
    .NOTES
        Resolves the API key via Get-ApiKeyFromEnvFile and the portal URL via Get-PortalUrlFromApiKey.
    #>
function Initialize-ApiContext {
    $ApiKey = Get-ApiKeyFromEnvFile
    $script:PortalUrl = Get-PortalUrlFromApiKey -ApiKey $ApiKey

    $script:Headers = @{
        Accept        = "application/json"
        Authorization = $ApiKey
    }
    $script:ApiBaseUrl = "$($script:PortalUrl)/api/v1"
    Write-Host "Initialized API context for tenant: $($script:PortalUrl)"
}

<#
This section of the script contains the generic API
plumbing functions (request execution, pagination, status validation).
#>

<#
    .SYNOPSIS
        Validates HTTP status codes and throws appropriate errors for non-success responses.
    .PARAMETER StatusCode
        The HTTP status code to validate.
    .PARAMETER Response
        Optional response object to include in error messages.
    .OUTPUTS
        None. Returns silently for 2XX status codes. Throws exceptions for all error codes.
    .NOTES
        Includes response body in error message when available.
    #>
function Test-ApiResponseStatusCode {
    param(
        [Parameter(Mandatory = $true)]
        [int]$StatusCode,

        [Parameter(Mandatory = $false)]
        [object]$Response = $null
    )

    if ($StatusCode -ge 200 -and $StatusCode -lt 300) {
        return
    }

    $errorStatusCodes = @{
        400 = "Bad Request"
        401 = "Unauthorized"
        403 = "Forbidden"
        404 = "Not Found"
        405 = "Method Not Allowed"
        409 = "Conflict"
        500 = "Internal Server Error"
        501 = "Not Implemented"
        503 = "Service Unavailable"
    }

    if ($errorStatusCodes.ContainsKey($StatusCode)) {
        $reasonPhrase = $errorStatusCodes[$StatusCode]
        $errorMessage = "API request failed with status code $StatusCode ($reasonPhrase)"
    }
    else {
        $errorMessage = "API request failed with status code $StatusCode"
    }

    $responseBody = $null
    if ($null -ne $Response) {
        $responseBody = if ($Response -is [string]) {
            $Response
        }
        elseif ($Response -is [PSCustomObject] -or $Response -is [hashtable]) {
            $Response | ConvertTo-Json -Depth 10
        }
        else {
            $Response.ToString()
        }
    }

    $fullErrorMessage = $errorMessage
    if ($null -ne $responseBody -and $responseBody.Trim() -ne "") {
        $fullErrorMessage = "$errorMessage`nResponse body: $responseBody"
    }

    $exception = New-Object System.Exception $fullErrorMessage
    $exception | Add-Member -MemberType NoteProperty -Name "StatusCode" -Value $StatusCode
    $exception | Add-Member -MemberType NoteProperty -Name "Response" -Value $Response

    $errorRecord = New-Object System.Management.Automation.ErrorRecord(
        $exception,
        "ApiRequestFailed",
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $null
    )

    throw $errorRecord
}

<#
    .SYNOPSIS
        Makes HTTP requests to the Zero Networks API with error handling.
    .PARAMETER Method
        HTTP method to use (GET, POST, PUT, PATCH, DELETE).
    .PARAMETER ApiEndpoint
        API endpoint path (e.g., "groups/custom" or "/groups/custom/g:c:abcd1234/members").
    .PARAMETER Body
        Optional request body object. Will be converted to JSON if not already a string.
    .PARAMETER QueryParams
        Optional query parameters object to include in the request.
    .OUTPUTS
        Returns the API response object.
    .NOTES
        Automatically validates status codes and throws exceptions for errors.
        Retries up to 3 times with a short exponential backoff (1s, 2s, 4s) if the API responds with
        HTTP 429 (rate limited), since concurrent subnet-batch requests (-MaxConcurrentBatches) can
        trigger rate limiting that a single sequential request stream would not have.
    #>
function Invoke-ApiRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$ApiEndpoint,

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [object]$QueryParams = $null
    )

    try {
        $requestParams = @{
            Method  = $Method
            Uri     = "$script:ApiBaseUrl/$ApiEndpoint"
            Headers = $script:Headers
        }

        $QueryString = ""
        if ($null -ne $QueryParams) {
            $QueryString = ($QueryParams.GetEnumerator() | ForEach-Object {
                "$($_.Key)=$($_.Value.ToString())"
            }) -join '&'
            $requestParams['Uri'] = $requestParams['Uri'] + "?" + $QueryString
        }

        if ($null -ne $Body) {
            $requestParams['Body'] = if ($Body -is [string]) {
                $Body
            }
            else {
                $Body | ConvertTo-Json -Depth 10 -Compress
            }
            $requestParams['ContentType'] = "application/json"
        }

        $maxAttempts = 3
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            $statusCode = $null
            $response = Invoke-RestMethod @requestParams -SkipHttpErrorCheck -StatusCodeVariable statusCode

            if ($statusCode -eq 429 -and $attempt -lt $maxAttempts) {
                $backoffSeconds = [math]::Pow(2, $attempt - 1)
                Write-Warning "Received HTTP 429 (rate limited) from $($requestParams['Uri']). Retrying in $backoffSeconds second(s) (attempt $attempt of $maxAttempts)..."
                Start-Sleep -Seconds $backoffSeconds
                continue
            }
            break
        }

        Test-ApiResponseStatusCode -StatusCode $statusCode -Response $response | Out-Null

        return $response
    }
    catch {
        if ($null -ne $_.Exception.StatusCode -and ($_.Exception.StatusCode -eq 404)) {
            throw $_
        }
        throw "API request to $($requestParams['Uri']) failed due to error:`n$_"
    }
}

<#
    .SYNOPSIS
        Wraps Invoke-ApiRequest to transparently handle cursor- and offset-based pagination.
    .PARAMETER Method
        HTTP method to use (GET, POST, PUT, PATCH, DELETE).
    .PARAMETER ApiEndpoint
        API endpoint path.
    .PARAMETER QueryParams
        Optional query parameters object to include in the request.
    .PARAMETER Body
        Optional request body object.
    .OUTPUTS
        Returns the complete API response object with all paginated items combined.
    .NOTES
        Automatically handles both cursor-based and offset-based pagination.
    #>
function Invoke-PaginatedApiRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$ApiEndpoint,

        [Parameter(Mandatory = $false)]
        [object]$QueryParams = $null,

        [Parameter(Mandatory = $false)]
        [object]$Body = $null
    )

    $response = Invoke-ApiRequest -Method $Method -ApiEndpoint $ApiEndpoint -Body $Body -QueryParams $QueryParams

    $NextCursor = $response.nextCursor
    while ($NextCursor -and ($NextCursor.Length -gt 0)) {
        $QueryParams['_cursor'] = $NextCursor
        Write-Debug "Fetching page with cursor $($QueryParams['_cursor'])"
        $nextPageResponse = Invoke-ApiRequest -Method $Method -ApiEndpoint $ApiEndpoint -Body $Body -QueryParams $QueryParams
        if ($nextPageResponse.items.Count -gt 0) {
            $response.items += $nextPageResponse.items
        }
        $NextCursor = $nextPageResponse.nextCursor
    }

    $TotalItemsCount = $response.count
    if ($null -ne $TotalItemsCount) {
        $QueryParams['_offset'] = $response.nextOffset
        while ($response.items.Count -lt $TotalItemsCount) {
            Write-Debug "Fetching next page with offset $($QueryParams['_offset'])"
            $nextPageResponse = Invoke-ApiRequest -Method $Method -ApiEndpoint $ApiEndpoint -Body $Body -QueryParams $QueryParams
            if ($nextPageResponse.items.Count -gt 0) {
                $response.items += $nextPageResponse.items
            }
            $QueryParams['_offset'] = $nextPageResponse.nextOffset
        }
    }

    Write-Debug "Total items retrieved from $($ApiEndpoint): $($response.items.Count)"
    return $response
}

<#
This section of the script contains functions related to
subnet-based asset discovery for group membership.
#>

<#
    .SYNOPSIS
        Expands an IPv4 CIDR subnet into an array of individual host address strings.
    .PARAMETER TargetSubnet
        The CIDR subnet to expand (e.g., "10.200.200.0/24").
    .OUTPUTS
        Returns an ArrayList of every dotted-quad host address in the subnet range (including network/broadcast addresses).
    .NOTES
        Subnets larger than /24 (256 addresses) require interactive confirmation before proceeding.
        Subnets larger than /16 (65,536 addresses) are rejected outright, since resolving them would require
        an impractical number of batched API calls. Throws an exception if the subnet is malformed, too large,
        or if the user declines the confirmation prompt.
    #>
function Get-SubnetHostAddresses {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetSubnet
    )
    Write-Host "Expanding subnet $TargetSubnet into individual host addresses"

    $parts = $TargetSubnet -split '/'
    $networkIp = [ipaddress]::Parse($parts[0])
    $prefixLength = [int]$parts[1]

    if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
        throw "Invalid CIDR prefix length in subnet $TargetSubnet : must be between 0 and 32"
    }

    $networkBytes = $networkIp.GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($networkBytes)
    }
    $networkInt = [BitConverter]::ToUInt32($networkBytes, 0)

    $maskInt = if ($prefixLength -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefixLength) }
    $networkBaseInt = $networkInt -band $maskInt

    [uint64]$numAddresses = [uint64]1 -shl (32 - $prefixLength)

    if ($numAddresses -gt 65536) {
        throw "Subnet $TargetSubnet contains $numAddresses addresses, which exceeds the maximum supported size of 65,536 (/16). Please provide a smaller subnet."
    }
    elseif ($numAddresses -gt 256) {
        Write-Warning "Subnet $TargetSubnet contains $numAddresses addresses, which will require $([math]::Ceiling($numAddresses / $script:SUBNET_BATCH_SIZE)) batched API call(s) to resolve assets.`nThis may take a long time to complete. Please confirm you want to proceed with this subnet size."
        $confirmation = Read-Host "Type 'y' to confirm you want to proceed with this subnet size"
        if ($confirmation -ne 'y') {
            throw "Aborted subnet expansion for $TargetSubnet - user did not confirm proceeding with a subnet larger than /24"
        }
    }

    [System.Collections.ArrayList]$AssetSubnetHostAddresses = @()
    for ([uint64]$i = 0; $i -lt $numAddresses; $i++) {
        $currentInt = [uint32]([uint64]$networkBaseInt + $i)
        $currentBytes = [BitConverter]::GetBytes($currentInt)
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($currentBytes)
        }
        $currentIp = [ipaddress]::new($currentBytes)
        $AssetSubnetHostAddresses.Add($currentIp.ToString()) | Out-Null
    }

    Write-Host "Expanded subnet $TargetSubnet into $($AssetSubnetHostAddresses.Count) host addresses"
    return $AssetSubnetHostAddresses
}

<#
    .SYNOPSIS
        Retrieves monitored client/server assets whose last known IP address falls within a set of subnet host addresses.
    .PARAMETER AssetSubnetHostAddresses
        ArrayList of dotted-quad host address strings to search for (as produced by Get-SubnetHostAddresses).
    .PARAMETER MaxConcurrentBatches
        Maximum number of batch queries to run concurrently. Defaults to 5. Set to 1 to force sequential behavior.
    .OUTPUTS
        Returns an ArrayList of asset entity objects (assetType Client or Server only) whose lastIpAddress matched any of the provided addresses.
    .NOTES
        Addresses are queried in batches of $script:SUBNET_BATCH_SIZE, since the API has no native subnet-range filter.
        Each batch query filters on both lastIpAddress and assetType server-side; a client-side filter is also applied
        as a safety net, mirroring how OU-based asset discovery filters out non-asset entities.
        Batches are queried concurrently (via ForEach-Object -Parallel), so "Querying batch N of M..." progress
        messages may print out of order - this is cosmetic only and does not affect the assets returned.
    #>
function Get-AssetsByHostAddresses {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$AssetSubnetHostAddresses,

        [Parameter(Mandatory = $false)]
        [int]$MaxConcurrentBatches = 5
    )
    Write-Host "Retrieving client/server assets matching $($AssetSubnetHostAddresses.Count) subnet host addresses"

    $batchSize = $script:SUBNET_BATCH_SIZE
    $totalAddresses = $AssetSubnetHostAddresses.Count
    $totalBatches = [math]::Ceiling($totalAddresses / $batchSize)

    [System.Collections.ArrayList]$Batches = @()
    $batchNumber = 1
    for ($i = 0; $i -lt $totalAddresses; $i += $batchSize) {
        $endIndex = [math]::Min($i + $batchSize - 1, $totalAddresses - 1)
        $Batches.Add([PSCustomObject]@{
            BatchNumber = $batchNumber
            Addresses   = @($AssetSubnetHostAddresses[$i..$endIndex])
        }) | Out-Null
        $batchNumber++
    }

    # ForEach-Object -Parallel runspaces do not inherit $script: variables or functions from the
    # calling scope - capture what each batch's API call needs here and re-hydrate it via $using:
    # inside the parallel block.
    $ApiBaseUrl = $script:ApiBaseUrl
    $Headers = $script:Headers
    $QualifyingAssetTypes = $script:QUALIFYING_ASSET_TYPES
    $CapturedDebugPreference = $DebugPreference
    $InvokeApiRequestDef = ${function:Invoke-ApiRequest}.ToString()
    $InvokePaginatedApiRequestDef = ${function:Invoke-PaginatedApiRequest}.ToString()
    $TestApiResponseStatusCodeDef = ${function:Test-ApiResponseStatusCode}.ToString()

    $BatchResults = $Batches | ForEach-Object -ThrottleLimit $MaxConcurrentBatches -Parallel {
        ${function:Test-ApiResponseStatusCode} = $using:TestApiResponseStatusCodeDef
        ${function:Invoke-ApiRequest} = $using:InvokeApiRequestDef
        ${function:Invoke-PaginatedApiRequest} = $using:InvokePaginatedApiRequestDef
        $script:ApiBaseUrl = $using:ApiBaseUrl
        $script:Headers = $using:Headers
        $DebugPreference = $using:CapturedDebugPreference

        $batch = $_
        Write-Host "Querying batch $($batch.BatchNumber) of $($using:totalBatches) ($($batch.Addresses.Count) addresses)..."

        # Filter server-side on lastIpAddress only - this is the same filter shape already proven to
        # work against /assets/monitored elsewhere in this repo. A second, unverified "assetType"
        # filter here previously caused the API to return zero results (its expected value format
        # is undocumented), so assetType is restricted client-side instead (see the Where-Object
        # filter on $script:QUALIFYING_ASSET_TYPES below, after the parallel block).
        $FilterArray = @(
            @{
                id = "lastIpAddress"
                includeValues = @($batch.Addresses)
            }
        )
        $FilterJson = $FilterArray | ConvertTo-Json -Compress -AsArray -Depth 10

        $QueryParams = @{
            _limit = 100
            showInactive = $false
            _filters = $FilterJson
        }

        $response = Invoke-PaginatedApiRequest -Method "GET" -ApiEndpoint "/assets/monitored" -QueryParams $QueryParams

        Write-Debug "Batch $($batch.BatchNumber) response body: $($response | ConvertTo-Json -Compress -Depth 10)"

        if ($null -ne $response.items -and $response.items.Count -gt 0) {
            $response.items
        }
    }

    [System.Collections.ArrayList]$Assets = @()
    if ($null -ne $BatchResults) {
        $Assets.AddRange(@($BatchResults))
    }

    # Client-side safety net: only keep assetType Client (1) or Server (2), in case the server-side
    # filter is not honored, and dedupe by id (an asset can match more than one queried host address).
    [System.Collections.ArrayList]$UniqueAssets = @(
        $Assets | Where-Object { $script:QUALIFYING_ASSET_TYPES -contains $_.assetType } | Sort-Object -Property id -Unique
    )

    Write-Host "Retrieved $($UniqueAssets.Count) unique client/server assets across $totalBatches batch(es) matching subnet host addresses"
    return $UniqueAssets
}

<#
This section of the script contains functions related to
custom group lookup, creation, and membership management.
#>

<#
    .SYNOPSIS
        Looks up an existing custom group by exact name.
    .PARAMETER GroupName
        The custom group name to search for.
    .OUTPUTS
        Returns the matching group entity object, or $null if no group with that exact name exists.
    .NOTES
        Uses GET /groups/custom with a name filter. Matches only on an exact (case-sensitive) name match.
    #>
function Get-CustomGroupByName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )
    Write-Host "Checking whether custom group '$GroupName' already exists"

    $FilterArray = @(
        @{
            id = "name"
            includeValues = @($GroupName)
        }
    )
    $FilterJson = $FilterArray | ConvertTo-Json -Compress -AsArray -Depth 10

    $QueryParams = @{
        _limit = 100
        with_count = $true
        _filters = $FilterJson
    }

    $response = Invoke-PaginatedApiRequest -Method "GET" -ApiEndpoint "groups/custom" -QueryParams $QueryParams

    Write-Debug "Custom group lookup response body: $($response | ConvertTo-Json -Compress -Depth 10)"

    if ($null -eq $response.items) {
        throw "Custom group lookup API response is malformed and does not contain 'items' property"
    }

    foreach ($item in $response.items) {
        if ($item.name -eq $GroupName) {
            Write-Host "Found existing custom group '$GroupName' ($($item.id))"
            return $item
        }
    }

    Write-Host "Custom group '$GroupName' does not exist yet"
    return $null
}

<#
    .SYNOPSIS
        Creates a custom group if it does not already exist, returning its ID either way.
    .PARAMETER GroupName
        The custom group name to look up or create.
    .PARAMETER Subnet
        The subnet this group is mapped to (used only for the auto-generated description and the local record).
    .PARAMETER DryRun
        If specified, does not call the create API when the group is missing - returns $null instead.
    .OUTPUTS
        Returns the custom group ID (string), or $null if the group does not exist and -DryRun was specified.
    .NOTES
        Groups are always created with no members - membership is applied separately via Add-AssetsToCustomGroup,
        so the "already exists" and "just created" code paths behave identically downstream.
    #>
function New-CustomGroupIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [string]$Subnet,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    $existingGroup = Get-CustomGroupByName -GroupName $GroupName
    if ($null -ne $existingGroup) {
        return $existingGroup.id
    }

    if ($DryRun) {
        Write-Host "[DRY RUN] Would create custom group '$GroupName' for subnet $Subnet"
        return $null
    }

    $body = @{
        name = $GroupName
        description = "Auto-created from subnet $Subnet by New-CustomGroupsFromSubnets.ps1"
    }

    $response = Invoke-ApiRequest -Method "POST" -ApiEndpoint "groups/custom" -Body $body

    if ($null -eq $response.entity -or [string]::IsNullOrWhiteSpace($response.entity.id)) {
        throw "Create custom group response is malformed and does not contain 'entity.id' property"
    }

    Write-Host "Created custom group '$GroupName' ($($response.entity.id)) for subnet $Subnet"
    return $response.entity.id
}

<#
    .SYNOPSIS
        Retrieves the set of asset IDs currently in a custom group.
    .PARAMETER GroupId
        The custom group ID to look up members for.
    .OUTPUTS
        Returns a hashtable keyed by member asset ID (values are unused, hashtable used as a set) for O(1) membership checks.
    .NOTES
        Uses GET /groups/custom/{groupId}/successors, the same shape used for AD OU membership lookups.
    #>
function Get-CustomGroupMemberIds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )
    Write-Host "Retrieving current members of custom group $GroupId"

    $QueryParams = @{
        _limit = 100
    }

    $response = Invoke-PaginatedApiRequest -Method "GET" -ApiEndpoint "groups/custom/$GroupId/successors" -QueryParams $QueryParams

    Write-Debug "Custom group members response body: $($response | ConvertTo-Json -Compress -Depth 10)"

    $MemberIds = @{}
    if ($null -ne $response.items) {
        foreach ($item in $response.items) {
            $MemberIds[$item.id] = $true
        }
    }

    Write-Host "Custom group $GroupId currently has $($MemberIds.Count) member(s)"
    return $MemberIds
}

<#
    .SYNOPSIS
        Adds assets to a custom group, skipping any already present, in batches of 50.
    .PARAMETER GroupId
        The custom group ID to add members to.
    .PARAMETER Assets
        ArrayList of asset objects (must have an .id property) to add.
    .PARAMETER DryRun
        If specified, previews the operation without calling the mutation API.
    .OUTPUTS
        Returns a PSCustomObject with 'Added' and 'Skipped' ArrayList properties (of asset objects), for summary reporting.
    .NOTES
        Membership is checked once up front via Get-CustomGroupMemberIds; assets already present are skipped entirely.
    #>
function Add-AssetsToCustomGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Assets,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    $Result = [PSCustomObject]@{
        Added   = [System.Collections.ArrayList]@()
        Skipped = [System.Collections.ArrayList]@()
    }

    if ($Assets.Count -eq 0) {
        return $Result
    }

    $CurrentMemberIds = Get-CustomGroupMemberIds -GroupId $GroupId

    [System.Collections.ArrayList]$AssetsToAdd = @()
    foreach ($asset in $Assets) {
        if ($CurrentMemberIds.ContainsKey($asset.id)) {
            Write-Host "Asset $($asset.name) ($($asset.id)) is already a member of group $GroupId - skipping"
            $Result.Skipped.Add($asset) | Out-Null
        }
        else {
            $AssetsToAdd.Add($asset) | Out-Null
        }
    }

    if ($AssetsToAdd.Count -eq 0) {
        Write-Host "No new assets to add to group $GroupId - all $($Assets.Count) asset(s) already members"
        return $Result
    }

    $batchSize = 50
    $totalToAdd = $AssetsToAdd.Count
    $totalBatches = [math]::Ceiling($totalToAdd / $batchSize)
    $batchNumber = 1

    for ($i = 0; $i -lt $totalToAdd; $i += $batchSize) {
        $endIndex = [math]::Min($i + $batchSize - 1, $totalToAdd - 1)
        $batch = [System.Collections.ArrayList]@($AssetsToAdd[$i..$endIndex])

        $body = @{
            membersId = @($batch | ForEach-Object { $_.id })
        }

        if ($DryRun) {
            Write-Host "[DRY RUN] Would add batch $batchNumber of $totalBatches ($($batch.Count) assets) to group $GroupId"
            Write-Host "[DRY RUN] Request body: $($body | ConvertTo-Json -Compress -Depth 10)"
        }
        else {
            Write-Host "Adding batch $batchNumber of $totalBatches ($($batch.Count) assets) to group $GroupId..."
            Invoke-ApiRequest -Method "PUT" -ApiEndpoint "groups/custom/$GroupId/members" -Body $body | Out-Null
            Write-Host "Successfully added $($batch.Count) asset(s) to group $GroupId"
        }

        $Result.Added.AddRange($batch)
        $batchNumber++
    }

    return $Result
}

<#
This section of the script contains functions related to
the local JSON audit record of groups created and assets assigned.
#>

<#
    .SYNOPSIS
        Computes the local group-subnet record cache file path for the current tenant.
    .OUTPUTS
        Returns the full path to the <envName>-CustomGroupSubnetRecord.json file located next to the script.
    .NOTES
        envName is derived from $script:PortalUrl, stripping a trailing ".zeronetworks.com" suffix if present;
        otherwise the full host is used as-is.
    #>
function Get-GroupRecordPath {
    $envName = ([Uri]$script:PortalUrl).Host -replace '\.zeronetworks\.com$', ''
    return Join-Path -Path $PSScriptRoot -ChildPath "$envName-CustomGroupSubnetRecord.json"
}

<#
    .SYNOPSIS
        Reads the local group-subnet record file, returning an empty record if it does not exist.
    .OUTPUTS
        Returns a hashtable keyed by group name, each value a hashtable with groupId/subnet/assetsAssigned/lastUpdated.
    .NOTES
        Uses ConvertFrom-Json -AsHashtable so the record can be mutated and re-saved with ordinary hashtable syntax.
    #>
function Read-GroupRecord {
    $RecordPath = Get-GroupRecordPath
    if (-not (Test-Path -Path $RecordPath)) {
        return @{}
    }

    try {
        $record = Get-Content -Path $RecordPath -Raw | ConvertFrom-Json -AsHashtable
    }
    catch {
        throw "Failed to read group record file '$RecordPath': $_"
    }

    if ($null -eq $record) {
        return @{}
    }
    return $record
}

<#
    .SYNOPSIS
        Writes the local group-subnet record file to disk, overwriting any existing file.
    .PARAMETER Record
        Hashtable keyed by group name (as returned/mutated from Read-GroupRecord) to persist.
    .OUTPUTS
        None. Writes the record file to Get-GroupRecordPath.
    .NOTES
        None.
    #>
function Save-GroupRecord {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Record
    )
    $RecordPath = Get-GroupRecordPath
    try {
        $Record | ConvertTo-Json -Depth 10 | Set-Content -Path $RecordPath
    }
    catch {
        throw "Failed to write group record file '$RecordPath': $_"
    }
    Write-Debug "Group record file written to $RecordPath with $($Record.Count) group(s)"
}

<#
    .SYNOPSIS
        Updates (or inserts) a single group's entry in the local JSON record file and saves it immediately.
    .PARAMETER GroupName
        The custom group name being recorded.
    .PARAMETER GroupId
        The custom group ID.
    .PARAMETER Subnet
        The subnet mapped to this group.
    .PARAMETER AddedAssetIds
        Array of asset IDs newly added to the group during this run (merged into any previously recorded assets).
    .OUTPUTS
        None. Persists the updated record to disk via Save-GroupRecord.
    .NOTES
        Called after each group is processed (not just at the end of the script), so a mid-run failure
        still leaves a usable partial record on disk.
    #>
function Update-GroupRecordEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [string]$Subnet,

        [Parameter(Mandatory = $false)]
        [string[]]$AddedAssetIds = @()
    )
    $Record = Read-GroupRecord

    $existingAssets = @()
    if ($Record.ContainsKey($GroupName) -and $Record[$GroupName].ContainsKey('assetsAssigned')) {
        $existingAssets = @($Record[$GroupName]['assetsAssigned'])
    }
    $mergedAssets = @(@($existingAssets) + @($AddedAssetIds) | Select-Object -Unique)

    $Record[$GroupName] = @{
        groupId        = $GroupId
        subnet         = $Subnet
        assetsAssigned = $mergedAssets
        lastUpdated    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    Save-GroupRecord -Record $Record
}

<#
This section of the script is responsible for
reading and validating the subnet-to-group-name mapping CSV.
#>

<#
    .SYNOPSIS
        Reads and validates the subnet-to-custom-group-name mapping CSV.
    .PARAMETER CsvPath
        Path to the CSV file to read and validate.
    .OUTPUTS
        Returns an array of PSCustomObject representing the validated CSV rows (Subnet, "Custom Group Name").
    .NOTES
        Required columns: "Subnet" (IPv4 CIDR), "Custom Group Name".
    #>
function Get-SubnetCsvData {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )
    if (-not (Test-Path -Path $CsvPath)) {
        throw "Subnet mapping CSV file not found: $CsvPath"
    }

    try {
        $csvData = @(Import-Csv -Path $CsvPath)
        Write-Host "Read $($csvData.Count) rows of subnet mapping CSV data"
    }
    catch {
        throw "Failed to read subnet mapping CSV file: $_"
    }

    if ($csvData.Count -eq 0) {
        throw "Subnet mapping CSV file is empty or contains no data rows."
    }

    $requiredColumns = @('Subnet', 'Custom Group Name')
    $actualColumns = $csvData[0].PSObject.Properties.Name
    $missingColumns = @($requiredColumns | Where-Object { $actualColumns -notcontains $_ })

    if ($missingColumns.Count -gt 0) {
        throw "Subnet mapping CSV validation failed: missing required column(s) $($missingColumns -join ', '). Actual columns found: $($actualColumns -join ', ')"
    }

    $CidrPattern = '^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/(3[0-2]|[1-2]?\d)$'
    for ($i = 0; $i -lt $csvData.Count; $i++) {
        $row = $csvData[$i]
        $csvRowNumber = $i + 2

        if ([string]::IsNullOrWhiteSpace($row.Subnet)) {
            throw "Subnet mapping CSV validation failed: Subnet is empty at row $csvRowNumber"
        }
        if ($row.Subnet -notmatch $CidrPattern) {
            throw "Subnet mapping CSV validation failed: '$($row.Subnet)' at row $csvRowNumber is not a valid IPv4 CIDR subnet"
        }
        if ([string]::IsNullOrWhiteSpace($row.'Custom Group Name')) {
            throw "Subnet mapping CSV validation failed: Custom Group Name is empty at row $csvRowNumber"
        }
    }

    Write-Host "Validated $($csvData.Count) rows of subnet mapping CSV data"
    return $csvData
}

<#
This section of the script contains the shared per-group
processing workflow and final summary reporting.
#>

<#
    .SYNOPSIS
        Resolves/creates a custom group for a subnet mapping, discovers matching assets, and assigns them.
    .PARAMETER GroupName
        The custom group name to process.
    .PARAMETER Subnet
        The subnet mapped to this group.
    .PARAMETER DryRun
        If specified, previews all changes without calling any mutating API endpoint.
    .PARAMETER MaxConcurrentBatches
        Maximum number of subnet-batch asset resolution requests to run concurrently.
    .OUTPUTS
        Returns a PSCustomObject summarizing what happened for this group (for the final run summary).
    .NOTES
        Always updates the local JSON record via Update-GroupRecordEntry, even when the group did not
        already exist and -DryRun prevented it from actually being created (record reflects a null groupId
        in that case, and is corrected on the next non-dry-run pass).
    #>
function Invoke-ProcessGroupSubnetMapping {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,

        [Parameter(Mandatory = $true)]
        [string]$Subnet,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [int]$MaxConcurrentBatches = 5
    )
    Write-Host "$("="*80)"
    Write-Host "Processing group '$GroupName' for subnet $Subnet"
    Write-Host "$("="*80)"

    $GroupId = New-CustomGroupIfMissing -GroupName $GroupName -Subnet $Subnet -DryRun:$DryRun

    if ([string]::IsNullOrWhiteSpace($GroupId)) {
        Write-Host "[DRY RUN] Skipping asset discovery/assignment for '$GroupName' - group does not exist yet and would only be created in a non-dry-run pass"
        return [PSCustomObject]@{
            GroupName      = $GroupName
            Subnet         = $Subnet
            GroupCreated   = $null
            AssetsFound    = 0
            AssetsAdded    = 0
            AssetsSkipped  = 0
        }
    }

    $HostAddresses = Get-SubnetHostAddresses -TargetSubnet $Subnet
    [System.Collections.ArrayList]$Assets = [System.Collections.ArrayList]@(Get-AssetsByHostAddresses -AssetSubnetHostAddresses $HostAddresses -MaxConcurrentBatches $MaxConcurrentBatches)

    $AssignResult = Add-AssetsToCustomGroup -GroupId $GroupId -Assets $Assets -DryRun:$DryRun

    Update-GroupRecordEntry -GroupName $GroupName -GroupId $GroupId -Subnet $Subnet -AddedAssetIds @($AssignResult.Added | ForEach-Object { $_.id })

    Write-Host "Finished processing group '$GroupName': $($Assets.Count) asset(s) found, $($AssignResult.Added.Count) added, $($AssignResult.Skipped.Count) already present"

    return [PSCustomObject]@{
        GroupName     = $GroupName
        Subnet        = $Subnet
        GroupId       = $GroupId
        AssetsFound   = $Assets.Count
        AssetsAdded   = $AssignResult.Added.Count
        AssetsSkipped = $AssignResult.Skipped.Count
    }
}

<#
    .SYNOPSIS
        Prints a summary table of every group processed during this run.
    .PARAMETER Results
        Array of PSCustomObjects as returned by Invoke-ProcessGroupSubnetMapping.
    .OUTPUTS
        None. Writes a formatted summary to the console (and, via the active transcript, to the log file).
    .NOTES
        None.
    #>
function Write-RunSummary {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Results
    )
    Write-Host ""
    Write-Host "$("="*80)"
    Write-Host "RUN SUMMARY"
    Write-Host "$("="*80)"
    $Results | Format-Table -Property GroupName, Subnet, AssetsFound, AssetsAdded, AssetsSkipped -AutoSize | Out-String -Width 4096 | Write-Host

    $totalAdded = ($Results | Measure-Object -Property AssetsAdded -Sum).Sum
    $totalSkipped = ($Results | Measure-Object -Property AssetsSkipped -Sum).Sum
    Write-Host "Processed $($Results.Count) group(s). Total assets added: $totalAdded. Total assets already present (skipped): $totalSkipped."
    Write-Host "$("="*80)"
}

<#
This is the main entry point for the script. All work is wrapped
in a transcript so console output is mirrored to a timestamped log file.
#>
$LogDirectory = Join-Path -Path $PSScriptRoot -ChildPath "logs"
if (-not (Test-Path -Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory | Out-Null
}
$LogFilePath = Join-Path -Path $LogDirectory -ChildPath "New-CustomGroupsFromSubnets_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

try {
    Start-Transcript -Path $LogFilePath | Out-Null

    Initialize-ApiContext

    [System.Collections.ArrayList]$RunResults = @()

    switch ($PSCmdlet.ParameterSetName) {
        "BySubnetCsv" {
            Write-Host "$($DryRun ? "[DRY RUN] " : '')Starting workflow to create/populate custom groups from subnet CSV: $SubnetCsvPath"

            $csvData = Get-SubnetCsvData -CsvPath $SubnetCsvPath

            foreach ($row in $csvData) {
                $result = Invoke-ProcessGroupSubnetMapping -GroupName $row.'Custom Group Name' -Subnet $row.Subnet -DryRun:$DryRun -MaxConcurrentBatches $MaxConcurrentBatches
                $RunResults.Add($result) | Out-Null
            }

            Write-Host "$($DryRun ? "[DRY RUN] " : '')Finished workflow to create/populate custom groups from subnet CSV: $SubnetCsvPath"
        }
        "ByGroupName" {
            Write-Host "$($DryRun ? "[DRY RUN] " : '')Starting workflow to (re-)populate custom group '$TargetGroupName' from local record"

            $Record = Read-GroupRecord
            if (-not $Record.ContainsKey($TargetGroupName)) {
                throw "Group '$TargetGroupName' was not found in the local record file ($(Get-GroupRecordPath)). Run this script against the subnet CSV first (-SubnetCsvPath) to establish a subnet mapping for this group, or check the spelling of -TargetGroupName."
            }
            $Subnet = $Record[$TargetGroupName]['subnet']
            if ([string]::IsNullOrWhiteSpace($Subnet)) {
                throw "Group '$TargetGroupName' exists in the local record file but has no recorded subnet mapping."
            }

            $result = Invoke-ProcessGroupSubnetMapping -GroupName $TargetGroupName -Subnet $Subnet -DryRun:$DryRun -MaxConcurrentBatches $MaxConcurrentBatches
            $RunResults.Add($result) | Out-Null

            Write-Host "$($DryRun ? "[DRY RUN] " : '')Finished workflow to (re-)populate custom group '$TargetGroupName'"
        }
    }

    Write-RunSummary -Results $RunResults
}
finally {
    Stop-Transcript | Out-Null
}
