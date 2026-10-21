#Requires -Version 7.0
<#
.SYNOPSIS
    Bulk-triage Zero Networks network alerts from a CSV export.

.DESCRIPTION
    Reads a CSV export of network alerts (as downloaded from the portal's
    Network Alerts page), and applies a state change and/or classification
    change to every alert ID in it via the Network Alerts API.

    Requires a .env file (see .env.example) next to this script, or the
    ZN_API_BASE_URL / ZN_API_KEY environment variables.

.PARAMETER InputFile
    Path to the network alerts CSV export (must have an 'ID' column).

.PARAMETER State
    New alert state to set on every alert in the CSV.

.PARAMETER Classification
    Top-level classification bucket. Requires -ClassificationCategory
    (or use -ClassificationSlug instead of this pair).

.PARAMETER ClassificationCategory
    Specific classification reason within -Classification.

.PARAMETER ClassificationSlug
    Raw API classification slug to send verbatim, bypassing the
    -Classification/-ClassificationCategory lookup table (use this if a
    guessed slug turns out wrong - see README for the confirmed/guessed table).

.PARAMETER Comment
    Optional comment to set on every alert.

.PARAMETER AssigneeEmail
    Email of the account to assign every alert to. Looked up via GET /users
    (filtered by email) and resolved to its entity ID for assigneeUserId;
    terminates if no matching account is found.

.PARAMETER ChangeTicket
    Optional change ticket value to set on every alert.

.PARAMETER CustomHeaders
    JSON-encoded object of extra headers to append to every request,
    e.g. '{"zn-env-id":"..."}'.

.PARAMETER BatchSize
    Maximum number of concurrent in-flight PATCH calls (default: 10).

.PARAMETER DryRun
    Log what would be sent for each alert without calling the API.

.EXAMPLE
    ./Triage-Alerts.ps1 -InputFile alerts.csv -State closed `
        -Classification false-positive -ClassificationCategory not-malicious

.EXAMPLE
    ./Triage-Alerts.ps1 -InputFile alerts.csv -AssigneeEmail you@example.com -DryRun -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Alias('i', 'Path')]
    [string]$InputFile,

    [ValidateSet('closed', 'in-progress', 'reopened')]
    [string]$State,

    [ValidateSet('false-positive', 'informational', 'true-positive')]
    [string]$Classification,

    [ValidateSet(
        'compromised-account', 'confirmed-activity', 'line-of-business-application',
        'malicious-user-activity', 'malware', 'multi-staged-attack', 'not-enough-data',
        'not-malicious', 'other', 'phishing', 'security-testing', 'unwanted-software'
    )]
    [string]$ClassificationCategory,

    [string]$ClassificationSlug,

    [string]$Comment,

    [string]$AssigneeEmail,

    [string]$ChangeTicket,

    [string]$CustomHeaders,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$BatchSize = 10,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$IdColumn = 'ID'
$RetryAttempts = 3
$RetryStatusCodes = @(429, 500, 502, 503, 504)

$IsVerbose = $VerbosePreference -eq 'Continue'
$BoundParams = $PSBoundParameters

# State: CLI kebab-case value -> API slug. Confirmed against real PATCH
# responses. "new" is deliberately excluded: the API rejects it as a target
# state ("state failed custom validation because value must be one of
# [in_progress, closed, reopened]") - it's only a state alerts start in, not
# one you can transition back to.
$StateSlugs = [ordered]@{
    'in-progress' = 'in_progress'
    'closed'      = 'closed'
    'reopened'    = 'reopened'
}

# Classification: "<classification>|<classification-category>" -> API slug
# for the single `userAlertClassification` field. Built from the 14 labels
# returned by GET /alerts/filters. Every row is confirmed against a real API
# response (see tests/SLUG_VERIFICATION.md). The two "Other" categories (under
# True positive / Informational) are disambiguated with a per-parent suffix
# since both share the label "Other" but map to distinct slugs.
$ClassificationSlugs = [ordered]@{
    'true-positive|multi-staged-attack'          = 'multi_staged_attack'
    'true-positive|malware'                      = 'malware'
    'true-positive|malicious-user-activity'      = 'malicious_user_activity'
    'true-positive|unwanted-software'            = 'unwanted_software'
    'true-positive|phishing'                     = 'phishing'
    'true-positive|compromised-account'          = 'compromised_account'
    'true-positive|other'                        = 'true_positive_other'
    'informational|security-testing'             = 'security_testing'
    'informational|confirmed-activity'           = 'confirmed_activity'
    'informational|line-of-business-application' = 'line_of_business_application'
    'informational|other'                        = 'informational_other'
    'false-positive|not-malicious'               = 'not_malicious'
    'false-positive|not-enough-data'             = 'not_enough_data'
    'false-positive|other'                       = 'false_positive_other'
}


function Write-Log {
    <#
    .SYNOPSIS
        Write a timestamped log line to stderr. DEBUG lines are only written
        when the script runs with -Verbose.
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message
    )
    if ($Level -eq 'DEBUG' -and -not $IsVerbose) {
        return
    }
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss,fff')
    [Console]::Error.WriteLine("$timestamp [$Level] triage_alerts: $Message")
}


function Exit-WithUsageError {
    <#
    .SYNOPSIS
        Report an invalid combination of parameters and exit with code 2.
    #>
    param([Parameter(Mandatory)][string]$Message)
    [Console]::Error.WriteLine("Triage-Alerts.ps1: error: $Message")
    [Console]::Error.WriteLine("Run 'Get-Help ./Triage-Alerts.ps1 -Full' for usage.")
    exit 2
}


function Test-Arguments {
    <#
    .SYNOPSIS
        Validate parameter combinations that ValidateSet can't express.
    #>
    if ([bool]$Classification -ne [bool]$ClassificationCategory) {
        Exit-WithUsageError '-Classification and -ClassificationCategory must be given together.'
    }
    if ($Classification -and $ClassificationSlug) {
        Exit-WithUsageError (
            'Use either -Classification/-ClassificationCategory or ' +
            '-ClassificationSlug, not both.'
        )
    }
    if (-not ($State -or $Classification -or $ClassificationSlug -or $AssigneeEmail)) {
        Exit-WithUsageError (
            'Nothing to do: provide -State, -Classification/' +
            '-ClassificationCategory (or -ClassificationSlug), and/or ' +
            '-AssigneeEmail.'
        )
    }
}


function Import-DotEnv {
    <#
    .SYNOPSIS
        Load KEY=VALUE pairs from the nearest .env file into the process
        environment, without overriding variables that are already set.

    .DESCRIPTION
        Searches for .env starting in the given directory and walking up
        through its parents, stopping at the first one found.
    #>
    param([Parameter(Mandatory)][string]$StartDirectory)

    $dir = Get-Item -LiteralPath $StartDirectory
    $envFile = $null
    while ($dir) {
        $candidate = Join-Path $dir.FullName '.env'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $envFile = $candidate
            break
        }
        $dir = $dir.Parent
    }
    if (-not $envFile) {
        return
    }

    foreach ($rawLine in Get-Content -LiteralPath $envFile -Encoding utf8) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#')) {
            continue
        }
        if ($line -match '^export\s+') {
            $line = $line -replace '^export\s+', ''
        }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) {
            continue
        }
        $key = $line.Substring(0, $eq).Trim()
        $value = $line.Substring($eq + 1).Trim()

        if ($value.Length -ge 2 -and $value[0] -in '"', "'" -and $value.IndexOf($value[0], 1) -gt 0) {
            # Quoted value: take everything up to the matching closing quote.
            $quote = $value[0]
            $value = $value.Substring(1, $value.IndexOf($quote, 1) - 1)
            if ($quote -eq '"') {
                $value = $value -replace '\\n', "`n" -replace '\\"', '"'
            }
        }
        else {
            # Unquoted value: strip an inline " # comment".
            $value = ($value -replace '\s+#.*$', '').Trim()
        }

        if ($null -eq [Environment]::GetEnvironmentVariable($key)) {
            [Environment]::SetEnvironmentVariable($key, $value)
        }
    }
}


function Get-Config {
    <#
    .SYNOPSIS
        Load ZN_API_BASE_URL and ZN_API_KEY from the environment / .env file.

    .OUTPUTS
        Hashtable with BaseUrl (trailing slash stripped, "/api/v1" appended)
        and ApiKey. Exits with code 1 if either required variable is missing.
    #>
    Import-DotEnv -StartDirectory $PSScriptRoot

    $baseUrl = ([string]$env:ZN_API_BASE_URL).TrimEnd('/')
    if ($baseUrl) {
        $baseUrl += '/api/v1'
    }
    $apiKey = [string]$env:ZN_API_KEY

    $missing = @()
    if (-not $baseUrl) { $missing += 'ZN_API_BASE_URL' }
    if (-not $apiKey) { $missing += 'ZN_API_KEY' }
    if ($missing) {
        Write-Log ERROR (
            "Missing required environment variable(s): $($missing -join ', '). " +
            'Copy .env.example to .env and fill in the values.'
        )
        exit 1
    }

    return @{ BaseUrl = $baseUrl; ApiKey = $apiKey }
}


function Resolve-ClassificationSlug {
    <#
    .SYNOPSIS
        Resolve the API classification slug from the parameters.

    .OUTPUTS
        The API slug to send, or $null if no classification change was
        requested. Exits with code 1 if -Classification/-ClassificationCategory
        names a combination not present in the lookup table.
    #>
    if ($ClassificationSlug) {
        return $ClassificationSlug
    }
    if (-not $Classification) {
        return $null
    }

    $key = "$Classification|$ClassificationCategory"
    if (-not $ClassificationSlugs.Contains($key)) {
        Write-Log ERROR (
            "No known mapping for -Classification $Classification -ClassificationCategory " +
            "$ClassificationCategory. See README for valid combinations, or pass " +
            '-ClassificationSlug directly.'
        )
        exit 1
    }
    return $ClassificationSlugs[$key]
}


function Read-AlertIds {
    <#
    .SYNOPSIS
        Read alert IDs from the CSV export's ID column.

    .OUTPUTS
        Deduplicated (order-preserving) list of non-empty alert IDs. Exits
        with code 1 if the file is missing or the ID column is absent.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Log ERROR "Input CSV not found: $Path"
        exit 1
    }

    # Parse the header row on its own (as a one-row CSV of itself) so a
    # header-only export yields zero IDs rather than a missing-column error.
    $headerLine = Get-Content -LiteralPath $Path -Encoding utf8 -TotalCount 1
    $fieldNames = @()
    if ($headerLine) {
        $fieldNames = @(("$headerLine`n$headerLine" | ConvertFrom-Csv).PSObject.Properties.Name)
    }
    if ($IdColumn -notin $fieldNames) {
        Write-Log ERROR "Input CSV is missing required column: $IdColumn"
        exit 1
    }

    $ids = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $rowNum = 1
    foreach ($row in Import-Csv -LiteralPath $Path -Encoding utf8) {
        $rowNum++
        $alertId = ([string]$row.$IdColumn).Trim()
        if (-not $alertId) {
            Write-Log WARNING "Skipping row ${rowNum}: empty $IdColumn"
            continue
        }
        if (-not $seen.Add($alertId)) {
            Write-Log WARNING "Skipping row ${rowNum}: duplicate alert ID $alertId"
            continue
        }
        $ids.Add($alertId)
    }

    Write-Log INFO "Loaded $($ids.Count) alert ID(s) from $Path"
    return , $ids.ToArray()
}


function New-SharedBody {
    <#
    .SYNOPSIS
        Build the PATCH body fields shared across every alert.

    .OUTPUTS
        Ordered hashtable of body fields to merge with each alert's "alertId".
    #>
    param(
        [AllowNull()][string]$ClassificationSlug,
        [AllowNull()][string]$AssigneeUserId
    )

    $body = [ordered]@{}
    if ($State) {
        $body['state'] = $StateSlugs[$State]
    }
    if ($ClassificationSlug) {
        $body['userAlertClassification'] = $ClassificationSlug
    }
    if ($AssigneeUserId) {
        $body['assigneeUserId'] = $AssigneeUserId
    }
    if ($BoundParams.ContainsKey('Comment')) {
        $body['comment'] = $Comment
    }
    if ($BoundParams.ContainsKey('ChangeTicket')) {
        $body['changeTicket'] = $ChangeTicket
    }
    return $body
}


function Invoke-ZnRequest {
    <#
    .SYNOPSIS
        Send one request to the Zero Networks API.

    .DESCRIPTION
        Throws on a non-2xx response with the status and response body in the
        message, and the status code stored in the exception's
        Data['StatusCode'] (used to decide whether to retry).
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body
    )

    $uri = $Client.BaseUrl + $Path
    $params = @{
        Method               = $Method
        Uri                  = $uri
        Headers              = $Client.Headers
        TimeoutSec           = 30
        SkipHttpErrorCheck   = $true
        SkipHeaderValidation = $true
        Verbose              = $false
    }
    if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Compress -Depth 10
        $params['Body'] = [Text.Encoding]::UTF8.GetBytes($json)
        $params['ContentType'] = 'application/json'
    }

    $response = Invoke-WebRequest @params
    $status = [int]$response.StatusCode
    $reason = $response.BaseResponse.ReasonPhrase
    Write-Log DEBUG "HTTP Request: $Method $uri `"$status $reason`""

    if ($status -lt 200 -or $status -ge 300) {
        $kind = if ($status -ge 500) { 'Server error' } elseif ($status -ge 400) { 'Client error' } else { 'Unexpected response' }
        $exc = [System.Exception]::new(
            "$kind '$status $reason' for url '$uri'. Response body: $($response.Content)"
        )
        $exc.Data['StatusCode'] = $status
        throw $exc
    }
    return $response
}


function Resolve-AssigneeId {
    <#
    .SYNOPSIS
        Look up a Zero Networks account by email and return its entity ID
        (e.g. "u:a:..."). Exits with code 1 if no account, or more than one
        account, matches the email.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$Email
    )

    $filters = ConvertTo-Json -Compress -Depth 5 -InputObject @(
        [ordered]@{ id = 'email'; includeValues = @($Email); excludeValues = @() }
    )
    $query = [ordered]@{
        '_limit'         = '100'
        '_offset'        = '0'
        '_search'        = ''
        'with_count'     = 'true'
        '_filters'       = $filters
        'order'          = 'asc'
        'orderColumns[]' = 'name'
        'showInactive'   = 'false'
    }
    $queryString = ($query.GetEnumerator() | ForEach-Object {
            [uri]::EscapeDataString($_.Key) + '=' + [uri]::EscapeDataString($_.Value)
        }) -join '&'

    $response = Invoke-ZnRequest -Client $Client -Method GET -Path "/users?$queryString"
    $items = @(($response.Content | ConvertFrom-Json).items)
    $matched = @($items | Where-Object { $_ -and ([string]$_.email) -eq $Email })

    if ($matched.Count -eq 0) {
        Write-Log ERROR "No account found with email: $Email"
        exit 1
    }
    if ($matched.Count -gt 1) {
        $ids = ($matched | ForEach-Object { if ($_.id) { $_.id } else { '?' } }) -join ', '
        Write-Log ERROR "Multiple accounts found with email: $Email (ids: $ids)"
        exit 1
    }

    $accountId = $matched[0].id
    Write-Log INFO "Resolved assignee $Email to account ID $accountId"
    return $accountId
}


function Test-RetryableError {
    <#
    .SYNOPSIS
        Return $true if an exception represents a transient/retryable API error.
    #>
    param([Parameter(Mandatory)][System.Exception]$Exception)

    if ($Exception.Data.Contains('StatusCode')) {
        return $Exception.Data['StatusCode'] -in $RetryStatusCodes
    }
    return (
        $Exception -is [System.Net.Http.HttpRequestException] -or
        $Exception -is [System.TimeoutException] -or
        $Exception -is [System.OperationCanceledException] -or
        $Exception -is [System.IO.IOException]
    )
}


function Invoke-AlertPatch {
    <#
    .SYNOPSIS
        Issue the PATCH request to update one alert, retrying transient
        failures with exponential backoff (1s, 2s, ... capped at 10s).
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Body
    )

    $payload = [ordered]@{ alertId = $AlertId }
    foreach ($entry in $Body.GetEnumerator()) {
        $payload[$entry.Key] = $entry.Value
    }

    for ($attempt = 1; ; $attempt++) {
        try {
            $null = Invoke-ZnRequest -Client $Client -Method PATCH -Path "/network/alerts/$AlertId" -Body $payload
            return
        }
        catch {
            $exc = $_.Exception
            if ($attempt -ge $RetryAttempts -or -not (Test-RetryableError -Exception $exc)) {
                throw $exc
            }
            $wait = [Math]::Min([Math]::Max([Math]::Pow(2, $attempt - 1), 1), 10)
            Write-Log DEBUG "Retrying alert $AlertId in ${wait}s (attempt $attempt failed: $($exc.Message))"
            Start-Sleep -Seconds $wait
        }
    }
}


function Invoke-Triage {
    <#
    .SYNOPSIS
        Triage every alert in AlertIds, at most BatchSize at a time.

    .OUTPUTS
        One result object (AlertId, Error) per alert, in input order. Error
        is $null on success, or a reason string on failure.
    #>
    param(
        [hashtable]$Client,
        [Parameter(Mandatory)][string[]]$AlertIds,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Body,
        [int]$BatchSize,
        [switch]$DryRun
    )

    if ($DryRun) {
        $bodyJson = $Body | ConvertTo-Json -Compress -Depth 10
        return @(foreach ($alertId in $AlertIds) {
                Write-Log INFO "[dry-run] Would PATCH alert $alertId with $bodyJson"
                [pscustomobject]@{ AlertId = $alertId; Error = $null }
            })
    }

    # Functions aren't visible inside -Parallel runspaces, so ship their
    # definitions across as strings and re-create them on the other side.
    $functionDefs = @{}
    foreach ($name in 'Write-Log', 'Invoke-ZnRequest', 'Test-RetryableError', 'Invoke-AlertPatch') {
        $functionDefs[$name] = (Get-Command $name -CommandType Function).Definition
    }
    $indexed = for ($i = 0; $i -lt $AlertIds.Count; $i++) {
        [pscustomobject]@{ Index = $i; AlertId = $AlertIds[$i] }
    }

    $results = $indexed | ForEach-Object -ThrottleLimit $BatchSize -Parallel {
        foreach ($def in ($using:functionDefs).GetEnumerator()) {
            Set-Item -Path "function:$($def.Key)" -Value ([scriptblock]::Create($def.Value))
        }
        $IsVerbose = $using:IsVerbose
        $RetryAttempts = $using:RetryAttempts
        $RetryStatusCodes = $using:RetryStatusCodes
        $ErrorActionPreference = 'Stop'

        $index = $_.Index
        $alertId = $_.AlertId
        try {
            Invoke-AlertPatch -Client $using:Client -AlertId $alertId -Body $using:Body
            Write-Log INFO "Triaged alert $alertId"
            [pscustomobject]@{ Index = $index; AlertId = $alertId; Error = $null }
        }
        catch {
            Write-Log ERROR "Failed to triage alert ${alertId}: $($_.Exception.Message)"
            [pscustomobject]@{ Index = $index; AlertId = $alertId; Error = $_.Exception.Message }
        }
    }

    return @($results | Sort-Object Index | Select-Object AlertId, Error)
}


function Write-Summary {
    <#
    .SYNOPSIS
        Log a console summary of the run's results.
    #>
    param([Parameter(Mandatory)][object[]]$Results)

    $failures = @($Results | Where-Object { $null -ne $_.Error })
    if ($failures) {
        Write-Log INFO "$($Results.Count - $failures.Count) alert(s) triaged successfully, $($failures.Count) failed:"
        foreach ($failure in $failures) {
            Write-Log INFO "  $($failure.AlertId): $($failure.Error)"
        }
    }
    else {
        Write-Log INFO "$($Results.Count) alert(s) triaged successfully, none failed."
    }
}


function Invoke-Main {
    <#
    .SYNOPSIS
        Orchestrate the full read -> triage -> summarize pipeline.

    .OUTPUTS
        Process exit code (0 if no alerts failed, else 1).
    #>
    Test-Arguments
    $classificationSlug = Resolve-ClassificationSlug

    $extraHeaders = @{}
    if ($CustomHeaders) {
        try {
            $extraHeaders = ConvertFrom-Json -InputObject $CustomHeaders -AsHashtable
        }
        catch {
            Write-Log ERROR "-CustomHeaders is not valid JSON: $($_.Exception.Message)"
            exit 1
        }
        if ($extraHeaders -isnot [System.Collections.IDictionary]) {
            Write-Log ERROR "-CustomHeaders must be a JSON object, e.g. '{`"key`":`"value`"}'."
            exit 1
        }
    }

    $alertIds = Read-AlertIds -Path $InputFile
    if ($alertIds.Count -eq 0) {
        Write-Log WARNING 'No alert IDs to process.'
        return 0
    }

    # A client is needed even in dry-run mode when an assignee must be resolved,
    # since that lookup is a real (read-only) API call, not part of the dry run.
    $client = $null
    if ($BoundParams.ContainsKey('AssigneeEmail') -or -not $DryRun) {
        $config = Get-Config
        $headers = @{ Authorization = $config.ApiKey }
        foreach ($entry in $extraHeaders.GetEnumerator()) {
            $headers[$entry.Key] = [string]$entry.Value
        }
        $client = @{ BaseUrl = $config.BaseUrl; Headers = $headers }
    }

    $assigneeUserId = $null
    if ($AssigneeEmail) {
        $assigneeUserId = Resolve-AssigneeId -Client $client -Email $AssigneeEmail
    }

    $body = New-SharedBody -ClassificationSlug $classificationSlug -AssigneeUserId $assigneeUserId
    $suffix = if ($DryRun) { ' (dry run)' } else { '' }
    Write-Log INFO "Triaging $($alertIds.Count) alert(s) with $($body | ConvertTo-Json -Compress -Depth 10)$suffix"

    $results = Invoke-Triage -Client $client -AlertIds $alertIds -Body $body -BatchSize $BatchSize -DryRun:$DryRun

    Write-Summary -Results $results
    if ($results | Where-Object { $null -ne $_.Error }) {
        return 1
    }
    return 0
}


exit (Invoke-Main)
