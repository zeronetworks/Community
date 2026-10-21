#Requires -Version 7.0
<#
.SYNOPSIS
    Verify the -State / -Classification slugs in ../Triage-Alerts.ps1.

.DESCRIPTION
    For each state / classification slug entry, PATCHes a single field on one
    of two dev alerts, then GETs the alert back and checks the returned
    `state` / `userAlertClassification` integer matches the expected position
    in the live `GET /network/alerts/filters` response (the API's own ground
    truth for what each integer means). Safe to re-run: it only mutates the
    two hardcoded dev alert IDs below, and every value tested is a real,
    settable state/classification.

    -AssigneeEmail is required: setting `state` to anything but `new` fails
    API-side validation ("missing assignee") unless the alert already has one,
    so this script assigns both dev alerts up front. Requires the same .env as
    ../Triage-Alerts.ps1 (ZN_API_BASE_URL, ZN_API_KEY) - looked up
    automatically from the repo root regardless of the current working
    directory.

.PARAMETER AssigneeEmail
    Email of the account to assign the dev alerts to before testing state
    transitions.

.PARAMETER CustomHeaders
    JSON-encoded object of extra headers, e.g. '{"zn-env-id":"..."}'.

.EXAMPLE
    ./tests/Verify-Slugs.ps1 -AssigneeEmail you@example.com -CustomHeaders '{"zn-env-id":"..."}'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AssigneeEmail,

    [string]$CustomHeaders
)

$ErrorActionPreference = 'Stop'

# Same dev alerts used throughout this repo's manual testing.
$DevAlertIds = @('n:d:C7ZCfAa1', 'n:d:PeFaX0vK')

# CLI value -> (API slug, expected `state` int from /network/alerts/filters).
$StateSlugs = [ordered]@{
    'in-progress' = @('in_progress', 2)
    'closed'      = @('closed', 3)
    'reopened'    = @('reopened', 4)
}

# "<classification>|<category>" -> (API slug, expected
# `userAlertClassification` int - its 1-indexed position in the filters
# "classification" selections list).
$ClassificationSlugs = [ordered]@{
    'true-positive|multi-staged-attack'          = @('multi_staged_attack', 1)
    'true-positive|malware'                      = @('malware', 2)
    'true-positive|malicious-user-activity'      = @('malicious_user_activity', 3)
    'true-positive|unwanted-software'            = @('unwanted_software', 4)
    'true-positive|phishing'                     = @('phishing', 5)
    'true-positive|compromised-account'          = @('compromised_account', 6)
    'true-positive|other'                        = @('true_positive_other', 7)
    'informational|security-testing'             = @('security_testing', 8)
    'informational|confirmed-activity'           = @('confirmed_activity', 9)
    'informational|line-of-business-application' = @('line_of_business_application', 10)
    'informational|other'                        = @('informational_other', 11)
    'false-positive|not-malicious'               = @('not_malicious', 12)
    'false-positive|not-enough-data'             = @('not_enough_data', 13)
    'false-positive|other'                       = @('false_positive_other', 14)
}


function Import-DotEnv {
    <# Same .env loader as Triage-Alerts.ps1: nearest .env walking up from StartDirectory. #>
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
            $quote = $value[0]
            $value = $value.Substring(1, $value.IndexOf($quote, 1) - 1)
            if ($quote -eq '"') {
                $value = $value -replace '\\n', "`n" -replace '\\"', '"'
            }
        }
        else {
            $value = ($value -replace '\s+#.*$', '').Trim()
        }

        if ($null -eq [Environment]::GetEnvironmentVariable($key)) {
            [Environment]::SetEnvironmentVariable($key, $value)
        }
    }
}


function Get-Config {
    Import-DotEnv -StartDirectory $PSScriptRoot
    $baseUrl = ([string]$env:ZN_API_BASE_URL).TrimEnd('/')
    $apiKey = [string]$env:ZN_API_KEY
    if (-not $baseUrl -or -not $apiKey) {
        [Console]::Error.WriteLine(
            'Missing ZN_API_BASE_URL / ZN_API_KEY - copy .env.example to .env and fill in.'
        )
        exit 1
    }
    return @{ BaseUrl = "$baseUrl/api/v1"; ApiKey = $apiKey }
}


function Invoke-ZnRaw {
    <# Send one request and return the raw response, whatever its status. #>
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body
    )
    $params = @{
        Method               = $Method
        Uri                  = $Client.BaseUrl + $Path
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
    return Invoke-WebRequest @params
}


function Assert-Success {
    <# Throw with the status and response body if the response isn't 2xx. #>
    param([Parameter(Mandatory)]$Response)
    $status = [int]$Response.StatusCode
    if ($status -lt 200 -or $status -ge 300) {
        $uri = $Response.BaseResponse.RequestMessage.RequestUri
        throw "HTTP $status $($Response.BaseResponse.ReasonPhrase) for url '$uri'. Response body: $($Response.Content)"
    }
}


function Test-NoFieldsToUpdate {
    <# True if a PATCH was a no-op because the alert already had that value. #>
    param([Parameter(Mandatory)]$Response)
    return [int]$Response.StatusCode -eq 400 -and ([string]$Response.Content).Contains('no fields to update')
}


function Resolve-AssigneeId {
    <# Same lookup as Triage-Alerts.ps1's Resolve-AssigneeId: GET /users filtered by email. #>
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

    $response = Invoke-ZnRaw -Client $Client -Method GET -Path "/users?$queryString"
    Assert-Success $response
    $items = @(($response.Content | ConvertFrom-Json).items)
    $matched = @($items | Where-Object { $_ -and ([string]$_.email) -eq $Email })
    if ($matched.Count -eq 0) {
        [Console]::Error.WriteLine("No account found with email: $Email")
        exit 1
    }
    return $matched[0].id
}


function Set-Assignee {
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][string]$AssigneeUserId
    )
    $response = Invoke-ZnRaw -Client $Client -Method PATCH -Path "/network/alerts/$AlertId" `
        -Body ([ordered]@{ alertId = $AlertId; assigneeUserId = $AssigneeUserId })
    Assert-Success $response
}


function Get-FiltersGroundTruth {
    <# Return @{ state = @{1 = 'New'; ...}; classification = @{1 = '...'; ...} }. #>
    param([Parameter(Mandatory)][hashtable]$Client)
    $response = Invoke-ZnRaw -Client $Client -Method GET -Path '/network/alerts/filters'
    Assert-Success $response
    $truth = @{}
    foreach ($filter in ($response.Content | ConvertFrom-Json).filters) {
        if ($filter.id -in 'state', 'classification') {
            $labels = @{}
            foreach ($selection in $filter.selections) {
                $labels[[int]$selection.id] = $selection.name
            }
            $truth[$filter.id] = $labels
        }
    }
    return $truth
}


function Get-AlertField {
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][string]$Field
    )
    $response = Invoke-ZnRaw -Client $Client -Method GET -Path "/network/alerts/$AlertId"
    Assert-Success $response
    return ($response.Content | ConvertFrom-Json).alert.$Field
}


function Test-State {
    # `state` is a workflow, not a free-form field - e.g. an alert can only be
    # "reopened" after it's been "closed". Callers must run these in the
    # natural pipeline order (in-progress -> closed -> reopened) on the same
    # alert rather than jumping to an arbitrary state.
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][string]$CliValue,
        [Parameter(Mandatory)][string]$Slug
    )
    $body = [ordered]@{ alertId = $AlertId; state = $Slug }
    if ($Slug -eq 'closed') {
        # Closing is rejected unless a classification (and its comment) is sent too.
        $body['userAlertClassification'] = 'not_malicious'
        $body['comment'] = "Verify-Slugs.ps1: $Slug"
    }
    $response = Invoke-ZnRaw -Client $Client -Method PATCH -Path "/network/alerts/$AlertId" -Body $body
    if (-not (Test-NoFieldsToUpdate $response)) {
        Assert-Success $response
    }
    $returnedId = Get-AlertField -Client $Client -AlertId $AlertId -Field 'state'
    return [ordered]@{ kind = 'state'; cli = $CliValue; slug = $Slug; returned_id = $returnedId }
}


function Test-Classification {
    param(
        [Parameter(Mandatory)][hashtable]$Client,
        [Parameter(Mandatory)][string]$AlertId,
        [Parameter(Mandatory)][string]$CliValue,
        [Parameter(Mandatory)][string]$Slug
    )
    # A classification change apparently requires a non-empty comment.
    $response = Invoke-ZnRaw -Client $Client -Method PATCH -Path "/network/alerts/$AlertId" -Body ([ordered]@{
            alertId                 = $AlertId
            userAlertClassification = $Slug
            comment                 = "Verify-Slugs.ps1: $Slug"
        })
    if (-not (Test-NoFieldsToUpdate $response)) {
        Assert-Success $response
    }
    $returnedId = Get-AlertField -Client $Client -AlertId $AlertId -Field 'userAlertClassification'
    return [ordered]@{ kind = 'classification'; cli = $CliValue; slug = $Slug; returned_id = $returnedId }
}


function Invoke-Main {
    $config = Get-Config
    $headers = @{ Authorization = $config.ApiKey }
    if ($CustomHeaders) {
        foreach ($entry in (ConvertFrom-Json -InputObject $CustomHeaders -AsHashtable).GetEnumerator()) {
            $headers[$entry.Key] = [string]$entry.Value
        }
    }
    $client = @{ BaseUrl = $config.BaseUrl; Headers = $headers }

    $assigneeUserId = Resolve-AssigneeId -Client $client -Email $AssigneeEmail
    foreach ($alertId in $DevAlertIds) {
        Set-Assignee -Client $client -AlertId $alertId -AssigneeUserId $assigneeUserId
    }

    $groundTruth = Get-FiltersGroundTruth -Client $client
    $results = [System.Collections.Generic.List[object]]::new()

    # State is a workflow (in-progress -> closed -> reopened), so all three
    # must be walked in order on a single alert rather than jumping to an
    # arbitrary target state on a fresh alert each time.
    $stateAlertId = $DevAlertIds[0]
    foreach ($entry in $StateSlugs.GetEnumerator()) {
        $slug, $expectedId = $entry.Value
        $result = Test-State -Client $client -AlertId $stateAlertId -CliValue $entry.Key -Slug $slug
        $result['expected_id'] = $expectedId
        $results.Add($result)
    }

    $i = 0
    foreach ($entry in $ClassificationSlugs.GetEnumerator()) {
        $slug, $expectedId = $entry.Value
        $alertId = $DevAlertIds[$i % $DevAlertIds.Count]
        $i++
        $cli = $entry.Key -replace '\|', '/'
        $result = Test-Classification -Client $client -AlertId $alertId -CliValue $cli -Slug $slug
        $result['expected_id'] = $expectedId
        $results.Add($result)
    }

    $okCount = 0
    $row = '{0,-14} {1,-45} {2,-30} {3,8} {4,8} {5,-45} {6}'
    Write-Host ($row -f 'kind', 'cli', 'slug', 'returned', 'expected', 'label', 'status')
    foreach ($r in $results) {
        $labelMap = $groundTruth[$r.kind]
        $label = if ($labelMap -and $labelMap.ContainsKey([int]$r.returned_id)) {
            $labelMap[[int]$r.returned_id]
        }
        else {
            "<unknown id $($r.returned_id)>"
        }
        $status = if ($r.returned_id -eq $r.expected_id) { 'OK' } else { 'MISMATCH' }
        if ($status -eq 'OK') { $okCount++ }
        Write-Host ($row -f $r.kind, $r.cli, $r.slug, $r.returned_id, $r.expected_id, $label, $status)
    }

    Write-Host "`n$okCount/$($results.Count) confirmed."
    if ($okCount -eq $results.Count) {
        return 0
    }
    return 1
}


$exitCode = Invoke-Main
exit $exitCode
