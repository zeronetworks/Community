#Requires -Module ZeroNetworks
<#
.SYNOPSIS
    Find common AD groups shared by source users that accessed a specific destination.

.DESCRIPTION
    Queries Zero Networks network activities for a destination asset (by IP or FQDN),
    collects distinct source users, retrieves all their group memberships via the ZN
    module, and reports every group shared by at least MinUserCount of those users.
    Output is a CSV with one row per qualifying group.

    AUTHENTICATION (required before running):
    The script uses the API key stored in the $env:ZNApiKey environment variable.
    Set it using either of:
      * Set-ZNApiKey -ApiKey '<api-key>'   - stores the key in $env:ZNApiKey for the session.
      * Connect-ZN -Email '<you@org>'       - interactive OTP login that populates $env:ZNApiKey.
      * Or set the variable directly:  $env:ZNApiKey = '<api-key>'
    If $env:ZNApiKey is not set, the script stops with an authentication error.

.PARAMETER DestinationFQDN
    FQDN of the destination asset (mutually exclusive with DestinationIP).

.PARAMETER DestinationIP
    IPv4 address of the destination asset (mutually exclusive with DestinationFQDN).

.PARAMETER MinUserCount
    Minimum number of source users that must share a group for it to appear in the
    report. Default: 2.

.PARAMETER FromDays
    How many days back to search for activities. Default: 30.

.PARAMETER OutputPath
    Full path for the output CSV file. If omitted, a timestamped file is created in
    the current directory.

.PARAMETER IncludeSourceUsers
    Off by default. When specified, adds a 'SourceUsers' column listing the member
    names in each group. Omitted by default because it becomes very noisy when groups
    contain thousands of users; the 'SourceUserCount' column is always present.

.PARAMETER MaxParallel
    Max concurrent group-membership lookups (1-16, default 8). Parallelism is used on
    PowerShell 7+; on Windows PowerShell 5.1 lookups run sequentially regardless.
    Lower this if the tenant returns HTTP 429 (rate limiting). All API calls already
    retry with exponential backoff.

.EXAMPLE
    .\Find-CommonGroupsForDestination.ps1 -DestinationFQDN "fileserver.corp.local" -MinUserCount 3 -FromDays 7

.EXAMPLE
    .\Find-CommonGroupsForDestination.ps1 -DestinationIP "10.10.0.50" -MinUserCount 2 -OutputPath "C:\Reports\groups.csv"
#>

[CmdletBinding(DefaultParameterSetName = 'Help')]
param(
    [Parameter(Mandatory, ParameterSetName = 'FQDN')]
    [string]$DestinationFQDN,

    [Parameter(Mandatory, ParameterSetName = 'IP')]
    [string]$DestinationIP,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MinUserCount = 2,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$FromDays = 30,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludeSourceUsers,

    [Parameter()]
    [ValidateRange(1, 16)]
    [int]$MaxParallel = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 0. No destination supplied -> show usage instead of a parameter-set error.
# ---------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Help') {
    Write-Host @"

Find-CommonGroupsForDestination.ps1
  Finds AD groups shared by the source users that accessed a given destination,
  and writes the common groups (>= a threshold) to a CSV.

USAGE
  .\Find-CommonGroupsForDestination.ps1 -DestinationFQDN <fqdn> [options]
  .\Find-CommonGroupsForDestination.ps1 -DestinationIP   <ip>   [options]

REQUIRED (choose one)
  -DestinationFQDN <string>   FQDN of the destination (managed asset or external domain).
  -DestinationIP   <string>   IPv4 address of the destination.

OPTIONS
  -MinUserCount <int>   Min source users sharing a group to report it.  Default: 2
  -FromDays     <int>   Days of activity history to scan (1-365).        Default: 30
  -OutputPath   <string> CSV output path.  Default: .\CommonGroups_<dest>_<timestamp>.csv
  -IncludeSourceUsers   Add a 'SourceUsers' column listing member names.  Default: off (noisy at scale)

PREREQUISITE (authentication required)
  The script reads the API key from `$env:ZNApiKey`. Set it first using either:
    Set-ZNApiKey -ApiKey '<api-key>'      # stores key in `$env:ZNApiKey` for the session
    Connect-ZN -Email '<you@org>'         # interactive OTP login, populates `$env:ZNApiKey`
    `$env:ZNApiKey = '<api-key>'           # or set the env var directly

EXAMPLES
  .\Find-CommonGroupsForDestination.ps1 -DestinationFQDN "fileserver.corp.local" -MinUserCount 3 -FromDays 7
  .\Find-CommonGroupsForDestination.ps1 -DestinationIP "10.10.0.50"

  For full help:  Get-Help .\Find-CommonGroupsForDestination.ps1 -Full

"@ -ForegroundColor Cyan
    return
}

# Make -Debug non-interactive (default behaviour would prompt on every Write-Debug).
if ($PSBoundParameters.ContainsKey('Debug')) { $DebugPreference = 'Continue' }

# Safe accessor for optional JSON properties (StrictMode throws on missing ones).
function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# Run a scriptblock with retry + exponential backoff on transient API failures
# (HTTP 429 / 5xx and transport-level errors). Non-transient errors (e.g. 400/401/
# 403/404) are rethrown immediately. Honors a Retry-After header when present.
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$Description = 'API call',
        [int]$MaxAttempts = 4,
        [int]$BaseDelayMs = 1000
    )
    for ($attempt = 1; ; $attempt++) {
        try {
            return & $Action
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            $transient = ($status -in 429, 500, 502, 503, 504) -or ($null -eq $status)
            if (-not $transient -or $attempt -ge $MaxAttempts) { throw }

            $delayMs = $BaseDelayMs * [math]::Pow(2, $attempt - 1)
            try {
                $ra = $_.Exception.Response.Headers.RetryAfter.Delta.TotalMilliseconds
                if ($ra) { $delayMs = [math]::Max($delayMs, $ra) }
            } catch {}
            $delayMs = [int]($delayMs + (Get-Random -Minimum 0 -Maximum 250))   # jitter
            Write-Verbose "$Description failed (attempt $attempt/$MaxAttempts, status=$status); retrying in $delayMs ms."
            Start-Sleep -Milliseconds $delayMs
        }
    }
}

# ---------------------------------------------------------------------------
# 1. Validate authentication
# ---------------------------------------------------------------------------
if (-not $env:ZNApiKey) {
    throw "Not authenticated: `$env:ZNApiKey is not set. Run  Set-ZNApiKey -ApiKey '<key>'  or  Connect-ZN  (or set `$env:ZNApiKey directly) before running this script."
}

$accountName = (Read-ZNJWTtoken $env:ZNApiKey).aud.split('.')[0]
$baseUrl     = "https://$accountName.zeronetworks.com/api/v1"
$headers     = @{ Authorization = $env:ZNApiKey }
Write-Verbose "Authenticated to account '$accountName' (base URL: $baseUrl)."

$epoch = [datetime]'1970-01-01T00:00:00Z'
$fromEpochMs = [int64][math]::Floor(((Get-Date).AddDays(-$FromDays).ToUniversalTime() - $epoch).TotalMilliseconds)
$toEpochMs   = [int64][math]::Floor(((Get-Date).ToUniversalTime() - $epoch).TotalMilliseconds)
Write-Verbose ("Time window: {0:u} .. {1:u} ({2} days)" -f (Get-Date).AddDays(-$FromDays).ToUniversalTime(), (Get-Date).ToUniversalTime(), $FromDays)
Write-Debug   "Epoch window (ms): from=$fromEpochMs to=$toEpochMs"

if (-not $OutputPath) {
    $slug = if ($DestinationFQDN) {
        $DestinationFQDN -replace '[^\w.]', '_'
    } else {
        $DestinationIP -replace '\.', '_'
    }
    $OutputPath = ".\CommonGroups_${slug}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
}
Write-Verbose "Output CSV path: $OutputPath"

# ---------------------------------------------------------------------------
# 2. Build the server-side destination filter
#
#    The /activities/network feed is global; we scope it with the `_filters`
#    query parameter (a JSON array of {id, includeValues}). The `dstAsset`
#    filter does a partial match on the destination asset name OR external
#    domain, so it covers both managed assets and internet FQDNs; `dstIpAddress`
#    matches an exact IP or CIDR. Because dstAsset is a partial match, we keep a
#    light exact post-filter on the nested `dst` object for precision.
# ---------------------------------------------------------------------------
$destLabel = if ($DestinationFQDN) { $DestinationFQDN } else { $DestinationIP }
Write-Host "Destination: $destLabel" -ForegroundColor Cyan

if ($PSCmdlet.ParameterSetName -eq 'FQDN') {
    $filterId   = 'dstAsset'
    $filterVal  = $DestinationFQDN
    $dstMatches = { param($dst) (Get-Prop $dst 'fqdn') -eq $DestinationFQDN }
} else {
    $filterId   = 'dstIpAddress'
    $filterVal  = $DestinationIP
    $dstMatches = { param($dst) (Get-Prop $dst 'ip') -eq $DestinationIP }
}

$filtersJson = ConvertTo-Json @([ordered]@{ id = $filterId; includeValues = @($filterVal) }) -Depth 5 -Compress
$filtersEnc  = [uri]::EscapeDataString($filtersJson)
Write-Host "  Filter: $filtersJson" -ForegroundColor DarkGray
Write-Host "  Searching last $FromDays days of network activities..." -ForegroundColor DarkGray
Write-Verbose "Destination filter id='$filterId', value='$filterVal'."
Write-Debug   "Encoded _filters: $filtersEnc"

# ---------------------------------------------------------------------------
# 3. Collect the distinct source users that reached the destination.
#
#    Primary path: the distinctField endpoint returns the de-duplicated list of
#    source users (with per-user hit counts) for the destination filter in ONE
#    call -- far cheaper than paging every activity record (which can be tens of
#    thousands of rows on a busy destination). If that endpoint is unavailable
#    (older tenant), we fall back to paging /activities/network.
#
#    distinctField returns only the userName (DOMAIN\user); activity records
#    also carry the SID. Either way we resolve to a ZN user id in step 4.
# ---------------------------------------------------------------------------
$sourceUsers = [ordered]@{}   # key -> @{ Sid; Name; Count }

function Add-SourceUser {
    param([string]$Sid, [string]$Name, [int]$Count = 0)
    if (-not $Name -and -not $Sid) { return }
    $key = if ($Sid) { "sid:$Sid" } else { "name:$($Name.ToLowerInvariant())" }
    if (-not $sourceUsers.Contains($key)) {
        $sourceUsers[$key] = @{ Sid = $Sid; Name = $Name; Count = $Count }
    }
}

$usedDistinctField = $false
$distinctUrl = "$baseUrl/activities/network/distinctField/srcUser?from=$fromEpochMs&to=$toEpochMs&_filters=$filtersEnc"
Write-Debug "GET $distinctUrl"
try {
    $df    = Invoke-WithRetry -Description 'distinctField/srcUser' -Action {
        Invoke-RestMethod -Uri $distinctUrl -Headers $headers -Verbose:$false -Debug:$false
    }
    $aggs  = @(Get-Prop (Get-Prop $df 'items') 'aggregations')
    foreach ($a in $aggs) {
        $nm = Get-Prop $a 'name'
        if (-not $nm -or $nm -eq 'Unknown') { continue }
        Add-SourceUser -Name $nm -Count ([int](Get-Prop $a 'count'))
        Write-Debug "distinct srcUser: '$nm' (count=$(Get-Prop $a 'count'))"
    }
    $usedDistinctField = $true
    Write-Host "  Distinct source users (summarized): $($sourceUsers.Count)" -ForegroundColor DarkGray
    Write-Verbose "Used distinctField/srcUser endpoint: 1 call, $($aggs.Count) raw values -> $($sourceUsers.Count) distinct."
} catch {
    Write-Verbose "distinctField endpoint unavailable ($($_.Exception.Message)); falling back to full activity scan."
}

if (-not $usedDistinctField) {
    # Fallback: page the full activity feed and dedupe source users client-side.
    $cursor = $null; $pageSize = 400; $actUrl = "$baseUrl/activities/network"
    $totalFetched = 0; $matchedCount = 0; $pageNum = 0
    do {
        $pageNum++
        $query = "?_limit=$pageSize&from=$fromEpochMs&to=$toEpochMs&_filters=$filtersEnc"
        if ($cursor) { $query += "&_cursor=$cursor" }
        Write-Debug "GET $actUrl$query"
        try {
            $page = Invoke-WithRetry -Description "activities page $pageNum" -Action {
                Invoke-RestMethod -Uri "$actUrl$query" -Headers $headers -Verbose:$false -Debug:$false
            }
        } catch {
            Write-Warning "Activities API call failed after retries: $_"
            break
        }
        $items = @($page.items)
        $totalFetched += $items.Count
        foreach ($act in $items) {
            # Server already filtered by destination; confirm exact dst match.
            if (-not (& $dstMatches (Get-Prop $act 'dst'))) { continue }
            $matchedCount++
            $src = Get-Prop $act 'src'
            $sid = Get-Prop $src 'userId'
            if ($sid) { Add-SourceUser -Sid $sid -Name (Get-Prop $src 'userName') }
        }
        $cursor = $page.scrollCursor
        Write-Progress -Activity "Scanning network activities for $destLabel" `
                       -Status ("Page $pageNum | scanned $totalFetched | $($sourceUsers.Count) distinct source users")
        Write-Verbose ("Page {0}: scanned={1} matched={2} distinctUsers={3}" -f $pageNum, $totalFetched, $matchedCount, $sourceUsers.Count)
    } while ($items.Count -eq $pageSize -and $cursor)
    Write-Progress -Activity "Scanning network activities for $destLabel" -Completed
    Write-Host "  Total activities scanned   : $totalFetched" -ForegroundColor DarkGray
    Write-Host "  Distinct source users      : $($sourceUsers.Count)" -ForegroundColor DarkGray
}

if ($sourceUsers.Count -eq 0) {
    Write-Warning "No source users found for '$destLabel' in the last $FromDays days."
    return
}

# ---------------------------------------------------------------------------
# 3b. Build a SID/PrincipalName -> ZN user lookup from the directory
#
#    Activity SIDs do not always match user.Sid (e.g. Entra synthetic SIDs),
#    so we resolve by SID first, then fall back to src.userName == PrincipalName.
# ---------------------------------------------------------------------------
Write-Host "`nBuilding user directory map..." -ForegroundColor Cyan

$bySid = @{}; $byPrincipal = @{}
$offset = 0
do {
    Write-Debug "Get-ZNUser -Limit 400 -Offset $offset"
    $offsetLocal = $offset
    $uPage = Invoke-WithRetry -Description "Get-ZNUser offset $offsetLocal" -Action {
        Get-ZNUser -Limit 400 -Offset $offsetLocal -Verbose:$false -Debug:$false
    }
    $uItems = @($uPage.Items)
    foreach ($u in $uItems) {
        if ($u.Sid)           { $bySid[$u.Sid] = $u }
        if ($u.PrincipalName) { $byPrincipal[$u.PrincipalName.ToLowerInvariant()] = $u }
    }
    $offset += $uItems.Count
    Write-Verbose "Directory page fetched: $($uItems.Count) users (total indexed: $offset)."
} while ($uItems.Count -eq 400)

Write-Host "  Directory users indexed    : $($bySid.Count) by SID, $($byPrincipal.Count) by principal name" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# 4a. Resolve each distinct source user to a unique ZN user id.
#     (SID first, then userName == PrincipalName; dedupe by ZN id.)
# ---------------------------------------------------------------------------
Write-Host "`nResolving users..." -ForegroundColor Cyan

$resolvedUsers = [System.Collections.Generic.List[object]]::new()  # @{ Id; Name }
$unresolved    = [System.Collections.Generic.List[string]]::new()
$processedIds  = [System.Collections.Generic.HashSet[string]]::new()

foreach ($kvp in $sourceUsers.GetEnumerator()) {
    $src      = $kvp.Value
    $userName = if ($src.Name) { $src.Name } else { $src.Sid }

    $znUser = $null; $resolvedVia = $null
    if ($src.Sid -and $bySid.ContainsKey($src.Sid)) {
        $znUser = $bySid[$src.Sid]; $resolvedVia = 'SID'
    } elseif ($src.Name -and $byPrincipal.ContainsKey($src.Name.ToLowerInvariant())) {
        $znUser = $byPrincipal[$src.Name.ToLowerInvariant()]; $resolvedVia = 'PrincipalName'
    }

    if (-not $znUser) {
        # Typically well-known/system/machine accounts (SYSTEM, LOCAL SERVICE, *$) - no AD groups.
        $unresolved.Add($userName)
        Write-Verbose "Unresolved source user '$userName' (sid='$($src.Sid)') - skipped."
        continue
    }
    # Case-variant userNames / multiple SIDs can map to one ZN user; count once.
    if (-not $processedIds.Add($znUser.Id)) {
        Write-Debug "Duplicate -> ZN user $($znUser.Id) already processed; skipping '$userName'."
        continue
    }
    $resolvedUsers.Add([pscustomobject]@{ Id = $znUser.Id; Name = $znUser.Name })
    Write-Debug "Resolved '$userName' via $resolvedVia -> ZN user $($znUser.Id)"
}

Write-Host "  Source users resolved      : $($resolvedUsers.Count) / $($sourceUsers.Count)" -ForegroundColor DarkGray
if ($unresolved.Count -gt 0) {
    Write-Host "  Unresolved (skipped)       : $($unresolved.Count) (e.g. $((($unresolved | Select-Object -First 3) -join ', ')))" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 4b. Retrieve each resolved user's group memberships.
#     Parallel on PowerShell 7+ (capped by -MaxParallel); sequential on 5.1.
#     Each call is retry-wrapped. Returns @{ Name; Groups }.
# ---------------------------------------------------------------------------
Write-Host "Retrieving group memberships for $($resolvedUsers.Count) user(s)..." -ForegroundColor Cyan

# Parallelism only pays off once there are enough users to amortize runspace
# startup cost; below the threshold, sequential is faster. Tune via -MaxParallel.
$parallelThreshold = 20
$useParallel = ($PSVersionTable.PSVersion.Major -ge 7) -and ($MaxParallel -gt 1) -and ($resolvedUsers.Count -ge $parallelThreshold)
Write-Verbose ("Membership lookup mode: {0} ({1} users, PS {2})." -f `
    $(if ($useParallel) {"parallel, throttle $MaxParallel"} else {"sequential (< $parallelThreshold users or PS<7 or -MaxParallel 1)"}), `
    $resolvedUsers.Count, $PSVersionTable.PSVersion)

if ($useParallel) {
    # Call the REST endpoint that Get-ZNUserMemberOf wraps (GET /users/{id}/ancestors)
    # directly, so parallel runspaces do NOT each pay the (heavy) Import-Module cost.
    $apiKey = $env:ZNApiKey
    $base   = $baseUrl
    $membershipResults = $resolvedUsers | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
        $u   = $_
        $hdr = @{ Authorization = $using:apiKey }
        $uri = "$using:base/users/$($u.Id)/ancestors"
        $groups = $null
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            try {
                $groups = (Invoke-RestMethod -Uri $uri -Headers $hdr -Verbose:$false).items
                break
            } catch {
                $status = $null; try { $status = [int]$_.Exception.Response.StatusCode } catch {}
                $transient = ($status -in 429,500,502,503,504) -or ($null -eq $status)
                if (-not $transient -or $attempt -eq 4) {
                    Write-Warning "  Could not retrieve groups for $($u.Name) ($($u.Id)): $_"
                    break
                }
                Start-Sleep -Milliseconds ([int](1000 * [math]::Pow(2, $attempt-1) + (Get-Random -Maximum 250)))
            }
        }
        [pscustomobject]@{ Name = $u.Name; Groups = @($groups) }
    }
} else {
    $membershipResults = foreach ($u in $resolvedUsers) {
        $groups = $null
        try {
            $groups = Invoke-WithRetry -Description "Get-ZNUserMemberOf $($u.Id)" -Action {
                (Get-ZNUserMemberOf -UserId $u.Id -Verbose:$false -Debug:$false).Items
            }
        } catch {
            Write-Warning "  Could not retrieve groups for $($u.Name) ($($u.Id)): $_"
        }
        Write-Verbose "User '$($u.Name)' ($($u.Id)) is a member of $(@($groups).Count) group(s)."
        [pscustomobject]@{ Name = $u.Name; Groups = @($groups) }
    }
}

# ---------------------------------------------------------------------------
# 4c. Merge memberships into the group -> users map (sequential; no races).
# ---------------------------------------------------------------------------
# groupId -> @{ Name; Id; Users (list of display names) }
$groupUserMap = [ordered]@{}
foreach ($res in $membershipResults) {
    foreach ($g in $res.Groups) {
        if (-not $g) { continue }
        $gid = $g.Id
        if (-not $groupUserMap.Contains($gid)) {
            $groupUserMap[$gid] = @{
                Name  = $g.Name
                Id    = $gid
                Users = [System.Collections.Generic.List[string]]::new()
            }
        }
        $groupUserMap[$gid].Users.Add($res.Name)
    }
}

# ---------------------------------------------------------------------------
# 5. Filter groups by threshold and build report
# ---------------------------------------------------------------------------
Write-Verbose "Distinct groups seen across resolved users: $($groupUserMap.Count). Applying threshold >= $MinUserCount."

$qualifying = $groupUserMap.Values |
    Where-Object { $_.Users.Count -ge $MinUserCount } |
    Sort-Object { $_.Users.Count } -Descending

if ($qualifying.Count -eq 0) {
    Write-Warning "No groups found with $MinUserCount or more source users. Try lowering -MinUserCount."
    return
}

Write-Host "`n$($qualifying.Count) group(s) with >= $MinUserCount source users." -ForegroundColor Green

if ($IncludeSourceUsers) {
    Write-Verbose "Including 'SourceUsers' column (member names) in output."
} else {
    Write-Verbose "Omitting member names; use -IncludeSourceUsers to add the 'SourceUsers' column."
}

$csvRows = foreach ($g in $qualifying) {
    $row = [ordered]@{
        GroupName       = $g.Name
        GroupId         = $g.Id
        SourceUserCount = $g.Users.Count
    }
    if ($IncludeSourceUsers) {
        $row.SourceUsers = ($g.Users | Sort-Object) -join '; '
    }
    $row.Destination  = $destLabel
    $row.LookbackDays = $FromDays
    [PSCustomObject]$row
}

$csvRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Verbose "Wrote $($csvRows.Count) row(s) to $OutputPath."

Write-Host "Report saved  : $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "=== Top 10 Common Groups ===" -ForegroundColor Cyan
$topCols = if ($IncludeSourceUsers) { 'GroupName','SourceUserCount','SourceUsers' } else { 'GroupName','SourceUserCount' }
$csvRows | Select-Object -First 10 | Format-Table $topCols -AutoSize -Wrap
