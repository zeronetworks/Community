#Requires -Version 7

<#
.SYNOPSIS
    Automatically deactivates breakglass on Zero Networks assets after a configurable grace period.

.DESCRIPTION
    Queries the Zero Networks assets endpoint for devices currently in breakglass, then looks up
    their most recent breakglass activation audit record. Assets whose activation is older than
    the specified grace period are deactivated (or reported if -DryRun). Designed for fully
    unattended scheduled execution.

    TimePeriod is a minimum breakglass duration - assets activated MORE THAN 
    that long ago are eligible for deactivation. Ignores breakglass events by 
    the Zero Networks Admins by default. Assets activated within the grace 
    period are left untouched. Run this on a schedule (e.g., every hour) so that each run picks
    up activations that have just passed their grace period.

    All activity is written as CEF (Common Event Format) log entries to a configurable file.
    Console output mirrors the log at the same level. Default log level is Information.

    AUDIT TYPE CODES
    $BREAKGLASS_ACTIVATE_TYPES lists the auditType codes that indicate a breakglass activation.
    Override with -BreakglassActivateTypes if your tenant uses different codes.


.PARAMETER TimePeriod
    Grace period - breakglass activations older than this will be deactivated.
    Format: <number><unit> - m (minutes), h (hours), d (days), w (weeks).
    Examples: 30m, 4h, 1d, 2w

.PARAMETER ApiKey
    Zero Networks API key (JWT). Defaults to the ZN_API_KEY environment variable.

.PARAMETER LogFile
    Path to the CEF log output file.
    Defaults to <script-directory>\Reset-Breakglass.log.

.PARAMETER LogLevel
    Minimum severity to log and display: Debug | Information (default) | Warning | Error.

.PARAMETER DryRun
    Reports what would be deactivated without calling the deactivation API.

.PARAMETER ExcludeGroupIds
    One or more group asset IDs whose members are exempt from auto-deactivation.
    Breakglass activated by a member of any listed group will be skipped.
    Group IDs take the form g:s:XXXXXXXX - find them in the ZN portal.
    You can also hardcode groups in $BREAKGLASS_EXCLUDE_GROUPS.

.PARAMETER DisableGroupExclusion
    Skips all group-based exclusion, including the default "Zero Networks Admins" exemption
    ($BREAKGLASS_EXCLUDE_GROUP_NAMES), $BREAKGLASS_EXCLUDE_GROUPS, and -ExcludeGroupIds.
    Every eligible breakglass activation is deactivated regardless of who activated it.

.PARAMETER BreakglassActivateTypes
    One or more auditType codes that indicate a breakglass activation event.
    Defaults to 132.

.EXAMPLE
    .\Reset-Breakglass.ps1 -TimePeriod 4h
    Deactivates breakglass on assets where it has been active for more than 4 hours.

.EXAMPLE
    .\Reset-Breakglass.ps1 -TimePeriod 1d -DryRun
    Shows what would be deactivated without making changes. Assets activated within the
    last 24 hours are left untouched.

.EXAMPLE
    .\Reset-Breakglass.ps1 -TimePeriod 8h -LogLevel Debug -LogFile "C:\Logs\bg-reset.log"
    Runs with full debug logging to a custom path.

.EXAMPLE
    .\Reset-Breakglass.ps1 -TimePeriod 1m -LogLevel Debug -DryRun -BreakglassActivateTypes 132
    Use a very short grace period the first time to confirm audit type codes.

.EXAMPLE
    .\Reset-Breakglass.ps1 -TimePeriod 4h -DisableGroupExclusion
    Deactivates breakglass on all eligible assets, including activations by
    members of the default-excluded "Zero Networks Admins" group.

.EXAMPLE
    # One-time setup: register a Windows Scheduled Task that runs this script every hour
    # with a 4-hour grace period, unattended, as SYSTEM. Run this block once from an
    # elevated PowerShell prompt.

    # Step 1 - store the API key where SYSTEM can read it.
    # The task below runs as SYSTEM, which has no user profile of its own, so a
    # User-scoped environment variable would never be visible to it. Machine scope is
    # readable by SYSTEM and by every user on the box, so only run this on a host where
    # that's an acceptable exposure - anyone with local admin can read it back out with
    # [Environment]::GetEnvironmentVariable('ZN_API_KEY','Machine').
    [Environment]::SetEnvironmentVariable('ZN_API_KEY', '<your-api-key>', 'Machine')

    # Step 2 - register the task.
    $action    = New-ScheduledTaskAction -Execute 'pwsh.exe' `
        -Argument '-NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\Reset-Breakglass.ps1" -TimePeriod 4h'
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBattery -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName 'ZeroNetworks-Reset-Breakglass' -Action $action `
        -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Deactivates Zero Networks breakglass after its grace period expires.'

    Step 1 sets ZN_API_KEY as a MACHINE-scoped environment variable. This takes effect
    immediately for the scheduled task without a reboot or logoff: Task Scheduler spins up
    a brand-new process (and, for a SYSTEM task, a fresh SYSTEM logon session) on every
    run, and Windows builds that process's environment block by reading the registry at
    that moment - it isn't inherited from some already-running session. Replace
    <your-api-key> with the real key; omitting -ApiKey when invoking the script then falls
    through to this environment variable (see the ApiKey parameter).

    -Action defines what runs: pwsh.exe invoking this script non-interactively with a
    4-hour grace period; update the -File path and -TimePeriod to match your deployment.

    -Trigger models a recurring hourly schedule: Task Scheduler has no native "every N
    hours forever" trigger, so a single -Once trigger is combined with -RepetitionInterval
    (how often it repeats) and -RepetitionDuration of [TimeSpan]::MaxValue (repeat
    indefinitely rather than stopping after a fixed duration).

    -Principal runs the task as SYSTEM via -LogonType ServiceAccount, so it executes
    whether or not a user is logged in and no password needs to be stored; -RunLevel
    Highest grants the elevation some systems need to write the log file.

    -Settings keeps the task firing on schedule even on a laptop running on battery or
    briefly unavailable at the scheduled time (-StartWhenAvailable catches it up on the
    next opportunity).

    After registering, verify with:
      Get-ScheduledTask -TaskName 'ZeroNetworks-Reset-Breakglass'
    Trigger an immediate test run with:
      Start-ScheduledTask -TaskName 'ZeroNetworks-Reset-Breakglass'
    Remove it later with:
      Unregister-ScheduledTask -TaskName 'ZeroNetworks-Reset-Breakglass' -Confirm:$false

.NOTES
    Author:  Olaf Gradin
    Contact: olaf.gradin@zeronetworks.com
    Date:    2026-06-25

    See the scheduled-task .EXAMPLE above for a copy-pasteable Register-ScheduledTask
    setup - including the recommended Machine-scoped ZN_API_KEY environment variable -
    that runs this script unattended on a recurring interval.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9]+[mhdw]$')]
    [string]$TimePeriod,

    [Parameter()]
    [string]$ApiKey,

    [Parameter()]
    [string]$LogFile = (Join-Path $PSScriptRoot 'Reset-Breakglass.log'),

    [Parameter()]
    [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
    [string]$LogLevel = 'Information',

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [string[]]$ExcludeGroupIds = @(),

    [Parameter()]
    [switch]$DisableGroupExclusion,

    [Parameter()]
    [int[]]$BreakglassActivateTypes = @(132)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Constants - VERIFY AS NEEDED --------------------------

# Audit log action type codes that indicate breakglass was ACTIVATED on an asset.
# Run with -LogLevel Debug against a window where breakglass was triggered; the script
# will output all unique auditType values seen.
$script:BREAKGLASS_ACTIVATE_TYPES = $BreakglassActivateTypes

# REST sub-path for deactivating breakglass on a single asset.
# Full URL becomes: <baseUrl>/assets/<assetId>/<BREAKGLASS_DEACTIVATE_PATH>  [POST]
$script:BREAKGLASS_DEACTIVATE_PATH = 'actions/deactivate-break-glass'

# Group names to resolve to IDs at runtime - portable across tenants.
# Each name is searched against /groups/system; matched IDs are merged with
# $BREAKGLASS_EXCLUDE_GROUPS and any -ExcludeGroupIds values.
$script:BREAKGLASS_EXCLUDE_GROUP_NAMES = @('Zero Networks Admins')

# Group IDs whose members are exempt from auto-deactivation (tenant-specific).
# Use this when you already know the IDs, or alongside $BREAKGLASS_EXCLUDE_GROUP_NAMES.
# Use -ExcludeGroupIds to pass additional groups at runtime without editing this file.
$script:BREAKGLASS_EXCLUDE_GROUPS = @()

# REST path template for listing members of a system group.
# Full URL becomes: <baseUrl>/groups/system/<groupId>/<GROUP_MEMBERS_PATH>  [GET]
$script:GROUP_MEMBERS_PATH = 'successors'

$script:SCRIPT_VERSION = '1.0.0'
$script:CEF_VENDOR     = 'ZeroNetworks'
$script:CEF_PRODUCT    = 'Reset-Breakglass'

# -- Log-level numeric map ------------------------------------------------------

$script:LOG_LEVEL_MAP = @{
    Debug       = 0
    Information = 3
    Warning     = 6
    Error       = 8
}
function Get-BreakglassActivationsForAssets {
    param(
        [string[]]$AssetIds,
        [string]$BaseUrl,
        [hashtable]$Headers
    )

    $remaining = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in ($AssetIds | Where-Object { $_ })) { [void]$remaining.Add($id) }

    $found  = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $limit  = 400
    $offset = 0
    $cursor = $null

    $filters = @(
        @{
            id            = 'auditType'
            includeValues = @($script:BREAKGLASS_ACTIVATE_TYPES | ForEach-Object { "$_" })
        }
    )
    $filtersJson    = ConvertTo-Json -InputObject $filters -Compress -Depth 5
    if ($filtersJson -notmatch '^\[') { $filtersJson = "[$filtersJson]" }
    $filtersEncoded = [Uri]::EscapeDataString($filtersJson)

    do {
        $uri = "$BaseUrl/audit?_limit=$limit&order=desc&_filters=$filtersEncoded"
        if ($cursor) {
            $uri += "&_cursor=$cursor"
        } else {
            $uri += "&_offset=$offset"
        }

        $response = Invoke-ZnApi -Uri $uri -Headers $Headers
        $items    = @($response.items)
        if ($items.Count -eq 0) { break }

        foreach ($item in $items) {
            $id = $item.reportedObjectId
            if ($id -and $remaining.Contains($id) -and -not $found.ContainsKey($id)) {
                $found[$id] = $item
                [void]$remaining.Remove($id)
            }
        }

        Write-Log "Audit scan page: $($items.Count) entries (remaining assets: $($remaining.Count))" -Level Debug -SignatureId 'AUDIT-SCAN'

        if ($remaining.Count -eq 0) { break }

        $cursor = $null
        foreach ($name in @('cursor', 'nextCursor', 'next')) {
            if ($response.PSObject.Properties[$name] -and $response.$name) {
                $cursor = $response.$name
                break
            }
        }
        if (-not $cursor) {
            $offset += $items.Count
            if ($items.Count -lt $limit) { break }
        }
    } while ($true)

    return $found
}

# -- Helpers -------------------------------------------------------------------

function Resolve-TimePeriod {
    param([string]$Period)
    $num  = [int]($Period -replace '[mhdw]$', '')
    $unit = [string]$Period[-1]
    if     ($unit -eq 'm') { return [TimeSpan]::FromMinutes($num)       }
    elseif ($unit -eq 'h') { return [TimeSpan]::FromHours($num)         }
    elseif ($unit -eq 'd') { return [TimeSpan]::FromDays($num)          }
    elseif ($unit -eq 'w') { return [TimeSpan]::FromDays($num * 7)      }
    else                   { throw "Unknown time unit '$unit' in '$Period'" }
}

function Get-ResolvedApiKey {
    if ($script:ApiKey) { return $script:ApiKey }
    $envKey = [System.Environment]::GetEnvironmentVariable('ZN_API_KEY')
    if ($envKey) { return $envKey }
    throw 'API key not found. Provide via -ApiKey or set the ZN_API_KEY environment variable.'
}

function Get-BaseUrlFromJwt {
    param([string]$Token)
    $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        $audience = $decoded.aud ?? $decoded.api_url ?? $decoded.tenant
        if ($audience) {
            $baseUrl = "https://$($audience.TrimEnd('/'))/api/v1"
            Write-Log "Detected API endpoint from JWT: $baseUrl" -Level Debug -SignatureId 'AUTH-001'
            return $baseUrl
        }
    } catch { }
    Write-Log 'Could not parse JWT audience - using default portal URL' -Level Warning -SignatureId 'AUTH-002'
    return 'https://portal.zeronetworks.com/api/v1'
}

function Get-ApiHeaders {
    param([string]$Key)
    return @{
        Authorization  = $Key
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }
}

function Write-CefLog {
    param(
        [string]$SignatureId,
        [string]$Name,
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string]$Severity = 'Information',
        [hashtable]$Extensions = @{}
    )

    if ($script:LOG_LEVEL_MAP[$Severity] -lt $script:LOG_LEVEL_MAP[$script:LogLevel]) { return }

    $cefSev = switch ($Severity) {
        'Debug'       { 1 }
        'Information' { 3 }
        'Warning'     { 6 }
        'Error'       { 8 }
    }
    $rt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

    $extParts = [System.Collections.Generic.List[string]]::new()
    $extParts.Add("rt=$rt")
    foreach ($kv in $Extensions.GetEnumerator()) {
        $val = [string]($kv.Value ?? '')
        # CEF extension value escaping: backslash → \\, newlines → space, = → \=
        $val = $val.Replace('\', '\\').Replace("`r`n", ' ').Replace("`n", ' ').Replace("`r", ' ').Replace('=', '\=')
        $extParts.Add("$($kv.Key)=$val")
    }

    $line = "CEF:0|$script:CEF_VENDOR|$script:CEF_PRODUCT|$script:SCRIPT_VERSION|$SignatureId|$Name|$cefSev|$($extParts -join ' ')"

    try {
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    } catch {
        Write-Warning "CEF log write failed ($script:LogFile): $($_.Exception.Message)"
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Debug', 'Information', 'Warning', 'Error')]
        [string]$Level = 'Information',
        [string]$SignatureId = 'SCRIPT-000',
        [hashtable]$Extensions = @{}
    )

    if ($script:LOG_LEVEL_MAP[$Level] -lt $script:LOG_LEVEL_MAP[$script:LogLevel]) { return }

    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Debug'       { 'DarkGray' }
        'Information' { 'Cyan'     }
        'Warning'     { 'Yellow'   }
        'Error'       { 'Red'      }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color

    $ext = $Extensions.Clone()
    if (-not $ext.ContainsKey('msg')) { $ext['msg'] = $Message }
    Write-CefLog -SignatureId $SignatureId -Name $Level -Severity $Level -Extensions $ext
}

function Invoke-ZnApi {
    param(
        [string]$Uri,
        [string]$Method = 'Get',
        [hashtable]$Headers,
        [object]$Body = $null
    )
    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $Headers
        ErrorAction = 'Stop'
    }
    if ($Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 5 -Compress) }

    try {
        return Invoke-RestMethod @params
    } catch {
        $status = $_.Exception.Response?.StatusCode.value__
        $detail = $_.ErrorDetails?.Message ?? $_.Exception.Message
        throw "[$Method $Uri] HTTP $status - $detail"
    }
}

function Get-BreakglassAssets {
    param(
        [string]$BaseUrl,
        [hashtable]$Headers
    )

    $allAssets = [System.Collections.Generic.List[object]]::new()
    $limit     = 400
    $offset    = 0

    $filters = @(
        @{
            id            = 'breakGlassStatus'
            includeValues = @('true')
        }
    )
    $filtersJson    = ConvertTo-Json -InputObject $filters -Compress -Depth 5
    if ($filtersJson -notmatch '^\[') { $filtersJson = "[$filtersJson]" }
    $filtersEncoded = [Uri]::EscapeDataString($filtersJson)

    do {
        $uri      = "$BaseUrl/assets/monitored?_limit=$limit&_offset=$offset&_filters=$filtersEncoded&showInactive=false"
        $response = Invoke-ZnApi -Uri $uri -Headers $Headers
        $items    = @($response.items)

        if ($items.Count -eq 0) { break }

        foreach ($item in $items) { $allAssets.Add($item) }
        Write-Log "Breakglass assets page fetched: $($items.Count) at offset $offset (running total: $($allAssets.Count))" -Level Debug -SignatureId 'ASSET-001'

        $offset += $items.Count
        if ($items.Count -lt $limit) { break }
    } while ($true)

    return $allAssets
}

function Get-LatestBreakglassActivation {
    param(
        [string]$AssetId,
        [string]$BaseUrl,
        [hashtable]$Headers
    )

    $filters = @(
        @{
            id            = 'auditType'
            includeValues = @($script:BREAKGLASS_ACTIVATE_TYPES | ForEach-Object { "$_" })
        },
        @{
            id            = 'reportedObjectId'
            includeValues = @($AssetId)
        }
    )
    $filtersJson    = ConvertTo-Json -InputObject $filters -Compress -Depth 5
    if ($filtersJson -notmatch '^\[') { $filtersJson = "[$filtersJson]" }
    $filtersEncoded = [Uri]::EscapeDataString($filtersJson)

    $uri      = "$BaseUrl/audit?_limit=1&order=desc&_filters=$filtersEncoded"
    $response = Invoke-ZnApi -Uri $uri -Headers $Headers
    $items    = @($response.items)
    if ($items.Count -eq 0) { return $null }
    return $items[0]
}
function Get-LatestBreakglassActivationByName {
    param(
        [string]$AssetName,
        [string]$BaseUrl,
        [hashtable]$Headers
    )

    if (-not $AssetName) { return $null }

    $filters = @(
        @{
            id            = 'auditType'
            includeValues = @($script:BREAKGLASS_ACTIVATE_TYPES | ForEach-Object { "$_" })
        },
        @{
            id            = 'affectedEntities'
            includeValues = @($AssetName)
        }
    )
    $filtersJson    = ConvertTo-Json -InputObject $filters -Compress -Depth 5
    if ($filtersJson -notmatch '^\[') { $filtersJson = "[$filtersJson]" }
    $filtersEncoded = [Uri]::EscapeDataString($filtersJson)

    $uri      = "$BaseUrl/audit?_limit=1&order=desc&_filters=$filtersEncoded"
    $response = Invoke-ZnApi -Uri $uri -Headers $Headers
    $items    = @($response.items)
    if ($items.Count -eq 0) { return $null }
    return $items[0]
}
function Get-AuditLog {
    param(
        [string]$BaseUrl,
        [hashtable]$Headers,
        [long]$FromMs,
        [long]$ToMs
    )

    $allEntries = [System.Collections.Generic.List[object]]::new()
    $limit      = 400
    $offset     = 0

    $fromStr = ([DateTimeOffset]::FromUnixTimeMilliseconds($FromMs)).ToString('yyyy-MM-dd HH:mm:ss UTC')
    $toStr   = ([DateTimeOffset]::FromUnixTimeMilliseconds($ToMs)).ToString('yyyy-MM-dd HH:mm:ss UTC')
    Write-Log "Querying audit log: $fromStr → $toStr" -Level Debug -SignatureId 'AUDIT-001'

    do {
        $uri      = "$BaseUrl/audit?_from=$FromMs&_to=$ToMs&_limit=$limit&_offset=$offset"
        $response = Invoke-ZnApi -Uri $uri -Headers $Headers
        $items    = @($response.items)

        if ($items.Count -eq 0) { break }

        # The API may ignore _to and return entries beyond our window; discard those here.
        foreach ($item in $items) {
            if (-not $item.timestamp -or [long]$item.timestamp -le $ToMs) {
                $allEntries.Add($item)
            }
        }
        Write-Log "Page fetched: $($items.Count) entries at offset $offset (running total in window: $($allEntries.Count))" -Level Debug -SignatureId 'AUDIT-002'

        $offset += $items.Count
        if ($items.Count -lt $limit) { break }

        # Tail early-exit: audit entries come back newest-first; once the oldest entry on this
        # page is before our fetch window we've covered everything relevant - stop paging.
        $timestamps = $items | Where-Object { $_.timestamp } | ForEach-Object { [long]$_.timestamp }
        if ($timestamps) {
            $minTs = ($timestamps | Measure-Object -Minimum).Minimum
            if ($minTs -lt $FromMs) {
                Write-Log "Pagination early-exit at offset $offset - oldest entry on page predates fetch window." -Level Debug -SignatureId 'AUDIT-EXIT'
                break
            }
        }
    } while ($true)

    return $allEntries
}

function Resolve-GroupIdsByName {
    param(
        [string[]]$Names,
        [string]$BaseUrl,
        [hashtable]$Headers
    )
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($name in ($Names | Where-Object { $_ })) {
        $encoded = [Uri]::EscapeDataString($name)
        $uri     = "$BaseUrl/groups/system?_search=$encoded&_limit=50"
        try {
            $response = Invoke-ZnApi -Uri $uri -Headers $Headers
            $matched  = @($response.items | Where-Object { $_.name -eq $name })
            if ($matched.Count -eq 0) {
                Write-Log "No system group found with name '$name' - skipping exclusion" -Level Warning -SignatureId 'GROUP-RESOLVE'
            } else {
                foreach ($g in $matched) {
                    $ids.Add($g.id)
                    Write-Log "Resolved excluded group '$name' → $($g.id)" -Level Debug -SignatureId 'GROUP-RESOLVE'
                }
            }
        } catch {
            Write-Log "Could not resolve group name '$name': $($_.Exception.Message)" -Level Warning -SignatureId 'GROUP-RESOLVE-ERR'
        }
    }
    return $ids
}

function Get-GroupMemberIds {
    param(
        [string]$GroupId,
        [string]$BaseUrl,
        [hashtable]$Headers
    )
    $ids    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $limit  = 400
    $offset = 0
    Write-Log "Fetching members of excluded group: $GroupId" -Level Debug -SignatureId 'GROUP-001'
    do {
        $uri = "$BaseUrl/groups/system/$GroupId/$($script:GROUP_MEMBERS_PATH)?_limit=$limit&_offset=$offset&includeNestedMembers=false&showInactive=false"
        try {
            $response = Invoke-ZnApi -Uri $uri -Headers $Headers
        } catch {
            Write-Log "Could not fetch members for group $GroupId - group exclusion skipped: $($_.Exception.Message)" `
                -Level Warning -SignatureId 'GROUP-ERR'
            return $ids
        }
        $items = $response.items
        if ($null -eq $items -or $items.Count -eq 0) { break }
        $items = @($items)
        foreach ($item in $items) {
            $id = $item.id ?? $item.userId
            if ($id) { [void]$ids.Add($id) }
        }
        $offset += $items.Count
        if ($items.Count -lt $limit) { break }
    } while ($true)
    Write-Log "Group $GroupId - $($ids.Count) member(s) will be excluded" -Level Debug -SignatureId 'GROUP-002'
    return ,$ids
}

function Remove-AssetBreakglass {
    param(
        [string]$AssetId,
        [string]$AssetName,
        [string]$BaseUrl,
        [hashtable]$Headers,
        [string]$ActivatedBy,
        [string]$ActivatedAt
    )

    $cefBase = @{
        dhost    = $AssetName
        cs1Label = 'assetId'
        cs1      = $AssetId
        cs2Label = 'activatedBy'
        cs2      = $ActivatedBy
        cs3Label = 'activatedAt'
        cs3      = $ActivatedAt
    }

    if ($script:DryRun) {
        Write-Log "[DRY RUN] Would deactivate breakglass: $AssetName (activated by $ActivatedBy at $ActivatedAt)" `
            -Level Information -SignatureId 'BG-DRY' -Extensions ($cefBase + @{ act = 'BreakglassDeactivateSkipped'; outcome = 'skipped'; reason = 'DryRun' })
        return 'DryRun'
    }

    $uri = "$BaseUrl/assets/$AssetId/$script:BREAKGLASS_DEACTIVATE_PATH"
    try {
        Invoke-ZnApi -Uri $uri -Method Post -Headers $Headers | Out-Null
        Write-Log "Breakglass deactivated: $AssetName (reversing action by $ActivatedBy from $ActivatedAt)" `
            -Level Information -SignatureId 'BG-RESET' -Extensions ($cefBase + @{ act = 'BreakglassDeactivated'; outcome = 'success' })
        return 'Success'
    } catch {
        Write-Log "Failed to deactivate breakglass on $AssetName ($AssetId): $($_.Exception.Message)" `
            -Level Error -SignatureId 'BG-ERR' -Extensions ($cefBase + @{ act = 'BreakglassDeactivateFailed'; outcome = 'failure'; reason = $_.Exception.Message })
        return 'Failed'
    }
}

# -- Main ----------------------------------------------------------------------

function Main {
    $modeTag = if ($script:DryRun) { ' [DRY RUN]' } else { '' }
    Write-Log "Reset-Breakglass v$script:SCRIPT_VERSION starting$modeTag (LogLevel=$script:LogLevel)" `
        -Level Information -SignatureId 'SCRIPT-START' -Extensions @{
            cs1Label = 'timePeriod'; cs1 = $script:TimePeriod
            cs2Label = 'logFile';    cs2 = $script:LogFile
            cs3Label = 'dryRun';     cs3 = $script:DryRun.ToString()
            cs4Label = 'groupExclusionDisabled'; cs4 = $script:DisableGroupExclusion.ToString()
        }

    # Resolve grace period window.
    # _to   = now - span  (activations must be older than this to be eligible)
    $span   = Resolve-TimePeriod -Period $script:TimePeriod
    $toMs   = ([DateTimeOffset]::UtcNow - $span).ToUnixTimeMilliseconds()
    $cutoff = ([DateTimeOffset]::FromUnixTimeMilliseconds($toMs)).ToString('yyyy-MM-dd HH:mm:ss UTC')
    Write-Log "Grace period: $($span.ToString()) - deactivating breakglass activated before $cutoff" `
        -Level Information -SignatureId 'SCRIPT-001'

    # Auth and endpoint
    $key     = Get-ResolvedApiKey
    $baseUrl = Get-BaseUrlFromJwt -Token $key
    $headers = Get-ApiHeaders -Key $key

    # Exclude activations performed by members of configured exempt groups
    $excludedIds = $null
    if ($script:DisableGroupExclusion) {
        Write-Log "Group exclusion disabled (-DisableGroupExclusion) - no activations are exempt" `
            -Level Information -SignatureId 'GROUP-DISABLED'
    } else {
        $resolvedIds      = Resolve-GroupIdsByName -Names $script:BREAKGLASS_EXCLUDE_GROUP_NAMES -BaseUrl $baseUrl -Headers $headers
        $allExcludeGroups = @(@($resolvedIds) + @($script:BREAKGLASS_EXCLUDE_GROUPS) + @($script:ExcludeGroupIds) |
            Where-Object { $_ } | Sort-Object -Unique)
        if ($allExcludeGroups.Count -gt 0) {
            $excludedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($gid in $allExcludeGroups) {
                foreach ($id in (Get-GroupMemberIds -GroupId $gid -BaseUrl $baseUrl -Headers $headers)) {
                    [void]$excludedIds.Add($id)
                }
            }
            if ($excludedIds.Count -gt 0) {
                Write-Log "Loaded $($excludedIds.Count) excluded member(s) across $($allExcludeGroups.Count) group(s)" `
                    -Level Debug -SignatureId 'BG-EXEMPT-LOAD'
            }
        }
    }

    # Fetch assets currently in breakglass
    $breakglassAssets = @(Get-BreakglassAssets -BaseUrl $baseUrl -Headers $headers)
    Write-Log "Assets currently in breakglass: $($breakglassAssets.Count)" -Level Information -SignatureId 'ASSET-COUNT'

    if ($breakglassAssets.Count -eq 0) {
        Write-Log "No assets currently in breakglass - nothing to reset." `
            -Level Information -SignatureId 'BG-NONE' -Extensions @{ outcome = 'noop' }
        Write-Log "Reset-Breakglass completed." -Level Information -SignatureId 'SCRIPT-END' -Extensions @{ outcome = 'success' }
        return
    }

    $resetCount     = 0
    $failCount      = 0
    $dryRunCount    = 0
    $eligibleCount  = 0
    $skippedNewer   = 0
    $skippedNoAudit = 0
    $skippedExcluded = 0

    $assetIds = @($breakglassAssets | ForEach-Object { $_.id ?? $_.assetId ?? $_.reportedObjectId } | Where-Object { $_ })
    $activationMap = Get-BreakglassActivationsForAssets -AssetIds $assetIds -BaseUrl $baseUrl -Headers $headers

    foreach ($asset in $breakglassAssets) {
        $assetId = $asset.id ?? $asset.assetId ?? $asset.reportedObjectId
        if (-not $assetId) {
            Write-Log "Skipping breakglass asset with missing id" -Level Warning -SignatureId 'BG-ASSET-ID'
            continue
        }
        $assetName = $asset.name ?? $asset.hostname ?? $asset.fqdn ?? $assetId

        $entry = $null
        if ($activationMap.ContainsKey($assetId)) { $entry = $activationMap[$assetId] }
        if (-not $entry) {
            $entry = Get-LatestBreakglassActivationByName -AssetName $assetName -BaseUrl $baseUrl -Headers $headers
        }
        if (-not $entry) {
            Write-Log "No activation audit entry found for $assetName ($assetId) - skipping" `
                -Level Warning -SignatureId 'BG-AUDIT-MISS'
            $skippedNoAudit++
            continue
        }

        $entryTs = if ($entry.timestamp) { [long]$entry.timestamp } else { $null }
        $activatedAt = if ($entry.timestamp) {
            try { ([DateTimeOffset]::FromUnixTimeMilliseconds([long]$entry.timestamp)).ToString('yyyy-MM-dd HH:mm:ss UTC') }
            catch { [string]$entry.timestamp }
        } else { 'unknown' }
        if ($entryTs -and $entryTs -gt $toMs) {
            Write-Log "Breakglass activation for $assetName is newer than cutoff ($activatedAt) - skipping" `
                -Level Debug -SignatureId 'BG-NEWER' -Extensions @{ cs1Label = 'assetId'; cs1 = $assetId }
            $skippedNewer++
            continue
        }

        $activatedBy = $entry.performedBy?.name ?? $entry.performedBy?.id ?? 'unknown'
        $eligibleCount++

        if ($excludedIds -and $excludedIds.Count -gt 0) {
            $performerId = $entry.performedBy?.id
            if ($performerId -and $excludedIds.Contains($performerId)) {
                Write-Log "Exempted activation for $assetName - performed by excluded group member" `
                    -Level Information -SignatureId 'BG-EXEMPT' -Extensions @{
                        act      = 'BreakglassExempted'
                        outcome  = 'skipped'
                        reason   = 'ExcludedGroup'
                        cs1Label = 'assetId';     cs1 = $assetId
                        cs2Label = 'performedBy'; cs2 = $performerId
                    }
                $skippedExcluded++
                continue
            }
        }

        Write-Log "Breakglass activation detected: $assetName | by: $activatedBy | at: $activatedAt" `
            -Level Information -SignatureId 'BG-DETECT' -Extensions @{
                act      = 'BreakglassDetected'
                dhost    = $assetName
                cs1Label = 'assetId';      cs1 = $assetId
                cs2Label = 'activatedBy';  cs2 = $activatedBy
                cs3Label = 'activatedAt';  cs3 = $activatedAt
            }

        $result = Remove-AssetBreakglass `
            -AssetId     $assetId `
            -AssetName   $assetName `
            -BaseUrl     $baseUrl `
            -Headers     $headers `
            -ActivatedBy $activatedBy `
            -ActivatedAt $activatedAt

        switch ($result) {
            'Success' { $resetCount++ }
            'Failed'  { $failCount++  }
            'DryRun'  { $dryRunCount++ }
        }
    }

    $outcome = if ($failCount -gt 0 -and $resetCount -eq 0) { 'failure' }
               elseif ($failCount -gt 0)                    { 'partial' }
               else                                          { 'success' }

    Write-Log "Reset-Breakglass completed - Reset: $resetCount  Failed: $failCount  DryRun: $dryRunCount  Eligible: $eligibleCount  SkippedNewer: $skippedNewer  SkippedNoAudit: $skippedNoAudit  SkippedExcluded: $skippedExcluded  Period: $script:TimePeriod" `
        -Level Information -SignatureId 'SCRIPT-END' -Extensions @{
            cs1Label = 'resetCount';  cs1 = $resetCount
            cs2Label = 'failCount';   cs2 = $failCount
            cs3Label = 'timePeriod';  cs3 = $script:TimePeriod
            cs4Label = 'dryRunCount'; cs4 = $dryRunCount
            cs5Label = 'eligibleCount'; cs5 = $eligibleCount
            outcome  = $outcome
        }
}

Main
