<#
.NOTES
    NAME: Thomas Obarowski (original) / updated by Ken
    LINK: https://github.com/tjobarow/
    AUTHOR: tjobarow@gmail.com
    VERSION: 1.3
.SYNOPSIS
   Reads a CSV of Linux assets (columns matching the ZN API payload) and adds them to
   the Zero Networks dashboard as manual Linux assets, optionally binding them to a
   non-default SSH credential profile and/or pinning them to a deployment cluster.

.DESCRIPTION
   New in 1.3 (fixes):
     - Log file now anchored to $PSScriptRoot instead of the working directory.
     - Input file validation (token + CSV) with clear error messages before any API calls.
     - Empty-CSV guard prevents cryptic Get-Member failures.
     - Column-presence detection uses [bool](...) cast for reliable PowerShell 5.1/7 behaviour.
     - Add-ZnLinuxAsset now throws on unrecognised response shape instead of silently
       returning a raw object that would corrupt the cluster-pin step.
     - Resolve-DefaultProfileId refactored into a proper function with explicit parameters;
       cached result stored in $script:ResolvedDefaultProfileId.
     - $createdAssets uses a Generic List to avoid O(n²) array-copy on +=.
     - ConvertTo-Json depth reduced to 2 for routine log lines (bodies are shallow).
     - API token cleared from memory (Remove-Variable) at end of script.
     - [CmdletBinding(SupportsShouldProcess)] + $PSCmdlet.ShouldProcess guards added to
       mutating API calls (Add-ZnLinuxAsset, Set-ZnDeploymentCluster) for -WhatIf support.

   New in 1.2:
     - CSV columns now mirror the API payload: displayName, fqdn, profileId.
     - If fqdn is blank/missing on a row, displayName is used as the fqdn.
     - If profileId is blank/missing on a row, the script falls back to
       $DefaultProfileId, and finally to the tenant's "Default Linux Profile"
       (resolved once per run via GET /api/v1/settings/asset-management/linux/profile).
     - The legacy <host>.company.com normalization has been removed - put the
       full FQDN (or IP) directly in the CSV.

   Functions exposed (1.1+):
     - Add-ZnLinuxAsset           : POST /api/v1/assets/linux
     - Set-ZnDeploymentCluster    : PUT  /api/v1/assets/actions/deployments-cluster
     - Get-ZnLinuxProfile         : GET  /api/v1/settings/asset-management/linux/profile
     - Get-ZnDefaultLinuxProfileId: convenience lookup for the "Default Linux Profile"
     - Resolve-DefaultProfileId   : cached wrapper around Get-ZnDefaultLinuxProfileId
     - Invoke-ZnRequest           : shared header/JSON wrapper around Invoke-RestMethod

.INPUTS
    .\linux-assets.csv with these columns (header row required):
        displayName           (required) - friendly label for the asset
        fqdn                  (optional) - FQDN or IP; if blank, displayName is used
        profileId             (optional) - e.g. "l:c:3WskUa28"; if blank, default profile is used
        deploymentsClusterId  (optional) - e.g. "C:d:009243d6"; if blank, falls back to
                                           the -DeploymentsClusterId param
    .\token.txt with the Zero Networks API token.
.OUTPUTS
   <script dir>\<YYYY-MM-DD>-enroll-linux-script.log
.PARAMETER TokenPath
   Path to the file containing the Zero Networks API token. Defaults to .\token.txt.
.PARAMETER BaseUri
   Base portal URI (e.g. https://portal.zeronetworks.com or https://portal-dev.zeronetworks.com).
.PARAMETER DeploymentsClusterId
   Optional. If set, every asset successfully created in this run is pinned
   to this deployment cluster after enrollment.
.PARAMETER DefaultProfileId
   Optional. ProfileId applied to every CSV row that does NOT specify one of its own.
   If neither this nor the row-level value is set, the script resolves the tenant's
   "Default Linux Profile" via the API.
.PARAMETER CsvPath
   Path to the input CSV. Defaults to .\linux-assets.csv.
.EXAMPLE
   .\enrollLinuxAsset.ps1 `
       -TokenPath .\token.txt `
       -BaseUri https://portal-dev.zeronetworks.com `
       -DeploymentsClusterId "C:d:009243d6" `
       -DefaultProfileId "l:c:3WskUa28"
.EXAMPLE
   # Dry-run: shows what would be created/pinned without calling the API
   .\enrollLinuxAsset.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]   # Fix #13: enables -WhatIf / -Confirm
param(
    [string]$TokenPath = ".\token.txt",
    [string]$BaseUri = "https://portal.zeronetworks.com",
    [string]$DeploymentsClusterId,
    [string]$DefaultProfileId,
    [string]$CsvPath = ".\linux-assets.csv"
)

# ----------------------------- Configuration -----------------------------
# All runtime configuration is now driven by the parameters above.

# ----------------------------- Helpers -----------------------------------

# Fix #11: anchor log to script directory, not working directory
$LogFile = Join-Path $PSScriptRoot "$(Get-Date -UFormat '%Y-%m-%d')-enroll-linux-script.log"

function Write-ZnLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    $line = "$(Get-Date -UFormat '%Y-%m-%d %T'): $Message"
    Write-Host $line
    $line | Out-File -FilePath $LogFile -Append
}

function Get-ZnErrorBody {
    <#
    .SYNOPSIS
        Best-effort extraction of the response body from a failed Invoke-RestMethod.
        Works under both PowerShell 5.1 (read response stream) and 7+ (ErrorDetails.Message).
    #>
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return $ErrorRecord.ErrorDetails.Message
    }

    try {
        $resp = $ErrorRecord.Exception.Response
        if ($null -ne $resp) {
            $stream = $resp.GetResponseStream()
            if ($null -ne $stream) {
                $stream.Position = 0
                $reader = [System.IO.StreamReader]::new($stream)
                return $reader.ReadToEnd()
            }
        }
    }
    catch { }

    return ""
}

function Invoke-ZnRequest {
    <#
    .SYNOPSIS
        Thin wrapper around Invoke-RestMethod that injects the standard ZN headers.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Post', 'Put', 'Delete', 'Patch')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Token,
        $Body
    )

    $params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = @{
            "Authorization" = $Token
            "Accept"        = "application/json"
            "Content-Type"  = "application/json"
        }
    }
    if ($null -ne $Body) {
        # Fix #12: depth 2 is sufficient for these shallow request bodies
        $params["Body"] = ($Body | ConvertTo-Json -Depth 2)
    }

    return Invoke-RestMethod @params
}

# ----------------------------- API functions -----------------------------

function Add-ZnLinuxAsset {
    <#
    .SYNOPSIS
        Enrolls a Linux host as a manual asset in Zero Networks.
    .PARAMETER Fqdn
        Full FQDN (or IP) of the Linux host. Used as displayName when -DisplayName is not set.
    .PARAMETER DisplayName
        Optional display name. Defaults to $Fqdn.
    .PARAMETER ProfileId
        Optional Linux configuration / SSH credential profile ID
        (e.g. "l:c:3WskUa28"). When set, the asset will use the SSH user
        credential bound to that profile instead of the tenant default.
    .PARAMETER Token
        Zero Networks API token.
    .PARAMETER BaseUri
        Base portal URI (e.g. https://portal.zeronetworks.com).
    .OUTPUTS
        The asset ID string returned by the API.
    #>
    [CmdletBinding(SupportsShouldProcess)]   # Fix #13: -WhatIf support
    param(
        [Parameter(Mandatory = $true)][string]$Fqdn,
        [string]$DisplayName,
        [string]$ProfileId,
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$BaseUri = "https://portal.zeronetworks.com"
    )

    if (-not $DisplayName) { $DisplayName = $Fqdn }

    $body = @{
        displayName = $DisplayName
        fqdn        = $Fqdn
    }
    if ($ProfileId) { $body["profileId"] = $ProfileId }

    # Fix #12: depth 2 is sufficient; Fix #13: ShouldProcess guard
    Write-ZnLog "POST $BaseUri/api/v1/assets/linux  body=$(ConvertTo-Json $body -Depth 2 -Compress)"
    if (-not $PSCmdlet.ShouldProcess("$DisplayName ($Fqdn)", "Create Linux asset")) {
        return $null
    }

    $resp = Invoke-ZnRequest -Uri "$BaseUri/api/v1/assets/linux" -Method Post -Token $Token -Body $body
    Write-ZnLog "Create response: $($resp | ConvertTo-Json -Depth 2 -Compress)"

    # Extract the asset ID across the most common ZN response shapes:
    #   { id: "a:l:..." }
    #   { items: [ { id: "a:l:..." } ] }
    #   { items: [ "a:l:..." ] }
    if ($resp -is [string]) { return $resp }
    if ($resp.id)           { return $resp.id }
    if ($resp.items) {
        $first = @($resp.items)[0]
        if ($null -ne $first) {
            if ($first -is [string]) { return $first }
            if ($first.id)           { return $first.id }
        }
    }

    # Fix #2: throw instead of silently returning a broken object
    throw "Could not locate asset ID in API response for '$DisplayName'. Raw response: $($resp | ConvertTo-Json -Depth 2 -Compress)"
}

function Set-ZnDeploymentCluster {
    <#
    .SYNOPSIS
        Pins one or more assets to a Zero Networks deployment cluster.
    .PARAMETER AssetIds
        One or more asset IDs (e.g. "a:l:ZP5ee1GG").
    .PARAMETER DeploymentsClusterId
        Deployment cluster ID (e.g. "C:d:009243d6").
    .PARAMETER Token
        Zero Networks API token.
    .PARAMETER BaseUri
        Base portal URI.
    .OUTPUTS
        Whatever the API returns for the action call.
    #>
    [CmdletBinding(SupportsShouldProcess)]   # Fix #13: -WhatIf support
    param(
        [Parameter(Mandatory = $true)][string[]]$AssetIds,
        [Parameter(Mandatory = $true)][string]$DeploymentsClusterId,
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$BaseUri = "https://portal.zeronetworks.com"
    )

    $body = @{
        assetIds             = $AssetIds
        deploymentsClusterId = $DeploymentsClusterId
    }

    Write-ZnLog "PUT $BaseUri/api/v1/assets/actions/deployments-cluster  body=$(ConvertTo-Json $body -Depth 2 -Compress)"
    if (-not $PSCmdlet.ShouldProcess("cluster $DeploymentsClusterId", "Pin $($AssetIds.Count) asset(s)")) {
        return $null
    }

    return Invoke-ZnRequest -Uri "$BaseUri/api/v1/assets/actions/deployments-cluster" -Method Put -Token $Token -Body $body
}

function Get-ZnLinuxProfile {
    <#
    .SYNOPSIS
        Lists Linux configuration / SSH credential profiles.
    .DESCRIPTION
        GET /api/v1/settings/asset-management/linux/profile
        Returns the items array, where each item has fields:
            id, name, username, allowInstallPackages, isUsedByAsset
    .PARAMETER Token
        Zero Networks API token.
    .PARAMETER BaseUri
        Base portal URI.
    .OUTPUTS
        Array of profile objects.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$BaseUri = "https://portal.zeronetworks.com"
    )

    Write-ZnLog "GET $BaseUri/api/v1/settings/asset-management/linux/profile"
    $resp = Invoke-ZnRequest -Uri "$BaseUri/api/v1/settings/asset-management/linux/profile" -Method Get -Token $Token
    return $resp.items
}

function Get-ZnDefaultLinuxProfileId {
    <#
    .SYNOPSIS
        Resolves the ID of the profile named "Default Linux Profile".
    .DESCRIPTION
        Calls Get-ZnLinuxProfile and looks for the item whose .name equals
        "Default Linux Profile" (case-insensitive). Throws if not found.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$BaseUri = "https://portal.zeronetworks.com"
    )

    $profiles = Get-ZnLinuxProfile -Token $Token -BaseUri $BaseUri
    $match = $profiles | Where-Object { $_.name -ieq "Default Linux Profile" } | Select-Object -First 1
    if (-not $match) {
        throw "Could not find a Linux profile named 'Default Linux Profile'. Profiles returned: $($profiles.name -join ', ')"
    }
    Write-ZnLog "Resolved default Linux profile: '$($match.name)' -> $($match.id) (username=$($match.username))"
    return $match.id
}

# Fix #3 / #10: proper function with explicit parameters; cache stored in $script: scope
$script:ResolvedDefaultProfileId = $null

function Resolve-DefaultProfileId {
    <#
    .SYNOPSIS
        Returns the default Linux profile ID, calling the API at most once per run.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$BaseUri = "https://portal.zeronetworks.com"
    )

    if ($script:ResolvedDefaultProfileId) { return $script:ResolvedDefaultProfileId }
    $script:ResolvedDefaultProfileId = Get-ZnDefaultLinuxProfileId -Token $Token -BaseUri $BaseUri
    return $script:ResolvedDefaultProfileId
}

# ----------------------------- Main flow ---------------------------------

# Fix #5: validate input files before doing anything else
if (-not (Test-Path -LiteralPath $TokenPath)) {
    throw "Token file not found: $TokenPath"
}
if (-not (Test-Path -LiteralPath $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

Write-ZnLog "Reading contents of $CsvPath..."

# Pull token once.
# Fix #8: trim and store; cleared via Remove-Variable at end of script.
$Token = (Get-Content -Path $TokenPath -Raw).Trim()

# CSV columns mirror the API payload: displayName, fqdn, profileId.
$rawCsv = Import-Csv -Path $CsvPath

# Fix #4: guard against an empty CSV (header-only or completely empty file)
if (-not $rawCsv) {
    Write-ZnLog "CSV is empty - nothing to do."
    exit 0
}

# Fix #1: use [bool](...) cast for reliable column-presence detection in PS 5.1 and 7+
$hasDisplayNameColumn = [bool]($rawCsv | Get-Member -Name "displayName"          -MemberType NoteProperty -ErrorAction SilentlyContinue)
$hasFqdnColumn        = [bool]($rawCsv | Get-Member -Name "fqdn"                 -MemberType NoteProperty -ErrorAction SilentlyContinue)
$hasProfileColumn     = [bool]($rawCsv | Get-Member -Name "profileId"            -MemberType NoteProperty -ErrorAction SilentlyContinue)
$hasClusterColumn     = [bool]($rawCsv | Get-Member -Name "deploymentsClusterId" -MemberType NoteProperty -ErrorAction SilentlyContinue)

if (-not $hasDisplayNameColumn) {
    throw "$CsvPath must have a 'displayName' column."
}
if (-not $hasFqdnColumn) {
    Write-ZnLog "CSV has no fqdn column - displayName will be used as fqdn for every row."
}
if (-not $hasProfileColumn) {
    Write-ZnLog "CSV has no profileId column - falling back to DefaultProfileId / tenant default."
}
if (-not $hasClusterColumn) {
    Write-ZnLog "CSV has no deploymentsClusterId column - falling back to -DeploymentsClusterId param for all rows."
}

# Fix #6: use a Generic List to avoid O(n²) array-copy on +=
$createdAssets = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($row in $rawCsv) {
    $displayName = $row.displayName
    if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

    # If fqdn is missing or blank, fall back to displayName.
    $fqdn = if ($hasFqdnColumn) { $row.fqdn } else { $null }
    if ([string]::IsNullOrWhiteSpace($fqdn)) { $fqdn = $displayName }

    Write-ZnLog "Row: displayName='$displayName' fqdn='$fqdn'"

    # Resolve the profile to use, in priority order:
    #   1. CSV row's profileId column
    #   2. $DefaultProfileId script parameter
    #   3. Tenant's "Default Linux Profile" (resolved via API on first need)
    $profileForRow = $null
    if ($hasProfileColumn -and -not [string]::IsNullOrWhiteSpace($row.profileId)) {
        $profileForRow = $row.profileId
    }
    elseif ($DefaultProfileId) {
        $profileForRow = $DefaultProfileId
    }
    else {
        try {
            # Fix #3: pass parameters explicitly instead of relying on captured outer vars
            $profileForRow = Resolve-DefaultProfileId -Token $Token -BaseUri $BaseUri
        }
        catch {
            Write-ZnLog "Could not resolve default Linux profile - asset will be created without profileId. ($_)"
        }
    }

    # Sanity-check the profileId prefix. Linux profile IDs are shaped like "l:c:xxxx".
    # IDs starting with "C:d:" are deployment-cluster IDs and will produce a 400.
    if ($profileForRow -and $profileForRow -notlike "l:c:*") {
        Write-ZnLog ("WARN: profileId '{0}' for '{1}' does not look like a Linux profile ID (expected 'l:c:...'). 'C:d:...' is a deployment-cluster ID and belongs in the deploymentsClusterId column, not profileId." -f $profileForRow, $displayName)
    }

    # Resolve which cluster (if any) this row should be pinned to:
    #   1. CSV row's deploymentsClusterId column
    #   2. -DeploymentsClusterId script param
    $clusterForRow = $null
    if ($hasClusterColumn -and -not [string]::IsNullOrWhiteSpace($row.deploymentsClusterId)) {
        $clusterForRow = $row.deploymentsClusterId
    }
    elseif ($DeploymentsClusterId) {
        $clusterForRow = $DeploymentsClusterId
    }
    if ($clusterForRow -and $clusterForRow -notlike "C:d:*") {
        Write-ZnLog ("WARN: deploymentsClusterId '{0}' for '{1}' does not look like a cluster ID (expected 'C:d:...')." -f $clusterForRow, $displayName)
    }

    try {
        $params = @{
            Fqdn        = $fqdn
            DisplayName = $displayName
            Token       = $Token
            BaseUri     = $BaseUri
        }
        if ($profileForRow) { $params["ProfileId"] = $profileForRow }

        $assetId = Add-ZnLinuxAsset @params
        if ($null -ne $assetId) {
            # $assetId is $null only under -WhatIf; skip logging/tracking in that case
            Write-ZnLog "Linux host created - $displayName ($fqdn) has asset ID: $assetId"
            # Fix #6: .Add() instead of +=
            $createdAssets.Add([pscustomobject]@{
                displayName = $displayName
                assetId     = $assetId
                clusterId   = $clusterForRow
            })
        }
    }
    catch {
        $body = Get-ZnErrorBody $_
        Write-ZnLog ("Web request failed for {0} ({1}): status={2} desc={3} body={4}" -f `
            $displayName,
            $fqdn,
            $_.Exception.Response.StatusCode.value__,
            $_.Exception.Response.StatusDescription,
            $body)
    }
}

# Group successfully-created assets by their resolved clusterId and PUT once per group.
$toPin = $createdAssets | Where-Object { $_.clusterId -and $_.assetId }
if ($toPin.Count -eq 0) {
    Write-ZnLog "No assets had a deploymentsClusterId set - skipping pin step."
}
else {
    $groups = $toPin | Group-Object -Property clusterId
    foreach ($g in $groups) {
        $clusterId = $g.Name
        $ids       = @($g.Group.assetId)
        try {
            Write-ZnLog "Pinning $($ids.Count) asset(s) to deployment cluster $clusterId..."
            $pinResult = Set-ZnDeploymentCluster `
                -AssetIds             $ids `
                -DeploymentsClusterId $clusterId `
                -Token                $Token `
                -BaseUri              $BaseUri
            if ($null -ne $pinResult) {
                # Fix #7: depth 2 is sufficient for pin response logging
                Write-ZnLog "Pin response for $clusterId : $($pinResult | ConvertTo-Json -Compress -Depth 2)"
            }
        }
        catch {
            $body = Get-ZnErrorBody $_
            Write-ZnLog ("Deployment-cluster pin failed for {0}: status={1} desc={2} body={3}" -f `
                $clusterId,
                $_.Exception.Response.StatusCode.value__,
                $_.Exception.Response.StatusDescription,
                $body)
        }
    }
}

# Fix #8: clear the plaintext token from memory
Remove-Variable -Name Token -ErrorAction SilentlyContinue
