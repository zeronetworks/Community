#Requires -Version 7

<#
.SYNOPSIS
    Exports the OT/IoT asset types that the tenant accepts into a CSV file.

.DESCRIPTION
    Calls the Zero Networks API (GET /assets/ot/filters) and reads the tenant's 'type' filter.
    Writes one row per type to a CSV file with a 'type' column. The type name is written when it
    resolves to exactly one type. Names that collide after normalization are written as their
    numeric IDs. With -IncludeId, an 'id' column is added. The CSV is UTF-8 with a BOM so that
    Excel reads it correctly.

    The output file is not overwritten unless -Force is given. Validation and API errors are
    reported before any file is written.

.PARAMETER ApiKey
    Zero Networks API key. Any key role works, including read-only. Defaults to the ZN_API_KEY
    environment variable, which keeps the key out of shell history.

.PARAMETER PortalUrl
    Portal address, for example https://example-admin.zeronetworks.com. When omitted, the host is
    taken from the API key. Falls back to https://portal.zeronetworks.com if no host is found.

.PARAMETER OutputPath
    Path of the CSV file to write. Defaults to OtAssetTypes.csv in the current directory.

.PARAMETER IncludeId
    Adds an 'id' column after 'type' with each type's numeric ID.

.PARAMETER Force
    Overwrite the output file when it already exists.

.PARAMETER PassThru
    Also write the exported rows to the pipeline as objects.

.EXAMPLE
    $Env:ZN_API_KEY = '<your-api-key>'
    .\Get-OtAssetTypes.ps1

    Writes OtAssetTypes.csv in the current directory with one type name per row.

.EXAMPLE
    .\Get-OtAssetTypes.ps1 -PortalUrl 'https://example-admin.zeronetworks.com' -OutputPath '.\types.csv' -IncludeId

    Writes types.csv with 'type' and 'id' columns, using the given portal address.

.EXAMPLE
    .\Get-OtAssetTypes.ps1 -OutputPath '.\types.csv' -Force -PassThru

    Overwrites types.csv and also returns the exported rows to the pipeline.

.NOTES
    Requires PowerShell 7.0 or later. Keep this script and OtAssetCommon.ps1 in the same folder.
    Any API key role works. Prefer the ZN_API_KEY environment variable over -ApiKey so the key
    does not appear in shell history.
    Exit codes: 0 on success, 1 on any failure.

.LINK
    README.md

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$ApiKey = $Env:ZN_API_KEY,
    [Parameter(Mandatory = $false)][string]$PortalUrl,
    [Parameter(Mandatory = $false)][string]$OutputPath = './OtAssetTypes.csv',
    [Parameter(Mandatory = $false)][switch]$IncludeId,
    [Parameter(Mandatory = $false)][switch]$Force,
    [Parameter(Mandatory = $false)][switch]$PassThru
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('InformationAction')) { $InformationPreference = 'Continue' }
$commonPath = Join-Path -Path $PSScriptRoot -ChildPath 'OtAssetCommon.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    Write-Error -Message "Required helper file 'OtAssetCommon.ps1' was not found in '$PSScriptRoot'. Keep New-OtAsset.ps1, Get-OtAssetTypes.ps1 and OtAssetCommon.ps1 in the same folder." -ErrorAction Continue
    exit 1
}
. $commonPath

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Error -Message 'An API key is required. Pass -ApiKey or set the ZN_API_KEY environment variable.' -ErrorAction Continue
    exit 1
}

$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ((Test-Path -LiteralPath $resolvedOutput) -and -not $Force) {
    Write-Error -Message "'$resolvedOutput' already exists; use -Force to overwrite." -ErrorAction Continue
    exit 1
}

try {
    $base = Get-ApiBaseUrl -ApiKey $ApiKey -PortalUrl $PortalUrl
    $types = @(Get-OtAssetTypeList -ApiBaseUrl $base -ApiKey $ApiKey)
}
catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    exit 1
}

$rows = [System.Collections.Generic.List[object]]::new()
$ambiguous = [System.Collections.Generic.List[string]]::new()
foreach ($t in $types) {
    $resolvedId = $null
    try {
        $resolvedId = Resolve-OtAssetType -Value $t.Name -TypeList $types -WarningAction SilentlyContinue
    }
    catch {
        $resolvedId = $null
    }

    if ($null -ne $resolvedId -and [int]$resolvedId -eq [int]$t.Id) {
        $typeValue = [string]$t.Name
    }
    else {
        $typeValue = [string]$t.Id
        $ambiguous.Add("'$($t.Name)' ($($t.Id))")
    }

    if ($IncludeId) {
        $rows.Add([pscustomobject]@{ type = $typeValue; id = $t.Id })
    }
    else {
        $rows.Add([pscustomobject]@{ type = $typeValue })
    }
}

if ($ambiguous.Count -gt 0) {
    Write-Warning "These type names are ambiguous after normalization, so their numeric IDs were written instead: $($ambiguous -join ', ')"
}

$exportParams = @{
    LiteralPath       = $resolvedOutput
    NoTypeInformation = $true
    Encoding          = 'utf8BOM'
    UseQuotes         = 'AsNeeded'
}
if ($Force) { $exportParams['Force'] = $true }

try {
    $rows | Export-Csv @exportParams
}
catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    exit 1
}

Write-Information "Wrote $($rows.Count) OT/IoT asset types to $resolvedOutput"

if ($PassThru) {
    $rows
}

exit 0
