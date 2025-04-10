<#
.DESCRIPTION
This PowerShell script will take inputs for an asset name and risk score to automatically quarantine based on a pre-selected threshold.

.PARAMETER APIKey
This key is created by you within the Zero Networks portal of your tenant. It is tenant-specific. This script requires a read-write key.

.PARAMETER AssetName
This is the name as it appears within the Assets of Zero Networks portal. From this, we look up the Asset ID and use that to quarantine the asset.

.SYNOPSIS
Quarantines an asset in the Zero Networks portal based on its name and risk score, using the provided API key and a predefined risk threshold.
#>

param (
    [string]$AssetName,
    [int]$RiskScore,
    [string]$APIKey = $Env:ZN_API_KEY
)

if (-not $APIKey) {
    Write-Host "An API key is required for this operation. It can be passed to this script or read from the environment variable ZN_API_KEY."
    Exit 1
}

###################################################################
# If the tenant variable is set, we'll use a specific tenant URL  #
# for API resources. This should only be set if your API settings #
# within the portal show your company name in the API URL.        #
# Anything less than or equal to the risky score will be          #
# quarantined.                                                    #
###################################################################
$tenant = ""
$risky = 4

if ($tenant) {
    $tenantHost = "$tenant-admin"
    Write-Host "Using $tenant"
} else { 
    $tenantHost = "portal"
}

$BaseUrl = "https://$tenantHost.zeronetworks.com/api/v1"

# Resolve the asset name to an asset ID
$AssetSearchEndpoint = "$BaseUrl/assets"
$Headers = @{
    "Authorization" = $ApiKey
    "Content-Type"  = "application/json"
    "accept" = "application/json"
}

$body = @{
    "_limit" = 1
    "_offset" = 0
    "_filters" = '[{"id":"name","includeValues":["'+$AssetName+'"],"excludeValues":[]}]'
    "with_count" = 'true'
    "order" = 'asc'
    'orderColumns[]' = 'name'
    "showInactive" = 'false'
}

try {
    $Assets = Invoke-RestMethod -Uri $AssetSearchEndpoint -Method Get -Headers $Headers -Body $body

    if (-not $Assets) {
        Write-Host "Asset with name '$AssetName' not found." -ForegroundColor Red
        exit
    }

    $Asset = $Assets.items
} catch {
    Write-Host "Failed to retrieve asset information. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# Check the risk score threshold
if ($RiskScore -le $risky) {
    Write-Host "Attempting to quarantine host $($Asset.fqdn) with asset ID: `"$($Asset.id)`""
    $Endpoint = "$BaseUrl/assets/$($Asset.id)/actions/quarantine"

    $body = @{ 'quarantine' = 'true' }

    try {
        $Response = Invoke-RestMethod -Uri $Endpoint -Method Put -Headers $Headers -Body (ConvertTo-Json $body)
        Write-Host "Asset with name '$AssetName' has been successfully quarantined." -ForegroundColor Green
    } catch {
        Write-Host "Failed to quarantine the asset. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "Risk score is greater than $risky. No action taken." -ForegroundColor Yellow
}