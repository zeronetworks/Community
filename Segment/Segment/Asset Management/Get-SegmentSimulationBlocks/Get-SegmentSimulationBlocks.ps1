#requires -Module ZeroNetworks

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $true, ParameterSetName = "AllAssets")]
    [string]$ApiKey,

    [Parameter(Mandatory = $true, ParameterSetName = "ByAssetId")]
    [string]$AssetId,

    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [switch]$SkipLearningFilter,

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [ValidateSet("Incoming", "Outgoing")]
    [string]$Direction = "Incoming",

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [switch]$IgnorePendingRules,

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [ValidateSet("Both", "Internal", "External")]
    [string]$TrafficType = "Both",

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [string]$From
)

$ErrorActionPreference = "Stop"

function Test-ResponseForError {
    param(
        [Parameter(Mandatory = $true)]
        $Response
    )
    if($Response -is [ZeroNetworks.PowerShell.Cmdlets.Api.Models.Error]) {
        throw "ZeroNetworks API returned an error: $($Response | ConvertTo-Json -Compress | Out-String)"
    }
}

function Convert-IsoTimestampToMs {
    <#
    .SYNOPSIS
        Converts an ISO formatted timestamp string to a milliseconds integer timestamp.
    .PARAMETER IsoTimestamp
        ISO formatted timestamp string (e.g., "2024-01-15T12:00:00.000Z").
    .OUTPUTS
        Returns an integer representing the Unix timestamp in milliseconds.
    .NOTES
        This function parses the ISO timestamp and converts it to Unix epoch milliseconds.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$IsoTimestamp
    )
    
    $DateTimeOffset = [DateTimeOffset]::Parse($IsoTimestamp)
    return $DateTimeOffset.ToUnixTimeMilliseconds()
}

function Convert-MsTimestampToIso {
    <#
    .SYNOPSIS
        Converts a milliseconds integer timestamp to an ISO formatted timestamp string.
    .PARAMETER MsTimestamp
        Integer representing the Unix timestamp in milliseconds (e.g., 1766466000000).
    .OUTPUTS
        Returns a string representing the ISO formatted timestamp (e.g., "2024-01-15T12:00:00.000Z").
    .NOTES
        This function converts a Unix epoch milliseconds timestamp to ISO 8601 format.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [long]$MsTimestamp
    )
    
    $DateTimeOffset = [DateTimeOffset]::FromUnixTimeMilliseconds($MsTimestamp)
    return $DateTimeOffset.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Invoke-ZeroNetworksApiCall {
    <#
    .SYNOPSIS
        Makes an API call to ZeroNetworks API and validates the response.
    .PARAMETER Headers
        Hashtable containing HTTP headers for the API request (e.g., Authorization, Content-Type).
    .PARAMETER Method
        HTTP method to use for the API call (e.g., GET, POST, PUT, DELETE).
    .PARAMETER Url
        Full URL for the API endpoint.
    .PARAMETER Body
        Hashtable or object containing the request body. Will be converted to JSON if provided.
    .OUTPUTS
        Returns the response from the API call if successful.
    .NOTES
        This function validates that the response is successful (HTTP status code 200-299) and throws an error if not.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $false)]
        $Body
    )

    try {
        #Write-Host "Invoking API call to $Url with method $Method" -ForegroundColor Green
        $InvokeParams = @{
            Uri = $Url
            Method = $Method
            Headers = $Headers
            ErrorAction = "Stop"
        }

        if ($Body) {
            $BodyJson = $Body | ConvertTo-Json -Depth 10
            $InvokeParams.Body = $BodyJson
        }

        $Response = Invoke-RestMethod @InvokeParams
        return $Response
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        $ErrorMessage = $_.Exception.Message
        
        if ($_.ErrorDetails.Message) {
            $ErrorMessage = $_.ErrorDetails.Message
        }
        
        throw "API call failed with status code $StatusCode : $ErrorMessage"
    }
}

function Get-RequiredZnAssets {
    param(
        [Parameter(Mandatory = $false)]
        [string]$AssetId,
        [Parameter(Mandatory = $false)]
        [switch]$SkipLearningFilter
    )

    # Get by AssetId if one provided
    if ($AssetId) {
        Write-Host "Getting only single asset by id: $($AssetId)" -ForegroundColor Green
        $Assets = Get-ZnAsset -AssetId $AssetId
        Test-ResponseForError -Response $Assets
    }
    else {
            if ($SkipLearningFilter) {
            Write-Host "Getting all assets (skipping filtering for only assets in learning mode)!" -ForegroundColor Red
            $Response = Get-ZnAsset -Limit 300
        } else {
            # Create filter that will only return assets that are in learning mode
            $FilterHashTable = @(
                @{
                    "id"            = "protectionStatus"
                    "includeValues" = @("5","10","11","12","13","14","15","16","17","18")
                    "excludeValues" = @()
                }
            )
            $FiltersJson = $FilterHashTable | ConvertTo-Json -Depth 10 -AsArray -Compress
            Write-Host "Getting all assets currently in learning mode" -ForegroundColor Green
            $Response = Get-ZnAsset -Limit 300 -Filters $FiltersJson
        }
        Test-ResponseForError -Response $Response
        $Assets = $Response.Items

        while($Assets.Count -lt $Response.Count) {
            if ($SkipLearningFilter) {
                $Response = Get-ZnAsset -Limit 300 -Offset $Response.NextOffset
            } else {
                $Response = Get-ZnAsset -Limit 300 -Filters $FiltersJson -Offset $Response.NextOffset
            }
            Test-ResponseForError -Response $Response
            $Assets = $Assets + $Response.Items
        }

        Write-Host "Retrieved $($Assets.Count) assets" -ForegroundColor Green

    }
    return $Assets
}


function Get-AssetSegmentSimulationResults {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AssetId,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Incoming", "Outgoing")]
        [string]$Direction = "Incoming",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Both", "Internal", "External")]
        [string]$TrafficType = "Both",

        [Parameter(Mandatory = $false)]
        [bool]$IgnorePendingRules = $false,

        [Parameter(Mandatory = $true)]
        [Int64]$From
    )

    # Create mapping hash tables for Direction and TrafficType
    $DirectionToDirectionCode = @{
        "Incoming" = 1
        "Outgoing" = 2
    }

    $TrafficTypeToTrafficTypeCode = @{
        "Internal" = 1
        "External" = 2
        "Both"     = 3
    }

    # Convert Direction and TrafficType to their corresponding codes
    $DirectionCode = $DirectionToDirectionCode[$Direction]
    $TrafficTypeCode = $TrafficTypeToTrafficTypeCode[$TrafficType]

    # Create the full URL, including the API endpoint for segment simulation
    $FullUrl = "$Script:ApiUrl/protection/$AssetId/simulate-access"

    # Set up rule states
    $RuleStates = @(
        1 # Enabled rules
        2 # Pending rules
    )
    if ($IgnorePendingRules) {
        $RuleStates.Remove(2) # Pending rules
    }

    # Create body
    $BodyHashTable = @{
        "from" = $From
        "direction" = $DirectionCode
        "trafficType" = $TrafficTypeCode
        "ruleStates" = $RuleStates
    }

    if ($FullUrl.contains("dev")) {
        Write-Host "Running in development environment, using early access request body syntax (removing ruleStates, using includePendingRules instead)" -ForegroundColor DarkYellow
        $BodyHashTable.Add("includePendingRules", $IgnorePendingRules)
        $BodyHashTable.Remove("ruleStates")
    }

    $Response = Invoke-ZeroNetworksApiCall -Headers $Script:Headers -Method POST -Url $FullUrl -Body $BodyHashTable
    Test-ResponseForError -Response $Response
    return $Response.items

   
}


<#
MAIN SCRIPT EXECUTION BEGINS HERE
#>

# Display Zero Networks ASCII art banner
Write-Host @"
.---------------------------------------------------------------------------------.
|                                                                                 |
|                                                                                 |
|   /\/|  _____                _   _      _                      _          /\/|  |
|  |/\/  |__  /___ _ __ ___   | \ | | ___| |___      _____  _ __| | _____  |/\/   |
|          / // _ | '__/ _ \  |  \| |/ _ | __\ \ /\ / / _ \| '__| |/ / __|        |
|         / /|  __| | | (_) | | |\  |  __| |_ \ V  V | (_) | |  |   <\__ \        |
|        /____\___|_|  \___/  |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_|___/        |
|                                                                                 |
|                                                                                 |
'---------------------------------------------------------------------------------'
"@ -ForegroundColor DarkBlue
Write-Host ""


# Set API Key for ZeroNetworks module - If key invalid, this will throw an error
Set-ZnApiKey -ApiKey $ApiKey
Write-Host "API Key set successfully" -ForegroundColor Green

<#
 Try to extract environment details from API Key, and configure HTTP headers 
 and API URL for custom API calls that are not supported by the ZeroNetworks module
#>
$TokenDetails = Read-ZNJWTtoken -token $ApiKey
if (-not ($TokenDetails.e_name -and $TokenDetails.aud)) {
    throw "Failed to extract environment details from API Key"
}
else {
    $Environment = $TokenDetails.e_name
    $BaseUrl = $TokenDetails.aud
    Write-Host "Extracted environment details from API Key:" -ForegroundColor Green
    Write-Host "Environment: $($Environment)`nBase URL: $($BaseUrl)" -ForegroundColor Cyan

    $Script:ApiUrl = "https://$BaseUrl/api/v1"
    $Script:Headers = @{
        "Authorization" = "$($ApiKey)"
        "Content-Type"  = "application/json"
    }
    Write-Host "Configured HTTP headers and API URL for custom API calls" -ForegroundColor Green  
}

# Calculate From timestamp if not provided (default to 7 days ago)
if (-not $From) {
    $From = (Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-Host "From timestamp not provided, using -From value of 7 days ago: $From" -ForegroundColor Yellow
}

# Convert $From ISO timestamp string to milliseconds integer timestamp
$FromMsTimestamp = Convert-IsoTimestampToMs -IsoTimestamp $From
Write-Host "Converted From timestamp to milliseconds: $FromMsTimestamp" -ForegroundColor Green

# Retrieve the relevant assets using ZeroNetworks module. 
# If AssetId is provided, retrieve only the single asset with that ID.
# If AssetId is not provided, retrieve all assets currently in learning mode.
if ($AssetId) {
    $Assets = @(Get-RequiredZnAssets -AssetId $AssetId)
}
else {
    $Assets = Get-RequiredZnAssets -SkipLearningFilter:$SkipLearningFilter
}

# Iterate over all retrieve assets and run segment simulation for each asset
foreach ($Asset in $Assets) {
    $Results = @(Get-AssetSegmentSimulationResults -AssetId $Asset.EntityId -Direction $Direction -TrafficType $TrafficType -IgnorePendingRules:$IgnorePendingRules -From $FromMsTimestamp)
    Write-Host "Segment simulation results for asset $($Asset.EntityId):" -ForegroundColor Green
}