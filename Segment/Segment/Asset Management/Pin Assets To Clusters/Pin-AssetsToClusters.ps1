<#
.SYNOPSIS
    Manages asset-to-deployment-cluster assignments in Zero Networks Segment.

.DESCRIPTION
    This script provides functionality to pin or unpin assets to deployment clusters in Zero Networks Segment.
    It supports individual asset operations, bulk operations via CSV file, listing deployment clusters,
    and exporting CSV templates. The script includes comprehensive validation, and dry-run mode for previewing changes.

.PARAMETER ApiKey
    Zero Networks API key with appropriate permissions. Required for all operations except ExportCsvTemplate.

.PARAMETER PortalUrl
    Base URL for the Zero Networks portal. Defaults to https://portal.zeronetworks.com.

.PARAMETER AssetId
    Asset ID to pin or unpin. Required for ByAssetId parameter set.

.PARAMETER OUPath
    Organizational Unit (OU) path to pin or unpin all assets within. Required for ByOuPath parameter set.

.PARAMETER DisableNestedOuResolution
    Disables nested OU resolution when pinning/unpinning assets by OU path. Defaults to false.

.PARAMETER DeploymentClusterId
    Deployment cluster ID to pin/unpin assets to. Required for ByAssetId and ByOuPath parameter sets.

.PARAMETER Unpin
    Switch to unpin assets instead of pinning them. Available for ByAssetId, ByOuPath, and ByCsvPath parameter sets.

.PARAMETER SkipSegmentServerValidation
    Skip validation that deployment clusters have online segment servers. Available for ByAssetId, ByOuPath, and ByCsvPath parameter sets.

.PARAMETER DryRun
    Preview changes without applying them. Available for ByAssetId, ByOuPath, and ByCsvPath parameter sets.

.PARAMETER StopOnAssetValidationError
    Stop processing and throw an error when asset validation fails. Available for ByOuPath and ByCsvPath parameter sets.

.PARAMETER ListDeploymentClusters
    Switch to list all deployment clusters with detailed information.

.PARAMETER CsvPath
    Path to CSV file containing assets to pin/unpin. Required for ByCsvPath parameter set.

.PARAMETER ExportCsvTemplate
    Switch to export a CSV template file for bulk operations.

.PARAMETER EnableDebug
    Enables debug output. When provided, sets $DebugPreference to Continue. When not provided, sets $DebugPreference to SilentlyContinue.

.NOTES
    Requires PowerShell 7.0 or higher.
    Large CSV files are automatically processed in batches of 50 assets.

.EXAMPLE
    .\Pin-AssetsToClusters.ps1 -ApiKey "your-api-key" -AssetId "a:a:qvI6tVtn" -DeploymentClusterId "C:d:00fd409f"
    Pins a single asset to a deployment cluster.

.EXAMPLE
    .\Pin-AssetsToClusters.ps1 -ApiKey "your-api-key" -CsvPath ".\assets.csv" -Unpin
    Unpins multiple assets from deployment clusters using a CSV file.

.EXAMPLE
    .\Pin-AssetsToClusters.ps1 -ApiKey "your-api-key" -CsvPath ".\assets.csv" -DryRun
    Previews what changes would be made without actually applying them.

.EXAMPLE
    .\Pin-AssetsToClusters.ps1 -ApiKey "your-api-key" -OUPath "OU=Computers,DC=domain,DC=com" -DeploymentClusterId "C:d:00fd409f"
    Pins all assets within the specified OU path to a deployment cluster.
#>

<#PSScriptInfo
.VERSION 1.0
.AUTHOR Thomas Obarowski (https://www.linkedin.com/in/tjobarow/)
.TAGS Automation Scripts
#>

#requires -Version 7.0

[CmdletBinding(DefaultParameterSetName = "ByAssetId")]
param(
    # Shared parameter for sets that require authentication
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $true)]
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $true)]
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $true)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $false)]
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [string]$PortalUrl = "https://portal.zeronetworks.com",
    
    # ParameterSet 1: Pin by Asset ID and Deployment Cluster ID
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $true)]
    [string]$AssetId,
    
    # ParameterSet: Pin by OU Path and Deployment Cluster ID
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $true)]
    [string]$OUPath,
    
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $false)]
    [switch]$DisableNestedOuResolution = $false,
    
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $true)]
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $true)]
    [string]$DeploymentClusterId,
    
    # Shared switch parameter for unpinning (available in ByAssetId, ByOuPath, and ByCsvPath sets)
    [Parameter(ParameterSetName = "ByAssetId")]
    [Parameter(ParameterSetName = "ByOuPath")]
    [Parameter(ParameterSetName = "ByCsvPath")]
    [switch]$Unpin,
    
    # Shared switch parameter to skip segment server validation (available in all sets with ApiKey)
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [switch]$SkipSegmentServerValidation,
    
    # Shared switch parameter for dry run mode (available in all sets with ApiKey)
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [switch]$DryRun,
    
    # Switch parameter to stop on asset validation error (available in ByOuPath and ByCsvPath sets)
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [switch]$StopOnAssetValidationError,
    
    # ParameterSet 2: List Deployment Clusters
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $true)]
    [switch]$ListDeploymentClusters,
    
    # ParameterSet 3: Pin from CSV file
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $true)]
    [string]$CsvPath,
    
    # ParameterSet 4: Export CSV Template
    [Parameter(ParameterSetName = "ExportCsvTemplate", Mandatory = $true)]
    [switch]$ExportCsvTemplate,
    
    # Shared switch parameter for debug output (available in all parameter sets)
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByOuPath", Mandatory = $false)]
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [Parameter(ParameterSetName = "ExportCsvTemplate", Mandatory = $false)]
    [switch]$EnableDebug
)
$ErrorActionPreference = "Stop"

# Set DebugPreference based on EnableDebug switch parameter
if ($EnableDebug) {
    $DebugPreference = "Continue"
    Write-Debug "Debug output enabled"
}
else {
    $DebugPreference = "SilentlyContinue"
}

# Script-wide deployment cluster field mappings hashtable
# Maps numeric status codes to human-readable values for strategy, status, state, and service IDs
# Used by Invoke-DecodeDeploymentClusterIDFields to convert API responses to readable format
$script:DeploymentClusterFieldMappings = @{
    "strategy" = @{
        "byId" = @{
            "0" = "CLUSTER_STRATEGY_UNSPECIFIED"
            "1" = "Active / Passive"
            "2" = "Active / Active"
        }
        "byName" = @{
            "CLUSTER_STRATEGY_UNSPECIFIED" = 0
            "Active / Passive" = 1
            "Active / Active" = 2
            "ACTIVE_PASSIVE" = 1
            "ACTIVE_ACTIVE" = 2
        }
    }
    "assignedDeployments.status" = @{
        "byId" = @{
            "0" = "DEPLOYMENT_STATUS_UNSPECIFIED"
            "1" = "Offline"
            "2" = "Online"
            "3" = "Network disconnected"
        }
        "byName" = @{
            "DEPLOYMENT_STATUS_UNSPECIFIED" = 0
            "Offline" = 1
            "Online" = 2
            "Network disconnected" = 3
        }
    }
    "assignedDeployments.state" = @{
        "byId" = @{
            "0" = "DEPLOYMENT_STATE_UNSPECIFIED"
            "1" = "Primary"
            "2" = "Secondary"
        }
        "byName" = @{
            "DEPLOYMENT_STATE_UNSPECIFIED" = 0
            "Primary" = 1
            "Secondary" = 2
            "DEPLOYMENT_STATE_PRIMARY" = 1
            "DEPLOYMENT_STATE_SECONDARY" = 2
        }
    }
    "assignedDeployments.servicesInfo.serviceId" = @{
        "byId" = @{
            "0" = "SERVICE_ID_UNSPECIFIED"
            "1" = "ad"
            "2" = "winrm"
            "3" = "ansible-manager"
        }
        "byName" = @{
            "SERVICE_ID_UNSPECIFIED" = 0
            "ad" = 1
            "winrm" = 2
            "ansible-manager" = 3
            "SERVICE_ID_AD" = 1
            "SERVICE_ID_WINRM" = 2
            "SERVICE_ID_ANSIBLE_MANAGER" = 3
        }
    }
    "assignedDeployments.servicesInfo.status" = @{
        "byId" = @{
            "0" = "DEPLOYMENT_STATUS_UNSPECIFIED"
            "1" = "Offline"
            "2" = "Online"
            "3" = "Network disconnected"
        }
        "byName" = @{
            "DEPLOYMENT_STATUS_UNSPECIFIED" = 0
            "Offline" = 1
            "Online" = 2
            "Network disconnected" = 3
        }
    }
    "assignedDeployments.servicesInfo.state" = @{
        "byId" = @{
            "0" = "DEPLOYMENT_STATE_UNSPECIFIED"
            "1" = "Primary"
            "2" = "Secondary"
        }
        "byName" = @{
            "DEPLOYMENT_STATE_UNSPECIFIED" = 0
            "Primary" = 1
            "Secondary" = 2
            "DEPLOYMENT_STATE_PRIMARY" = 1
            "DEPLOYMENT_STATE_SECONDARY" = 2
        }
    }
}

# Initalize a few data structures that are used throughout the script
$script:SegmentServerHashtable = $null
$script:DeploymentClusterHashtable = $null

<#
This section of the script contains all of the
asset related functions in the script
#>


<#
    .SYNOPSIS
        Validates multiple assets to determine if they can be pinned or unpinned to deployment clusters.
    .PARAMETER Assets
        ArrayList of asset objects to validate.
    .PARAMETER AssetMustBePinned
        If specified, validates that assets are already pinned (for unpinning operations).
    .PARAMETER StopOnAssetValidationError
        If specified, throws an error and terminates the script if any asset fails validation.
    .OUTPUTS
        Returns an ArrayList of asset objects that passed validation.
    .NOTES
        Filters out segment servers automatically. If StopOnAssetValidationError is set and any asset fails validation, the script will exit with an error.
    #>
function Test-ValidateProvidedAssetsCanBePinned {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Assets,
        [Parameter(Mandatory = $false)]
        [switch]$AssetMustBePinned,
        [Parameter(Mandatory = $false)]
        [switch]$StopOnAssetValidationError
    )
    # Validate each asset can be pinned/unpinned. Keep a track of any assets that pass or fail validation.
    # If the -StopOnAssetValidationError switch is provided, throw an error if any asset fails validation,
    # which will cause the script to exit with a non-zero exit code.
    [System.Collections.ArrayList]$AssetsPassedValidation = @()
    [System.Collections.ArrayList]$AssetsFailedValidation = @()
    foreach ($asset in $Assets) {
        if ($script:SegmentServerHashtable.ContainsKey($asset.id)) {
            Write-Warning "Asset $($asset.name) ($($asset.id)) is a segment server. Segment servers cannot be pinned to a deployment cluster. Ignoring this asset!"
            continue
        }

        try {
            Test-AssetCanBePinned -AssetId $asset.id -AssetMustBePinned:$AssetMustBePinned
            $AssetsPassedValidation.Add($asset) | Out-Null
        }
        catch {
            $errorMessage = "Failed to validate asset $($asset.name) ($($asset.id)): $_"
            Write-Warning "$errorMessage. Continuing..."
            $asset | Add-Member -MemberType NoteProperty -Name "ErrorMessage" -Value $_
            $AssetsFailedValidation.Add($asset) | Out-Null
            continue
        }
    }

    if ($AssetsFailedValidation.Count -gt 0) {
        Write-Warning "Failed to validate $($AssetsFailedValidation.Count)/$($Assets.Count) assets. Check list below for details."
        $AssetsFailedValidation | Format-Table -Property name, id, ErrorMessage | Out-String | Write-Warning
        if ($StopOnAssetValidationError) {
            throw "At least one asset failed validation! Terminating script due to -StopOnAssetValidationError being set"
        }
    }

    if ($AssetsPassedValidation.Count -eq 0) {
        Write-Host "No assets to pin/unpin. Exiting..."
        exit 0
    }

    Write-Host "Validated that $($AssetsPassedValidation.Count) assets can be $($Unpin ? "unpinned" : "pinned") to deployment cluster"
    return $AssetsPassedValidation

}

<#
    .SYNOPSIS
        Validates that an asset can be pinned or unpinned to a deployment cluster.
    .PARAMETER AssetId
        The asset ID to validate.
    .PARAMETER AssetMustBePinned
        If specified, validates that the asset is already pinned (for unpinning operations).
    .OUTPUTS
        None. Throws an exception if validation fails.
    .NOTES
        Throws an exception if validation fails. The order of validation checks is important.
    #>
function Test-AssetCanBePinned {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AssetId,
        [Parameter(Mandatory = $false)]
        [switch]$AssetMustBePinned
    )
    # Get asset details from portal API
    $AssetDetails = Get-AssetDetails -AssetId $AssetId

    <#
    AssetIsPinnedDeploymentClusterStatus:
    0 --> ASSIGNED_ASSET_DEPLOYMENTS_CLUSTER_SOURCE_UNKNOWN
    1 --> SYSTEM
    2 --> USER
    3 --> DOMAIN
    4 --> SUBNET
    5 --> NONE
    6 --> NOT_APPLICABLE
    ===============================================
    # 0-4 --> Asset is pinned to a deployment cluster
    # 5 --> Asset is not pinned to a deployment cluster
    # 6 --> Asset is not applicable to be pinned to a deployment cluster
    #>
    $AssetIsPinnedDeploymentClusterSource = @(0,1,2,3,4)
    
    # Validation order is important - check prerequisites first, then state
    # 1st: Check if asset is a segment server
    if ($script:SegmentServerHashtable.ContainsKey($AssetDetails.id)) {
        throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is a segment server. Segment servers cannot be pinned to a deployment cluster."
    }

    # 2nd: Check if asset is monitored by a Segment Server (assetStatus = 2)
    if ($AssetDetails.assetStatus -ne 2) {
        throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not monitored by a Segment Server (e.g uses Cloud Connector, Lightweight Agent). Only hosts monitored by a Segment Server can be pinned to a deployment cluster."
    }
    
    # 3rd: Check if asset is healthy (healthStatus = 1)
    if ($AssetDetails.healthState.healthStatus -ne 1) {
        throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not healthy! Please check the asset health in the portaland try again."
    }
    
    # 4th: Check if asset is applicable for pinning (deploymentsClusterSource != 6)
    if ($AssetDetails.deploymentsClusterSource -eq 6) {
        throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) applicable to be pinned to a deployment cluster"
    }
    
    # 5th: For unpinning, verify asset is already pinned
    if ($AssetMustBePinned) {
        if (-not ($AssetIsPinnedDeploymentClusterSource -contains $AssetDetails.deploymentsClusterSource)) {
            throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not pinned to a deployment cluster! It must be pinned to a deployment cluster to be unpinned."
        }
    }
    # 6th: For pinning, verify asset is not already pinned
    else {
        if ($AssetIsPinnedDeploymentClusterSource -contains $AssetDetails.deploymentsClusterSource) {
            throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is already pinned to Deployment Cluster ID: $($AssetDetails.deploymentsCluster.id) - Deployment Cluster Name: $($AssetDetails.deploymentsCluster.name) - Segment Server ID: $($AssetDetails.assignedDeployment.id) - Segment Server Name: $($AssetDetails.assignedDeployment.name)"
        }
    }
    
    Write-Host "Validated that asset $($AssetDetails.name) ($($AssetDetails.id)) can be $($Unpin ? "unpinned" : "pinned") to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
}

<#
    .SYNOPSIS
        Retrieves detailed information about an asset from the Zero Networks API.
    .PARAMETER AssetId
        The asset ID to retrieve details for.
    .OUTPUTS
        Returns the asset entity object from the API response.
    .NOTES
        Throws an exception if the asset is not found or if the API response is malformed.
    #>
function Get-AssetDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AssetId
    )
    Write-Debug "Getting asset details for asset ID: $AssetId"
    try {
        $response = Invoke-ApiRequest -Method "GET" -ApiEndpoint "assets/$AssetId"
        if ($null -eq $response.entity) {
            throw "Asset details response is malformed and does not contain 'entity' property"
            
        }
        Write-Debug "Found asset details for $($response.entity.name) - $AssetId"
        return $response.entity
    }
    catch {
        if ($null -ne $_.Exception.StatusCode -and ($_.Exception.StatusCode -eq 404)) {
            throw "Asset with ID $AssetId was not found"
            
        }
        else {
            throw $_
            
        }
    }
}

<#
    .SYNOPSIS
        Retrieves Organizational Unit (OU) entity information from the Zero Networks API.
    .PARAMETER OUPath
        The OU path to retrieve information for (e.g., "OU=Computers,DC=domain,DC=com").
    .OUTPUTS
        Returns the OU entity object from the API response.
    .NOTES
        Throws an exception if the OU is not found or if the API response is malformed.
    #>
function Get-OUInfoFromApi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OUPath
    )
    Write-Host "Finding OU entity information for: $OUPath"
    try {
        # Build filter array for API query - filters OUs by name matching the provided OU path
        # The API expects filters in a specific JSON format: array of filter objects with 'id' and 'includeValues'
        $FilterArray = @(
            @{
                id = "name"
                includeValues = @(
                    $OUPath
                )
            }
        )
        # Convert filter array to JSON string format required by the API
        # -AsArray ensures it's formatted as a JSON array, -Depth 10 handles nested objects
        $FilterJson = $FilterArray | ConvertTo-Json -Compress -AsArray -Depth 10
       
        # Build query parameters for the API request
        $QueryParams = @{
            _limit = 100
            with_count = $true
            _filters = $FilterJson
        }
       
        # Query the OU groups endpoint with pagination support
        $response = Invoke-PaginatedApiRequest -Method "GET" -ApiEndpoint "/groups/ou" -QueryParams $QueryParams

        Write-Debug "OU response body: $($response | ConvertTo-Json -Compress -Depth 10)"
        
        # Validate response structure
        if ($null -eq $response.items) {
            throw "API response is malformed and does not contain 'items' property"
        }

        # If response.items is empty (count = 0)
        if ($response.items.Count -eq 0) {
            throw "Could not find OU: $OUPath"
        }
        
        foreach ($item in $response.items) {
            if ($item.name -eq $OUPath) {
                Write-Host "Found matched OU entity ($($item.id)) for provided OU path: $OUPath"
                return $item
            }
        }

        # If it makes it here, none of the returned OUs match the provided OU path
        throw "API did not return any OUs that match the provided OU path ($OUPath).`nAPI returned OUs: $($response.items.name -join ' /// ')"
    }
    catch {
        throw "Failed to retrieve information for $OUPath : $_"
    }
}

<#
    .SYNOPSIS
        Retrieves all assets within a specified Organizational Unit (OU) from the Zero Networks API.
    .PARAMETER EntityId
        The OU entity ID to retrieve assets for.
    .PARAMETER OUPath
        The OU path (optional, used for display purposes only).
    .PARAMETER DisableNestedOuResolution
        If specified, disables nested OU resolution and only returns direct members.
    .OUTPUTS
        Returns an array of asset entity objects that belong to the OU.
    .NOTES
        Filters out identities and only returns assets. Throws an exception if no assets are found or if the API response is malformed.
    #>
function Get-AssetsFromOU {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EntityId,
        [Parameter(Mandatory = $false)]
        [string]$OUPath,
        [Parameter(Mandatory = $false)]
        [switch]$DisableNestedOuResolution
    )
    Write-Host "Getting assets for OU Path: $OUPath (Entity ID: $EntityId)"
    Write-Debug "Will retrieve nested OU member? $($DisableNestedOuResolution ? "No" : "Yes")"
    try {

        $QueryParams = @{
            _limit = 100
            includeNestedMembers = $DisableNestedOuResolution ? "false" : "true"
        }

        # Query groups API with Entity ID filter
        $response = Invoke-PaginatedApiRequest -Method "GET" -ApiEndpoint "groups/ou/$EntityId/successors" -QueryParams $QueryParams

        Write-Debug "Assets from OU response body: $($response | ConvertTo-Json -Compress -Depth 10)"

        # Validate response structure
        if ($null -eq $response.items) {
            throw "API response is malformed and does not contain 'items' property"
        }

        # The successors endpoint will return both identities and assets. We only want assets.
        # It seems all assets will have an assetType property, but identities will not.
        $Assets = $response.items | Where-Object { $null -ne $_.assetType }        

        # If response.items is empty (count = 0)
        if ($Assets.Count -eq 0) {
            throw "No assets found in OU: $OUPath"
        }
        
        Write-Host "Retrieved $($Assets.Count) assets from OU: $OUPath"
        return $Assets
    }
    catch {
        throw "Failed to get assets from OU: $OUPath : $_"
    }
}

<#
    .SYNOPSIS
        Pins or unpins assets to a deployment cluster in batches for efficient processing.
    .PARAMETER AssetsPassedValidation
        ArrayList of asset objects that have passed validation and are ready to be pinned/unpinned.
    .PARAMETER DeploymentClusterId
        The deployment cluster ID to pin/unpin assets to.
    .PARAMETER Unpin
        If specified, unpins assets from the deployment cluster. Otherwise, pins them.
    .PARAMETER DryRun
        If specified, previews the operation without making API calls.
    .OUTPUTS
        None. Writes progress messages to the console.
    .NOTES
        Automatically batches assets into groups of 50 for large asset lists to optimize API performance.
    #>
function Invoke-BatchBasedClusterPinning {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$AssetsPassedValidation,
        [Parameter(Mandatory = $true)]
        [string]$DeploymentClusterId,
        [Parameter(Mandatory = $false)]
        [switch]$Unpin,
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    if ($AssetsPassedValidation.Count -eq 0) {
        Write-Host "No assets to pin/unpin. Exiting..."
        exit 0
    }

    $totalAssets = $AssetsPassedValidation.Count
    Write-Host "$($Unpin ? "Unpinning" : "Pinning") $totalAssets assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
    
    # Batch processing for large asset lists (>50 assets)
    # The API performs better with smaller batches, so we split large lists into batches of 50
    if ($totalAssets -gt 50) {
        $batchSize = 50
        $batchNumber = 1
        # Calculate total number of batches needed (round up)
        $totalBatches = [math]::Ceiling($totalAssets / $batchSize)
        
        # Process assets in batches
        for ($i = 0; $i -lt $totalAssets; $i += $batchSize) {
            # Create batch using array slicing: get items from index $i to the minimum of ($i + batchSize - 1) or (totalAssets - 1)
            # This ensures we don't go beyond the array bounds on the last batch
            $endIndex = [math]::Min($i + $batchSize - 1, $totalAssets - 1)
            $batch = [System.Collections.ArrayList]@($AssetsPassedValidation[$i..$endIndex])
            Write-Host "Processing batch $batchNumber of $totalBatches ($($batch.Count) assets)..."
            Set-AssetsToDeploymentCluster -Assets $batch -DeploymentClusterId $DeploymentClusterId -Unpin:$Unpin -DryRun:$DryRun
            if (-not $DryRun) {
                Write-Host "Successfully $($Unpin ? "unpinned" : "pinned") $($batch.Count) assets to deployment cluster $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
            }
            $batchNumber++
        }
    }
    else {
        # Process all assets at once for smaller lists (50 or fewer assets)
        Set-AssetsToDeploymentCluster -Assets $AssetsPassedValidation -DeploymentClusterId $DeploymentClusterId -Unpin:$Unpin -DryRun:$DryRun
    }

}
<#
    .SYNOPSIS
        Pins or unpins assets to a deployment cluster via the Zero Networks API.
    .PARAMETER Assets
        ArrayList of asset objects to pin or unpin.
    .PARAMETER DeploymentClusterId
        The deployment cluster ID to pin/unpin assets to.
    .PARAMETER Unpin
        If specified, unpins assets from the deployment cluster. Otherwise, pins them.
    .PARAMETER DryRun
        If specified, previews the operation without making API calls.
    .OUTPUTS
        None. Writes success messages to the console.
    .NOTES
        In dry-run mode, displays the request body that would be sent but does not make the API call.
    #>
function Set-AssetsToDeploymentCluster {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Assets,
        [Parameter(Mandatory = $true)]
        [string]$DeploymentClusterId,
        [Parameter(Mandatory = $false)]
        [switch]$Unpin,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    # Extract asset IDs from asset objects - the API requires an array of asset ID strings
    $assetIds = @($Assets | ForEach-Object { $_.id })

    # Build request body for the API
    # For pinning: include both assetIds and deploymentsClusterId
    # For unpinning: only include assetIds (omitting deploymentsClusterId unpins the assets)
    $body = @{
        assetIds = $assetIds
    }
    if (-not $Unpin) {
        # Only add deploymentsClusterId when pinning (not when unpinning)
        $body.deploymentsClusterId = $DeploymentClusterId
    }
    
    Write-Debug "$($Unpin ? "Unpinning" : "Pinning") $($Assets.Count) assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
    
    if ($DryRun) {
        Write-Host "[DRY RUN] Would $($Unpin ? "unpin" : "pin") $($Assets.Count) assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
        Write-Host "[DRY RUN] Asset IDs that would be $($Unpin ? "unpinned" : "pinned"): $($Assets | Format-Table | Out-String)"
        Write-Host "[DRY RUN] Request body: $($body | ConvertTo-Json -Compress -Depth 10)"
    }
    else {
        Invoke-ApiRequest -Method "PUT" -ApiEndpoint "/assets/actions/deployments-cluster" -Body $body | Out-Null
        Write-Host "Successfully $($Unpin ? "unpinned" : "pinned") $($Assets.Count) assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
    }
}

<#
This section of the script contains functions related to 
deployment cluster operations.
#>

<#
    .SYNOPSIS
        Validates that a deployment cluster ID exists and optionally checks segment server status.
    .PARAMETER DeploymentClusterId
        The deployment cluster ID to validate.
    .PARAMETER SkipSegmentServerValidation
        If specified, skips validation of segment server assignment and online status.
    .OUTPUTS
        None. Throws an exception if the deployment cluster is not found or validation fails.
    .NOTES
        Throws an exception if the deployment cluster is not found or validation fails.
    #>
function Invoke-ValidateDeploymentClusterId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeploymentClusterId,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipSegmentServerValidation
    )
    Write-Host "Validating deployment cluster ID: $DeploymentClusterId"
    
    # Initialize deployment cluster hashtable, and segment server hashtable if not already done
    if ($null -eq $script:DeploymentClusterHashtable) {
        Get-DeploymentClusters | Out-Null
    }
    
    # Verify deployment cluster exists
    if (-not $script:DeploymentClusterHashtable.ContainsKey($DeploymentClusterId)) {
        throw "Deployment cluster ID $DeploymentClusterId not found"
    }

    # Get deployment cluster object for validation
    $deploymentCluster = $script:DeploymentClusterHashtable[$DeploymentClusterId]

    # Validate segment server assignment and status (unless skipped)
    if (-not $SkipSegmentServerValidation) {
        # Check that cluster has at least one assigned segment server
        if ($deploymentCluster.assignedDeployments.Count -eq 0) {
            throw "Deployment cluster `"$($deploymentCluster.name)`" ($DeploymentClusterId) has no segment servers assigned to it"
        }
        # Check that at least one segment server is online (status = "Online")
        if (($deploymentCluster.assignedDeployments | Where-Object {$_.status -eq "Online"}).Count -eq 0) {
            throw "Deployment cluster  `"$($deploymentCluster.name)`" ($DeploymentClusterId) has no online segment servers! Please check the segment server status in the portal and try again. If the segment server is online, please check the segment server health and try again."
        }
    }
    else {
        Write-Host "Skipping segment server validation"
    }
    Write-Host "Validated that deployment cluster `"$($deploymentCluster.name)`" ($DeploymentClusterId) exists in tenant"
}

<#
    .SYNOPSIS
        Retrieves all deployment clusters from the Zero Networks API and decodes field mappings.
    .OUTPUTS
        Returns an array of deployment cluster objects with decoded field values.
    .NOTES
        Automatically initializes the script-wide deployment cluster hashtable for validation purposes.
    #>
function Get-DeploymentClusters {
    Write-Host "Getting deployment clusters"
    $response = Invoke-ApiRequest -Method "GET" -ApiEndpoint "environments/cluster"
    
    # Validate response structure
    if (-not $response.items) {
        throw "Deployment clusters response is malformed and does not contain 'items' property"
    }
    if ($response.items.Count -eq 0) {
        throw "No deployment clusters found"
    }
    
    # Ensure items is an array (handle single item responses)
    if ($response.items -isnot [System.Array]) {
        $DeploymentClusters = @($response.items)
    }
    else {
        $DeploymentClusters = $response.items
    }

    # Decode numeric status codes to human-readable values
    $DeploymentClusters = Invoke-DecodeDeploymentClusterIDFields -DeploymentClusters $DeploymentClusters

    # Create hashtable for fast lookup by cluster ID
    New-DeploymentClusterHashtable -DeploymentClusters $DeploymentClusters

    # Create hashtable for fast lookup by segment server ID
    New-SegmentServerHashtable -DeploymentClusters $DeploymentClusters

    return $DeploymentClusters
}

<#
    .SYNOPSIS
        Creates a script-wide hashtable of deployment clusters indexed by cluster ID.
    .PARAMETER DeploymentClusters
        Array of deployment cluster objects to index.
    .OUTPUTS
        None. Creates a script-wide hashtable stored in $script:DeploymentClusterHashtable.
    .NOTES
        The hashtable is stored in $script:DeploymentClusterHashtable for script-wide access.
    #>
function New-DeploymentClusterHashtable {
    param(
        [Parameter(Mandatory = $true)]
        [System.Array]$DeploymentClusters
    )
    # Create hashtable indexed by cluster ID for O(1) lookup performance
    $script:DeploymentClusterHashtable = @{}
    foreach ($cluster in $DeploymentClusters){
        $DeploymentClusterHashtable[$cluster.id] = $cluster
    }
    Write-Debug "Created script-wide hashtable of deployment clusters"
    
}

<#
    .SYNOPSIS
        Creates a script-wide hashtable of segment servers indexed by asset ID.
    .PARAMETER DeploymentClusters
        Array of deployment cluster objects containing segment server information.
    .OUTPUTS
        None. Creates a script-wide hashtable stored in $script:SegmentServerHashtable.
    .NOTES
        The hashtable is stored in $script:SegmentServerHashtable for script-wide access. Used to quickly identify if an asset is a segment server.
    #>
function New-SegmentServerHashtable {
    param(
        [Parameter(Mandatory = $true)]
        [System.Array]$DeploymentClusters
    )
    # Create hashtable indexed by server ID for O(1) lookup performance
    $script:SegmentServerHashtable = @{}
    foreach ($cluster in $DeploymentClusters){
        foreach ($deployment in $cluster.assignedDeployments){
            $SegmentServerHashtable[$deployment.assetId] = $deployment
        }
    }
    Write-Debug "Created script-wide hashtable of segment servers"
}

<#
    .SYNOPSIS
        Decodes numeric status codes in deployment cluster objects to human-readable values.
    .PARAMETER DeploymentClusters
        Array of deployment cluster objects to decode.
    .OUTPUTS
        Returns the deployment clusters array with decoded field values.
    .NOTES
        Only decodes fields that are of type System.Int64. Other types are left unchanged.
    #>
function Invoke-DecodeDeploymentClusterIDFields {
    param(
        [Parameter(Mandatory = $true)]
        [System.Array]$DeploymentClusters
    )
    Write-Host "Decoding deployment cluster ID fields! (e.g Updating strategy=2 --> strategy=Active/Active)"
    
    # Decode cluster-level fields
    foreach ($cluster in $DeploymentClusters){
        # Decode strategy field (0=UNSPECIFIED, 1=Active/Passive, 2=Active/Active)
        if ($cluster.strategy.GetType() -eq [System.Int64]) {
            $cluster.strategy = $script:DeploymentClusterFieldMappings['strategy']['byId'][$cluster.strategy.ToString()]
        }

        # Decode deployment-level fields
        if ($cluster.assignedDeployments.Count -gt 0) {
            foreach ($deployment in $cluster.assignedDeployments){
                # Decode deployment status and state
                if ($deployment.status.GetType() -eq [System.Int64]) {
                    $deployment.status = $script:DeploymentClusterFieldMappings['assignedDeployments.status']['byId'][$deployment.status.ToString()]
                }
                if ($deployment.state.GetType() -eq [System.Int64]) {
                    $deployment.state = $script:DeploymentClusterFieldMappings['assignedDeployments.state']['byId'][$deployment.state.ToString()]
                }
                
                # Decode service-level fields
                if ($deployment.servicesInfo.Count -gt 0) {
                    foreach ($service in $deployment.servicesInfo){
                        if ($service.serviceId.GetType() -eq [System.Int64]) {
                            $service.serviceId = $script:DeploymentClusterFieldMappings['assignedDeployments.servicesInfo.serviceId']['byId'][$service.serviceId.ToString()]
                        }
                        if ($service.status.GetType() -eq [System.Int64]) {
                            $service.status = $script:DeploymentClusterFieldMappings['assignedDeployments.servicesInfo.status']['byId'][$service.status.ToString()]
                        }
                        if ($service.state.GetType() -eq [System.Int64]) {
                            $service.state = $script:DeploymentClusterFieldMappings['assignedDeployments.servicesInfo.state']['byId'][$service.state.ToString()]
                        }
                    }
                }
            }
        }
    }
    return $DeploymentClusters
}

<#
    .SYNOPSIS
        Displays deployment cluster information to the console in a formatted layout.
    .PARAMETER DeploymentClusters
        Array of deployment cluster objects to display.
    .OUTPUTS
        None. Writes formatted deployment cluster information to the console.
    .NOTES
        Output includes cluster name, ID, asset count, HA strategy, and detailed segment server information.
    #>
function Write-DeploymentClusters {
    param(
        [Parameter(Mandatory = $true)]
        [object]$DeploymentClusters
    )
    
    Write-Host "Writing deployment clusters information to console"
    foreach ($cluster in $DeploymentClusters){
        Write-Host $("="*(($Host.UI.RawUI.WindowSize.Width)/2))
        Write-Host "Deployment cluster: $($cluster.name)"
        Write-Host "Cluster ID: $($cluster.id)"
        Write-Host "Number of assets in cluster: $($cluster.numOfAssets)"
        Write-Host "HA Strategy: $(if ($cluster.strategy -eq 2) { "Active/Active" } else { "Active/Passive" })"
        Write-Host "Segment server deployments assigned to this cluster:"
        if ($cluster.assignedDeployments.Count -eq 0) {
            Write-Host "$(" "*2)No segment server deploments are assigned to this cluster"
        }
        else {
            Write-Host "$("~"*(($Host.UI.RawUI.WindowSize.Width)/4))"
            foreach ($deployment in $cluster.assignedDeployments){
                Write-Host "$(" "*2)Name: $($deployment.name)"
                Write-Host "$(" "*2)Deployment ID: $($deployment.id)"
                Write-Host "$(" "*2)Server Asset ID: $($deployment.assetId)"
                Write-Host "$(" "*2)Status: $($deployment.status)"
                Write-Host "$(" "*2)State: $($deployment.state)"
                Write-Host "$(" "*2)Num Assets Associated: $($deployment.numOfAssets)"
                Write-Host "$(" "*2)Internal IP Address: $($deployment.internalIpAddress)"
                Write-Host "$(" "*2)External IP Address: $($deployment.externalIpAddress)"
                Write-Host "$(" "*2)Segment Server Version: $($deployment.assemblyVersion)"
                Write-Host "$(" "*2)Is Preferred Deployment: $(if ($deployment.id -eq $cluster.preferredDeployment.id) { "Yes" } else { "No" })"
                Write-Host "$(" "*2)Deployment Services:"
                foreach ($service in $deployment.servicesInfo){
                    Write-Host "$(" "*4)--------------------------------"
                    Write-Host "$(" "*4)Service ID: $($service.serviceId)"
                    Write-Host "$(" "*4)Service Status: $($service.status)"
                    Write-Host "$(" "*4)Service State: $($service.state)"
                    Write-Host "$(" "*4)--------------------------------"
                }
                
                Write-Host "$(" "*2)$("-"*(($Host.UI.RawUI.WindowSize.Width)/4))"
            }
        }
        Write-Host $("="*(($Host.UI.RawUI.WindowSize.Width)/2))
    }
    Write-Host "Finished writing deployment clusters information to console"
    
}

<#
This section of the script is responsible for 
creating and exporting the CSV template.
#>

<#
    .SYNOPSIS
        Exports a CSV template file for bulk asset pinning operations.
    .OUTPUTS
        None. Creates a CSV template file in the current directory.
    .NOTES
        The template file is saved as "pin-assets-to-clusters-template.csv" in the current directory.
    #>
function Export-CsvTemplate {
    $template = [PSCustomObject]@{
        AssetName = $null
        AssetId = $null
        DeploymentClusterId = $null
    }
    $template | Export-Csv -Path ".\pin-assets-to-clusters-template.csv" -NoTypeInformation
    Write-Host "CSV Template exported to .\pin-assets-to-clusters-template.csv"
    Write-Host "Please fill in AT LEAST the AssetId, AssetName and DeploymentClusterId columns, and then run the script again with the -CsvPath parameter to pin the assets to the clusters."
    Write-Host "Example: .\Pin-AssetsToClusters.ps1 -CsvPath '.\pin-assets-to-clusters-template.csv' -ApiKey 'your-api-key'"
}

<#
    .SYNOPSIS
        Reads and validates CSV data for bulk asset operations.
    .PARAMETER CsvPath
        Path to the CSV file to read and validate.
    .OUTPUTS
        Returns an array of PSCustomObject representing the validated CSV rows.
    .NOTES
        Required columns: AssetId, DeploymentClusterId. AssetName is optional.
    #>
function Get-CsvData {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )
    # Verify CSV file exists
    if (-not (Test-Path -Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }
    
    # Import CSV data
    try {
        $csvData = @(Import-Csv -Path $CsvPath)
        Write-Host "Read $($csvData.Count) rows of CSV data"
    }
    catch {
        throw "Failed to read CSV file: $_"
    }
    
    # Validate CSV has data rows
    if ($csvData.Count -eq 0) {
        throw "CSV file is empty or contains no data rows."
    }
    
    # Validate required columns exist
    $requiredColumns = @('AssetId', 'AssetName', 'DeploymentClusterId')
    $firstRow = $csvData[0]
    $actualColumns = $firstRow.PSObject.Properties.Name
    $missingColumns = @()
    
    foreach ($column in $requiredColumns) {
        if ($actualColumns -notcontains $column) {
            $missingColumns += $column
        }
    }
    
    if ($missingColumns.Count -gt 0) {
        throw "CSV validation failed: The CSV file needs at least AssetId and DeploymentClusterId columns. Actual columns found in CSV: $($actualColumns -join ', ')"
    }
    
    # Validate each row has required values (Import-Csv excludes header from data array)
    for ($i = 0; $i -lt $csvData.Count; $i++) {
        $row = $csvData[$i]
        $csvRowNumber = $i + 2  # +2: row 1 is header, arrays are 0-indexed
        
        if ($null -eq $row.AssetId) {
            throw "CSV validation failed: AssetId is null at row $csvRowNumber (index $i)"
        }
        
        if ($null -eq $row.DeploymentClusterId) {
            throw "CSV validation failed: DeploymentClusterId is null at row $csvRowNumber (index $i)"
        }
    }
    
    Write-Host "Validated $($csvData.Count) rows of CSV data"
    # Return validated CSV data
    return $csvData
}

<#
This section of the script is responsible for 
initializing the API context and making API requests.
#>

<#
    .SYNOPSIS
        Initializes the API context with headers and base URL for Zero Networks API requests.
    .OUTPUTS
        None. Sets $script:Headers and $script:ApiBaseUrl for use by Invoke-ApiRequest function.
    .NOTES
        Sets $script:Headers and $script:ApiBaseUrl for use by Invoke-ApiRequest function.
    #>
function Initialize-ApiContext {
    $script:Headers = @{
        Accept        = "application/json"
        Authorization = $ApiKey
    }
    $script:ApiBaseUrl = "$PortalUrl/api/v1"
}

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
    
    # First check if status code is 2XX (success)
    if ($StatusCode -ge 200 -and $StatusCode -lt 300) {
        return
    }
    
    # Define specific error status codes with their reason phrases
    $errorStatusCodes = @{
        400 = "Bad Request"
        401 = "Unauthorized"
        403 = "Forbidden"
        404 = "Not Found"
        405 = "Method Not Allowed"
        500 = "Internal Server Error"
        501 = "Not Implemented"
        503 = "Service Unavailable"
    }
    
    # Determine error message based on whether status code is in the defined list
    if ($errorStatusCodes.ContainsKey($StatusCode)) {
        $reasonPhrase = $errorStatusCodes[$StatusCode]
        $errorMessage = "API request failed with status code $StatusCode ($reasonPhrase)"
    }
    else {
        # Catch-all for any other non-2XX status code
        $errorMessage = "API request failed with status code $StatusCode"
    }
    
    # Format response body for error message (if available)
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
    
    # Combine error message with response body
    $fullErrorMessage = $errorMessage
    if ($null -ne $responseBody -and $responseBody.Trim() -ne "") {
        $fullErrorMessage = "$errorMessage`nResponse body: $responseBody"
    }
    
    # Create exception with status code and response as custom properties
    $exception = New-Object System.Exception $fullErrorMessage
    $exception | Add-Member -MemberType NoteProperty -Name "StatusCode" -Value $StatusCode
    $exception | Add-Member -MemberType NoteProperty -Name "Response" -Value $Response
    
    # Create and throw error record
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
        Wraps the existing Invoke-ApiRequest function to handle pagination.
    .PARAMETER Method
        HTTP method to use (GET, POST, PUT, PATCH, DELETE).
    .PARAMETER ApiEndpoint
        API endpoint path (e.g., "assets/123" or "/groups/ou").
    .PARAMETER QueryParams
        Optional query parameters object to include in the request.
    .PARAMETER Body
        Optional request body object. Will be converted to JSON if not already a string.
    .OUTPUTS
        Returns the complete API response object with all paginated items combined.
    .NOTES
        Automatically handles both cursor-based and offset-based pagination. All pages are fetched and items are combined into a single response.
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

    # Make initial API request
    $response = Invoke-ApiRequest -Method $Method -ApiEndpoint $ApiEndpoint -Body $Body -QueryParams $QueryParams

    # Handle cursor pagination if the endpoint supports it
    $NextCursor = $response.nextCursor
    while ($NextCursor -and ($NextCursor.Length -gt 0)) {
        # Update query parameters with the cursor for the next page
        $QueryParams['_cursor'] = $NextCursor
        Write-Debug "Fetching page with cursor $($QueryParams['_cursor'])"
        $nextPageResponse = Invoke-ApiRequest -Method $Method -ApiEndpoint $ApiEndpoint -Body $Body -QueryParams $QueryParams
        Write-Debug "Retrieved an additional page from API endpoint $($ApiEndpoint)"
        Write-Debug "Response size: $($nextPageResponse.items.Count)"
        # Append items from this page to the main response
        if ($nextPageResponse.items.Count -gt 0) {
            $response.items += $nextPageResponse.items
        }
        Write-Debug "Items retrieved so far: $($response.items.Count)"
        Write-Debug "Next Cursor $($nextPageResponse.nextCursor)"
        # Get the cursor for the next page (if any)
        $NextCursor = $nextPageResponse.nextCursor
    }

    # Handle offset-based pagination if the endpoint supports it
    $TotalItemsCount = $response.count
    $QueryParams['_offset'] = $response.nextOffset
    # Continue fetching pages until we have all items
    while ($response.items.Count -lt $TotalItemsCount) {
        Write-Debug "Fetching next page with offset $($QueryParams['_offset'])"
        $nextPageResponse = Invoke-ApiRequest -Method $Method -ApiEndpoint $ApiEndpoint -Body $Body -QueryParams $QueryParams
        Write-Debug "Retrieved an additional page from API endpoint $($ApiEndpoint)"
        Write-Debug "Response size: $($nextPageResponse.items.Count)"
        # Append items from this page to the main response
        if ($nextPageResponse.items.Count -gt 0) {
            $response.items += $nextPageResponse.items
        }
        Write-Debug "Items retrieved so far: $($response.items.Count)"
        Write-Debug "Next Offset $($nextPageResponse.nextOffset)"
        # Update offset for the next page
        $QueryParams['_offset'] = $nextPageResponse.nextOffset
    }
    
    Write-Debug "Total items retrieved: $($response.items.Count)"
    Write-Debug "Retrieved all pages from $($ApiEndpoint)"

    return $response
}

<#
    .SYNOPSIS
        Makes HTTP requests to the Zero Networks API with error handling.
    .PARAMETER Method
        HTTP method to use (GET, POST, PUT, PATCH, DELETE).
    .PARAMETER ApiEndpoint
        API endpoint path (e.g., "assets/123" or "/assets/actions/deployments-cluster").
    .PARAMETER Body
        Optional request body object. Will be converted to JSON if not already a string.
    .OUTPUTS
        Returns the API response object.
    .NOTES
        Automatically validates status codes and throws exceptions for errors.
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
        # Build request parameters
        $requestParams = @{
            Method  = $Method
            Uri     = "$script:ApiBaseUrl/$ApiEndpoint"
            Headers = $script:Headers
        }
        
        # Build query string from query parameters if provided
        # Convert the hashtable/dictionary to URL-encoded query string format (key1=value1&key2=value2)
        # No URL encoding is actually done, because when I use built in methods to do it, it breaks the API requests
        $QueryString = ""
        if ($null -ne $QueryParams) {
            # Iterate through each key-value pair and format as "key=value", then join with '&'
            $QueryString = ($QueryParams.GetEnumerator() | ForEach-Object { 
                "$($_.Key)=$($_.Value.ToString())" 
            }) -join '&'
            # Append query string to the URI
            $requestParams['Uri'] = $requestParams['Uri'] + "?" + $QueryString
        }

        # Add request body if provided (convert objects to JSON if needed)
        if ($null -ne $Body) {
            # If body is already a string, use it as-is; otherwise convert the object to JSON
            # Note: The conditional expression returns the value, which is then assigned to $requestParams['Body']
            $requestParams['Body'] = if ($Body -is [string]) {
                $Body
            }
            else {
                $Body | ConvertTo-Json -Depth 10 -Compress
            }
            # Set content type to JSON for API requests with a body
            $requestParams['ContentType'] = "application/json"
        }
        
        # Execute request and capture status code (SkipHttpErrorCheck allows manual error handling)
        $statusCode = $null
        $response = Invoke-RestMethod @requestParams -SkipHttpErrorCheck -StatusCodeVariable statusCode

        # Validate status code (throws exception for non-2XX codes)
        Test-ApiResponseStatusCode -StatusCode $statusCode -Response $response | Out-Null

        return $response
    }
    catch {
        # Re-throw 404 errors as-is (Test-ApiResponseStatusCode already formatted them)
        if ($null -ne $_.Exception.StatusCode -and ($_.Exception.StatusCode -eq 404)) {
            throw $_
        }
        # Wrap unexpected errors with request context
        throw "API request to $($requestParams['Uri']) failed due to error:`n$_"
    }
}

<#
This is the main switch statement that determines which
workflow to execute based on the parameter set matched.
#>
switch ($PSCmdlet.ParameterSetName) {
    "ByAssetId" {
        Write-Host "$($DryRun ? "[DRY RUN] " : '')Starting workflow to $($Unpin ? "unpin" : "pin") asset $AssetId to deployment cluster $DeploymentClusterId"
        Initialize-ApiContext
        
        # Validate deployment cluster exists and has online segment servers
        Invoke-ValidateDeploymentClusterId -DeploymentClusterId $DeploymentClusterId -SkipSegmentServerValidation:$SkipSegmentServerValidation
        
        # Validate asset can be pinned/unpinned
        Test-AssetCanBePinned -AssetId $AssetId -AssetMustBePinned:$Unpin
        
        # Create asset object for the function
        $asset = [PSCustomObject]@{
            id = $AssetId
        }
        $Assets = [System.Collections.ArrayList]@($asset)
        
        # Execute pin/unpin operation
        Set-AssetsToDeploymentCluster -Assets $Assets -DeploymentClusterId $DeploymentClusterId -Unpin:$Unpin -DryRun:$DryRun
        
        Write-Host "$($DryRun ? "[DRY RUN] " : '')Finished workflow to $($Unpin ? "unpin" : "pin") asset $AssetId to deployment cluster $DeploymentClusterId"
    }
    "ByOuPath" {
        Write-Host "$($DryRun ? "[DRY RUN] " : '')Starting workflow to $($Unpin ? "unpin" : "pin") assets in OU path $OUPath to deployment cluster $DeploymentClusterId"
        Initialize-ApiContext
        
        # Validate deployment cluster exists and has online segment servers
        Invoke-ValidateDeploymentClusterId -DeploymentClusterId $DeploymentClusterId -SkipSegmentServerValidation:$SkipSegmentServerValidation

        # Get OU Information from API
        $OUInformation = Get-OUInfoFromApi -OUPath $OUPath

        <#
        Wrapping certain function calls in the [System.Collections.ArrayList]@() is a workaround to avoid a conversion error if only ONE asset is returned.
        Powershell, if only one object is returned, will remove the array wrapper and return the object directly, which causes a conversion error.
        Wrapping the return value in an array ensures that the value is always returned as an array, regardless of the number of objects returned.
        #>
        # Get members of OU
        [System.Collections.ArrayList]$Assets = [System.Collections.ArrayList]@(Get-AssetsFromOU -OUPath $OUPath -EntityId $OUInformation.id -DisableNestedOuResolution:$DisableNestedOuResolution) 
        
        # Validate each asset can be pinned/unpinned
        [System.Collections.ArrayList]$AssetsPassedValidation = [System.Collections.ArrayList]@(Test-ValidateProvidedAssetsCanBePinned -Assets $Assets -AssetMustBePinned:$Unpin -StopOnAssetValidationError:$StopOnAssetValidationError)

        # Finally, call function to perform the batch based cluster pinning/unpinning operation
        Invoke-BatchBasedClusterPinning -AssetsPassedValidation $AssetsPassedValidation -DeploymentClusterId $DeploymentClusterId -Unpin:$Unpin -DryRun:$DryRun
        
        Write-Host "$($DryRun ? "[DRY RUN] " : '')Finished workflow to $($Unpin ? "unpin" : "pin") assets in OU path $OUPath to deployment cluster $DeploymentClusterId"
    }
    "ByCsvPath" {
        Write-Host "$($DryRun ? "[DRY RUN] " : '')Starting workflow to $($Unpin ? "unpin" : "pin") assets from CSV file $CsvPath"
        Initialize-ApiContext
        
        # Read and validate CSV data
        $csvData = Get-CsvData -CsvPath $CsvPath
        
        # Get unique deployment cluster IDs from CSV
        $UniqueClusterIds = @($csvData.DeploymentClusterId | Select-Object -Unique)
        
        # Validate all deployment clusters exist and have online segment servers
        foreach ($clusterId in $UniqueClusterIds) {
            Invoke-ValidateDeploymentClusterId -DeploymentClusterId $clusterId -SkipSegmentServerValidation:$SkipSegmentServerValidation
        }

        # Since the CSV data template does not have 1:1 field names as assets returned from API
        # We need to create a new arraylist of assets, with field names normalized to match the API response
        # (Allows for code re-use)
        [System.Collections.ArrayList]$Assets = @()
        foreach ($row in $csvData) {
            $Assets.Add([pscustomobject]@{
                id = $row.AssetId
                name = $row.AssetName
                DeploymentClusterId = $row.DeploymentClusterId
            }) | Out-Null
        }

        # Validate each asset can be pinned/unpinned
        [System.Collections.ArrayList]$AssetsPassedValidation = [System.Collections.ArrayList]@(Test-ValidateProvidedAssetsCanBePinned -Assets $Assets -AssetMustBePinned:$Unpin -StopOnAssetValidationError:$StopOnAssetValidationError)
        
        # Process each cluster's assets
        foreach ($clusterId in $UniqueClusterIds) {
            $AssetsToProcess = [System.Collections.ArrayList]@($AssetsPassedValidation | Where-Object { $_.DeploymentClusterId -eq $clusterId })
            Write-Host "Processing $($Unpin ? "unpinning" : "pinning") operation against $($clusterId) for $($AssetsToProcess.Count) assets"
            Invoke-BatchBasedClusterPinning -AssetsPassedValidation $AssetsToProcess -DeploymentClusterId $clusterId -Unpin:$Unpin -DryRun:$DryRun
        }
        
        Write-Host "$($DryRun ? "[DRY RUN] " : '')Finished workflow to $($Unpin ? "unpin" : "pin") assets from CSV file $CsvPath"
    }
    "ListDeploymentClusters" {
        Initialize-ApiContext
        $DeploymentClusters = Get-DeploymentClusters
        Write-DeploymentClusters -DeploymentClusters $DeploymentClusters
        ""
    }
    "ExportCsvTemplate" {
        Export-CsvTemplate
    }
}
