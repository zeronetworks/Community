#requires -Version 7.0

[CmdletBinding(DefaultParameterSetName = "ByAssetId")]
param(
    # Shared parameter for sets that require authentication
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $true)]
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $true)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $true)]
    [string]$ApiKey,

    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $false)]
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [string]$PortalUrl = "https://portal.zeronetworks.com",
    
    # ParameterSet 1: Pin by Asset ID and Deployment Cluster ID
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $true)]
    [string]$AssetId,
    
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $true)]
    [string]$DeploymentClusterId,
    
    # Shared switch parameter for unpinning (available in ByAssetId and ByCsvPath sets)
    [Parameter(ParameterSetName = "ByAssetId")]
    [Parameter(ParameterSetName = "ByCsvPath")]
    [switch]$Unpin,
    
    # Shared switch parameter to skip segment server validation (available in all sets with ApiKey)
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [switch]$SkipSegmentServerValidation,
    
    # Shared switch parameter for dry run mode (available in all sets with ApiKey)
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $false)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $false)]
    [switch]$DryRun,
    
    # ParameterSet 2: List Deployment Clusters
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $true)]
    [switch]$ListDeploymentClusters,
    
    # ParameterSet 3: Pin from CSV file
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $true)]
    [string]$CsvPath,
    
    # ParameterSet 4: Export CSV Template
    [Parameter(ParameterSetName = "ExportCsvTemplate", Mandatory = $true)]
    [switch]$ExportCsvTemplate
)
$ErrorActionPreference = "Stop"

# Script-wide deployment cluster field mappings hashtable
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

<#
This section of the script contains all of the
asset related functions in the script
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
    # ORDER OF VALIDATION MATTERS HERE!
    # 1st: Check if asset is monitored by a Segment Server, if not, error out.
    if ($AssetDetails.assetStatus -ne 2) {
        throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not monitored by a Segment Server (e.g uses Cloud Connector, Lightweight Agent). Only hosts monitored by a Segment Server can be pinned to a deployment cluster."
        
    }
    # 2nd: Check if asset is healthy, if not, error out.
    if ($AssetDetails.healthState.healthStatus -ne 1) {
        throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not healthy! Please check the asset health in the portaland try again."
        
    }
    # 3rd: If asset is not applicable to be pinned to a deployment cluster, error out.
    # deploymentsClusterSource = 6 --> NOT_APPLICABLE.
    if ($AssetDetails.deploymentsClusterSource -eq 6) {
        throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) applicable to be pinned to a deployment cluster"
        
    }
    # 4th: If workflow is looking unpin an asset, test that the asset IS ALREADY pinned to a deployment cluster.
    if ($AssetMustBePinned) {
        if (-not ($AssetIsPinnedDeploymentClusterSource -contains $AssetDetails.deploymentsClusterSource)) {
            throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not pinned to a deployment cluster! It must be pinned to a deployment cluster to be unpinned."
            
        }
    }
    # 5th: Else, if workflow is looking to pin an asset, test that the asset IS NOT already pinned to a deployment cluster.
    else {
        if ($AssetIsPinnedDeploymentClusterSource -contains $AssetDetails.deploymentsClusterSource) {
            throw "Asset $($AssetDetails.name) ($($AssetDetails.id)) is already pinned to Deployment Cluster ID: $($AssetDetails.deploymentsCluster.id) - Deployment Cluster Name: $($AssetDetails.deploymentsCluster.name) - Segment Server ID: $($AssetDetails.assignedDeployment.id) - Segment Server Name: $($AssetDetails.assignedDeployment.name)"
            
        }
    }
    
    Write-Host "Validated that asset $($AssetDetails.name) ($($AssetDetails.id)) can be pinned to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
}

function Get-AssetDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AssetId
    )
    Write-Host "Getting asset details for asset ID: $AssetId"
    try {
        $response = Invoke-ApiRequest -Method "GET" -ApiEndpoint "assets/$AssetId"
        if ($null -eq $response.entity) {
            throw "Asset details response is malformed and does not contain 'entity' property"
            
        }
        Write-Host "Found asset details for $($response.entity.name) - $AssetId"
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

function Set-AssetsToDeploymentCluster {
    param(
        [Parameter(Mandatory = $true)]
        [array]$AssetIdsArray,
        [Parameter(Mandatory = $true)]
        [string]$DeploymentClusterId,
        [Parameter(Mandatory = $false)]
        [switch]$Unpin,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    $body = @{
        assetIds = $AssetIdsArray
    }
    if (-not $Unpin) {
        $body.deploymentsClusterId = $DeploymentClusterId
    }
    Write-Host "$($Unpin ? "Unpinning" : "Pinning") $($AssetIdsArray.Count) assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
    
    if ($DryRun) {
        Write-Host "[DRY RUN] Would $($Unpin ? "unpin" : "pin") $($AssetIdsArray.Count) assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
    }
    else {
        $response = Invoke-ApiRequest -Method "PUT" -ApiEndpoint "/assets/actions/deployments-cluster" -Body $body
        Write-Host "Successfully $($Unpin ? "unpinned" : "pinned") $($AssetIdsArray.Count) assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
    }
}

<#
This section of the script contains functions related to 
deployment cluster operations.
#>
function Invoke-ValidateDeploymentClusterId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeploymentClusterId,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipSegmentServerValidation
    )
    Write-Host "Validating deployment cluster ID: $DeploymentClusterId"
    if ($null -eq $script:DeploymentClusterHashtable) {
        # If deployment cluster hashtable is not initialized, 
        # call function Get-DeploymentClusters to initialize it
        Get-DeploymentClusters
    }
    if (-not $script:DeploymentClusterHashtable.ContainsKey($DeploymentClusterId)) {
        throw "Deployment cluster ID $DeploymentClusterId not found"
    }

    # Since the we validated the DeploymentClusterId exists, get it's object from the hashtable
    $deploymentCluster = $script:DeploymentClusterHashtable[$DeploymentClusterId]

    # Get assigned deployments for the deployment cluster
    if (-not $SkipSegmentServerValidation) {
        #Validate that the deployment cluster has >= 1 active segment server
        if ($deploymentCluster.assignedDeployments.Count -eq 0) {
            throw "Deployment cluster `"$($deploymentCluster.name)`" ($DeploymentClusterId) has no segment servers assigned to it"
        }
        # Validate that at least one segment server is online (status=2 --> Online)
        if (
            ($deploymentCluster.assignedDeployments | Where-Object {$_.status -eq "Online"}).Count -eq 0) {
                throw "Deployment cluster  `"$($deploymentCluster.name)`" ($DeploymentClusterId) has no online segment servers! Please check the segment server status in the portal and try again. If the segment server is online, please check the segment server health and try again."
        }
    }
    else {
        Write-Host "Skipping segment server validation"
    }
    Write-Host "Validated that deployment cluster `"$($deploymentCluster.name)`" ($DeploymentClusterId) exists in tenant"
}

function Get-DeploymentClusters {
    Write-Host "Getting deployment clusters"
    $response = Invoke-ApiRequest -Method "GET" -ApiEndpoint "environments/cluster"
    if (-not $response.items) {
        throw "Deployment clusters response is malformed and does not contain 'items' property"
        
    }
    if ($response.items.Count -eq 0) {
        throw "No deployment clusters found"
        
    }
    if ($response.items -isnot [System.Array]) {
        $DeploymentClusters = @($response.items)
    }
    else {
        $DeploymentClusters = $response.items
    }

    # Decode deployment cluster ID fields using script-wide hashtable
    $DeploymentClusters = Invoke-DecodeDeploymentClusterIDFields -DeploymentClusters $DeploymentClusters

    # Create a script-wide hashtable of deployment clusters for easy access and validation
    New-DeploymentClusterHashtable -DeploymentClusters $DeploymentClusters

    return $DeploymentClusters
}
function New-DeploymentClusterHashtable {
    param(
        [Parameter(Mandatory = $true)]
        [System.Array]$DeploymentClusters
    )
    $script:DeploymentClusterHashtable = @{}
    foreach ($cluster in $DeploymentClusters){
        $DeploymentClusterHashtable[$cluster.id] = $cluster
    }
    Write-Host "Created script-wide hashtable of deployment clusters"
    
}
function Invoke-DecodeDeploymentClusterIDFields {
    param(
        [Parameter(Mandatory = $true)]
        [System.Array]$DeploymentClusters
    )
    Write-Host "Decoding deployment cluster ID fields! (e.g Updating strategy=2 --> strategy=Active/Active)"
    foreach ($cluster in $DeploymentClusters){
        if ($cluster.strategy.GetType() -eq [System.Int64]) {
            $cluster.strategy = $script:DeploymentClusterFieldMappings['strategy']['byId'][$cluster.strategy.ToString()]
        }

        if ($cluster.assignedDeployments.Count -gt 0) {
            foreach ($deployment in $cluster.assignedDeployments){
                if ($deployment.status.GetType() -eq [System.Int64]) {
                    $deployment.status = $script:DeploymentClusterFieldMappings['assignedDeployments.status']['byId'][$deployment.status.ToString()]
                }
                if ($deployment.state.GetType() -eq [System.Int64]) {
                    $deployment.state = $script:DeploymentClusterFieldMappings['assignedDeployments.state']['byId'][$deployment.state.ToString()]
                }
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
function Export-CsvTemplate {
    $template = [PSCustomObject]@{
        AssetName = $null
        AssetId = $null
        DeploymentClusterId = $null
    }
    $template | Export-Csv -Path ".\pin-assets-to-clusters-template.csv" -NoTypeInformation
    Write-Host "CSV Template exported to .\pin-assets-to-clusters-template.csv"
    Write-Host "Please fill in AT LEAST the AssetId and DeploymentClusterId columsn, and then run the script again with the -CsvPath parameter to pin the assets to the clusters."
    Write-Host "Example: .\Pin-AssetsToClusters.ps1 -CsvPath '.\pin-assets-to-clusters-template.csv' -ApiKey 'your-api-key'"
}

function Get-CsvData {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )
    # Check if CSV file exists
    if (-not (Test-Path -Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
        
    }
    
    # Read CSV file into an array of PSCustomObjects
    try {
        $csvData = @(Import-Csv -Path $CsvPath)
        Write-Host "Read $($csvData.Count) rows of CSV data"
    }
    catch {
        throw "Failed to read CSV file: $_"
        
    }
    
    # Validate that CSV has data
    if ($csvData.Count -eq 0) {
        throw "CSV file is empty or contains no data rows."
        
    }
    
    # Validate header row has required columns
    $requiredColumns = @('AssetId', 'DeploymentClusterId')
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
    
    # Note: Import-Csv automatically excludes the header row from the data array
    
    # Enumerate the array and validate each object
    for ($i = 0; $i -lt $csvData.Count; $i++) {
        $row = $csvData[$i]
        $csvRowNumber = $i + 2  # +2 because row 1 is header, and arrays are 0-indexed
        
        # Check if AssetId is null
        if ($null -eq $row.AssetId) {
            throw "CSV validation failed: AssetId is null at row $csvRowNumber (index $i)"
            
        }
        
        # Check if DeploymentClusterId is null
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
function Initialize-ApiContext {
    $script:Headers = @{
        Accept        = "application/json"
        Authorization = $ApiKey
    }
    $script:ApiBaseUrl = "$PortalUrl/api/v1"
}

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
    
    # Format response body if available
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
    
    # Build full error message with response body if available
    $fullErrorMessage = $errorMessage
    if ($null -ne $responseBody -and $responseBody.Trim() -ne "") {
        $fullErrorMessage = "$errorMessage`nResponse body: $responseBody"
    }
    
    # Create exception with status code and response as attributes
    $exception = New-Object System.Exception $fullErrorMessage
    $exception | Add-Member -MemberType NoteProperty -Name "StatusCode" -Value $StatusCode
    $exception | Add-Member -MemberType NoteProperty -Name "Response" -Value $Response
    
    # Create error record and throw
    $errorRecord = New-Object System.Management.Automation.ErrorRecord(
        $exception,
        "ApiRequestFailed",
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $null
    )
    
    throw $errorRecord
}

function Invoke-ApiRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,
        
        [Parameter(Mandatory = $true)]
        [string]$ApiEndpoint,
        
        [Parameter(Mandatory = $false)]
        [object]$Body = $null
    )
    
    try {
        #Write-Host "Sending $Method request to $script:ApiBaseUrl/$ApiEndpoint"
        $requestParams = @{
            Method  = $Method
            Uri     = "$script:ApiBaseUrl/$ApiEndpoint"
            Headers = $script:Headers
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
        $statusCode = $null
        $response = Invoke-RestMethod @requestParams -SkipHttpErrorCheck -StatusCodeVariable statusCode

        # Check for error status codes and handle accordingly
        Test-ApiResponseStatusCode -StatusCode $statusCode -Response $response
        
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
This is the main switch statement that determines which
workflow to execute based on the parameter set matched.
#>
switch ($PSCmdlet.ParameterSetName) {
    "ByAssetId" {
        Write-Host "$($DryRun ? "[DRY RUN] " : '') Starting workflow to $($Unpin ? "unpin" : "pin") asset $AssetId to deployment cluster $DeploymentClusterId"
        Initialize-ApiContext
        # Validate deployment cluster ID
        Invoke-ValidateDeploymentClusterId -DeploymentClusterId $DeploymentClusterId -SkipSegmentServerValidation:$SkipSegmentServerValidation
        # Test if asset can be pinned/unpinned to deployment cluster
        Test-AssetCanBePinned -AssetId $AssetId -AssetMustBePinned:$Unpin
        Write-Host "Unpinning asset $AssetId from deployment cluster $DeploymentClusterId"
        # Either pin or unpin asset to deployment cluster, dependent on the -Unpin switch parameter
        Set-AssetsToDeploymentCluster -AssetIdsArray @($AssetId) -DeploymentClusterId $DeploymentClusterId -Unpin:$Unpin -DryRun:$DryRun
        Write-Host "$($DryRun ? "[DRY RUN] " : '') Finished workflow to $($Unpin ? "unpin" : "pin") asset $AssetId to deployment cluster $DeploymentClusterId"

    }
    "ByCsvPath" {
        Write-Host "$($DryRun ? "[DRY RUN] " : '') Starting workflow to $($Unpin ? "unpin" : "pin") assets from CSV file $CsvPath"
        Initialize-ApiContext
        # Read CSV data into an array of PSCustomObjects
        $csvData = Get-CsvData -CsvPath $CsvPath
        # Get unique deployment cluster IDs from the CSV data
        $UniqueClusterIds = @($csvData.DeploymentClusterId | Select-Object -Unique)
        # Validate that all deployment cluster IDs in the CSV are valid and exist in tenant
        foreach ($clusterId in $UniqueClusterIds) {
            Invoke-ValidateDeploymentClusterId -DeploymentClusterId $clusterId -SkipSegmentServerValidation:$SkipSegmentServerValidation
         }

        # Test current state of assets to validate each can be pinned/unpinned to deployment clusters
        foreach ($row in $csvData) {
            Test-AssetCanBePinned -AssetId $row.AssetId -AssetMustBePinned:$Unpin
        }
        Write-Host "Validated that all assets can be $($Unpin ? "unpinned" : "pinned") to deployment clusters"

        # Use UniqueClusterIds to get unique assets that are to be pinned/unpinned to that cluster
        # This is an cluster --> assets map
        $AssetClusterMappingHashtable = @{}
        foreach ($clusterId in $UniqueClusterIds) {
            $AssetClusterMappingHashtable[$clusterId] = @( $csvData | Where-Object { $_.DeploymentClusterId -eq $clusterId } )
        }
        Write-Host "Created asset cluster mapping hashtable"
        foreach ($clusterId in $AssetClusterMappingHashtable.Keys) {
            # Extract AssetIds from CSV objects
            $assetIds = $AssetClusterMappingHashtable[$clusterId] | ForEach-Object { $_.AssetId }
            $totalAssets = $assetIds.Count
            
            Write-Host "$($Unpin ? "Unpinning" : "Pinning") $totalAssets assets to deployment cluster $($script:DeploymentClusterHashtable[$clusterId].name)"
            
            if ($totalAssets -gt 50) {
                # Process in batches of 50
                $batchSize = 50
                $batchNumber = 1
                $totalBatches = [math]::Ceiling($totalAssets / $batchSize)
                
                for ($i = 0; $i -lt $totalAssets; $i += $batchSize) {
                    $batch = $assetIds[$i..([math]::Min($i + $batchSize - 1, $totalAssets - 1))]
                    Write-Host "Processing batch $batchNumber of $totalBatches ($($batch.Count) assets)..."
                    Set-AssetsToDeploymentCluster -AssetIdsArray $batch -DeploymentClusterId $clusterId -Unpin:$Unpin -DryRun:$DryRun
                    if (-not $DryRun) {
                        Write-Host "Successfully $($Unpin ? "unpinned" : "pinned") $($batch.Count) assets to deployment cluster $($script:DeploymentClusterHashtable[$clusterId].name)"
                    }
                    $batchNumber++
                }

            }
            else {
                # Process all assets at once if 50 or fewer
                Set-AssetsToDeploymentCluster -AssetIdsArray $assetIds -DeploymentClusterId $clusterId -Unpin:$Unpin -DryRun:$DryRun
            }
        }
        Write-Host "$($DryRun ? "[DRY RUN] " : '') Finished workflow to $($Unpin ? "unpin" : "pin") assets from CSV file $CsvPath"
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
