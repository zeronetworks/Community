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


<#
This section of the script contains all of the
asset related functions in the script
#>
function Test-AssetCanBePinned {
    param(
        [Parameter(Mandatory = $true)]
        [object]$AssetDetails
    )
    # ORDER OF VALIDATION MATTERS HERE!
    # 1st: Check if asset is monitored by a Segment Server, if not, error out.
    if ($AssetDetails.assetStatus -ne 2) {
        Write-Error "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not monitored by a Segment Server (e.g uses Cloud Connector, Lightweight Agent). Only hosts monitored by a Segment Server can be pinned to a deployment cluster."
        exit 1
    }
    # 2nd: Check if asset is healthy, if not, error out.
    if ($AssetDetails.healthState.healthStatus -ne 1) {
        Write-Error "Asset $($AssetDetails.name) ($($AssetDetails.id)) is not healthy! Please check the asset health in the portaland try again."
        exit 1
    }
    # 3rd: Check if asset is already pinned to a deployment cluster, if so, error out.
    # deploymentsClusterSource = 5 --> NONE.
    if ($AssetDetails.deploymentsClusterSource -ne 5 -and $AssetDetails.deploymentsClusterSource -ne 6) {
        Write-Error "Asset $($AssetDetails.name) ($($AssetDetails.id)) is already pinned to Deployment Cluster ID: $($AssetDetails.deploymentsCluster.id) - Deployment Cluster Name: $($AssetDetails.deploymentsCluster.name) - Segment Server ID: $($AssetDetails.assignedDeployment.id) - Segment Server Name: $($AssetDetails.assignedDeployment.name)"
        exit 1
    }
    # 4th: If asset is not applicable to be pinned to a deployment cluster, error out.
    # deploymentsClusterSource = 6 --> NOT_APPLICABLE.
    elseif ($AssetDetails.deploymentsClusterSource -eq 6) {
        Write-Error "Asset $($AssetDetails.name) ($($AssetDetails.id)) applicable to be pinned to a deployment cluster!"
        exit 1
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
            Write-Error "Asset details response is malformed and does not contain 'entity' property"
            exit 1
        }
        Write-Host "Found asset details for $($response.entity.name) - $AssetId"
        return $response.entity
    }
    catch {
        if ($null -ne $_.Exception.StatusCode -and ($_.Exception.StatusCode -eq 404)) {
            Write-Error "Asset with ID $AssetId was not found!"
            exit 1
        }
        else {
            Write-Error $_
            exit 1
        }
    }
}

function Set-AssetsToDeploymentCluster {
    param(
        [Parameter(Mandatory = $true)]
        [array]$AssetIdsArray,
        [Parameter(Mandatory = $true)]
        [string]$DeploymentClusterId
    )
    $body = @{
        assetIds = $AssetIdsArray
        deploymentsClusterId = $DeploymentClusterId
    }
    Write-Host "Pinning $($AssetIdsArray.Count) assets to deployment cluster: $($script:DeploymentClusterHashtable[$DeploymentClusterId].name)"
    Invoke-ApiRequest -Method "PUT" -ApiEndpoint "/assets/actions/deployments-cluster" -Body $body
}

<#
This section of the script contains functions related to 
deployment cluster operations.
#>
function Get-DeploymentClusters {
    Write-Host "Getting deployment clusters!"
    $response = Invoke-ApiRequest -Method "GET" -ApiEndpoint "environments/cluster"
    if (-not $response.items) {
        Write-Error "Deployment clusters response is malformed and does not contain 'items' property"
        exit 1
    }
    if ($response.items.Count -eq 0) {
        Write-Error "No deployment clusters found!"
        exit 1
    }
    if ($response.items -isnot [System.Array]) {
        $DeploymentClusters = @($response.items)
    }
    else {
        $DeploymentClusters = $response.items
    }

    # Test if DeploymentClusterFieldMappings.json file exists, if so, read it into a hashtable
    if (Test-Path -Path "DeploymentClusterFieldMappings.json") {
        $DeploymentClusters = Invoke-DecodeDeploymentClusterIDFields -DeploymentClusters $DeploymentClusters
    }
    else {
        Write-Warning "DeploymentClusterFieldMappings.json file not found! Skipping deployment cluster ID field decoding!"
    }

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
    Write-Host "Created script-wide hashtable of deployment clusters!"
    
}
function Invoke-DecodeDeploymentClusterIDFields {
    param(
        [Parameter(Mandatory = $true)]
        [System.Array]$DeploymentClusters
    )
    Write-Host "Decoding deployment cluster ID fields! (e.g Updating strategy=2 --> strategy=Active/Active)"
    $DeploymentClusterFieldMappings = Get-Content -Path "DeploymentClusterFieldMappings.json" | ConvertFrom-Json -AsHashtable -Depth 10
    foreach ($cluster in $DeploymentClusters){
        if ($cluster.strategy.GetType() -eq [System.Int64]) {
            $cluster.strategy = $DeploymentClusterFieldMappings['strategy']['byId'][$cluster.strategy.ToString()]
        }

        if ($cluster.assignedDeployments.Count -gt 0) {
            foreach ($deployment in $cluster.assignedDeployments){
                if ($deployment.status.GetType() -eq [System.Int64]) {
                    $deployment.status = $DeploymentClusterFieldMappings['assignedDeployments.status']['byId'][$deployment.status.ToString()]
                }
                if ($deployment.state.GetType() -eq [System.Int64]) {
                    $deployment.state = $DeploymentClusterFieldMappings['assignedDeployments.state']['byId'][$deployment.state.ToString()]
                }
                if ($deployment.servicesInfo.Count -gt 0) {
                    foreach ($service in $deployment.servicesInfo){
                        if ($service.serviceId.GetType() -eq [System.Int64]) {
                            $service.serviceId = $DeploymentClusterFieldMappings['assignedDeployments.servicesInfo.serviceId']['byId'][$service.serviceId.ToString()]
                        }
                        if ($service.status.GetType() -eq [System.Int64]) {
                            $service.status = $DeploymentClusterFieldMappings['assignedDeployments.servicesInfo.status']['byId'][$service.status.ToString()]
                        }
                        if ($service.state.GetType() -eq [System.Int64]) {
                            $service.state = $DeploymentClusterFieldMappings['assignedDeployments.servicesInfo.state']['byId'][$service.state.ToString()]
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
    
    Write-Host "Writing deployment clusters information to console!"
    foreach ($cluster in $DeploymentClusters){
        Write-Host $("="*(($Host.UI.RawUI.WindowSize.Width)/2))
        Write-Host "Deployment cluster: $($cluster.name)"
        Write-Host "Cluster ID: $($cluster.id)"
        Write-Host "Number of assets in cluster: $($cluster.numOfAssets)"
        Write-Host "HA Strategy: $(if ($cluster.strategy -eq 2) { "Active/Active" } else { "Active/Passive" })"
        Write-Host "Segment server deployments assigned to this cluster:"
        if ($cluster.assignedDeployments.Count -eq 0) {
            Write-Host "$(" "*2)No segment server deploments are assigned to this cluster!"
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
    Write-Host "Finished writing deployment clusters information to console!"
    
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
    Write-Host "Example: .\Pin-AssetsToClusters.ps1 -CsvPath '.\pin-assets-to-clusters.csv' -ApiKey 'your-api-key'"
    Exit 0
}

function Get-CsvData {
    # Check if CSV file exists
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        exit 1
    }
    
    # Read CSV file into an array of PSCustomObjects
    try {
        $csvData = @(Import-Csv -Path $CsvPath)
    }
    catch {
        Write-Error "Failed to read CSV file: $_"
        exit 1
    }
    
    # Validate that CSV has data
    if ($csvData.Count -eq 0) {
        Write-Error "CSV file is empty or contains no data rows."
        exit 1
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
        Write-Error "CSV validation failed: The CSV file needs at least AssetId and DeploymentClusterId columns."
        Write-Error "Actual columns found in CSV: $($actualColumns -join ', ')"
        exit 1
    }
    
    # Note: Import-Csv automatically excludes the header row from the data array
    
    # Enumerate the array and validate each object
    for ($i = 0; $i -lt $csvData.Count; $i++) {
        $row = $csvData[$i]
        $csvRowNumber = $i + 2  # +2 because row 1 is header, and arrays are 0-indexed
        
        # Check if AssetId is null
        if ($null -eq $row.AssetId) {
            Write-Error "CSV validation failed: AssetId is null at row $csvRowNumber (index $i)"
            exit 1
        }
        
        # Check if DeploymentClusterId is null
        if ($null -eq $row.DeploymentClusterId) {
            Write-Error "CSV validation failed: DeploymentClusterId is null at row $csvRowNumber (index $i)"
            exit 1
        }
    }
    
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
        Write-Host "Sending $Method request to $script:ApiBaseUrl/$ApiEndpoint"
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
        Write-Error "API request to $($requestParams['Uri']) failed due to error:`n$_"
        exit 1
    }
}

<#
This is the main switch statement that determines which
workflow to execute based on the parameter set matched.
#>
switch ($PSCmdlet.ParameterSetName) {
    "ByAssetId" {
        Write-Host "Starting workflow to pin asset $AssetId to deployment cluster $DeploymentClusterId"
        Initialize-ApiContext
        $AssetDetails = Get-AssetDetails -AssetId $AssetId
        Test-AssetCanBePinned -AssetDetails $AssetDetails
        Set-AssetsToDeploymentCluster -AssetIdsArray @($AssetId) -DeploymentClusterId $DeploymentClusterId
        ""
    }
    "ByCsvPath" {
        Initialize-ApiContext
        $csvData = Get-CsvData
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
