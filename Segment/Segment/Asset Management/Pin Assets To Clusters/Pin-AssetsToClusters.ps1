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
    [string[]]$AssetId,
    
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
        return @($response.items)
    }
    else {
        return $response.items
    }
}

function Write-DeploymentClusters {
    param(
        [Parameter(Mandatory = $true)]
        [object]$DeploymentClusters
    )
    foreach ($cluster in $DeploymentClusters){
        Write-Host $("="*($Host.UI.RawUI.WindowSize.Width))
        Write-Host "Deployment cluster: $($cluster.name)"
        Write-Host "Cluster ID: $($cluster.id)"
        Write-Host "Number of assets in cluster: $($cluster.numOfAssets)"
        Write-Host "HA Strategy: $(if ($cluster.strategy -eq 2) { "Active/Active" } else { "Active/Passive" })"
        Write-Host "Segment server deployments assigned to this cluster:"
        if ($cluster.assignedDeployments.Count -eq 0) {
            Write-Host "$("`t"*1)No segment server deploments are assigned to this cluster!"
        }
        else {
            foreach ($deployment in $cluster.assignedDeployments){
                Write-Host "--------------------------------"
                Write-Host "$("`t"*1)Name: $($deployment.name)"
                Write-Host "$("`t"*1)Deployment ID: $($deployment.id)"
                Write-Host "$("`t"*1)Deployment IP Address: $($deployment.internalIpAddress)"
                Write-Host "$("`t"*1)Is Preferred Deployment: $(if ($deployment.id -eq $cluster.preferredDeployment.id) { "Yes" } else { "No" })"
                Write-Host "--------------------------------"
            }
        }
        Write-Host $("="*($Host.UI.RawUI.WindowSize.Width))
    }    
}


function Initialize-ApiContext {
    $script:Headers = @{
        Accept        = "application/json"
        Authorization = $ApiKey
    }
    $script:ApiBaseUrl = "$PortalUrl/api/v1"
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
                $Body | ConvertTo-Json -Depth 10
            }
            $requestParams['ContentType'] = "application/json"
        }
        
        $response = Invoke-RestMethod @requestParams
        return $response
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        
        if ($null -ne $statusCode -and $statusCode -ge 400 -and $statusCode -lt 500) {
            Write-Error "API request failed: The API key is invalid or you do not have permission to access this resource."
            exit 1
        }
        else {
            Write-Error "API request failed: $_"
            exit 1
        }
    }
}

switch ($PSCmdlet.ParameterSetName) {
    "ByAssetId" {
        Initialize-ApiContext
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
