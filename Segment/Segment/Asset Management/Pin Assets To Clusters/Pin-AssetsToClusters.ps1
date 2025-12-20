#requires -Modules ZeroNetworks
#requires -Version 7.0

[CmdletBinding(DefaultParameterSetName = "ByAssetId")]
param(
    # Shared parameter for sets that require authentication
    [Parameter(ParameterSetName = "ByAssetId", Mandatory = $true)]
    [Parameter(ParameterSetName = "ListDeploymentClusters", Mandatory = $true)]
    [Parameter(ParameterSetName = "ByCsvPath", Mandatory = $true)]
    [string]$ApiKey,
    
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
    Write-Output "CSV Template exported to .\pin-assets-to-clusters-template.csv"
    Write-Output "Please fill in AT LEAST the AssetId and DeploymentClusterId columsn, and then run the script again with the -CsvPath parameter to pin the assets to the clusters."
    Write-Output "Example: .\Pin-AssetsToClusters.ps1 -CsvPath '.\pin-assets-to-clusters.csv' -ApiKey 'your-api-key'"
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

switch ($PSCmdlet.ParameterSetName) {
    "ByAssetId" {
        ""
    }
    "ByCsvPath" {
        $csvData = Get-CsvData
    }
    "ListDeploymentClusters" {
        ""
    }
    "ExportCsvTemplate" {
        Export-CsvTemplate
    }
}