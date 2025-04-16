<#
.DESCRIPTION
This command will use the Zero Networks API specified to create an OT/IoT asset within your tenant of the Zero Networks platform. The tenant is based on the authentication of your API Key used which may be set as a switch to this script, or by default via the environment variable "ZN_API_KEY". This script also allows an input file for the list of devices to import. This file can be created by using the Excel w/Macros file with the same name as this file and exporting a CSV from it.

.PARAMETER csvFilePath
A CSV file generated as an export from the Excel file (XLSM) with the same name.

.PARAMETER APIKey
This key is created by you within the Zero Networks portal of your tenant. It is tenant-specific. This script requires a read-write key.

.PARAMETER ip
Supply an IP address (e.g. 192.168.100.1) for the OT/IoT asset. This parameter is required if not taken from an input file.

.PARAMETER fqdn
A fully-qualified domain name that should resolve to the IP address given. This parameter is optional.

.PARAMETER name
Used as the display name of the OT/IoT asset inside the Zero Networks portal. This parameter is required if not taken from an input file.
#>

param (
    [string]$csvFilePath,
    [string]$APIKey = $Env:ZN_API_KEY,
    [string]$ip,
    [string]$fqdn = "",
    [string]$name
)

if (-not $APIKey) {
    Write-Host "An API key is required for this operation. It can be passed to this script or read from the environment variable ZN_API_KEY."
    Exit 1
}

$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("Content-Type","application/json")
$uri = "https://portal.zeronetworks.com/api/v1"
$query = "/assets/ot"

if ($csvFilePath) {
    $csvData = Import-Csv -Path $csvFilePath

    foreach ($row in $csvData) {
        $jsonRow = $row | ConvertTo-Json -Depth 1
        Write-Host "Creating: $($row.displayName)..."
        try {
            # Could be captured as a collection to provide AssetID output
            $response = Invoke-RestMethod -Uri "$($uri)$($query)" -Method Post -Headers $znHeaders -Body $jsonRow   
        }
        catch {
            # Commonly a jwt authorization error, but couldn't capture that particular exception.
            $Error[4]
            Exit 1
        }
    }
} elseif ($ip -and $name) {
    $body = [PSCustomObject]@{
        ipv4 = $ip
        displayName = $name
        type = '135'
        fqdn = $fqdn
    }
    $response = Invoke-RestMethod -Uri "$($uri)$($query)" -Method Post -Headers $znHeaders -Body (ConvertTo-Json $body)
} else { Write-Host "You must supply either a file or IP and Name for a single asset."}