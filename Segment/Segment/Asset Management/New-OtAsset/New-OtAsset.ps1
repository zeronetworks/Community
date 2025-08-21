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

.PARAMETER DryRun
If specified, the script will only show what would be sent to the API, but will not perform any changes.
#>

param (
    [string]$csvFilePath,
    [string]$APIKey = $Env:ZN_API_KEY,
    [string]$ip,
    [string]$fqdn = "",
    [string]$name,
    [switch]$DryRun
)

function Get-ApiUrlFromJwt($jwt) {
    $parts = $jwt -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    $payloadObj = $null
    try { $payloadObj = $json | ConvertFrom-Json } catch { return $null }
    return $payloadObj.api_url ?? $payloadObj.tenant ?? $payloadObj.aud ?? $null
}

if (-not $APIKey) {
    Write-Host "An API key is required for this operation. It can be passed to this script or read from the environment variable ZN_API_KEY."
    Exit 1
}

$apiUrlFromJwt = Get-ApiUrlFromJwt $APIKey
if ($apiUrlFromJwt) {
    $uri = "https://" + $apiUrlFromJwt.TrimEnd('/') + "/api/v1"
} else {
    $uri = "https://portal.zeronetworks.com/api/v1"
}

$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("Content-Type","application/json")
$query = "/assets/ot"

function Invoke-ZnRestMethod {
    param (
        [string]$Uri,
        [string]$Method,
        $Headers,
        $Body
    )
    try {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $Body
            } catch {
        Write-Host "API call failed: $($_.Exception.Message)"
        $errorMessage = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errorMessage = $_.ErrorDetails.Message
        } elseif ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errorMessage = $reader.ReadToEnd()
            } catch {
                $errorMessage = "<Unable to read error response body>"
            }
        }
        if ($errorMessage) {
            try {
                $responseJson = $errorMessage | ConvertFrom-Json
                Write-Host "API Error: $($responseJson.message ?? $responseJson.error ?? $responseJson)"
            } catch {
                Write-Host "API Error: $errorMessage"
            }
        }
        # Exit 1
    }
}

if ($csvFilePath) {
    $csvData = Import-Csv -Path $csvFilePath

    foreach ($row in $csvData) {
        $body = [PSCustomObject]@{
            ipv4        = $row.ipv4
            type        = [int]$row.type  # Ensure this is a number, not string
            displayName = $row.displayName
            fqdn        = $row.fqdn
            switchId    = $row.switchId
            interfaceName = $row.interfaceName
        }
        $jsonRow = $body | ConvertTo-Json -Depth 1
        Write-Host "Creating: $($row.displayName)..."
        if ($DryRun) {
            Write-Host "[DryRun] Would POST to $($uri)$($query) with body:"
            Write-Host $jsonRow
        } else {
            $response = Invoke-ZnRestMethod -Uri "$($uri)$($query)" -Method Post -Headers $znHeaders -Body $jsonRow
        }
    }
} elseif ($ip -and $name) {
    $body = [PSCustomObject]@{
        ipv4        = $ip
        type        = 135
        displayName = $name
        fqdn        = $fqdn
    }
    $jsonBody = $body | ConvertTo-Json
    if ($DryRun) {
        Write-Host "[DryRun] Would POST to $($uri)$($query) with body:"
        Write-Host $jsonBody
    } else {
        $response = Invoke-ZnRestMethod -Uri "$($uri)$($query)" -Method Post -Headers $znHeaders -Body $jsonBody
    }
} else { Write-Host "You must supply either a file or IP and Name for a single asset."}