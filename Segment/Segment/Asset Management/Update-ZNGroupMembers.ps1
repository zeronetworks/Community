<#
.SYNOPSIS
    Updates Zero Networks custom group members with IP ranges.

.DESCRIPTION
    Converts CIDR IP ranges to Zero Networks item IDs and updates a custom group's membership.

.PARAMETER APIKey
    Zero Networks API key (raw string).

.PARAMETER RangesFilePath
    Path to file containing CIDR ranges (one per line).

.PARAMETER GroupID
    Zero Networks custom group ID (format: g:c:xxxxx).

.PARAMETER BaseURL
    Zero Networks API base URL. Defaults to production environment.

.EXAMPLE
    .\Update-ZNGroupMembers.ps1 -APIKey "your-api-key-here" -RangesFilePath "ipRanges.txt" -GroupID "g:c:nexZMPPY"

.EXAMPLE
    .\Update-ZNGroupMembers.ps1 -APIKey "your-api-key-here" -RangesFilePath "ipRanges.txt" -GroupID "g:c:nexZMPPY" -BaseURL "https://staging.zeronetworks.com/api/v1"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$APIKey,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$RangesFilePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^g:c:[a-zA-Z0-9]+$')]
    [string]$GroupID,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$BaseURL = "https://portal.zeronetworks.com/api/v1"
)

function Generate-ItemId {
    <#
    .SYNOPSIS
        Converts a CIDR address to Zero Networks item ID format.
    
    .PARAMETER CidrAddress
        CIDR notation IP address (e.g., 192.168.1.0/24).
    
    .OUTPUTS
        String in format b:12{hex_ip}{hex_mask}
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$CidrAddress
    )
  
    # Split the CIDR address into IP and subnet mask
    $ipAddress = ($CidrAddress -split '/')[0]
    $subnetMask = ($CidrAddress -split '/')[1]
  
    # Split the IP address into octets
    $octets = $ipAddress.Split('.')
  
    # Convert each octet to binary and concatenate
    $binaryString = ($octets | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ''
  
    # Convert the binary string to hexadecimal
    $hexString = [Convert]::ToInt64($binaryString, 2).ToString('X')
  
    # Convert the subnet mask to hexadecimal
    $hexMask = [Convert]::ToInt32($subnetMask).ToString('X')
  
    # Construct the final item ID
    "b:12{0}{1}" -f $hexString.PadLeft(8, '0'), $hexMask.PadLeft(2, '0') 
}

# Read ranges and filter empty lines
$ranges = Get-Content $RangesFilePath | Where-Object { $_ -match '\S' }

if ($ranges.Count -eq 0) {
    throw "No valid IP ranges found in: $RangesFilePath"
}

# Build headers
$znHeaders = @{
    "Authorization" = $APIKey
    "Content-Type"  = "application/json"
}

# Convert ranges to item IDs
$rangeIds = @()
foreach ($range in $ranges) {
    try {
        $rangeIds += Generate-ItemId $range
    }
    catch {
        Write-Warning "Failed to convert range '$range': $_"
    }
}

if ($rangeIds.Count -eq 0) {
    throw "No valid item IDs generated from ranges"
}

# Build request body
$body = @{
    membersId = $rangeIds
} | ConvertTo-Json

# Construct full URI using base URL
$uri = "$BaseURL/groups/custom/$GroupID/members"

try {
    $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $znHeaders -Body $body
    Write-Host "Successfully updated group $GroupID with $($rangeIds.Count) IP ranges"
    Write-Host "API endpoint: $uri"
    return $response
}
catch {
    Write-Error "Failed to update group: $_"
    throw
}
