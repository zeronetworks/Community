$APIKey = "<API-KEY>"
$depID = "<Segment-Server-ID>" #This can be pulled from the settings page, ensure you add the "Server ID" column


# Function to check if IP falls in the subnet
function Test-IPInSubnet {
    param (
        [string]$IPAddress,
        [string]$Subnet,
        [int]$PrefixLength
    )

    # Convert the IP and subnet into IP address objects
    $ip = [System.Net.IPAddress]::Parse($IPAddress)
    $subnetIp = [System.Net.IPAddress]::Parse($Subnet)

    # Convert IP and subnet to byte arrays
    $ipBytes = $ip.GetAddressBytes()
    $subnetBytes = $subnetIp.GetAddressBytes()

    # Reverse the byte arrays to handle endianness
    [Array]::Reverse($ipBytes)
    [Array]::Reverse($subnetBytes)

    # Convert the byte arrays to 32-bit unsigned integers
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    $subnetInt = [BitConverter]::ToUInt32($subnetBytes, 0)

    # Create a subnet mask based on the prefix length (CIDR notation)
    $mask = -bnot ((1 -shl (32 - $PrefixLength)) - 1)

    # Check if the IP is in the subnet
    return (($ipInt -band $mask) -eq ($subnetInt -band $mask))
}

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")

$apiString = "assets/monitored?_limit=1&_offset=0&order=asc&orderColumns[]=name&showInactive=false"

$uri = "https://portal.zeronetworks.com/api/v1"

$assetsToCheck = @()

#Get the total number of assets
$allAssets = Invoke-RestMethod -Uri "$uri/$apiString" -Method Get -Headers $znHeaders

$i=0

#Page through results if needed
for(;$i -le ($allAssets.Count);) { 
    $assetsToCheck += (Invoke-RestMethod -Uri "$uri/assets/monitored?_limit=400&_offset=$i&order=asc&orderColumns[]=name&showInactive=false" -Method Get -Headers $znHeaders).items
    $i = $i+400
 }

 # Get subnet and CIDR range
 $subnet = "10.0.0.0"
 $CIDR = 24

 # Filter assets based on subnet
 $filteredAssets = $assetsToCheck | Where-Object {
    foreach ($ip in $_.ipV4Addresses) {
        if (Test-IPInSubnet -IPAddress $ip -Subnet $subnet -PrefixLength $CIDR ) {
            return $true
        }
    }
    return $false
}

# Extract IDs of the filtered assets
$filteredAssetIds = $filteredAssets | ForEach-Object { $_.id }

$preferredServerString = "assets/actions/preferred-deployment"
# Output the body to verify

foreach ($assetIdsString in $filteredAssetIds) {
    # Set Payload
    $body = @{
        assetId = $assetIdsString
        preferredDeploymentId = $depID
    }
    Invoke-RestMethod -Uri "$uri/$preferredServerString" -Method PUT -Headers $znHeaders -Body ($body | ConvertTo-Json)
}

