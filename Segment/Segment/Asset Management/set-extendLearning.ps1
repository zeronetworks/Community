$APIKey = "<INSERT_YOUR_API_KEY>"
$uri = "https://zncustlabs-admin.zeronetworks.com/api/v1"  # <----  UPDATE WITH YOUR API URL

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")

$apiString = "assets/queued?_limit=1&_offset=0&_filters=&order=asc&orderColumns[]=name&showInactive=false&with_count=true"

$assetsToCheck = @()

$fullURI = "$uri/$apiString"

#Get the total number of assets
$allAssets = Invoke-RestMethod -Uri $fullURI -Method Get -Headers $znHeaders

$i=0

#Page through results if needed
for(;$i -le ($allAssets.Count);) { 
    $assetsToCheck += (Invoke-RestMethod -Uri "$uri/assets/queued?_limit=400&_offset=$i&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders).items
    $i = $i+400
 }

# Extract all asset IDs
$assetIds = $assetsToCheck | ForEach-Object { $_.id }

# Build payload
$payload = @{
    items = $assetIds
    extendByDays = 30
    # maintenanceWindowId = ""   # replace if needed
} | ConvertTo-Json

# PUT request to extend learning
$extendUri = "$uri/assets/actions/queue"

Invoke-RestMethod -Uri $extendUri -Method Put -Headers $znHeaders -Body $payload
