$APIKey = ''
#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"

$assetsToCheck = @()

#Get the total number of assets
$allAssets = Invoke-RestMethod -Uri "$uri/assets?_limit=1&_offset=0&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders

$i=0

#Page through results if needed
for(;$i -le ($allAssets.Count);) { 
    $assetsToCheck += (Invoke-RestMethod -Uri "$uri/assets?_limit=400&_offset=$i&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders).items
    $i = $i+400
 }

 $inactiveAssets = @()

 foreach($asset in ($assetsToCheck | Where-Object {$_.ipV4Addresses.Count -eq 0 -and $_.ipV6Addresses.Count -eq 0})){
     $inactiveAssets += $asset
 }
 
