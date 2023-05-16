$APIKey = ''

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"

$assetsToUnprotect = @()

#Get total protected assets
$protectedAssets = Invoke-RestMethod -Uri "$uri/assets/protected?_limit=1&_offset=0&with_count=true" -Method Get -Headers $znHeaders

#Get all protected Assets
$i=0
for(;$i -le ($protectedAssets.Count);) { 
    $assetsToUnprotect += (Invoke-RestMethod -Uri "$uri/assets/protected?_limit=400&_offset=$i&with_count=false" -Method Get -Headers $znHeaders).items
    $i = $i+400
 }

$unprotectItems = @()

foreach($asset in $assetsToUnprotect){
    $unprotectItems += $asset.id
}

$unprotectBody = @{
    "items" = @($unprotectItems)
}

$unprotectBody = $unprotectBody | ConvertTo-Json

Invoke-RestMethod -Uri "$uri/assets/actions/unprotect" -Method POST -Body $unprotectBody -Headers $znHeaders

$learnBody = @{
    "items" = @($unprotectItems)
    "queueDays" = 30
}
$learnBody = $learnBody | ConvertTo-Json

Invoke-RestMethod -Uri "$uri/assets/actions/queue" -Method POST -Body $learnBody -Headers $znHeaders
