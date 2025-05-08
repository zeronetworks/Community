$APIKey = ''

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("Content-Type","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"

$assetsToCheck = @()

$queuedAssets = Invoke-RestMethod -Uri "$uri/assets/queued?_limit=1&_offset=0&with_count=true" -Method Get -Headers $znHeaders

$i=0

for(;$i -le ($queuedAssets.Count);) { 
    $assetsToCheck += (Invoke-RestMethod -Uri "$uri/assets/queued?_limit=400&_offset=$i&with_count=false" -Method Get -Headers $znHeaders).items
    $i = $i+400
 }

$unprotectItems = @()

foreach($asset in ($assetsToCheck | where {$_.assetStatus -eq 1})){
    $unprotectItems += $asset.id
}

$a=1
$batchitems = @()
foreach($item in $unprotectItems){
    $batchitems += $item
    $unprotectBody = @{
        "items" = @($batchitems)
    }
    
    if($a % 100 -eq 0){
        Invoke-RestMethod -Uri "$uri/assets/actions/unprotect" -Method POST -Body ($unprotectBody | ConvertTo-Json) -Headers $znHeaders
        $batchitems = @()
    }

    $a++
}
