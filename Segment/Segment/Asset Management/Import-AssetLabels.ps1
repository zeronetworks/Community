$apiToken = ""
$domain = "ad.com"

$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$apiToken)
$znHeaders.Add("Content-Type","application/json")
$uri = "https://portal.zeronetworks.com/api/v1"

# Excel should have the following columns: Asset Name, Applications, Environment
# if asset has multiple applications, they should be separated by ";"
$assetExcel = import-excel -path ./ZNHosttoApplicationmapping.xlsx

$assetsList = @()
foreach ($asset in $assetExcel) {
    $assetId = $null
    #try to find the assetid byt name plus domain
    $assetId = Invoke-RestMethod -Uri "$uri/assets/searchId?fqdn=$($asset.InZN).$($domain)" -Headers $znHeaders -Method Get
    if($assetId -eq $null) {
        $assetId = "NotFound"
    }

    $assetData = [PSCustomObject]@{
        "Hostname" = $asset.'Asset Name'
        "Applications" = $asset.Applications
        "Environment" = $asset.Environment
        "AssetId" = $assetId
    }
    $assetsList += $assetData
}

foreach ($asset in $assetsList) {
    write-host "Processing $($asset.AssetId)" -ForegroundColor Green
    $body = $null
    $labels = $null
    $label = $null
    if($asset.AssetId -ne "NotFound") {
        $body = @{}
        $labels = @()
        $appList = $asset.Applications -split ";"
        $applist | foreach-object { 
            $label = @{"key" = "Application"; "value" = $_.Trim()}
            $labels += $label
        }
        $label = @{"key" = "Environment"; "value" = $asset.Environment}
        $labels += $label
        $body.Add("labels",$labels)
        Invoke-RestMethod -Uri "$uri/assets/$($asset.AssetId)/labels/add" -Headers $znHeaders -Method Post -Body ($body | ConvertTo-Json -Depth 5)
    }
}