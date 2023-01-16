<#
    .Synopsis
    Simple API Call to add an OT/IoT asset entry to Zero Networks
    .Description
    This example will loop through OT assets in a provided CSV file and then add each individual asset to Zero Networks OT/IoT asset group.
#>

$apikey = "<apiKey>"

$OTAssets = import-csv .\ESXHostIPs.csv

#Build Headers and uri
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$apiKey)
$znHeaders.Add("Content-Type","application/json")
$uri = "https://portal.zeronetworks.com/api/v1/assets/ot"

foreach($ot in $OTAssets){
    $name = $ot.Name
    $ip = $ot.IP
    $body = @{
        "type" = 12
        "ipv4" = "$ip"
        "displayName"= "$name"
    }
    Invoke-RestMethod -Method POST -Uri $uri -Body ($body | ConvertTo-Json) -Headers $znHeaders
}