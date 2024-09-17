# this script is designed to take a list of assets and move them into learning
# Get API Token from the console
$apiToken = "YOUR_API"
# path to a file C:\temp\hosts.txt
$file = "PATH_TO_FILE.txt"
# update this with your AD domain 
$adDomain = "YOUR_DOMAIN.com"
# how many days you want to learn.
$daysToLearn = 30

# check for zero networks powershell module
if(get-module ZeroNetworks -ListAvailable){
    Write-Host "Importing Module"
    Import-Module ZeroNetworks
} else {
    write-host "Installing Module"
    Install-Module ZeroNetworks -Scope CurrentUser -Force
    Import-Module ZeroNetworks
}

Set-ZNApiKey -ApiKey $apiToken

$hosts = Get-Content $file

$items = @()
foreach($host in $hosts){
    $name = $host + "." + $adDomain
    $assetId = (Search-ZNAsset -Fqdn $name).AssetId
    $items += "$assetId"
}

Invoke-ZNAssetNetworkQueue -items $items -QueueDays $daysToLearn
