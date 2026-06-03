<#
    .Synopsis
    Batch adds assets to a Tag Group
    .Description
    This example will use the Zero Networks PowerShell module to import a csv of assets and batch add them to a specific tag group.
#>
$apiKey = ''
$assets = Import-CSV -Path "C:\path\to\assets.csv"
$groupId = 'g:t:xxxxxxxx'

if (-not(Get-Module -ListAvailable -Name ZeroNetworks)) {
    Install-Module ZeroNetworks -scope CurrentUser
}

Import-Module ZeroNetworks

Set-ZNApiKey -ApiKey $apiKey

#Batch the assets into tag groups
$batch = 0
$counter = 0
$batchAssets = @()
while ($counter -le $assets.Count) {
    $assetId = Search-ZNAsset -Fqdn $assets[$counter].Name
    $batchAssets += $assetId
    $counter++
    $batch++
    if($batch -eq 100){
        Add-ZNTagGroupsMember -GroupId $groupId -MembersId $batchAssets
        $batch = 0
        $batchAssets = @()
    }
}