<#
    .Synopsis
    Simple API Call to Trusted Internet IPs
    .Description
    This example will loop IP addresses in a text file and add them to the Trust Internet settings.
#>

$apikey = "<apiKey>"

if($apiKey -eq "<apiKey>"){
    $apiKey = Read-Host -Prompt "Enter your API Key"
}
$znHeaders = @{"Authorization" = $apiKey; "Content-Type" = "application/json"; "Accept" = "application/json"}

$Path = Read-Host -Prompt "Enter the path to the file containing the IPs to add"

$ipsToAdd = Get-Content -Path $Path

$currentSetting = Invoke-RestMethod -Method Get -Uri "https://portal-dev.zeronetworks.com/api/v1/settings/system/trusted-external" -Headers $znHeaders

foreach($ip in $ipsToAdd){
    #check if the IP is already in the list
    if($currentSetting.config.externalIpsList -notcontains $ip){
        $currentSetting.config.externalIpsList += $ip
    }
}

Invoke-RestMethod -Method Put -Uri "https://portal-dev.zeronetworks.com/api/v1/settings/system/trusted-external" -Headers $znHeaders -Body ($currentSetting.config | ConvertTo-Json)