$apiKey = ''

if (-not(Get-Module -ListAvailable -Name ZeroNetworks)) {
    Install-Module ZeroNetworks -scope CurrentUser
}

Import-Module ZeroNetworks

Set-ZNApiKey -ApiKey $apiKey

#Get the client system group
$clientsGroup = (Get-ZNGroup -Search clients).Items | where {$_.id -like "g:s:*"}

#build filter Idseg is not segmented and memberOf Clients group.
$filters = '[{"id":"identityProtectionStatus","includeValues":["1"],"excludeValues":[]},{"id":"nestedMemberOf","includeValues":["'+($clientsGroup.Id)+'"],"excludeValues":[]}]'

#get the count of assets
$count = (Get-ZNAssetsMonitored -Limit 1 -filters $filters -WithCount).Count

#loop to get all the asset Ids that match the filter.
$offset = 0
$assets = @()
while ($offset -lt $count) {
    $assets += (Get-ZNAssetsMonitored -Limit 400 -Offset $offset -Filters $filters).Items
    $offset += 400
}

#Batch the assets into id learning
$batch = 0
$counter = 0
$batchAssets = @()
while ($counter -le $assets.Count) {
    $batchAssets += $assets[$counter].Id
    $counter++
    $batch++
    if($batch -eq 100){
        $body = @{
            "items" = $batchAssets
            "queueDays" = 30
        }
        Invoke-RestMethod -uri "https://portal.zeronetworks.com/api/v1/assets/identity-actions/queue" -Headers @{"Authorization" = $apiKey; "Content-Type" = "application/json"} -Method Post -Body ($body | ConvertTo-Json)
        $body = $null
        $batch = 0
    }
}