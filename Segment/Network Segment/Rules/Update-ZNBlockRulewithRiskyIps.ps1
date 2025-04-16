#Get API key from settings and paste here
$APIKey = ''
#Get the block rule id from the portal and paste here
$blockRuleId = ""

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("Accept","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"

#get Activities from the last 24 hours
[string]$from = ([datetimeoffset](Get-Date -AsUTC).AddDays(-1).Date).ToUnixTimeMilliseconds()
[string]$to = ([datetimeoffset]((Get-Date -AsUTC).AddDays(-1).Date | Get-Date -Hour 23 -Minute 59 -Second 59)).ToUnixTimeMilliseconds()
$filters = "_limit=400&order=desc&from=$from&to=$to&_filters=[%7B%22id%22:%22srcRiskLevel%22,%22includeValues%22:[%222%22],%22excludeValues%22:[]%7D,%7B%22id%22:%22state%22,%22includeValues%22:[%223%22],%22excludeValues%22:[]%7D]"

#Handling paging
$doneScrolling = $false
do {
    $data = Invoke-RestMethod -Uri "$uri/activities/network?$filters" -Method Get -ContentType application/json -Headers $znHeaders
    $activities += $data.items
    if($data.scrollCursor){
        $scrollCuror = $data.scrollCursor
        $filters = "_limit=400&order=desc&from=$from&to=$to&_cursor=$scrollCuror&_filters=[%7B%22id%22:%22srcRiskLevel%22,%22includeValues%22:[%222%22],%22excludeValues%22:[]%7D,%7B%22id%22:%22state%22,%22includeValues%22:[%223%22],%22excludeValues%22:[]%7D]"
    }
    else {
        $doneScrolling = $true
    }
} while (
    $doneScrolling = $false
)

Write-Host "Found "$activities.Count" new ips"

#Get the block rule
$blockRule = (Invoke-RestMethod -Uri "$uri/protection/rules/inbound-block/$blockRuleId" -Method Get -ContentType application/json -Headers $znHeaders).items

#Get the blocked IPs
$blockedIps = $blockRule.remoteEntityIdsList


#Encode New IPs and add to blocked Ips list
foreach($activity in $activities){
    if($activity.src.assetId -in $blockedIps){}
    else {
        $blockedIps += $activity.src.assetId
    }
}

#set the updated rule properties
$updatedBlockRule = @{
    "description"= $blockRule.description
    "expiresAt" = $blockRule.expiresAt
    "localEntityId" =  $blockRule.localEntityId
    "localProcessesList"= @(
      "*"
    )
    "portsList" = @(
        $blockRule.portsList
    )
    "remoteEntityIdsList" = @($blockedIps)
    "state" = $blockRule.state
  }

#Update the rule
Invoke-RestMethod -Uri "$uri/protection/rules/inbound-block/$blockRuleId" -Method PUT -Body ($updatedBlockRule | ConvertTo-Json) -Headers $znHeaders -ContentType application/json