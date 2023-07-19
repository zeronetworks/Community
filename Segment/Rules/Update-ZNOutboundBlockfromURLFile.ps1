#Get API key from settings and paste here
$APIKey = $Env:ZNAPIKey

#Get the block rule id from the portal and paste here
$blockRuleId = ""

#Get the filepath of bad URLs
$badURLFilePath = "c:\tmp\badurls.txt"

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("Accept","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"

$blockedURLs = @()

#Get the block rule
$blockRule = (Invoke-RestMethod -Uri "$uri/protection/rules/outbound-block/$blockRuleId" -Method Get -ContentType application/json -Headers $znHeaders).items

#Get the bad URLs from file
$badURLs = Get-Content $badURLFilePath

foreach($url in $badURLs){
    #check for wildcard
    if($url.StartsWith("*")){
        $blockedURLs += "b:18$url"
    } else {
        $blockedURLs += "b:17$url"
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
    "remoteEntityIdsList" = @($blockedURLs)
    "state" = $blockRule.state
  }

  #Update the rule
Invoke-RestMethod -Uri "$uri/protection/rules/outbound-block/$blockRuleId" -Method PUT -Body ($updatedBlockRule | ConvertTo-Json) -Headers $znHeaders -ContentType application/json