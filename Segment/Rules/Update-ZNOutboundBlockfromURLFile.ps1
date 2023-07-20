#Get API key from settings and paste here
$APIKey = ""

#Get the block rule description from the portal and paste here
$blockRuleName = "Block Bad Domain URLs"

#Get the filepath of bad URLs
$badURLFilePath = "c:\tmp\badurls.txt"

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("Accept","application/json")
$filters = "_limit=400&order=desc"


$uri = "https://portal.zeronetworks.com/api/v1"

$blockedURLs = @()

#Get the block rule

#Handling paging
$doneScrolling = $false
do {
    $blockRules = (Invoke-RestMethod -Uri "$uri/protection/rules/outbound-block/?$filters" -Method Get -ContentType application/json -Headers $znHeaders).items
    $activities += $blockRules.items
    if($blockRules.scrollCursor){
        $scrollCuror = $blockRules.scrollCursor
        $filters = "_limit=400&order=desc&from=$from&to=$to&_cursor=$scrollCuror"
    }
    else {
        $doneScrolling = $true
    }
} while (
    $doneScrolling = $false
)

$found = $false

foreach($blockRule in $blockRules){
    if($blockRule.description -eq $blockRuleName ){
        $blockRuleId = $blockRule.id
        $found = $true
        break
    } 
}

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

#NOT FOUND
if(!$found){

    Write-Host "Rule not found, please create outbound block rule in the portal!"

}else{
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
}
