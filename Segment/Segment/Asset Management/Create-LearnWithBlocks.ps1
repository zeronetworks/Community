$apikey = "<apiKey>"

#Build Headers and uri
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$apiKey)
$znHeaders.Add("Content-Type","application/json")
$uri = "https://portal.zeronetworks.com/api/v1/"

#Check for Custom Group
$res = Invoke-RestMethod -Method Get -Uri ($uri+"groups/custom?_limit=100&_offset=0&_filters=[%7B%22id%22:%22name%22,%22includeValues%22:[%22AllLearningWithBlocks%22],%22excludeValues%22:[]%7D]&order=asc&orderColumns[]=name&with_count=true&showInactive=false") -Headers $znHeaders
if($res.count -eq 0){
    #Create Custom Group
    $body = @{
        "description" = "All assets in Learning with blocks mode"
        "membersId" = @()
        "name" = "AllLearningWithBlocks"
    }

    $group = Invoke-RestMethod -Method Post -Uri ($uri+"groups/custom") -Headers $znHeaders -Body ($body | ConvertTo-Json -Depth 3)
    $group = $group.entity
} else {
    $group = $res.Items | where {$_.Name -eq "AllLearningWithBlocks"}
}

#Get all assets in Learning with blocks mode
$assetCount = (Invoke-RestMethod -Method Get -Uri ($uri+"assets/queued?_limit=1&_offset=$offset&with_count=true") -Headers $znHeaders).Count
$assetsInLearning = @()
$offset = 0
do {
    $res = Invoke-RestMethod -Method Get -Uri ($uri+"assets/queued?_limit=400&_offset=$offset") -Headers $znHeaders
    $offset = $res.nextOffset
    $assetsInLearning += $res.Items
} while ($offset -lt $assetsInLearning)

#filter just the assets in learn with blocks
$assetsInLearningWithBlocks = @()
$assetsInLearningWithBlocks += $assetsInLearning | where {$_.state.protectionState -eq 15 -or $_.state.protectionState -eq 16 -or $_.state.protectionState -eq 17 -or $_.state.protectionState -eq 18}

#Batch the assets into custom groups
$batch = 0
$counter = 0
$batchAssets = @()
do {
    $batchAssets += $assetsInLearningWithBlocks[$counter].id
    $counter++
    $batch++
    if($batch -eq 100){
        $body = @{
            "membersId" = $batchAssets
        }
        Invoke-RestMethod -Method Put -Uri ($uri+"groups/custom/"+$group.Id+"/members") -Headers $znHeaders -Body ($body | ConvertTo-Json -Depth 3)
        $batch = 0
        $batchAssets = @()
    }
} while ($counter -le $assetsInLearningWithBlocks.Count)
