$APIKey = "<INSERT_API_KEY>"

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")


$uri = "https://portal.zeronetworks.com/api/v1"


function Show-AssetsDates {
    param (
        $status = "monitored"  # Define a default value for the status parameter
    )
    
    Write-Output "--------------Fetching dates for $status Assets..."

    # Use $status variable in the API string
    $apiString = "assets/$($status)?_limit=1&_offset=0&_filters=&order=asc&orderColumns[]=name&showInactive=false&with_count=true"
    $assetsToCheck = @()

    # Get the total number of assets
    $allAssets = Invoke-RestMethod -Uri "$uri/$apiString" -Method Get -Headers $znHeaders

    $i = 0

    # Page through results if needed
    for (; $i -le ($allAssets.Count);) { 
        $assetsToCheck += (Invoke-RestMethod -Uri "$uri/assets/$($status)?_limit=400&_offset=$i&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders).items
        $i = $i + 400
    }

    # Get Audit data for assets in the specified status
    foreach ($lasset in $assetsToCheck) {
        $apiString = "assets/$($lasset.id)/audit?_limit=30&_cursor=&_search=&_filters=[%7B%22id%22:%22auditType%22,%22includeValues%22:[%227%22,%2244%22],%22excludeValues%22:[]%7D]&order=desc"  
        $audits = Invoke-RestMethod -Uri "$uri/$apiString" -Method Get -Headers $znHeaders
        Write-Host $lasset.name $audits.items[0].isoTimestamp | FT
    }
}

# Show Monitored Assets
Show-AssetsDates -status "monitored" 
# Show Learning Assets
Show-AssetsDates -status "queued" 
# Show Segmented Assets
Show-AssetsDates -status "protected" 
