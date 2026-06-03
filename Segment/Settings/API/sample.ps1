$APIKey = '<INSERT_KEY>'

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"


#Get the total number of assets
$allAssets = Invoke-RestMethod -Uri "$uri/assets?_limit=1&_offset=0&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders

$allAssets
