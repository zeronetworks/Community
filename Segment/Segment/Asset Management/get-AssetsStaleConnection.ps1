$APIKey = ' '

# Define the number of days
$n = 180  # Change this value as per your requirement

# Get the date from n days ago
$dateNdaysAgo = (Get-Date).AddDays(-$n)

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"

$assetsToCheck = @()

#Get the total number of assets
$allAssets = Invoke-RestMethod -Uri "$uri/assets?_limit=1&_offset=0&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders

$i=0

#Page through results if needed
for(;$i -le ($allAssets.Count);) { 
    $assetsToCheck += (Invoke-RestMethod -Uri "$uri/assets?_limit=400&_offset=$i&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders).items
    $i = $i+400
 }

 $disconnectedAssets = @()
 
 #Get machines that are disconnected and the lastLogonTimestamp is $n number of days ago
 foreach($asset in ($assetsToCheck | Where-Object {$_.state.isAssetConnected -eq $false -and $_.lastLogonTimestamp -lt (Get-Date -Date $dateNdaysAgo -UFormat %s) })){
    $disconnectedAssets  += $asset
}
