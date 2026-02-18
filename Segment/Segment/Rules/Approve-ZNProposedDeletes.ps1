<#
    .Synopsis
    Simple script to mass accept proposed delete rules
    .Description
    This example script will fetch all rules in a proposed delete stat and accept the deletion of those rules.
    .PARAMETER WhatIf
    Does not perform any deletions, only simulates the actions with output
    .PARAMETER InactiveAssetsOnly
    When specified, only rules associated with inactive assets will be processed.
    .PARAMETER NoHitsOnly
    When specified, only rules that have 0 hits in the last 6 months hits will be processed.
    .PARAMETER ApiKey
    The API key to use for authentication to the Zero Networks portal, must be a read/write key.
#>

param(
    [switch]$WhatIf,
    [switch]$InactiveAssetsOnly,
    [switch]$NoHitsOnly,
    [string]$ApiKey = ""
)
if($ApiKey -eq ""){
    Write-Error "An API key must be provided via the ApiKey parameter"
    exit 1
}

function Read-ZNJWTtoken {
 
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
 
    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
 
    #Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    Write-Verbose "Base64 encoded (padded) header:"
    Write-Verbose $tokenheader
    #Convert from Base64 encoded string to PSObject all at once
    Write-Verbose "Decoded header:"
    #[System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | fl | Out-Default
 
    #Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    Write-Verbose "Base64 encoded (padded) payoad:"
    Write-Verbose $tokenPayload
    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Verbose "Decoded array in JSON format:"
    Write-Verbose $tokenArray
    #Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json
    Write-Verbose "Decoded Payload:"
    
    return $tokobj
}

$decodedToken = Read-ZNJWTToken $ApiKey
$ZNAccountName = $decodedToken.aud.Split(".zeronetworks.com")[0]

#Build Headers and uri
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$apiKey)
$znHeaders.Add("Content-Type","application/json")
$uri = "https://$ZNAccountName.zeronetworks.com/api/v1/"

# Get all rules in proposed delete state
Write-Host "Getting count of rules in proposed delete state..."
$rulesCount = (Invoke-RestMethod -Method GET -Uri ($uri + "protection/rules/inbound?_limit=100&_offset=0&_filters=[%7B%22id%22:%22ruleSuggestionType%22,%22includeValues%22:[%222%22],%22excludeValues%22:[]%7D]&with_count=true&_add_builtins=false&_add_ancestors=true&_enrich_remote_ips=true&order=desc&orderColumns[]=createdAt") -Headers $znHeaders).count
Write-Host "Found $rulesCount rules in proposed delete state."

#fetch all rules
Write-Host "Fetching all rules in proposed delete state..."
$limit = 400
$offset = 0
$rules = @()
do {
    $offset
    $rules += (Invoke-RestMethod -Method GET -Uri ($uri + "protection/rules/inbound?_limit=$limit&_offset=$offset&_filters=[%7B%22id%22:%22ruleSuggestionType%22,%22includeValues%22:[%222%22],%22excludeValues%22:[]%7D]&with_count=false&_add_builtins=false&_add_ancestors=true&_enrich_remote_ips=true&order=desc&orderColumns[]=createdAt") -Headers $znHeaders).Items
    $offset += $limit
    
} while ($offset -le $rules.Count)
Write-Host "Fetched $($rules.Count) rules."

# Process each rule
$rulesDeleted = 0
$rulesWouldDelete = 0
write-Host "Processing rules..."
foreach($rule in $rules){
    if($NoHitsOnly -and $rule.suggestionReason -eq "Rule cleanup: This rule has not been used in the last 6 months"){
        If($WhatIf){
            Write-Host "Would approve deletion of rule ID $($rule.id) with 0 hits in last 6 months."
            $rulesWouldDelete++
        } else {
            Write-Host "Approving deletion of rule ID $($rule.id) with 0 hits in last 6 months."
            #Invoke-RestMethod -Method DELETE -Uri ($uri + "protection/rules/inbound/review/approve-delete/$($rule.id)") -Headers $znHeaders
            $rulesDeleted++
        }
    }
    if($InactiveAssetsOnly -and $rule.suggestionReason -eq "Rule cleanup: This rule references an inactive asset(s)"){
        If($WhatIf){
            Write-Host "Would approve deletion of rule ID $($rule.id) with inactive assets."
            $rulesWouldDelete++
        } else {
            Write-Host "Approving deletion of rule ID $($rule.id) with inactive assets."
            #Invoke-RestMethod -Method DELETE -Uri ($uri + "protection/rules/inbound/review/approve-delete/$($rule.id)") -Headers $znHeaders
            $rulesDeleted++
        }
    }
}
Write-Host "Processing complete."
if($WhatIf){
    Write-Host "$rulesWouldDelete rules would be approved for deletionout of $($rules.Count)."
} else {
    Write-Host "$rulesDeleted rules have been approved for deletion out of $($rules.Count)."
}