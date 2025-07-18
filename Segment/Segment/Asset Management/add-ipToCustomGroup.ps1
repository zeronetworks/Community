param (
    [Parameter(Mandatory = $true)]
    [string]$IPaddress,

    [Parameter(Mandatory = $true)]
    [string]$GroupID,

    [Parameter(Mandatory = $false)]
    [string]$baseUri = "https://portal.zeronetworks.com/api/v1/",

    [Parameter(Mandatory = $true)]
    [string]$APIKey
)

# Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization", $APIKey)
$znHeaders.Add("content-type", "application/json")

# Function Lookup Remote Candidates
function remoteCandidates {
    param (
        [string[]]$ipsString # Input parameter is an array of strings (IP addresses)
    )
    $allResults = @() # Initialize an empty array to store all results
    $ips = $ipsString.Split(',') | ForEach-Object { $_.Trim() } # Split and trim IPs
    foreach ($ip in $ips) {
        $candidateUri = "$baseUri/protection/rules/inbound/remote-candidates?_limit=100&_offset=0&_search=$ip&ruleType=1"
        try {
            $results = Invoke-RestMethod -Uri $candidateUri -Method Get -Headers $znHeaders
            $allResults += $results # Append results to the array
        }
        catch {
            Write-Error "Failed to get remote candidates for IP: $ip - $_"
        }
    }
    return $allResults # Return the array of results
}

$eid = (remoteCandidates -ipsString $IPaddress).items.id

$body = @{
    membersId = @($eid)
}
$jsonBody = $body | ConvertTo-Json -Depth 1
$uri = "$baseUri/groups/custom/$GroupID/members"

Invoke-RestMethod -Uri "$uri" -Method PUT -Headers $znHeaders -Body $jsonBody
