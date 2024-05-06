<#
.SYNOPSIS
    Retrieves and processes service accounts that have logged on within a specified number of days.

.DESCRIPTION
    This script fetches service accounts that have logged on within the past 'n' days from a specified API endpoint.
    It requires an API key which it reads from a file. The script pages through all service accounts, filters
    out those which haven't logged on within the past 'n' days or are in a certain protection state, and optionally queues them
    for an operation if any are found.

.PARAMETER n
    Specifies the number of days in the past to check for account activity. Default is 180 days.

.PARAMETER APIKeyFile
    Specifies the path to the file containing the API key needed for authentication with the API.

.EXAMPLE
    .\ScriptName.ps1 -n 180 -APIKeyFile 'keys\external.txt'

    This runs the script with a lookback period of 180 days and reads the API key from 'keys\external.txt'.

.INPUTS
    None. You cannot pipe objects to this script.

.OUTPUTS
    Outputs the names of the active service accounts and performs a POST request if valid accounts are found.

.NOTES
    Version:        1.0
    Author:         Ken Ward
    Creation Date:  5/6/2024
    Purpose/Change: Initial script development

#>

# Usage of parameters (if needed in the script for flexibility)
param (
    [int]$n = 180,
    [string]$APIKey = '<API_KEY>'
)

# Get the date from n days ago
$dateNdaysAgo = (Get-Date).AddDays(-$n)

#Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$APIKey)
$znHeaders.Add("content-type","application/json")

$uri = "https://portal.zeronetworks.com/api/v1"

$usersToCheck = @()

#Get the total number of assets
$allUsers= Invoke-RestMethod -Uri "$uri/users/service-account?_limit=1&_offset=0&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders

$i=0

#Page through results if needed
for(;$i -le ($allUsers.Count);) { 
    $usersToCheck += (Invoke-RestMethod -Uri "$uri/users/service-account?_limit=400&_offset=$i&_filters=&with_count=true&order=asc&orderColumns[]=name" -Method Get -Headers $znHeaders).items
    $i = $i+400
 }

 $currentUsers = @()
 
 #Get service accounts that have logged on in n days
 foreach($svcAcct in ($usersToCheck | Where-Object {$_.lastLogon -gt (Get-Date -Date $dateNdaysAgo -UFormat %s) -and $_.protectionState -ne 3 })){
    $currentUsers  += $svcAcct
}

$currentUsers | Select-Object -ExpandProperty Name
$ids = $currentUsers | Select-Object -ExpandProperty id

#Make sure there is at least one account to act on
if($currentUsers.Count){
    $body = @{
        queueDays = 30
        userIds = @($ids)
    }
    $jsonBody = $body | ConvertTo-Json
    
    Invoke-RestMethod -Uri "$uri/users/service-account/queue" -Method Post -Headers $znHeaders -Body $jsonBody
} else {
    Write-Host "No Accounts Match timing"
}

