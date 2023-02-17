<#PSScriptInfo
.NAME Thomas Obarowski
.LINK https://github.com/tjobarow/
.AUTHOR tjobarow@gmail.com

.VERSION 1.0


.Synopsis
   This script accepts a CSV of assets which SHOULD be monitored, and queries the ZN API to see if they are showing as monitored.. 
   
.DESCRIPTION
    This script does the following:
    - Reads a list of asset hostnames from a CSV named targeted-assets.csv
    - Retrieves all monitored assets from ZN API
        - Uses some basic math to determine how many pages of data need to be retrieved to get all monitored assets
        - REQUIRES YOUR API TOKEN BE STORED IN A FILE NAMED token.txt WITHIN SAME DIRECTORY AS SCRIPT
    - Checks to see if each asset within targeted-assets.csv exists within all of the monitored assets retrieved from ZN API
    - It will write the data to a new CSV named <%Y-%m-%d>-mon-assets-audit-report.csv, which saves into the directory the script is ran from
        - The CSV includes every asset from targeted-assets.csv in column 1, and whether (true/false) they are monitored in column 2

.EXAMPLE
   Update .csv to contain contains asset hostnames: 
   testserver1.company.com
   testserver2
   testserver3

   (It doesn't matter whether you put the domain or not, as the script will only pay attention to the actual hostname, not domain )

    The script will then run, read the contents of the CSV, query the ZN API for all monitored assets, and then compare the list of
    targeted assets (from targeted-assets.csv) to the monitored assets returned from ZN API. It logs this process to the console, as
    well as a log file. 

        2023-02-06 2023 10:09:02: Found host testserver1 in CSV file...
        2023-02-06 2023 10:09:02: Found host testserver2 in CSV file...
        ... (portions omitted) ...
        2023-02-06 2023 10:09:02: Setting up request headers...
        2023-02-06 2023 10:09:02: Making API call to determine # of monitored assets that exist..
        2023-02-06 2023 10:09:02: Found a total of 234 monitored assets currently in ZN...
        2023-02-06 2023 10:09:02: Will need to make 3 to /assets/monitored endpoint to get all monitored assets... (Page limit = 100)...
        2023-02-06 2023 10:09:02: Making request  #1 to ZN /assets/monitored API endpoint...
        ... (portions omitted) ...
        2023-02-06 2023 10:09:02: API call returned testserver1 as a monitored asset...
        2023-02-06 2023 10:09:02: API call returned testserver3 as a monitored asset...
        ... (portions omitted) ...
        2023-02-06 2023 10:09:04: Comparing list of assets which should be monitored, to what is actually monitored per ZN API...
        2023-02-06 2023 10:09:04: testserver1 is showing as remotely monitored...
        2023-02-06 2023 10:09:04: testserver2 is NOT SHOWING as remotely monitored...
        ... (portions omitted) ...

    The script then prints this data to console, as well as exports it to a CSV.

        2023-02-06 2023 10:09:04: Printing contents of status list...
        hostName           monitorStatus
        --------           -------------
        testserver1             True
        testserver2             False
        Saving results of script to CSV file...

.INPUTS
    - File named "targeted-assets.csv" that lives in the same directory as the script is ran from
    - Text file named "token.txt" which contains your dashboard API token

.OUTPUTS
   Log file named "<%Y-%m-$d>-audit-mon-assets-script.log" (where <%Y-%m-$d> is the current Year-Month-Day)
   CSV file named "<%Y-%m-$d>-mon-assets-audit-report.csv" that contains the monitored status of each targeted asset


.NOTES
   Make sure you have your API token saved in a text file named token.txt within the same directory
    - You can realisticly pass this script your token however you see fit. The token is required to construct the request headers
    - on line 99.

    Based on trial and error, my understanding of asset status via API is:
        protection state:
            1 = monitored
            2 = learning
            3 = protected
#>

#Log data
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Loading list of assets that should be actively monitored..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Loading list of assets that should be actively monitored..."

#Load list of hosts that have been added to AD group
$hostCsvObj = Get-Content -Path .\targeted-assets.csv | Select-Object -Skip 1 | ConvertFrom-Csv -Header 'hostname','monitor status'

#Just for logging purposes
foreach ($asset in $hostCsvObj){
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Found host $($asset.hostname) in CSV file..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
}


<#
Configure Parameters that will be used for all API calls. 
These are not query paramters, but Invoke-RestMethod parameters, for that function call itself
#>
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Setting up request headers..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Setting up request headers..."
$params = @{
    Method="Get"
    Headers=@{
        "Authorization"="$(Get-Content -Path .\token.txt)"
        "Accept"="application/json"
        "Content-Type"="application/json"
    }
}


#logging
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Making API call to determine # of monitored assets that exist.." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Making API call to determine # of monitored assets that exist.."

<# 
Make API call to /assets/statistics which will give us # of monitored assets
This is needed because we will need to potentially make multiple requests to /assets/monitored if # of  monitored assets 
exceeds our response limit of 100 assets per request.
#>
$response=Invoke-RestMethod @params -Uri "https://portal.zeronetworks.com/api/v1/assets/statistics"
$totalMonAssets=$response.item.monitoredCount
$totalReqToMake=0

#Logging 
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Found a total of $totalMonAssets monitored assets currently in ZN..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Found a total of $totalMonAssets monitored assets currently in ZN..."

#Our limit will be 100 assets returned per request to /assets/monitored, so if there are 100 or less total monitored assets we only need to make 1 request
if ([int]$totalMonAssets -le 100) {
    $totalReqToMake=1
}

#Else if there are more than 100, take the total number of monitored assets, divide it by 100, add 1, and round down to get how many requests we will need to make
else {
    $totalReqToMake=[math]::Floor(([int]$totalMonAssets/100)+1)
}

#Logging
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Will need to make $totalReqToMake to /assets/monitored endpoint to get all monitored assets... (Page limit = 100)..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Will need to make $totalReqToMake to /assets/monitored endpoint to get all monitored assets... (Page limit = 100)..."

<#
Make $totalReqToMake number of requests to get all monitored assets
We scale $i up by 100, because if we do, we can use it as the offset variable to pass the API call to get additional pages of data :) Just makes things simpler overall

Assets returned will be saved to the $monAssetHT hashtable
#>
$monAssetHT=@{}

#For loop will call the Invoke-RestMethod function $totalReqToMake times
for ($i=0; $i -lt ($totalReqToMake*100); $i+=100) {
    
    #Logging
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Making request  #$(($i+100)/100) to ZN /assets/monitored API endpoint..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Making request  #$(($i+100)/100) to ZN /assets/monitored API endpoint..."

    #Make REST API call
    $response=Invoke-RestMethod @params -Uri "https://portal.zeronetworks.com/api/v1/assets/monitored?_offset=$i&_limit=100"
    
    #And for each asset returned by that API call, we save the assets hostname and IP Address as a new key/value pair in the $monAssetsHT hashtable.
    foreach ($monAsset in $response.items){
        
        #We only want the hostname, not full FQDN, so .Split(".")[0] will split the returned hostname using "." as delimiter, and we take the 0 index of that to save only the hostname
        $monAssetHT.Add($monAsset.name.Split(".")[0],$monAsset.ipV4Addresses[0])
        
        #Logging
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): API call returned $($monAsset.name.Split(".")[0]) as a monitored asset..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): API call returned $($monAsset.name.Split(".")[0]) as a monitored asset..."
    }
}

<#
This section iterates through each hostname that SHOULD be actively monitored (loaded from CSV) and sees if the hostname exists
as a key in $monAssetHT. $monAssetHT contains all hosts that are actively monitored in ZN per the API calls made in the 
previous section.

If an asset exists in $monAssetHT, we know it is remotely monitored (and is actually sending data to ZN), so we create a PSCustomObject to reflect that, and add it to a list named $statusList

If an asset DOES NOT exist in $monAssetHT, we know it is NOT YET remotely monitored (waiting for GPO refresh, or could be an issue), so we create a PSCustomObject to reflect that, and add it to a list named $statusList
#>

#Logging
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Comparing list of assets which should be monitored, to what is actually monitored per ZN API..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Comparing list of assets which should be monitored, to what is actually monitored per ZN API..."

$statusList = @()
foreach ($hostName in $hostCsvObj){
    if($monAssetHT.ContainsKey($hostName.hostname.Split(".")[0])) {
       #Logging
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): $($hostName.hostname) is showing as remotely monitored..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): $($hostName.hostname) is showing as remotely monitored..."
        
        #Create PSCustomObject which will be used later to generate a CSV
        $statusList += [PSCustomObject]@{
            hostName=$hostName.hostname
            monitorStatus="True"
        }
    }
    else {
        #Logging
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): $($hostName.hostname) is NOT SHOWING as remotely monitored..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): $($hostName.hostname) is NOT SHOWING as remotely monitored..."
        
        #Create PSCustomObject which will be used later to generate a CSV
        $statusList += [PSCustomObject]@{
            hostName=$hostName.hostname
            monitorStatus="False"
        }
    }
}

# Logging
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Printing contents of status list..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append

#Print table to log file
$statusList | Format-Table -Property hostName,monitorStatus | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append

#Export the status list to a CSV 
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Saving results of script to CSV file..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-audit-mon-assets-script.log" -Append
$statusList | Export-Csv -Path "$(Get-Date -UFormat "%Y-%m-%d")-mon-assets-audit-report.csv" -NoTypeInformation
