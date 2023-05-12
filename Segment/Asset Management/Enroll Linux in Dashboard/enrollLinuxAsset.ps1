<#

.NOTES
    NAME: Thomas Obarowski
    LINK: https://github.com/tjobarow/
    AUTHOR: tjobarow@gmail.com
    VERSION: 1.0

.SYNOPSIS
   This script accepts a CSV of Linux servers, and adds them to the Zero Networks dashboard as a manual Linux asset. 
   
.DESCRIPTION
   This script does the following:
   - Reads a list of Linux hostnames from a CSV file named linx-assets.csv
   - Normalizes all hostnames to include your company domain at the end - this is incase some hostnames do not have trailing domain in CSV
        - e.g.: linuxserver gets correct to linuxserver.company.com
        - YOU MUST UPDATE THE STRING ON LINES 67 & 72 TO MATCH YOUR COMPANY DOMAIN
   - Makes a REST API call to Zero Networks to enroll the Linux host as a manual Linux asset. 
        - The displayName and FQDN parameters of the API call are the same value - the full FQDN of the linux host (linuxserver.company.com)
        - The API token is read from a text file, named token.txt - you must create this file for the API call to succeed
    - This information is logged to a .log file, including the asset ID returned from the API

    Note: Make sure to update the string to match your company's domain on lines 67 & 72 

.EXAMPLE
   Update .csv to contain contains several hostnames of linux servers: 
   testserver1.company.com
   testserver2
   testserver3

   (It doesn't matter whether you put the domain or not, as long as you have updated the domain on lines 67 & 72 )

   The script will then run, read the contents of the CSV, and add them to Zero Networks. The output will be logged to the console, as well
   as a log file named "<%Y-%m-$d>-enroll-linux-script.log" (where <%Y-%m-$d> is the current Year-Month-Day)
   2023-01-26 2023 23:21:29: Reading contents of linux-assets.csv...
   2023-01-26 2023 23:21:29: Found linuxserver1.company.com in the CSV...
   2023-01-26 2023 23:21:29: Found linuxserver2.company.com in the CSV...
   2023-01-26 2023 23:21:29: Setting up request headers...
   2023-01-26 2023 23:21:29: Making POST request to https://portal.zeronetworks.com/api/v1/assets/linux create linuxserver1.company.com...
   2023-01-26 2023 23:21:30: Linux host created - linuxserver1.company.com has asset ID: <<ASSET ID RETURNED>>...
   2023-01-26 2023 23:21:30: Making POST request to https://portal.zeronetworks.com/api/v1/assets/linux create linuxserver2.company.com...
   2023-01-26 2023 23:21:30: Linux host created - linuxserver2.company.com has asset ID: <<ASSET ID RETURNED>>...

.INPUTS
    - File named "linux-assets.csv" that lives in the same directory as the script is ran from
    - Text file named "token.txt" which contains your dashboard API token

.OUTPUTS
   Log file named "<%Y-%m-$d>-enroll-linux-script.log" (where <%Y-%m-$d> is the current Year-Month-Day)
   
#>

# Log info
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Reading contents of linux-assets.csv..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-enroll-linux-script.log" -Append
#Load list of Linux hosts to be added to ZN dashboard from CSV named "linux-asssets.csv"
$hostCsvObj = Get-Content -Path .\linux-assets.csv | Select-Object -Skip 1 | ConvertFrom-Csv -Header 'HostName'

#This empty list will hold the Linux assets to add to ZN. This list will be iterated through and each host added to dashboard
$hostList = @()

<#
The way we generated an inventory of linux servers means some of the hostnames in the loaded CSV have our domain at the end, while others do not.
Our goal is to have the hosts sent to ZN in the format of <hostname>@<domain>.com
#>

#So for each hostname from the CSV
foreach ($hostname in $hostCsvObj){
    #If the hostname is attached, save it to $hostFixed variable w/o doing anything.
    if ( ($hostname).HostName -match ".company.com") {
        $hostFixed = ($hostname).HostName
    }
    #Else if it doesn't already have the domain, add the domain to the end
    else {
        $hostfixed = "$(($hostname).HostName).company.com"
    }
    #And add this normalized hostname to the $hostList 
    $hostList += $hostFixed
    #Log info
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Found $hostFixed in the CSV..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-enroll-linux-script.log" -Append
}

#Log info
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Setting up request headers..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-enroll-linux-script.log" -Append
<#
Set up params for the API call.

This is NOT just query parameters, but is actually a hashtable of all parameters to pass to Invoke-RestMethod 
#>
$params = @{
    Uri="https://portal.zeronetworks.com/api/v1/assets/linux"
    Method="Post"
    Headers=@{
        #The API token is stored in a text file named "token.txt"
        "Authorization"="$(Get-Content -Path .\token.txt)"
        "Accept"="application/json"
        "Content-Type"="application/json"
    }
}

<#
For each Linux host in the host list, we construct the request body using a hashtable, and then use Invoke-RestMethod to add the Linux host to ZN

A try/catch is used in case the web request fails for whatever reason. Invoke-WebRequest should (per my understanding) count certain HTTP status codes
(such as 404) as errors and throw an exception. There is no real handling besides printing and logging that failure.

#>
foreach ($linuxHost in $hostList) {
    $params["Body"]=@{
        "displayName"=$linuxHost
        "fqdn"=$linuxHost
    }  | ConvertTo-Json 
    $linuxHost
    $params
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Making POST request to $($params.Uri) create $linuxHost..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-enroll-linux-script.log" -Append
    try {
        $response=Invoke-RestMethod @params
        $response
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Linux host created - $linuxHost has asset ID: $response..." | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-enroll-linux-script.log" -Append
    } catch {
        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Web request failed:\n
        Status code $($_.Exception.Response.StatusCode.value__)\n
        Status Description:$($_.Exception.Response.StatusDescription)"

        "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Web request failed:\n
        Status code $($_.Exception.Response.StatusCode.value__)\n
        Status Description:$($_.Exception.Response.StatusDescription)" | Out-File -FilePath ".\$(Get-Date -UFormat "%Y-%m-%d")-enroll-linux-script.log" -Append
    }
}