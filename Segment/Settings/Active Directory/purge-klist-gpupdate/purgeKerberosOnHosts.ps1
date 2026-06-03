<#

.NOTES
    NAME: Thomas Obarowski
    LINK: https://github.com/tjobarow/
    AUTHOR: tjobarow@gmail.com
    VERSION: 1.0

.SYNOPSIS
   This script accepts a CSV of remote Windows servers, and runs several command useful for forcing GPO processing
   
.DESCRIPTION
   This script accepts a CSV list of remote Windows servers which have been added to the "ZNMonitoredAssets" AD group
   and uses the cmdlet "Invoke-Command" to remotely clear the each servers Kerberos ticket, and force a group policy
   update. It uses "jobs" inside of "Invoke-Command" in order to asynchronously run these commands on all listed servers.
   When all jobs are complete, this script will retrieve all job results, and print/log them to the user for verification. 
   The script requires the user to provide valid credentials for a domain account with permissions to make remote calls
   to the servers in the provided hosts.csv file. 

   Since the Kerberos ticket on a server contains group membership information, until the ticket refreshes, the asset will 
   not process the ZerNetworksMonitoredAssets GPO, and thus will not send firewall event logs to ZN. This script force refreshes the
   ticket, and then forces a group policy update. This significantly can speed up the time it takes for an asset to appear
   as monitored, and send data to ZN. 

.EXAMPLE
   Update Hosts.csv to contain contains several hostnames of windows servers: 
   testserver1
   testserver2
   testserver3

   (may need to add full FQDN depending on environment)

   The script will read these FQDNs from hosts.csv, and then start job on each server to run the following commands:
        klist -li 0x3e4 purge
        klist -li 0x3e7 purge
        gpupdate /force
    
    After all jobs are complete, the user can see the output of each job, for example:
        2023-02-02 2023 23:05:03: Running commands on winserver1 succeeded with the following output...

        Current LogonId is 0:0x9d83b571
        Targeted LogonId is 0:0x3e4
            Deleting all tickets:
            Ticket(s) purged!

        Current LogonId is 0:0x9d83b571
        Targeted LogonId is 0:0x3e7
            Deleting all tickets:
            Ticket(s) purged!
        Updating policy...



        Computer Policy update has completed successfully.

        User Policy update has completed successfully.

    This information is written to the console, as well as a log file named "<%Y-%m-$d>-zn-klist-purge.log"

.INPUTS
    - File named "hosts.csv" that lives in the same directory as the script is ran from
    - Credentials for a domain account that has WinRM permissions on the remote server

.OUTPUTS
   Log file named "<%Y-%m-$d>-zn-klist-purge.log"

.NOTES
   Make sure the supplied domain account has permissions to invoke remote commands on the servers. The servers themselves should also have WinRM enabled,
   and be able to accept remote commands. 
#>



"############################################################################################################" | Out-File -FilePath .\zn-klist-purge.log -Append

#This will generate interactive prompt to get username and pwd to use in the Invoke-Command call
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Prompting user for credentials..." | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append

#$credObj = Get-Credential -UserName 'JDL\svc-zeronetworks' -Message 'Enter Valid Domain Admin or Similar Credentials'
$credObj = Get-Credential -Message 'Enter Valid Domain Admin or Similar Credentials'
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): User entered credentials..." | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append

#This imports a list of hosts to run the klist commands and gpupdate against
#CSV must be in local path and named hosts.csv. Using Get-Content and Select-Obj to skip the header row of the CSV
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Reading contents of hosts.csv..." | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
$hostCsvObj = Get-Content -Path .\hosts.csv | Select-Object -Skip 1 | ConvertFrom-Csv -Header 'hostname'

#Create script block to run in job. These commands were taken from zero networks documentation, and should force the computer account to get a new k ticket.
#By doing this, the computer account will get updated AD group memberships, including the new ZeroNetworksMonitoredAsset group, and hence apply
# ZeroNetworksMonitoredAsset GPO when it does gpdupate
$scriptBlock = {
    klist -li 0x3e4 purge
    klist -li 0x3e7 purge
    gpupdate /force
}
#FOR TESTING
#$scriptBlock = {ipconfig}
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Will reach out to each host and run: $scriptBlock" | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Will reach out to each host and run: $scriptBlock"

#Start a remote background job on each host in the CSV file. Commands to be run are defined above in the $scriptBlock variable
foreach ($hostName in $hostCsvObj) {
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Starting background job to purge klist and gupdate on $($hostName."hostname")..." | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Starting background job to purge klist and gupdate on $($hostName."hostname")..."
    Invoke-Command -ComputerName $hostName.hostname -credential $credObj -AsJob -JobName $hostName.hostname -ScriptBlock $scriptBlock
}

#Wait for jobs to complete. This variable is never referenced. May be able to delete variable assignment, but I can't test it atm. 
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Waiting for all jobs to complete..." | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Waiting for all jobs to complete..."
$completedJobs = Get-Job | Wait-Job
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): All jobs complete..." | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
"$(Get-Date -UFormat "%Y-%m-%d %Y %T"): All jobs complete..."

#Print which jobs failed, if any, and log it to file
foreach ($failedJob in Get-Job -State Failed) {
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Running commands on $($failedJob."Name") failed. You may have to manually purge kerb tix, or troubleshoot why Invoke-Command failed" | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Running commands on $($failedJob."Name") failed. You may have to manually purge kerb tix, or troubleshoot why Invoke-Command failed"
}

#Print the output of each job and log it to file
foreach ($compJob in Get-Job -State Completed) {
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Running commands on $($compJob."Name") succeeded with the following output..." | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
    "$(Get-Date -UFormat "%Y-%m-%d %Y %T"): Running commands on $($compJob."Name") succeeded with the following output..."
    $compJob | Receive-Job -Keep | Out-File -FilePath .\$(Get-Date -UFormat "%Y-%m-%d")-zn-klist-purge.log -Append
}

#Remove all jobs as they peristent across script executions (they are bound to PSSession)
Get-Job | Remove-Job