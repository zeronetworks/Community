<#
    .Synopsis
    Sample Script to parse through the trust server logs and summarize the last 1000 entries for quick troubleshooting

    .Description
    This script will first grab the latest log file and then parse the last 1000 entries. 
	Then parse and split the logs and summarize the results

    .NOTES
        Filename: Logs - Parse WinRM from Trust Server logs and Summarize.ps1
        Author: Jing Nghik <jing@zeronetworks.com>
        Modified date: 1/27/2023
#>

#lov folder path
$logFolderPath = Join-Path $($env:ProgramFiles) "Zero Networks\Logs"

# messages to ignore
$ignoreMessages = @(
    'sending ip seen to cloud'
)

# log files 
$logs = @{ winrm = "trust-winrm.log" }

$datetime = Get-Date -Format "yyyy-MM-dd"
$logs = (Get-Content (Join-Path $logFolderpath $logs.winrm)) | Select-String -Pattern $datetime
Write-Host -foreground Cyan "$($filteredLogs.Count) lines in logs"

$filteredLogs = $logs | Select -last 1000

####### Create array for parsed logs and parse the last 1000 entries #######################
## array for parsed logs
$array = @()
Write-Host -foreground Yellow "Only using the last 1000 lines in log file to summarize"
## split logs, remove ignored list and add to array
$messages = ForEach ($line in $filteredLogs) { 
    $index = $filteredLogs.IndexOf($line)
    ## Split the log
    $splitted = $line.ToString().split("|")
    "$($splitted[-2]), $($splitted[-1])"

    Try {
        if ($splitted[-1] -notin $ignoreMessages) {
    
            $array += [PSCustomObject]@{
                computer = $splitted[-2].split('\,')[0].split('\=')[1]
                message = $splitted[-1]       
            }
        }
        Write-Progress -Activity "Parsing Log file" -Status "$($index) of $($filteredLogs.count)" -PercentComplete ($index / $filteredLogs.count * 100)
    }
    Catch {}
}

################ Summarize parsed results ###################
$array | Group-Object -Property message | Select-Object Name, Count | Sort-Object -Property Count -Descending | Select -first 20
