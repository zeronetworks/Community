<#
    .Synopsis
    Sample Script to parse through the trust server WinRM logs including those that are in zips.

    .Description
    This script will first grab zipi files depending on the number of days you set for lookback (default lookback two days).
    Next the script will extract the zip files into the temp folder path.
    After that, the script will copy the current Trust-WinRM.log file to the temp folder path.
    Finally, the script will loop through all log files looking for lines that contain the assetID supplied and write those lines to a new file.

    .NOTES
        Filename: znlog-filter.ps1
        Author: Ken Ward <ken.ward@zeronetworks.com>
        Modified date: 10/17/2023
#>

$defaultAssetID = "a:a:tTrHI9Rm"
$targetAssetId = Read-Host -Prompt "AssetID [$defaultAssetID]"
if (-not $targetAssetId) { $targetAssetId = $defaultAssetID }

$defaultLogFolderPath = Join-Path $($env:ProgramFiles) "Zero Networks\Logs" #Defaults to C:\Program Files\ZeroNetworks\Logs
$logFolderPath = Read-Host -Prompt "Log Folder path [$defaultLogFolderPath]"
if (-not $logFolderPath) { $logFolderPath = $defaultLogFolderPath }

$defaultLookback = 2
$lookBack = Read-Host -Prompt "Days to look back [$defaultLookback]"
if (-not $lookBack) { $lookBack = $defaultLookback }

$targetDate = (Get-Date).AddDays(-$lookBack).ToString($dateFormat)
$dateFormat = "yyyy-MM-dd"

$defaultDpath = "$env:USERPROFILE\zn-tmp"
$dpath = Read-Host -Prompt "Output Path [$defaultDpath]"
if (-not $dpath) { $dpath = $defaultDpath }


$defaultOFile = "$dpath\trust-winrm_filtered.txt"
$outputFile= Read-Host -Prompt "Output Path [$defaultOFile]"
if (-not $outputFile) { $outputFile = $defaultOFile }

If (! (test-path -PathType container $dpath))  {  
  New-Item -ItemType Directory -Path $dpath 
}

# Get Zips 
$filelist = get-childItem -path $logFolderPath -Filter trust-winrm*.zip | Where-Object {
    $_.BaseName -match '\d{4}-\d{2}-\d{2}' -and 
    [datetime]::ParseExact(([regex]::Match($_.BaseName,'\d{4}-\d{2}-\d{2}').Value),'yyyy-MM-dd',$null) -ge $targetDate 
}

foreach ($zipFile in $filelist){
    Expand-Archive -Path $zipFile.PSPath -DestinationPath $dpath -Force
}


#Copy current WinRM log file
If (test-path -PathType Leaf $logFolderPath\trust-winrm.log ) {  
    Copy-Item -path $logFolderPath\trust-winrm.log -Destination $dpath\trust-winrm.log 
}

# Get all WinRM Logs
$loglist = get-childItem -path $dpath -Filter trust-winrm*.log

foreach ($log in $loglist){
   # Read the log file and filter by assetId
    Get-Content -Path $log.PSPath | Where-Object {
        $_ -like "*assetId=$targetAssetId*"
    } | Tee-Object -Append $outputFile
}


