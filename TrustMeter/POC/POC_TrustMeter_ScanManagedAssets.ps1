<# POC_TrustMeter_ScanManagedAssets.ps1

.NAME Jing Nghik
.LINK https://github.com/teachjing
.AUTHOR jing@zeronetworks.com

.VERSION 1.0

.Synopsis
   The purpose of this script is to perform a network port scan on assets managed by Zero Networks.
   
.DESCRIPTION
   These exposed ports could potentially be exploited/compromised by an attacker depending on the type of vulnerability. 
   Its important to iteratively close these open ports unless its expected behavior. 

   This script was created mainly with the intent of reviewing open ports on assets targeted for the POC 
   Steps are:
   - Conduct a scan on assets either in monitoring, learning state. (Save this report for comparison)
   - Set same assets to protection.
   - Perform the same scan against these protected assets.
   - Compare exposed ports before/after being protected by Zero Networks.

.EXAMPLE
   You can run the script with no arguments and it will prompt you with the required parameters it needs. 
      .\POC_TrustMeter_ScanManagedAssets.ps1

   You can also run this script with arguments if you wish to perform this scan in one-line without having input any required parameters. 

   Performs a scan on assets in learning and protected
   .\POC_TrustMeter_ScanManagedAssets.ps1 -apiToken <Api Token created in portal> -mode deep -assetGroups "learning,protected" 

.OUTPUTS
   An HTML report will automatically be created
   Output from scans will be stored in a subdirectory titled "POC"

.NOTES
    - For any protected assets, you may have to exclude the asset performing the scan from JIT MFA policies in order not to trigger multiple MFA prompts. 
    - It is suggested to create a scanner group and then exclude any assets that will perform scans from JIT MFA policies. 
#>

param($apiToken, $baseURL = "https://portal.zeronetworks.com/api/v1", $mode="deep", $assetGroups)

if (!(Test-Path $PSScriptRoot\TrustMeter.exe)) { 
    Write-Error "TrustMeter.exe not detected where this script was ran. Please ensure this script is in the same folder as TrustMeter.exe`n"
    Write-Host "`nYou can download the latest version of TrustMeter at https://zeronetworks.com/trustmeter/"
    break
}

Clear-Host
Write-Host -ForegroundColor DarkCyan -BackgroundColor Cyan "POC - TrustMeter Port Scan Report`n"
Write-Host -ForegroundColor Cyan "   Purpose: " -NoNewline; Write-Host "The purpose of this script is to perform a simple network port scan to help identify how exposed ports are on each asset. `n   These exposed ports could potentially be exploited/compromised by an attacker depending on the type of vulnerability. `n"
Write-Host -ForegroundColor Yellow "   Note: " -NoNewline; Write-Host "This script will only scan assets that are in a monitor, learning, or protected state in the Zero Networks Portal.`n   Be sure assets are in a monitored, learning, or protected state to ensure they are targeted for this scan."
Read-host "`nPress Enter to continue"

if ($apiToken -eq $null) {
    Write-Host -ForegroundColor Yellow "No API Token provided (We use this to automatically grab assets in monitored,learning, and/or protection). An API token (read-only) can be created in the portal at 'https://portal-dev.zeronetworks.com/#/settings/tokens"
    $apiToken = Read-Host "Please paste generated token here"
}

if ($assetGroups -eq $null) {
    Write-Host -ForegroundColor Cyan "Which type of assets would you like to scan (Available groups:" -NoNewline; Write-Host " monitored, learning, protection, all" -NoNewline; Write-Host ")"
    $assetGroups = Read-Host "To include multiple groups separate with comma (ex. learning,protection)"
}

$header = @{
    "Authorization" = "$apiToken"
}

$scanIPs = @()

function Add-ZNAssets {
    param($type, $apiToken)
    $ips = @()
    $endpoint = switch ($type) {
        "monitored" { @{url="$baseURL/assets/monitored?_limit=50&_offset=0";color="DarkCyan"} }
        "learning" { @{url="$baseURL/assets/queued?_limit=50&_offset=0";color="Cyan"} }
        "protected" { @{url="$baseURL/assets/protected?_limit=50&_offset=0";color="Green"} }
    }
    $assets = (Invoke-RestMethod -Method GET -Uri $endpoint.url -Headers $header).items
    Write-Host -Foreground $endpoint.color "`n ==== Adding $type assets to scan pool ===="
    if ($assets.count -gt 0) {
        ForEach ($asset in $assets) {
            if ($asset.ipV4Addresses.Count -gt 0) {
                Write-Host "   $($asset.name) ($($asset.ipV4Addresses -join ', '))"
                $ips += $asset.ipV4Addresses
            } 
            else {
                Write-Host "   $($asset.name) " -NoNewline; Write-Host -foreground yellow "Could not identify IP to scan. Skipping..."
            }
        }
        return $ips
    } 
    else {
        Write-Host -ForegroundColor yellow "   No assets discovered in $type to add to scan pool"}
}

## Add assets in learning to scan pool
if($assetGroups.tolower() -match "(monitor|monitored|all)") {$scanIPs += Add-ZNAssets -type "monitored" -apiToken $apiToken}

## Add assets in learning to scan pool
if($assetGroups.tolower() -match "(learn|learning|all)") {$scanIPs += Add-ZNAssets -type "learning" -apiToken $apiToken}

## Add Protected assets to scan pool
if($assetGroups.tolower() -match "(protected|protection|all)") {$scanIPs += Add-ZNAssets -type "protected" -apiToken $apiToken}

## Remove any duplicate IPs
$scanIPs = $scanIPs | select -Unique

Write-Host -foreground Cyan "`nStarting trust meter and including IP(s) from assets in learning/protected"
& .\TrustMeter.exe "--skipad" "--skipcloud" "--skipgui" "-cs" "no" "--mode" $mode "--ipranges" ($scanIPs -join (','))

## Moving Report to POC subfolder
$dateTime = '{0}' -f ([system.string]::format('{0:yyyyMMdd_HHmmss}',(Get-Date)))
$folder = Get-ChildItem -Directory $PSScriptRoot | Where-Object {$_.Name -match "TrustMeter Results"} | Sort CreationTime -Descending | Select -First 1
$newFolderName = "TrustMeter POC Scan Results - $($assetGroups -replace(',','-')) - $($dateTime)"
Write-Host "Moving Report to POC\$newFolderName subfolder"
Move-Item -Path $folder.FullName -Destination (Join-Path $folder.Parent.FullName "\POC\$newFolderName") -force