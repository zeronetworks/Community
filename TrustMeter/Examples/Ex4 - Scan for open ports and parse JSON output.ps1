<#
    .Synopsis
    Example 4 - Scans for open ports on any asset and IP range. After scan, parse JSON results from report

    .Description
    Scan for any open ports on an AD asset an unmanaged asset IP if the ipranges are provided. 
    After the report is complete, this script will parse the results in the json file stored in the report folder.

    .NOTES
        Filename: Ex4 - Scan for open ports and parse JSON output
        Author: Jing Nghik <jing@zeronetworks.com>
        Modified date: 1/27/2023
#>
param(
    #[Parameter(Mandatory=$false)]$ipranges
    $ipranges
)

if ([string]::IsNullOrEmpty($ipranges)) {
    Write-Host "Example '192.168.0.0/24' or '192.168.0.0/24,192.168.10.0/24'"
    $ipranges = Read-Host "Please provide a single or list of ip ranges seperated by comma"
}


####### Determine if trust meter configured #######
if ([string]::IsNullOrEmpty($env:trustmeter) -or (-not (Test-Path "$($env:trustmeter)\trustmeter.exe")) ) {
    Write-Host -ForegroundColor Red "Trust Meter path not defined";
    $env:trustmeter = Read-Host "Please provide trust meter path (ex: c:\trustmeter\)"
};
$trustMeterPath = $env:trustmeter
Write-Host -Foregroud green "Trust Meter found on $($path.FullName)\trustmeter.exe"
####################################################

######## Run Trust Meter ############################
Write-Host -ForegroundColor Cyan "`n`nRunning Trust Meter `nScan for any open ports on any AD Asset and IP Range.`n Then we will parse the JSON results and also clean up old reports (Keep 10 latest)"
& (Join-Path $trustMeterPath "trustmeter.exe") "--skipgui" "--skipcloud" "--ipranges" $ipranges "--debug"

################## Get Report and only keep 10 of the latest reports ###################
$reports = Get-ChildItem -Directory -Path $trustMeterPath | Where-Object {$_.BaseName -match "TrustMeter Results"} | Sort-Object -Property "LastWriteTime" -Descending
Write-Host "Found $($reports.count) reports"
ForEach ($report in $reports) {
    if ( ($reports.IndexOf($report) -ge 10)) {
        Write-Host -ForegroundColor Yellow "Removing any old generated reports..."
        Remove-item $report -Recurse -Force -ErrorAction SilentlyContinue
    }
}
######################################################################################

################# Parse JSON Results from Report ###################
Write-Host -ForegroundColor Yellow "`nParsing JSON in results`n"
if (Test-Path $reports[0].FullName) {
    $jsonPath = Get-ChildItem -File $reports[0].FullName | Where-Object {$_.Extension -in @('.json')} | Select -First 1
    $json = (Get-Content -path ($jsonPath.FullName) | ConvertFrom-Json)

    $properties = ($json | Get-Member -MemberType "NoteProperty").Name
    ForEach ($property in ($properties)) {
        if ( $json.$property) {
            Write-Host -ForegroundColor Cyan "$($property): " -NoNewline; Write-Host $json.$property
        }
    }
}
#####################################################################