<#
    .Synopsis
    Example 2 - Scans for open ports on any AD asset within the AD Forest
	
    .Description
    This will use TrustMeter to scan for any open ports on all computers within AD Forest using the provided credentials. 
	
    .NOTES
        Filename: Ex2 - Simple scan for open ports on all AD Assets in Forest.ps1
        Author: Jing Nghik <jing@zeronetworks.com>
        Modified date: 1/27/2023
#>

## Determine if trust meter configured
if ([string]::IsNullOrEmpty($env:trustmeter) -or (-not (Test-Path "$($env:trustmeter)\trustmeter.exe")) ) {
    Write-Host -ForegroundColor Red "Trust Meter path not defined";
    $env:trustmeter = Read-Host "Please provide trust meter path (ex: c:\trustmeter\)"
};

$trustMeterPath = $env:trustmeter
Write-Host "Trust Meter found on $($path.FullName)\trustmeter.exe"

## Run Trust Meter and skip the gui and cloud
Write-Host -ForegroundColor Cyan "`n`nRunning Trust Meter `nExample 2 - Scans for open ports on any AD asset within the AD Forest"
& (Join-Path $trustMeterPath "trustmeter.exe") "--scanscope" "forest" "--skipgui" "--skipcloud" "--debug"
