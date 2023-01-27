<#
    .Synopsis
    Example 3 - Scans for open ports on an AD asset and any IP residing in the provided input IP ranges
    .Description
    Scan for any open ports on an AD asset an unmanaged asset IP if the ipranges are provided

    .Example
    ./Ex3 - Scan an list of IP Ranges.ps1 "192.168.0.0/24"

    .Example
    ./Ex3 - Scan an list of IP Ranges.ps1 "192.168.0.0/24, 192.168.10.0/24"
#>

param(
    #[Parameter(Mandatory=$false)]$ipranges
    $ipranges
)

## Determine if trust meter configured
if ([string]::IsNullOrEmpty($env:trustmeter) -or (-not (Test-Path "$($env:trustmeter)\trustmeter.exe")) ) {
    Write-Host -ForegroundColor Red "Trust Meter path not defined";
    $env:trustmeter = Read-Host "Please provide trust meter path (ex: c:\trustmeter\)"
};

$trustMeterPath = $env:trustmeter
Write-Host -Foregroud green "Trust Meter found on $($path.FullName)\trustmeter.exe"

if ([string]::IsNullOrEmpty($ipranges)) {
    Write-Host "Example '192.168.0.0/24' or '192.168.0.0/24,192.168.10.0/24'"
    $ipranges = Read-Host "Please provide a single or list of ip ranges seperated by comma"
}

Write-Host -ForegroundColor Cyan "`n`nRunning Trust Meter"
& (Join-Path $trustMeterPath "trustmeter.exe") "--skipgui" "--skipcloud" "--ipranges" $ipranges "--debug"
