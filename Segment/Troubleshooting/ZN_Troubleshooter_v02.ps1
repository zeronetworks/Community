<# Zero Networks Troubleshooting script
.NAME Ken Ward
.LINK https://www.zeronetworks.com
.AUTHOR ken@zeronetworks.com
.VERSION 2.0
.Synopsis
   This scripts purpose is to help quickly troubleshoot common scenarios related to issues on the Trust Server or monitored/protected assets
   
.DESCRIPTION
   This script does the following
   - Checks if WinRM and firewall services are running
   - Checks if WinRM is listening on the proper ports
   - Generates a GPO RSOP report to analyze
   - Validates Zero Network group policies are associated to local asset
   - Identify other group policies that may conflict with Zero Networks
   - Identify if there are other firewall rules on the local asset not managed by Zero Networks
   -  
   - Verify firewall events (5156,5157) audit logs are enabled

   - On the trust server
     - Verifies trust services are running
     - Verify connectivity with Zero Network cloud services
     - Verify if on latest version of trust server

   - On endpoints
     - Check network connectivity with trust server

   During all checks remediation will be provided for items that failed and also a recap is generated at the end of the script. 

.EXAMPLE
   Simply just run the file and it will automatically check and provide remediation steps at the end for you to focus troubleshooting on. 

.INPUTS
    - No inputs has been implemented yet

.OUTPUTS
    - Will create an output file in $logFilePath

.NOTES
   You typically would run this on a machine that is monitored/protected by Zero Networks or on the trust server for network connectivity checks and testing. 
#>

# Check if the script is running as an administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    # If not running as admin, write an error message and exit
    #Write-Error "This script requires administrative privileges. Please run it as an administrator."
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
    #exit
}

# Define the path for the log file
$logFile = "ZN_TroubleshootingReport.txt"
$gopReport = "GPOreport.xml"


# Get the directory path from the file path
$folderPath = Split-Path -Path $logFilePath

# Check if the folder exists
if (-not (Test-Path -Path $folderPath)) {
    # The folder does not exist, so create it
    New-Item -ItemType Directory -Path $folderPath
} 

if (test-path $logFilePath) { Remove-Item $logFilePath} ## Remove old report

function Check-ServiceStatus {
    param (
        [string]$ServiceName,
        [string]$LogFilePath
    )

    # Check if the specified service is running
    $service = Get-Service -Name $ServiceName
    if ($service.Status -ne 'Running') {
        $warningMessage = "$ServiceName service is not running."
        Write-Warning $warningMessage
        $warningMessage | Out-File -FilePath $LogFilePath -Append
    } else {
        $output = "$ServiceName service is running"
        Write-Host $output
    }
    
}

function Check-LocalWinRMListening {
    # Array of ports to check
    $ports = @(5985, 5986)

    # Check each port
    foreach ($port in $ports) {
        $listening = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
        if ($listening) {
            Write-Host "Local host is listening on WinRM port $port."
        } else {
            $warningMessage = "Local host is not listening on WinRM port $port."
            Write-Warning $warningMessage
            $warningMessage | Out-File -FilePath $LogFilePath -Append
        }
    }
}

function Check-FirewallAuditLogsEnabled {
    # Define the audit policy subcategories for firewall events
    $firewallAuditSubcategories = @("Filtering Platform Connection", "Filtering Platform Packet Drop")

    # Check each subcategory
    foreach ($subcategory in $firewallAuditSubcategories) {
        $auditPolicy = auditpol /get /subcategory:"$subcategory" | Out-String
        if ($auditPolicy -match "Success and Failure") {
            Write-Host "Audit logs for $subcategory are enabled (Success and Failure)."
        } else {
            $warningMessage = "Audit logs for $subcategory are not fully enabled. Current setting: $auditPolicy"
            Write-Warning $warningMessage
            $warningMessage | Out-File -FilePath $LogFilePath -Append
        }
    }
}

function Create-GpoReport {
    $path = Join-Path $env:LOCALAPPDATA "ZeroNetworks"
    If(!(test-path -PathType container $path)) { New-Item -ItemType Directory -Path $path }
    if (test-path $path\report.xml) { Remove-Item $path\report.xml} ## Remove old report
    cmd.exe /c "gpresult /X $($path)\report.xml /f"
    (Join-Path $env:LOCALAPPDATA "ZeroNetworks\report.xml")
}
function Check-ZNGPOs {
    $path = Join-Path $env:LOCALAPPDATA "ZeroNetworks"
    $GPResultXML = [xml](Get-Content -Path "$($path)\report.xml")
    $GPONames = $GPResultXML.Rsop.ComputerResults.GPO | Select-Object *, @{N="Id";E={$_.Path.Identifier."#text"}} | Where-Object {$_.Name -in @("ZeroNetworksMonitor","ZeroNetworksProtect")} | Select Name, Enabled, IsValid, SecurityFilter
    $names = @("ZeroNetworksMonitor","ZeroNetworksProtect") 
    $check = foreach ($name in $names) { 
        [PSCustomObject] @{
            Name = $name
            GPO = "$(if($name -in $GPONames.Name) {"GPO Found"} else {"No GPO detected"})"
        }
    }
    $check | Format-Table
    $noGpoEntries = $check | Where-Object { $_.GPO -eq "No GPO detected" }

    if ($noGpoEntries) {
        $warningMessage = "Not able to locate ZeroNetworks configured group policies assigned to this asset"
        Write-Warning $warningMessage
        $warningMessage | Out-File -FilePath $LogFilePath -Append
    } else {
        Write-Host "GPOs found."
    }


}

function Check-GPOConflict {
    $path = Join-Path $env:LOCALAPPDATA "ZeroNetworks"
    $GPResultXML = [xml](Get-Content -Path "$($path)\report.xml")

    ## Find all GPOS with identifiers
    $GPOs = ($GPResultXML.GetElementsByTagName("GPO") | Where-Object { ($_.Identifier)}) | Select-Object *, @{N="Parent";E={$_.ParentNode.Name}}
    $GPONames = $GPResultXML.Rsop.ComputerResults.GPO | Select-Object *, @{N="Id";E={$_.Path.Identifier."#text"}}

    # Get related GPO name
    ForEach ($GPO in $GPOs) {
        $Name = ($GPONames | Where-Object {$_.Id -eq $GPO.Identifier."#text"})
        $GPO | Add-Member -MemberType NoteProperty -Name "GPOName" -Value $Name.Name -Force
    }

    $filter = @{
        "Names" = @(
            "Windows Defender Firewall: Prohibit notifications"
            "Windows Defender Firewall: Prohibit unicast response to multicast or broadcast requests"
            "Windows Defender Firewall: Protect all network connections"
            "Configure user Group Policy loopback processing mode"
            "Specify the maximum log file size (KB)"
            "Allow Basic authentication"
            "Allow remote server management through WinRM"
            "Allow unencrypted traffic"
        )
        "LocalNames" = @(
            "InboundFirewallRules"
            "OutboundFirewallRules"
            "DefaultInboundAction"
            "DefaultOutboundAction"
            "AuditSetting"
            "UserRightsAssignment"
            "DisableNotifications"
            "EnableFirewall"
        )
    }

    $filtered = @()
    $maxColumnLength = 30
    ForEach ($GPO in $GPOs) {
        $parentName = "$(if($GPO.ParentNode.KeyPath) {$GPO.ParentNode.KeyPath} else {$GPO.ParentNode.Name})"
        if ( ($GPO.ParentNode.LocalName -in $filter.LocalNames) -or ($GPO.ParentNode.Name -in $filter.Names)) {
            $p = [PSCustomObject]@{
                ParentLocalName = "$(([string]$GPO.ParentNode.LocalName)[0..$maxColumnLength] -join '')"
                ParentName = "$($parentName[0..$maxColumnLength] -join '')"
                #ParentName = "$(([string]$GPO.ParentNode.Name)[0..$maxColumnLength] -join '')"
                "Winning GPO" = "$(([string]$GPO.GPOName)[0..$maxColumnLength] -join '')"
                Value = "$(
                    if ($GPO.ParentNode.Value) {$GPO.ParentNode.Value}
                    elseif ($GPO.ParentNode.KeyPath) {$GPO.ParentNode.AdmSetting}
                    elseif ($GPO.ParentNode.State) {$GPO.ParentNode.State}
                    elseif ($GPO.ParentNode.SettingString) {$GPO.ParentNode.SettingString}
                    elseif ($GPO.ParentNode.SettingBoolean) {$GPO.ParentNode.SettingBoolean}
                    elseif ($GPO.ParentNode.SettingNumber) {$GPO.ParentNode.SettingNumber}
                    elseif ($GPO.ParentNode.SettingValue) {$GPO.ParentNode.SettingValue}
                    elseif ($GPO.ParentNode.Action) {"$($GPO.ParentNode.Dir)-$($GPO.ParentNode.Action)-$(if ($GPO.ParentNode.LPort) {$GPO.ParentNode.LPort} else {$GPO.ParentNode.RPort})"}
                    elseif ($GPO.ParentNode.LocalName -match "UserRightsAssignment") {$GPO.ParentNode.member.name."#text"}
                )"
                Result = "$(if( ($GPO.GPOName -like "ZeroNetworks*") ) {"Pass"} else {"Warning"})"
            }
            if($p.value) {$filtered += $p}
        }
    }
    $filtered | Format-Table
            
        }

function Check-Comms2Segment {
    $fwRule = Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {$_.DisplayName -eq "ZNRemoteAccess"} | Select *, @{ N="Trust Servers"; Expression={($_ | Get-NetFirewallAddressFilter).RemoteAddress}}
    $fwRule = $fwRule | Select-Object DisplayName, Enabled, Profile, Direction, Action, "Trust Servers"
    $trustServers = ForEach ($server in $fwRule."Trust Servers") {
        ## Reverse lookup trust server IP
        Try {
            $resolvedName = (Resolve-DnsName $server -ErrorAction Ignore).NameHost
        }
        Catch {
        }
        [PSCustomObject]@{
            IP = $server
            "Hostname" = $resolvedName
            "DNS Check" = if ($resolvedName) {"Success"} else {"Failed"}
        }
    }

    $trustServers | ForEach-Object {
        if($_.Hostname -ne ""){$sslCheck = Test-NetConnection -ComputerName $_.Hostname -Port 443 }

        $_ | Add-Member -MemberType NoteProperty -Name "Port" -value $sslCheck.Port -Force
        $_ | Add-Member -MemberType NoteProperty -Name "Protocol" -value $sslCheck.Protocol -Force
        $_ | Add-Member -MemberType NoteProperty -Name "Connectivity To Trust Server" -value $(if ($sslCheck.Result) {"Success"} else {"Failed"}) -Force
    }
    $trustServers | FT
    
}

Check-ServiceStatus -ServiceName "WinRM" -LogFilePath $logFilePath
Check-ServiceStatus -ServiceName "MpsSvc" -LogFilePath $logFilePath

Check-LocalWinRMListening

Check-FirewallAuditLogsEnabled

Check-Comms2Segment 

Create-GpoReport
Check-ZNGPOs
Check-GPOConflict

# Wait for user input before terminating
Read-Host -Prompt "Press Enter to exit"
