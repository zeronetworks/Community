#Requires -Version 7

<#
.SYNOPSIS
    This script is used to provide a break glass method in case of issues with Zero Networks Segment.

.DESCRIPTION
    This script is designed to handle network and identity segmentation break glass scenarios for both Windows and Linux environments. Usage is only recommended if immediate access is required and other methods, such as Zero Networks Cloud Break Glass, are unavailable. 
    It supports multiple operation modes including privileged access, general access, and port testing. The script can operate exclusively on Windows or Linux assets, or both simultaneously, with additional features like SSH key usage for Linux and credential management for Windows.

.PARAMETER Windows
    Indicates that the script will operate on Windows assets. This switch is mandatory when operating in the 'Windows' or 'Both' parameter sets.

.PARAMETER Linux
    Indicates that the script will operate on Linux assets. This switch is mandatory when operating in the 'Linux' or 'Both' parameter sets.

.PARAMETER LinuxUseSSHKey
    When operating on Linux assets, this switch enables the use of an SSH key for authentication.

.PARAMETER Mode
    Specifies the operation mode of the script. Valid options are 'Privileged', 'All', or 'TestPort'. This parameter is applicable to both Windows and Linux.

.PARAMETER Network
    If specified, the script will perform operations related to network segmentation.

.PARAMETER Identity
    If specified, the script will handle operations related to identity segmentation.

.PARAMETER ServersOnly
    Limits the operation of the script to server assets only.

.PARAMETER DisableBlockRule
    Disables any blocking rules that are in place as part of the script's operation.

.EXAMPLE
    PS> .\BreakGlass.ps1 -Windows -Mode Privileged -Network
    This example runs the script for Windows assets opening all inbound privileged ports such as RDP and WinRM, focusing on network segmentation.

.EXAMPLE
    PS> .\BreakGlass.ps1 -Linux -LinuxUseSSHKey -Mode All -ServersOnly
    Runs the script for Linux server assets, opening all inbound ports using an SSH key.

.NOTES
    Requires PowerShell 7 or higher. Ensure that the necessary modules and permissions are in place before running the script.

.LINK
    Consult the Zero Networks Admin Guide for more information.

#>


param (
    [Parameter(Mandatory = $true, ParameterSetName = "Windows")]
    [Parameter(Mandatory = $true, ParameterSetName = "Both")]
    [switch]
    $Windows,

    [Parameter(Mandatory = $true, ParameterSetName = "Linux")]
    [Parameter(Mandatory = $true, ParameterSetName = "Both")]
    [switch]
    $Linux,

    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [switch]
    $LinuxUseSSHKey,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [ValidateSet("Privileged", "All", "TestPort")]
    [string]
    $Mode,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [switch]
    $Network,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Both")]
    [switch]
    $Identity,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [switch]
    $ServersOnly,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [switch]
    $DisableBlockRule,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [string]
    $ADUserName,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [SecureString]
    $ADSvcPassword,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [string]
    $LinuxUserName,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Both")]
    [SecureString]
    $LinuxSvcPassword

)

# Handle Inputs
if (!$PSBoundParameters['Network'] -and !$PSBoundParameters['Identity']) {
    Write-Host "Please specify either -Network or -Identity"
    exit
}
if (!$PSBoundParameters['Windows'] -and !$PSBoundParameters['Linux']) {
    Write-Host "Please specify either -Windows or -Linux or both parameters"
    exit
}
if ($PSBoundParameters['Network'] -and !$PSBoundParameters['mode']) {
    Write-Host "Please specify a mode when using -Network"
    exit
}
if ($PSBoundParameters["mode"] -eq "TestPort") {
    $global:port = Read-Host 'Enter the port to use for testing'
}
if ($PSBoundParameters['Windows']) {
    $creds = @()
    if ($PSBoundParameters['ADUserName']){
        if($PSBoundParameters['ADUserName'] -like "*\*"){
            $domain = $PSBoundParameters['ADUserName'].Split("\")[0]
            $user = $PSBoundParameters['ADUserName'].Split("\")[1]
        } elseif ($PSBoundParameters['ADUserName'] -like "*@*") {
            $domain = $PSBoundParameters['ADUserName'].Split("@")[1]
            $user = $PSBoundParameters['ADUserName'].Split("@")[0]
        } else {
            Write-Host "Invalid username format. Please use either domain\username or user@domain.com"
            break
        }
        $WinRMSecretPassword = ConvertTo-SecureString $ADSvcPassword -AsPlainText -Force
        $userName = "$domain\$user"
        $object = @{
            "Domain"     = $domain
            "Credential" = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $WinRMSecretPassword
        }
        $creds += New-Object -TypeName PSObject -Property $object
    } else {
        $ADInfo = Get-Content "C:\Program Files\Zero Networks\BreakGlass\segmentedAssets.json" | ConvertFrom-Json
        if ($null -eq $ADInfo) {
            Write-Host "segmentedAssets.json not found or empty."
            exit
        }
        foreach ($forest in $ADInfo.ForestsConfig) {
            $user = $forest.PrimaryDomain.AdUserName
            $domain = $forest.PrimaryDomain.DomainDnsName
            $WinRMSecretPassword = Read-Host "Please enter the password for $domain\$user" -AsSecureString
            $userName = "$domain\$user"
            $object = @{
                "Domain"     = $domain
                "Credential" = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $WinRMSecretPassword
            }
            $creds += New-Object -TypeName PSObject -Property $object
            #Placeholder to check secondary domains for different username and passwords.
            foreach ($secondaryDomain in $forest.SecondaryDomains) {
                $user = $secondaryDomain.AdUserName
                $domain = $secondaryDomain.DomainDnsName
                $WinRMSecretPassword = Read-Host "Please enter the password for $domain\$user" -AsSecureString
                $userName = "$domain\$user"
                $object = @{
                    "Domain"     = $secondaryDomain.DomainDnsName
                    "Credential" = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $WinRMSecretPassword
                }
                $creds += New-Object -TypeName PSObject -Property $object
            }
                    
        }
    }
}
if ($PSBoundParameters['Linux']) {
    if (!$PSBoundParameters['LinuxUseSSHKey']) {
        if($PSBoundParameters['LinuxUserName']){
            $linuxUsername = $LinuxUserName
        } else {
            $linuxUsername = Read-Host 'Enter the username for the Linux User'
        }
        if($PSBoundParameters['LinuxSvcPassword']){
            $LinuxSecretPassword = ConvertTo-SecureString $LinuxSvcPassword -AsPlainText -Force
        } else {
            $LinuxSecretPassword = Read-Host 'Enter password for the Linux User' -AsSecureString
        }
        $LinuxCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $linuxUsername, $LinuxSecretPassword
    }
    else {
        if($PSBoundParameters['LinuxUserName']){
            $linuxUsername = $LinuxUserName
        } else {
            $linuxUsername = Read-Host 'Enter the username for the Linux User'
        }
        $LinuxCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $linuxUsername, (New-Object System.Security.SecureString)
        $linuxSSHKey = Read-Host 'Enter the path to the SSH Key file'
    }

}

#check for SSH Module
if (!(Get-Module -ListAvailable | Where-Object { $_.Name -eq "POSH-SSH" })) {
    Write-Host "POSH-SSH Module not found. Installing now."
    Install-Module -Name Posh-SSH -Force -ErrorVariable errmsg
    if ($errmsg) {
        Write-Host "Error installing Posh-SSH Module from web. Using Local source."
        New-Item C:\Temp\NuPkg -ItemType Directory -Force | Out-Null
        copy-item "C:\Program Files\Zero Networks\BreakGlass\posh-ssh.3.1.1.nupkg" C:\Temp\NuPkg -Force | Out-Null
        Register-PSRepository -Name LocalPackages -SourceLocation C:\Temp\NuPkg -InstallationPolicy Trusted
        Install-Module -Name Posh-SSH -Repository LocalPackages -Force -ErrorVariable errmsg
        Unregister-PSRepository LocalPackages
    }
}

# Setup logging files
$success_list = "./success_list.txt"
$failed_list = "./failed_list.txt"
Out-file -FilePath $success_list
Out-File -FilePath $failed_list

#Load segmented Assets
$segmentedAssets = (Get-Content "C:\Program Files\Zero Networks\Breakglass\segmentedAssets.json" | ConvertFrom-Json).segmentedAssets
if ($null -eq $segmentedAssets) {
    Write-Host "segmentedAssets.json not found."
    exit
}

# Type 1 = Client 2 = Server
# Entity Source 3 = AD, 6 = Ansible, 7 = OT, 8 = Workgroup, 9 = AzureAD, 15 = Manual Linux

#Handle windows assets
if ($PSBoundParameters['Windows']) {
    if ($ServersOnly) {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 3 -and $_.type -eq 2 -and $_.osType -eq 2 }
    }
    else {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 3 -and $_.osType -eq 2 } | Sort-Object -Property type -Descending
    }

    if ($members.count -eq 0) {
        Write-Host "No Windows Assets found in the segmented assets list"
    }
    else {
        $members | ForEach-Object -ThrottleLimit 100 -Parallel {
            if ($null -eq $_.Fqdn ) {
                write-host "Error occurred with object $_ "
                break
            }
            $AssetFQDN = $_.Fqdn
            $connect = $false
            if ($_.IsNetworkSegmented -eq $true -or $_.IsIdentitySegmented -eq $true) {
                if ($_.IsNetworkSegmented -eq $true -and $($using:Network)) {
                    $connect = $true
                }
                if ($_.IsIdentitySegmented -eq $true -and $($using:Identity)) {
                    $connect = $true
                }
                if ($connect -eq $true) {
                    Write-Host "Establishing sesssion to $AssetFQDN...."
                    $Credential = ($($using:creds) | Where-Object { $_.Domain -like $AssetFQDN.Substring($AssetFQDN.IndexOf(".") + 1) }).Credential
                    $ps = New-PSSession -ComputerName $AssetFQDN -Credential $Credential -Authentication Kerberos -ErrorAction SilentlyContinue -ErrorVariable errmsg
                    
                    if ($ps -ne $null ) {
                        write-host "Connection established to asset: $AssetFQDN"
                        if ($_.IsNetworkSegmented -eq $true -and $($using:Network)) {
                            if ($($using:mode) -eq "All" ) {
                                Write-Output "Adding Zero Networks Break Glass All rule on $AssetFQDN"
                                Invoke-Command -Session $ps -Scriptblock { netsh advfirewall firewall add rule name="Zero Networks Break Glass Inbound Allow All" dir=in action=allow protocol=any } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                                Invoke-Command -Session $ps -Scriptblock { netsh advfirewall firewall add rule name="Zero Networks Break Glass Outbound Allow All" dir=out action=allow protocol=any } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                                if ($PSBoundParameters['DisableBlockRule']) {
                                    Invoke-Command -Session $ps -Scriptblock { $allrules = @(netsh advfirewall firewall show rule name=all) | Where-Object { $_ -match '^([^:]+):\s*(\S.*)$' } | ForEach-Object -Begin { $FirstRun = $true; $HashProps = @{} } -Process { if (($Matches[1] -eq 'Rule Name') -and (!($FirstRun))) { New-Object -TypeName PSCustomObject -Property $HashProps; $HashProps = @{} }; $HashProps.$($Matches[1]) = $Matches[2]; $FirstRun = $false } -End { New-Object -TypeName PSCustomObject -Property $HashProps }; $blockrules = $allrules | Where-Object { $_.Enabled -eq "Yes" -and $_.Action -eq "Block" }; foreach ($blockrule in $blockrules) { $ruleName = $blockrule.'Rule Name'; netsh advfirewall firewall set rule name="$ruleName" new enable=no } } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                                }
                            }
                            if ($($using:mode) -eq "Privileged") {
                                Write-Output "Adding Zero Networks Break Glass RDP rule on $AssetFQDN"
                                Invoke-Command -Session $ps -Scriptblock { netsh advfirewall firewall add rule name="Zero Networks Break Glass Inbound Allow RDP" dir=in action=allow protocol=TCP localport=3389 } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                                Invoke-Command -Session $ps -Scriptblock { netsh advfirewall firewall add rule name="Zero Networks Break Glass Outbound Allow All" dir=out action=allow protocol=any } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                                if ($PSBoundParameters['DisableBlockRule']) {
                                    Invoke-Command -Session $ps -Scriptblock { $allrules = @(netsh advfirewall firewall show rule name=all) | Where-Object { $_ -match '^([^:]+):\s*(\S.*)$' } | ForEach-Object -Begin { $FirstRun = $true; $HashProps = @{} } -Process { if (($Matches[1] -eq 'Rule Name') -and (!($FirstRun))) { New-Object -TypeName PSCustomObject -Property $HashProps; $HashProps = @{} }; $HashProps.$($Matches[1]) = $Matches[2]; $FirstRun = $false } -End { New-Object -TypeName PSCustomObject -Property $HashProps }; $blockrules = $allrules | Where-Object { $_.Enabled -eq "Yes" -and $_.Action -eq "Block" }; foreach ($blockrule in $blockrules) { $ruleName = $blockrule.'Rule Name'; netsh advfirewall firewall set rule name="$ruleName" new enable=no } } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                                }
                            }
                            if ($($using:mode) -eq "TestPort") {
                                $tport = $($global:port)                               
                                Write-Output "Adding Zero Networks Break Glass TestPort ($tport) rule on $AssetFQDN"
                                Invoke-Command -Session $ps  -ArgumentList $tport -Scriptblock { param($tport); netsh advfirewall firewall add rule name="Zero Networks Break Glass Inbound Allow TestPort ($tport)" dir=in action=allow protocol=TCP localport=$tport} -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                            }
                        }
                        if ($_.IsIdentitySegmented -eq $true -and $($using:Identity)) {
                            #Invoke-Command -Session $ps -Scriptblock { net localgroup | select -skip 4 | ? { $_ -and $_ -match 'ZeroNetworks' } | ForEach-Object { $group = $_.replace("*", ""); net localgroup $group | select -skip 6 | ? { $_ -and $_ -notmatch 'successfully' } | Foreach-Object { net localgroup $group $_ /DELETE } } } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                            Write-Output "Resetting local policy on $AssetFQDN"
                            Invoke-Command -Session $ps -ScriptBlock { secedit /export /cfg $env:temp\backup.cfg | out-null; $secpolcontent = Get-Content $env:temp\backup.cfg; $groupNames = (net localgroup | Select-Object -skip 4 | Where-Object { $_ -and $_ -match 'ZeroNetworks' }).replace("*", ""); foreach ($groupName in $groupNames) { $secpolcontent = $secpolcontent -replace ",$groupname,", "," -replace "$groupName,", "" -replace "$groupName", "" }; $secpolcontent | Out-File $env:temp\backup.cfg; secedit /configure /db C:\Windows\security\local.db /cfg $env:temp\backup.cfg /overwrite /log $env:temp\breakglass.log /quiet } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                            Write-Output "Running gpupdate on $AssetFQDN"
                            Invoke-Command -Session $ps -Scriptblock { gpupdate.exe /force /Target:Computer } -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                        }
                        write-output "removing session"
                        Remove-PSSession $ps
                        if ($errmsg -eq '' -or $errmsg.count -eq 0) {
                            Add-Content -Path $($using:success_list) -Value $AssetFQDN
                        }
                    }
                    else {
                        Write-Output "Could NOT connect to $AssetFQDN"
                        Add-Content -Path $($using:failed_list) -Value ($AssetFQDN + " Error: " + $errmsg)

                    }
                }
            }
            else {
                Write-Output "Asset $AssetFQDN is not segmented. Skipping"
            }
        }
    }
    $members = $null
}

if ($PSBoundParameters['Linux']) {
    #Handle Linux Assets
    if ($ServersOnly) {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 6 -or $_.entitySource -eq 15 -or $_.entitySource -eq 3  -and $_.type -eq 2 -and $_.osType -eq 3 }
    }
    else {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 6 -or $_.entitySource -eq 15 -or $_.entitySource -eq 3 -and $_.osType -eq 3  } | Sort-Object -Property type -Descending
    }

    if ($members.count -eq 0) {
        Write-Host "No Linux Assets found in the segmented assets list"
    }
    else {
        if ($linuxSSHKey) {
            $useKey = $true
            $Credential = $LinuxCredential
        }
        else {
            $useKey = $false
            $Credential = $LinuxCredential
        }
        $members | ForEach-Object -ThrottleLimit 100 -Parallel {
            if ($null -eq $_.Fqdn) {
                write-host "Error occurred with object $_ "
                break
            }
            $AssetFQDN = $_.Fqdn
            $connect = $false
            if ($_.IsNetworkSegmented -eq $true) {
                if ($_.IsNetworkSegmented -eq $true -and $($using:Network)) {
                    $connect = $true
                }
                if ($connect -eq $true) {
                    if ($($using:useKey) -eq $true) {
                        $ssh = New-SSHSession -ComputerName $AssetFQDN -KeyFile $($global:linuxSSHKey) -Credential $($using:Credential) -AcceptKey -ErrorAction SilentlyContinue -ErrorVariable errmsg -KnownHost (Get-SSHOpenSSHKnownHost -LocalFile $env:TEMP\$AssetFQDN_known_hosts.json)
                    }
                    else {
                        $ssh = New-SSHSession -ComputerName $AssetFQDN -Credential $($using:Credential) -AcceptKey -ErrorAction SilentlyContinue -ErrorVariable errmsg -KnownHost (Get-SSHOpenSSHKnownHost -LocalFile $env:TEMP\$AssetFQDN_known_hosts.json)
                    }
                    if ($null -ne $ssh ) {              
                        function Insert-IptablesRule {
                            param (
                                $stream,
                                $chain,
                                $index,
                                $rule
                            )
                            
                            $command = "python -c `"import iptc; table = iptc.Table(iptc.Table.FILTER); chain = iptc.Chain(table, '$chain'); rule = iptc.easy.encode_iptc_rule($rule); chain.insert_rule(rule, $index)`" 2>breakglass_errors"

                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $command -ErrorAction Stop -ErrorVariable errmsg | Out-Null
                        }

                        write-host "Connection established to asset: $AssetFQDN"
                        #Establish a stream for sudo su
                        $stream = $ssh.Session.CreateShellStream("ps-ssh", 0, 0, 0, 0, 100)
                        Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo su" -ErrorAction stop -ErrorVariable errmsg | Out-Null
                 
                        if ($_.IsNetworkSegmented -eq $true -and $($using:Network)) {
                            $KillExistingCollectorCommand = "(pid=`$(pgrep -a python | grep ''ZeroNetworks'' | cut -d ' ' -f1); if [ ! -z `$pid ]; then kill -9 `$pid; fi)"
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $KillExistingCollectorCommand -ErrorAction Stop -ErrorVariable errmsg | Out-Null

                            $ActivatePythonVirtualEnvCommand = ". ./.zn-internal/venv3/bin/activate || . ./.zn-internal/venv2/bin/activate"
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $ActivatePythonVirtualEnvCommand -ErrorAction stop -ErrorVariable errmsg | Out-Null

                            $SetXtablesLibDir = "python -c 'import iptc' || export XTABLES_LIBDIR=`$(cat '.zn-internal/cached_xtables_libdir')"
                            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $SetXtablesLibDir  -ErrorAction stop -ErrorVariable errmsg | Out-Null

                            $inboundRule = ''

                            if ($($using:mode) -eq "All" ) {
                                Write-Output "Adding Zero Networks Break Glass All rule on $AssetFQDN"
                                $inboundRule = "{'target': 'ACCEPT'}"
                            }
                            if ($($using:mode) -eq "Privileged") {
                                Write-Output "Adding Zero Networks Break Glass SSH rule on $AssetFQDN"
                                $inboundRule = "{'protocol': 'tcp', 'tcp': {'dport': '22'}, 'target': 'ACCEPT'}"
                            }

                            Insert-IptablesRule -stream $stream -chain "INPUT" -index 0 -rule $inboundRule
                          
                            $outboundRule = "{'target': 'ACCEPT'}"
                            Insert-IptablesRule -stream $stream -chain "OUTPUT" -index 0 -rule $outboundRule
                        }
                        Remove-SSHSession $ssh
                        if ($errmsg -eq '' -or $errmsg.count -eq 0) {
                            Add-Content -Path $($using:success_list) -Value $AssetFQDN
                        }
                    }
                    else {
                        Write-Output "Could NOT connect to $AssetFQDN"
                        Add-Content -Path $($using:failed_list) -Value ($AssetFQDN + " Error: " + $errmsg)

                    }
                }
            }
            else {
                Write-Output "Asset $AssetFQDN is not segmented. Skipping"
            }
        }
    }
}

#Cleanup
$creds = $null
$members = $null
$Credential = $null
$LinuxCredential = $null
$WinRMSecretPassword = $null
$LinuxSecretPassword = $null
$linuxSSHKey = $null