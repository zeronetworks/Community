<#
    .Synopsis
    Gets any firewall rules associated with other AD group policies (GPOs)
    .Description
    Gets any firewall rules associated with other AD group policies (GPOs)
#>

Import-Module ActiveDirectory, GroupPolicy
$adDomain = Get-ADDomain

$policies = New-object "System.Collections.Generic.Dictionary[[String],[String]]"
$gpos = Get-GPO -Domain $domain.DNSRoot -All
foreach($gpo in $GPOs){
    $found = $false
    if(($GPO.DisplayName) -eq "ZeroNetworksMonitor"){}
    elseif(($gpo.DisplayName) -eq "ZeroNetworksProtect-DoNotModify"){}
    else{
        Write-host "Checking " $gpo.DisplayName 
        $result = Get-GPRegistryValue -Name $gpo.DisplayName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ErrorAction SilentlyContinue
        if($result -ne $null){$found = $true}
        $result = Get-GPRegistryValue -Name $gpo.DisplayName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ErrorAction SilentlyContinue
        if($result -ne $null){$found = $true}
        $result = Get-GPRegistryValue -Name $gpo.DisplayName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -ErrorAction SilentlyContinue
        if($result -ne $null){$found = $true}
        $result = Get-GPRegistryValue -Name $gpo.DisplayName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -ErrorAction SilentlyContinue
        if($result -ne $null){$found = $true}

        if($found -eq $true){
            $policies.Add($gpo.Displayname,"")
        }
    }
}
#$rules | FL


Write-Host "GPO Names with Firewall Settings" -ForegroundColor Red
$policies.Keys

