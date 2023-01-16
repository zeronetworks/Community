<#
    .Synopsis
    Gets any firewall rules associated with other AD group policies (GPOs)
    .Description
    Gets any firewall rules associated with other AD group policies (GPOs)
#>

Import-Module ActiveDirectory, GroupPolicy
$adDomain = Get-ADDomain

$rules = New-object "System.Collections.Generic.Dictionary[[String],[String]]"
$gpos = Get-GPO -Domain $domain.DNSRoot -All
foreach($gpo in $GPOs){
    if(($GPO.DisplayName) -eq "ZeroNetworksMonitor"){}
    elseif(($gpo.DisplayName) -eq "ZeroNetworksProtect"){}
    else{
        Write-host "Checking " $gpo.DisplayName 
        $result = Get-GPRegistryValue -Name $gpo.DisplayName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -ErrorAction SilentlyContinue | where {$_.Value -like "*Dir=In*"} 
        if($result -ne $null){
            $rules.Add($gpo.Displayname,$result.Value)
        }
    }
}
#$rules | FL

Write-Host "GPO Names with Firewall Rules"
$rules.Keys
