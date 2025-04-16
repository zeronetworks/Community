
$GPOName = "ZeroNetworksProtect-DoNotModify"


Function Get-ForestDCIPs {
    $DCIPs = (Get-ADForest).Domains | foreach{(Get-ADDomain -Identity $_).DNSRoot | foreach{(Get-ADDomainController -Filter * -Server $_).IPv4Address}}

    $formattedDCIPs = @()
    foreach ($IP in $DCIPs) {
        $formattedDCIPs += "RA4=$IP"
    }
    $formattedDCIPs = $formattedDCIPs -join "|"

    return $formattedDCIPs
}

Function Add-OutboundFWRuleForDC {
    param (
        [string]$GPOName,
        [string]$DCIPs,
        [string]$DomainController
    )

    Set-GPRegistryValue -Name $GPOName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -Value "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=53|RPort=88|RPort=135|RPort=389|RPort=445|RPort=464|RPort=636|RPort2_10=3268-3269|RPort2_10=49152-65535|$DCIPs|Name=ZNAccessOut-ADDC|" -ValueName ("{"+(New-Guid).Guid+"}") -Type String -Server $DomainController
    Set-GPRegistryValue -Name $GPOName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -Value "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RPort=67|RPort=88|RPort=123|RPort=138|RPort=389|RPort=464|$DCIPs|Name=ZNAccessOut-ADDC|" -ValueName ("{"+(New-Guid).Guid+"}") -Type String -Server $DomainController
}

Function Add-OutboundFWRuleForDHCPDNS {
    param (
        [string]$GPOName,
        [string]$DomainController
    )

    Set-GPRegistryValue -Name $GPOName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -Value "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=53|RPort2_10=67-68|Name=ZNAccessOut-DNS-DHCP|" -ValueName ("{"+(New-Guid).Guid+"}") -Type String -Server $DomainController
    Set-GPRegistryValue -Name $GPOName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -Value "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RPort2_10=67-68|Name=ZNAccessOut-DNS-DHCP|" -ValueName ("{"+(New-Guid).Guid+"}") -Type String -Server $DomainController
    Set-GPRegistryValue -Name $GPOName -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -Value "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=1|Name=ZNAccessOut-ICMP|" -ValueName ("{"+(New-Guid).Guid+"}") -Type String -Server $DomainController
}

Write-Host "Getting AD Forest Domain Controller IP Addresses"
$DCIPs = Get-ForestDCIPs

$DomainController = (Get-ADDomainController).HostName

$GPO = Get-GPO -Domain (Get-ADDomain).DNSRoot -All | Where {$_.DisplayName -like "ZeroNetworksProtect*" }
if($GPO.Count -ne 1){
    Write-Host "Error finding the GPO"
    $GPOName = Read-Host "Please enter the name of the protect GPO"
} else {
    $GPOName = $GPO.DisplayName
}

Write-Host "Adding outbound FW rules to Protect GPO"
Add-OutboundFWRuleForDC -GPOName $GPOName -DCIPs $DCIPs -DomainController $DomainController
Add-OutboundFWRuleForDHCPDNS -GPOName $GPOName -DomainController $DomainController

Write-Host "Zero Networks Protect GPO Updated"