<#
    .Synopsis
    Simple API Call to add an OT/IoT asset entry to Zero Networks
    .Description
    This example will loop through OT assets in a provided CSV file and then add each individual asset to Zero Networks OT/IoT asset group.
#>
# OT Asset Types
# 'IP camera' = 4
# 'Smart TV' = 5
# 'Factory controller' = 6
# 'Medical device' = 7
# 'Printer' = 8
# 'Scanner' = 9
# 'Smart card reader' = 10
# 'Router' = 11
# 'Hypervisor' = 12
# 'PLC' = 13
# 'HMI' = 14
# 'Switch' = 15
# 'Terminal station' = 16
# 'RTU' = 17
# 'Wireless access point' = 18
# 'Historian' = 19
# 'Game console' = 20
# 'Fire alarm' = 21
# 'UPS' = 22
# 'Storage appliance' =23
# 'Virtualization appliance' = 24
# 'Firewall appliance' = 25
# 'Security scanner' = 26
# 'Security controller' = 27  
# 'Door lock' = 28
# 'Biometric entry system' = 29
# 'HVAC' = 30
# 'Room scheduler' = 31

$apikey = "<apiKey>"

$OTAssets = import-csv .\ESXHostIPs.csv

#Build Headers and uri
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization",$apiKey)
$znHeaders.Add("Content-Type","application/json")
$uri = "https://portal.zeronetworks.com/api/v1/assets/ot"

foreach($ot in $OTAssets){
    $name = $ot.Name
    $ip = $ot.IP
    $body = @{
        "type" = 12
        "ipv4" = "$ip"
        "displayName"= "$name"
    }
    Invoke-RestMethod -Method POST -Uri $uri -Body ($body | ConvertTo-Json) -Headers $znHeaders
}
