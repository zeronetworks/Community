# Script to check ZNRemoteManagementGroup membership in local Administrators and check Restricted Groups GPOs

$groupName = "ZNRemoteManagementGroup"
$computerName = $env:COMPUTERNAME

# Check local Administrators group membership
$localAdmins = Get-LocalGroupMember -Group "Administrators"
if ($localAdmins.Where({ $_.Name -eq $groupName })) {
    Write-Host "$groupName is a member of the local Administrators group."
} else {
    Write-Host "$groupName is NOT a member of the local Administrators group."

    # Check for Restricted Groups GPOs
    $gpoResults = gpresult /r 2>&1 | Out-String
    $gpoLines = $gpoResults -split "`r`n"

    $restrictedGroupsGPOs = @()
    $inRestrictedGroupsSection = $false

    foreach ($line in $gpoLines) {
        if ($line -match "Restricted Groups") {
            $inRestrictedGroupsSection = $true
        }
        if ($inRestrictedGroupsSection -and $line -match "GPO: (.+)") {
            $restrictedGroupsGPOs += $Matches[1]
        }
        if ($inRestrictedGroupsSection -and $line -match "The following GPOs were not applied because they were filtered out") {
            $inRestrictedGroupsSection = $false;
        }
    }

    if ($restrictedGroupsGPOs.Count -gt 0) {
        Write-Host "Restricted Groups GPOs found:"
        foreach ($gpo in $restrictedGroupsGPOs) {
            Write-Host "  - $gpo"

            #get the GPO's XML.
            $gpoGUID = (Get-GPO -Name $gpo).Id
            $gpoXMLPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$gpoGUID}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            if(Test-Path $gpoXMLPath){
                $gpoContent = Get-Content $gpoXMLPath -Raw
                if($gpoContent -match "\[Groups\]"){
                    if($gpoContent -match "Administrators.*$groupName"){
                        Write-Host "    - $groupName is configured in this GPO"
                    }
                }
            }
        }

    } else {
        Write-Host "No Restricted Groups GPOs found."
    }
}
