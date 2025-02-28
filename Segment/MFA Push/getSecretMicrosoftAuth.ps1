[CmdletBinding()]
param (
    [Parameter()]
    [string] $TenantId
)

$IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Set the end date for the ClientSecret
$endDate = (Get-Date).AddYears(2)

# Pwsh Core flavor because the module is different
if ($PSVersionTable.PSEdition -eq "Core") {

    if (-Not (Get-Module -ListAvailable -Name Az)) {
        if ($IsElevated) {
            Install-Module -Name Az -AllowClobber -Force
        } else {
            Write-Host -ForegroundColor Red "AzureAD Module is not installed and you are not running in an elevated session."
            Write-Host -ForegroundColor Red "Please run Powershell as an Administrator and try again."
            return
        }
        
    }

    if (-Not (Get-AzContext).Account | Out-Null) {
        $login = "Connect-AzAccount"
        if ($TenantId) { $login += " -Tenant $($TenantId)" }
        else { write-warning "skipping Tenant specificity on connecting to AzureAD"}
        Invoke-Expression $login | Out-Null
    }

    # Get the Azure Multi-Factor Authentication (MFA) App ID from Zero Networks Enterprise App (Gallery Entity)
    $AzureMFAAppID = (Get-AzADServicePrincipal -DisplayNameBeginsWith 'zero networks').AppId

    # Get the AzureAD service principal ObjectId for the MFA App ID
    $AzureMFAObj = Get-AzADServicePrincipal -ApplicationId $AzureMFAAppID

    # Generate a new secret and set its expiry based on $endDate variable
    $ClientSecret = New-AzADSpCredential -ObjectId $AzureMFAObj.Id -EndDate $endDate | Select-Object -ExpandProperty secretText


} else {
    if (-not (Get-Module -ListAvailable -Name AzureAD)) {
        if ($IsElevated) {
            Install-Module -Name AzureAD -Repository PSGallery -AllowClobber -Force
        } else {
            Write-Host -ForegroundColor Red "AzureAD Module is not installed and you are not running in an elevated session."
            Write-Host -ForegroundColor Red "Please run Powershell as an Administrator and try again."
            return
        }
    }

    # Connect to AzureAD
    try {Get-AzureADTenantDetail | Out-Null}
    catch {
        $login = "Connect-AzureAD"
        
        if ($TenantId) { $login += " -TenantId $($TenantId)" }
        else { write-warning "skipping Tenant specificity on connecting to AzureAD"}
        
        Invoke-Expression $login | Out-Null
    }

    # Get the Azure Multi-Factor Authentication (MFA) App ID from Zero Networks Enterprise App (Gallery Entity)
    $AzureMFAAppID = (Get-AzureADServicePrincipal -Filter "DisplayName eq 'Zero Networks'").AppId

    # Get the AzureAD service principal ObjectId for the MFA App ID
    $AzureMFAObjID = Get-AzureADServicePrincipal -Filter "AppId eq '$AzureMFAAppID'" | Select-Object -ExpandProperty ObjectId

    # Generate a new secret and set its expiry based on $endDate variable
    $ClientSecret = New-AzureADServicePrincipalPasswordCredential -ObjectId $AzureMFAObjID -EndDate $endDate | Select-Object -ExpandProperty Value
}

# Print the ClientSecret
if ($ClientSecret) {
    Write-Host "ClientSecret: $($ClientSecret)" -ForegroundColor Green
    Set-Clipboard -Value $ClientSecret
    Write-Host -ForegroundColor DarkYellow "Copied to the clipboard if your OS supports it!"
} else {
    Write-Warning "No secret was found. Could be an authorization issue! Check that you have the proper permissions and that you are connected to the intended Tenant and Subscription context. You can change these using -TenantId and -SubscriptionName."
}