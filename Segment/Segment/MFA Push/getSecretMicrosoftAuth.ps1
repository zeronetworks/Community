# Install only the necessary Microsoft.Graph submodules
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications"
)
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing $module..." -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber
    }
    Import-Module $module
}
# Connect to Microsoft Graph with application permissions
# Note: This requires app registration with appropriate permissions
Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome
# Define the Azure Multi-Factor Authentication (MFA) App ID
$AzureMFAAppID = "981f26a1-7f43-403b-a875-f8b09b8cd720"
# Get the service principal ObjectId for the MFA App ID
$AzureMFAServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AzureMFAAppID'"
$AzureMFAObjID = $AzureMFAServicePrincipal.Id
# Set the end date for the ClientSecret (2 years from now)
$endDate = (Get-Date).AddYears(2)
# Generate a new ClientSecret using Microsoft Graph
$passwordCredential = @{
    displayName = "ClientSecret-$(Get-Date -Format 'yyyy-MM-dd')"
    endDateTime = $endDate
}
# Add the password credential to the service principal
$newPassword = Add-MgServicePrincipalPassword -ServicePrincipalId $AzureMFAObjID -PasswordCredential $passwordCredential
# Get the secret value (this is only available immediately after creation)
$ClientSecret = $newPassword.SecretText
# Print the ClientSecret
Write-Host "ClientSecret: $ClientSecret"
# Disconnect from Microsoft Graph
Disconnect-MgGraph
