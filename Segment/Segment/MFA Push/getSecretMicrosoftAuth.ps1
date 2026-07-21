param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

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
$connectParams = @{
    Scopes    = "Application.ReadWrite.All"
    NoWelcome = $true
}
if ($TenantId) {
    $connectParams.TenantId = $TenantId
}
try {
    Connect-MgGraph @connectParams -ErrorAction Stop
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}
# Define the Azure Multi-Factor Authentication (MFA) App ID
$AzureMFAAppID = "981f26a1-7f43-403b-a875-f8b09b8cd720"
# Get the service principal ObjectId for the MFA App ID
$AzureMFAServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AzureMFAAppID'"
# Create the App if missing
if ($null -eq $AzureMFAServicePrincipal) {
	write-verbose "AppId not found, creating."
	$AzureMFAServicePrincipal = New-MgServicePrincipal -AppId "$AzureMFAAppID"
}
# Fail if not found!
if ($null -eq $AzureMFAServicePrincipal) {
	write-error "Application not found and could not be created!"
	exit 1
}
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