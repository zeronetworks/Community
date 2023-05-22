# Install the AzureAD module if not already installed
if (-not (Get-Module -ListAvailable -Name AzureAD)) {
    Install-Module -Name AzureAD -Force
}

# Import the AzureAD module
Import-Module AzureAD

# Connect to AzureAD
Connect-AzureAD

# Define the Azure Multi-Factor Authentication (MFA) App ID
$AzureMFAAppID = "981f26a1-7f43-403b-a875-f8b09b8cd720"

# Get the AzureAD service principal ObjectId for the MFA App ID
$AzureMFAObjID = Get-AzureADServicePrincipal -Filter "AppId eq '$AzureMFAAppID'" | Select-Object -ExpandProperty ObjectId

# Set the end date for the ClientSecret
$endDate = (Get-Date).AddYears(2)

# Generate a new ClientSecret and retrieve the value
$ClientSecret = New-AzureADServicePrincipalPasswordCredential -ObjectId $AzureMFAObjID -EndDate $endDate | Select-Object -ExpandProperty Value

# Print the ClientSecret
Write-Host "ClientSecret: $ClientSecret"
