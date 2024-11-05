[CmdletBinding()]
param (
    # API Token to get download URL
    [Parameter(Position = 0)]
    [String]
    $APIToken = "",

    # Install/Uninstall
    [Parameter(Position = 1)]
    [ValidateSet("install", "uninstall")]
    [String]
    $CloudConnectorFunction = "install",

    # Token to use to install the Cloud Connector
    [Parameter(Position = 2)]
    [string]
    $CloudConnectorToken = "",

    # Cloud Connector Source
    [ValidateSet("AD", "WORKGROUP", "AZURE", "AZURE_AD", "AWS", "GCP", "IBM","ORACLE","VMWARE","ALIBABA","OVH","LUMEN")]
    [Parameter(Position = 3)]
    [string]
    $CloudConnectorSource = "AD"
)

# Normalize function and source case
$CloudConnectorFunction = $CloudConnectorFunction.ToLower()
$CloudConnectorSource = $CloudConnectorSource.ToUpper()
$fileName = "znCC-Installer"

# Set up headers for API request
$znHeaders = @{
    "Authorization" = $APIToken
    "content-type" = "application/json"
}

# Define installer arguments based on function type
switch ($CloudConnectorFunction) {
    "install" { $installerArgs = "-$CloudConnectorFunction -token $CloudConnectorToken -source $CloudConnectorSource" }
    "uninstall" { $installerArgs = "-$CloudConnectorFunction -token $CloudConnectorToken" }
}

# Define the installer URI and fetch download URL
$installerUri = 'https://portal.zeronetworks.com/api/v1/download/cloud-connector/installer'
$response = Invoke-WebRequest -Uri $installerUri -Method GET -Headers $znHeaders
# Validate Response
if (!$response -or !$response.Content) {
    Write-Host "Failed to retrieve download URL from the API."
    exit
}

[string]$downloadUrl = ($response.Content | ConvertFrom-Json).url

# Download the installer
try {
    Invoke-WebRequest -Uri $downloadUrl -Method GET -OutFile "$env:TEMP\$fileName.zip"
} catch {
    Write-Host "Failed to download the installer"
    exit
}

# Extract the Zip file
$zipPath = "$env:TEMP\$fileName.zip"
try {
    Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\$fileName" -Force
} catch {
    Write-Host "Failed to extract the installer"
    exit
}

# Run the installer
$installerFolder = Get-ChildItem -Path "$env:TEMP\$fileName" -Directory
$installerFile = Get-ChildItem -Path "$($installerFolder.FullName)\ZnCloudConnectorSetup-x64.exe"

try {
    Start-Process -FilePath $installerFile.FullName -NoNewWindow -PassThru -Wait -ArgumentList $installerArgs
} catch {
    Write-Host "Failed to run install."
    exit
}

# Clean up
Remove-Item -Path "$env:TEMP\$fileName.zip" -Force
Remove-Item -Path "$env:TEMP\$fileName" -Recurse -Force