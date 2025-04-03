#update 4.0
[CmdletBinding()]
param(
    # Install/Uninstall
    [Parameter(Mandatory = $False)]
    [ValidateSet("install", "uninstall")]
    [String]$CloudConnectorFunction = "install",

    # Token to use to install the Cloud Connector
    [Parameter(Mandatory = $False)]
    [String]$CloudConnectorToken = "<INSERT_CC_TOKEN>",

    # Cloud Connector Source
    [ValidateSet("AD", "WORKGROUP", "AZURE", "AZURE_AD", "AWS", "GCP", "IBM", "ORACLE", "VMWARE", "ALIBABA", "OVH", "LUMEN")]
    [Parameter(Mandatory = $False)]
    [String]$CloudConnectorSource = "AD"
)

# Extract Aud from JWT to find cloud connector URL.
# Your JWT token
$jwt = $CloudConnectorToken

# Split the JWT into its parts
$parts = $jwt -split '\.'

if ($parts.Count -ne 3) {
    throw "Invalid JWT format"
}

# Decode the payload (second part) from Base64URL
$payload = $parts[1]
$remainder = $payload.Length % 4
if ($remainder -ne 0) {
    $payload += '=' * (4 - $remainder)
}
$payload = $payload.Replace('-', '+').Replace('_', '/')
$bytes = [Convert]::FromBase64String($payload)
$json = [System.Text.Encoding]::UTF8.GetString($bytes)

# Convert to a PowerShell object
$payloadObj = $json | ConvertFrom-Json

# Extract the 'aud' field
$audience = $payloadObj.aud



# Logging function
$logFile = "$env:TEMP\CloudConnector.log"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$timestamp] [$Level] $Message"
}
Write-Log -Message "Script execution started."

if ($CloudConnectorToken -eq "<INSERT_CC_TOKEN>") {
    Write-Log -Message "Cloud Connector Token is required for installation but not provided." -Level "ERROR"
    exit
}

# Define installer arguments
switch ($CloudConnectorFunction) {
    "install" {
        $installerArgs = "-$CloudConnectorFunction -token $CloudConnectorToken -source $CloudConnectorSource"
    }
    "uninstall" { 
        $installerArgs = "-$CloudConnectorFunction -token $CloudConnectorToken"
    }
}

# Set up headers for API request
$znHeaders = @{
    "Authorization" = $CloudConnectorToken
    "Content-Type"  = "application/json"
}

# API request for download URL
$installerUri = "https://$audience/installer"
$response = Invoke-WebRequest -Uri $installerUri -Method GET -Headers $znHeaders -UseBasicParsing -ErrorAction Stop
if ($response.StatusCode -ne 200) {
    Write-Log -Message "Failed to retrieve the download URL. HTTP Status Code: $($response.StatusCode)" -Level "ERROR"
    exit
}

# Parse the response
[string]$downloadUrl = ($response.Content | ConvertFrom-Json).url
if (-not $downloadUrl) {
    Write-Log -Message "Download URL is missing in the API response." -Level "ERROR"
    exit
}

# Download the installer
$fileName = "znCC-Installer"
$zipPath = "$env:TEMP\$fileName.zip"
try {
    Invoke-WebRequest -Uri $downloadUrl -Method GET -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-Log -Message "Installer downloaded successfully."
} catch {
    Write-Log -Message "Failed to download the installer: $_" -Level "ERROR"
    exit
}

# Extract the zip file
$installerFolderPath = "$env:TEMP\$fileName"
try {
    Expand-Archive -Path $zipPath -DestinationPath $installerFolderPath -Force -ErrorAction Stop
    Write-Log -Message "Installer extracted successfully."
} catch {
    Write-Log -Message "Failed to extract the installer: $_" -Level "ERROR"
    exit
}

# Locate the installer executable
$installerFile = Get-ChildItem -Path "$installerFolderPath" -Filter "ZnCloudConnectorSetup-x64.exe" -Recurse -ErrorAction Stop
if (-not $installerFile) {
    Write-Log -Message "Installer executable not found in the extracted files." -Level "ERROR"
    exit
}

# Run the installer
try {
    Start-Process -FilePath $installerFile.FullName -NoNewWindow -Wait -ArgumentList $installerArgs
    Write-Log -Message "Installer executed successfully."
} catch {
    Write-Log -Message "Failed to execute the installer: $_" -Level "ERROR"
    exit
}

#Tail setup log
$setupLogPath = "$env:LOCALAPPDATA\ZeroNetworks\logs\setup.log"
if (Test-Path -Path $setupLogPath) {
    $setupText = Get-Content $setupLogPath  -Tail 1
    Write-Log -Message "CloudConnector Log Output: $setupText" 
}

# Clean up temporary files
try {
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $installerFolderPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Temporary files cleaned up successfully."
} catch {
    Write-Log -Message "Failed to clean up temporary files: $_" -Level "WARNING"
}

# Handle uninstallation-specific tasks
if ($CloudConnectorFunction -eq "uninstall") {
    $systempath = 'C:\Windows\System32\config\systemprofile\AppData\Local\ZeroNetworks'
    $count = 0
    while ($count -lt 5) {
        Start-Sleep -Seconds 2
        $count++
        if (-not (Get-Service -Name 'zncloudconnector' -ErrorAction SilentlyContinue).Status -eq 'Running') {
            break
        }
    }
    if ((Test-Path $systempath -ErrorAction SilentlyContinue)) {
        try {
            Remove-Item -Path $systempath -Recurse -Force -ErrorAction Stop
            Write-Log -Message "Cloud Connector system files cleaned up successfully."
        } catch {
            Write-Log -Message "Failed to remove Cloud Connector system files: $_" -Level "WARNING"
        }
    }
}

Write-Log -Message "Script execution completed successfully."
