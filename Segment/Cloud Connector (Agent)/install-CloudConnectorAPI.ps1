#update3.2
[CmdletBinding()]
param(
    # API Token to get download URL
    [Parameter(Mandatory = $False)]
    [String]$APIToken =  " ",

    # Install/Uninstall
    [Parameter(Mandatory = $True)]
    [ValidateSet("install", "uninstall")]
    [String]$CloudConnectorFunction,

    # Token to use to install the Cloud Connector
    [Parameter(Mandatory = $False)]
    [String]$CloudConnectorToken = " ",

    # Cloud Connector Source
    [ValidateSet("AD", "WORKGROUP", "AZURE", "AZURE_AD", "AWS", "GCP", "IBM", "ORACLE", "VMWARE", "ALIBABA", "OVH", "LUMEN")]
    [Parameter(Mandatory = $False)]
    [String]$CloudConnectorSource = "AD"
)

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

# Validate API Token
if ($APIToken -eq "") {
    Write-Log -Message "API Token is required but not provided." -Level "ERROR"
    exit
}

# Define installer arguments
switch ($CloudConnectorFunction) {
    "install" {
        if ($CloudConnectorToken -eq "<INSERT_CC_TOKEN>") {
            Write-Log -Message "Cloud Connector Token is required for installation but not provided." -Level "ERROR"
            exit
        }
        $installerArgs = "-$CloudConnectorFunction -token $CloudConnectorToken -source $CloudConnectorSource"
    }
    "uninstall" {
        $installerArgs = "-$CloudConnectorFunction"
    }
}

# Set up headers for API request
$znHeaders = @{
    "Authorization" = $APIToken
    "Content-Type"  = "application/json"
}

# API request for download URL
$installerUri = 'https://portal.zeronetworks.com/api/v1/download/cloud-connector/installer'
$response = Invoke-WebRequest -Uri $installerUri -Method GET -Headers $znHeaders -ErrorAction Stop
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
    Invoke-WebRequest -Uri $downloadUrl -Method GET -OutFile $zipPath -ErrorAction Stop
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
    Write-Log -Message $setupText  
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