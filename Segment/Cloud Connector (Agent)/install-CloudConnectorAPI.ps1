#update3.0
[CmdletBinding()]

param(
    # API Token to get download URL
    [Parameter(mandatory=$False)]
    [String]$APIToken = "<INSERT_API_TOKEN>",

    # Install/Uninstall
    [Parameter(mandatory=$True)]
    [ValidateSet("install", "uninstall")]
    [String]$CloudConnectorFunction,

    # Token to use to install the Cloud Connector
    [Parameter(mandatory=$False)]
    [string]$CloudConnectorToken = "<INSERT_CC_TOKEN>",

    # Cloud Connector Source
    [ValidateSet("AD", "WORKGROUP", "AZURE", "AZURE_AD", "AWS", "GCP", "IBM","ORACLE","VMWARE","ALIBABA","OVH","LUMEN")]
    [Parameter(mandatory=$False)]
    [string]$CloudConnectorSource

)

$systempath = 'C:\Windows\System32\config\systemprofile\AppData\Local\ZeroNetworks'
if (($CloudConnectorFunction -eq "install") -and (Test-Path $systempath -ErrorAction SilentlyContinue)) {
    Remove-Item -Path $systempath -Recurse -Force -ErrorAction SilentlyContinue
}
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

#write-output $CloudConnectorFunction
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
}

catch {
    Write-Host "Failed to download the installer"
    exit
}

# Extract the Zip file
$zipPath = "$env:TEMP\$fileName.zip"
try {
    Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\$fileName" -Force

}

catch {

    Write-Host "Failed to extract the installer"
    exit
}

# Run the installer
$installerFolder = Get-ChildItem -Path "$env:TEMP\$fileName" -Directory
$installerFile = Get-ChildItem -Path "$($installerFolder.FullName)\ZnCloudConnectorSetup-x64.exe"

try {
    Start-Process -FilePath $installerFile.FullName -NoNewWindow -PassThru -Wait -ArgumentList $installerArgs
}

catch {
    Write-Host "Failed to run install."
    exit
}

# Clean up

try{
    Remove-Item -Path "$env:TEMP\$fileName.zip" -Force -ErrorAction SilentlyContinue | out-null
    Remove-Item -Path "$env:TEMP\$fileName" -Recurse -Force -ErrorAction SilentlyContinue | out-null
}

catch {
    write-output 'something may not have have been cleaned up right'

}

finally {

    if (($CloudConnectorFunction -eq "uninstall") -and (Test-Path $systempath -ErrorAction SilentlyContinue)) {

        $count = 0
        do {
            Start-Sleep -Seconds 1
            $count ++
        }
        until ((((get-service -name 'zncloudconnector' -ErrorAction SilentlyContinue).status -ne 'Running') -and ((get-service -name 'zncloudconnectorupdater' -ErrorAction SilentlyContinue).status -ne 'Running') -and (Test-Path $systempath -ErrorAction SilentlyContinue)) -or ($count -eq 3))
        if ($count -ne 3) {
            Remove-Item -Path $systempath -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            if ((Test-Path $systempath -ErrorAction SilentlyContinue)) {write-output "$systempath not cleaned up"} else {}
        }
    }
}