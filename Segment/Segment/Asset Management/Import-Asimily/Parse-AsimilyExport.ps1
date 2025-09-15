<#
.SYNOPSIS
    Parses Asimily asset export files and creates OT assets in Zero Networks.

.DESCRIPTION
    This script processes Asimily export files (*_mainAssetsGrid.xlsx) to:
    - Parse and filter asset data (requires IP address)
    - Construct hostnames for assets missing them using manufacturer, model, and MAC address
    - Compare multiple export files to identify new assets
    - Intelligently map device types to Zero Networks OT asset categories
    - Create OT assets directly in Zero Networks via API
    
    The script maintains a master dataset for future comparisons and creates manageable 
    working files containing only new assets discovered between exports.

.PARAMETER TenantName
    Optional tenant/customer name to filter Asimily files. If provided, only files 
    matching "*{TenantName}*_mainAssetsGrid.xlsx" will be processed.

.PARAMETER FilePath
    Optional specific path to an Asimily export file. If not provided, the script 
    will auto-discover files in the current directory.

.PARAMETER OutputDirectory
    Directory where comparison files will be created. Defaults to current directory (".").

.PARAMETER APIKey
    Zero Networks API key for creating OT assets. If not provided, defaults to the 
    ZN_API_KEY environment variable. Required for Zero Networks integration.

.PARAMETER DryRun
    If specified, shows what OT assets would be created in Zero Networks without 
    actually making API calls. Useful for testing and validation.

.PARAMETER SkipZNIntegration
    If specified, skips Zero Networks integration entirely. The script will only 
    process Asimily files and create comparison reports.

.INPUTS
    Excel files matching the pattern "*_mainAssetsGrid.xlsx" in the current directory.
    Also includes browser download copies like "*_mainAssetsGrid (1).xlsx", "*_mainAssetsGrid (2).xlsx", etc.

.OUTPUTS
    - Newest Asimily file becomes the master (old files deleted)
    - PSCustomObject with processing results and working dataset
    - Zero Networks OT assets created (if integration enabled)

.EXAMPLE
    .\Parse-AsimilyExport.ps1
    
    Processes all Asimily files in the current directory and creates OT assets in Zero Networks.

.EXAMPLE
    .\Parse-AsimilyExport.ps1 -TenantName "CustomerA" -DryRun
    
    Processes files for CustomerA and shows what OT assets would be created without actually creating them.

.EXAMPLE
    .\Parse-AsimilyExport.ps1 -SkipZNIntegration -OutputDirectory "C:\Reports"
    
    Only processes Asimily files without Zero Networks integration, saving reports to C:\Reports.

.EXAMPLE
    $result = .\Parse-AsimilyExport.ps1 -TenantName "CustomerA" -SkipZNIntegration
    $result.DeviceTypeMappings | Format-Table
    
    Processes files and displays the device type mappings that were applied.

.NOTES
    File Name      : Parse-AsimilyExport.ps1
    Author         : Olaf Gradin (olaf.gradin@zeronetworks.com)
    Company        : Zero Networks
    Creation Date  : August 20, 2025
    
    Prerequisites:
    - ImportExcel PowerShell module (Install-Module ImportExcel)
    - Zero Networks API key (for integration features)
    
    Device Type Mapping:
    The script intelligently maps Asimily device data to Zero Networks OT asset types (4-178)
    based on manufacturer, device model, and OS information. Common mappings include:
    - IP Cameras (Hikvision, Axis) -> Type 4
    - Printers (HP, Canon) -> Type 8  
    - Network Equipment (Cisco, Juniper) -> Types 11, 15
    - Industrial Controllers (Siemens, Schneider) -> Types 6, 13, 14
    - Generic/Unknown devices -> Type 135 (OT Device)
    
    File Management:
    - Oldest file becomes the master baseline
    - Newer files (including browser download copies like file (1).xlsx) are compared against the master
    - New records are identified and processed
    - Old files are deleted and remaining file is renamed to clean original filename
    - Prevents accumulating (1), (2), (3) increments over time
    
.LINK
    https://github.com/zeronetworks/Community
#>

param(
    [Parameter(Mandatory = $false, HelpMessage = "Customer/tenant name to filter Asimily files")]
    [string]$TenantName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Specific path to Asimily export file")]
    [string]$FilePath,
    
    [Parameter(Mandatory = $false, HelpMessage = "Output directory for comparison files")]
    [string]$OutputDirectory = ".",
    
    [Parameter(Mandatory = $false, HelpMessage = "Zero Networks API key for OT asset creation")]
    [string]$APIKey = $Env:ZN_API_KEY,
    
    [Parameter(Mandatory = $false, HelpMessage = "Test mode - show what would be created without making API calls")]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false, HelpMessage = "Skip Zero Networks integration entirely")]
    [switch]$SkipZNIntegration
)

# Import required module for Excel processing
try {
    Import-Module ImportExcel -ErrorAction Stop
} catch {
    Write-Error "ImportExcel module is required. Install it with: Install-Module ImportExcel"
    Write-Error "You can install it by running: Install-Module ImportExcel -Scope CurrentUser"
    exit 1
}

function Get-ManufacturerBaseName {
    param([string]$Manufacturer)
    
    if ([string]::IsNullOrWhiteSpace($Manufacturer)) {
        return ""
    }
    
    # Common manufacturer mappings to shorter names
    $manufacturerMap = @{
        "Cisco Systems" = "Cisco"
        "Hewlett Packard" = "HP"
        "Hewlett-Packard" = "HP"
        "Dell Inc." = "Dell"
        "Microsoft Corporation" = "Microsoft"
        "Apple Inc." = "Apple"
        "Intel Corporation" = "Intel"
        "VMware, Inc." = "VMware"
        "Red Hat, Inc." = "RedHat"
    }
    
    # Check if we have a specific mapping
    foreach ($key in $manufacturerMap.Keys) {
        if ($Manufacturer -like "*$key*") {
            return $manufacturerMap[$key]
        }
    }
    
    # If no mapping found, take the first word or up to first space/comma
    $baseName = ($Manufacturer -split '[\s,]')[0]
    return $baseName
}

function Get-MacSuffix {
    param([string]$MacAddress)
    
    if ([string]::IsNullOrWhiteSpace($MacAddress)) {
        return ""
    }
    
    # Remove colons, dashes, and spaces, get last 4 hex characters
    $cleanMac = $MacAddress -replace '[:\-\s]', ''
    if ($cleanMac.Length -ge 4) {
        return $cleanMac.Substring($cleanMac.Length - 4).ToUpper()
    }
    return $cleanMac.ToUpper()
}

function New-DeviceName {
    param(
        [string]$Manufacturer,
        [string]$DeviceModel,
        [string]$MacAddress
    )
    
    $maxLength = 32
    $separator = "-"
    
    $manufacturerBase = Get-ManufacturerBaseName -Manufacturer $Manufacturer
    $macSuffix = Get-MacSuffix -MacAddress $MacAddress
    
    # Build name parts (only add non-empty parts)
    $nameParts = @()
    
    if (-not [string]::IsNullOrWhiteSpace($manufacturerBase)) {
        $nameParts += $manufacturerBase
    }
    
    if (-not [string]::IsNullOrWhiteSpace($DeviceModel)) {
        $nameParts += $DeviceModel
    }
    
    if (-not [string]::IsNullOrWhiteSpace($macSuffix)) {
        $nameParts += $macSuffix
    }
    
    if ($nameParts.Count -eq 0) {
        return "Unknown-Device"
    }
    
    # Calculate available space for device model
    $fixedParts = @()
    if (-not [string]::IsNullOrWhiteSpace($manufacturerBase)) {
        $fixedParts += $manufacturerBase
    }
    if (-not [string]::IsNullOrWhiteSpace($macSuffix)) {
        $fixedParts += $macSuffix
    }
    
    $separatorsNeeded = $nameParts.Count - 1
    $fixedLength = ($fixedParts | Measure-Object -Property Length -Sum).Sum + $separatorsNeeded
    
    # If we have a device model, calculate how much space it can use
    if (-not [string]::IsNullOrWhiteSpace($DeviceModel) -and $nameParts.Count -gt 1) {
        $availableForModel = $maxLength - $fixedLength + $DeviceModel.Length
        if ($DeviceModel.Length -gt $availableForModel -and $availableForModel -gt 0) {
            $DeviceModel = $DeviceModel.Substring(0, $availableForModel)
            # Update nameParts
            $modelIndex = -1
            for ($i = 0; $i -lt $nameParts.Count; $i++) {
                if ($nameParts[$i] -eq $DeviceModel -or ($nameParts[$i].Length -gt $availableForModel -and $i -ne 0 -and $i -ne ($nameParts.Count - 1))) {
                    $modelIndex = $i
                    break
                }
            }
            if ($modelIndex -ge 0) {
                $nameParts[$modelIndex] = $DeviceModel
            }
        }
    }
    
    # Join parts and ensure we don't exceed max length
    $finalName = $nameParts -join $separator
    if ($finalName.Length -gt $maxLength) {
        $finalName = $finalName.Substring(0, $maxLength)
    }
    
    return $finalName
}

function Find-AsimilyFiles {
    param([string]$TenantName)
    
    # Updated pattern to include browser download copies like (1), (2), etc.
    if ($TenantName) {
        $basePattern = "*${TenantName}*_mainAssetsGrid.xlsx"
        $copyPattern = "*${TenantName}*_mainAssetsGrid (?).xlsx"
    } else {
        $basePattern = "*_mainAssetsGrid.xlsx"
        $copyPattern = "*_mainAssetsGrid (?).xlsx"
    }
    
    # Get both original files and browser download copies
    $baseFiles = @(Get-ChildItem -Path "." -Filter $basePattern)
    $copyFiles = @(Get-ChildItem -Path "." -Filter $copyPattern)
    
    # Combine and sort by LastWriteTime (oldest first)
    $allFiles = @()
    $allFiles += $baseFiles
    $allFiles += $copyFiles
    $files = $allFiles | Sort-Object LastWriteTime
    
    return $files
}

function Test-UniqueNames {
    param([array]$Data)
    
    $constructedNames = $Data | Where-Object { [string]::IsNullOrWhiteSpace($_.'Hostname') } | ForEach-Object {
        New-DeviceName -Manufacturer $_.'Manufacturer' -DeviceModel $_.'Device Model' -MacAddress $_.'MAC Address'
    }
    
    $duplicates = $constructedNames | Group-Object | Where-Object { $_.Count -gt 1 }
    
    if ($duplicates) {
        Write-Warning "Duplicate constructed names found:"
        $duplicates | ForEach-Object {
            Write-Warning "  Name: $($_.Name) (appears $($_.Count) times)"
        }
        return $false
    }
    
    return $true
}

function Get-ZeroNetworksDeviceTypeMap {
    # Zero Networks OT/IoT Device Type mappings from the Excel lookup table
    return @{
        # Common mappings based on keywords
        "Camera" = 4      # IP camera
        "TV" = 5          # Smart TV
        "Controller" = 6   # Factory controller
        "Medical" = 7      # Medical device
        "Printer" = 8     # Printer
        "Scanner" = 9     # Scanner
        "Card Reader" = 10 # Smart card reader
        "Router" = 11     # Router
        "Hypervisor" = 12 # Hypervisor
        "PLC" = 13        # PLC
        "HMI" = 14        # HMI
        "Switch" = 15     # Switch
        "Terminal" = 16   # Terminal station
        "RTU" = 17        # RTU
        "Access Point" = 18 # Wireless access point
        "Historian" = 19  # Historian
        "Game" = 20       # Game console
        "Alarm" = 21      # Fire alarm
        "UPS" = 22        # UPS
        "Storage" = 23    # Storage appliance
        "Firewall" = 25   # Firewall appliance
        "Security" = 26   # Security scanner
        "Door" = 28       # Door lock
        "Biometric" = 29  # Biometric entry system
        "HVAC" = 30       # HVAC
        "Phone" = 59      # VoIP Phone
        "Sensor" = 68     # Temperature sensor (generic sensor)
        "Robot" = 74      # Robot
        "Display" = 66    # Digital sign
        "Tablet" = 75     # Tablet
        "Scale" = 45      # Scale
        "Clock" = 43      # Clock
        "Speaker" = 50    # Smart speaker
        "Light" = 163    # Smart light
        "Lock" = 165     # Smart lock controller
        "Default" = 135   # OT DEVICE (generic fallback)
    }
}

function Get-AsimilyToZNDeviceTypeMap {
    # Direct mapping from Asimily Device Type to Zero Networks OT Asset Types
    return @{
        # Direct matches
        "IP Camera" = 4
        "Smart TV" = 5
        "Printer" = 8
        "Scanner" = 9
        "Printer/Scanner" = 8  # Use printer for combo devices
        "Access Point" = 18
        "VoIP Phone" = 59
        "IP Phone" = 59
        "Phone" = 59
        "Tablet" = 75
        "HVAC Controller" = 30
        "Access Control System" = 82
        "Power Supply" = 144
        "UPS" = 22
        "Speaker" = 50
        "IP Speaker" = 50
        "Projector" = 146
        "Digital Signage Player" = 66
        "Monitor" = 66
        "Media Gateway" = 126
        "Media player" = 127
        "Controller" = 57
        "Logic controller" = 57
        "Panel PC" = 118
        "Intercom" = 71
        "Lighting Device" = 163
        
        # Common OT/IoT mappings
        "Network Appliance" = 11  # Router
        "IT Server" = 136         # OT Server
        "IT Workstation" = 118    # Industrial workstation
        "Medical Cart IT Workstation" = 118
        "Terminal" = 16           # Terminal station
        "Point-of-Sale Equipment" = 140  # Point of sale
        "Smart Device" = 135      # Generic OT device
        "IoT/Smart Device" = 135
        "Mobile" = 110            # Generic mobile device
        "Mobile/IoT device" = 110
        "Mobile/Tablet" = 110
        "Environmental Monitoring System/Clock" = 68  # Sensor
        "Surveillance Camera" = 65    # Security camera
        "IP Camera/Surveillance System" = 65
        "Surveillance Camera/Detection System" = 65
        "Video Surveillance System" = 173
        "Building Device" = 64    # Building automation controller
        "Medical/Building Device" = 64
        "Building System Workstation" = 64
        "Entertainment System" = 20   # Game console
        "Streaming Device" = 128      # Media streamer
        "TV/Speaker" = 5              # Smart TV
        "Industrial device" = 135     # Generic OT device
        "Power Management" = 142      # Power distribution unit
        "Collaboration device" = 80   # Video conference
        "Telepresence device" = 80
        "Teleconference device" = 80
        "Serial to Ethernet Convertor" = 70  # Serial to ethernet
        "Video Encoder and Decoder" = 171    # Video decoder
        "Workstation on Wheels" = 97         # Clinical mobile device
        "Zero client" = 115              # Industrial thin client
        "Phone/Communications device" = 59   # VoIP phone
        "Wireless IP Phone" = 177        # Wireless phone
        "Audio equipment" = 147          # Radio
        "Fax machine" = 8               # Printer (closest match)
        "Exercise Equipment" = 109       # Fitness device
        "Data Acquisition Server" = 102  # Data logger
        "Network Automation Engine" = 114 # Industrial network equipment
        "Communication Server" = 62     # VoIP server
        "Domain Controller" = 2         # Server
        
        # Fallback for unmapped types
        "Default" = 135  # OT Device (generic)
    }
}

function Get-DeviceTypeFromAsimily {
    param(
        [string]$AsimilyDeviceType,
        [string]$Manufacturer = "",
        [string]$DeviceModel = ""
    )
    
    # Use direct mapping from Asimily Device Type
    $deviceTypeMap = Get-AsimilyToZNDeviceTypeMap
    
    # Clean up the device type (remove extra spaces, normalize)
    $cleanDeviceType = $AsimilyDeviceType.Trim()
    
    # Try direct match first
    if ($deviceTypeMap.ContainsKey($cleanDeviceType)) {
        return $deviceTypeMap[$cleanDeviceType]
    }
    
    # Try partial matches for complex device types
    foreach ($key in $deviceTypeMap.Keys) {
        if ($key -ne "Default" -and $cleanDeviceType -like "*$key*") {
            return $deviceTypeMap[$key]
        }
    }
    
    # Try keyword matching within the device type
    $lowerDeviceType = $cleanDeviceType.ToLower()
    if ($lowerDeviceType -match "camera|surveillance") { return 4 }
    if ($lowerDeviceType -match "printer|scan") { return 8 }
    if ($lowerDeviceType -match "phone|voip") { return 59 }
    if ($lowerDeviceType -match "tablet|mobile") { return 75 }
    if ($lowerDeviceType -match "server") { return 136 }
    if ($lowerDeviceType -match "workstation|pc") { return 118 }
    if ($lowerDeviceType -match "controller|control") { return 57 }
    if ($lowerDeviceType -match "access.*point|wireless") { return 18 }
    
    # Default fallback
    Write-Verbose "Unknown device type '$AsimilyDeviceType' - using default OT Device (135)"
    return $deviceTypeMap["Default"]
}

function Invoke-ZnRestMethod {
    param (
        [string]$Uri,
        [string]$Method,
        $Headers,
        $Body
    )
    try {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $Body
    } catch {
        Write-Host "API call failed: $($_.Exception.Message)" -ForegroundColor Red
        $errorMessage = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errorMessage = $_.ErrorDetails.Message
        } elseif ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errorMessage = $reader.ReadToEnd()
            } catch {
                $errorMessage = "<Unable to read error response body>"
            }
        }
        if ($errorMessage) {
            try {
                $responseJson = $errorMessage | ConvertFrom-Json
                Write-Host "API Error: $($responseJson.message ?? $responseJson.error ?? $responseJson)" -ForegroundColor Red
            } catch {
                Write-Host "API Error: $errorMessage" -ForegroundColor Red
            }
        }
        return $null
    }
}

function Get-ApiUrlFromJwt($jwt) {
    $parts = $jwt -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    $payloadObj = $null
    try { $payloadObj = $json | ConvertFrom-Json } catch { return $null }
    return $payloadObj.api_url ?? $payloadObj.tenant ?? $payloadObj.aud ?? $null
}

function Add-AssetsToZeroNetworks {
    param(
        [array]$AssetData,
        [string]$APIKey,
        [switch]$DryRun
    )
    
    if (-not $APIKey) {
        Write-Warning "No API key provided. Skipping Zero Networks integration."
        return @{ Success = $false; Message = "No API key" }
    }
    
    $apiUrlFromJwt = Get-ApiUrlFromJwt $APIKey
    if ($apiUrlFromJwt) {
        $uri = "https://" + $apiUrlFromJwt.TrimEnd('/') + "/api/v1"
    } else {
        $uri = "https://portal.zeronetworks.com/api/v1"
    }
    
    $znHeaders = @{
        "Authorization" = $APIKey
        "Content-Type" = "application/json"
    }
    $query = "/assets/ot"
    
    $results = @{
        Success = 0
        Failed = 0
        Errors = @()
    }
    
    foreach ($asset in $AssetData) {
        $deviceType = Get-DeviceTypeFromAsimily -AsimilyDeviceType $asset.'Device Type' -Manufacturer $asset.'Manufacturer' -DeviceModel $asset.'Device Model'
        
        $body = [PSCustomObject]@{
            ipv4        = $asset.'IP Address'
            type        = $deviceType
            displayName = $asset.'Hostname'
            fqdn        = if ([string]::IsNullOrWhiteSpace($asset.'FQDN')) { "" } else { $asset.'FQDN' }
        }
        
        $jsonBody = $body | ConvertTo-Json
        
        Write-Host "Creating OT Asset: $($asset.'Hostname') ($($asset.'IP Address')) - Type: $deviceType" -ForegroundColor Cyan
        
        if ($DryRun) {
            Write-Host "[DryRun] Would POST to $($uri)$($query) with body:" -ForegroundColor Yellow
            Write-Host $jsonBody -ForegroundColor Gray
            $results.Success++
        } else {
            $response = Invoke-ZnRestMethod -Uri "$($uri)$($query)" -Method Post -Headers $znHeaders -Body $jsonBody
            if ($response) {
                Write-Host "  ✓ Created successfully" -ForegroundColor Green
                $results.Success++
            } else {
                Write-Host "  ✗ Failed to create" -ForegroundColor Red
                $results.Failed++
                $results.Errors += "Failed to create $($asset.'Hostname')"
            }
        }
    }
    
    return $results
}

# Main script logic
Write-Host "Starting Asimily Export Parser..." -ForegroundColor Green

# Find Asimily files
$asimilyFiles = Find-AsimilyFiles -TenantName $TenantName

if ($asimilyFiles.Count -eq 0) {
    Write-Error "No Asimily export files found matching pattern '*_mainAssetsGrid.xlsx'"
    exit 1
}

Write-Host "Found $($asimilyFiles.Count) Asimily file(s):" -ForegroundColor Yellow
$asimilyFiles | ForEach-Object { Write-Host "  $($_.Name) (Modified: $($_.LastWriteTime))" }

# Process files
$allData = @()
$masterFile = $null
$masterData = @()

foreach ($file in $asimilyFiles) {
    Write-Host "Processing file: $($file.Name)..." -ForegroundColor Cyan
    
    try {
        $data = Import-Excel -Path $file.FullName
        Write-Host "  Imported $($data.Count) records" -ForegroundColor White
        
        # Filter out records without IP addresses
        $validData = $data | Where-Object { -not [string]::IsNullOrWhiteSpace($_.'IP Address') }
        Write-Host "  $($validData.Count) records have IP addresses" -ForegroundColor White
        
        # Add constructed hostnames where missing
        foreach ($record in $validData) {
            if ([string]::IsNullOrWhiteSpace($record.'Hostname')) {
                $record.'Hostname' = New-DeviceName -Manufacturer $record.'Manufacturer' -DeviceModel $record.'Device Model' -MacAddress $record.'MAC Address'
                $record | Add-Member -NotePropertyName 'HostnameConstructed' -NotePropertyValue $true -Force
            } else {
                $record | Add-Member -NotePropertyName 'HostnameConstructed' -NotePropertyValue $false -Force
            }
        }
        
        if ($masterFile -eq $null) {
            $masterFile = $file
            $masterData = $validData
            Write-Host "  Set as master file" -ForegroundColor Green
        } else {
            $allData += $validData
        }
    }
    catch {
        Write-Error "Failed to process file $($file.Name): $($_.Exception.Message)"
        continue
    }
}

# Test for unique constructed names
Write-Host "Testing constructed name uniqueness..." -ForegroundColor Yellow
if (-not (Test-UniqueNames -Data $masterData)) {
    Write-Error "Constructed names are not unique. Please reassess the naming pattern."
    exit 1
}

if ($allData.Count -gt 0) {
    Write-Host "Testing uniqueness across all files..." -ForegroundColor Yellow
    if (-not (Test-UniqueNames -Data ($masterData + $allData))) {
        Write-Error "Constructed names are not unique across all files. Please reassess the naming pattern."
        exit 1
    }
}

Write-Host "All constructed names are unique!" -ForegroundColor Green

# Handle comparison if multiple files
if ($allData.Count -gt 0) {
    Write-Host "Comparing files to find new records..." -ForegroundColor Yellow
    
    # Compare based on Device ID
    $masterDeviceIds = $masterData | ForEach-Object { $_.'Device ID' }
    $newRecords = $allData | Where-Object { $_.'Device ID' -notin $masterDeviceIds }
    
    Write-Host "Found $($newRecords.Count) new records" -ForegroundColor White
    
    # ========================================
    # ASSET SUMMARY
    # ========================================
    Write-Host "`n--- ASSET PROCESSING SUMMARY ---" -ForegroundColor Cyan
    Write-Host "Files processed: $($asimilyFiles.Count)" -ForegroundColor White
    Write-Host "Master file: $($masterFile.Name)" -ForegroundColor White
    Write-Host "Total records in master: $($masterData.Count)" -ForegroundColor White
    if ($allData.Count -gt 0) {
        Write-Host "Records in comparison files: $(($allData | Measure-Object).Count)" -ForegroundColor White
        Write-Host "New records to process: $($newRecords.Count)" -ForegroundColor $(if ($newRecords.Count -gt 0) { 'Green' } else { 'Yellow' })
        
        if ($newRecords.Count -gt 0) {
            Write-Host "`nNew records by device type:" -ForegroundColor Gray
            $newRecords | Group-Object 'Device Type' | Sort-Object Count -Descending | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "Single file processing - no comparison performed" -ForegroundColor Yellow
        Write-Host "All records will be processed: $($masterData.Count)" -ForegroundColor White
        
        Write-Host "`nRecords by device type:" -ForegroundColor Gray
        $masterData | Group-Object 'Device Type' | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Gray
        }
        if (($masterData | Group-Object 'Device Type').Count -gt 10) {
            Write-Host "  ... and $(($masterData | Group-Object 'Device Type').Count - 10) more device types" -ForegroundColor Gray
        }
    }
    Write-Host "--- END SUMMARY ---`n" -ForegroundColor Cyan
    
    if ($newRecords.Count -gt 0) {
        # ========================================
        # PHASE 2: ZERO NETWORKS INTEGRATION
        # ========================================
        if (-not $SkipZNIntegration) {
            Write-Host "Starting Zero Networks integration for $($newRecords.Count) new assets..." -ForegroundColor Cyan
            
            # Add device type predictions to the new records
            foreach ($record in $newRecords) {
                $deviceType = Get-DeviceTypeFromAsimily -AsimilyDeviceType $record.'Device Type' -Manufacturer $record.'Manufacturer' -DeviceModel $record.'Device Model'
                $record | Add-Member -NotePropertyName 'ZN_DeviceType' -NotePropertyValue $deviceType -Force
            }
            
            # Create assets in Zero Networks
            $znResults = Add-AssetsToZeroNetworks -AssetData $newRecords -APIKey $APIKey -DryRun:$DryRun
            
            Write-Host "Zero Networks Integration Results:" -ForegroundColor Green
            Write-Host "  Successfully created: $($znResults.Success)" -ForegroundColor Green
            Write-Host "  Failed: $($znResults.Failed)" -ForegroundColor $(if ($znResults.Failed -gt 0) { 'Red' } else { 'Green' })
            
            if ($znResults.Errors.Count -gt 0) {
                Write-Host "  Errors:" -ForegroundColor Red
                $znResults.Errors | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
            }
        } else {
            Write-Host "Zero Networks integration skipped (-SkipZNIntegration specified)" -ForegroundColor Yellow
        }
        # ========================================
        
        # File Management: Keep newest file as master, delete old files
        Write-Host "Managing files: keeping newest as master..." -ForegroundColor Yellow
        
        # The newest file should already be the master from our sorting
        # Add new records to the master data for the return object
        $updatedMasterData = $masterData + $newRecords
        
        # Delete older files (all files except the master)
        $filesToDelete = $asimilyFiles | Where-Object { $_.FullName -ne $masterFile.FullName }
        foreach ($fileToDelete in $filesToDelete) {
            Write-Host "Removing old file: $($fileToDelete.Name)" -ForegroundColor Yellow
            Remove-Item -Path $fileToDelete.FullName -Force
        }
        
        # Clean up filename: rename master file to remove (1), (2) etc. increments
        if ($masterFile.Name -match '(.+)\s\(\d+\)\.xlsx$') {
            $cleanFileName = $masterFile.Name -replace '\s\(\d+\)', ''
            $cleanFilePath = Join-Path $masterFile.DirectoryName $cleanFileName
            
            # Only rename if the clean filename doesn't already exist
            if (-not (Test-Path $cleanFilePath)) {
                Write-Host "Renaming master file to clean name: $cleanFileName" -ForegroundColor Cyan
                Rename-Item -Path $masterFile.FullName -NewName $cleanFileName
                $masterFile = Get-Item $cleanFilePath  # Update the master file reference
            } else {
                Write-Host "Clean filename already exists, keeping current name: $($masterFile.Name)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "File management completed. Master file: $($masterFile.Name)" -ForegroundColor Green
    } else {
        Write-Host "No new records found - no comparison file needed" -ForegroundColor Yellow
    }
} else {
    Write-Host "Only one file found - no comparison needed" -ForegroundColor Yellow
    
    # The single file case already shows summary above, just proceed to Phase 2
    # ========================================
    # PHASE 2: ZERO NETWORKS INTEGRATION (SINGLE FILE CASE)
    # ========================================
    if (-not $SkipZNIntegration) {
        Write-Host "Starting Zero Networks integration for all $($masterData.Count) assets..." -ForegroundColor Cyan
        
        # Add device type predictions to all records
        foreach ($record in $masterData) {
            $deviceType = Get-DeviceTypeFromAsimily -AsimilyDeviceType $record.'Device Type' -Manufacturer $record.'Manufacturer' -DeviceModel $record.'Device Model'
            $record | Add-Member -NotePropertyName 'ZN_DeviceType' -NotePropertyValue $deviceType -Force
        }
        
        # Create assets in Zero Networks
        $znResults = Add-AssetsToZeroNetworks -AssetData $masterData -APIKey $APIKey -DryRun:$DryRun
        
        Write-Host "Zero Networks Integration Results:" -ForegroundColor Green
        Write-Host "  Successfully created: $($znResults.Success)" -ForegroundColor Green
        Write-Host "  Failed: $($znResults.Failed)" -ForegroundColor $(if ($znResults.Failed -gt 0) { 'Red' } else { 'Green' })
        
        if ($znResults.Errors.Count -gt 0) {
            Write-Host "  Errors:" -ForegroundColor Red
            $znResults.Errors | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
        }
    } else {
        Write-Host "Zero Networks integration skipped (-SkipZNIntegration specified)" -ForegroundColor Yellow
    }
    # ========================================
    
    Write-Host "Single file processing completed. File: $($masterFile.Name)" -ForegroundColor Green
}

Write-Host "Script completed successfully!" -ForegroundColor Green
Write-Host "Parse-AsimilyExport.ps1 - Created by Olaf Gradin (Zero Networks)" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor White
Write-Host "  Master file: $($masterFile.Name)" -ForegroundColor White
Write-Host "  Total records processed: $($masterData.Count)" -ForegroundColor White
if ($allData.Count -gt 0) {
    Write-Host "  New records found: $($newRecords.Count)" -ForegroundColor White
}

$constructedCount = ($masterData | Where-Object { $_.'HostnameConstructed' -eq $true }).Count
Write-Host "  Hostnames constructed: $constructedCount" -ForegroundColor White

# Prepare and return result object
$finalMasterData = if ($allData.Count -gt 0) { $masterData + $newRecords } else { $masterData }
# Prepare Zero Networks results for the object
$znIntegrationResults = $null
if (-not $SkipZNIntegration -and (Test-Path Variable:znResults)) {
    $znIntegrationResults = @{
        Enabled = $true
        DryRun = $DryRun.IsPresent
        Success = $znResults.Success
        Failed = $znResults.Failed
        Errors = $znResults.Errors
        APIKeyProvided = -not [string]::IsNullOrWhiteSpace($APIKey)
    }
} else {
    $znIntegrationResults = @{
        Enabled = $false
        Skipped = $SkipZNIntegration.IsPresent
        APIKeyProvided = -not [string]::IsNullOrWhiteSpace($APIKey)
    }
}

$resultObject = [PSCustomObject]@{
    MasterFile = $masterFile.Name
    TotalRecords = $finalMasterData.Count
    NewRecordsCount = if ($allData.Count -gt 0) { $newRecords.Count } else { 0 }
    ConstructedHostnamesCount = ($finalMasterData | Where-Object { $_.'HostnameConstructed' -eq $true }).Count
    AllRecords = $finalMasterData
    NewRecords = if ($allData.Count -gt 0) { $newRecords } else { @() }
    ConstructedHostnames = $finalMasterData | Where-Object { $_.'HostnameConstructed' -eq $true } | Select-Object 'Device ID', 'Hostname', 'Manufacturer', 'Device Model', 'MAC Address'
    DeviceTypeMappings = $finalMasterData | Where-Object { $_.PSObject.Properties.Name -contains 'ZN_DeviceType' } | Select-Object 'Device ID', 'Hostname', 'Manufacturer', 'Device Model', 'Device Type', 'ZN_DeviceType'
    ZeroNetworksIntegration = $znIntegrationResults
    ProcessingSummary = @{
        FilesProcessed = $asimilyFiles.Count
        RecordsWithoutIP = if ($allData.Count -gt 0) { ($allData + $masterData | Measure-Object).Count - $finalMasterData.Count } else { 0 }
        UniqueNamesValidated = $true
        OldFilesDeleted = if ($allData.Count -gt 0) { $filesToDelete.Count } else { 0 }
        FileManagement = "Simplified: newest file becomes master, old files deleted"
    }
}

Write-Host "`nResult object returned for inspection. Usage examples:" -ForegroundColor Cyan
Write-Host "  `$result.NewRecords | Select-Object 'Device ID', Hostname, 'Device Type' | Format-Table" -ForegroundColor Gray
Write-Host "  `$result.DeviceTypeMappings | Format-Table" -ForegroundColor Gray
Write-Host "  `$result.ZeroNetworksIntegration" -ForegroundColor Gray
Write-Host "`nFor help: Get-Help .\Parse-AsimilyExport.ps1 -Full" -ForegroundColor Yellow

return $resultObject