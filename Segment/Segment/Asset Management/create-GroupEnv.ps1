param (
    [Parameter(Mandatory = $true)]
    [string]$IPaddress,

    [Parameter(Mandatory = $true)]
    [string]$GroupID,

    [Parameter(Mandatory = $false)]
    [string]$baseUri = "https://portal.zeronetworks.com/api/v1/",

    [Parameter(Mandatory = $true)]
    [string]$APIKey
)

# Headers
$znHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$znHeaders.Add("Authorization", $APIKey)
$znHeaders.Add("content-type", "application/json")

# Function Lookup Remote Candidates
function remoteCandidates {
    param (
        [string[]]$ipsString # Input parameter is an array of strings (IP addresses)<#
.SYNOPSIS
    Automates the creation of groups and addition of members via an API, based on a CSV input.
.DESCRIPTION
    This script reads a CSV file containing device information (Name, FQDN, Environment).
    It processes each item, handling blank or comma-separated Environments.
    For each unique Environment, it ensures a corresponding group exists in the target API (creating it if necessary).
    If a group is newly created, the script attempts to verify its existence by re-fetching it before adding members.
    Then, it resolves devices from the CSV to their API-specific asset IDs by looking them up by name and validating with FQDN.
    Finally, it adds these resolved assets as members to the appropriate group.

    Prerequisites: PowerShell 5.1 or later.

.PARAMETER CsvFilePath
    The full path to the input CSV file.
    The CSV must contain columns: 'Name', 'Fully qualified domain name', and 'Environment'.
.PARAMETER BaseApiUrl
    The base URL for the API. Example: "https://portal.zeronetworks.com/api/v1"
.PARAMETER ApiKey
    The API key for authentication. This is passed directly as a string.
.EXAMPLE
    .\create-GroupEnv.ps1 -CsvFilePath "C:\path\to\your\devices.csv" -BaseApiUrl "https://portal.zeronetworks.com/api/v1" -ApiKey "your_api_key_here" -Verbose

    This example runs the script with the specified CSV, API URL, and API key, with verbose logging enabled.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$CsvFilePath,

    [Parameter(Mandatory=$true)]
    [string]$BaseApiUrl,

    [Parameter(Mandatory=$true)]
    [string]$ApiKey
)

# --- Script-level Configuration ---
$VerbosePreference = if ($PSBoundParameters.Verbose) { 'Continue' } else { 'SilentlyContinue' }

# --- Helper Functions ---
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO" # INFO, WARNING, ERROR
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Write-Host $logEntry
    if ($Level -eq "ERROR" -or $Level -eq "WARNING") {
        Write-Warning $logEntry # Also writes to warning stream
    }
    if ($PSBoundParameters.Verbose -and $Level -eq "INFO") {
        Write-Verbose $Message # For -Verbose output consistency
    }
}

# --- Main Script Logic ---

# 1. Read and Validate CSV
Write-Log "Starting script..."
if (-not (Test-Path $CsvFilePath)) {
    Write-Log "ERROR: CSV file not found at '$CsvFilePath'." -Level ERROR
    exit 1
}

try {
    Write-Log "Reading CSV file: $CsvFilePath"
    $csvData = Import-Csv -Path $CsvFilePath
}
catch {
    Write-Log "ERROR: Failed to read or parse CSV file. Details: $($_.Exception.Message)" -Level ERROR
    exit 1
}

if (-not $csvData) {
    Write-Log "WARNING: CSV file is empty or could not be parsed correctly." -Level WARNING
    exit 0
}

# Check for required columns
$requiredColumns = @('Name', 'Fully qualified domain name', 'Environment')
$actualColumns = $csvData[0].PSObject.Properties.Name
foreach ($col in $requiredColumns) {
    if ($actualColumns -notcontains $col) {
        Write-Log "ERROR: CSV file is missing required column: '$col'. Please ensure columns 'Name', 'Fully qualified domain name', and 'Environment' exist." -Level ERROR
        exit 1
    }
}

# 2. Process and Normalize Data
Write-Log "Processing and normalizing CSV data..."
$processedItems = @()
foreach ($row in $csvData) {
    $name = $row.Name
    $fqdn = $row.'Fully qualified domain name' # Accessing column with space in name
    $EnvironmentsRaw = $row.Environment

    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($fqdn)) {
        Write-Log "WARNING: Skipping row with missing Name or FQDN: Name='$name', FQDN='$fqdn'." -Level WARNING
        continue
    }

    $EnvironmentsToProcess = @()
    if ([string]::IsNullOrWhiteSpace($EnvironmentsRaw)) {
        $EnvironmentsToProcess += "no-Environment"
    }
    else {
        $EnvironmentsToProcess += $EnvironmentsRaw.Split(',').Trim() | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    foreach ($Environment in $EnvironmentsToProcess) {
        $processedItems += [PSCustomObject]@{
            Name              = $name
            FQDN              = $fqdn
            EnvironmentToProcess  = $Environment.Trim()
        }
    }
}

if (-not $processedItems) {
    Write-Log "WARNING: No valid items to process after normalization." -Level WARNING
    exit 0
}

# 3. Group Items by Final 'EnvironmentToProcess'
Write-Log "Grouping items by Environment..."
$groupedByEnvironment = $processedItems | Group-Object -Property EnvironmentToProcess

# --- API Interaction Setup ---
$headers = @{
    "Authorization" = $ApiKey
    "Content-Type"  = "application/json"
}

# 4. Iterate through each unique 'EnvironmentToProcess' group
foreach ($group in $groupedByEnvironment) {
    $currentEnvironment = $group.Name
    Write-Log "Processing Environment group: '$currentEnvironment'"

    $targetGroupID = $null
    $wasGroupNewlyCreated = $false # Flag to indicate if we just created this group

    # (a) Ensure Group Exists in API and Get its ID
    try {
        Write-Log "Checking if group '$currentEnvironment' exists..."
        $filterValue = '[{"id":"name","includeValues":["' + $currentEnvironment + '"],"excludeValues":[]}]'
        #$encodedFilter = [System.Web.HttpUtility]::UrlEncode($filterValue)
        $encodedFilter = [uri]::EscapeDataString($filterValue)
        $checkGroupUri = "$BaseApiUrl/groups/custom?_limit=1&_filters=$encodedFilter" 

        $existingGroupResponse = Invoke-RestMethod -Uri $checkGroupUri -Method Get -Headers $headers
        
        if ($existingGroupResponse.items -and $existingGroupResponse.items.Count -gt 0) {
            $targetGroupID = $existingGroupResponse.items[0].id # Assuming ID is directly in item
            Write-Log "Group '$currentEnvironment' found with ID: $targetGroupID"
        }
        else {
            Write-Log "Group '$currentEnvironment' not found. Creating it..."
            $createGroupUri = "$BaseApiUrl/groups/custom"
            $createGroupBody = @{
                name        = $currentEnvironment
                description = "Group for $currentEnvironment (auto-created by script)"
                membersId   = @() 
            } | ConvertTo-Json -Depth 5

            $newGroupResponse = Invoke-RestMethod -Uri $createGroupUri -Method Post -Headers $headers -Body $createGroupBody
            
            # CORRECTED: Access ID from the nested 'entity' object
            if ($newGroupResponse.entity -and $newGroupResponse.entity.id) {
                $targetGroupID = $newGroupResponse.entity.id
                $wasGroupNewlyCreated = $true # Set the flag
                Write-Log "Group '$currentEnvironment' created successfully with ID: $targetGroupID"
            } else {
                Write-Log "ERROR: Failed to create group '$currentEnvironment' or could not retrieve its ID from the response." -Level ERROR
                Write-Log "API Response for group creation: $(ConvertTo-Json $newGroupResponse -Depth 5)" -Level INFO
                continue 
            }
        }
    }
    catch {
        Write-Log "ERROR: Exception during group check/creation for '$currentEnvironment'. Details: $($_.Exception.Message)" -Level ERROR
        Write-Log "API Call Details: URI tried was for checking or creating group." -Level INFO
        Write-Log "API Response (if any): $($_.ErrorDetails.Message)" -Level INFO 
        continue 
    }

    if (-not $targetGroupID) {
        Write-Log "ERROR: Could not obtain a valid Group ID for Environment '$currentEnvironment'. Skipping member addition." -Level ERROR
        continue
    }

    # If the group was newly created, verify its availability with retries
    if ($wasGroupNewlyCreated) {
        $maxRetries = 3
        $retryDelaySeconds = 3 # Short delay between retries
        $groupVerified = $false

        for ($retryCount = 1; $retryCount -le $maxRetries; $retryCount++) {
            Write-Log "INFO: Verifying newly created group '$currentEnvironment' (ID: $targetGroupID), attempt $retryCount of $maxRetries..." -Level INFO
            try {
                # Attempt to fetch the group by its ID
                $verifyGroupUri = "$BaseApiUrl/groups/custom/$targetGroupID"
                $verificationResponse = Invoke-RestMethod -Uri $verifyGroupUri -Method Get -Headers $headers
                
                # Check if the verification response has the 'entity' object and the correct ID within it
                if ($verificationResponse.entity -and $verificationResponse.entity.id -eq $targetGroupID) {
                    Write-Log "INFO: Group '$currentEnvironment' (ID: $targetGroupID) successfully verified." -Level INFO
                    $groupVerified = $true
                    break # Exit retry loop
                } else {
                     Write-Log "WARNING: Verification attempt $retryCount for group '$currentEnvironment' (ID: $targetGroupID) succeeded but response structure was unexpected or ID did not match." -Level WARNING
                     Write-Log "Verification Response: $(ConvertTo-Json $verificationResponse -Depth 5)" -Level INFO
                }
            }
            catch {
                Write-Log "WARNING: Verification attempt $retryCount for group '$currentEnvironment' (ID: $targetGroupID) failed. Details: $($_.Exception.Message)" -Level WARNING
                Write-Log "API Response (if any) from failed verification: $($_.ErrorDetails.Message)" -Level INFO
            }

            if ($retryCount -lt $maxRetries) {
                Write-Log "INFO: Waiting $retryDelaySeconds seconds before next verification attempt..." -Level INFO
                Start-Sleep -Seconds $retryDelaySeconds
            }
        }

        if (-not $groupVerified) {
            Write-Log "ERROR: Failed to verify newly created group '$currentEnvironment' (ID: $targetGroupID) after $maxRetries attempts. Skipping member addition for this group." -Level ERROR
            continue # Skip to the next Environment group
        }
    }

    # (b) For the current $targetGroupID, Prepare and Add Members
    $listOfMemberApiIdsForCurrentGroup = [System.Collections.Generic.List[string]]::new()

    Write-Log "Finding and validating members for group '$currentEnvironment' (ID: $targetGroupID)..."
    foreach ($item in $group.Group) { 
        $csvItemName = $item.Name
        $csvItemFqdn = $item.FQDN
        Write-Log "Attempting to resolve asset: Name='$csvItemName', FQDN='$csvItemFqdn'"

        try {
            $assetFilterValue = '[{"id":"name","includeValues":["' + $csvItemName + '"],"excludeValues":[]}]'
            #$encodedAssetFilter = [System.Web.HttpUtility]::UrlEncode($assetFilterValue)
            $encodedAssetFilter = [uri]::EscapeDataString($assetFilterValue)
            $findAssetUri = "$BaseApiUrl/assets?_limit=10&_filters=$encodedAssetFilter&showInactive=false" 

            $assetSearchResponse = Invoke-RestMethod -Uri $findAssetUri -Method Get -Headers $headers
            
            $foundMatchingAsset = $false
            if ($assetSearchResponse.items -and $assetSearchResponse.items.Count -gt 0) {
                foreach ($assetObject in $assetSearchResponse.items) {
                    $assetApiId = $assetObject.id
                    $assetApiFqdn = $assetObject.fqdn

                    if ($assetApiFqdn -is [string] -and $assetApiFqdn.Equals($csvItemFqdn, [System.StringComparison]::OrdinalIgnoreCase)) {
                        Write-Log "  MATCH: Found asset ID '$assetApiId' for Name='$csvItemName', FQDN='$csvItemFqdn'"
                        if (-not $listOfMemberApiIdsForCurrentGroup.Contains($assetApiId)) {
                             $listOfMemberApiIdsForCurrentGroup.Add($assetApiId)
                        } else {
                            Write-Log "  INFO: Asset ID '$assetApiId' already added for this group." -Level INFO
                        }
                        $foundMatchingAsset = $true
                        break 
                    } else {
                         Write-Log "  MISMATCH: Asset ID '$assetApiId' has FQDN '$assetApiFqdn', expected '$csvItemFqdn' for name '$csvItemName'." -Level INFO
                    }
                }
            }
            
            if (-not $foundMatchingAsset) {
                Write-Log "WARNING: No matching asset found in API for Name='$csvItemName' with FQDN='$csvItemFqdn'." -Level WARNING
            }
        }
        catch {
            Write-Log "ERROR: Exception while finding asset Name='$csvItemName', FQDN='$csvItemFqdn'. Details: $($_.Exception.Message)" -Level ERROR
            Write-Log "API Call Details: URI was '$findAssetUri'" -Level INFO
            Write-Log "API Response (if any): $($_.ErrorDetails.Message)" -Level INFO
        }
    } 

    if ($listOfMemberApiIdsForCurrentGroup.Count -gt 0) {
        Write-Log "Adding $($listOfMemberApiIdsForCurrentGroup.Count) members to group '$currentEnvironment' (ID: $targetGroupID)..."
        try {
            $addMembersUri = "$BaseApiUrl/groups/custom/$targetGroupID/members"
            $addMembersBody = @{
                membersId = $listOfMemberApiIdsForCurrentGroup.ToArray() 
            } | ConvertTo-Json -Depth 5
            
            Invoke-RestMethod -Uri $addMembersUri -Method Put -Headers $headers -Body $addMembersBody
            Write-Log "Successfully submitted request to add members to group '$currentEnvironment'."
        }
        catch {
            Write-Log "ERROR: Exception while adding members to group '$currentEnvironment' (ID: $targetGroupID). Details: $($_.Exception.Message)" -Level ERROR
            Write-Log "API Call Details: URI was '$addMembersUri'" -Level INFO
            Write-Log "Request Body Sent: $addMembersBody" -Level INFO
            Write-Log "API Response (if any): $($_.ErrorDetails.Message)" -Level INFO
        }
    }
    else {
        Write-Log "No valid members found/resolved to add to group '$currentEnvironment'." -Level INFO
    }

    Write-Log "Finished processing Environment group: '$currentEnvironment'."
    Write-Host "" 

} 

Write-Log "Script finished."

    )
    $allResults = @() # Initialize an empty array to store all results
    $ips = $ipsString.Split(',') | ForEach-Object { $_.Trim() } # Split and trim IPs
    foreach ($ip in $ips) {
        $candidateUri = "$baseUri/protection/rules/inbound/remote-candidates?_limit=100&_offset=0&_search=$ip&ruleType=1"
        try {
            $results = Invoke-RestMethod -Uri $candidateUri -Method Get -Headers $znHeaders
            $allResults += $results # Append results to the array
        }
        catch {
            Write-Error "Failed to get remote candidates for IP: $ip - $_"
        }
    }
    return $allResults # Return the array of results
}

$eid = (remoteCandidates -ipsString $IPaddress).items.id

$body = @{
    membersId = @($eid)
}
$jsonBody = $body | ConvertTo-Json -Depth 1
$uri = "$baseUri/groups/custom/$GroupID/members"

Invoke-RestMethod -Uri "$uri" -Method PUT -Headers $znHeaders -Body $jsonBody
