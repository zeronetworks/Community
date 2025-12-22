# Pin Assets To Clusters

A PowerShell script for pinning (assigning) or unpinning (unassigning) assets to a particular deployment cluster in Zero Networks (Network/Identity/RPC Segment). This script allows you to pin/unpin individual assets, or in bulk via CSV.

## Requirements

- **PowerShell 7.0 or higher**
- **Zero Networks API Key** with appropriate permissions

## Features

- Pin or unpin individual assets to deployment clusters
- Bulk operations via CSV file
- Automatic batching for large asset lists (50 assets per batch)
- Dry run mode to preview changes without applying them (`-DryRun`)
- Comprehensive validation before making changes
- List all deployment clusters with detailed information (`-ListDeploymentClusters`)
- Export CSV template for bulk operations (`-ExportCsvTemplate`)

## Prerequisites for pinning an asset to a cluster
You can only pin assets that meet the following criterion:
- **Must be monitored by a segment server** - You cannot pin assets monitored by Cloud Connector, Segment Connector, etc.
- **Must have a health status of *Healthy*** - The asset cannot have any health issues listed.
- **Target cluster must have at least one online and active segment server.** *You can skip this check by adding the `-SkipSegmentServerValidation` parameter at run-time*.
- **Obviously, an asset cannot already be pinned** (The script checks for this)


## Parameter Sets

The script supports four parameter sets:

### 1. ByAssetId (Default)
Pin or unpin a single asset to a deployment cluster.

**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-AssetId` - The asset ID to pin/unpin
- `-DeploymentClusterId` - The deployment cluster ID

**Optional Parameters:**
- `-PortalUrl` - Portal URL (default: `https://portal.zeronetworks.com`)
- `-Unpin` - Switch to unpin instead of pin
- `-SkipSegmentServerValidation` - Skip validation that segment servers are online
- `-DryRun` - Preview changes without applying them

### 2. ByCsvPath
Pin or unpin multiple assets from a CSV file.

**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-CsvPath` - Path to the CSV file

**Optional Parameters:**
- `-PortalUrl` - Portal URL (default: `https://portal.zeronetworks.com`)
- `-Unpin` - Switch to unpin instead of pin
- `-SkipSegmentServerValidation` - Skip validation that segment servers are online
- `-DryRun` - Preview changes without applying them

### 3. ListDeploymentClusters
List all deployment clusters with detailed information.

**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-ListDeploymentClusters` - Switch to enable listing mode

**Optional Parameters:**
- `-PortalUrl` - Portal URL (default: `https://portal.zeronetworks.com`)

### 4. ExportCsvTemplate
Export a CSV template file for bulk operations.

**Required Parameters:**
- `-ExportCsvTemplate` - Switch to enable template export

## Quick Start
### Single asset pinning
#### 1. Find the asset ID
- Within the Zero Networks portal, go to **Entities -> Assets -> Monitored** and add the necessary filters to find the asset in question (e.g filter by Name -> MY-PC-1). 
- Enable the **Asset ID** column in the table of assets
- Copy the **Asset ID** to a text document to be referenced later

#### 2. Run script with -ListDeploymentClusters parameter to get Cluster ID
Run the script with the `-ListDeploymentClusters` parameter. This will output information about all clusters in the tenant to your console.

*The data below is actual output, but specific identifying information has been changed for secrecy.*
```powershell
./Pin-AssetsToClusters.ps1' -ApiKey <API KEY HERE> -PortalUrl https://<MY URL>.zeronetworks.com -ListDeploymentClusters
...
Getting deployment clusters
Decoding deployment cluster ID fields! (e.g Updating strategy=2 --> strategy=Active/Active)
Created script-wide hashtable of deployment clusters
Writing deployment clusters information to console
======================================================================================================================
Deployment cluster: ZN deployments cluster
Cluster ID: C:d:00ab123d
Number of assets in cluster: 10
HA Strategy: Active/Passive
Segment server deployments assigned to this cluster:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  Name: MY-SEGMENT-SRV001
  Deployment ID: 47792f8f-1213-1234-abcd-4fb47f2794d3
  Server Asset ID: a:a:JabcdEjT
  Status: Online
  State: Primary
  Num Assets Associated: 10
  Internal IP Address: 10.2.3.4
  External IP Address: 1.20.21.22
  Segment Server Version: 25.10.3.4
  Is Preferred Deployment: Yes
  Deployment Services:
    --------------------------------
    Service ID: ad
    Service Status: Online
    Service State: Primary
    --------------------------------
    --------------------------------
    Service ID: winrm
    Service Status: Online
    Service State: Primary
    --------------------------------
    --------------------------------
    Service ID: ansible-manager
    Service Status: Online
    Service State: Primary
    --------------------------------
  -----------------------------------------------------------
======================================================================================================================
======================================================================================================================
Deployment cluster: EU Cluster
Cluster ID: C:d:8PghlCty
Number of assets in cluster: 0
HA Strategy: Active/Passive
Segment server deployments assigned to this cluster:
  No segment server deploments are assigned to this cluster
======================================================================================================================
Finished writing deployment clusters information to console
```

#### 3. Extract cluster ID(s) from output
Analyze the output from the script ran with `-ListDeploymentClusters`. Make note of each **Cluster ID(s)** you wish to pin the asset(s) to. E.g ```C:d:8PghlCty```

#### 4. Pin the asset to the cluster
Run the script in single asset mode, specifying a particular asset and cluster ID. This will pin this asset to the specified cluster.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "a:a:qvI6tVtn" `
    -DeploymentClusterId "C:d:00fd409f" `
    -PortalUrl "https://your-portal.zeronetworks.com"
```

### Bulk Operations
#### 1. Export applicable assets to CSV within the portal
- From within the Zero Networks portal, go to *Entities -> Assets -> Monitored* and add the filter **Monitored By --> Segment Server** and **Health Status --> Healthy** (Prerequisites).
- Filter the list additionally until it only displays assets you wish to pin/unpin.
- Export the list to a CSV file

#### 2. Run the script to generate a CSV template
To facilitate ease of use, the script, when ran with the `-ExportCsvTemplate` parameter, will export a CSV template at `./pin-assets-to-clusters-template.csv`

#### 3. List deployment clusters
Follow the steps [2. Run script with -ListDeploymentClusters parameter to get Cluster ID](#2-run-script-with--listdeploymentclusters-parameter-to-get-cluster-id) and [3. Extract cluster ID(s) from output](#3-extract-cluster-ids-from-output) from the [Single asset pinning](#single-asset-pinning) section above to obtain a list of relevant Cluster IDs.

#### 4. Populate CSV template
Copy the asset IDs (and asset names, if desired) into the CSV template previously generated. Copy and paste the cluster ID (for which you wish to pin that asset to)in the *DeploymentClusterId* column of the CSV for each asset.

Your CSV should look similar to:
```csv
AssetName,AssetId,DeploymentClusterId
Server-01,a:a:qvI6tVtn,C:d:00fd409f
Server-02,a:a:abc123,C:d:00fd409f
Server-03,a:a:def456,C:d:00fd409g
```

To review the required columns in the CSV, please read [CSV file format](#csv-file-format).

#### 5. Run script against the CSV
Finally, run the script, passing it the path to your CSV.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -PortalUrl "https://your-portal.zeronetworks.com"
```

## Usage Examples

### Pin a Single Asset

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "a:a:qvI6tVtn" `
    -DeploymentClusterId "C:d:00fd409f" `
    -PortalUrl "https://your-portal.zeronetworks.com"
```

### Unpin a Single Asset

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "a:a:qvI6tVtn" `
    -DeploymentClusterId "C:d:00fd409f" `
    -Unpin
```

### Pin Assets from CSV File

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -PortalUrl "https://your-portal.zeronetworks.com"
```

### Unpin Assets from CSV File

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -Unpin
```

### Dry Run (Preview Changes)

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -DryRun
```

### List All Deployment Clusters

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -ListDeploymentClusters
```

### Export CSV Template

```powershell
.\Pin-AssetsToClusters.ps1 -ExportCsvTemplate
```

## CSV File Format

The CSV file must contain at least the following columns:

- **AssetId** (required) - The asset ID to pin/unpin
- **DeploymentClusterId** (required) - The deployment cluster ID
- **AssetName** (optional) - Asset name for reference

Example CSV:

```csv
AssetName,AssetId,DeploymentClusterId
Server-01,a:a:qvI6tVtn,C:d:00fd409f
Server-02,a:a:abc123,C:d:00fd409f
Server-03,a:a:def456,C:d:00fd409g
```

## Validation

The script performs comprehensive validation before making any changes:

### Asset Validation
- Asset must be monitored by a Segment Server (not Cloud Connector or Lightweight Agent)
- Asset must be healthy
- Asset must be applicable to be pinned to a deployment cluster (An asset's deploymentSource attribute cannot be set to "Not Applicable")
- For pinning: Asset must not already be pinned to a deployment cluster
- For unpinning: Asset must already be pinned to a deployment cluster

### Deployment Cluster Validation
- Deployment cluster must exist in the tenant
- Deployment cluster must have at least one segment server assigned (unless `-SkipSegmentServerValidation` is used)
- At least one segment server must be online (unless `-SkipSegmentServerValidation` is used)


## Dry Run Mode

Use the `-DryRun` switch to preview what changes would be made without actually applying them. In dry run mode:

- All validations are still performed
- The script shows what would be done
- The request body that would be sent is displayed
- No API calls are made to modify asset assignments

## Error Handling

The script includes comprehensive error handling:

- **404 errors**: Asset or deployment cluster not found
- **400/401/403/405 errors**: Bad request, unauthorized, forbidden, or method not allowed
- **500/501/503 errors**: Server errors with detailed messages
- **Validation errors**: Clear messages when assets or clusters don't meet requirements

All errors include the status code, reason phrase, and response body when available.

## Output

The script provides detailed console output including:

- Progress messages for each operation
- Validation results
- Batch processing information (for large operations)
- Success confirmations
- Error messages with context

## Notes

- The script requires PowerShell 7.0 or higher
- API keys should be kept secure and not committed to version control
- Large operations may take time depending on the number of assets and network conditions
- The script uses `$ErrorActionPreference = "Stop"` to ensure errors are handled properly

## Troubleshooting

### "Asset is not monitored by a Segment Server"
The asset must be using a Segment Server, not Cloud Connector or Lightweight Agent.

### "Deployment cluster has no online segment servers"
Ensure at least one segment server in the deployment cluster is online. Use `-SkipSegmentServerValidation` to bypass this check if needed.

### "Asset is already pinned to a deployment cluster"
The asset is already pinned to a cluster. Use `-Unpin` first if you want to change the assignment.

