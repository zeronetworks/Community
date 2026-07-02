# Pin Assets To Clusters

A PowerShell script for pinning (assigning) or unpinning (unassigning) assets to a particular deployment cluster in Zero Networks. This script allows you to pin/unpin individual assets, or in bulk via CSV, AD OU path, or IPv4 subnet (CIDR).

## Requirements

- **PowerShell 7.0 or higher**
- **Zero Networks API Key** with appropriate permissions

## Features

- Pin or unpin assets to deployment clusters via asset ID, CSV file, Active Directory OU path, or IPv4 subnet (CIDR)
- Target clusters by human-readable name (`-DeploymentClusterName`), resolved via a local per-tenant name cache file (see [Deployment Cluster Name Resolution](#deployment-cluster-name-resolution))
- Bulk operations via CSV file, AD OU path, or IPv4 subnet
- Automatic batching for large asset lists (50 assets per batch)
- Dry run mode to preview changes without applying them (`-DryRun`)
- Comprehensive validation before making changes
- Stop on validation error option (`-StopOnAssetValidationError`) for strict validation enforcement
- Nested OU resolution control (`-DisableNestedOuResolution`) for OU-based operations
- Asset health check bypass (`-SkipAssetHealthValidation`) for cases where a transient/stale unhealthy status shouldn't block pinning
- Concurrent subnet asset resolution with tunable throttling (`-MaxConcurrentBatches`) for subnet-based operations
- List all deployment clusters with detailed information (`-ListDeploymentClusters`)
- Export CSV template for bulk operations (`-ExportCsvTemplate`)
- Debug output mode (`-EnableDebug`) for troubleshooting

## Prerequisites for pinning an asset to a cluster
You can only pin assets that meet the following criterion:
- **Must be monitored by a segment server** - You cannot pin assets monitored by Cloud Connector, Segment Connector, etc.
- **Must have a health status of *Healthy*** - The asset cannot have any health issues listed. *You can skip this check by adding the `-SkipAssetHealthValidation` parameter at run-time*.
- **Target cluster must have at least one online and active segment server.** *You can skip this check by adding the `-SkipSegmentServerValidation` parameter at run-time*.
- **Obviously, an asset cannot already be pinned** (The script checks for this)


## Script use cases

The script supports six different use cases:

### 1. Pinning/Unpinning Asset by Asset ID & Deployment Cluster Name (Default)
Pin or unpin a single asset to a deployment cluster. You can use the `-ListDeploymentClusters` use case to get the deployment cluster name.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "your-asset-id" `
    -DeploymentClusterName "your-deployment-cluster-name" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

See the [Quick start](#quick-start) section for more examples.

#### Supported Parameters
**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-AssetId` - The asset ID to pin/unpin
- `-DeploymentClusterName` - The deployment cluster name (resolved to a cluster ID via the local name cache file - see [Deployment Cluster Name Resolution](#deployment-cluster-name-resolution))
- `-PortalUrl` - Portal URL (e.g., `https://yourportal-admin.zeronetworks.com`)

**Optional Parameters:**
- `-Unpin` - Switch to unpin instead of pin
- `-SkipSegmentServerValidation` - Skip validation that segment servers are online
- `-SkipAssetHealthValidation` - Skip validation that the asset is healthy
- `-DryRun` - Preview changes without applying them
- `-EnableDebug` - Enable debug output

### 2. Active Directory OU Bulk Operations
Pin or unpin all assets within a specified Active Directory Organizational Unit (OU) path to a deployment cluster.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -OUPath "OU=Your,DC=Company,DC=com" `
    -DeploymentClusterName "your-deployment-cluster-name" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

See the [Quick start](#quick-start) section for more examples.

#### Supported Parameters
**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-OUPath` - The OU path (e.g., "OU=Computers,DC=domain,DC=com")
- `-DeploymentClusterName` - The deployment cluster name (resolved to a cluster ID via the local name cache file - see [Deployment Cluster Name Resolution](#deployment-cluster-name-resolution))
- `-PortalUrl` - Portal URL (e.g., `https://yourportal-admin.zeronetworks.com`)

**Optional Parameters:**
- `-DisableNestedOuResolution` - Disable nested OU resolution (default: `false`). When set to `true`, only direct members of the OU are processed, not nested OUs.
- `-Unpin` - Switch to unpin instead of pin
- `-SkipSegmentServerValidation` - Skip validation that segment servers are online
- `-SkipAssetHealthValidation` - Skip validation that assets are healthy
- `-DryRun` - Preview changes without applying them
- `-StopOnAssetValidationError` - Stop processing and throw an error when asset validation fails. If not specified, the script continues processing and only operates on assets that passed validation.
- `-EnableDebug` - Enable debug output

### 3. CSV Bulk Operations
Pin or unpin multiple assets from a CSV file. Use `-ExportCsvTemplate` and `-ListDeploymentClusters` to help you build your CSV.
#### Supported Parameters
**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-CsvPath` - Path to the CSV file
- `-PortalUrl` - Portal URL (e.g., `https://yourportal-admin.zeronetworks.com`)

**Optional Parameters:**
- `-Unpin` - Switch to unpin instead of pin
- `-SkipSegmentServerValidation` - Skip validation that segment servers are online
- `-SkipAssetHealthValidation` - Skip validation that assets are healthy
- `-DryRun` - Preview changes without applying them
- `-StopOnAssetValidationError` - Stop processing and throw an error when asset validation fails. If not specified, the script continues processing and only operates on assets that passed validation.
- `-EnableDebug` - Enable debug output

### 4. IPv4 Subnet (CIDR) Bulk Operations
Pin or unpin all monitored assets whose last known IP address falls within a specified IPv4 subnet (CIDR range) to a deployment cluster.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -TargetSubnet "10.200.200.0/24" `
    -DeploymentClusterName "your-deployment-cluster-name" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

The script expands the CIDR range into individual host addresses (including network/broadcast addresses) and resolves them to monitored assets via the API. Host address batches are queried concurrently (see `-MaxConcurrentBatches`) to speed up resolution for large subnets.

**Subnet size limits:**
- Subnets larger than `/24` (more than 256 addresses) require interactive confirmation before proceeding, since resolution will require multiple batched API calls.
- Subnets larger than `/16` (more than 65,536 addresses) are rejected outright.

#### Supported Parameters
**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-TargetSubnet` - IPv4 CIDR subnet to pin/unpin assets within (e.g., `10.200.200.0/24`)
- `-DeploymentClusterName` - The deployment cluster name (resolved to a cluster ID via the local name cache file - see [Deployment Cluster Name Resolution](#deployment-cluster-name-resolution))
- `-PortalUrl` - Portal URL (e.g., `https://yourportal-admin.zeronetworks.com`)

**Optional Parameters:**
- `-Unpin` - Switch to unpin instead of pin
- `-SkipSegmentServerValidation` - Skip validation that segment servers are online
- `-SkipAssetHealthValidation` - Skip validation that assets are healthy
- `-DryRun` - Preview changes without applying them
- `-StopOnAssetValidationError` - Stop processing and throw an error when asset validation fails. If not specified, the script continues processing and only operates on assets that passed validation.
- `-MaxConcurrentBatches` - Maximum number of subnet-batch asset resolution requests to run concurrently (default: `5`, range: `1`-`20`). Set to `1` to force fully sequential behavior.
- `-EnableDebug` - Enable debug output

### 5. List your deployment clusters
List all deployment clusters with detailed information.
#### Supported Parameters
**Required Parameters:**
- `-ApiKey` - Your Zero Networks API key
- `-ListDeploymentClusters` - Switch to enable listing mode
- `-PortalUrl` - Portal URL (e.g., `https://yourportal-admin.zeronetworks.com`)

**Optional Parameters:**
- `-EnableDebug` - Enable debug output

### 6. Export CSV Template to use with CSV Bulk Operations
Export a CSV template file for bulk operations.
#### Supported Parameters
**Required Parameters:**
- `-ExportCsvTemplate` - Switch to enable template export

**Optional Parameters:**
- `-EnableDebug` - Enable debug output

## Quick Start
### Single asset pinning
#### 1. Find the asset ID
- Within the Zero Networks portal, go to **Entities -> Assets -> Monitored** and add the necessary filters to find the asset in question (e.g filter by Name -> MY-PC-1). 
- Enable the **Asset ID** column in the table of assets
- Copy the **Asset ID** to a text document to be referenced later

#### 2. Run script with -ListDeploymentClusters parameter to get Cluster Name
Run the script with the `-ListDeploymentClusters` parameter. This will output information about all clusters in the tenant to your console, and will also create/refresh the local `<envName>-DeploymentClusters.json` name cache file next to the script (see [Deployment Cluster Name Resolution](#deployment-cluster-name-resolution)).

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

#### 3. Extract cluster name(s) from output
Analyze the output from the script ran with `-ListDeploymentClusters`. Make note of each **Cluster Name** (the `Deployment cluster: ...` line) you wish to pin the asset(s) to. E.g ```EU Cluster```

#### 4. Pin the asset to the cluster
Run the script in single asset mode, specifying a particular asset and cluster name. This will pin this asset to the specified cluster.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "a:a:123456tn" `
    -DeploymentClusterName "Production Cluster" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

### Pinning Assets by OU Path (Bulk Ops)
#### 1. Get the OU path
- Determine the Active Directory Organizational Unit (OU) path for the assets you want to pin/unpin
- The OU path format should be: `OU=Computers,DC=domain,DC=com`
- You can find OU paths using Active Directory tools or PowerShell

#### 2. List deployment clusters
Follow the steps [2. Run script with -ListDeploymentClusters parameter to get Cluster Name](#2-run-script-with--listdeploymentclusters-parameter-to-get-cluster-name) and [3. Extract cluster name(s) from output](#3-extract-cluster-names-from-output) from the [Single asset pinning](#single-asset-pinning) section above to obtain the Cluster Name.

#### 3. Pin assets in the OU to the cluster
Run the script with the OU path and cluster ID. By default, the script will process assets in nested OUs as well.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -OUPath "OU=Computers,DC=domain,DC=com" `
    -DeploymentClusterName "Production Cluster" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

To process only direct members of the OU (excluding nested OUs), use the `-DisableNestedOuResolution` parameter:

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -OUPath "OU=Computers,DC=domain,DC=com" `
    -DeploymentClusterName "Production Cluster" `
    -DisableNestedOuResolution $true
```

**Note:** The script automatically filters out segment servers and any non-computer entity, processing only valid assets from the OU.

### Pinning Assets by IPv4 Subnet (Bulk Ops)
#### 1. Determine the target subnet
- Determine the IPv4 CIDR subnet (e.g., `10.200.200.0/24`) covering the assets you want to pin/unpin. Assets are matched based on their last known IP address in the portal.

#### 2. List deployment clusters
Follow the steps [2. Run script with -ListDeploymentClusters parameter to get Cluster Name](#2-run-script-with--listdeploymentclusters-parameter-to-get-cluster-name) and [3. Extract cluster name(s) from output](#3-extract-cluster-names-from-output) from the [Single asset pinning](#single-asset-pinning) section above to obtain the Cluster Name.

#### 3. Pin assets in the subnet to the cluster
Run the script with the target subnet and cluster ID.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -TargetSubnet "10.200.200.0/24" `
    -DeploymentClusterName "Production Cluster" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

**Note:** Subnets larger than `/24` will prompt for interactive confirmation before proceeding, since resolving assets requires multiple batched API calls. Subnets larger than `/16` are rejected. Use `-MaxConcurrentBatches` to control how many resolution batches run in parallel.

### Pinning assets from a CSV (Bulk Ops)
#### 1. Export applicable assets to CSV within the portal
- From within the Zero Networks portal, go to *Entities -> Assets -> Monitored* and add the filter **Monitored By --> Segment Server** and **Health Status --> Healthy** (Prerequisites).
- Filter the list additionally until it only displays assets you wish to pin/unpin.
- Export the list to a CSV file

#### 2. Run the script to generate a CSV template
To facilitate ease of use, the script, when ran with the `-ExportCsvTemplate` parameter, will export a CSV template at `./pin-assets-to-clusters-template.csv`

#### 3. List deployment clusters
Follow the steps [2. Run script with -ListDeploymentClusters parameter to get Cluster Name](#2-run-script-with--listdeploymentclusters-parameter-to-get-cluster-name) and [3. Extract cluster name(s) from output](#3-extract-cluster-names-from-output) from the [Single asset pinning](#single-asset-pinning) section above to obtain a list of relevant Cluster names.

#### 4. Populate CSV template
Copy the asset IDs and asset names into the CSV template previously generated. Copy and paste the cluster name (for which you wish to pin that asset to) in the *DeploymentClusterName* column of the CSV for each asset.

**Required CSV Columns:** AssetName, AssetId, DeploymentClusterName

Your CSV should look similar to:
```csv
AssetName,AssetId,DeploymentClusterName
Server-01,a:a:123456tn,Production Cluster
Server-02,a:a:abc123,Production Cluster
Server-03,a:a:def456,EU Cluster
```

To review the required columns in the CSV, please read [CSV file format](#csv-file-format).

#### 5. Run script against the CSV
Finally, run the script, passing it the path to your CSV.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

## Usage Examples

### Pin a Single Asset

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "a:a:123456tn" `
    -DeploymentClusterName "Production Cluster" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

### Unpin a Single Asset

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "a:a:123456tn" `
    -DeploymentClusterName "Production Cluster" `
    -Unpin
```

### Pin Assets from CSV File

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

### Unpin Assets from CSV File

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -Unpin
```

### Pin Assets by OU Path

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -OUPath "OU=Computers,DC=domain,DC=com" `
    -DeploymentClusterName "Production Cluster" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

### Unpin Assets by OU Path

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -OUPath "OU=Computers,DC=domain,DC=com" `
    -DeploymentClusterName "Production Cluster" `
    -Unpin
```

### Pin Assets by OU Path (Disable Nested OU Resolution)

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -OUPath "OU=Computers,DC=domain,DC=com" `
    -DeploymentClusterName "Production Cluster" `
    -DisableNestedOuResolution $true
```

### Pin Assets by IPv4 Subnet

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -TargetSubnet "10.200.200.0/24" `
    -DeploymentClusterName "Production Cluster" `
    -PortalUrl "https://yourportal-admin.zeronetworks.com"
```

### Unpin Assets by IPv4 Subnet

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -TargetSubnet "10.200.200.0/24" `
    -DeploymentClusterName "Production Cluster" `
    -Unpin
```

### Pin Assets by IPv4 Subnet with Custom Concurrency

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -TargetSubnet "10.200.0.0/20" `
    -DeploymentClusterName "Production Cluster" `
    -MaxConcurrentBatches 10
```

### Skip Asset Health Validation

Use `-SkipAssetHealthValidation` if a transient or stale unhealthy status in the portal shouldn't block a pin/unpin operation. All other validations (segment server check, monitored-by-Segment-Server check, applicability, and pin state) are still enforced.

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -AssetId "a:a:123456tn" `
    -DeploymentClusterName "Production Cluster" `
    -SkipAssetHealthValidation
```

### Stop on Asset Validation Error

When using `-StopOnAssetValidationError`, the script will stop and throw an error if any asset fails validation, rather than continuing with only the validated assets:

```powershell
.\Pin-AssetsToClusters.ps1 `
    -ApiKey "your-api-key" `
    -CsvPath ".\pin-assets-to-clusters-template.csv" `
    -StopOnAssetValidationError
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

The CSV file must contain the following columns:

- **AssetId** (required) - The asset ID to pin/unpin
- **AssetName** (required) - Asset name for reference and validation
- **DeploymentClusterName** (required) - The deployment cluster name (resolved to a cluster ID via the local name cache file - see [Deployment Cluster Name Resolution](#deployment-cluster-name-resolution))

Example CSV:

```csv
AssetName,AssetId,DeploymentClusterName
Server-01,a:a:123456tn,Production Cluster
Server-02,a:a:abc123,Production Cluster
Server-03,a:a:def456,EU Cluster
```

## Deployment Cluster Name Resolution

All parameter sets that target a deployment cluster (`-AssetId`, `-OUPath`, `-TargetSubnet`, and CSV rows) take a `-DeploymentClusterName`/`DeploymentClusterName` value instead of a raw cluster ID. Names are resolved to cluster IDs using a local JSON cache file:

- The cache file is named `<envName>-DeploymentClusters.json`, where `envName` is derived from the `-PortalUrl` host (e.g. `https://mycompany-admin.zeronetworks.com` → `mycompany-admin-DeploymentClusters.json`).
- The cache file is stored **next to the script** (not the current working directory), and is a flat JSON object mapping cluster name to cluster ID.
- If the cache file doesn't exist, the script creates it automatically the first time it's needed - this happens on every run that has `-ApiKey`/`-PortalUrl` (i.e. every parameter set except `-ExportCsvTemplate`).
- The cache file is **not** refreshed automatically on every run. If a cluster is renamed or a new cluster is added, run `-ListDeploymentClusters` to refresh the cache file (it always overwrites the cache with fresh data from the API).
- If a supplied `-DeploymentClusterName` isn't found in the cache file, the script fails immediately with an error listing the known cluster names from the file.
- The cache file is gitignored (`*-DeploymentClusters.json`) since it contains tenant-specific cluster IDs and shouldn't be committed.

## Validation

The script performs comprehensive validation before making any changes:

### Asset Validation
- Asset must not be a segment server (segment servers cannot be pinned to deployment clusters)
- Asset must be monitored by a Segment Server (not Cloud Connector or Lightweight Agent)
- Asset must be healthy (unless `-SkipAssetHealthValidation` is used)
- Asset must be applicable to be pinned to a deployment cluster (An asset's deploymentSource attribute cannot be set to "Not Applicable")
- For pinning: Asset must not already be pinned to a deployment cluster
- For unpinning: Asset must already be pinned to a deployment cluster

### Deployment Cluster Validation
- Deployment cluster must exist in the tenant
- Deployment cluster must have at least one segment server assigned (unless `-SkipSegmentServerValidation` is used)
- At least one segment server must be online (unless `-SkipSegmentServerValidation` is used)

### Validation Error Handling

When processing multiple assets (via CSV or OU path), the script handles validation errors in two ways:

**Default Behavior (Continue on Error):**
- Assets that fail validation are logged as warnings
- The script continues processing and only operates on assets that passed validation
- A summary of failed validations is displayed at the end

**Stop on Error (`-StopOnAssetValidationError`):**
- If any asset fails validation, the script immediately stops and throws an error
- No assets are processed if validation fails for any asset
- Useful when you want to ensure all assets are valid before making any changes


## Dry Run Mode

Use the `-DryRun` switch to preview what changes would be made without actually applying them. In dry run mode:

- All validations are still performed
- The script shows what would be done
- The request body that would be sent is displayed
- No API calls are made to modify asset assignments


## Notes

- The script requires PowerShell 7.0 or higher
- API keys should be kept secure and not committed to version control
- Large operations may take time depending on the number of assets and network conditions
- The script uses `$ErrorActionPreference = "Stop"` to ensure errors are handled properly

## Troubleshooting

### "Deployment cluster name '...' not found in cache file '...'"
The cluster name doesn't match any entry in the local `<envName>-DeploymentClusters.json` cache file (the error message lists the known names). Run `-ListDeploymentClusters` to refresh the cache if the cluster was recently added or renamed, then double-check the spelling.

### "Asset is not monitored by a Segment Server"
The asset must be using a Segment Server, not Cloud Connector or Lightweight Agent.

### "Deployment cluster has no online segment servers"
Ensure at least one segment server in the deployment cluster is online. Use `-SkipSegmentServerValidation` to bypass this check if needed.

### "Asset is already pinned to a deployment cluster"
The asset is already pinned to a cluster. Use `-Unpin` first if you want to change the assignment.

### "Asset is a segment server"
Segment servers cannot be pinned to deployment clusters. The script automatically filters out segment servers when processing OUs or CSV files, but will show a warning for each one encountered.

### "Failed to validate X assets"
When processing multiple assets, some may fail validation. By default, the script continues processing and only operates on validated assets. Use `-StopOnAssetValidationError` if you want the script to stop when any asset fails validation.

### "Could not find OU: [OU Path]"
The OU path provided does not exist in Active Directory or cannot be found by the API. Verify the OU path format is correct (e.g., "OU=Computers,DC=domain,DC=com") and that the OU exists in your directory, and that the domain where the OU resides is being brought into Zero Networks.

