# Create Custom Group From Asset Subnets

A PowerShell script that creates Zero Networks custom groups from a subnet-to-group-name CSV mapping and populates each group with every client/server asset whose last known IP address falls within the mapped subnet. Already-existing groups are reused (not recreated), and assets already in a group are skipped rather than re-added.

## Requirements

- **PowerShell 7.0 or higher**
- **Zero Networks API Key** with appropriate permissions, stored in a local `.env` file (see [Setup](#setup))

## Features

- Creates missing custom groups, or reuses existing ones with the same name
- Populates groups with client/server assets matched by last known IP address within a subnet (CIDR)
- Skips assets already in the target group instead of re-adding them
- Bulk operation via CSV file (subnet → custom group name mapping)
- Single-group re-run mode driven by a local JSON audit record, without needing the CSV (`-TargetGroupName`)
- Local JSON audit record of every group created/found, its subnet, and the assets assigned to it (see [Local JSON Record](#local-json-record))
- Console + timestamped log file output for every run (see [Logging](#logging))
- API key read from a local `.env` file - never passed on the command line or committed to source control
- Tenant portal URL automatically derived from the API key (no `-PortalUrl` parameter needed)
- Dry run mode to preview changes without applying them (`-DryRun`)
- Concurrent subnet asset resolution with tunable throttling (`-MaxConcurrentBatches`)
- Debug output mode (`-EnableDebug`) for troubleshooting

## Setup

### 1. Create your `.env` file
Copy `.env.example` to `.env` in this directory and fill in your Zero Networks API key:

```
ZN_API_KEY=your-api-key-here
```

The `.env` file is gitignored and should never be committed. The script derives the tenant portal URL automatically from this key (Zero Networks API keys are JWTs whose payload contains the tenant host).

### 2. Prepare your subnet mapping CSV
Create (or edit) `subnet-group-mappings.csv` with two columns: `Subnet` (IPv4 CIDR) and `Custom Group Name`.

```csv
Subnet,Custom Group Name
10.1.11.0/24,TEST-SERVERS-FLOOR
10.2.20.0/24,TEST-LINUX-FLOOR
```

## Script use cases

### 1. Process all mappings from a CSV (Default)
Creates/reuses each custom group listed in the CSV and populates it with matching client/server assets.

```powershell
.\New-CustomGroupsFromSubnets.ps1 -SubnetCsvPath .\subnet-group-mappings.csv
```

#### Supported Parameters
**Optional Parameters:**
- `-SubnetCsvPath` - Path to the subnet mapping CSV (default: `.\subnet-group-mappings.csv`)
- `-DryRun` - Preview changes without applying them
- `-MaxConcurrentBatches` - Maximum number of subnet-batch asset resolution requests to run concurrently (default: `5`, range: `1`-`20`)
- `-EnableDebug` - Enable debug output

### 2. Re-run against a single, already-known group
Re-processes one group by name, pulling its subnet from the local JSON record instead of the CSV. Useful for picking up newly-discovered assets in a subnet without re-reading the whole CSV.

```powershell
.\New-CustomGroupsFromSubnets.ps1 -TargetGroupName "TEST-SERVERS-FLOOR"
```

#### Supported Parameters
**Required Parameters:**
- `-TargetGroupName` - Name of the custom group to re-process (must already exist in the local JSON record - see [Local JSON Record](#local-json-record))

**Optional Parameters:**
- `-DryRun` - Preview changes without applying them
- `-MaxConcurrentBatches` - Maximum number of subnet-batch asset resolution requests to run concurrently (default: `5`, range: `1`-`20`)
- `-EnableDebug` - Enable debug output

## Usage Examples

### Process the default CSV
```powershell
.\New-CustomGroupsFromSubnets.ps1
```

### Process a custom CSV path
```powershell
.\New-CustomGroupsFromSubnets.ps1 -SubnetCsvPath ".\my-mappings.csv"
```

### Preview changes without applying them
```powershell
.\New-CustomGroupsFromSubnets.ps1 -DryRun
```

### Re-run against a single known group
```powershell
.\New-CustomGroupsFromSubnets.ps1 -TargetGroupName "TEST-SERVERS-FLOOR"
```

### Increase subnet-batch concurrency for large subnets
```powershell
.\New-CustomGroupsFromSubnets.ps1 -MaxConcurrentBatches 10
```

### Troubleshoot with debug output
```powershell
.\New-CustomGroupsFromSubnets.ps1 -DryRun -EnableDebug
```

## Which assets are added

Only monitored assets of `assetType` **Client** or **Server** whose last known IP address falls within the mapped subnet are considered. Other asset types (IP cameras, printers, routers, hypervisors, etc.) are never added, even if their IP falls in range.

**Subnet size limits** (same as the underlying subnet-expansion logic used elsewhere in this repo):
- Subnets larger than `/24` (more than 256 addresses) require interactive confirmation before proceeding, since resolution requires multiple batched API calls.
- Subnets larger than `/16` (more than 65,536 addresses) are rejected outright.

## Local JSON Record

Every run writes/updates a JSON record file next to the script, named `<envName>-CustomGroupSubnetRecord.json` (`envName` derived from the tenant host in the API key, e.g. `mycompany-admin-CustomGroupSubnetRecord.json`). It is updated after **each** group is processed, not just at the end, so a mid-run failure still leaves a usable partial record.

```json
{
  "TEST-SERVERS-FLOOR": {
    "groupId": "g:c:xxxxxxxx",
    "subnet": "10.1.11.0/24",
    "assetsAssigned": ["a:a:xxxxxxxx", "a:s:yyyyyyyy"],
    "lastUpdated": "2026-08-18T12:00:00Z"
  }
}
```

- `-TargetGroupName` reads this file to determine which subnet to (re-)process for a given group name, and fails with a clear error if the group isn't in the record yet.
- The record file is gitignored (`*-CustomGroupSubnetRecord.json`) since it's tenant-specific.

## Logging

Every run mirrors all console output to a timestamped log file at `logs\New-CustomGroupsFromSubnets_<yyyyMMdd-HHmmss>.log` (created next to the script). The `logs\` directory is gitignored. Use `-EnableDebug` to include verbose API/flow tracing in both the console and the log file.

## Dry Run Mode

Use the `-DryRun` switch to preview what changes would be made without actually applying them:

- Group existence is still checked, but missing groups are **not** created
- Matching assets are still discovered and checked against current group membership
- The request body that would be sent to add members is displayed, but no mutating API calls are made
- The local JSON record is still updated for groups that already exist, but not for groups that would only be created in a non-dry-run pass

## Notes

- The script requires PowerShell 7.0 or higher
- The API key is read from `.env` and is never accepted as a command-line parameter, so it never ends up in shell history
- The script uses `$ErrorActionPreference = "Stop"` to ensure errors are handled properly
- `Pin-AssetsToClusters.ps1` (this script's sibling reference for subnet-based asset discovery patterns) and `*.csv` files in this directory are gitignored, since they're local reference/input material rather than deliverables

## Troubleshooting

### "Could not find a .env file at '...'"
Create a `.env` file next to the script (copy `.env.example`) containing `ZN_API_KEY=<your api key>`.

### "'.env' file at '...' does not contain a ZN_API_KEY=<key> entry."
Check that your `.env` file has a line exactly in the form `ZN_API_KEY=<key>` (no quotes needed, blank lines and `#` comments are ignored).

### "ZN_API_KEY does not look like a valid JWT..."
The portal URL is derived from the API key itself. Double check the key was copied in full (JWTs have 3 dot-separated segments) and hasn't been truncated.

### "Group '...' was not found in the local record file..."
`-TargetGroupName` only works for groups this script has already processed at least once (via the CSV), since it reads the subnet mapping from the local JSON record rather than accepting one directly. Run against the CSV first to establish the mapping.

### "Subnet mapping CSV validation failed: ... is not a valid IPv4 CIDR subnet"
Check the `Subnet` column values are well-formed CIDR notation (e.g. `10.1.11.0/24`).
