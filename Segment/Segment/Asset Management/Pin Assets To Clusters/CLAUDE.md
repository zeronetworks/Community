# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a standalone PowerShell 7+ utility, `Pin-AssetsToClusters.ps1`, that pins/unpins Zero Networks Segment assets to deployment clusters via the Zero Networks REST API (`/api/v1`). It is one script in a much larger multi-project monorepo (`Community`); treat this directory as its own self-contained unit — there is no shared build system, package manifest, or test runner across the monorepo.

There are no automated tests, linter config, or build step in this project. Validation is done by running the script directly (see below).

## Running the script

```powershell
# List deployment clusters (also initializes cluster/segment-server lookups, and refreshes the name cache file)
./Pin-AssetsToClusters.ps1 -ApiKey <key> -PortalUrl https://<tenant>-admin.zeronetworks.com -ListDeploymentClusters

# Export a CSV template for bulk operations
./Pin-AssetsToClusters.ps1 -ExportCsvTemplate

# Pin/unpin a single asset (-DryRun previews without calling the mutation API)
./Pin-AssetsToClusters.ps1 -ApiKey <key> -AssetId <assetId> -DeploymentClusterName <clusterName> [-Unpin] [-DryRun] [-EnableDebug]

# Bulk via CSV or AD OU path
./Pin-AssetsToClusters.ps1 -ApiKey <key> -CsvPath ./assets.csv [-Unpin] [-DryRun]
./Pin-AssetsToClusters.ps1 -ApiKey <key> -OUPath "OU=Computers,DC=domain,DC=com" -DeploymentClusterName <clusterName> [-DisableNestedOuResolution] [-StopOnAssetValidationError]

# Bulk via IPv4 subnet (CIDR)
./Pin-AssetsToClusters.ps1 -ApiKey <key> -TargetSubnet "10.200.200.0/24" -DeploymentClusterName <clusterName> [-Unpin] [-DryRun] [-StopOnAssetValidationError]
```

`-EnableDebug` sets `$DebugPreference = "Continue"` for verbose API/flow tracing. There is no `-WhatIf`/Pester test suite — use `-DryRun` against a real (or test) tenant to validate changes before committing.

All parameter sets that target a cluster take `-DeploymentClusterName`/a CSV `DeploymentClusterName` column, not a raw cluster ID — `-DeploymentClusterId` was removed entirely. Names are resolved to IDs via a local `<envName>-DeploymentClusters.json` cache file kept next to the script (`$PSScriptRoot`), where `envName` is derived from the `-PortalUrl` host. See `Resolve-DeploymentClusterName` and `Initialize-DeploymentClusterCache` below.

## Architecture

Single-file script driven by a `[CmdletBinding]` parameter-set switch (`ByAssetId`, `ByOuPath`, `ByCsvPath`, `ByTargetSubnet`, `ListDeploymentClusters`, `ExportCsvTemplate`). The final `switch ($PSCmdlet.ParameterSetName)` block at the bottom of the file is the entry point — read it first to see how each mode wires the helper functions together.

Key flow shared by all mutating parameter sets:
1. `Initialize-ApiContext` — sets script-scoped `$script:Headers` / `$script:ApiBaseUrl` from `-ApiKey` / `-PortalUrl`, then calls `Initialize-DeploymentClusterCache` to ensure the local name cache file exists (creates it from the API if missing; does not refresh an existing one).
2. `Resolve-DeploymentClusterName` → `Invoke-ValidateDeploymentClusterId` — resolves the user-supplied `-DeploymentClusterName` to a cluster ID via the cache file (throws immediately, listing known names, on a cache miss), then validates that ID exists and has an online segment server via `Get-DeploymentClusters` (lazily populates `$script:DeploymentClusterHashtable` and `$script:SegmentServerHashtable`, keyed by cluster ID and segment-server asset ID respectively, for O(1) lookups used throughout validation). Everything downstream of this step (batching/pinning functions) still operates on the resolved cluster ID, not the name.
3. Asset resolution differs per mode: `Get-AssetDetails` (single asset), `Get-OUInfoFromApi` + `Get-AssetsFromOU` (OU mode), `Get-CsvData` (CSV mode, normalizes CSV rows into the same shape as API asset objects so downstream code is mode-agnostic), or `Get-SubnetHostAddresses` + `Get-AssetsByHostAddresses` (subnet mode, expands a CIDR range into host addresses and resolves them to monitored assets via a `lastIpAddress` filter).
4. `Test-AssetCanBePinned` / `Test-ValidateProvidedAssetsCanBePinned` — enforces the pin/unpin prerequisites (not a segment server, monitored by Segment Server, healthy, applicable, correct current pin state). Validation order matters — see comments in `Test-AssetCanBePinned`.
5. `Invoke-BatchBasedClusterPinning` → `Set-AssetsToDeploymentCluster` — batches assets in groups of 50 and calls the `PUT /assets/actions/deployments-cluster` endpoint (or prints the would-be request body under `-DryRun`).

API plumbing: `Invoke-ApiRequest` (single request + status-code validation via `Test-ApiResponseStatusCode`) is wrapped by `Invoke-PaginatedApiRequest`, which transparently follows both cursor-based (`nextCursor`) and offset-based (`nextOffset`/`count`) pagination and merges `items` across pages.

`$script:DeploymentClusterFieldMappings` (near the top of the script) decodes numeric enum codes returned by the API (cluster strategy, deployment status/state, service IDs) into human-readable strings via `Invoke-DecodeDeploymentClusterIDFields`. Note: `DeploymentClusterFieldMappings.json` in this directory holds the same mapping data as a standalone reference file but is not read by the script — the script keeps its own inline copy in `$script:DeploymentClusterFieldMappings`. If one is updated, update the other to keep them in sync.

`deploymentsClusterSource` on an asset (values 0–6) is the key field driving pin-state validation — see the block comment above `$AssetIsPinnedDeploymentClusterSource` in `Test-AssetCanBePinned` for the meaning of each code.

**Deployment cluster name resolution:** `Get-DeploymentClusterCachePath` derives `$envName` from the `-PortalUrl` host (stripping a trailing `.zeronetworks.com`) and returns `$PSScriptRoot/<envName>-DeploymentClusters.json`. `Save-DeploymentClusterCache` writes a flat `name -> id` JSON map to that path from a `Get-DeploymentClusters` result. `Initialize-DeploymentClusterCache` (called from `Initialize-ApiContext`) creates the file only if it's missing — it does not refresh an existing file. `Resolve-DeploymentClusterName` reads the cache file and resolves a name to an ID, throwing (and listing known names) on a miss. The `ListDeploymentClusters` parameter set is the one exception that always overwrites the cache via `Save-DeploymentClusterCache` after its own `Get-DeploymentClusters` call, since it already fetches fresh data — this is the documented way to refresh the cache after clusters are added/renamed. The cache file (`*-DeploymentClusters.json`) is gitignored.

### Per-Parameter-Set Workflow Sequences

The bottom-of-file `switch ($PSCmdlet.ParameterSetName)` block dispatches to one of these sequences. Each is self-contained — read the relevant `case` directly for exact call order.

**`ByAssetId`** (single asset, no batching):
1. `Initialize-ApiContext`
2. `Resolve-DeploymentClusterName` resolves `-DeploymentClusterName` to a cluster ID (local var `$DeploymentClusterId`), then `Invoke-ValidateDeploymentClusterId` validates that ID exists (and has an online segment server, unless `-SkipSegmentServerValidation`).
3. `Test-AssetCanBePinned` — validates the single asset directly (not via `Test-ValidateProvidedAssetsCanBePinned`, since there's only one asset and no need to continue-on-error across a list).
4. Wraps `-AssetId` in a one-element `PSCustomObject` ArrayList.
5. `Set-AssetsToDeploymentCluster` is called directly — `Invoke-BatchBasedClusterPinning` is skipped because a single asset never needs batching.

**`ByOuPath`** (bulk via AD OU, single cluster):
1. `Initialize-ApiContext`
2. `Resolve-DeploymentClusterName` resolves `-DeploymentClusterName` to a cluster ID, then `Invoke-ValidateDeploymentClusterId` for that ID.
3. `Get-OUInfoFromApi` — resolves `-OUPath` to an OU entity ID.
4. `Get-AssetsFromOU` — fetches OU members (nested, unless `-DisableNestedOuResolution`), filters to assets only, wrapped in `[System.Collections.ArrayList]@(...)` to guard against PowerShell unwrapping single-item results.
5. `Test-ValidateProvidedAssetsCanBePinned` — validates the whole asset list at once, honoring `-StopOnAssetValidationError`.
6. `Invoke-BatchBasedClusterPinning` → `Set-AssetsToDeploymentCluster` in batches of 50, all against the single validated cluster.

**`ByTargetSubnet`** (bulk via IPv4 CIDR subnet, single cluster):
1. `Initialize-ApiContext`
2. `Resolve-DeploymentClusterName` resolves `-DeploymentClusterName` to a cluster ID, then `Invoke-ValidateDeploymentClusterId` for that ID.
3. `Get-SubnetHostAddresses` — expands `-TargetSubnet` into every individual host address in the range (including network/broadcast addresses). Warns and requires interactive confirmation above /24 (256 addresses), and hard-stops above /16 (65,536 addresses).
4. `Get-AssetsByHostAddresses` — queries `/assets/monitored` in batches of `$script:SUBNET_BATCH_SIZE` (default 100, not a script parameter) using a `lastIpAddress` filter. Batches run concurrently via `ForEach-Object -Parallel`, up to `-MaxConcurrentBatches` (default 5; set to 1 for sequential behavior) — results are merged into a single list after the parallel block completes (empty batches are expected, not an error). `Invoke-ApiRequest` retries up to 3 times with exponential backoff on HTTP 429 to absorb any rate limiting the added concurrency triggers.
5. `Test-ValidateProvidedAssetsCanBePinned` — validates the whole asset list at once, honoring `-StopOnAssetValidationError`. Assets from `/assets/monitored` already carry `.id`/`.name` in the shape expected, so no normalization step is needed (unlike `ByCsvPath`).
6. `Invoke-BatchBasedClusterPinning` → `Set-AssetsToDeploymentCluster` in batches of 50, all against the single validated cluster.

**`ByCsvPath`** (bulk via CSV, potentially multiple clusters):
1. `Initialize-ApiContext`
2. `Get-CsvData` — reads and validates the CSV (required columns, non-empty rows). The cluster column is `DeploymentClusterName`, not an ID.
3. Extracts the **unique** `DeploymentClusterName` values present in the CSV, resolves each via `Resolve-DeploymentClusterName`, and runs `Invoke-ValidateDeploymentClusterId` once per resolved cluster ID (not once per row) — building a `$ClusterNameToIdMap` hashtable along the way.
4. CSV rows are normalized into asset-shaped `PSCustomObject`s (`id`, `name`, `DeploymentClusterId`) using `$ClusterNameToIdMap` to look up each row's resolved ID, so downstream validation/pinning functions are mode-agnostic with the OU/AssetId paths (they still key off `DeploymentClusterId`, never the name).
5. `Test-ValidateProvidedAssetsCanBePinned` validates the full normalized asset list in one pass (across all clusters at once), honoring `-StopOnAssetValidationError`.
6. For each unique resolved cluster ID (`$ClusterNameToIdMap.Values`), the validated assets are filtered by `DeploymentClusterId` and passed to `Invoke-BatchBasedClusterPinning` → `Set-AssetsToDeploymentCluster` (batches of 50) — so each cluster gets its own batched mutation call(s).

## Coding Standards

### Function Documentation

Every function written must include a powershell block comment proceeding it, documenting the function. The comment should include a .SYNOPSIS, .PARAMETER (for every parameter), .OUTPUTS, .NOTES.

For example:
```powershell
<#
.SYNOPSIS
    Retrieves detailed information about an asset from the Zero Networks API.
.PARAMETER AssetId
    The asset ID to retrieve details for.
.OUTPUTS
    Returns the asset entity object from the API response.
.NOTES
    Throws an exception if the asset is not found or if the API response is malformed.
#>
```
### Git Commit Message

Every git commit message must follow the widely practiced **Conventional Commits** guidelines. Invoke the `/conventional-commits` skill.
