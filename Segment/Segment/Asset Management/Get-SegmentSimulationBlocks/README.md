# Get-SegmentSimulationBlocks

## Overview

`Get-SegmentSimulationBlocks.ps1` simulates what would happen to observed network traffic if assets currently in **Learning Mode** were segmented today. For each asset and each observed port/protocol combination, the script reports which source entities would be:

- **MFA Prompted** — prompted for MFA before allowing connection
- **Blocked** — outright blocked - source will not be able to connect to port

*The script can report on **Allowed** source entities if the **-ShowAllowedConnections** parameter is provided*

This helps identify gaps in segmentation rules before an asset is moved out of Learning Mode, so that legitimate traffic isn't inadvertently blocked.

## Requirements

- PowerShell 5.1 or later
- [Zero Networks PowerShell Module](https://github.com/zeronetworks/zero-powershell) installed (`Install-Module ZeroNetworks`)
- A Zero Networks API key (RO should work)

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-ApiKey` | Yes | — | Zero Networks API key (JWT). Used to authenticate and to derive the tenant's API base URL. |
| `-AssetId` | Yes (ByAssetId set) | — | ID of a single asset to simulate (e.g. `a:a:XXXXXXXX`). Cannot combine parameter with `-CsvFilePath`. |
| `-CsvFilePath` | No (ByCsvImport set) | — | Path to a CSV file with columns `Asset Id` and `Name` (obtained via export from admin portal). Runs the simulation against the listed assets. Cannot combine parameter with `-AssetId`. |
| `-From` | No | 7 days ago | ISO 8601 timestamp defining the start of the traffic observation window (e.g. `"2025-01-01T00:00:00Z"`). Only traffic observed after this time is considered. |
| `-Direction` | No | `Incoming` | Direction of traffic to simulate. Accepted values: `Incoming`, `Outgoing`. |
| `-TrafficType` | No | `Both` | Scope of traffic to evaluate. Accepted values: `Both`, `Internal`, `External`. |
| `-SkipLearningFilter` | No | `$false` | By default, only assets currently in Learning Mode are retrieved. Specify this switch to include all assets regardless of protection status. |
| `-IgnorePendingRules` | No | `$false` | When specified, pending (unapproved) rules are excluded from the simulation and will not count as covering traffic. |
| `-ShowDisabledRules` | No | `$false` | When specified, disabled rules are included in the simulation and may cover traffic that would otherwise be blocked. |
| `-ShowAllowedConnections` | No | `$false` | By default, port/protocol entries where all observed traffic would be allowed are suppressed. Set to `$true` to display them. |

## Examples

### All assets in Learning Mode

Runs the simulation against every asset currently in Learning Mode, using the default 7-day traffic lookback window and evaluating incoming traffic from both internal and external sources.

```powershell
.\Get-SegmentSimulationBlocks.ps1 -ApiKey "<your-api-key>"
```

### Single asset by ID

Runs the simulation for a specific asset, evaluating outgoing traffic observed since January 1, 2025, and displaying connections that would be allowed in addition to those that would be blocked.

```powershell
.\Get-SegmentSimulationBlocks.ps1 `
    -ApiKey "<your-api-key>" `
    -AssetId "a:a:XXXXXXXX" `
    -Direction Outgoing `
    -From "2025-01-01T00:00:00Z" `
    -ShowAllowedConnections $true
```

### Assets from a CSV file

Runs the simulation against a specific list of assets defined in a CSV file. The CSV must have `Asset Id` and `Name` columns (with a header row).

```powershell
.\Get-SegmentSimulationBlocks.ps1 `
    -ApiKey "<your-api-key>" `
    -CsvFilePath ".\assets.csv"
```

## Debugging

The script uses PowerShell's standard `-Debug` common parameter (available because of `[CmdletBinding()]`). When `-Debug` is provided, additional diagnostic output is written for:

- **API call failures** — the full request URI, HTTP method, request body, response status code, and error message are printed when `Invoke-ZeroNetworksApiCall` catches an exception. Without `-Debug`, the error is surfaced only as a short message.
- **Assets with no results** — assets that return zero simulation results are noted (otherwise silently skipped).

```powershell
.\Get-SegmentSimulationBlocks.ps1 -ApiKey "<your-api-key>" -AssetId "a:a:XXXXXXXX" -Debug
```
