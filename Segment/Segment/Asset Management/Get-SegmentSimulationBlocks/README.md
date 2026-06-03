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
## Understanding output

Due to the complex nature of simulate segmentation results, it's difficult to provide a CSV export in this fashion that is **easily readable** (you can export the results per asset in the admin portal, but it's not the easiest to read, hence the tools existence).

So, the script prints out results for each asset, using a intendation and divider-based structured format, like below. Comments are included below to explain the structure of the output, and how to interept it.

```powershell
-------------------------------------------------------
# This is the asset these results pertain to
Segmentation Simulation Results for: CONTOSO-DC02 (a:a:Mn5Op6Qr)
# This is just a warning to let you know this asset is in indefinite learning
⚠️   Asset is set to indefinite Learning Mode!
-------------------------------------------------------
        # Each section below pertains to a particular destination port on the asset
        -------------------------------------------------------------------------
        # This is the port these results pertain to, along with asset information
        # Formatted so you know THIS/PORT --INTO--> THIS ASSET (ID)
        TCP/3389 --> CONTOSO-DC02 (a:a:Mn5Op6Qr)
        # How many times connections were made to this port
        Number of Occurences: 12
        # Timestamp of last connection to this port
        Last observed at: 2026-02-24T13:05:06.918-05:00
        # The process(es) which listen on this port, effectively
        Connections landed on local processes:
                 - c:\windows\system32\svchost.exe (termservice)
        =======================================================
        <#
         This section might have three sections
         - ALLOWED ASSETS (if -ShowAllowedConnections provided) - Assets that attempted to connect to this port and would be allowed post-segment
         - BLOCKED ASSETS - Assets that attempted to connect to this port and would be blocked post-segment
         - ASSETS PROMPTED FOR MFA - Assets that attmepted to connect to this port and would instead by prompted for MFA post-segment
        #>

        <# In this example, this asset attempted to connect to RDP 11 times over the time period, and after segmenting the destination asset (CONTOSO-DC02), would be prompted for MFA #>
        The following entities will be prompoted for MFA to connect to TCP/3389 after segmentation:
                ⚠️   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:TCP/3389 - Observed 11 times
        =======================================================
        -------------------------------------------------------------------------
        -------------------------------------------------------------------------
        TCP/139 --> CONTOSO-DC02 (a:a:Mn5Op6Qr)
        Number of Occurences: 11
        Last observed at: 2026-02-24T13:11:40.800-05:00
        Connections landed on local processes:
                 - system
        =======================================================
        # In this example, you can see that CONTOSO-JUMP01 would be BLOCKED from TCP/139 once this asset (CONTOSO-DC002) is segmented
        The following entities will be BLOCKED FROM CONNECTING to TCP/139 after segmentation:
                ❌   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:TCP/139 - Observed 11 times
        =======================================================
        -------------------------------------------------------------------------
        -------------------------------------------------------------------------
        TCP/5985 --> CONTOSO-DC02 (a:a:Mn5Op6Qr)
        Number of Occurences: 11
        Last observed at: 2026-02-24T13:13:27.481-05:00
        Connections landed on local processes:
                 - system
        =======================================================
        The following entities will be prompoted for MFA to connect to TCP/5985 after segmentation:
                ⚠️   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:TCP/5985 - Observed 11 times
        =======================================================
        -------------------------------------------------------------------------
        -------------------------------------------------------------------------
        UDP/5353 --> CONTOSO-DC02 (a:a:Mn5Op6Qr)
        Number of Occurences: 6
        Last observed at: 2026-02-24T13:01:27.672-05:00
        Connections landed on local processes:
                 - c:\windows\system32\svchost.exe (dnscache)
        =======================================================
        The following entities will be BLOCKED FROM CONNECTING to UDP/5353 after segmentation:
                ❌   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:UDP/5353 - Observed 6 times
        =======================================================
        -------------------------------------------------------------------------
        -------------------------------------------------------------------------
        UDP/137 --> CONTOSO-DC02 (a:a:Mn5Op6Qr)
        Number of Occurences: 6
        Last observed at: 2026-02-24T13:00:54.971-05:00
        Connections landed on local processes:
                 - system
        =======================================================
        The following entities will be BLOCKED FROM CONNECTING to UDP/137 after segmentation:
                ❌   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:UDP/137 - Observed 6 times
        =======================================================
        -------------------------------------------------------------------------
        -------------------------------------------------------------------------
        TCP/5357 --> CONTOSO-DC02 (a:a:Mn5Op6Qr)
        Number of Occurences: 6
        Last observed at: 2026-02-24T13:00:59.125-05:00
        Connections landed on local processes:
                 - system
        =======================================================
        The following entities will be BLOCKED FROM CONNECTING to TCP/5357 after segmentation:
                ❌   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:TCP/5357 - Observed 6 times
        =======================================================
        -------------------------------------------------------------------------
```