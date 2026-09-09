# Get-SegmentSimulationBlocks

## Overview

`Get-SegmentSimulationBlocks.ps1` simulates what would happen to observed network traffic if assets currently in **Learning Mode** were segmented today. For each asset and each observed port/protocol combination, the script reports which entities would be:

- **MFA Prompted** — prompted for MFA before allowing connection
- **Blocked** — outright blocked and unable to connect
- **Excluded** — excluded from blocking via an existing Access Exception rule (always shown when present)

*The script can also report on **Allowed** entities if the **-ShowAllowedConnections** parameter is provided, and on entities classified as **benign** traffic if the **-IncludeBenign** switch is provided*

Whether an entity is a **source** or a **destination** depends on **-Direction**: for `Incoming` (the default), entities are the sources connecting into the asset; for `Outgoing`, entities are the destinations the asset connects out to. The script's output wording and connection arrows adjust automatically based on `-Direction`. Pass `-Direction Both` to run both simulations for every asset and see the complete picture — incoming and outgoing exposure — in one unified per-asset report.

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
| `-Direction` | No | `Incoming` | Direction of traffic to simulate. Accepted values: `Incoming`, `Outgoing`, `Both`. `Both` runs both simulations per asset and renders them as two labeled sub-sections ("Incoming Traffic" / "Outgoing Traffic") within one unified per-asset block. |
| `-TrafficType` | No | `Both` | Scope of traffic to evaluate. Accepted values: `Both`, `Internal`, `External`. |
| `-SkipLearningFilter` | No | `$false` | By default, only assets currently in Learning Mode are retrieved. Specify this switch to include all assets regardless of protection status. |
| `-IgnorePendingRules` | No | `$false` | When specified, pending (unapproved) rules are excluded from the simulation and will not count as covering traffic. |
| `-ShowDisabledRules` | No | `$false` | When specified, disabled rules are included in the simulation and may cover traffic that would otherwise be blocked. |
| `-ShowAllowedConnections` | No | `$false` | By default, port/protocol entries where all observed traffic would be allowed are suppressed. Set to `$true` to display them. |
| `-IncludeBenign` | No | `$false` | By default, entities whose traffic is classified as benign by the API are suppressed. Specify this switch to display them. |
| `-PortalUrlOverride` | No | — (derived from `-ApiKey`) | Overrides the API base host normally derived from the `aud` claim of the JWT (e.g. `"portal.zeronetworks.com"`). Useful for pointing the script at a different environment than the one embedded in the API key. |
| `-CustomHeader` | No | — | Hashtable of additional HTTP headers to send with the script's direct REST API calls (e.g. `@{ "zn-env-id" = "<envId>" }`). Merged into the default headers; can add new headers or override `Authorization`/`Content-Type`. |

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

### Single asset, both directions

Runs the simulation for a specific asset in both directions, showing everything that would connect into it AND everything it connects out to, in one unified report.

```powershell
.\Get-SegmentSimulationBlocks.ps1 `
    -ApiKey "<your-api-key>" `
    -AssetId "a:a:XXXXXXXX" `
    -Direction Both
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
         This section might have up to five sub-sections:
         - ALLOWED (if -ShowAllowedConnections provided) - entities that attempted to connect to this port and would be allowed post-segment
         - PROMPTED FOR MFA - entities that attempted to connect to this port and would instead be prompted for MFA post-segment
         - BLOCKED - entities that attempted to connect to this port and would be blocked post-segment
         - EXCLUDED (always shown when present) - entities excluded from blocking via an existing Access Exception rule
         - BENIGN (if -IncludeBenign provided) - entities whose traffic to this port is classified as benign and would not be blocked
        #>

        <# In this example, this asset attempted to connect to RDP 11 times over the time period, and after segmenting the destination asset (CONTOSO-DC02), would be prompted for MFA #>
        The following sources will be prompoted for MFA to connect to CONTOSO-DC02 on TCP/3389 after segmentation:
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
        The following sources will be BLOCKED FROM CONNECTING to CONTOSO-DC02 on TCP/139 after segmentation:
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
        The following sources will be prompoted for MFA to connect to CONTOSO-DC02 on TCP/5985 after segmentation:
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
        The following sources will be BLOCKED FROM CONNECTING to CONTOSO-DC02 on UDP/5353 after segmentation:
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
        The following sources will be BLOCKED FROM CONNECTING to CONTOSO-DC02 on UDP/137 after segmentation:
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
        The following sources will be BLOCKED FROM CONNECTING to CONTOSO-DC02 on TCP/5357 after segmentation:
                ❌   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:TCP/5357 - Observed 6 times
        =======================================================
        -------------------------------------------------------------------------
```

With `-Direction Outgoing`, the same asset is now the one initiating connections, so entities are **destinations** and the wording/arrows flip accordingly:

```powershell
        -------------------------------------------------------------------------
        # Formatted so you know THIS ASSET (ID) --OUT TO--> THIS/PORT
        CONTOSO-DC02 (a:a:Mn5Op6Qr) --> TCP/445
        Number of Occurences: 4
        Last observed at: 2026-02-24T13:20:11.203-05:00
        =======================================================
        # CONTOSO-DC02 is the one connecting out, so CONTOSO-FS01 is the destination
        CONTOSO-DC02 will be BLOCKED FROM CONNECTING to the following destinations on TCP/445 after segmentation:
                ❌   - CONTOSO-DC02 --> CONTOSO-FS01 (a:a:Zx9Yw8Vu):TCP/445 - Observed 4 times
        =======================================================
        -------------------------------------------------------------------------
```

With `-Direction Both`, each asset's block contains both directions, grouped into labeled sub-sections — Incoming first, then Outgoing:

```powershell
-------------------------------------------------------
Segmentation Simulation Results for: CONTOSO-DC02 (a:a:Mn5Op6Qr)
⚠️   Asset is set to indefinite Learning Mode!
-------------------------------------------------------
====================
Incoming Traffic
====================
        -------------------------------------------------------------------------
        TCP/139 --> CONTOSO-DC02 (a:a:Mn5Op6Qr)
        Number of Occurences: 11
        Last observed at: 2026-02-24T13:11:40.800-05:00
        =======================================================
        The following sources will be BLOCKED FROM CONNECTING to CONTOSO-DC02 on TCP/139 after segmentation:
                ❌   - CONTOSO-JUMP01 (a:a:Kl3Mn4Op) --> CONTOSO-DC02:TCP/139 - Observed 11 times
        =======================================================
        -------------------------------------------------------------------------
====================
Outgoing Traffic
====================
        -------------------------------------------------------------------------
        CONTOSO-DC02 (a:a:Mn5Op6Qr) --> TCP/445
        Number of Occurences: 4
        Last observed at: 2026-02-24T13:20:11.203-05:00
        =======================================================
        CONTOSO-DC02 will be BLOCKED FROM CONNECTING to the following destinations on TCP/445 after segmentation:
                ❌   - CONTOSO-DC02 --> CONTOSO-FS01 (a:a:Zx9Yw8Vu):TCP/445 - Observed 4 times
        =======================================================
        -------------------------------------------------------------------------
```