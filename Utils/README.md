# Utils

Standalone utility scripts that complement the Zero Networks platform but don't fit cleanly under `Segment/`, `Connect/`, `TrustMeter/`, or `Detections/`.

## Contents

| Script | Purpose |
|---|---|
| [Find-CommonGroupsForDestination.ps1](Find-CommonGroupsForDestination.ps1) | Find the AD groups shared by users that accessed a given destination, to help build identity-based segmentation rules. |

---

## Find-CommonGroupsForDestination.ps1

Queries Zero Networks network activities for a destination asset (by IP or FQDN), collects the distinct source users that contacted it, retrieves each user's group memberships from the ZN directory, and writes a CSV listing every AD group shared by at least `MinUserCount` of those users.

The output is intended to help answer: *"Which AD group(s) should I scope this destination's access rule to?"*

### Requirements

- **PowerShell 5.1+** (Windows PowerShell or PowerShell 7)
- **[ZeroNetworks PowerShell module](https://www.powershellgallery.com/packages/ZeroNetworks)** (`#Requires -Module ZeroNetworks`)
- **Zero Networks API key** with permission to read network activities and the user directory

### Authentication

The script reads the API key from `$env:ZNApiKey`. Set it once per session using any of:

```powershell
Set-ZNApiKey -ApiKey '<api-key>'      # stores key in $env:ZNApiKey for the session
Connect-ZN    -Email  '<you@org>'     # interactive OTP login, populates $env:ZNApiKey
$env:ZNApiKey = '<api-key>'           # or set the env var directly
```

If `$env:ZNApiKey` is not set the script exits with an authentication error.

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-DestinationFQDN` | one of these | – | FQDN of the destination asset (managed asset or external domain). |
| `-DestinationIP`   | one of these | – | IPv4 address of the destination asset. |
| `-MinUserCount` | no | `2` | Minimum number of source users that must share a group for it to appear in the report. |
| `-FromDays` | no | `30` | How many days of activity history to scan (`1`–`365`). |
| `-OutputPath` | no | `./CommonGroups_<dest>_<timestamp>.csv` | Output CSV path. |
| `-IncludeSourceUsers` | no | off | Switch. Adds a `SourceUsers` column to the CSV listing the member display names per group. Off by default — groups containing thousands of users make the column very noisy. `SourceUserCount` is always present. |
| `-MaxParallel` | no | `8` | Max concurrent group-membership lookups (`1`–`16`). Used only on PowerShell 7+ and only once there are at least 20 resolved users to amortize runspace startup. Set to `1` to force sequential, lower if the tenant returns HTTP 429. Ignored on Windows PowerShell 5.1. |

`-DestinationFQDN` and `-DestinationIP` are mutually exclusive — supply exactly one. Running the script with neither prints usage and exits.

`-Verbose` and `-Debug` are honoured (`-Debug` is forced non-interactive). API tracing inside the ZN module is suppressed so the key isn't echoed to the console.

### How it works

1. Validates `$env:ZNApiKey` and decodes the JWT to derive the tenant base URL.
2. Builds a `_filters` query (`dstAsset` for FQDN, `dstIpAddress` for IP) scoped to the requested time window.
3. **Collects distinct source users** in one of two ways:
   - **Fast path (primary):** calls `/activities/network/distinctField/srcUser`, which returns the de-duplicated set of source users (with per-user hit counts) in a single request. This avoids paging through tens of thousands of activity rows on busy destinations.
   - **Fallback:** if the `distinctField` endpoint is unavailable (older tenant), the script pages `/activities/network` and de-duplicates client-side.
4. Pages through `Get-ZNUser` to build a SID → user and PrincipalName → user lookup, so activity SIDs that don't match ZN user IDs (e.g. Entra synthetic SIDs) can still be resolved.
5. **Resolves** each distinct source user against that lookup (SID first, then PrincipalName). If two source entries map to the same ZN user (case-variant `userName`, or multiple SIDs for one identity) the user is counted **once**. Unresolvable system/machine accounts are skipped and reported.
6. **Retrieves group memberships** for each resolved user:
   - On **PowerShell 7+** with ≥ 20 resolved users, the script fans out to `-MaxParallel` concurrent runspaces (default 8) calling `/users/{id}/ancestors` directly — this avoids the per-runspace cost of re-importing the ZN module.
   - On **Windows PowerShell 5.1**, on PS 7+ with fewer than 20 resolved users, or when `-MaxParallel 1` is supplied, the script runs sequentially via `Get-ZNUserMemberOf`.
   - All API calls (distinctField, activity pages, `Get-ZNUser`, membership lookups) are wrapped with retry + exponential backoff + jitter on transient failures (HTTP 429 / 5xx and transport errors). `Retry-After` headers are honoured.
7. Merges memberships into a group → users map (sequential, race-free), filters out groups below `-MinUserCount`, sorts by member count desc, writes the CSV, and prints the top 10 to the console.

### Output

The script writes a CSV with one row per qualifying group:

| Column | Always present? | Description |
|---|---|---|
| `GroupName` | yes | Display name of the AD group. |
| `GroupId` | yes | Zero Networks group ID. |
| `SourceUserCount` | yes | Number of source users (that accessed the destination) who are members. |
| `SourceUsers` | only with `-IncludeSourceUsers` | Semicolon-separated list of those user display names. |
| `Destination` | yes | The destination FQDN or IP that was queried. |
| `LookbackDays` | yes | The `-FromDays` value used for the run. |

A summary table (top 10 by `SourceUserCount`) is also printed to the console — it includes the `SourceUsers` column only when `-IncludeSourceUsers` is set.

### Usage

```powershell
# Authenticate once
Set-ZNApiKey -ApiKey '<api-key>'

# Find groups shared by >= 3 users that hit a file server in the last 7 days
.\Find-CommonGroupsForDestination.ps1 `
    -DestinationFQDN 'fileserver.corp.local' `
    -MinUserCount    3 `
    -FromDays        7

# Same, by IP, with an explicit output path
.\Find-CommonGroupsForDestination.ps1 `
    -DestinationIP '10.10.0.50' `
    -OutputPath    'C:\Reports\fileserver-groups.csv'

# Include the SourceUsers column (member display names per group)
.\Find-CommonGroupsForDestination.ps1 `
    -DestinationFQDN     'fileserver.corp.local' `
    -IncludeSourceUsers

# Throttle parallel membership lookups (e.g. tenant is rate-limiting on PS 7+)
.\Find-CommonGroupsForDestination.ps1 `
    -DestinationFQDN 'fileserver.corp.local' `
    -MaxParallel     2

# See the full PowerShell help (synopsis, parameters, examples)
Get-Help .\Find-CommonGroupsForDestination.ps1 -Full
```

### Notes & caveats

- The fast path (`distinctField/srcUser`) returns only `userName` (`DOMAIN\user`), so users are resolved by `PrincipalName`. The fallback activity-scan path also captures the SID and tries SID first. Either way, well-known/system/machine accounts (`SYSTEM`, `LOCAL SERVICE`, `*$`, etc.) won't resolve to a ZN user and are skipped — the count of unresolved users is reported.
- Only activities that include source-user information are considered. Service-to-service or agentless flows without a resolvable user contribute nothing to the report.
- If two source entries map to the same ZN user, the user is counted **once** per group (no double-counting from SID/name variants).
- The activity-feed fallback path uses cursor pagination at `_limit=400`; very long lookbacks on busy destinations will take longer and consume more API calls. The fast path is unaffected.
- Lower `-MinUserCount` to surface narrower groups, raise it to focus on broadly shared groups.
- `-IncludeSourceUsers` is off by default because the column is unbounded — a group of 10,000 users yields a single 10,000-entry semicolon-joined string per row. Turn it on for small groups or targeted investigations.
- If the tenant returns HTTP 429 (rate limiting), the built-in retry/backoff usually handles it transparently; if it persists, lower `-MaxParallel` (or set it to `1`).
