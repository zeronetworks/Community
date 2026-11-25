# Audit Unmonitored Sources

Find the devices that are talking to your important servers but are not yet monitored by Zero Networks.

Point the tool at a destination, such as a single server or a group of domain controllers, and pick a time window. It reads the network activity that Zero Networks recorded for that destination and reports every **unmonitored source** that connected to it: the source IP address, its FQDN when one is known, the destination, and the ports and protocols used. Use the results to decide which devices to add to the admin portal, and which rules you need before you start segmenting.

## Contents

- [What You Get](#what-you-get)
- [What Is an Unmonitored Source](#what-is-an-unmonitored-source)
- [Requirements](#requirements)
- [Setup](#setup)
- [Quick Start](#quick-start)
- [Parameters](#parameters)
- [Reading the Results](#reading-the-results)
- [Excluding Group Members](#excluding-group-members)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [Good to Know](#good-to-know)

## What You Get

Every run produces three outputs:

| Output | What it contains |
|---|---|
| **Console summary** | Key totals for the run and a table of the top source and destination pairs. |
| **Markdown report** | The run summary, an estimate of how much unmonitored traffic to expect over longer periods, and the top 50 source and destination pairs. |
| **CSV of raw activities** | Every unmonitored activity found, newest first, ready for a spreadsheet or your own analysis. |

## What Is an Unmonitored Source

Every network activity has a source and a destination. A source that Zero Networks manages carries asset information, such as its protection state and asset type. An **unmonitored source** is a device that appears in the traffic but has none of that information, because it has not been added to Zero Networks. For these sources, only the address details are known: IP address, port, and sometimes an FQDN.

The tool counts a source as unmonitored when its activity record has none of `assetSrc`, `networkProtectionState` or `assetType`. Activities that have no source IP are skipped.

## Requirements

- **Python 3.11 or later.**
- **[uv](https://docs.astral.sh/uv/getting-started/installation/).** The script is a self-contained `uv` script. `uv run` installs the dependencies for you, so there is no `pip install` step.
- **A Zero Networks API key** that can read network activities, assets and groups. To create one in the admin portal, navigate to Settings ⇒ Integrations ⇒ API.

## Setup

1. Copy the example settings file:

   ```bash
   cp .env.example .env
   ```

2. Open `.env` and set these values:

   | Variable | Description |
   |---|---|
   | `ZN_API_BASE_URL` | Your portal base URL, for example `https://<your-org>-admin.zeronetworks.com`. Do not add `/api/v1`. The script adds it. |
   | `ZN_API_KEY` | Your API key. It is sent in the `Authorization` header and is never written to the logs or the reports. |

The script reads `.env` from the folder you run it from. Keep this file private. It is already listed in `.gitignore`.

## Quick Start

Audit the last 7 days of traffic to a single asset:

```bash
uv run audit_unmonitored_sources.py --dstAssetId <asset-id>
```

Audit a group of assets over a specific window:

```bash
uv run audit_unmonitored_sources.py --dstGroupId <group-id> \
    --from 2026-11-17T00:00:00Z --to 2026-11-18T00:00:00Z
```

Asset IDs look like `a:a:gbd9haum` and group IDs look like `g:t:i0je8cz5`.

When the run finishes, the paths of the CSV and Markdown files are printed at the end of the output.

## Parameters

You must provide exactly one of `--dstAssetId` or `--dstGroupId`.

| Parameter | Required | Default | Description |
|---|---|---|---|
| `--dstAssetId <id>` | One of these | - | The destination asset to audit. Only activities sent to this asset are reported. Cannot be combined with `--dstGroupId`. |
| `--dstGroupId <id>` | One of these | - | The destination group to audit. Activities sent to any asset in the group are reported. Cannot be combined with `--dstAssetId`. |
| `--from <ISO 8601>` | No | 7 days before `--to` | Start of the time window, for example `2026-11-01T00:00:00Z`. Offsets such as `-05:00` are accepted. A timestamp with no offset is treated as UTC. |
| `--to <ISO 8601>` | No | Now (UTC) | End of the time window. Uses the same formats as `--from` and must be later than it. |
| `--excludeDstGroupAsSource` / `--no-excludeDstGroupAsSource` | No | On for groups | Leave out sources that are members of the destination group. See [Excluding Group Members](#excluding-group-members). |
| `--top <n>` | No | 50 | Number of pairs to print in the console. Use `0` to print all of them. This does not change the files. |
| `--outputDir <path>` | No | `./reports` | Folder for the CSV and Markdown files. It is created if it does not exist. |
| `--customHeader '<json>'` | No | - | Extra HTTP headers, as a JSON object, to send with every request. For example, `'{"myheader":"exampleheader"}'`. Values must be strings. |
| `--verbose` | No | Off | Show detailed logging, including request URLs and the names (never the values) of custom headers. |

### Quoting `--customHeader`

The JSON must reach the script as a single argument.

- **bash or zsh (macOS, Linux):** wrap the JSON in single quotes.

  ```bash
  uv run audit_unmonitored_sources.py --dstAssetId <asset-id> --customHeader '{"myheader":"exampleheader"}'
  ```

- **PowerShell:** wrap the JSON in single quotes and escape each inner double quote with a backslash.

  ```powershell
  uv run audit_unmonitored_sources.py --dstAssetId <asset-id> --customHeader '{\"myheader\":\"exampleheader\"}'
  ```

If the script reports that the header is not valid JSON, the quoting did not survive. Run again with `--verbose` to check the value.

## Reading the Results

### Console Output

While the run is in progress, the tool prints one line for each page of activities it retrieves. Each line shows the running total of activities retrieved, the time range the page covers, the number of unmonitored activities on that page, and the number of unique unmonitored sources found so far.

When it finishes, the tool prints a summary followed by the top pairs:

```
Target:                       Group - Domain Controllers - g:t:i0je8cz5
Group Member Count:           12
Window (UTC):                 2026-11-17 00:00:00 to 2026-11-24 00:00:00
Activities retrieved:         48210
Unmonitored activities:       731
Unique unmonitored sources:   14
Unique unmonitored src+dst:   22

#  SOURCE IP     SOURCE FQDN            DESTINATION       PORTS/PROTO         COUNT
-  ------------  ---------------------  ----------------  ------------------  -----
1  10.20.30.41   build07.example.com    dc01.example.com  389/TCP, 636/TCP    212
...
```

The values above are examples only.

| Line | Meaning |
|---|---|
| **Target** | The asset, or the group name and ID, that was audited. |
| **Group Member Count** | Shown for group targets only. It shows `not loaded` when you turned exclusion off, and `unavailable` when the member list could not be read. |
| **Window (UTC)** | The time window that was searched. |
| **Activities retrieved** | Every activity to the destination in the window, monitored or not. |
| **Unmonitored activities** | Activities whose source is unmonitored. |
| **Unique unmonitored sources** | Distinct unmonitored source IP addresses. |
| **Unique unmonitored src+dst** | Distinct pairs of source and destination. |

### Top Pairs

Each row in the table is one source IP address talking to one destination. The ports and protocols are listed for each pair but are not used to split it into separate rows, so a device that uses five ports to reach one server appears once.

- **Ports/Proto** lists each port and protocol the pair used, most frequent first. It shows up to 10, followed by `+N more`. A `?` means the activity had no port, which is typical for ICMP.
- **Count** is the number of activities for the pair.
- Rows are sorted by count, highest first. Ties are ordered by source IP address, then by destination.

### Markdown Report

The `.md` file has three sections:

1. **Summary.** The target, the window, the totals shown in the console, and, when exclusion is on, the group member counts and the number of activities that were excluded.
2. **Scale Estimates.** The number of unmonitored activities you can expect over 8 hours, 12 hours, 24 hours and 1 week. This is simple arithmetic: the count for your window is scaled up or down to each period. For example, 100 unmonitored activities in a 1-hour window gives 2,400 in 24 hours. Unique sources and pairs do not scale in a straight line, so they are not estimated. It is recommended to audit a window that represents normal business activity so that the estimates are meaningful.
3. **Top 50 Pairs.** The 50 busiest source and destination pairs, with ports, protocols, occurrence counts, and the first and last time each pair was seen. The table always shows 50 rows, regardless of `--top`.

### CSV of Raw Activities

The `_activities.csv` file has one row for every unmonitored activity found. Rows are ordered from newest to oldest and the file is UTF-8. The tool writes it while it retrieves data, so even very large audits use little memory.

| Column | Description |
|---|---|
| `timestamp_utc` | When the activity happened (UTC, ISO 8601). |
| `timestamp_ms` | The same time, in epoch milliseconds. |
| `source_ip` | IP address of the unmonitored source. |
| `source_fqdn` | FQDN of the source. Blank when none was reported. |
| `source_port` | Source port. |
| `destination_asset` | Destination FQDN, or IP address when there is no FQDN. |
| `destination_asset_id` | Destination asset ID. |
| `destination_ip` | Destination IP address. |
| `destination_port` | Destination port. |
| `protocol` | `TCP`, `UDP` or `ICMP`. Other protocols show their protocol number. |
| `raw_json` | The complete original activity as JSON, so no field is lost. |

### File Names

Both files are created on every run, even when no unmonitored sources are found:

```
reports/unmonitored-sources_<asset|group>-<id>_<UTC timestamp>_activities.csv
reports/unmonitored-sources_<asset|group>-<id>_<UTC timestamp>.md
```

## Excluding Group Members

When you audit a destination group, members of that group often talk to each other. For example, domain controllers replicate with one another. That traffic is not what you are looking for, so the tool leaves out any source that is itself a member of the destination group.

This is **on by default** when you use `--dstGroupId`. To include group members as sources, add `--no-excludeDstGroupAsSource`.

How it works:

1. Before retrieving activities, the tool loads the members of the group, including members of nested groups and inactive members.
2. A source is excluded when it matches a member by asset ID, IP address, or FQDN. FQDNs are compared without regard to case.
3. Excluded activities are not counted as unmonitored. The Markdown summary reports them separately as **Excluded (dst group members)**.

If the member list cannot be loaded, the tool prints a warning and completes the audit **without** excluding members, and the console shows `Group Member Count: unavailable`. If you passed `--excludeDstGroupAsSource` yourself, the tool stops with an error instead, so you never receive a report that includes members you asked to exclude.

Exclusion applies to group targets only. With `--dstAssetId` there is no group, so nothing is excluded, and passing `--excludeDstGroupAsSource` is an error.

## Usage Examples

Audit the last 7 days (the default) for one asset:

```bash
uv run audit_unmonitored_sources.py --dstAssetId <asset-id>
```

Audit a specific week for a group, and print every pair to the console:

```bash
uv run audit_unmonitored_sources.py --dstGroupId <group-id> \
    --from 2026-11-01T00:00:00Z --to 2026-11-08T00:00:00Z \
    --top 0
```

Audit a business-hours window in US Eastern time (UTC-5):

```bash
uv run audit_unmonitored_sources.py --dstGroupId <group-id> \
    --from 2026-11-19T09:00:00-05:00 --to 2026-11-19T12:00:00-05:00
```

Include the group's own members as sources:

```bash
uv run audit_unmonitored_sources.py --dstGroupId <group-id> --no-excludeDstGroupAsSource
```

Write the reports to a custom folder and send an extra header with every request:

```bash
uv run audit_unmonitored_sources.py --dstAssetId <asset-id> \
    --outputDir ./audit-output \
    --customHeader '{"myheader":"exampleheader"}' \
    --verbose
```

## Troubleshooting

| Symptom | What to check |
|---|---|
| The run ends with an error about `.env` or the API key | Confirm that `ZN_API_BASE_URL` and `ZN_API_KEY` are set in the `.env` file in the folder you run the script from. |
| `Destination asset not found` | Check the asset ID. Asset IDs look like `a:a:gbd9haum`. |
| Zero unmonitored sources, but you expected some | Widen the time window. Also check the **Activities retrieved** total. If it is `0`, no traffic to this destination was recorded in the window. |
| `Continuing WITHOUT excluding group members` | The group's member list could not be read. The report still completes but includes group members as sources. Run again with `--verbose` and review the error. |
| The group shows as `Group - <id>` with no name | The group name could not be looked up. The audit results are not affected. |
| The header is reported as not valid JSON | See [Quoting `--customHeader`](#quoting---customheader). |
| The run is slow | A long window on a busy destination means many pages of activities. Start with a narrow window and widen it if needed. |

## Good to Know

- **Default window.** Without `--from` and `--to`, the tool audits the last 7 days.
- **Activity retention.** The tool can only report activity that the portal still holds. Activity older than your retention period does not appear, even inside the window you request.
- **Group targets.** `--dstGroupId` covers traffic to assets that belong to the group. Destinations outside the group are not included.
- **Spreadsheet safety.** FQDNs come from network data. Any CSV cell that begins with `=`, `+`, `-` or `@` is prefixed with a single quote so a spreadsheet does not run it as a formula. The Markdown report escapes `|` characters in cells.
- **Exit codes.** `0` means the run completed, including runs that found no unmonitored sources. `1` means a configuration, API or usage error, such as a missing `.env` value, an unknown asset ID, or `--from` later than `--to`. `2` means an invalid command line, such as giving both or neither of `--dstAssetId` and `--dstGroupId`.
