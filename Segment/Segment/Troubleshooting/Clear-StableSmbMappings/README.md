# Clear-StaleSmbArtifacts.ps1

## Why this exists

End users can get an unexpected MFA prompt for SMB (enforced by Zero Networks Network Segmentation) without actively opening a share. This happens because Windows silently re-establishes SMB connections to previously-used hosts through several independent client-side mechanisms:

1. Idle SMB client connections/sessions left open with no active file handles
2. Explorer's "restore previous folder windows" reopening a UNC-path window on logon/restart
3. Quick Access, Recent Items, Network Shortcuts, and jump list entries that reference a UNC path — any of which Explorer or a background process (search indexer, thumbnail generation, jump list refresh) can silently re-touch
4. Windows Search indexing a UNC location that was explicitly added to the index

Network Segmentation enforces at the network/driver layer, so it can't tell "user double-clicked a share" apart from "Explorer silently redialed a stale handle" — both look like a new SMB connection attempt and get gated with MFA.

This script addresses items **#1 and #3**. Items #2 and #4 are one-time registry/config changes, not something to run repeatedly — see `Registry-PersistBrowsers.md` and `Search-Indexing-Exclusion.md`.

## What it does

| Function | Mechanism addressed | Behavior |
|---|---|---|
| `Get-IdleSmbConnection` | #1 | Finds SMB connections with `NumOpens -eq 0` (no open file handles) and disconnects them via `net use /delete`. There's no native idle-timestamp API for the SMB client, so "no open handles" is used as the idle proxy. |
| `Get-SmbQuickAccessItem` | #3 | Enumerates Quick Access (pinned + recent) via the Shell namespace, filters to entries whose `Path` is a UNC path (`\\*`), and unpins/removes only those. |
| `Get-SmbShortcutTarget` | #3 | Resolves the real target of `.lnk` files under **Recent Items** and **Network Shortcuts**, filters to UNC targets, and deletes only the matching shortcut files. |
| `Get-SmbJumpListFile` | #3 | Scans `AutomaticDestinations`/`CustomDestinations` jump list files for embedded UNC path strings and deletes any file that matches. |
| Thumbnail cache clear | #3 | Always fully clears `thumbcache_*.db` — individual cache entries are keyed by a content hash, not a path, so there's no reliable way to filter this one to "SMB only." Stopping/restarting `explorer.exe` is required to release the file lock. |

Everything except the thumbnail cache clear only touches entries that resolve to a `\\server\share` path — local-path Quick Access pins, Recent items, and jump lists are left alone.

## Usage

```powershell
# Dry run — report what would be removed/disconnected, no changes made
.\Clear-StaleSmbArtifacts.ps1 -ReportOnly -Verbose

# Dry run via the standard PowerShell mechanism (equivalent effect)
.\Clear-StaleSmbArtifacts.ps1 -WhatIf

# Perform the cleanup
.\Clear-StaleSmbArtifacts.ps1 -Verbose

# Report-only run piped to a CSV for review before wider rollout
.\Clear-StaleSmbArtifacts.ps1 -ReportOnly | Export-Csv .\smb-cleanup-report.csv -NoTypeInformation
```

The script always emits a result object per action taken (or that would be taken), so you can pipe it to `Format-Table`, `Export-Csv`, or `Out-File` for logging.

## Scheduling

Because Quick Access, Recent Items, Network Shortcuts, jump lists, and the thumbnail cache all live under `HKCU` / `%APPDATA%` / `%LOCALAPPDATA%`, this **must run in the interactive user's context**, not as SYSTEM. A SYSTEM-context task cannot reach a logged-on user's profile artifacts without impersonation.

Recommended Task Scheduler setup:
- **Trigger:** On unlock, on workstation idle, or a recurring timer (e.g. every few hours) — not tied to logon alone, since the goal is also to catch idle connections accumulated during the day
- **Run as:** the logged-on user (not "Run whether user is logged on or not" / SYSTEM)
- **Run only when user is logged on:** yes
- **Action:** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Clear-StaleSmbArtifacts.ps1"` (drop `-ReportOnly` once validated)

## Caveats

- **Jump list cleanup is file-level, not entry-level.** Each `.ms` file bundles multiple entries for one application. A match means "this file references a UNC path somewhere inside it" — the whole file is removed, including any non-UNC entries for that app. This is a detection/removal-granularity limitation of the compound-file format, not a bug.
- **Thumbnail cache clearing is unconditional and disruptive.** It stops and restarts `explorer.exe`, which closes the user's open Explorer windows. This was confirmed acceptable for this use case, but don't schedule it so frequently that it becomes an annoyance.
- **Quick Access unpin verb can vary slightly across Windows builds.** The script tries `unpinfromhome` then `removefromhome` and logs a warning (non-fatal) if neither works for a given entry.
- **Idle connection detection uses `NumOpens -eq 0` as a proxy for "idle."** This is accurate for "no open file handles right now" but isn't a true last-used timestamp, since the SMB client doesn't expose one via PowerShell.

## Requirements

- Windows PowerShell 5.1+ (in-box `SmbShare` module cmdlets, no external modules required)
- Must run in the interactive user's session context
