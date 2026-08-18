# Disabling Explorer's "Restore previous folder windows"

## What this addresses

One of the ways Windows silently re-establishes an SMB connection with no active user action: if a File Explorer window was open and pointed at a UNC path (`\\server\share\...`) when the user last restarted or logged off, Windows can reopen that same window automatically at the next logon — which immediately triggers a fresh SMB connection attempt to that path, with no user click involved. Where Network Segmentation enforces MFA-on-access at the network layer, that silent reconnect looks identical to a real user-initiated connection and gets gated with an MFA prompt.

This is controlled by a single registry value, not something that needs periodic cleanup (unlike Quick Access/Recent/jump lists, which accumulate new entries over time — see `Clear-StaleSmbArtifacts.ps1` / `README.md`). Set it once and the reconnect vector is eliminated entirely, because there's no window state left to restore.

## The registry value

| | |
|---|---|
| **Hive/Key** | `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` |
| **Value name** | `PersistBrowsers` |
| **Type** | `REG_DWORD` |
| **Disabled (recommended)** | `0` |
| **Enabled (Windows default)** | `1` |
| **Scope** | Per-user (`HKCU`) |

This is the same setting exposed in the GUI as **File Explorer Options → View → Advanced settings → "Restore previous folder windows at logon"**.

## Why it's per-user (`HKCU`, not `HKLM`)

Explorer's window-restore state is tied to the logged-on user's shell session, so the setting — and the underlying window-state it governs — is per-user. There's no machine-wide (`HKLM`) equivalent value; centralized deployment has to land in each user's `HKCU` hive, which is exactly what Group Policy Preferences or a per-user logon script is for (see below).

## Setting it manually

```powershell
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
    -Name 'PersistBrowsers' -Value 0 -Type DWord
```

No reboot is required, but it won't retroactively close any already-open windows or purge any state that's already scheduled to restore this session — it takes effect starting at the *next* logon.

## Deploying via Group Policy

For fleet-wide rollout across the customer's environment:

1. **Group Policy Preferences (recommended)** — `User Configuration → Preferences → Windows Settings → Registry`, create a new registry item:
   - Hive: `HKEY_CURRENT_USER`
   - Key Path: `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
   - Value name: `PersistBrowsers`
   - Value type: `REG_DWORD`
   - Value data: `0`

2. **Administrative Templates** — there isn't a dedicated ADMX policy that maps directly to this specific value in stock Windows; GPP registry deployment (above) is the standard approach for this particular setting.

Because it's a `HKCU` value, GPP applies it per-user at the next Group Policy refresh/logon for each user in scope — no per-machine SYSTEM-context script needed.

## Why this fully closes the vector

Unlike Quick Access, Recent Items, and jump lists — which are *history* that keeps accumulating and needs periodic clearing — "restore previous folder windows" is a *behavior toggle*. With `PersistBrowsers = 0`, Windows never captures/restores that window state in the first place, so there's nothing to clean up after the fact. This is the one item of the four mechanisms discussed that's a permanent fix rather than an ongoing mitigation.
