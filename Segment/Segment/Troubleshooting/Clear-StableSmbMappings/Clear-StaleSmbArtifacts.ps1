<#
.SYNOPSIS
    Disconnects idle SMB client connections and removes Explorer artifacts
    (Quick Access, Recent items, Network Shortcuts, jump lists) that point
    at SMB/UNC paths, plus a full thumbnail cache clear.

.DESCRIPTION
    Windows silently re-establishes SMB connections to previously-used hosts
    through several client-side mechanisms: idle SMB sessions with no open
    handles, pinned/recent Quick Access entries, Recent Items and Network
    Shortcuts shortcuts, and jump list history — all of which can cause a
    background SMB connection attempt with no active user action. Where
    Network Segmentation enforces MFA-on-access, that background reconnect
    is indistinguishable from a real user-initiated connection and triggers
    a prompt the user didn't expect.

    This script finds and removes only the entries that target an SMB/UNC
    path (\\server\share), leaving local-path entries untouched. Thumbnail
    cache is cleared in full, since individual cache entries cannot be
    reliably mapped back to a source path.

    Must be run in the interactive user's context (not SYSTEM) because
    Quick Access, Recent Items, Network Shortcuts, jump lists, and the
    thumbnail cache all live under HKCU / %APPDATA% / %LOCALAPPDATA%.

.PARAMETER ReportOnly
    List what would be disconnected/removed without making any changes.
    This is the default-safe way to run the script; combine with -Verbose
    for a detailed console trace, or redirect output to a file for logging
    from a scheduled task.

.EXAMPLE
    .\Clear-StaleSmbArtifacts.ps1 -ReportOnly -Verbose

    Dry run — shows what would be disconnected/removed.

.EXAMPLE
    .\Clear-StaleSmbArtifacts.ps1

    Performs the cleanup. Use -WhatIf to preview via the standard
    ShouldProcess mechanism instead of -ReportOnly if you prefer.

.EXAMPLE
    .\Clear-StaleSmbArtifacts.ps1 -ReportOnly | Export-Csv .\smb-cleanup-report.csv -NoTypeInformation

    Report-only run piped to a CSV for review before deploying broadly.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$ReportOnly
)

function Write-ActionResult {
    param(
        [string]$Category,
        [string]$Target,
        [string]$Action,
        [bool]$Performed
    )
    [pscustomobject]@{
        Category  = $Category
        Target    = $Target
        Action    = $Action
        Performed = $Performed
    }
}

function Get-IdleSmbConnection {
    <#
        Idle SMB client connections/sessions with no open file handles.
        NumOpens is used as an idle proxy since the SMB client does not
        expose a last-used timestamp via PowerShell.
    #>
    Get-SmbConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.NumOpens -eq 0 }
}

function Get-SmbQuickAccessItem {
    <#
        Quick Access (pinned + recent) entries whose target path is a
        UNC/SMB path. Uses the Shell Quick Access namespace, which
        exposes .Path directly.
    #>
    $shell = New-Object -ComObject Shell.Application
    $qa = $shell.Namespace('shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}')
    if (-not $qa) { return @() }

    $qa.Items() | Where-Object { $_.Path -like '\\*' }
}

function Get-SmbShortcutTarget {
    <#
        Resolves .lnk shortcut targets under the given folder(s) and
        returns only those pointing at a UNC/SMB path. Shared by
        Recent Items and Network Shortcuts.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Path
    )

    $wsh = New-Object -ComObject WScript.Shell

    Get-ChildItem -Path $Path -Filter '*.lnk' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $target = $null
            try {
                $target = $wsh.CreateShortcut($_.FullName).TargetPath
            } catch {
                Write-Verbose "Failed to resolve shortcut target for $($_.FullName): $_"
            }
            if ($target -like '\\*') {
                [pscustomobject]@{
                    File   = $_.FullName
                    Target = $target
                }
            }
        }
}

function Get-SmbJumpListFile {
    <#
        Jump list (.ms) files under AutomaticDestinations/CustomDestinations
        whose raw contents reference a UNC/SMB path. Detection is via a
        Unicode string scan of the compound-file bytes rather than a proper
        OLE compound-file parse, so a match means "this file references a
        UNC path somewhere inside it" — removal is file-level, not
        per-entry, since jump list files bundle multiple entries per app.
    #>
    $jumpListPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms"
        "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms"
    )

    $uncPattern = '\\\\[A-Za-z0-9._-]+\\[^\x00]+'

    Get-ChildItem -Path $jumpListPaths -ErrorAction SilentlyContinue |
        ForEach-Object {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $text = [System.Text.Encoding]::Unicode.GetString($bytes)
            $match = [regex]::Match($text, $uncPattern)
            if ($match.Success) {
                [pscustomobject]@{
                    File  = $_.FullName
                    Match = $match.Value
                }
            }
        }
}

$results = New-Object System.Collections.Generic.List[object]

# --- 1. Idle SMB connections ---------------------------------------------
Write-Verbose 'Checking for idle SMB connections (no open handles)...'
foreach ($conn in Get-IdleSmbConnection) {
    $target = "\\$($conn.ServerName)\$($conn.ShareName)"
    $performed = $false
    if ($ReportOnly) {
        Write-Verbose "[ReportOnly] Would disconnect idle SMB connection: $target"
    } elseif ($PSCmdlet.ShouldProcess($target, 'Disconnect idle SMB connection')) {
        net use $target /delete /y | Out-Null
        $performed = $true
        Write-Verbose "Disconnected idle SMB connection: $target"
    }
    $results.Add((Write-ActionResult -Category 'IdleSmbConnection' -Target $target -Action 'Disconnect' -Performed $performed))
}

# --- 2. Quick Access (SMB entries only) -----------------------------------
Write-Verbose 'Checking Quick Access for SMB/UNC entries...'
foreach ($item in Get-SmbQuickAccessItem) {
    $performed = $false
    if ($ReportOnly) {
        Write-Verbose "[ReportOnly] Would unpin/remove Quick Access entry: $($item.Path)"
    } elseif ($PSCmdlet.ShouldProcess($item.Path, 'Remove Quick Access entry')) {
        $removed = $false
        foreach ($verb in 'unpinfromhome', 'removefromhome') {
            try {
                $item.InvokeVerb($verb)
                $removed = $true
                break
            } catch {
                Write-Verbose "Verb '$verb' failed for $($item.Path): $_"
            }
        }
        $performed = $removed
        if ($removed) { Write-Verbose "Removed Quick Access entry: $($item.Path)" }
        else { Write-Warning "Could not remove Quick Access entry (unrecognized verb on this build): $($item.Path)" }
    }
    $results.Add((Write-ActionResult -Category 'QuickAccess' -Target $item.Path -Action 'Unpin/Remove' -Performed $performed))
}

# --- 3. Recent Items (SMB entries only) -----------------------------------
Write-Verbose 'Checking Recent Items for SMB/UNC shortcuts...'
foreach ($entry in Get-SmbShortcutTarget -Path "$env:APPDATA\Microsoft\Windows\Recent") {
    $performed = $false
    if ($ReportOnly) {
        Write-Verbose "[ReportOnly] Would remove Recent Item: $($entry.File) -> $($entry.Target)"
    } elseif ($PSCmdlet.ShouldProcess($entry.File, "Remove Recent Item (target: $($entry.Target))")) {
        Remove-Item -LiteralPath $entry.File -Force -ErrorAction SilentlyContinue
        $performed = $true
        Write-Verbose "Removed Recent Item: $($entry.File)"
    }
    $results.Add((Write-ActionResult -Category 'RecentItem' -Target $entry.Target -Action 'Delete shortcut' -Performed $performed))
}

# --- 4. Network Shortcuts (always SMB by definition) ----------------------
Write-Verbose 'Checking Network Shortcuts for SMB/UNC targets...'
foreach ($entry in Get-SmbShortcutTarget -Path "$env:APPDATA\Microsoft\Windows\Network Shortcuts") {
    $performed = $false
    if ($ReportOnly) {
        Write-Verbose "[ReportOnly] Would remove Network Shortcut: $($entry.File) -> $($entry.Target)"
    } elseif ($PSCmdlet.ShouldProcess($entry.File, "Remove Network Shortcut (target: $($entry.Target))")) {
        Remove-Item -LiteralPath $entry.File -Force -ErrorAction SilentlyContinue
        $performed = $true
        Write-Verbose "Removed Network Shortcut: $($entry.File)"
    }
    $results.Add((Write-ActionResult -Category 'NetworkShortcut' -Target $entry.Target -Action 'Delete shortcut' -Performed $performed))
}

# --- 5. Jump lists referencing SMB/UNC paths (file-level) -----------------
Write-Verbose 'Checking jump lists for SMB/UNC references...'
foreach ($entry in Get-SmbJumpListFile) {
    $performed = $false
    if ($ReportOnly) {
        Write-Verbose "[ReportOnly] Would remove jump list file: $($entry.File) (matched: $($entry.Match))"
    } elseif ($PSCmdlet.ShouldProcess($entry.File, "Remove jump list file (matched: $($entry.Match))")) {
        Remove-Item -LiteralPath $entry.File -Force -ErrorAction SilentlyContinue
        $performed = $true
        Write-Verbose "Removed jump list file: $($entry.File)"
    }
    $results.Add((Write-ActionResult -Category 'JumpList' -Target $entry.File -Action 'Delete file (matched UNC reference)' -Performed $performed))
}

# --- 6. Thumbnail cache (full clear, not path-filterable) -----------------
Write-Verbose 'Clearing thumbnail cache (full clear; entries are not mappable back to source paths)...'
$thumbCachePath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db"
$performed = $false
if ($ReportOnly) {
    Write-Verbose '[ReportOnly] Would stop explorer.exe and clear thumbnail cache files.'
} elseif ($PSCmdlet.ShouldProcess('thumbcache_*.db', 'Stop explorer.exe and delete thumbnail cache')) {
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Remove-Item -Path $thumbCachePath -Force -ErrorAction SilentlyContinue
    Start-Process explorer.exe
    $performed = $true
    Write-Verbose 'Thumbnail cache cleared and Explorer restarted.'
}
$results.Add((Write-ActionResult -Category 'ThumbnailCache' -Target $thumbCachePath -Action 'Stop explorer / delete cache / restart explorer' -Performed $performed))

$results
