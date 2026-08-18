# Excluding SMB/UNC Locations from Windows Search Indexing

## What this addresses

Windows Search's background indexer can independently touch a network share to (re)build its index, which is another silent, non-interactive way an SMB connection attempt can occur — the user never opened the share, the indexer did it in the background. Where Network Segmentation enforces MFA-on-access, that background touch is indistinguishable from a real connection attempt.

## Important: this usually doesn't apply

Windows Search does **not** index UNC/mapped-drive locations by default. A network location only gets indexed if:

- It was **explicitly added** as an indexed location (Control Panel → Indexing Options → Modify → checking a network path), **or**
- The share is enabled for **Offline Files** (Sync Center) — see the note at the bottom, since that's a related but separate mechanism from indexing itself.

So the first step for any affected machine is to check whether this even applies before doing anything.

## Checking current indexed locations

**GUI:** Control Panel → **Indexing Options** → the "Included Locations" list shows every indexed path, including any network locations that were explicitly added.

**Programmatic check** — same COM API used for removal below:

```powershell
$searchManager      = New-Object -ComObject 'Microsoft.Search.Interop.CSearchManager'
$catalogManager     = $searchManager.GetCatalog('SystemIndex')
$crawlScopeManager  = $catalogManager.GetCrawlScopeManager()

$crawlScopeManager.EnumerateScopeRules() | ForEach-Object {
    [pscustomobject]@{
        Path      = $_.PatternOrPath
        IsIncluded = $_.IsIncluded
        IsDefault  = $_.IsDefault
    }
} | Where-Object { $_.Path -like '\\*' }
```

This lists any scope rules whose path is a UNC path — if this returns nothing, indexing isn't a contributing factor on that machine and no further action is needed here.

## Removing a UNC location from the index scope

If a UNC path is found in the indexed locations, remove it via the same `CSearchManager` COM API used by the Indexing Options control panel under the hood (there is no dedicated PowerShell cmdlet for this):

```powershell
$searchManager     = New-Object -ComObject 'Microsoft.Search.Interop.CSearchManager'
$catalogManager    = $searchManager.GetCatalog('SystemIndex')
$crawlScopeManager = $catalogManager.GetCrawlScopeManager()

$crawlScopeManager.RemoveDefaultScopeRule('\\server\share', $true, 0)
$crawlScopeManager.SaveAll()
```

- The `$true` argument marks the rule as an "include" rule being removed (matches how the GUI adds included network locations).
- `SaveAll()` commits the change; the indexer picks it up without requiring a service restart, though a full removal of previously-indexed content from the catalog can take a little time to complete in the background.
- This needs to run in the context of the user who added the location (indexed locations are commonly per-user for network paths added via the GUI), or adjust scope handling if it was configured machine-wide.

## Separate but related: Offline Files (Sync Center)

Offline Files is a distinct feature from search indexing, but produces the same symptom: if a share (or a folder within it) is marked "Always available offline," Windows runs a background sync against that share on its own schedule — independent of indexing, independent of Explorer being open — which is another silent SMB touch.

Check per-share:
- **GUI:** right-click the mapped drive/share in Explorer → look for "Always available offline" (toggle it off if enabled).
- **Sync Center:** Control Panel → Sync Center → Manage offline files, to see everything currently configured for offline availability.

If the customer's affected users have any shares configured this way, disabling offline availability closes this vector the same way removing the location from the search index closes that one — worth checking both while diagnosing, since they're easy to conflate but require separate fixes.
