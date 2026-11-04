<#
.SYNOPSIS
Creates, updates, or removes Zero Networks custom groups in bulk from a CSV file.

.DESCRIPTION
Reads a CSV in which each row adds one member (asset, group of any kind, user account, IP alias,
subnet, IP, FQDN, or wildcard domain) to a target custom group. Groups that do not exist are created; existing groups
are reused and only missing members are added, so the script is safe to re-run. Parent groups
can be declared with parentGroup, which nests the target group under the parent.

Members can be given as an entityName (looked up by name) or, optionally, as an entityId (a tenant
ID that is checked directly and takes precedence over entityName when both are present).
The whole CSV is resolved and validated before anything is written: every entityName or entityId is
classified and looked up, parent and member group references are checked, dependencies are
ordered (children before parents) and cycles are rejected. Any unresolvable entity stops the run
unless -SkipResolveErrors is given.

Two destructive modes are available and are mutually exclusive with each other:
-RemoveMembers removes the listed members from the target groups, and -RemoveGroupsAndMembers
empties the target groups, unlinks them from parents, and deletes them. Both show a summary and
ask for confirmation unless -Force is given. -WhatIf shows what would happen without changing
anything.

-SiteGroups enforces the Zero Networks Sites layout: group names must start with Site_,
leaf groups may contain only subnets, and parent groups may contain only child Site_ groups.
It also writes a Markdown site hierarchy map after the rules pass. See SITE-GROUPS.md.

The API key is read from -ApiKey or prompted for as a secure string. It is never written to
the console or to verbose output.

.PARAMETER CsvPath
Path to the CSV file. Required columns: entityName, targetGroupName, newGroupDescription,
parentGroup. Each row adds one member to targetGroupName. A row with an empty entityName and
an empty entityId only defines the group. The optional entityId column holds the tenant ID of
the member (for example a:x:xxxxxxxx or b:120a14000010). When entityId is set it is used
instead of entityName, which is then ignored for resolution (a warning is printed if the two
refer to different entities). When entityId is empty the row resolves by entityName as before.
The column may be left out of the CSV entirely.

.PARAMETER PortalUrl
Tenant portal host, for example mycompany-admin.zeronetworks.com. A leading scheme, trailing
slash, or /api/v1 suffix is accepted and removed.

.PARAMETER ApiKey
Zero Networks API key. If omitted, the script prompts for it as a secure string.

.PARAMETER SkipResolveErrors
Skip member rows that cannot be resolved (missing or ambiguous names) instead of stopping. Skipped rows are listed at the end of the run. Site rule violations are never skipped.

.PARAMETER SiteGroups
Validate the CSV against the Sites layout rules before any change is made. Bare IP addresses are
converted to /32 (IPv4) or /128 (IPv6). A Markdown hierarchy map is written in dry runs and real
runs; see SITE-GROUPS.md for the rules, the workflow and the map layout.

.PARAMETER SiteMapPath
Markdown file for the site hierarchy map. Used only with -SiteGroups; a map is written in that mode once validation passes (not when validation fails or the confirmation prompt is declined). Without this parameter the file is site-hierarchy-<yyyyMMdd-HHmmss>.md in the current directory. An explicit path is overwritten, and its folder is created if needed. Not allowed without -SiteGroups or with a removal switch. Its map is written after validation, both for -WhatIf/-DryRun (statuses Planned and Existing) and for a real run (statuses Created, Updated, Unchanged and Failed).

.PARAMETER RemoveMembers
Remove the listed entityName members from each targetGroupName. Groups are kept. The
newGroupDescription and parentGroup columns are ignored in this mode.

.PARAMETER RemoveGroupsAndMembers
Remove every member from each targetGroupName, unlink the group from its parent groups, and
delete the group. The entityName column is used only to determine deletion order.

.PARAMETER Force
Skip the confirmation prompt (create mode and both removal modes). Without -Force, a non-interactive
session aborts.

.PARAMETER DryRun
Alias-style switch equivalent to -WhatIf: runs lookups and validation, prints the plan, and makes no changes.

.EXAMPLE
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -WhatIf

.EXAMPLE
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\site-groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -SiteGroups

.NOTES
Requires PowerShell 7.0 or later.
Endpoints: POST groups/custom, PUT and DELETE groups/custom/{id}/members, GET groups/custom/{id}/members,
DELETE groups/custom/{id}, GET assets, groups/custom and groups with _filters on name, and
GET groups/custom/member-candidates for user accounts and IP aliases. entityId checks use GET assets
(assetId filter), GET groups (groupId), GET users (userId) and GET ip-aliases/{id}.
Only targetGroupName and parentGroup must be custom groups; entityName may be any entity kind.
Exit code 0 on success, 1 if any failure occurred or the run stopped on an error.
#>
#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Create')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [string]$PortalUrl,

    [string]$ApiKey,

    [switch]$SkipResolveErrors,

    [switch]$SiteGroups,

    [string]$SiteMapPath,

    [Parameter(ParameterSetName = 'RemoveMembers')]
    [switch]$RemoveMembers,

    [Parameter(ParameterSetName = 'RemoveGroupsAndMembers')]
    [switch]$RemoveGroupsAndMembers,

    [switch]$Force,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Pure helpers (no network access). Safe to dot-source for testing.
# ---------------------------------------------------------------------------

function ConvertTo-ZNApiBaseUrl {
    <#
    .SYNOPSIS
        Normalizes a portal host or URL to the API base URL.
    .PARAMETER PortalUrl
        Portal host or URL.
    .OUTPUTS
        System.String of the form https://<host>/api/v1.
    #>
    param([Parameter(Mandatory = $true)][string]$PortalUrl)

    $hostPart = $PortalUrl.Trim()
    $hostPart = [regex]::Replace($hostPart, '^[a-z][a-z0-9+.-]*://', '', 'IgnoreCase')
    $hostPart = $hostPart.Split('/')[0].TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($hostPart) -or $hostPart -notmatch '^[A-Za-z0-9.-]+(:\d+)?$') {
        throw "PortalUrl '$PortalUrl' is not a valid host name. Example: mycompany-admin.zeronetworks.com"
    }
    return "https://$hostPart/api/v1"
}

function Get-ZNMaskedKey {
    <#
    .SYNOPSIS
        Masks an API key for display, keeping only the last four characters.
    .PARAMETER Key
        The API key.
    .OUTPUTS
        System.String.
    #>
    param([string]$Key)
    if ([string]::IsNullOrEmpty($Key) -or $Key.Length -le 4) { return '****' }
    return ('*' * 8) + $Key.Substring($Key.Length - 4)
}

function Test-ZNHostname {
    <#
    .SYNOPSIS
        Tests whether a string is a dotted DNS hostname with at least one dot.
    .PARAMETER Value
        Candidate hostname.
    .OUTPUTS
        System.Boolean.
    #>
    param([string]$Value)
    return ($Value -match '^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
}

function ConvertTo-ZNNetwork {
    <#
    .SYNOPSIS
        Parses an IPv4 or IPv6 address with optional prefix and masks off host bits.
    .PARAMETER Value
        Address such as 10.20.5.17, 10.20.0.0/16, 2001:db8::/32.
    .OUTPUTS
        PSCustomObject with Family, Prefix, Bytes (masked network bytes), Address (masked, normalized text).
    .NOTES
        Throws on malformed input. A bare address gets the full-length prefix (/32 or /128).
    #>
    param([Parameter(Mandatory = $true)][string]$Value)

    $v = $Value.Trim()
    $parts = $v.Split('/')
    if ($parts.Count -gt 2) { throw "'$Value' is not a valid IP or CIDR" }

    $addressText = $parts[0]
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($addressText, [ref]$ip)) {
        throw "'$addressText' is not a valid IP address"
    }

    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($addressText -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            throw "'$addressText' is not a full dotted-quad IPv4 address"
        }
        $family = 'IPv4'
        $maxPrefix = 32
    }
    elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($addressText.Contains('%')) { throw "IPv6 scope IDs are not allowed in '$Value'" }
        $family = 'IPv6'
        $maxPrefix = 128
    }
    else {
        throw "'$addressText' is not an IPv4 or IPv6 address"
    }

    $prefix = $maxPrefix
    if ($parts.Count -eq 2) {
        if ($parts[1] -notmatch '^\d{1,3}$' -or [int]$parts[1] -gt $maxPrefix) {
            throw "prefix '/$($parts[1])' is invalid for $family (must be 0-$maxPrefix)"
        }
        $prefix = [int]$parts[1]
    }

    $bytes = $ip.GetAddressBytes()
    $network = [byte[]]::new($bytes.Length)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bitsInByte = [Math]::Max(0, [Math]::Min(8, $prefix - ($i * 8)))
        $mask = [byte](((0xFF -shl (8 - $bitsInByte)) -band 0xFF))
        $network[$i] = [byte]($bytes[$i] -band $mask)
    }
    $networkIp = [System.Net.IPAddress]::new($network)

    return [pscustomobject]@{
        Family  = $family
        Prefix  = $prefix
        Bytes   = $network
        Address = $networkIp.ToString()
        Masked  = (-not $networkIp.Equals($ip))
    }
}

function ConvertTo-ZNSubnetId {
    <#
    .SYNOPSIS
        Encodes an IPv4 or IPv6 address or subnet as a Zero Networks member ID.
    .PARAMETER Value
        Address or CIDR, for example 10.20.0.0/16 or 10.20.5.17.
    .OUTPUTS
        System.String. b:12 plus 8 hex digits and a 2-digit prefix for IPv4, or b:15 plus 32 hex digits and a 2-digit prefix for IPv6.
    .NOTES
        Host bits are masked before encoding. A bare address is encoded as /32 or /128.
    #>
    param([Parameter(Mandatory = $true)][string]$Value)

    $net = ConvertTo-ZNNetwork -Value $Value
    $hex = -join ($net.Bytes | ForEach-Object { '{0:x2}' -f $_ })
    $typeCode = if ($net.Family -eq 'IPv4') { 'b:12' } else { 'b:15' }
    return '{0}{1}{2:x2}' -f $typeCode, $hex, $net.Prefix
}

function ConvertFrom-ZNSubnetId {
    <#
    .SYNOPSIS
        Decodes a Zero Networks IPv4 or IPv6 subnet member ID into an address and prefix.
    .PARAMETER Id
        Subnet ID, for example b:120a14000010 (10.20.0.0/16) or b:15 plus 32 hex digits and a 2-digit prefix (IPv6).
    .OUTPUTS
        PSCustomObject with Family, Prefix, Address and Display (address/prefix, for example 10.20.0.0/16 or 10.20.5.17/32).
    .NOTES
        Inverse of ConvertTo-ZNSubnetId. Throws on malformed IDs or a prefix longer than the address family allows.
    #>
    param([Parameter(Mandatory = $true)][string]$Id)

    if ($Id -cmatch '^b:12([0-9a-f]{8})([0-9a-f]{2})$') {
        $family = 'IPv4'; $maxPrefix = 32; $hexAddress = $Matches[1]; $hexPrefix = $Matches[2]
    }
    elseif ($Id -cmatch '^b:15([0-9a-f]{32})([0-9a-f]{2})$') {
        $family = 'IPv6'; $maxPrefix = 128; $hexAddress = $Matches[1]; $hexPrefix = $Matches[2]
    }
    else {
        throw "'$Id' is not a subnet ID (expected b:12 plus 10 hex digits for IPv4, or b:15 plus 34 hex digits for IPv6)."
    }

    $prefix = [Convert]::ToInt32($hexPrefix, 16)
    if ($prefix -gt $maxPrefix) { throw "'$Id' has prefix /$prefix, which is invalid for $family (must be 0-$maxPrefix)." }

    $bytes = [byte[]]::new($hexAddress.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hexAddress.Substring($i * 2, 2), 16)
    }
    $address = [System.Net.IPAddress]::new($bytes).ToString()

    return [pscustomobject]@{
        Family  = $family
        Prefix  = $prefix
        Address = $address
        Display = "$address/$prefix"
    }
}

function ConvertTo-ZNFqdnId {
    <#
    .SYNOPSIS
        Encodes a fully qualified domain name as a Zero Networks member ID.
    .PARAMETER Name
        Domain name, for example Example.COM.
    .OUTPUTS
        System.String of the form b:17 plus the lowercase name.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)
    return 'b:17' + $Name.Trim().TrimEnd('.').ToLowerInvariant()
}

function ConvertTo-ZNDomainPatternId {
    <#
    .SYNOPSIS
        Encodes a wildcard domain pattern as a Zero Networks member ID.
    .PARAMETER Pattern
        Wildcard pattern such as *.corp.example.com.
    .OUTPUTS
        System.String of the form b:18 plus the lowercase pattern.
    #>
    param([Parameter(Mandatory = $true)][string]$Pattern)
    return 'b:18' + $Pattern.Trim().ToLowerInvariant()
}

function Get-ZNEntityKind {
    <#
    .SYNOPSIS
        Classifies one CSV entityName as a subnet, wildcard domain, or a name to resolve.
    .PARAMETER Value
        The entityName text.
    .OUTPUTS
        PSCustomObject with Kind (Subnet, Domain, Name, Invalid), Id, Display, IsBare, IsFqdn, Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$Value)

    $v = $Value.Trim()
    $base = [pscustomobject]@{ Kind = 'Name'; Id = $null; Display = $v; IsBare = $false; IsFqdn = $false; Reason = $null }

    if ($v.StartsWith('*.')) {
        if (Test-ZNHostname -Value $v.Substring(2)) {
            $base.Kind = 'Domain'
            $base.Id = ConvertTo-ZNDomainPatternId -Pattern $v
            $base.Display = $v.ToLowerInvariant()
        }
        else {
            $base.Kind = 'Invalid'
            $base.Reason = "wildcard entity must look like *.example.com"
        }
        return $base
    }

    if ($v -match '^\d{1,3}(\.\d{1,3}){3}(/\S*)?$' -or $v.Contains(':')) {
        try {
            $net = ConvertTo-ZNNetwork -Value $v
            $base.Kind = 'Subnet'
            $base.Id = ConvertTo-ZNSubnetId -Value $v
            $base.Display = "$($net.Address)/$($net.Prefix)"
            $base.IsBare = -not $v.Contains('/')
        }
        catch {
            $base.Kind = 'Invalid'
            $base.Reason = $_.Exception.Message
        }
        return $base
    }

    $base.IsFqdn = Test-ZNHostname -Value $v
    return $base
}

function Import-ZNGroupCsv {
    <#
    .SYNOPSIS
        Reads and validates the group CSV, returning one object per non-blank data row.
    .PARAMETER Path
        Path to the CSV file.
    .OUTPUTS
        PSCustomObject[] with Row, EntityName, EntityId, TargetGroupName, NewGroupDescription, ParentGroup.
    .NOTES
        entityId is optional: the column may be absent, and an empty cell means "use entityName".
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $required = @('entityName', 'targetGroupName', 'newGroupDescription', 'parentGroup')

    $records = @(Import-Csv -LiteralPath $Path)
    if ($records.Count -eq 0) { throw "CSV '$Path' has no data rows." }

    $propNames = @($records[0].PSObject.Properties.Name)
    $propFor = @{}
    $missingCols = @()
    foreach ($req in $required) {
        $found = $propNames | Where-Object { $_.Trim() -ieq $req } | Select-Object -First 1
        if ($found) { $propFor[$req] = $found } else { $missingCols += $req }
    }
    if ($missingCols.Count -gt 0) {
        throw "CSV '$Path' is missing required column(s): $($missingCols -join ', '). Required: $($required -join ', ')."
    }
    # Optional column: absent is fine.
    $entityIdProp = $propNames | Where-Object { $_.Trim() -ieq 'entityId' } | Select-Object -First 1

    $rows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $records.Count; $i++) {
        $rec = $records[$i]
        $rowNo = $i + 1
        $values = @{}
        foreach ($req in $required) { $values[$req] = ([string]$rec.($propFor[$req])).Trim() }
        $values['entityId'] = if ($entityIdProp) { ([string]$rec.($entityIdProp)).Trim() } else { '' }

        if (@($values.Values | Where-Object { $_ -ne '' }).Count -eq 0) { continue }
        if ($values['targetGroupName'] -eq '') {
            throw "CSV data row $rowNo : targetGroupName is required."
        }

        $rows.Add([pscustomobject]@{
                Row                 = $rowNo
                EntityName          = $values['entityName']
                EntityId            = $values['entityId']
                TargetGroupName     = $values['targetGroupName']
                NewGroupDescription = $values['newGroupDescription']
                ParentGroup         = $values['parentGroup']
            })
    }

    if ($rows.Count -eq 0) { throw "CSV '$Path' has no non-blank group rows." }
    return $rows.ToArray()
}

function New-ZNGroupModel {
    <#
    .SYNOPSIS
        Groups CSV rows by targetGroupName into group nodes, preserving first-seen order.
    .PARAMETER Rows
        Output of Import-ZNGroupCsv.
    .PARAMETER Mode
        Create, RemoveMembers or RemoveGroupsAndMembers. Descriptions are only used in Create mode.
    .OUTPUTS
        PSCustomObject with Nodes (case-insensitive hashtable), Order (names), Warnings.
    #>
    param(
        [Parameter(Mandatory = $true)][object[]]$Rows,
        [ValidateSet('Create', 'RemoveMembers', 'RemoveGroupsAndMembers')][string]$Mode = 'Create'
    )

    $nodes = @{}
    $order = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    foreach ($r in $Rows) {
        if (-not $nodes.ContainsKey($r.TargetGroupName)) {
            $nodes[$r.TargetGroupName] = [pscustomobject]@{
                Name        = $r.TargetGroupName
                Description = $null
                ParentName  = $null
                Rows        = [System.Collections.Generic.List[int]]::new()
                Members     = [System.Collections.Generic.List[object]]::new()
                Resolved    = [System.Collections.Generic.List[object]]::new()
                ExistingId  = $null
                Id          = $null
                ParentNode  = $null
                ParentId    = $null
                Status      = $null
                Notes       = ''
                Failed      = $false
                Missing     = $false
            }
            $order.Add($r.TargetGroupName)
        }
        $node = $nodes[$r.TargetGroupName]
        $node.Rows.Add($r.Row)

        if ($Mode -eq 'Create') {
            if ($r.NewGroupDescription) {
                if (-not $node.Description) { $node.Description = $r.NewGroupDescription }
                elseif ($node.Description -cne $r.NewGroupDescription) {
                    $warnings.Add("Group '$($node.Name)': conflicting newGroupDescription values; using the first ('$($node.Description)').")
                }
            }
        }
        if ($r.ParentGroup) {
            if (-not $node.ParentName) { $node.ParentName = $r.ParentGroup }
            elseif ($node.ParentName -cne $r.ParentGroup) {
                $warnings.Add("Group '$($node.Name)': conflicting parentGroup values; using the first ('$($node.ParentName)').")
            }
        }
        # A row has a member when entityId or entityName is set. entityId supersedes entityName for resolution.
        # Text is the entityName when present, otherwise the entityId (used in messages and ordering).
        if ($r.EntityName -or $r.EntityId) {
            $memberText = if ($r.EntityName) { [string]$r.EntityName } else { [string]$r.EntityId }
            $memberId = if ($r.EntityId) { [string]$r.EntityId } else { $null }
            $node.Members.Add([pscustomobject]@{ Row = $r.Row; Text = $memberText; Id = $memberId; EntityName = [string]$r.EntityName })
        }
    }

    return [pscustomobject]@{ Nodes = $nodes; Order = $order; Warnings = $warnings }
}

function Invoke-ZNTopoVisit {
    <#
    .SYNOPSIS
        Depth-first visit used by Get-ZNCreateOrder. Emits dependencies before dependents and throws on cycles.
    .PARAMETER Name
        Node name being visited.
    .PARAMETER Requires
        Hashtable of name to List[string] of names that must come first.
    .PARAMETER State
        Hashtable of visit state (1 = in progress, 2 = done).
    .PARAMETER Order
        Output list.
    .PARAMETER Path
        Current DFS path, used to report cycles.
    .OUTPUTS
        None.
    #>
    param(
        [string]$Name,
        [hashtable]$Requires,
        [hashtable]$State,
        [System.Collections.Generic.List[string]]$Order,
        [System.Collections.Generic.List[string]]$Path
    )

    if ($State[$Name] -eq 2) { return }
    if ($State[$Name] -eq 1) {
        $arr = $Path.ToArray()
        $start = $Path.IndexOf($Name)
        $cycle = @($arr[$start..($arr.Count - 1)]) + $Name
        throw "Circular group dependency detected: $($cycle -join ' -> '). Remove the loop from parentGroup or entityName references."
    }

    $State[$Name] = 1
    $Path.Add($Name)
    if ($Requires.ContainsKey($Name)) {
        foreach ($dep in @($Requires[$Name])) {
            Invoke-ZNTopoVisit -Name $dep -Requires $Requires -State $State -Order $Order -Path $Path
        }
    }
    $Path.RemoveAt($Path.Count - 1)
    $State[$Name] = 2
    $Order.Add($Name)
}

function Get-ZNCreateOrder {
    <#
    .SYNOPSIS
        Returns group names in dependency order (requirements first) and rejects cycles.
    .PARAMETER Names
        All group names, in CSV order.
    .PARAMETER Requires
        Hashtable of name to List[string] of names that must be processed first.
    .OUTPUTS
        System.String[] in dependency order.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $true)][hashtable]$Requires
    )

    $state = @{}
    $order = [System.Collections.Generic.List[string]]::new()
    $path = [System.Collections.Generic.List[string]]::new()
    foreach ($n in $Names) {
        Invoke-ZNTopoVisit -Name $n -Requires $Requires -State $state -Order $order -Path $path
    }
    return $order.ToArray()
}

function Get-ZNNodeDepth {
    <#
    .SYNOPSIS
        Returns the number of hierarchy levels at and below a group.
    .PARAMETER Name
        Group name.
    .PARAMETER ChildrenOf
        Hashtable of name to List[string] of child names.
    .PARAMETER Memo
        Cache hashtable.
    .OUTPUTS
        System.Int32.
    #>
    param([string]$Name, [hashtable]$ChildrenOf, [hashtable]$Memo)

    if ($Memo.ContainsKey($Name)) { return $Memo[$Name] }
    $best = 0
    if ($ChildrenOf.ContainsKey($Name)) {
        foreach ($c in @($ChildrenOf[$Name])) {
            $d = Get-ZNNodeDepth -Name $c -ChildrenOf $ChildrenOf -Memo $Memo
            if ($d -gt $best) { $best = $d }
        }
    }
    $Memo[$Name] = $best + 1
    return $Memo[$Name]
}

function Get-ZNSiteDepth {
    <#
    .SYNOPSIS
        Computes the maximum hierarchy depth across group nodes (parent links and group members).
    .PARAMETER Nodes
        Group node objects with Name, ParentName and Resolved.
    .OUTPUTS
        System.Int32.
    #>
    param([object[]]$Nodes)

    $childrenOf = @{}
    foreach ($n in $Nodes) {
        if (-not $childrenOf.ContainsKey($n.Name)) { $childrenOf[$n.Name] = [System.Collections.Generic.List[string]]::new() }
    }
    foreach ($n in $Nodes) {
        if ($n.ParentName -and $childrenOf.ContainsKey($n.ParentName)) { $childrenOf[$n.ParentName].Add($n.Name) }
        foreach ($r in $n.Resolved) {
            if ($r.CsvGroup -and $childrenOf.ContainsKey($r.CsvGroup)) { $childrenOf[$n.Name].Add($r.CsvGroup) }
        }
    }
    $memo = @{}
    $max = 0
    foreach ($n in $Nodes) {
        $d = Get-ZNNodeDepth -Name $n.Name -ChildrenOf $childrenOf -Memo $memo
        if ($d -gt $max) { $max = $d }
    }
    return $max
}

function Get-ZNSiteViolations {
    <#
    .SYNOPSIS
        Checks group nodes against the Sites layout rules and returns any violations.
    .PARAMETER Nodes
        Active group node objects.
    .PARAMETER Mode
        Create or a removal mode. Hierarchy rules apply only to Create.
    .OUTPUTS
        System.String[] of violation messages (empty when valid).
    #>
    param([object[]]$Nodes, [string]$Mode = 'Create')

    $violations = [System.Collections.Generic.List[string]]::new()
    $childNames = @{}
    foreach ($n in $Nodes) {
        if ($n.ParentName) {
            if (-not $childNames.ContainsKey($n.ParentName)) { $childNames[$n.ParentName] = $true }
        }
    }

    foreach ($n in $Nodes) {
        $where = "group '$($n.Name)'"
        if (-not $n.Name.StartsWith('Site_', [StringComparison]::Ordinal)) {
            $violations.Add("$where must start with 'Site_' (case-sensitive) in -SiteGroups mode.")
        }
        if ($n.ParentName -and -not $n.ParentName.StartsWith('Site_', [StringComparison]::Ordinal)) {
            $violations.Add("parent group '$($n.ParentName)' of $where must start with 'Site_'.")
        }

        $hasSubnet = $false
        $hasChildGroup = $childNames.ContainsKey($n.Name)
        foreach ($r in $n.Resolved) {
            switch ($r.Kind) {
                'Subnet' {
                    $hasSubnet = $true
                    if ($r.IsBare) { Write-Verbose "Site rule: bare address '$($r.Text)' in $where converted to $($r.Display)." }
                }
                'Group' {
                    $gname = if ($r.CsvGroup) { $r.CsvGroup } else { $r.Display }
                    if ($r.CsvGroup -or $r.IsCustom) { $hasChildGroup = $true }
                    if (-not $r.CsvGroup -and -not $r.IsCustom) {
                        $violations.Add("$where contains '$gname', which is a non-custom group; Site groups accept only subnets and custom Site_ groups (as child groups).")
                    }
                    elseif (-not $gname.StartsWith('Site_', [StringComparison]::Ordinal)) {
                        $violations.Add("$where contains group '$gname', which is not a Site_ group.")
                    }
                }
                default {
                    $label = switch ($r.Kind) {
                        'Asset' { 'an asset' }
                        'User' { 'a user account' }
                        'Alias' { 'an IP alias' }
                        'Fqdn' { 'an FQDN' }
                        'Domain' { 'a wildcard domain' }
                        default { "a $($r.Kind)" }
                    }
                    $violations.Add("$where contains '$($r.Text)' ($label); Site groups accept only subnets (parents accept only child Site_ groups).")
                }
            }
        }
        if ($Mode -eq 'Create' -and $hasSubnet -and $hasChildGroup) {
            $violations.Add("$where mixes subnets with child groups; leaf Site groups hold subnets only and parent Site groups hold only child Site_ groups.")
        }
    }
    return $violations.ToArray()
}

function Get-ZNSiteMapModel {
    <#
    .SYNOPSIS
        Builds the hierarchy model behind the site hierarchy map. Pure: makes no network calls.
    .PARAMETER Nodes
        Group node objects in CSV order, with Name, ParentName, Resolved, Status and ExistingId.
        Status is optional; when empty it is derived as Existing (group found in the tenant) or Planned.
    .OUTPUTS
        PSCustomObject with Groups (CSV groups in CSV order, then groups outside the CSV that are
        referenced as a parent or a member group), Edges (Parent, Child), GroupCount, SubnetCount,
        ExistingCount and MaxDepth (from Get-ZNSiteDepth). Each group has Name, IsExternal, Status,
        Level, Parents, Children and Subnets.
    #>
    param([object[]]$Nodes)

    $nodeList = @($Nodes | Where-Object { $null -ne $_ })
    $items = [System.Collections.Generic.List[object]]::new()
    $index = @{}

    foreach ($n in $nodeList) {
        $status = if ($n.Status) { [string]$n.Status } elseif ($n.ExistingId) { 'Existing' } else { 'Planned' }
        $subnets = [System.Collections.Generic.List[string]]::new()
        foreach ($r in @($n.Resolved)) {
            if ($r.Kind -eq 'Subnet') { $subnets.Add([string]$r.Display) }
        }
        $index[[string]$n.Name] = $items.Count
        $items.Add([pscustomobject]@{
                Name       = [string]$n.Name
                IsExternal = $false
                Status     = $status
                Level      = 1
                Parents    = [System.Collections.Generic.List[string]]::new()
                Children   = [System.Collections.Generic.List[string]]::new()
                Subnets    = $subnets
            })
    }

    # Groups outside the CSV: an existing parent (parentGroup) or an existing child group (member).
    foreach ($n in $nodeList) {
        $refs = [System.Collections.Generic.List[string]]::new()
        if ($n.ParentName) { $refs.Add([string]$n.ParentName) }
        foreach ($r in @($n.Resolved)) {
            if ($r.Kind -eq 'Group' -and -not $r.CsvGroup) { $refs.Add([string]$r.Display) }
        }
        foreach ($ref in $refs) {
            if ($index.ContainsKey($ref)) { continue }
            $index[$ref] = $items.Count
            $items.Add([pscustomobject]@{
                    Name       = $ref
                    IsExternal = $true
                    Status     = 'External'
                    Level      = 0
                    Parents    = [System.Collections.Generic.List[string]]::new()
                    Children   = [System.Collections.Generic.List[string]]::new()
                    Subnets    = [System.Collections.Generic.List[string]]::new()
                })
        }
    }

    # Parent -> child edges, de-duplicated, in CSV order.
    $pairs = [System.Collections.Generic.List[object]]::new()
    foreach ($n in $nodeList) {
        if ($n.ParentName) { $pairs.Add(@([string]$n.ParentName, [string]$n.Name)) }
        foreach ($r in @($n.Resolved)) {
            if ($r.Kind -eq 'Group') {
                $child = if ($r.CsvGroup) { [string]$r.CsvGroup } else { [string]$r.Display }
                $pairs.Add(@([string]$n.Name, $child))
            }
        }
    }
    $edgeKeys = @{}
    $edges = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $pairs) {
        $key = "$($p[0])`t$($p[1])"
        if ($edgeKeys.ContainsKey($key)) { continue }
        $edgeKeys[$key] = $true
        $edges.Add([pscustomobject]@{ Parent = $p[0]; Child = $p[1] })
        $items[$index[$p[1]]].Parents.Add($p[0])
        $items[$index[$p[0]]].Children.Add($p[1])
    }

    # Level: 1 for top-level groups, 0 for an existing group that has no parent, otherwise parent level + 1.
    # The relaxation is bounded so a cycle (already rejected by the planner) cannot loop forever.
    for ($pass = 0; $pass -le $items.Count; $pass++) {
        $changed = $false
        foreach ($it in $items) {
            foreach ($pn in $it.Parents) {
                $candidate = $items[$index[$pn]].Level + 1
                if ($candidate -gt $it.Level) { $it.Level = $candidate; $changed = $true }
            }
        }
        if (-not $changed) { break }
    }

    $subnetTotal = 0
    foreach ($n in $nodeList) {
        foreach ($r in @($n.Resolved)) { if ($r.Kind -eq 'Subnet') { $subnetTotal++ } }
    }

    return [pscustomobject]@{
        Groups        = $items.ToArray()
        Edges         = $edges.ToArray()
        GroupCount    = $nodeList.Count
        SubnetCount   = $subnetTotal
        ExistingCount = @($items | Where-Object { $_.IsExternal }).Count
        MaxDepth      = Get-ZNSiteDepth -Nodes $nodeList
    }
}

function ConvertTo-ZNSiteMapMarkdown {
    <#
    .SYNOPSIS
        Renders the site hierarchy model as Markdown: header, text hierarchy tree and table.
    .PARAMETER Model
        Output of Get-ZNSiteMapModel.
    .PARAMETER Mode
        Mode text for the header, for example 'Dry run preview' or 'Executed'.
    .PARAMETER TenantHost
        Tenant host name only (no scheme, path or API key).
    .PARAMETER CsvName
        File name of the CSV (not the full path).
    .PARAMETER Generated
        Timestamp shown in the header.
    .OUTPUTS
        System.String of Markdown with LF line endings.
    .NOTES
        Table cells and prose escape | ` < > \ and newlines. The tree sits in a fenced block, where
        backslash escapes would show literally, so its names are not escaped; the fence is made longer
        than any backtick run inside it. Each group's subnets are listed in full as leaf lines.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Model,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$TenantHost,
        [Parameter(Mandatory = $true)][string]$CsvName,
        [Parameter(Mandatory = $true)][datetime]$Generated
    )

    # Markdown prose and table cells.
    $mdEsc = {
        param([string]$Text)
        $t = $Text -replace '[\r\n]+', ' '
        return $t.Replace('\', '\\').Replace('|', '\|').Replace('`', '\`').Replace('<', '&lt;').Replace('>', '&gt;')
    }

    $groups = @($Model.Groups)
    $pos = @{}
    for ($i = 0; $i -lt $groups.Count; $i++) { $pos[$groups[$i].Name] = $i }

    # Text tree. Roots are groups with no parent; child groups follow CSV order, then the group's own subnets.
    $byName = @{}
    foreach ($g in $groups) { $byName[$g.Name] = $g }
    $labelOf = {
        param($g)
        if ($g.IsExternal) { return "$($g.Name)  (existing)" }
        $n = @($g.Subnets).Count
        if ($n -eq 0) { return "$($g.Name)  [$($g.Status)]" }
        $unit = if ($n -eq 1) { 'subnet' } else { 'subnets' }
        return "$($g.Name)  [$($g.Status)]  ($n $unit)"
    }
    $sortedChildren = {
        param($g)
        return @($g.Children | Sort-Object { $pos[$_] })
    }
    $teeText = ('{0}{1}{1} ' -f [char]0x251C, [char]0x2500)
    $elbowText = ('{0}{1}{1} ' -f [char]0x2514, [char]0x2500)
    $barText = ('{0}   ' -f [char]0x2502)
    $gapText = '    '
    $treeLines = [System.Collections.Generic.List[string]]::new()
    $render = $null
    $render = {
        param([string]$Name, [string]$Prefix, [bool]$IsRoot, [bool]$IsLast, [string[]]$Trail)
        $g = $byName[$Name]
        if ($IsRoot) {
            $line = [string](& $labelOf $g)
            $childPrefix = ''
        }
        else {
            $connector = if ($IsLast) { $elbowText } else { $teeText }
            $line = $Prefix + $connector + [string](& $labelOf $g)
            $childPrefix = $Prefix + $(if ($IsLast) { $gapText } else { $barText })
        }
        if ($Trail -contains $Name) { $treeLines.Add($line + ' (cycle)'); return }
        $treeLines.Add($line)
        $childGroups = @(& $sortedChildren $g)
        $subs = @($g.Subnets)
        # A root with no child groups indents its subnet leaves under it.
        if ($IsRoot -and $childGroups.Count -eq 0) { $childPrefix = $gapText }
        $total = $childGroups.Count + $subs.Count
        for ($k = 0; $k -lt $childGroups.Count; $k++) {
            & $render ([string]$childGroups[$k]) $childPrefix $false ($k -eq ($total - 1)) (@($Trail) + $Name)
        }
        for ($s = 0; $s -lt $subs.Count; $s++) {
            $connector = if (($childGroups.Count + $s) -eq ($total - 1)) { $elbowText } else { $teeText }
            $treeLines.Add($childPrefix + $connector + [string]$subs[$s])
        }
    }
    foreach ($g in $groups) {
        if (@($g.Parents).Count -eq 0) { & $render $g.Name '' $true $false @() }
    }
    $treeText = $treeLines -join "`n"
    $maxRun = 0
    foreach ($m in [regex]::Matches($treeText, '`+')) { if ($m.Length -gt $maxRun) { $maxRun = $m.Length } }
    $fence = '`' * [Math]::Max(3, $maxRun + 1)

    # Table with the full subnet list.
    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add('| Group | Parent | Level | Status | Subnet count | Subnets |')
    $rows.Add('|---|---|---|---|---|---|')
    foreach ($g in $groups) {
        $name = & $mdEsc $g.Name
        $status = & $mdEsc $g.Status
        $parentText = if (@($g.Parents).Count -gt 0) { (@($g.Parents | ForEach-Object { & $mdEsc $_ })) -join ', ' } else { '-' }
        if ($g.IsExternal) {
            $name = "$name (existing)"
            $level = '-'
            $count = '-'
            $subsText = '-'
        }
        else {
            $level = [string]$g.Level
            $count = [string]@($g.Subnets).Count
            $subsText = if (@($g.Subnets).Count -gt 0) { (@($g.Subnets | ForEach-Object { & $mdEsc $_ })) -join ', ' } else { '-' }
        }
        $rows.Add("| $name | $parentText | $level | $status | $count | $subsText |")
    }

    # Assemble the document.
    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add('# Site hierarchy map')
    $out.Add('')
    $out.Add("- **Generated:** $($Generated.ToString('yyyy-MM-dd HH:mm:ss'))")
    $out.Add("- **Tenant:** $(& $mdEsc $TenantHost)")
    $out.Add("- **CSV file:** $(& $mdEsc $CsvName)")
    $out.Add("- **Mode:** $(& $mdEsc $Mode)")
    $out.Add("- **Groups:** $($Model.GroupCount)")
    $out.Add("- **Subnets:** $($Model.SubnetCount)")
    $out.Add("- **Max depth:** $($Model.MaxDepth) level(s)")
    if ($Model.ExistingCount -gt 0) { $out.Add("- **Existing groups outside the CSV:** $($Model.ExistingCount)") }
    $out.Add('')
    if ($Model.MaxDepth -gt 3) {
        $out.Add("> **Warning:** the hierarchy is $($Model.MaxDepth) levels deep. The Sites guide recommends 2 to 3 levels.")
        $out.Add('')
    }
    $out.Add('## Hierarchy')
    $out.Add('')
    $out.Add($fence + 'text')
    foreach ($line in $treeLines) { $out.Add($line) }
    $out.Add($fence)
    $out.Add('')
    $out.Add('## Table')
    $out.Add('')
    foreach ($line in $rows) { $out.Add($line) }
    $out.Add('')
    $out.Add('> **Reminder:** Zero Networks must enable Sites after these groups exist.')
    return (($out -join "`n") + "`n")
}

function Write-ZNSiteMap {
    <#
    .SYNOPSIS
        Writes the site hierarchy map as UTF-8 without BOM, creating its folder if needed.
    .PARAMETER Path
        Target file path. Relative paths are resolved against the current PowerShell location.
    .PARAMETER Content
        Markdown text to write.
    .OUTPUTS
        System.String: the full path of the file written.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $dir = Split-Path -Parent $full
    # -WhatIf:$false: the map is still written in a dry run, and creating its folder is not a tenant change.
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false)
    }
    [System.IO.File]::WriteAllText($full, $Content, [System.Text.UTF8Encoding]::new($false))
    return $full
}

function Confirm-ZNRun {
    <#
    .SYNOPSIS
        Asks the operator to type 'yes' before a destructive or bulk run.
    .PARAMETER Prompt
        Text shown before the prompt.
    .PARAMETER Force
        Skip the prompt and confirm.
    .OUTPUTS
        System.Boolean.
    #>
    param([string]$Prompt, [switch]$Force)

    if ($Force) { return $true }
    if ([Console]::IsInputRedirected) {
        throw 'Confirmation required but the session is non-interactive. Re-run with -Force to proceed.'
    }
    $answer = Read-Host "$Prompt. Type 'yes' to continue"
    return (([string]$answer).Trim() -ceq 'yes')
}

function Get-ZNApiKey {
    <#
    .SYNOPSIS
        Returns the API key from the parameter, or prompts for it as a secure string.
    .PARAMETER ApiKey
        Key passed on the command line, possibly empty.
    .OUTPUTS
        System.String.
    #>
    param([string]$ApiKey)

    if (-not [string]::IsNullOrWhiteSpace($ApiKey)) { return $ApiKey.Trim() }
    if ([Console]::IsInputRedirected) {
        throw '-ApiKey was not supplied and no interactive console is available to prompt for it.'
    }
    $secure = Read-Host -AsSecureString -Prompt 'Zero Networks API key'
    $plain = [System.Net.NetworkCredential]::new('', $secure).Password
    if ([string]::IsNullOrWhiteSpace($plain)) { throw 'No API key was entered.' }
    return $plain.Trim()
}

# ---------------------------------------------------------------------------
# API plumbing. Invoke-ApiRequest is the only function that talks to the network.
# ---------------------------------------------------------------------------

function Invoke-ApiRequest {
    <#
    .SYNOPSIS
        Sends one request to the Zero Networks API, retrying on HTTP 429 and throwing on other errors.
    .PARAMETER Method
        HTTP method.
    .PARAMETER ApiEndpoint
        Endpoint relative to the API base URL.
    .PARAMETER Body
        Optional body, serialized to JSON.
    .PARAMETER QueryParams
        Optional query string parameters (values are URL-encoded).
    .OUTPUTS
        The parsed response object.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$ApiEndpoint,

        [object]$Body = $null,

        [hashtable]$QueryParams = $null
    )

    $uri = "$script:ApiBaseUrl/$ApiEndpoint"
    if ($null -ne $QueryParams -and $QueryParams.Count -gt 0) {
        $qs = ($QueryParams.GetEnumerator() | ForEach-Object {
                "$($_.Key)=$([uri]::EscapeDataString([string]$_.Value))"
            }) -join '&'
        $uri = $uri + '?' + $qs
    }

    $requestParams = @{
        Method  = $Method
        Uri     = $uri
        Headers = $script:Headers
    }
    if ($null -ne $Body) {
        $requestParams['Body'] = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 -Compress }
        $requestParams['ContentType'] = 'application/json'
    }

    Write-Verbose "$Method $ApiEndpoint"

    $maxAttempts = 3
    $statusCode = $null
    $response = $null
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        $statusCode = $null
        $response = Invoke-RestMethod @requestParams -SkipHttpErrorCheck -StatusCodeVariable statusCode
        if ($statusCode -eq 429 -and $attempt -lt $maxAttempts) {
            $backoff = [math]::Pow(2, $attempt - 1)
            Write-Warning "HTTP 429 (rate limited) from $Method $ApiEndpoint. Retrying in $backoff second(s) (attempt $attempt of $maxAttempts)."
            Start-Sleep -Seconds $backoff
            continue
        }
        break
    }

    if ($null -eq $statusCode -or $statusCode -lt 200 -or $statusCode -ge 300) {
        $bodyText = if ($null -eq $response) { '' }
        elseif ($response -is [string]) { $response }
        else { $response | ConvertTo-Json -Depth 10 -Compress }
        throw "API request $Method $ApiEndpoint failed with HTTP $statusCode. $bodyText".TrimEnd()
    }
    return $response
}

function Invoke-PaginatedApiRequest {
    <#
    .SYNOPSIS
        Follows nextCursor pagination for a GET request and returns all items.
    .PARAMETER Method
        HTTP method (GET).
    .PARAMETER ApiEndpoint
        Endpoint relative to the API base URL.
    .PARAMETER QueryParams
        Base query parameters. The caller's hashtable is not modified.
    .OUTPUTS
        System.Collections.Generic.List[object] of items.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$ApiEndpoint,
        [hashtable]$QueryParams = @{}
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $query = @{}
    foreach ($k in $QueryParams.Keys) { $query[$k] = $QueryParams[$k] }
    $seenCursors = @{}
    do {
        $response = Invoke-ApiRequest -Method $Method -ApiEndpoint $ApiEndpoint -QueryParams $query
        if ($null -ne $response -and $null -ne $response.items) {
            foreach ($item in $response.items) { $items.Add($item) }
        }
        $cursor = if ($null -ne $response) { [string]$response.nextCursor } else { '' }
        if ($cursor -and $seenCursors.ContainsKey($cursor)) {
            throw "Pagination cursor repeated for $ApiEndpoint; stopping to avoid an endless loop."
        }
        if ($cursor) {
            $seenCursors[$cursor] = $true
            $query['_cursor'] = $cursor
        }
    } while ($cursor)

    return $items
}

# ---------------------------------------------------------------------------
# Tenant lookups and membership operations.
# ---------------------------------------------------------------------------

function Get-ZNFilteredItems {
    <#
    .SYNOPSIS
        Lists items from an endpoint using _filters.
    .PARAMETER Endpoint
        Collection endpoint, for example assets or groups/custom.
    .PARAMETER Filters
        Filter objects with id and includeValues.
    .PARAMETER ExtraQuery
        Additional query parameters, for example showInactive=true.
    .OUTPUTS
        System.Object[] of items.
    #>
    param([string]$Endpoint, [object[]]$Filters, [hashtable]$ExtraQuery = @{})

    $filterJson = ConvertTo-Json -InputObject @($Filters) -Depth 5 -Compress
    $query = @{ _limit = 100; _filters = $filterJson }
    foreach ($k in $ExtraQuery.Keys) { $query[$k] = $ExtraQuery[$k] }
    $items = Invoke-PaginatedApiRequest -Method GET -ApiEndpoint $Endpoint -QueryParams $query
    return @($items)
}

function Find-ZNItemsByName {
    <#
    .SYNOPSIS
        Finds items whose name exactly matches (case-insensitive) from a collection endpoint.
    .PARAMETER Endpoint
        Collection endpoint: assets, groups/custom or groups.
    .PARAMETER Name
        Name to match.
    .OUTPUTS
        System.Object[] of unique matches (by id).
    .NOTES
        Results are cached per endpoint and name for the length of the run.
    #>
    param([string]$Endpoint, [string]$Name)

    $key = "$Endpoint|$Name"
    if ($script:LookupCache.ContainsKey($key)) { return $script:LookupCache[$key] }

    $items = Get-ZNFilteredItems -Endpoint $Endpoint -Filters @(@{ id = 'name'; includeValues = @($Name) })
    $seen = @{}
    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $items) {
        if (-not [string]::Equals([string]$item.name, $Name, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($seen.ContainsKey([string]$item.id)) { continue }
        $seen[[string]$item.id] = $true
        $hits.Add($item)
    }
    $result = $hits.ToArray()
    $script:LookupCache[$key] = $result
    return $result
}

function Find-ZNAssetsByName {
    <#
    .SYNOPSIS
        Finds active assets with an exact (case-insensitive) name match.
    .PARAMETER Name
        Asset name.
    .OUTPUTS
        System.Object[] of asset objects.
    .NOTES
        showInactive is not passed, so only active assets are returned by the API.
    #>
    param([string]$Name)
    return @(Find-ZNItemsByName -Endpoint 'assets' -Name $Name)
}

function Find-ZNCustomGroupsByName {
    <#
    .SYNOPSIS
        Finds custom groups with an exact (case-insensitive) name match.
    .PARAMETER Name
        Group name.
    .OUTPUTS
        System.Object[] of group objects.
    #>
    param([string]$Name)
    return @(Find-ZNItemsByName -Endpoint 'groups/custom' -Name $Name)
}

function Find-ZNAnyGroupsByName {
    <#
    .SYNOPSIS
        Finds groups of any kind (custom, Active Directory, built-in, system) with an exact (case-insensitive) name match.
    .PARAMETER Name
        Group name.
    .OUTPUTS
        System.Object[] of unique groups (by id). Each has id, name and IsCustom.
    .NOTES
        Unions the groups and groups/custom collections. A group found in groups/custom is marked IsCustom.
        Results are cached for the length of the run.
    #>
    param([string]$Name)

    $key = "anygroups|$Name"
    if ($script:LookupCache.ContainsKey($key)) { return $script:LookupCache[$key] }

    $seen = @{}
    $hits = [System.Collections.Generic.List[object]]::new()
    $custom = @(Find-ZNItemsByName -Endpoint 'groups/custom' -Name $Name)
    foreach ($g in $custom) {
        if ($seen.ContainsKey([string]$g.id)) { continue }
        $seen[[string]$g.id] = $true
        $hits.Add([pscustomobject]@{ id = [string]$g.id; name = [string]$g.name; IsCustom = $true })
    }
    $all = @(Find-ZNItemsByName -Endpoint 'groups' -Name $Name)
    foreach ($g in $all) {
        if ($seen.ContainsKey([string]$g.id)) { continue }
        $seen[[string]$g.id] = $true
        $hits.Add([pscustomobject]@{ id = [string]$g.id; name = [string]$g.name; IsCustom = $false })
    }
    $result = $hits.ToArray()
    $script:LookupCache[$key] = $result
    return $result
}

function Find-ZNUsersAndAliasesByName {
    <#
    .SYNOPSIS
        Finds user accounts and IP aliases with an exact (case-insensitive) name match, using one member-candidates call.
    .PARAMETER Name
        Name to match.
    .OUTPUTS
        System.Object[] of unique matches (by id). Each has id, name and Kind (User for u: ids, Alias for e:i: ids).
    .NOTES
        Calls GET groups/custom/member-candidates once per name. The response may be an array or an object with items.
        Other candidate kinds are ignored.
    #>
    param([string]$Name)

    $key = "candidates|$Name"
    if ($script:LookupCache.ContainsKey($key)) { return $script:LookupCache[$key] }

    $response = Invoke-ApiRequest -Method GET -ApiEndpoint 'groups/custom/member-candidates' -QueryParams @{ _search = $Name; _limit = 100 }
    # A bare array with one element unrolls to a single object, so a lone object without items is one candidate.
    $candidates = @()
    if ($response -is [pscustomobject] -and $response.PSObject.Properties.Name -contains 'items') {
        if ($null -ne $response.items) { $candidates = @($response.items) }
    }
    elseif ($null -ne $response) {
        $candidates = @($response)
    }

    $seen = @{}
    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $candidates) {
        $id = [string]$c.id
        if (-not [string]::Equals([string]$c.name, $Name, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($seen.ContainsKey($id)) { continue }
        $kind = if ($id.StartsWith('u:', [StringComparison]::Ordinal)) { 'User' }
        elseif ($id.StartsWith('e:i:', [StringComparison]::Ordinal)) { 'Alias' }
        else { $null }
        if (-not $kind) { continue }
        $seen[$id] = $true
        $hits.Add([pscustomobject]@{ id = $id; name = [string]$c.name; Kind = $kind })
    }
    $result = $hits.ToArray()
    $script:LookupCache[$key] = $result
    return $result
}

function Resolve-ZNEntity {
    <#
    .SYNOPSIS
        Resolves one entityName to a member ID, or to a CSV-defined group name.
    .PARAMETER Text
        The entityName text.
    .PARAMETER CsvGroupNames
        Hashtable of group names defined as targetGroupName in the CSV (name to canonical name). Empty in removal modes.
    .OUTPUTS
        PSCustomObject with Ok, Kind (Subnet, Domain, Fqdn, Asset, Group, User, Alias), Id, Display, CsvGroup,
        IsBare, IsCustom, Error and Warnings (collision notes, empty when only one tier matched).
    .NOTES
        Name lookup tiers: active asset, then group of any kind (plus CSV-defined groups), then user account,
        then IP alias. Same-tier duplicates are errors. When several tiers match, the highest tier wins.
        The FQDN fallback applies only when nothing matched.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [hashtable]$CsvGroupNames = @{}
    )

    $fail = { param($reason) [pscustomobject]@{ Ok = $false; Kind = $null; Id = $null; Display = $Text; CsvGroup = $null; IsBare = $false; IsCustom = $false; Error = $reason; Warnings = @() } }

    $kind = Get-ZNEntityKind -Value $Text
    switch ($kind.Kind) {
        'Invalid' { return & $fail $kind.Reason }
        'Subnet' {
            return [pscustomobject]@{ Ok = $true; Kind = 'Subnet'; Id = $kind.Id; Display = $kind.Display; CsvGroup = $null; IsBare = $kind.IsBare; IsCustom = $false; Error = $null; Warnings = @() }
        }
        'Domain' {
            return [pscustomobject]@{ Ok = $true; Kind = 'Domain'; Id = $kind.Id; Display = $kind.Display; CsvGroup = $null; IsBare = $false; IsCustom = $false; Error = $null; Warnings = @() }
        }
    }

    # Tier lookups. Every tier is checked so that collisions can be reported. Same-tier duplicates are errors.
    $assets = @(Find-ZNAssetsByName -Name $Text)
    if ($assets.Count -gt 1) {
        return & $fail "$($assets.Count) active assets are named '$Text'; cannot choose one."
    }

    $anyGroups = @(Find-ZNAnyGroupsByName -Name $Text)
    if ($anyGroups.Count -gt 1) {
        return & $fail "$($anyGroups.Count) groups are named '$Text'; cannot choose one."
    }

    $csvGroup = $null
    if ($CsvGroupNames.ContainsKey($Text)) { $csvGroup = [string]$CsvGroupNames[$Text] }

    $candidates = @(Find-ZNUsersAndAliasesByName -Name $Text)
    $users = @($candidates | Where-Object { $_.Kind -eq 'User' })
    $aliases = @($candidates | Where-Object { $_.Kind -eq 'Alias' })
    if ($users.Count -gt 1) {
        return & $fail "$($users.Count) user accounts are named '$Text'; cannot choose one."
    }
    if ($aliases.Count -gt 1) {
        return & $fail "$($aliases.Count) IP aliases are named '$Text'; cannot choose one."
    }

    # Tier matches, in fixed priority order: asset > group > user > alias.
    $matched = [System.Collections.Generic.List[string]]::new()
    if ($assets.Count -eq 1) { $matched.Add('asset') }
    if ($anyGroups.Count -eq 1 -or $csvGroup) { $matched.Add('group') }
    if ($users.Count -eq 1) { $matched.Add('user') }
    if ($aliases.Count -eq 1) { $matched.Add('alias') }

    if ($matched.Count -eq 0) {
        if ($kind.IsFqdn) {
            return [pscustomobject]@{ Ok = $true; Kind = 'Fqdn'; Id = (ConvertTo-ZNFqdnId -Name $Text); Display = $Text.ToLowerInvariant(); CsvGroup = $null; IsBare = $false; IsCustom = $false; Error = $null; Warnings = @() }
        }
        return & $fail "'$Text' was not found as an active asset, group, user account or IP alias, and is not a valid FQDN, IP, or subnet."
    }

    $warnings = @()
    if ($matched.Count -gt 1) {
        $warnings = @("'$Text' matched $($matched -join ', '); used $($matched[0]) (priority: asset > group > user > alias)")
    }

    switch ($matched[0]) {
        'asset' {
            return [pscustomobject]@{ Ok = $true; Kind = 'Asset'; Id = [string]$assets[0].id; Display = [string]$assets[0].name; CsvGroup = $null; IsBare = $false; IsCustom = $false; Error = $null; Warnings = $warnings }
        }
        'group' {
            if ($anyGroups.Count -eq 1) {
                return [pscustomobject]@{ Ok = $true; Kind = 'Group'; Id = [string]$anyGroups[0].id; Display = [string]$anyGroups[0].name; CsvGroup = $null; IsBare = $false; IsCustom = [bool]$anyGroups[0].IsCustom; Error = $null; Warnings = $warnings }
            }
            return [pscustomobject]@{ Ok = $true; Kind = 'Group'; Id = $null; Display = $csvGroup; CsvGroup = $csvGroup; IsBare = $false; IsCustom = $true; Error = $null; Warnings = $warnings }
        }
        'user' {
            return [pscustomobject]@{ Ok = $true; Kind = 'User'; Id = [string]$users[0].id; Display = [string]$users[0].name; CsvGroup = $null; IsBare = $false; IsCustom = $false; Error = $null; Warnings = $warnings }
        }
        'alias' {
            return [pscustomobject]@{ Ok = $true; Kind = 'Alias'; Id = [string]$aliases[0].id; Display = [string]$aliases[0].name; CsvGroup = $null; IsBare = $false; IsCustom = $false; Error = $null; Warnings = $warnings }
        }
    }
}

function Find-ZNItemsById {
    <#
    .SYNOPSIS
        Finds items whose id exactly matches, using an id filter on a collection endpoint.
    .PARAMETER Endpoint
        Collection endpoint: assets, groups or users.
    .PARAMETER FilterId
        Filter name for the id: assetId, groupId or userId.
    .PARAMETER Id
        ID to match (case-sensitive).
    .PARAMETER ShowInactive
        Also return inactive items (showInactive=true). Used only to explain why an asset ID does not resolve.
    .OUTPUTS
        System.Object[] of unique matches.
    .NOTES
        Each returned item is checked against the requested ID, so an ignored filter cannot produce a false match.
        Results are cached per endpoint, ID and showInactive setting for the length of the run.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$FilterId,
        [Parameter(Mandatory = $true)][string]$Id,
        [switch]$ShowInactive
    )

    $key = "byid|$Endpoint|$FilterId|$Id|$([bool]$ShowInactive)"
    if ($script:LookupCache.ContainsKey($key)) { return $script:LookupCache[$key] }

    $extra = @{}
    if ($ShowInactive) { $extra['showInactive'] = 'true' }
    $items = Get-ZNFilteredItems -Endpoint $Endpoint -Filters @(@{ id = $FilterId; includeValues = @($Id) }) -ExtraQuery $extra
    $seen = @{}
    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $items) {
        if ([string]$item.id -cne $Id) { continue }
        if ($seen.ContainsKey([string]$item.id)) { continue }
        $seen[[string]$item.id] = $true
        $hits.Add($item)
    }
    $result = $hits.ToArray()
    $script:LookupCache[$key] = $result
    return $result
}

function Find-ZNIpAliasById {
    <#
    .SYNOPSIS
        Looks up one IP alias by ID with GET ip-aliases/{id}.
    .PARAMETER Id
        Alias ID (e:i: followed by 8 letters or digits).
    .OUTPUTS
        System.Object[] with zero or one alias object.
    .NOTES
        HTTP 404 means the alias does not exist. Other errors are thrown. Results are cached for the length of the run.
    #>
    param([Parameter(Mandatory = $true)][string]$Id)

    $key = "alias|$Id"
    if ($script:LookupCache.ContainsKey($key)) { return $script:LookupCache[$key] }

    $found = @()
    try {
        $response = Invoke-ApiRequest -Method GET -ApiEndpoint "ip-aliases/$Id"
        if ($null -ne $response) { $found = @($response) }
    }
    catch {
        if ($_.Exception.Message -notmatch 'failed with HTTP 404\b') { throw }
    }
    $script:LookupCache[$key] = $found
    return $found
}

function Resolve-ZNEntityId {
    <#
    .SYNOPSIS
        Validates one entityId from the CSV and returns a result in the same shape as Resolve-ZNEntity.
    .PARAMETER Id
        The entityId text.
    .PARAMETER Row
        CSV row number, used in the mismatch warning.
    .PARAMETER EntityName
        The entityName on the same row, if any. It is never used for resolution. It only produces a warning
        when it differs from the validated entity's real name.
    .PARAMETER CsvGroupIds
        Hashtable of existing target group ID to CSV group name. A group ID found here resolves to that CSV group.
    .OUTPUTS
        PSCustomObject with Ok, Kind (Subnet, Domain, Fqdn, Asset, Group, User, Alias), Id, Display, CsvGroup,
        IsBare, IsCustom, Error and Warnings.
    .NOTES
        Format is checked against the Zero Networks entity ID patterns, then the entity is checked to exist (and to be active,
        for assets) with a read-only GET. Subnet, FQDN and wildcard domain IDs are encoded values, so only the format is checked.
        IP ranges (b:14, b:16) and other prefixes are rejected as unsupported.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [int]$Row = 0,
        [string]$EntityName = '',
        [hashtable]$CsvGroupIds = @{}
    )

    $v = $Id.Trim()
    $fail = { param($reason) [pscustomobject]@{ Ok = $false; Kind = $null; Id = $null; Display = $v; CsvGroup = $null; IsBare = $false; IsCustom = $false; Error = $reason; Warnings = @() } }
    $ok = { param($kind, $id, $display, $csvGroup, $isCustom) [pscustomobject]@{ Ok = $true; Kind = $kind; Id = $id; Display = $display; CsvGroup = $csvGroup; IsBare = $false; IsCustom = [bool]$isCustom; Error = $null; Warnings = @() } }

    # 1. Format (entity ID patterns). Case-sensitive, as the patterns are.
    $kind = $null
    $canonical = $v
    $hostName = $null
    if ($v -cmatch '^a:[a-z]:[A-Za-z0-9]{8}$') { $kind = 'Asset' }
    elseif ($v -cmatch '^g:[a-z]:[A-Za-z0-9]{8}$') { $kind = 'Group' }
    elseif ($v -cmatch '^u:[a-z]:[A-Za-z0-9]{8}$') { $kind = 'User' }
    elseif ($v -cmatch '^e:i:[A-Za-z0-9]{8}$') { $kind = 'Alias' }
    elseif (($v -cmatch '^b:12[0-9a-f]{10}$') -or ($v -cmatch '^b:15[0-9a-f]{34}$')) { $kind = 'Subnet' }
    elseif ($v -cmatch '^b:17(.+)$') {
        $hostName = $Matches[1].ToLowerInvariant()
        if (-not (Test-ZNHostname -Value $hostName)) {
            return & $fail "malformed entity ID '$v': b:17 must be followed by a valid fully qualified domain name."
        }
        $kind = 'Fqdn'
        $canonical = 'b:17' + $hostName
    }
    elseif ($v -cmatch '^b:18\*\.(.+)$') {
        $hostName = $Matches[1].ToLowerInvariant()
        if (-not (Test-ZNHostname -Value $hostName)) {
            return & $fail "malformed entity ID '$v': b:18 must be followed by *. and a valid domain name."
        }
        $kind = 'Domain'
        $canonical = 'b:18*.' + $hostName
    }
    elseif ($v -cmatch '^a:') { return & $fail "malformed entity ID '$v': an asset ID has the form a:<letter>:<8 letters or digits>." }
    elseif ($v -cmatch '^g:') { return & $fail "malformed entity ID '$v': a group ID has the form g:<letter>:<8 letters or digits>." }
    elseif ($v -cmatch '^u:') { return & $fail "malformed entity ID '$v': a user account ID has the form u:<letter>:<8 letters or digits>." }
    elseif ($v -cmatch '^e:i:') { return & $fail "malformed entity ID '$v': an IP alias ID has the form e:i:<8 letters or digits>." }
    elseif ($v -cmatch '^b:(12|15|17|18)') { return & $fail "malformed entity ID '$v': subnet, FQDN and domain IDs must follow the encoded formats (b:12 + 10 hex digits, b:15 + 34 hex digits, b:17<fqdn>, b:18*.<domain>)." }
    elseif ($v -cmatch '^b:') { return & $fail "unsupported entity ID type '$v': IP ranges and other b: entities are not supported. Use individual subnets instead." }
    elseif ($v -cmatch '^[a-z]:') { return & $fail "unsupported entity ID type '$v' (prefix '$($Matches[0])'). Supported: asset, group, user account, IP alias, subnet, FQDN and wildcard domain IDs." }
    else { return & $fail "malformed entity ID '$v'; expected a prefix such as a:, g:, u:, e:i:, or b: followed by an encoded value." }

    # 2. Existence (and active state for assets). Subnet, FQDN and domain IDs have no backing object to check.
    switch ($kind) {
        'Asset' {
            $hits = @(Find-ZNItemsById -Endpoint 'assets' -FilterId 'assetId' -Id $v)
            if ($hits.Count -eq 0) {
                $inactive = @(Find-ZNItemsById -Endpoint 'assets' -FilterId 'assetId' -Id $v -ShowInactive)
                if ($inactive.Count -gt 0) { return & $fail "asset ID '$v' exists but is not active; only active assets can be members." }
                return & $fail "asset ID '$v' was not found."
            }
            if ($hits.Count -gt 1) { return & $fail "asset ID '$v' matched $($hits.Count) assets; cannot choose one." }
            $display = [string]$hits[0].name
            if (-not $display) { $display = $v }
            $result = & $ok 'Asset' $v $display $null $false
        }
        'Group' {
            $hits = @(Find-ZNItemsById -Endpoint 'groups' -FilterId 'groupId' -Id $v)
            if ($hits.Count -eq 0) { return & $fail "group ID '$v' was not found." }
            if ($hits.Count -gt 1) { return & $fail "group ID '$v' matched $($hits.Count) groups; cannot choose one." }
            $isCustom = $v.StartsWith('g:c:', [StringComparison]::Ordinal)
            $display = [string]$hits[0].name
            if (-not $display) { $display = $v }
            if ($CsvGroupIds.ContainsKey($v)) {
                # An existing target group of this CSV: map to the CSV node so ordering and depth stay correct.
                $csvName = [string]$CsvGroupIds[$v]
                $result = & $ok 'Group' $null $csvName $csvName $true
            }
            else {
                $result = & $ok 'Group' $v $display $null $isCustom
            }
        }
        'User' {
            $hits = @(Find-ZNItemsById -Endpoint 'users' -FilterId 'userId' -Id $v)
            if ($hits.Count -eq 0) { return & $fail "user account ID '$v' was not found." }
            if ($hits.Count -gt 1) { return & $fail "user account ID '$v' matched $($hits.Count) users; cannot choose one." }
            $display = [string]$hits[0].name
            if (-not $display) { $display = $v }
            $result = & $ok 'User' $v $display $null $false
        }
        'Alias' {
            $hits = @(Find-ZNIpAliasById -Id $v)
            if ($hits.Count -eq 0) { return & $fail "IP alias ID '$v' was not found." }
            $display = [string]$hits[0].name
            if (-not $display) { $display = $v }
            $result = & $ok 'Alias' $v $display $null $false
        }
        'Subnet' {
            try { $decoded = ConvertFrom-ZNSubnetId -Id $v }
            catch { return & $fail "malformed entity ID '$v': $($_.Exception.Message)" }
            $result = & $ok 'Subnet' $v $decoded.Display $null $false
        }
        'Fqdn' { $result = & $ok 'Fqdn' $canonical $hostName $null $false }
        'Domain' { $result = & $ok 'Domain' $canonical ('*.' + $hostName) $null $false }
    }

    # 3. Warn when entityName (ignored for resolution) names a different entity than entityId.
    $warn = [System.Collections.Generic.List[string]]::new()
    $nameText = $EntityName.Trim()
    if ($nameText) {
        $nameInfo = Get-ZNEntityKind -Value $nameText
        $sameEntity = if ($nameInfo.Kind -in @('Subnet', 'Domain')) {
            [string]::Equals([string]$nameInfo.Id, [string]$result.Id, [StringComparison]::OrdinalIgnoreCase)
        }
        elseif ($nameInfo.IsFqdn) {
            [string]::Equals((ConvertTo-ZNFqdnId -Name $nameText), [string]$result.Id, [StringComparison]::OrdinalIgnoreCase)
        }
        else {
            [string]::Equals($nameText, [string]$result.Display, [StringComparison]::OrdinalIgnoreCase)
        }
        if (-not $sameEntity) {
            $warn.Add("row ${Row}: entityName '$nameText' ignored; entityId resolves to '$($result.Display)'")
        }
    }
    $result.Warnings = $warn.ToArray()
    return $result
}

function Get-ZNGroupMemberIds {
    <#
    .SYNOPSIS
        Returns the IDs of the current direct members of a custom group.
    .PARAMETER GroupId
        Custom group ID (g:c:...).
    .OUTPUTS
        System.String[].
    #>
    param([Parameter(Mandatory = $true)][string]$GroupId)

    $ids = [System.Collections.Generic.List[string]]::new()
    $query = @{}
    $seen = @{}
    do {
        $response = Invoke-ApiRequest -Method GET -ApiEndpoint "groups/custom/$GroupId/members" -QueryParams $query
        if ($null -ne $response -and $null -ne $response.membersId) {
            foreach ($id in $response.membersId) { $ids.Add([string]$id) }
        }
        $cursor = if ($null -ne $response) { [string]$response.nextCursor } else { '' }
        if ($cursor -and $seen.ContainsKey($cursor)) { throw "Pagination cursor repeated for group $GroupId members." }
        if ($cursor) { $seen[$cursor] = $true; $query['_cursor'] = $cursor }
    } while ($cursor)
    return $ids.ToArray()
}

function Add-ZNMissingMembers {
    <#
    .SYNOPSIS
        Adds member IDs to a custom group, skipping IDs already present, in batches of 50.
    .PARAMETER GroupId
        Custom group ID.
    .PARAMETER MemberIds
        Member IDs to ensure are present.
    .OUTPUTS
        System.String[] of IDs that were actually added.
    #>
    param([Parameter(Mandatory = $true)][string]$GroupId, [string[]]$MemberIds)

    $wanted = @($MemberIds | Where-Object { $_ } | Select-Object -Unique)
    if ($wanted.Count -eq 0) { return @() }

    $current = @(Get-ZNGroupMemberIds -GroupId $GroupId)
    $missing = @($wanted | Where-Object { $current -notcontains $_ })
    for ($i = 0; $i -lt $missing.Count; $i += 50) {
        $end = [Math]::Min($i + 49, $missing.Count - 1)
        $batch = [string[]]$missing[$i..$end]
        Invoke-ApiRequest -Method PUT -ApiEndpoint "groups/custom/$GroupId/members" -Body @{ membersId = $batch } | Out-Null
    }
    return $missing
}

function Remove-ZNMembers {
    <#
    .SYNOPSIS
        Removes member IDs from a custom group in batches of 50.
    .PARAMETER GroupId
        Custom group ID.
    .PARAMETER MemberIds
        Member IDs to remove.
    .OUTPUTS
        None.
    #>
    param([Parameter(Mandatory = $true)][string]$GroupId, [string[]]$MemberIds)

    $ids = @($MemberIds | Where-Object { $_ })
    for ($i = 0; $i -lt $ids.Count; $i += 50) {
        $end = [Math]::Min($i + 49, $ids.Count - 1)
        $batch = [string[]]$ids[$i..$end]
        Invoke-ApiRequest -Method DELETE -ApiEndpoint "groups/custom/$GroupId/members" -Body @{ membersId = $batch } | Out-Null
    }
}

function Find-ZNParentGroupIds {
    <#
    .SYNOPSIS
        Finds custom groups that directly contain the given group as a member (best effort).
    .PARAMETER GroupId
        Custom group ID.
    .OUTPUTS
        System.String[] of parent group IDs.
    .NOTES
        Candidates come from a directMemberOf filter. Each candidate is verified by reading its members,
        so an ignored filter only costs extra reads and cannot produce false parents.
    #>
    param([Parameter(Mandatory = $true)][string]$GroupId)

    try {
        $candidates = @(Get-ZNFilteredItems -Endpoint 'groups/custom' -Filters @(@{ id = 'directMemberOf'; includeValues = @($GroupId) }))
    }
    catch {
        Write-Warning "Could not look up parent groups of $GroupId (directMemberOf filter): $($_.Exception.Message). Continuing without unlinking it."
        return @()
    }

    $parents = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $candidates) {
        if ([string]$c.id -eq $GroupId) { continue }
        $members = @(Get-ZNGroupMemberIds -GroupId ([string]$c.id))
        if ($members -contains $GroupId) { $parents.Add([string]$c.id) }
    }
    return $parents.ToArray()
}

# ---------------------------------------------------------------------------
# Planning: classify, resolve, validate and order everything before any write.
# ---------------------------------------------------------------------------

function Build-ZNPlan {
    <#
    .SYNOPSIS
        Runs the full read-only pre-flight for a CSV and returns the plan.
    .PARAMETER Rows
        Output of Import-ZNGroupCsv.
    .PARAMETER Mode
        Create, RemoveMembers or RemoveGroupsAndMembers.
    .PARAMETER SiteGroups
        Enforce Sites layout rules.
    .PARAMETER SkipResolveErrors
        Skip unresolvable member rows instead of throwing.
    .OUTPUTS
        PSCustomObject with Mode, Nodes, Order (node objects in dependency order), Skipped, Warnings (model
        conflicts, entityId/entityName mismatch notes, depth notes), Collisions (name-collision notes resolved by
        priority, de-duplicated), MaxDepth.
    .NOTES
        Throws with all fatal problems listed when anything would make the run unsafe. Makes only GET requests.
    #>
    param(
        [Parameter(Mandatory = $true)][object[]]$Rows,
        [Parameter(Mandatory = $true)][ValidateSet('Create', 'RemoveMembers', 'RemoveGroupsAndMembers')][string]$Mode,
        [switch]$SiteGroups,
        [switch]$SkipResolveErrors
    )

    $isCreate = ($Mode -eq 'Create')
    $model = New-ZNGroupModel -Rows $Rows -Mode $Mode
    $nodes = $model.Nodes
    $order = @($model.Order)
    $fatal = [System.Collections.Generic.List[string]]::new()
    $unresolved = [System.Collections.Generic.List[object]]::new()
    $collisions = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($w in $model.Warnings) { $warnings.Add($w) }

    $csvNames = @{}
    if ($isCreate) { foreach ($n in $order) { $csvNames[$n] = $n } }

    # 1. Existing target groups.
    foreach ($name in $order) {
        $node = $nodes[$name]
        $existing = @(Find-ZNCustomGroupsByName -Name $name)
        if ($existing.Count -gt 1) {
            $fatal.Add("Group '$name': $($existing.Count) custom groups share this name; cannot choose one.")
            continue
        }
        if ($existing.Count -eq 1) {
            $node.ExistingId = [string]$existing[0].id
            continue
        }
        if ($isCreate) {
            $nonCustom = @(Find-ZNAnyGroupsByName -Name $name | Where-Object { -not $_.IsCustom })
            if ($nonCustom.Count -gt 0) {
                $fatal.Add("Group '$name': a non-custom group has this name, but targetGroupName must be a custom group. Choose a different targetGroupName.")
                continue
            }
        }
        if (-not $isCreate) {
            $node.Missing = $true
            if ($node.Members.Count -eq 0) {
                $unresolved.Add([pscustomobject]@{ Row = $node.Rows[0]; Group = $name; Entity = '(group)'; Reason = "custom group '$name' does not exist." })
            }
            foreach ($m in $node.Members) {
                $unresolved.Add([pscustomobject]@{ Row = $m.Row; Group = $name; Entity = $m.Text; Reason = "custom group '$name' does not exist." })
            }
        }
    }

    # 2. Resolve members (not needed for RemoveGroupsAndMembers, which only uses names for ordering).
    if ($Mode -ne 'RemoveGroupsAndMembers') {
        # Existing target groups that are defined in the CSV, keyed by ID. A group member with one of these IDs
        # maps back to the CSV node (Create only; removal modes never create CSV nodes).
        $csvIdMap = @{}
        if ($isCreate) {
            foreach ($n in $order) {
                if ($nodes[$n].ExistingId) { $csvIdMap[[string]$nodes[$n].ExistingId] = $n }
            }
        }
        foreach ($name in $order) {
            $node = $nodes[$name]
            if ($node.Missing) { continue }
            $seen = @{}
            foreach ($m in $node.Members) {
                if ($m.Id) {
                    # entityId path: no name lookups. entityName (if any) only feeds the mismatch warning.
                    $res = Resolve-ZNEntityId -Id $m.Id -Row $m.Row -EntityName $m.EntityName -CsvGroupIds $csvIdMap
                    $entityLabel = $m.Id
                    if ($res.Ok) {
                        $isSelf = ($res.CsvGroup -and $res.CsvGroup -ceq $name) -or ($res.Id -and $node.ExistingId -and $res.Id -ceq [string]$node.ExistingId)
                        if ($isSelf) {
                            $res = [pscustomobject]@{ Ok = $false; Error = "entityId '$($m.Id)' is the target group itself; a group cannot be a member of itself." }
                        }
                    }
                    foreach ($c in @($res.Warnings)) {
                        if ($warnings -notcontains $c) { $warnings.Add($c) }
                    }
                }
                else {
                    $res = Resolve-ZNEntity -Text $m.Text -CsvGroupNames $csvNames
                    $entityLabel = $m.Text
                    foreach ($c in @($res.Warnings)) {
                        if ($collisions -notcontains $c) { $collisions.Add($c) }
                        Write-Verbose "Row $($m.Row): $c."
                    }
                }
                if (-not $res.Ok) {
                    $unresolved.Add([pscustomobject]@{ Row = $m.Row; Group = $name; Entity = $entityLabel; Reason = $res.Error })
                    continue
                }
                $key = if ($res.CsvGroup) { "csv:$($res.CsvGroup)" } else { "$($res.Kind):$($res.Id)" }
                if ($seen.ContainsKey($key)) {
                    Write-Verbose "Row $($m.Row): '$($m.Text)' is already a member of '$name'; ignoring the duplicate."
                    continue
                }
                $seen[$key] = $true
                if ($res.IsBare) { Write-Verbose "Row $($m.Row): bare address '$($m.Text)' treated as $($res.Display)." }
                $node.Resolved.Add([pscustomobject]@{
                        Row      = $m.Row
                        Text     = $m.Text
                        Kind     = $res.Kind
                        Id       = $res.Id
                        Display  = $res.Display
                        CsvGroup = $res.CsvGroup
                        IsBare   = $res.IsBare
                        IsCustom = $res.IsCustom
                    })
            }
        }
    }

    # 3. Parent groups (Create only).
    if ($isCreate) {
        foreach ($name in $order) {
            $node = $nodes[$name]
            if (-not $node.ParentName) { continue }
            if ($nodes.ContainsKey($node.ParentName)) {
                $node.ParentNode = $nodes[$node.ParentName]
                continue
            }
            $parents = @(Find-ZNCustomGroupsByName -Name $node.ParentName)
            if ($parents.Count -eq 0) {
                $nonCustom = @(Find-ZNAnyGroupsByName -Name $node.ParentName | Where-Object { -not $_.IsCustom })
                if ($nonCustom.Count -gt 0) {
                    $fatal.Add("Group '$name': parent group '$($node.ParentName)' matches only a non-custom group; parentGroup must be a custom group.")
                }
                else {
                    $fatal.Add("Group '$name': parent group '$($node.ParentName)' does not exist as a custom group and is not defined in the CSV.")
                }
            }
            elseif ($parents.Count -gt 1) {
                $fatal.Add("Group '$name': parent group '$($node.ParentName)' matches $($parents.Count) custom groups; cannot choose one.")
            }
            else {
                $node.ParentId = [string]$parents[0].id
            }
        }
    }

    $active = @($order | ForEach-Object { $nodes[$_] } | Where-Object { -not $_.Missing })

    # 4. Site rules (never skippable).
    if ($SiteGroups) {
        foreach ($v in @(Get-ZNSiteViolations -Nodes $active -Mode $Mode)) { $fatal.Add("Site rule: $v") }
    }

    if ($fatal.Count -gt 0) {
        throw ("Pre-flight validation failed; no changes were made:`n - " + ($fatal -join "`n - "))
    }
    if ($unresolved.Count -gt 0 -and -not $SkipResolveErrors) {
        $lines = $unresolved | ForEach-Object { "row $($_.Row) [$($_.Group)] '$($_.Entity)': $($_.Reason)" }
        throw ("Could not resolve $($unresolved.Count) entit(y/ies); no changes were made. Fix the CSV or re-run with -SkipResolveErrors:`n - " + ($lines -join "`n - "))
    }

    # 5. Dependency order (Create and RemoveGroupsAndMembers; RemoveMembers does not need one).
    $ordered = @($active)
    if ($Mode -ne 'RemoveMembers') {
        $requires = @{}
        foreach ($n in $active) {
            if (-not $requires.ContainsKey($n.Name)) { $requires[$n.Name] = [System.Collections.Generic.List[string]]::new() }
        }
        foreach ($n in $active) {
            foreach ($r in $n.Resolved) {
                if ($r.CsvGroup -and $requires.ContainsKey($r.CsvGroup)) { $requires[$n.Name].Add($r.CsvGroup) }
            }
            if ($Mode -eq 'RemoveGroupsAndMembers') {
                foreach ($m in $n.Members) {
                    if ($requires.ContainsKey($m.Text)) { $requires[$n.Name].Add($m.Text) }
                }
            }
            if ($isCreate -and $n.ParentNode -and $requires.ContainsKey($n.ParentNode.Name)) {
                $requires[$n.ParentNode.Name].Add($n.Name)
            }
            if ($Mode -eq 'RemoveGroupsAndMembers' -and $n.ParentName -and $requires.ContainsKey($n.ParentName)) {
                $requires[$n.ParentName].Add($n.Name)
            }
        }
        $activeNames = @($active | ForEach-Object { $_.Name })
        $sorted = Get-ZNCreateOrder -Names $activeNames -Requires $requires
        $ordered = @($sorted | ForEach-Object { $nodes[$_] })
    }

    # 6. Hierarchy depth (warning only).
    $maxDepth = 0
    if ($isCreate -and $ordered.Count -gt 0) {
        $linkNodes = @($ordered | ForEach-Object { $_ })
        $maxDepth = Get-ZNSiteDepth -Nodes $linkNodes
        if ($SiteGroups -and $maxDepth -gt 3) {
            $warnings.Add("The hierarchy is $maxDepth levels deep; the Sites guide recommends 2 to 3.")
        }
    }

    return [pscustomobject]@{
        Mode       = $Mode
        SiteGroups = [bool]$SiteGroups
        Nodes      = $nodes
        Order      = $ordered
        CsvNodes   = @($active)
        Skipped    = $unresolved.ToArray()
        Warnings   = $warnings.ToArray()
        Collisions = $collisions.ToArray()
        MaxDepth   = $maxDepth
    }
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

function Write-ZNRunReport {
    <#
    .SYNOPSIS
        Prints the final report: group table, detail rows, skipped entities, and failures.
    .PARAMETER Title
        Report heading.
    .PARAMETER GroupRows
        Per-group summary objects.
    .PARAMETER DetailRows
        Per-member detail objects.
    .PARAMETER Skipped
        Skipped entity objects.
    .PARAMETER Failures
        Failure messages.
    .PARAMETER Collisions
        Name-collision notes that were resolved by priority.
    .PARAMETER Warnings
        Other pre-flight warnings (for example entityName ignored because entityId was given).
    .OUTPUTS
        None.
    #>
    param(
        [string]$Title,
        [object[]]$GroupRows = @(),
        [object[]]$DetailRows = @(),
        [object[]]$Skipped = @(),
        [string[]]$Failures = @(),
        [string[]]$Collisions = @(),
        [string[]]$Warnings = @()
    )

    Write-Host ''
    Write-Host "=== $Title ==="
    if ($GroupRows.Count -gt 0) { $GroupRows | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host }
    if ($DetailRows.Count -gt 0) {
        Write-Host 'Member detail:'
        $DetailRows | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    }
    if ($Warnings.Count -gt 0) {
        Write-Host "Warnings ($($Warnings.Count)):" -ForegroundColor Yellow
        foreach ($w in $Warnings) { Write-Host "  $w" -ForegroundColor Yellow }
    }
    if ($Collisions.Count -gt 0) {
        Write-Host "Name collisions resolved by priority ($($Collisions.Count)):" -ForegroundColor Yellow
        foreach ($c in $Collisions) { Write-Host "  $c" -ForegroundColor Yellow }
    }
    if ($Skipped.Count -gt 0) {
        Write-Host "Skipped entities ($($Skipped.Count)):" -ForegroundColor Yellow
        foreach ($s in $Skipped) { Write-Host "  row $($s.Row) [$($s.Group)] '$($s.Entity)': $($s.Reason)" -ForegroundColor Yellow }
    }
    if ($Failures.Count -gt 0) {
        Write-Host "Failures ($($Failures.Count)):" -ForegroundColor Red
        foreach ($f in $Failures) { Write-Host "  $f" -ForegroundColor Red }
    }
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

function Invoke-ZNCreateMode {
    <#
    .SYNOPSIS
        Creates missing groups, then adds members and parent links, in dependency order.
    .PARAMETER Plan
        Output of Build-ZNPlan (Mode Create).
    .PARAMETER Force
        Skip the confirmation prompt.
    .PARAMETER Cmdlet
        The calling cmdlet's $PSCmdlet, used for ShouldProcess.
    .PARAMETER SiteMapPath
        Site map file path (only used when Plan.SiteGroups is set). Empty means the default file name in the current directory.
    .PARAMETER CsvName
        CSV file name shown in the site map header.
    .OUTPUTS
        System.Int32 exit code.
    #>
    param($Plan, [switch]$Force, [System.Management.Automation.PSCmdlet]$Cmdlet, [string]$SiteMapPath = '', [string]$CsvName = '')

    $nodes = $Plan.Nodes

    # Writes the site hierarchy map (only with -SiteGroups). A failure is a warning, never a run failure.
    $writeSiteMap = {
        param([string]$ModeText)
        try {
            $mapPath = if ($SiteMapPath) {
                $SiteMapPath
            }
            else {
                Join-Path -Path (Get-Location).Path -ChildPath ('site-hierarchy-{0}.md' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            }
            $siteModel = Get-ZNSiteMapModel -Nodes $Plan.CsvNodes
            $md = ConvertTo-ZNSiteMapMarkdown -Model $siteModel -Mode $ModeText -TenantHost ([uri]$script:ApiBaseUrl).Host -CsvName $CsvName -Generated (Get-Date)
            $written = Write-ZNSiteMap -Path $mapPath -Content $md
            Write-Host "Site hierarchy map written: $written"
        }
        catch {
            Write-Warning "Could not write the site hierarchy map: $($_.Exception.Message)"
        }
    }
    $order = @($Plan.Order)
    $failures = [System.Collections.Generic.List[string]]::new()

    $toCreate = @($order | Where-Object { -not $_.ExistingId })
    $existing = @($order | Where-Object { $_.ExistingId })
    $parentLinks = @($order | Where-Object { $_.ParentNode -or $_.ParentId })
    $memberCount = @($order | ForEach-Object { $_.Resolved.Count } | Measure-Object -Sum).Sum

    Write-Host ''
    Write-Host "Plan: create $($toCreate.Count) group(s) [$(@($toCreate | ForEach-Object { $_.Name }) -join ', ')]"
    Write-Host "      reuse $($existing.Count) existing group(s) [$(@($existing | ForEach-Object { $_.Name }) -join ', ')]"
    Write-Host "      add up to $memberCount member(s) across $($order.Count) group(s); $($parentLinks.Count) parent link(s)."
    foreach ($w in $Plan.Warnings) { Write-Warning $w }
    foreach ($c in $Plan.Collisions) { Write-Warning $c }

    if (-not $Cmdlet.ShouldProcess($script:ApiBaseUrl, "Create or update $($order.Count) custom group(s)")) {
        Write-Host 'No changes made (WhatIf or declined).'
        if ($Plan.SiteGroups -and $WhatIfPreference) { & $writeSiteMap 'Dry run preview' }
        return 0
    }
    if (-not (Confirm-ZNRun -Prompt 'Apply these changes' -Force:$Force)) {
        Write-Host 'Aborted. No changes made.'
        return 0
    }

    # Phase 1: create missing groups in dependency order.
    foreach ($node in $order) {
        if ($node.ExistingId) {
            $node.Id = $node.ExistingId
            $node.Status = 'Unchanged'
            continue
        }
        try {
            $desc = if ($node.Description) { $node.Description } else { 'Created by New-ZNCustomGroupsFromCsv.ps1' }
            $resp = Invoke-ApiRequest -Method POST -ApiEndpoint 'groups/custom' -Body @{ name = $node.Name; description = $desc }
            $newId = if ($null -ne $resp -and $null -ne $resp.entity) { [string]$resp.entity.id } else { '' }
            if (-not $newId) { throw 'the response did not include entity.id' }
            $node.Id = $newId
            $node.Status = 'Created'
            Write-Host "Created group '$($node.Name)' ($newId)"
        }
        catch {
            $node.Failed = $true
            $node.Status = 'Failed'
            $failures.Add("Create group '$($node.Name)': $($_.Exception.Message)")
        }
    }

    $detail = [System.Collections.Generic.List[object]]::new()

    # Phase 2: add members (groups that were not created or failed are skipped).
    foreach ($node in $order) {
        if ($node.Failed) { continue }
        $blocked = @($node.Resolved | Where-Object { $_.CsvGroup -and $nodes[$_.CsvGroup].Failed })
        if ($blocked.Count -gt 0) {
            $failures.Add("Group '$($node.Name)': member group(s) $((@($blocked | ForEach-Object { $_.CsvGroup })) -join ', ') failed to create; their membership was not added.")
            $node.Failed = $true
            $node.Status = 'Failed'
            continue
        }
        $desired = [System.Collections.Generic.List[string]]::new()
        $byId = @{}
        foreach ($r in $node.Resolved) {
            $id = if ($r.CsvGroup) { [string]$nodes[$r.CsvGroup].Id } else { [string]$r.Id }
            $desired.Add($id)
            $byId[$id] = $r
        }
        try {
            $added = @(Add-ZNMissingMembers -GroupId $node.Id -MemberIds $desired.ToArray())
            foreach ($id in $added) {
                $r = $byId[$id]
                $detail.Add([pscustomobject]@{ Group = $node.Name; Kind = $r.Kind; Entity = $r.Display; Id = $id })
            }
            if ($added.Count -gt 0 -and $node.Status -eq 'Unchanged') { $node.Status = 'Updated' }
            Write-Host "Group '$($node.Name)': added $($added.Count) of $($desired.Count) member(s)."
        }
        catch {
            $node.Failed = $true
            $node.Status = 'Failed'
            $failures.Add("Add members to '$($node.Name)': $($_.Exception.Message)")
        }
    }

    # Phase 3: parent links (child group ID added to the parent's members).
    foreach ($node in $order) {
        if ($node.Failed) { continue }
        $parentNode = $node.ParentNode
        if (-not $parentNode -and -not $node.ParentId) { continue }
        $parentId = if ($parentNode) { [string]$parentNode.Id } else { [string]$node.ParentId }
        $parentLabel = if ($parentNode) { $parentNode.Name } else { $node.ParentName }
        if ($parentNode -and $parentNode.Failed) {
            $failures.Add("Link '$($node.Name)' under '$parentLabel': parent group failed to create.")
            $node.Failed = $true
            $node.Status = 'Failed'
            continue
        }
        try {
            $added = @(Add-ZNMissingMembers -GroupId $parentId -MemberIds @([string]$node.Id))
            if ($added.Count -gt 0) {
                $node.Notes = "linked under '$parentLabel'"
                $detail.Add([pscustomobject]@{ Group = $parentLabel; Kind = 'ParentLink'; Entity = $node.Name; Id = [string]$node.Id })
                if ($parentNode -and $parentNode.Status -eq 'Unchanged') { $parentNode.Status = 'Updated' }
            }
            else {
                $node.Notes = "already under '$parentLabel'"
            }
        }
        catch {
            $node.Failed = $true
            $node.Status = 'Failed'
            $failures.Add("Link '$($node.Name)' under '$parentLabel': $($_.Exception.Message)")
        }
    }

    $groupRows = @($order | ForEach-Object {
            [pscustomobject]@{
                Group       = $_.Name
                Status      = $_.Status
                Id          = $_.Id
                Parent      = if ($_.ParentName) { $_.ParentName } else { '' }
                ParentLink  = if ($_.Notes) { $_.Notes } else { '' }
            }
        })
    Write-ZNRunReport -Title 'Create custom groups from CSV' -GroupRows $groupRows -DetailRows $detail.ToArray() -Skipped $Plan.Skipped -Failures $failures.ToArray() -Collisions $Plan.Collisions -Warnings $Plan.Warnings
    if ($Plan.SiteGroups) { Write-Host 'Reminder: enable the Sites feature in Zero Networks once the groups are in place.' }

    $totals = @($order | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    Write-Host "Totals: $totals; skipped=$($Plan.Skipped.Count); failures=$($failures.Count)"
    if ($Plan.SiteGroups) { & $writeSiteMap 'Executed' }
    if ($failures.Count -gt 0) { return 1 }
    return 0
}

function Invoke-ZNRemoveMembersMode {
    <#
    .SYNOPSIS
        Removes the listed members from their target groups. Groups are kept.
    .PARAMETER Plan
        Output of Build-ZNPlan (Mode RemoveMembers).
    .PARAMETER Force
        Skip the confirmation prompt.
    .PARAMETER Cmdlet
        The calling cmdlet's $PSCmdlet, used for ShouldProcess.
    .OUTPUTS
        System.Int32 exit code.
    #>
    param($Plan, [switch]$Force, [System.Management.Automation.PSCmdlet]$Cmdlet)

    $failures = [System.Collections.Generic.List[string]]::new()
    $work = [System.Collections.Generic.List[object]]::new()
    $detail = [System.Collections.Generic.List[object]]::new()

    foreach ($node in $Plan.Order) {
        $current = @(Get-ZNGroupMemberIds -GroupId $node.ExistingId)
        $toRemove = @($node.Resolved | Where-Object { $current -contains $_.Id })
        $notMember = @($node.Resolved | Where-Object { $current -notcontains $_.Id })
        foreach ($r in $notMember) {
            $detail.Add([pscustomobject]@{ Group = $node.Name; Kind = $r.Kind; Entity = $r.Display; Id = $r.Id; Result = 'NotAMember' })
        }
        $work.Add([pscustomobject]@{ Node = $node; ToRemove = $toRemove; NotMember = $notMember; Removed = 0 })
    }

    $totalRemove = (@($work | ForEach-Object { $_.ToRemove.Count }) | Measure-Object -Sum).Sum
    $totalAbsent = (@($work | ForEach-Object { $_.NotMember.Count }) | Measure-Object -Sum).Sum
    Write-Host ''
    Write-Host "Plan: remove $totalRemove member(s) from $($work.Count) group(s); $totalAbsent already absent."
    foreach ($w in $work) {
        Write-Host "  - '$($w.Node.Name)': remove $($w.ToRemove.Count), not a member $($w.NotMember.Count)"
    }
    foreach ($w in $Plan.Warnings) { Write-Warning $w }
    foreach ($c in $Plan.Collisions) { Write-Warning $c }

    if ($totalRemove -eq 0) {
        Write-Host 'Nothing to remove.'
        Write-ZNRunReport -Title 'Remove members from CSV' -Skipped $Plan.Skipped -Collisions $Plan.Collisions -Warnings $Plan.Warnings
        return 0
    }
    if (-not $Cmdlet.ShouldProcess($script:ApiBaseUrl, "Remove $totalRemove member(s) from custom group(s)")) {
        Write-Host 'No changes made (WhatIf or declined).'
        return 0
    }
    if (-not (Confirm-ZNRun -Prompt "Remove $totalRemove member(s) from $($work.Count) group(s)" -Force:$Force)) {
        Write-Host 'Aborted. No changes made.'
        return 0
    }

    foreach ($w in $work) {
        if ($w.ToRemove.Count -eq 0) { continue }
        try {
            Remove-ZNMembers -GroupId $w.Node.ExistingId -MemberIds @($w.ToRemove | ForEach-Object { $_.Id })
            $w.Removed = $w.ToRemove.Count
            foreach ($r in $w.ToRemove) {
                $detail.Add([pscustomobject]@{ Group = $w.Node.Name; Kind = $r.Kind; Entity = $r.Display; Id = $r.Id; Result = 'Removed' })
            }
        }
        catch {
            $failures.Add("Remove members from '$($w.Node.Name)': $($_.Exception.Message)")
        }
    }

    $groupRows = @($work | ForEach-Object {
            [pscustomobject]@{ Group = $_.Node.Name; Id = $_.Node.ExistingId; Removed = $_.Removed; NotAMember = $_.NotMember.Count }
        })
    Write-ZNRunReport -Title 'Remove members from CSV' -GroupRows $groupRows -DetailRows $detail.ToArray() -Skipped $Plan.Skipped -Failures $failures.ToArray() -Collisions $Plan.Collisions -Warnings $Plan.Warnings
    if ($failures.Count -gt 0) { return 1 }
    return 0
}

function Invoke-ZNRemoveGroupsMode {
    <#
    .SYNOPSIS
        Empties each target group, unlinks it from parents, and deletes it. Children are processed before parents.
    .PARAMETER Plan
        Output of Build-ZNPlan (Mode RemoveGroupsAndMembers).
    .PARAMETER Force
        Skip the confirmation prompt.
    .PARAMETER Cmdlet
        The calling cmdlet's $PSCmdlet, used for ShouldProcess.
    .OUTPUTS
        System.Int32 exit code.
    #>
    param($Plan, [switch]$Force, [System.Management.Automation.PSCmdlet]$Cmdlet)

    $failures = [System.Collections.Generic.List[string]]::new()
    $work = [System.Collections.Generic.List[object]]::new()

    # Deletion order is the reverse of the dependency order: children first.
    $deleteOrder = @($Plan.Order)
    [array]::Reverse($deleteOrder)

    foreach ($node in $deleteOrder) {
        $members = @(Get-ZNGroupMemberIds -GroupId $node.ExistingId)
        $parents = @(Find-ZNParentGroupIds -GroupId $node.ExistingId)
        $work.Add([pscustomobject]@{ Node = $node; Members = $members; Parents = $parents; Status = 'Pending'; Notes = '' })
    }

    $totalMembers = (@($work | ForEach-Object { $_.Members.Count }) | Measure-Object -Sum).Sum
    $totalParents = (@($work | ForEach-Object { $_.Parents.Count }) | Measure-Object -Sum).Sum
    Write-Host ''
    Write-Host "Plan: empty and DELETE $($work.Count) group(s): $(@($work | ForEach-Object { $_.Node.Name }) -join ', ')"
    Write-Host "      remove $totalMembers member(s) in total and unlink from $totalParents parent group(s)."
    foreach ($w in $work) {
        Write-Host "  - '$($w.Node.Name)': $($w.Members.Count) member(s), $($w.Parents.Count) parent link(s), then delete"
    }
    foreach ($w in $Plan.Warnings) { Write-Warning $w }
    foreach ($c in $Plan.Collisions) { Write-Warning $c }

    if (-not $Cmdlet.ShouldProcess($script:ApiBaseUrl, "Empty and delete $($work.Count) custom group(s)")) {
        Write-Host 'No changes made (WhatIf or declined).'
        return 0
    }
    if (-not (Confirm-ZNRun -Prompt "Delete $($work.Count) group(s) and remove their members" -Force:$Force)) {
        Write-Host 'Aborted. No changes made.'
        return 0
    }

    foreach ($w in $work) {
        $name = $w.Node.Name
        $id = $w.Node.ExistingId
        try {
            if ($w.Members.Count -gt 0) { Remove-ZNMembers -GroupId $id -MemberIds $w.Members }
        }
        catch {
            $w.Status = 'EmptyFailed'
            $failures.Add("Empty group '$name': $($_.Exception.Message)")
            continue
        }
        $unlinkFailed = $false
        foreach ($parentId in $w.Parents) {
            try { Remove-ZNMembers -GroupId $parentId -MemberIds @($id) }
            catch {
                $unlinkFailed = $true
                $failures.Add("Unlink group '$name' from parent $parentId : $($_.Exception.Message)")
            }
        }
        try {
            Invoke-ApiRequest -Method DELETE -ApiEndpoint "groups/custom/$id" | Out-Null
            $w.Status = if ($unlinkFailed) { 'Deleted (unlink failed)' } else { 'Deleted' }
        }
        catch {
            $w.Status = 'Emptied, DeleteFailed'
            $failures.Add("Delete group '$name': $($_.Exception.Message)")
        }
    }

    $groupRows = @($work | ForEach-Object {
            [pscustomobject]@{ Group = $_.Node.Name; Id = $_.Node.ExistingId; Members = $_.Members.Count; ParentLinks = $_.Parents.Count; Status = $_.Status }
        })
    Write-ZNRunReport -Title 'Remove groups and members from CSV' -GroupRows $groupRows -Skipped $Plan.Skipped -Failures $failures.ToArray() -Collisions $Plan.Collisions -Warnings $Plan.Warnings
    if ($failures.Count -gt 0) { return 1 }
    return 0
}

# ---------------------------------------------------------------------------
# Entry point. Skipped when this file is dot-sourced (InvocationName '.').
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = 1
    if ($DryRun) { $WhatIfPreference = $true }
    try {
        $mode = $PSCmdlet.ParameterSetName
        $friendlyMode = switch ($mode) {
            'RemoveMembers' { 'RemoveMembers' }
            'RemoveGroupsAndMembers' { 'RemoveGroupsAndMembers' }
            default { 'Create' }
        }

        if ($PSBoundParameters.ContainsKey('SiteMapPath')) {
            if ([string]::IsNullOrWhiteSpace($SiteMapPath)) { throw '-SiteMapPath must not be empty.' }
            if (-not $SiteGroups) { throw '-SiteMapPath can only be used together with -SiteGroups.' }
            if ($friendlyMode -ne 'Create') { throw '-SiteMapPath cannot be used with -RemoveMembers or -RemoveGroupsAndMembers; the site map is only written in create mode.' }
        }

        $rows = @(Import-ZNGroupCsv -Path $CsvPath)

        $ApiKey = Get-ZNApiKey -ApiKey $ApiKey
        $script:ApiBaseUrl = ConvertTo-ZNApiBaseUrl -PortalUrl $PortalUrl
        $script:Headers = @{ Accept = 'application/json'; Authorization = $ApiKey }
        $script:LookupCache = @{}
        Write-Host "Tenant API: $script:ApiBaseUrl (key $(Get-ZNMaskedKey -Key $ApiKey))"

        $plan = Build-ZNPlan -Rows $rows -Mode $friendlyMode -SiteGroups:$SiteGroups -SkipResolveErrors:$SkipResolveErrors

        $exitCode = switch ($friendlyMode) {
            'Create' { Invoke-ZNCreateMode -Plan $plan -Force:$Force -Cmdlet $PSCmdlet -SiteMapPath $SiteMapPath -CsvName (Split-Path -Leaf $CsvPath) }
            'RemoveMembers' { Invoke-ZNRemoveMembersMode -Plan $plan -Force:$Force -Cmdlet $PSCmdlet }
            'RemoveGroupsAndMembers' { Invoke-ZNRemoveGroupsMode -Plan $plan -Force:$Force -Cmdlet $PSCmdlet }
        }
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $exitCode = 1
    }
    exit $exitCode
}
