<#
.SYNOPSIS
Creates, updates, or removes Zero Networks custom groups in bulk from a CSV file.

.DESCRIPTION
Reads a CSV in which each row adds one member (asset, subnet, IP, FQDN, wildcard domain, or
another group) to a target custom group. Groups that do not exist are created; existing groups
are reused and only missing members are added, so the script is safe to re-run. Parent groups
can be declared with parentGroup, which nests the target group under the parent.

The whole CSV is resolved and validated before anything is written: every entityName is
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

The API key is read from -ApiKey or prompted for as a secure string. It is never written to
the console or to verbose output.

.PARAMETER CsvPath
Path to the CSV file. Required columns: entityName, targetGroupName, newGroupDescription,
parentGroup. Each row adds one member (entityName) to targetGroupName. A row with an empty
entityName only defines the group.

.PARAMETER PortalUrl
Tenant portal host, for example mycompany-admin.zeronetworks.com. A leading scheme, trailing
slash, or /api/v1 suffix is accepted and removed.

.PARAMETER ApiKey
Zero Networks API key. If omitted, the script prompts for it as a secure string.

.PARAMETER SkipResolveErrors
Skip member rows that cannot be resolved (missing or ambiguous assets and groups) instead of
stopping. Skipped rows are listed at the end of the run. Site rule violations are never skipped.

.PARAMETER SiteGroups
Validate the CSV against the Sites layout rules before any change is made. Bare IP addresses are
converted to /32 (IPv4) or /128 (IPv6).

.PARAMETER RemoveMembers
Remove the listed entityName members from each targetGroupName. Groups are kept. The
newGroupDescription and parentGroup columns are ignored in this mode.

.PARAMETER RemoveGroupsAndMembers
Remove every member from each targetGroupName, unlink the group from its parent groups, and
delete the group. The entityName column is used only to determine deletion order.

.PARAMETER Force
Skip the confirmation prompt for the removal modes. Without -Force, a non-interactive session
aborts.

.EXAMPLE
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -WhatIf

.EXAMPLE
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\site-groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -SiteGroups

.NOTES
Requires PowerShell 7.0 or later.
Endpoints: POST groups/custom, PUT and DELETE groups/custom/{id}/members, GET groups/custom/{id}/members,
DELETE groups/custom/{id}, and GET assets, groups/custom, and groups with _filters on name.
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

    [Parameter(ParameterSetName = 'RemoveMembers')]
    [switch]$RemoveMembers,

    [Parameter(ParameterSetName = 'RemoveGroupsAndMembers')]
    [switch]$RemoveGroupsAndMembers,

    [switch]$Force
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
        PSCustomObject[] with Row, EntityName, TargetGroupName, NewGroupDescription, ParentGroup.
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

    $rows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $records.Count; $i++) {
        $rec = $records[$i]
        $rowNo = $i + 1
        $values = @{}
        foreach ($req in $required) { $values[$req] = ([string]$rec.($propFor[$req])).Trim() }

        if (@($values.Values | Where-Object { $_ -ne '' }).Count -eq 0) { continue }
        if ($values['targetGroupName'] -eq '') {
            throw "CSV data row $rowNo : targetGroupName is required."
        }

        $rows.Add([pscustomobject]@{
                Row                 = $rowNo
                EntityName          = $values['entityName']
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
        if ($r.EntityName) {
            $node.Members.Add([pscustomobject]@{ Row = $r.Row; Text = $r.EntityName })
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
                    $hasChildGroup = $true
                    $gname = if ($r.CsvGroup) { $r.CsvGroup } else { $r.Display }
                    if (-not $gname.StartsWith('Site_', [StringComparison]::Ordinal)) {
                        $violations.Add("$where contains group '$gname', which is not a Site_ group.")
                    }
                }
                default {
                    $violations.Add("$where contains '$($r.Text)' ($($r.Kind)); Site groups accept only subnets (parents accept only child Site_ groups).")
                }
            }
        }
        if ($Mode -eq 'Create' -and $hasSubnet -and $hasChildGroup) {
            $violations.Add("$where mixes subnets with child groups; leaf Site groups hold subnets only and parent Site groups hold only child Site_ groups.")
        }
    }
    return $violations.ToArray()
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
    .OUTPUTS
        System.Object[] of items.
    #>
    param([string]$Endpoint, [object[]]$Filters)

    $filterJson = ConvertTo-Json -InputObject @($Filters) -Depth 5 -Compress
    $items = Invoke-PaginatedApiRequest -Method GET -ApiEndpoint $Endpoint -QueryParams @{ _limit = 100; _filters = $filterJson }
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

function Resolve-ZNEntity {
    <#
    .SYNOPSIS
        Resolves one entityName to a member ID, or to a CSV-defined group name.
    .PARAMETER Text
        The entityName text.
    .PARAMETER CsvGroupNames
        Hashtable of group names defined as targetGroupName in the CSV (name to canonical name). Empty in removal modes.
    .OUTPUTS
        PSCustomObject with Ok, Kind (Subnet, Domain, Fqdn, Asset, Group), Id, Display, CsvGroup, IsBare, Error.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [hashtable]$CsvGroupNames = @{}
    )

    $fail = { param($reason) [pscustomobject]@{ Ok = $false; Kind = $null; Id = $null; Display = $Text; CsvGroup = $null; IsBare = $false; Error = $reason } }

    $kind = Get-ZNEntityKind -Value $Text
    switch ($kind.Kind) {
        'Invalid' { return & $fail $kind.Reason }
        'Subnet' {
            return [pscustomobject]@{ Ok = $true; Kind = 'Subnet'; Id = $kind.Id; Display = $kind.Display; CsvGroup = $null; IsBare = $kind.IsBare; Error = $null }
        }
        'Domain' {
            return [pscustomobject]@{ Ok = $true; Kind = 'Domain'; Id = $kind.Id; Display = $kind.Display; CsvGroup = $null; IsBare = $false; Error = $null }
        }
    }

    $assets = @(Find-ZNAssetsByName -Name $Text)
    if ($assets.Count -gt 1) {
        return & $fail "$($assets.Count) active assets are named '$Text'; cannot choose one."
    }

    $apiGroups = @(Find-ZNCustomGroupsByName -Name $Text)
    if ($apiGroups.Count -gt 1) {
        return & $fail "$($apiGroups.Count) custom groups are named '$Text'; cannot choose one."
    }

    $csvGroup = $null
    if ($CsvGroupNames.ContainsKey($Text)) { $csvGroup = [string]$CsvGroupNames[$Text] }

    if ($assets.Count -eq 1 -and ($apiGroups.Count -eq 1 -or $csvGroup)) {
        return & $fail "'$Text' matches both an active asset and a custom group; cannot tell which is meant."
    }

    if ($assets.Count -eq 1) {
        return [pscustomobject]@{ Ok = $true; Kind = 'Asset'; Id = [string]$assets[0].id; Display = [string]$assets[0].name; CsvGroup = $null; IsBare = $false; Error = $null }
    }
    if ($apiGroups.Count -eq 1) {
        return [pscustomobject]@{ Ok = $true; Kind = 'Group'; Id = [string]$apiGroups[0].id; Display = [string]$apiGroups[0].name; CsvGroup = $null; IsBare = $false; Error = $null }
    }
    if ($csvGroup) {
        return [pscustomobject]@{ Ok = $true; Kind = 'Group'; Id = $null; Display = $csvGroup; CsvGroup = $csvGroup; IsBare = $false; Error = $null }
    }
    if ($kind.IsFqdn) {
        return [pscustomobject]@{ Ok = $true; Kind = 'Fqdn'; Id = (ConvertTo-ZNFqdnId -Name $Text); Display = $Text.ToLowerInvariant(); CsvGroup = $null; IsBare = $false; Error = $null }
    }
    return & $fail "'$Text' was not found as an active asset or custom group, and is not a valid FQDN, IP, or subnet."
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
        PSCustomObject with Mode, Nodes, Order (node objects in dependency order), Skipped, Warnings, MaxDepth.
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
        foreach ($name in $order) {
            $node = $nodes[$name]
            if ($node.Missing) { continue }
            $seen = @{}
            foreach ($m in $node.Members) {
                $res = Resolve-ZNEntity -Text $m.Text -CsvGroupNames $csvNames
                if (-not $res.Ok) {
                    $unresolved.Add([pscustomobject]@{ Row = $m.Row; Group = $name; Entity = $m.Text; Reason = $res.Error })
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
                $fatal.Add("Group '$name': parent group '$($node.ParentName)' does not exist as a custom group and is not defined in the CSV.")
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
    $warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($w in $model.Warnings) { $warnings.Add($w) }
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
        Skipped    = $unresolved.ToArray()
        Warnings   = $warnings.ToArray()
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
    .OUTPUTS
        None.
    #>
    param(
        [string]$Title,
        [object[]]$GroupRows = @(),
        [object[]]$DetailRows = @(),
        [object[]]$Skipped = @(),
        [string[]]$Failures = @()
    )

    Write-Host ''
    Write-Host "=== $Title ==="
    if ($GroupRows.Count -gt 0) { $GroupRows | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host }
    if ($DetailRows.Count -gt 0) {
        Write-Host 'Member detail:'
        $DetailRows | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
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
    .OUTPUTS
        System.Int32 exit code.
    #>
    param($Plan, [switch]$Force, [System.Management.Automation.PSCmdlet]$Cmdlet)

    $nodes = $Plan.Nodes
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

    if (-not $Cmdlet.ShouldProcess($script:ApiBaseUrl, "Create or update $($order.Count) custom group(s)")) {
        Write-Host 'No changes made (WhatIf or declined).'
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
    Write-ZNRunReport -Title 'Create custom groups from CSV' -GroupRows $groupRows -DetailRows $detail.ToArray() -Skipped $Plan.Skipped -Failures $failures.ToArray()
    if ($Plan.SiteGroups) { Write-Host 'Reminder: enable the Sites feature in Zero Networks once the groups are in place.' }

    $totals = @($order | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    Write-Host "Totals: $totals; skipped=$($Plan.Skipped.Count); failures=$($failures.Count)"
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

    if ($totalRemove -eq 0) {
        Write-Host 'Nothing to remove.'
        Write-ZNRunReport -Title 'Remove members from CSV' -Skipped $Plan.Skipped
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
    Write-ZNRunReport -Title 'Remove members from CSV' -GroupRows $groupRows -DetailRows $detail.ToArray() -Skipped $Plan.Skipped -Failures $failures.ToArray()
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
    Write-ZNRunReport -Title 'Remove groups and members from CSV' -GroupRows $groupRows -Skipped $Plan.Skipped -Failures $failures.ToArray()
    if ($failures.Count -gt 0) { return 1 }
    return 0
}

# ---------------------------------------------------------------------------
# Entry point. Skipped when this file is dot-sourced (InvocationName '.').
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = 1
    try {
        $mode = $PSCmdlet.ParameterSetName
        $friendlyMode = switch ($mode) {
            'RemoveMembers' { 'RemoveMembers' }
            'RemoveGroupsAndMembers' { 'RemoveGroupsAndMembers' }
            default { 'Create' }
        }

        $rows = @(Import-ZNGroupCsv -Path $CsvPath)

        $ApiKey = Get-ZNApiKey -ApiKey $ApiKey
        $script:ApiBaseUrl = ConvertTo-ZNApiBaseUrl -PortalUrl $PortalUrl
        $script:Headers = @{ Accept = 'application/json'; Authorization = $ApiKey }
        $script:LookupCache = @{}
        Write-Host "Tenant API: $script:ApiBaseUrl (key $(Get-ZNMaskedKey -Key $ApiKey))"

        $plan = Build-ZNPlan -Rows $rows -Mode $friendlyMode -SiteGroups:$SiteGroups -SkipResolveErrors:$SkipResolveErrors

        $exitCode = switch ($friendlyMode) {
            'Create' { Invoke-ZNCreateMode -Plan $plan -Force:$Force -Cmdlet $PSCmdlet }
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
