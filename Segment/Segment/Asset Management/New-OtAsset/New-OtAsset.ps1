#Requires -Version 7

<#
.SYNOPSIS
    Creates OT/IoT assets in a Zero Networks tenant, one at a time or in bulk from a CSV file, or
    marks the assets named in a CSV file as inactive.

.DESCRIPTION
    Creates OT/IoT assets through the Zero Networks API. Use -Ip and -Name for one asset, or
    -CsvFilePath for many. Every row is validated before anything is created. The check includes
    the tenant's existing OT assets, the switches and interfaces named in the row, and duplicates
    inside the file. Problems are reported for every row at once. By default, one invalid row
    stops the whole run, so nothing is created.

    CSV columns. The first line is the header. Header names are case-insensitive. Rows are
    numbered from the line after the header, so the first data line is "Row 1". Skipped blank
    lines still count.
      ipv4           Required. Dotted IPv4 address. No CIDR and no leading zeros.
                     0.0.0.0, 127.0.0.1 and 255.255.255.255 are not allowed.
      type           Required. OT/IoT type display name or numeric ID. Names are read live from
                     the tenant on every run. Matching ignores case, spaces and punctuation but
                     is otherwise exact. Use Get-OtAssetTypes.ps1 to list the valid values.
      displayName    Required. Name of the asset in the portal. Duplicate names are rejected.
      fqdn           Optional. Fully qualified domain name.
      switchId       Optional. Switch ID in the format w:x:XXXXXXXX. Use together with
                     interfaceName. Setting only one of the two is an error.
      interfaceName  Optional. Exact, case-sensitive name of an interface on that switch. Use
                     together with switchId.
    Extra columns are ignored with a warning. Fully blank lines are skipped.

    Single-asset mode uses -Ip and -Name, with optional -Type, -Fqdn, -SwitchId and
    -InterfaceName. -Type defaults to "OT Device". If that name is not offered by the tenant but
    type 135 is, type 135 is used instead. An explicit -Type never falls back.

    Inactivate mode uses -CsvFilePath with -MarkOtAssetsInactive. Nothing is created. Each row is
    matched to one active OT asset whose name equals displayName exactly (case-sensitive) and
    whose type equals the row's type. The matched assets are then marked inactive, at most 100
    per request. Only the type and displayName columns are required. The ipv4, fqdn, switchId
    and interfaceName columns are ignored, so the CSV file used to create the assets can be
    reused to clean them up. Rows that do not match exactly one asset are reported as NotFound,
    TypeMismatch or Ambiguous. An Invalid, TypeMismatch or Ambiguous row stops the whole run, so
    nothing is inactivated, unless -ContinueOnError is set. NotFound rows do not stop the run.
    Inactive assets can be made active again in the portal.

.PARAMETER CsvFilePath
    CSV mode. Path to a CSV file with the columns described in DESCRIPTION. The file must exist.

.PARAMETER MarkOtAssetsInactive
    CSV mode only. Marks the existing OT assets named in the CSV file as inactive instead of
    creating assets. See DESCRIPTION. Cannot be combined with -SkipExistingCheck or with the
    single-mode parameters. Needs an API key that is allowed to change assets.

.PARAMETER Comment
    Inactivate mode only. Optional comment sent with each inactivate request. Requires
    -MarkOtAssetsInactive.

.PARAMETER Ip
    Single mode. Dotted IPv4 address of the asset, for example 192.0.2.50. Required in single mode.

.PARAMETER Name
    Single mode. Display name of the asset in the portal. Required in single mode.

.PARAMETER Fqdn
    Single mode. Optional fully qualified domain name for the asset. When omitted, the server
    chooses the value.

.PARAMETER Type
    Single mode. OT/IoT type display name or numeric ID. Defaults to "OT Device" (see DESCRIPTION).

.PARAMETER SwitchId
    Single mode. Switch ID in the format w:x:XXXXXXXX. Must be used together with -InterfaceName.

.PARAMETER InterfaceName
    Single mode. Exact, case-sensitive name of an interface on the switch given by -SwitchId.
    Must be used together with -SwitchId.

.PARAMETER ApiKey
    Zero Networks API key. Requires a read-write key. Defaults to the ZN_API_KEY environment
    variable, which keeps the key out of shell history.

.PARAMETER PortalUrl
    Portal address, for example https://example-admin.zeronetworks.com. Overrides the host read
    from the API key. When omitted, the host is taken from the API key, and
    https://portal.zeronetworks.com is used if no host is found.

.PARAMETER DryRun
    Runs all validation and the read-only API lookups. Nothing is created or inactivated. Add
    -Verbose to see each request body. The body is also in the Request property of each result.

.PARAMETER ContinueOnError
    Creates the valid rows and skips the invalid ones. Also keeps going after an API failure
    for one row. The exit code is still non-zero if any row was not created. With
    -MarkOtAssetsInactive, inactivates the matched rows even when other rows did not match,
    and keeps going after a failed inactivate request.

.PARAMETER SkipExistingCheck
    Does not download the existing OT asset list. Duplicate IPs and names are then reported by
    the server, row by row, as Skipped. Not available with -MarkOtAssetsInactive.

.EXAMPLE
    ./New-OtAsset.ps1 -Ip 192.0.2.50 -Name "Boiler Room PLC"

    Creates one asset with the default type, OT Device.

.EXAMPLE
    ./New-OtAsset.ps1 -Ip 192.0.2.51 -Name "Boiler Room PLC 2" -Type "PLC" -Fqdn plc1.example.com

    Creates one asset with a named type and an FQDN.

.EXAMPLE
    ./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv

    Validates every row and creates all of them. Nothing is created if any row is invalid.

.EXAMPLE
    ./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -DryRun

    Validates the CSV file against the tenant. Nothing is created. Add -Verbose to also see the
    request bodies.

.EXAMPLE
    ./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -ContinueOnError

    Creates the valid rows, skips the invalid ones and reports them.

.EXAMPLE
    ./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -MarkOtAssetsInactive -DryRun

    Matches every row to an active OT asset by name and type and shows what would be marked
    inactive. Nothing is changed.

.EXAMPLE
    ./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -MarkOtAssetsInactive -Comment "Lab cleanup"

    Marks the matched assets inactive, with a comment. They can be made active again in the
    portal.

.NOTES
    Requires PowerShell 7.0 or later. Keep this script, Get-OtAssetTypes.ps1, OtAssetCommon.ps1 and
    New-OtAsset.format.ps1xml in the same folder. Needs a read-write API key. Prefer the ZN_API_KEY
    environment variable over -ApiKey so the key does not appear in shell history.

    Exit codes:
      0  Every row was created (or inactivated with -MarkOtAssetsInactive), or was a dry run.
      1  At least one row was not created or inactivated (Invalid, Skipped, NotFound,
         TypeMismatch, Ambiguous, Failed or NotAttempted).
      2  Setup error: no API key, unreadable CSV or missing columns, failure to read the type
         list or the existing assets, or a missing OtAssetCommon.ps1.

    Results are written to the pipeline as one object per row, with the properties Row, Name, Ip,
    TypeId, TypeName, Status, AssetId, Error and Request. They are shown as a table with the
    columns Row, Name, Ip, Type, type_name, Status and Detail (Error, or else AssetId), defined in
    New-OtAsset.format.ps1xml. With -MarkOtAssetsInactive, AssetId is the matched existing asset
    and Request is the inactivate request body that included it. The validation count and the summary go to the information
    stream. Per-row progress and request bodies go to the verbose stream.

.LINK
    README.md
#>

[CmdletBinding(DefaultParameterSetName = 'ByCsv')]
param(
    [Parameter(ParameterSetName = 'ByCsv', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCsvInactivate', Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvFilePath,

    [Parameter(ParameterSetName = 'ByCsvInactivate', Mandatory = $true)][switch]$MarkOtAssetsInactive,
    [Parameter(ParameterSetName = 'ByCsvInactivate', Mandatory = $false)][string]$Comment,

    [Parameter(ParameterSetName = 'BySingle', Mandatory = $true)]
    [ValidatePattern('^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$')]
    [string]$Ip,

    [Parameter(ParameterSetName = 'BySingle', Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
    [Parameter(ParameterSetName = 'BySingle', Mandatory = $false)][string]$Fqdn,
    [Parameter(ParameterSetName = 'BySingle', Mandatory = $false)][string]$Type = 'OT Device',
    [Parameter(ParameterSetName = 'BySingle', Mandatory = $false)][string]$SwitchId,
    [Parameter(ParameterSetName = 'BySingle', Mandatory = $false)][string]$InterfaceName,

    [Parameter(Mandatory = $false)][string]$ApiKey = $Env:ZN_API_KEY,
    [Parameter(Mandatory = $false)][string]$PortalUrl,
    [Parameter(Mandatory = $false)][switch]$DryRun,
    [Parameter(Mandatory = $false)][switch]$ContinueOnError,
    [Parameter(ParameterSetName = 'ByCsv', Mandatory = $false)]
    [Parameter(ParameterSetName = 'BySingle', Mandatory = $false)]
    [switch]$SkipExistingCheck
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('InformationAction')) { $InformationPreference = 'Continue' }
$commonPath = Join-Path -Path $PSScriptRoot -ChildPath 'OtAssetCommon.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    Write-Error -Message "Required helper file 'OtAssetCommon.ps1' was not found in '$PSScriptRoot'. Keep New-OtAsset.ps1, Get-OtAssetTypes.ps1 and OtAssetCommon.ps1 in the same folder." -ErrorAction Continue
    exit 2
}
. $commonPath

# Constants used by the validation functions below.
$script:Ipv4Pattern = '^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$'
$script:DisallowedIpv4 = @('0.0.0.0', '255.255.255.255', '127.0.0.1')
$script:SwitchIdPattern = '^w:[a-z]:[a-zA-Z0-9]{8}$'
# Interface lists per switch, filled by Get-SwitchInterfaceNames so each switch is fetched once.
$script:SwitchInterfaceCache = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)

<#
.SYNOPSIS
    Reads and validates the shape of an OT asset CSV file.

.DESCRIPTION
    Checks the header for the required columns, warns once about unused columns, and returns one
    object per data row. Blank lines are skipped, but they still count. The Row value is the line
    number after the header, so the first data line is Row 1.

.PARAMETER Path
    Path to the CSV file.

.PARAMETER NameAndTypeOnly
    Requires only the type and displayName columns. ipv4 becomes optional. Used by
    -MarkOtAssetsInactive.

.OUTPUTS
    System.Management.Automation.PSCustomObject[]. Each object has Row (int), Ipv4, Type,
    DisplayName, Fqdn, SwitchId and InterfaceName (trimmed strings, empty when absent).

.NOTES
    Throws when a required column is missing, when there are no data rows, or when a line cannot
    be parsed. The thrown message names the file.
#>
function Read-OtAssetCsv {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][switch]$NameAndTypeOnly
    )

    $lines = @(Get-Content -LiteralPath $Path)
    $headerLine = ''
    if ($lines.Count -gt 0) {
        $headerLine = ([string]$lines[0]).TrimStart([char]0xFEFF)
    }
    $headers = @($headerLine -split ',' | ForEach-Object { $_.Trim().Trim('"').Trim() } | Where-Object { $_ -ne '' })

    if ($NameAndTypeOnly) {
        $required = @('type', 'displayName')
        $optional = @('ipv4', 'fqdn', 'switchId', 'interfaceName')
    }
    else {
        $required = @('ipv4', 'type', 'displayName')
        $optional = @('fqdn', 'switchId', 'interfaceName')
    }
    $known = $required + $optional

    $missing = @($required | Where-Object { $headers -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw "CSV '$Path' is missing required column(s): $($missing -join ', '). Required: $($required -join ', '). Optional: $($optional -join ', ')."
    }

    $unused = @($headers | Where-Object { $known -notcontains $_ })
    if ($unused.Count -gt 0) {
        Write-Warning "CSV '$Path' has column(s) that are not used and will be ignored: $($unused -join ', ')"
    }

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    for ($index = 1; $index -lt $lines.Count; $index++) {
        $lineNumber = $index + 1
        $lineText = [string]$lines[$index]
        if ([string]::IsNullOrWhiteSpace($lineText)) { continue }

        try {
            $records = @(ConvertFrom-Csv -InputObject @($headerLine, $lineText))
        }
        catch {
            throw "CSV '$Path' line $lineNumber could not be parsed: $($_.Exception.Message)"
        }
        if ($records.Count -eq 0) { continue }
        $record = $records[0]

        $anyValue = $false
        foreach ($prop in $record.PSObject.Properties) {
            if (-not [string]::IsNullOrWhiteSpace([string]$prop.Value)) { $anyValue = $true; break }
        }
        if (-not $anyValue) { continue }

        $fields = @{}
        foreach ($name in $known) { $fields[$name] = '' }
        foreach ($name in $headers) {
            if ($known -notcontains $name) { continue }
            $prop = $record.PSObject.Properties[$name]
            if ($null -ne $prop -and $null -ne $prop.Value) {
                $fields[$name] = ([string]$prop.Value).Trim()
            }
        }

        $rows.Add([pscustomobject]@{
                Row           = [int]($lineNumber - 1)
                Ipv4          = [string]$fields['ipv4']
                Type          = [string]$fields['type']
                DisplayName   = [string]$fields['displayName']
                Fqdn          = [string]$fields['fqdn']
                SwitchId      = [string]$fields['switchId']
                InterfaceName = [string]$fields['interfaceName']
            })
    }

    if ($rows.Count -eq 0) {
        throw "CSV '$Path' contains no data rows."
    }

    return $rows.ToArray()
}

<#
.SYNOPSIS
    Calls a paged GET endpoint and returns every item.

.DESCRIPTION
    Sends the request with _limit = 400. In Cursor mode, each page's nextCursor is sent as _cursor
    on the next request until nextCursor is empty. In Offset mode, _offset starts at 0 and grows by
    400 per page, and paging stops when a page holds fewer than 400 items.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl.

.PARAMETER ApiKey
    API key for the tenant.

.PARAMETER Path
    API path that begins with '/'.

.PARAMETER Query
    Extra query parameters. The paging parameters are added by this function.

.PARAMETER ItemsProperty
    Name of the response property that holds the items. Defaults to 'items'.

.PARAMETER Mode
    Cursor or Offset. Defaults to Cursor.

.OUTPUTS
    System.Object[]. The items from every page, in order.

.NOTES
    Throws when more than 1000 pages are returned. Errors from Invoke-ZnRestMethod are not caught.
#>
function Invoke-ZnPaginatedGet {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][hashtable]$Query,
        [Parameter(Mandatory = $false)][string]$ItemsProperty = 'items',
        [Parameter(Mandatory = $false)][ValidateSet('Cursor', 'Offset')][string]$Mode = 'Cursor'
    )

    $pageSize = 400
    $maxPages = 1000

    $baseQuery = @{}
    if ($null -ne $Query) {
        foreach ($key in $Query.Keys) { $baseQuery[$key] = $Query[$key] }
    }
    $baseQuery['_limit'] = $pageSize

    $collected = [System.Collections.Generic.List[object]]::new()
    $pageCount = 0
    $offset = 0
    $cursor = ''
    while ($true) {
        $pageCount++
        if ($pageCount -gt $maxPages) {
            throw "GET $Path returned more than $maxPages pages; stopping."
        }

        $pageQuery = @{}
        foreach ($key in $baseQuery.Keys) { $pageQuery[$key] = $baseQuery[$key] }
        if ($Mode -eq 'Offset') {
            $pageQuery['_offset'] = $offset
        }
        elseif ($cursor -ne '') {
            $pageQuery['_cursor'] = $cursor
        }

        $response = Invoke-ZnRestMethod -Method GET -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -Path $Path -Query $pageQuery

        $itemCount = 0
        $pageItems = $null
        if ($null -ne $response) { $pageItems = $response.$ItemsProperty }
        if ($null -ne $pageItems) {
            foreach ($item in @($pageItems)) {
                $collected.Add($item)
                $itemCount++
            }
        }

        if ($Mode -eq 'Offset') {
            if ($itemCount -lt $pageSize) { break }
            $offset += $pageSize
        }
        else {
            $nextCursor = $null
            if ($null -ne $response) { $nextCursor = $response.nextCursor }
            if ($nextCursor -is [string] -and $nextCursor -ne '') {
                $cursor = $nextCursor
            }
            else {
                break
            }
        }
    }

    return $collected.ToArray()
}

<#
.SYNOPSIS
    Loads the tenant's active OT assets and indexes them by name and by IP address.

.DESCRIPTION
    Reads every active OT asset with cursor paging. Inactive assets are not requested. In ByName,
    names are matched case-insensitively. Each IPv4 address, both managed and non-organization,
    maps to its asset. When a name or address appears more than once, the first asset seen is
    kept. ByExactName maps each name (case-sensitive) to every asset with that name, as objects
    with Id, Name and TypeId. TypeId is read from the item's assetType field, or else its type
    field, and is $null when neither holds an integer.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl.

.PARAMETER ApiKey
    API key for the tenant.

.OUTPUTS
    PSCustomObject with ByName and ByIp hashtables, ByExactName (Dictionary of string to a List of
    objects) and HasTypeField (bool, true when any item had an assetType or type field).

.NOTES
    Throws on API failure. The caller reports that as a setup error.
#>
function Get-ExistingOtAssetIndex {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey
    )

    $items = @(Invoke-ZnPaginatedGet -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -Path '/assets/ot' -Mode Cursor)

    $byName = @{}
    $byIp = @{}
    $byExactName = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new([System.StringComparer]::Ordinal)
    $hasTypeField = $false
    foreach ($item in $items) {
        if ($null -eq $item) { continue }

        $name = [string]$item.name
        if ($name -ne '' -and -not $byName.ContainsKey($name)) {
            $byName[$name] = $item
        }

        if ($name -ne '') {
            $assetTypeId = $null
            $typeProperty = $item.PSObject.Properties['assetType']
            if ($null -eq $typeProperty) { $typeProperty = $item.PSObject.Properties['type'] }
            if ($null -ne $typeProperty) {
                $hasTypeField = $true
                $parsedType = 0
                if ([int]::TryParse([string]$typeProperty.Value, [ref]$parsedType)) { $assetTypeId = $parsedType }
            }
            if (-not $byExactName.ContainsKey($name)) {
                $byExactName[$name] = [System.Collections.Generic.List[object]]::new()
            }
            $byExactName[$name].Add([pscustomobject]@{ Id = [string]$item.id; Name = $name; TypeId = $assetTypeId })
        }

        $addresses = @(@($item.ipV4Addresses) + @($item.nonOrgIpV4Addresses))
        foreach ($address in $addresses) {
            if ($address -is [string] -and $address -ne '' -and -not $byIp.ContainsKey($address)) {
                $byIp[$address] = $item
            }
        }
    }

    return [pscustomobject]@{ ByName = $byName; ByIp = $byIp; ByExactName = $byExactName; HasTypeField = $hasTypeField }
}

<#
.SYNOPSIS
    Loads the tenant's switches and indexes them by switch ID.

.DESCRIPTION
    Reads every switch with offset paging. The dictionary uses an ordinal (case-sensitive) key
    comparison, because switch IDs are case-sensitive.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl.

.PARAMETER ApiKey
    API key for the tenant.

.OUTPUTS
    System.Collections.Generic.Dictionary[string,object]. Maps switch ID to the switch item.

.NOTES
    Throws on API failure. The caller decides whether that is fatal, because switch rows can still
    be reported when the switch list is unavailable.
#>
function Get-SwitchIndex {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string, object]])]
    param(
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey
    )

    $items = @(Invoke-ZnPaginatedGet -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -Path '/assets/switches' -Mode Offset -ItemsProperty 'items')

    $index = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($item in $items) {
        if ($null -eq $item) { continue }
        $id = [string]$item.id
        if ($id -ne '' -and -not $index.ContainsKey($id)) {
            $index[$id] = $item
        }
    }

    return , $index
}

<#
.SYNOPSIS
    Returns the interface names on one switch.

.DESCRIPTION
    Reads the interfaces of a switch with offset paging and returns their names. The result is
    cached per switch in script scope, so each switch is requested at most once per run. A failed
    request is cached too, and the same error is thrown for later calls.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl.

.PARAMETER ApiKey
    API key for the tenant.

.PARAMETER SwitchId
    Switch ID in the format w:x:XXXXXXXX. The caller checks the format first.

.OUTPUTS
    System.String[]. Interface names, case preserved.

.NOTES
    Throws on API failure, with the API error message.
#>
function Get-SwitchInterfaceNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)][string]$SwitchId
    )

    if ($script:SwitchInterfaceCache.ContainsKey($SwitchId)) {
        $cached = $script:SwitchInterfaceCache[$SwitchId]
        if ($null -ne $cached.Error) { throw [string]$cached.Error }
        return [string[]]$cached.Names
    }

    try {
        $items = @(Invoke-ZnPaginatedGet -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -Path "/assets/switches/$SwitchId/interfaces" -Mode Offset -ItemsProperty 'interfaces')
        $names = [string[]]@($items | ForEach-Object { [string]$_.name })
    }
    catch {
        $message = [string]$_.Exception.Message
        $script:SwitchInterfaceCache[$SwitchId] = [pscustomobject]@{ Names = [string[]]@(); Error = $message }
        throw $message
    }

    $script:SwitchInterfaceCache[$SwitchId] = [pscustomobject]@{ Names = $names; Error = $null }
    return $names
}

<#
.SYNOPSIS
    Finds rows that repeat an IP address or a display name within the file.

.DESCRIPTION
    Groups rows by IPv4 address (exact match) and by display name (case-insensitive). Every row in
    a group of two or more gets a message, so each duplicate is visible in the output. Blank values
    are not grouped.

.PARAMETER Rows
    Row objects from Read-OtAssetCsv or from single mode.

.PARAMETER NamesOnly
    Checks display names only, case-sensitively, and ignores IP addresses. Used by
    -MarkOtAssetsInactive, where names are matched exactly.

.OUTPUTS
    System.Collections.Hashtable. Maps row number (int) to a list of messages.

.NOTES
    Rows without any duplicate are not in the hashtable.
#>
function Get-InFileDuplicateErrors {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object[]]$Rows,
        [Parameter(Mandatory = $false)][switch]$NamesOnly
    )

    $map = @{}
    $candidates = @($Rows | Where-Object { $null -ne $_ })

    $ipGroups = @()
    if (-not $NamesOnly) {
        $ipGroups = @($candidates | Where-Object { $_.Ipv4 -ne '' } | Group-Object -Property Ipv4 | Where-Object { $_.Count -ge 2 })
    }
    foreach ($group in $ipGroups) {
        $rowText = (@($group.Group | ForEach-Object { $_.Row }) -join ', ')
        foreach ($member in $group.Group) {
            $key = [int]$member.Row
            if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[string]]::new() }
            $map[$key].Add("duplicate IP $($group.Name) in this file (rows $rowText)")
        }
    }

    $nameGroups = @($candidates | Where-Object { $_.DisplayName -ne '' } | Group-Object -Property DisplayName -CaseSensitive:$NamesOnly | Where-Object { $_.Count -ge 2 })
    foreach ($group in $nameGroups) {
        $rowText = (@($group.Group | ForEach-Object { $_.Row }) -join ', ')
        foreach ($member in $group.Group) {
            $key = [int]$member.Row
            if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[string]]::new() }
            $map[$key].Add("duplicate displayName '$($member.DisplayName)' in this file (rows $rowText)")
        }
    }

    return $map
}

<#
.SYNOPSIS
    Validates one row against the tenant and returns every error found.

.DESCRIPTION
    Runs the checks in a fixed order and collects all errors, without a row prefix. The checks are:
    IPv4 format and reserved addresses, display name, type resolution, the switchId and
    interfaceName pair, the switchId format, existing assets by name and by IP, and the switch and
    interface lookups. The switch and interface checks run only when both switch fields are set and
    the switch ID format is valid.

.PARAMETER Row
    Row object with Row, Ipv4, Type, DisplayName, Fqdn, SwitchId and InterfaceName.

.PARAMETER TypeList
    Type list returned by Get-OtAssetTypeList.

.PARAMETER ExistingIndex
    Index returned by Get-ExistingOtAssetIndex, or $null when the existing check is skipped.

.PARAMETER SwitchIndex
    Index returned by Get-SwitchIndex, or $null when it is not available.

.PARAMETER SwitchLookupError
    Message explaining why the switch index is not available, or $null.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl.

.PARAMETER ApiKey
    API key for the tenant.

.OUTPUTS
    PSCustomObject with Errors (string[]), TypeId (int, or $null when the type did not resolve) and
    TypeName (the tenant's name for TypeId, or $null).

.NOTES
    Writes a warning when the type resolves to 1001. Does not throw for validation problems.
#>
function Test-OtAssetRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Row,
        [Parameter(Mandatory = $true)][object[]]$TypeList,
        [Parameter(Mandatory = $false)][object]$ExistingIndex,
        [Parameter(Mandatory = $false)][System.Collections.Generic.Dictionary[string, object]]$SwitchIndex,
        [Parameter(Mandatory = $false)][string]$SwitchLookupError,
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey
    )

    $rowErrors = [System.Collections.Generic.List[string]]::new()
    $typeId = $null

    if ($Row.Ipv4 -eq '') {
        $rowErrors.Add('ipv4 is blank')
    }
    elseif ($Row.Ipv4 -notmatch $script:Ipv4Pattern) {
        $rowErrors.Add("ipv4 '$($Row.Ipv4)' is not a valid IPv4 address")
    }
    elseif ($script:DisallowedIpv4 -contains $Row.Ipv4) {
        $rowErrors.Add("ipv4 $($Row.Ipv4) is not allowed")
    }

    if ($Row.DisplayName -eq '') {
        $rowErrors.Add('displayName is blank')
    }

    try {
        $typeId = Resolve-OtAssetType -Value ([string]$Row.Type) -TypeList $TypeList
    }
    catch {
        $rowErrors.Add([string]$_.Exception.Message)
        $typeId = $null
    }

    $hasSwitch = ($Row.SwitchId -ne '')
    $hasInterface = ($Row.InterfaceName -ne '')
    if ($hasSwitch -xor $hasInterface) {
        $rowErrors.Add('switchId and interfaceName must be provided together')
    }
    $switchFormatOk = $false
    if ($hasSwitch) {
        if ($Row.SwitchId -cmatch $script:SwitchIdPattern) {
            $switchFormatOk = $true
        }
        else {
            $rowErrors.Add("switchId '$($Row.SwitchId)' is not a valid switch ID (expected format w:x:XXXXXXXX)")
        }
    }

    if ($null -ne $ExistingIndex) {
        if ($Row.DisplayName -ne '' -and $ExistingIndex.ByName.ContainsKey($Row.DisplayName)) {
            $hit = $ExistingIndex.ByName[$Row.DisplayName]
            $rowErrors.Add("an OT asset named '$([string]$hit.name)' already exists (id $([string]$hit.id))")
        }
        if ($Row.Ipv4 -ne '' -and $ExistingIndex.ByIp.ContainsKey($Row.Ipv4)) {
            $hit = $ExistingIndex.ByIp[$Row.Ipv4]
            $rowErrors.Add("an OT asset with IP $($Row.Ipv4) already exists ('$([string]$hit.name)', id $([string]$hit.id))")
        }
    }

    if ($hasSwitch -and $hasInterface -and $switchFormatOk) {
        $switchId = $Row.SwitchId
        if ($SwitchLookupError) {
            $rowErrors.Add("could not verify switch '$switchId': $SwitchLookupError")
        }
        elseif ($null -eq $SwitchIndex) {
            $rowErrors.Add("could not verify switch '$switchId': the switch list is not available")
        }
        elseif (-not $SwitchIndex.ContainsKey($switchId)) {
            $rowErrors.Add("switch '$switchId' not found")
        }
        else {
            $switchName = [string]$SwitchIndex[$switchId].name
            $names = $null
            try {
                $names = @(Get-SwitchInterfaceNames -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -SwitchId $switchId)
            }
            catch {
                $rowErrors.Add("could not list interfaces for switch '$switchName ($switchId)': $([string]$_.Exception.Message)")
            }

            if ($null -ne $names) {
                $interfaceName = $Row.InterfaceName
                if ($names -cnotcontains $interfaceName) {
                    $closest = @($names | Where-Object {
                            $_ -ne '' -and (
                                $_.IndexOf($interfaceName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                                $interfaceName.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
                            )
                        } | Select-Object -First 5)
                    $message = "interface '$interfaceName' not found on switch '$switchName ($switchId)'"
                    if ($closest.Count -gt 0) {
                        $message += ' Closest: ' + (@($closest | ForEach-Object { "'$_'" }) -join ', ')
                    }
                    $rowErrors.Add($message)
                }
            }
        }
    }

    return [pscustomobject]@{
        Errors   = [string[]]$rowErrors.ToArray()
        TypeId   = $typeId
        TypeName = (Get-OtAssetTypeName -TypeId $typeId -TypeList $TypeList)
    }
}

<#
.SYNOPSIS
    Builds the JSON body for one asset creation request.

.DESCRIPTION
    Returns an ordered dictionary with ipv4, type (as an integer), displayName, and then fqdn,
    switchId and interfaceName, but only when each is not blank.

.PARAMETER Row
    Valid row object from the validation step.

.PARAMETER TypeId
    Resolved numeric type ID.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary.

.NOTES
    The key order is fixed so that dry-run output is stable.
#>
function New-OtAssetBody {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Row,
        [Parameter(Mandatory = $true)][int]$TypeId
    )

    $body = [ordered]@{
        ipv4        = $Row.Ipv4
        type        = $TypeId
        displayName = $Row.DisplayName
    }
    if ($Row.Fqdn -ne '') { $body['fqdn'] = $Row.Fqdn }
    if ($Row.SwitchId -ne '') { $body['switchId'] = $Row.SwitchId }
    if ($Row.InterfaceName -ne '') { $body['interfaceName'] = $Row.InterfaceName }

    return $body
}

<#
.SYNOPSIS
    Returns the tenant's display name for an OT/IoT type ID.

.DESCRIPTION
    Looks the ID up in the type list returned by Get-OtAssetTypeList. The list is read live from
    the tenant, so no names are hard-coded here.

.PARAMETER TypeId
    Numeric type ID, or $null.

.PARAMETER TypeList
    Type list returned by Get-OtAssetTypeList.

.OUTPUTS
    System.String, or $null when TypeId is $null or not in the list.

.NOTES
    Never throws.
#>
function Get-OtAssetTypeName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)][AllowNull()][object]$TypeId,
        [Parameter(Mandatory = $true)][object[]]$TypeList
    )

    if ($null -eq $TypeId) { return $null }
    $hit = @($TypeList | Where-Object { [int]$_.Id -eq [int]$TypeId }) | Select-Object -First 1
    if ($null -eq $hit) { return $null }
    return [string]$hit.Name
}

<#
.SYNOPSIS
    Matches one CSV row to an active OT asset for -MarkOtAssetsInactive.

.DESCRIPTION
    Resolves the row's type, then looks for active OT assets whose name equals displayName
    exactly (case-sensitive) and whose type equals the resolved type. An asset whose type was not
    returned by the API matches on name alone, and a verbose message says so.

.PARAMETER Row
    Row object from Read-OtAssetCsv.

.PARAMETER TypeList
    Type list returned by Get-OtAssetTypeList.

.PARAMETER ExistingIndex
    Index returned by Get-ExistingOtAssetIndex.

.OUTPUTS
    PSCustomObject with Status ('Matched', 'Invalid', 'NotFound', 'TypeMismatch' or 'Ambiguous'),
    TypeId, TypeName, AssetId (set only when Matched) and Errors (string[], empty when Matched).

.NOTES
    Does not throw for validation problems. Makes no API calls.
#>
function Find-OtAssetInactivateTarget {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Row,
        [Parameter(Mandatory = $true)][object[]]$TypeList,
        [Parameter(Mandatory = $true)][object]$ExistingIndex
    )

    $rowErrors = [System.Collections.Generic.List[string]]::new()
    $typeId = $null
    $name = [string]$Row.DisplayName

    if ($name -eq '') {
        $rowErrors.Add('displayName is blank')
    }
    try {
        $typeId = Resolve-OtAssetType -Value ([string]$Row.Type) -TypeList $TypeList
    }
    catch {
        $rowErrors.Add([string]$_.Exception.Message)
        $typeId = $null
    }
    $typeName = Get-OtAssetTypeName -TypeId $typeId -TypeList $TypeList

    $result = [pscustomobject]@{
        Status   = 'Invalid'
        TypeId   = $typeId
        TypeName = $typeName
        AssetId  = $null
        Errors   = [string[]]@()
    }
    if ($rowErrors.Count -gt 0) {
        $result.Errors = [string[]]$rowErrors.ToArray()
        return $result
    }

    $candidates = @()
    if ($ExistingIndex.ByExactName.ContainsKey($name)) {
        $candidates = @($ExistingIndex.ByExactName[$name])
    }

    if ($candidates.Count -eq 0) {
        $message = "no active OT asset is named '$name' (it may already be inactive)"
        if ($ExistingIndex.ByName.ContainsKey($name)) {
            $near = $ExistingIndex.ByName[$name]
            $message += "; found '$([string]$near.name)' (id $([string]$near.id)), which differs in case"
        }
        $result.Status = 'NotFound'
        $result.Errors = [string[]]@($message)
        return $result
    }

    $typeMatches = @($candidates | Where-Object { $null -eq $_.TypeId -or [int]$_.TypeId -eq [int]$typeId })
    foreach ($candidate in @($candidates | Where-Object { $null -eq $_.TypeId })) {
        Write-Verbose "Row $($Row.Row): the API did not return a type for asset $($candidate.Id); type check skipped"
    }

    if ($typeMatches.Count -eq 1) {
        $result.Status = 'Matched'
        $result.AssetId = [string]$typeMatches[0].Id
        return $result
    }

    $wanted = "$typeId"
    if ($typeName) { $wanted += " ($typeName)" }
    if ($typeMatches.Count -gt 1) {
        $ids = @($typeMatches | ForEach-Object { [string]$_.Id }) -join ', '
        $result.Status = 'Ambiguous'
        $result.Errors = [string[]]@("$($typeMatches.Count) active OT assets are named '$name' with type $wanted (ids $ids); inactivate them in the portal")
        return $result
    }

    $found = @($candidates | ForEach-Object {
            $foundName = Get-OtAssetTypeName -TypeId $_.TypeId -TypeList $TypeList
            $foundText = "type $($_.TypeId)"
            if ($foundName) { $foundText += " ($foundName)" }
            "id $($_.Id) has $foundText"
        }) -join '; '
    $result.Status = 'TypeMismatch'
    $result.Errors = [string[]]@("an active OT asset named '$name' exists, but not with type ${wanted}: $found")
    return $result
}

<#
.SYNOPSIS
    Runs -MarkOtAssetsInactive: matches every row and inactivates the matched assets.

.DESCRIPTION
    Loads the active OT assets, matches each row with Find-OtAssetInactivateTarget and flags
    duplicate display names in the file. When any row is Invalid, TypeMismatch or Ambiguous,
    nothing is sent unless ContinueOnError is set. NotFound rows never stop the run. Matched
    asset IDs are sent to POST /assets/ot/actions/inactivate in row order, at most 100 per
    request. A failed request marks its rows Failed and stops later requests unless
    ContinueOnError is set. With DryRun, no request is sent and the rows become DryRun.

.PARAMETER Rows
    Row objects from Read-OtAssetCsv.

.PARAMETER TypeList
    Type list returned by Get-OtAssetTypeList.

.PARAMETER ApiBaseUrl
    Base URL returned by Get-ApiBaseUrl.

.PARAMETER ApiKey
    API key for the tenant.

.PARAMETER Comment
    Optional comment. Sent as 'comment' when it is not blank.

.PARAMETER DryRun
    Sends no inactivate request.

.PARAMETER ContinueOnError
    Sends the matched rows even when other rows did not match, and keeps going after a failed
    request.

.OUTPUTS
    System.Collections.Generic.List[pscustomobject]. One evaluation per row, with Row, Name, Ip,
    TypeId, TypeName, Status, AssetId, Error and Request.

.NOTES
    Throws when the existing OT asset list cannot be read. The caller reports that as a setup
    error. Writes the match count to the information stream and one warning per unmatched row.
#>
function Invoke-OtAssetInactivation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Rows,
        [Parameter(Mandatory = $true)][object[]]$TypeList,
        [Parameter(Mandatory = $true)][string]$ApiBaseUrl,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $false)][string]$Comment,
        [Parameter(Mandatory = $false)][switch]$DryRun,
        [Parameter(Mandatory = $false)][switch]$ContinueOnError
    )

    $batchSize = 100
    $actionPath = '/assets/ot/actions/inactivate'

    $existingIndex = Get-ExistingOtAssetIndex -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey
    if (-not $existingIndex.HasTypeField) {
        Write-Verbose 'The OT asset list has no assetType or type field; assets are matched by name only.'
    }

    $duplicateErrors = Get-InFileDuplicateErrors -Rows $Rows -NamesOnly

    $evaluations = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($row in $Rows) {
        $match = Find-OtAssetInactivateTarget -Row $row -TypeList $TypeList -ExistingIndex $existingIndex

        $status = [string]$match.Status
        $messages = [System.Collections.Generic.List[string]]::new()
        $messages.AddRange([string[]]$match.Errors)
        if ($duplicateErrors.ContainsKey([int]$row.Row)) {
            $messages.AddRange([string[]]@($duplicateErrors[[int]$row.Row]))
            $status = 'Invalid'
        }
        foreach ($message in $messages) {
            Write-Warning "Row $($row.Row): $message"
        }

        $assetId = $null
        if ($status -eq 'Matched') { $assetId = $match.AssetId }
        $errorText = $null
        if ($messages.Count -gt 0) { $errorText = ($messages -join '; ') }

        $evaluations.Add([pscustomobject]@{
                Row      = [int]$row.Row
                Name     = [string]$row.DisplayName
                Ip       = [string]$row.Ipv4
                TypeId   = $match.TypeId
                TypeName = $match.TypeName
                Status   = $status
                AssetId  = $assetId
                Error    = $errorText
                Request  = $null
            })
    }

    $matchedCount = @($evaluations | Where-Object { $_.Status -eq 'Matched' }).Count
    Write-Information "Matched $($evaluations.Count) row(s) to active OT assets: $matchedCount matched, $($evaluations.Count - $matchedCount) not matched"

    $blockingCount = @($evaluations | Where-Object { $_.Status -in @('Invalid', 'TypeMismatch', 'Ambiguous') }).Count
    $targets = @($evaluations | Where-Object { $_.Status -eq 'Matched' })
    foreach ($target in $targets) { $target.Status = 'NotAttempted' }

    if ($blockingCount -gt 0 -and -not $ContinueOnError) {
        Write-Warning "$blockingCount row(s) are Invalid, TypeMismatch or Ambiguous; nothing was inactivated. Fix the errors above or rerun with -ContinueOnError."
        return , $evaluations
    }

    for ($start = 0; $start -lt $targets.Count; $start += $batchSize) {
        $end = [Math]::Min($start + $batchSize, $targets.Count) - 1
        $batch = @($targets[$start..$end])
        $body = [ordered]@{ assetIds = [string[]]@($batch | ForEach-Object { [string]$_.AssetId }) }
        if (-not [string]::IsNullOrWhiteSpace($Comment)) { $body['comment'] = $Comment }
        $json = ConvertTo-Json -InputObject $body -Depth 5 -Compress
        $rowRange = "rows $($batch[0].Row)-$($batch[-1].Row)"

        if ($DryRun) {
            Write-Verbose "[DryRun] $($rowRange): would POST $actionPath $json"
            foreach ($evaluation in $batch) {
                $evaluation.Status = 'DryRun'
                $evaluation.Request = $json
            }
            continue
        }

        try {
            $null = Invoke-ZnRestMethod -Method POST -ApiBaseUrl $ApiBaseUrl -ApiKey $ApiKey -Path $actionPath -Body $json
            foreach ($evaluation in $batch) {
                $evaluation.Status = 'Inactivated'
                $evaluation.Request = $json
            }
            Write-Verbose "$($rowRange): inactivated $($batch.Count) asset(s)"
        }
        catch {
            $postError = $_
            $postStatus = 0
            $postApiMessage = ''
            if ($postError.TargetObject -is [pscustomobject] -and $postError.TargetObject.PSObject.Properties['StatusCode']) {
                $postStatus = [int]$postError.TargetObject.StatusCode
                $postApiMessage = [string]$postError.TargetObject.ApiMessage
            }
            if ($postStatus -eq 403) {
                $failText = 'the API key is not allowed to inactivate OT assets (HTTP 403'
                if ($postApiMessage) { $failText += ": $postApiMessage" }
                $failText += '); use a read-write key that is allowed to change assets'
            }
            else {
                $failText = [string]$postError.Exception.Message
            }
            Write-Warning "Inactivate request for $rowRange failed: $failText"
            foreach ($evaluation in $batch) {
                $evaluation.Status = 'Failed'
                $evaluation.Error = $failText
            }
            if (-not $ContinueOnError) { break }
        }
    }

    return , $evaluations
}

<#
.SYNOPSIS
    Writes the summary line and one result object per evaluation.

.DESCRIPTION
    Counts the evaluations by status and writes "Summary: ..." to the information stream, in a
    fixed status order. Adds a dry-run hint when any row is DryRun and -Verbose is not set. Then
    writes one ZnOtAssetResult object per evaluation to the pipeline.

.PARAMETER Evaluations
    Evaluation objects from the create or inactivate flow.

.PARAMETER Action
    Past-tense verb used in the dry-run hint: 'created' or 'inactivated'.

.OUTPUTS
    PSCustomObject with type name ZnOtAssetResult and the properties Row, Name, Ip, TypeId,
    TypeName, Status, AssetId, Error and Request.

.NOTES
    Does not throw.
#>
function Write-OtAssetRunResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Evaluations,
        [Parameter(Mandatory = $true)][ValidateSet('created', 'inactivated')][string]$Action
    )

    $tally = @{}
    foreach ($evaluation in $Evaluations) {
        $tally[$evaluation.Status] = 1 + [int]$tally[$evaluation.Status]
    }
    $statusOrder = @('Created', 'Inactivated', 'DryRun', 'Skipped', 'NotFound', 'TypeMismatch', 'Ambiguous', 'Failed', 'Invalid', 'NotAttempted')
    $summaryParts = @($statusOrder | Where-Object { [int]$tally[$_] -gt 0 } | ForEach-Object { "$_ $([int]$tally[$_])" })
    Write-Information "Summary: $($summaryParts -join ', ')"
    if ([int]$tally['DryRun'] -gt 0 -and $VerbosePreference -eq [System.Management.Automation.ActionPreference]::SilentlyContinue) {
        Write-Information "DryRun: nothing was $Action. Add -Verbose to see each request body."
    }

    foreach ($evaluation in $Evaluations) {
        $result = [pscustomobject]@{
            Row      = $evaluation.Row
            Name     = $evaluation.Name
            Ip       = $evaluation.Ip
            TypeId   = $evaluation.TypeId
            TypeName = $evaluation.TypeName
            Status   = $evaluation.Status
            AssetId  = $evaluation.AssetId
            Error    = $evaluation.Error
            Request  = $evaluation.Request
        }
        $result.PSTypeNames.Insert(0, 'ZnOtAssetResult')
        $result
    }
}

# Main flow. Any unexpected error is reported and the script exits with code 2.
try {
    # Register the results table view once per session. Without the file, PowerShell's default
    # view is used instead.
    $formatPath = Join-Path -Path $PSScriptRoot -ChildPath 'New-OtAsset.format.ps1xml'
    if ((Test-Path -LiteralPath $formatPath -PathType Leaf) -and $null -eq (Get-FormatData -TypeName 'ZnOtAssetResult')) {
        try {
            Update-FormatData -AppendPath $formatPath -ErrorAction Stop
        }
        catch {
            Write-Verbose "Could not load '$formatPath'; using the default view. $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Error -Message 'An API key is required for this operation. Pass -ApiKey or set the ZN_API_KEY environment variable to a read-write key.' -ErrorAction Continue
        exit 2
    }

    if ($PSCmdlet.ParameterSetName -ne 'BySingle') {
        try {
            $rows = @(Read-OtAssetCsv -Path $CsvFilePath -NameAndTypeOnly:$MarkOtAssetsInactive)
        }
        catch {
            Write-Error -ErrorRecord $_ -ErrorAction Continue
            exit 2
        }
    }
    else {
        $rows = @(
            [pscustomobject]@{
                Row           = 1
                Ipv4          = ([string]$Ip).Trim()
                Type          = ([string]$Type).Trim()
                DisplayName   = ([string]$Name).Trim()
                Fqdn          = ([string]$Fqdn).Trim()
                SwitchId      = ([string]$SwitchId).Trim()
                InterfaceName = ([string]$InterfaceName).Trim()
            }
        )
    }

    try {
        $baseUrl = Get-ApiBaseUrl -ApiKey $ApiKey -PortalUrl $PortalUrl
        $typeList = @(Get-OtAssetTypeList -ApiBaseUrl $baseUrl -ApiKey $ApiKey)
    }
    catch {
        Write-Error -ErrorRecord $_ -ErrorAction Continue
        exit 2
    }

    if ($MarkOtAssetsInactive) {
        try {
            $evaluations = Invoke-OtAssetInactivation -Rows $rows -TypeList $typeList -ApiBaseUrl $baseUrl -ApiKey $ApiKey -Comment $Comment -DryRun:$DryRun -ContinueOnError:$ContinueOnError
        }
        catch {
            Write-Error -ErrorRecord $_ -ErrorAction Continue
            exit 2
        }
        Write-OtAssetRunResult -Evaluations $evaluations -Action 'inactivated'
        $notInactivatedCount = @($evaluations | Where-Object { $_.Status -notin @('Inactivated', 'DryRun') }).Count
        if ($notInactivatedCount -gt 0) { exit 1 }
        exit 0
    }

    # Single mode: fall back to type 135 when the default name is not offered by the tenant.
    if ($PSCmdlet.ParameterSetName -eq 'BySingle' -and -not $PSBoundParameters.ContainsKey('Type')) {
        $defaultResolves = $true
        try {
            $null = Resolve-OtAssetType -Value $rows[0].Type -TypeList $typeList
        }
        catch {
            $defaultResolves = $false
        }
        $hasTypeId135 = (@($typeList | Where-Object { $_.Id -eq 135 }).Count -gt 0)
        if (-not $defaultResolves -and $hasTypeId135) {
            $rows[0].Type = '135'
        }
    }

    $existingIndex = $null
    if (-not $SkipExistingCheck) {
        try {
            $existingIndex = Get-ExistingOtAssetIndex -ApiBaseUrl $baseUrl -ApiKey $ApiKey
        }
        catch {
            Write-Error -ErrorRecord $_ -ErrorAction Continue
            exit 2
        }
    }

    $switchIndex = $null
    $switchLookupError = $null
    if (@($rows | Where-Object { $_.SwitchId -ne '' }).Count -gt 0) {
        try {
            $switchIndex = Get-SwitchIndex -ApiBaseUrl $baseUrl -ApiKey $ApiKey
        }
        catch {
            $switchError = $_
            $switchStatus = 0
            $switchApiMessage = ''
            if ($switchError.TargetObject -is [pscustomobject] -and $switchError.TargetObject.PSObject.Properties['StatusCode']) {
                $switchStatus = [int]$switchError.TargetObject.StatusCode
                $switchApiMessage = [string]$switchError.TargetObject.ApiMessage
            }
            if ($switchStatus -eq 404) {
                $switchLookupError = "the switch API is not available for this tenant (HTTP 404: $switchApiMessage); OT switch features may be disabled"
            }
            elseif ($switchStatus -eq 403) {
                $switchLookupError = 'the API key is not allowed to read switches (HTTP 403)'
            }
            else {
                $switchLookupError = [string]$switchError.Exception.Message
            }
        }
    }

    $duplicateErrors = Get-InFileDuplicateErrors -Rows $rows

    $evaluations = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($row in $rows) {
        $check = Test-OtAssetRow -Row $row -TypeList $typeList -ExistingIndex $existingIndex -SwitchIndex $switchIndex -SwitchLookupError $switchLookupError -ApiBaseUrl $baseUrl -ApiKey $ApiKey

        $allErrors = [System.Collections.Generic.List[string]]::new()
        $allErrors.AddRange([string[]]$check.Errors)
        if ($duplicateErrors.ContainsKey([int]$row.Row)) {
            $allErrors.AddRange([string[]]@($duplicateErrors[[int]$row.Row]))
        }
        foreach ($message in $allErrors) {
            Write-Warning "Row $($row.Row): $message"
        }

        $evaluations.Add([pscustomobject]@{
                Row      = [int]$row.Row
                Name     = [string]$row.DisplayName
                Ip       = [string]$row.Ipv4
                TypeId   = $check.TypeId
                TypeName = $check.TypeName
                Source   = $row
                Errors   = [string[]]$allErrors.ToArray()
                Status   = 'NotAttempted'
                AssetId  = $null
                Error    = $null
                Request  = $null
            })
    }

    $invalidCount = @($evaluations | Where-Object { $_.Errors.Count -gt 0 }).Count
    $validCount = $evaluations.Count - $invalidCount
    Write-Information "Validated $($evaluations.Count) row(s): $validCount valid, $invalidCount invalid"

    foreach ($evaluation in $evaluations) {
        if ($evaluation.Errors.Count -gt 0) {
            $evaluation.Status = 'Invalid'
            $evaluation.Error = ($evaluation.Errors -join '; ')
        }
        else {
            $evaluation.Status = 'NotAttempted'
        }
    }

    if ($invalidCount -gt 0 -and -not $ContinueOnError) {
        Write-Warning "$invalidCount row(s) failed validation; nothing was created. Fix the errors above or rerun with -ContinueOnError."
    }
    else {
        $stopPosting = $false
        foreach ($evaluation in $evaluations) {
            if ($evaluation.Status -ne 'NotAttempted') { continue }
            if ($stopPosting) { continue }

            $body = New-OtAssetBody -Row $evaluation.Source -TypeId ([int]$evaluation.TypeId)
            $json = $body | ConvertTo-Json -Depth 10 -Compress

            if ($DryRun) {
                Write-Verbose "[DryRun] Row $($evaluation.Row): would POST /assets/ot $json"
                $evaluation.Status = 'DryRun'
                $evaluation.Request = $json
                continue
            }

            try {
                $response = Invoke-ZnRestMethod -Method POST -ApiBaseUrl $baseUrl -ApiKey $ApiKey -Path '/assets/ot' -Body $body
                $evaluation.Status = 'Created'
                $evaluation.AssetId = [string]$response.assetId
                $evaluation.Request = $json
                Write-Verbose "Row $($evaluation.Row): created '$($evaluation.Name)' ($($evaluation.AssetId))"
            }
            catch {
                $postError = $_
                $postStatus = 0
                $postApiMessage = ''
                if ($postError.TargetObject -is [pscustomobject] -and $postError.TargetObject.PSObject.Properties['StatusCode']) {
                    $postStatus = [int]$postError.TargetObject.StatusCode
                    $postApiMessage = [string]$postError.TargetObject.ApiMessage
                }

                if ($postStatus -eq 409) {
                    $evaluation.Status = 'Skipped'
                    $evaluation.Error = "already exists: $postApiMessage"
                }
                else {
                    $evaluation.Status = 'Failed'
                    $evaluation.Error = [string]$postError.Exception.Message
                    if (-not $ContinueOnError) { $stopPosting = $true }
                }
            }
        }
    }

    Write-OtAssetRunResult -Evaluations $evaluations -Action 'created'

    $notCreatedCount = @($evaluations | Where-Object { $_.Status -notin @('Created', 'DryRun') }).Count
    if ($notCreatedCount -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    exit 2
}
