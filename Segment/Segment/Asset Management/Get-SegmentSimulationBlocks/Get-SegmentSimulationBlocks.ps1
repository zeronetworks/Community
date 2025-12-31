#requires -Module ZeroNetworks

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $true, ParameterSetName = "AllAssets")]
    [string]$ApiKey,

    [Parameter(Mandatory = $true, ParameterSetName = "ByAssetId")]
    [string]$AssetId,

    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [switch]$SkipLearningFilter,

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [ValidateSet("Incoming", "Outgoing")]
    [string]$Direction = "Incoming",

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [switch]$IgnorePendingRules,

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [ValidateSet("Both", "Internal", "External")]
    [string]$TrafficType = "Both",

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [string]$From,

    [Parameter(Mandatory = $false, ParameterSetName = "ByAssetId")]
    [Parameter(Mandatory = $false, ParameterSetName = "AllAssets")]
    [switch]$ShowDisabledRules
)

$ErrorActionPreference = "Stop"


<#
 SCRIPT SCOPED MAPPING TABLES
#>
# Create mapping hash tables for Direction and TrafficType (script-scoped)
$script:DirectionToDirectionCode = @{
    "Incoming" = 1
    "Outgoing" = 2
}

$script:TrafficTypeToTrafficTypeCode = @{
    "Internal" = 1
    "External" = 2
    "Both"     = 3
}

# Create reverse mapping hash tables (code --> meaning)
$script:DirectionCodeToDirection = @{
    1 = "Incoming"
    2 = "Outgoing"
}

$script:TrafficTypeCodeToTrafficType = @{
    1 = "Internal"
    2 = "External"
    3 = "Both"
}

$script:ProtocolTypeMap = @{
    0 = "HOPOPT"
    1 = "ICMP"
    2 = "IGMP"
    3 = "GGP"
    4 = "IPV4"
    5 = "ST"
    6 = "TCP"
    7 = "CBT"
    8 = "EGP"
    9 = "IGP"
    10 = "BBN_RCC_MON"
    11 = "NVP_II"
    12 = "PUP"
    13 = "ARGUS"
    14 = "EMCON"
    15 = "XNET"
    16 = "CHAOS"
    17 = "UDP"
    18 = "MUX"
    19 = "DCN_MEAS"
    20 = "HMP"
    21 = "PRM"
    22 = "IDP"
    23 = "TRUNK_1"
    24 = "TRUNK_2"
    25 = "LEAF_1"
    26 = "LEAF_2"
    27 = "RDP"
    28 = "IRTP"
    29 = "ISO_TP4"
    30 = "NETBLT"
    31 = "MFE_NSP"
    32 = "MERIT_INP"
    33 = "DCCP"
    34 = "3PC"
    35 = "IDPR"
    36 = "XTP"
    37 = "DDP"
    38 = "IDPR_CMTP"
    39 = "TP_PLUS_PLUS"
    40 = "IL"
    41 = "EMBEDDEDIPV6"
    42 = "SDRP"
    43 = "IPV6ROUTINGHEADER"
    44 = "IPV6FRAGMENTHEADER"
    45 = "IDRP"
    46 = "RSVP"
    47 = "GRE"
    48 = "DSR"
    49 = "BNA"
    50 = "IPSECENCAPSULATINGSECURITYPAYLOAD"
    51 = "IPSECAUTHENTICATIONHEADER"
    52 = "I_NLSP"
    53 = "SWIPE"
    54 = "NARP"
    55 = "MOBILE"
    56 = "TLSP"
    57 = "SKIP"
    58 = "ICMPV6"
    59 = "IPV6NONEXTHEADER"
    60 = "IPV6DESTINATOPNOPTIONS"
    61 = "HOST_INTERANL"
    62 = "CFTP"
    63 = "LOCAL_NETWORK"
    64 = "SAT_EXPAK"
    65 = "KRYPTOLAN"
    66 = "RVD"
    67 = "IPPC"
    68 = "DISTRIBUTED_FILE_SYSTEM"
    69 = "SAT_MON"
    70 = "VISA"
    71 = "IPCU"
    72 = "CPNX"
    73 = "CPHB"
    74 = "WSN"
    75 = "PVP"
    76 = "BR_SAT_MON"
    77 = "ND"
    78 = "WB_MON"
    79 = "WB_EXPAK"
    80 = "ISO_IP"
    81 = "VMTP"
    82 = "SECURE_VMTP"
    83 = "VINES"
    84 = "IPTM"
    85 = "NSFNET_IGP"
    86 = "DGP"
    87 = "TCF"
    88 = "EIGRP"
    89 = "OSPF"
    90 = "SPRITE_RPC"
    91 = "LARP"
    92 = "MTP"
    93 = "AX_25"
    94 = "OS"
    95 = "MICP"
    96 = "SCC_SP"
    97 = "ETHERIP"
    98 = "ENCAP"
    99 = "PRIVATE_INCRIPTION"
    100 = "GMTP"
    101 = "IFMP"
    102 = "PNNI"
    103 = "PIM"
    104 = "ARIS"
    105 = "SCPS"
    106 = "QNX"
    107 = "A_N"
    108 = "IPCOMP"
    109 = "SNP"
    110 = "COMPAQ_PEER"
    111 = "IPX_IN_IP"
    112 = "VRRP"
    113 = "PGM"
    114 = "0_HOP"
    115 = "L2TP"
    116 = "DDX"
    117 = "IATP"
    118 = "STP"
    119 = "SRP"
    120 = "UTI"
    121 = "SMP"
    122 = "SM"
    123 = "PTP"
    124 = "IS_IS_OVER_IPV4"
    125 = "FIRE"
    126 = "CRTP"
    127 = "CRUDP"
    128 = "SSCOPMCE"
    129 = "IPLT"
    130 = "SPS"
    131 = "PIPE"
    132 = "SCTP"
    133 = "FC"
    134 = "RSVP_E2E_IGNORE"
    135 = "MOBILITY_HEADER"
    136 = "UDPLITE"
    137 = "MPLS_IN_IP"
    138 = "MANET"
    139 = "HIP"
    140 = "SHIM6"
    141 = "WESP"
    142 = "ROHC"
    143 = "ETHERNET"
    144 = "CUSTOM_144"
    145 = "CUSTOM_145"
    146 = "CUSTOM_146"
    147 = "CUSTOM_147"
    148 = "CUSTOM_148"
    149 = "CUSTOM_149"
    150 = "CUSTOM_150"
    151 = "CUSTOM_151"
    152 = "CUSTOM_152"
    153 = "CUSTOM_153"
    154 = "CUSTOM_154"
    155 = "CUSTOM_155"
    156 = "CUSTOM_156"
    157 = "CUSTOM_157"
    158 = "CUSTOM_158"
    159 = "CUSTOM_159"
    160 = "CUSTOM_160"
    161 = "CUSTOM_161"
    162 = "CUSTOM_162"
    163 = "CUSTOM_163"
    164 = "CUSTOM_164"
    165 = "CUSTOM_165"
    166 = "CUSTOM_166"
    167 = "CUSTOM_167"
    168 = "CUSTOM_168"
    169 = "CUSTOM_169"
    170 = "CUSTOM_170"
    171 = "CUSTOM_171"
    172 = "CUSTOM_172"
    173 = "CUSTOM_173"
    174 = "CUSTOM_174"
    175 = "CUSTOM_175"
    176 = "CUSTOM_176"
    177 = "CUSTOM_177"
    178 = "CUSTOM_178"
    179 = "CUSTOM_179"
    180 = "CUSTOM_180"
    181 = "CUSTOM_181"
    182 = "CUSTOM_182"
    183 = "CUSTOM_183"
    184 = "CUSTOM_184"
    185 = "CUSTOM_185"
    186 = "CUSTOM_186"
    187 = "CUSTOM_187"
    188 = "CUSTOM_188"
    189 = "CUSTOM_189"
    190 = "CUSTOM_190"
    191 = "CUSTOM_191"
    192 = "CUSTOM_192"
    193 = "CUSTOM_193"
    194 = "CUSTOM_194"
    195 = "CUSTOM_195"
    196 = "CUSTOM_196"
    197 = "CUSTOM_197"
    198 = "CUSTOM_198"
    199 = "CUSTOM_199"
    200 = "CUSTOM_200"
    201 = "CUSTOM_201"
    202 = "CUSTOM_202"
    203 = "CUSTOM_203"
    204 = "CUSTOM_204"
    205 = "CUSTOM_205"
    206 = "CUSTOM_206"
    207 = "CUSTOM_207"
    208 = "CUSTOM_208"
    209 = "CUSTOM_209"
    210 = "CUSTOM_210"
    211 = "CUSTOM_211"
    212 = "CUSTOM_212"
    213 = "CUSTOM_213"
    214 = "CUSTOM_214"
    215 = "CUSTOM_215"
    216 = "CUSTOM_216"
    217 = "CUSTOM_217"
    218 = "CUSTOM_218"
    219 = "CUSTOM_219"
    220 = "CUSTOM_220"
    221 = "CUSTOM_221"
    222 = "CUSTOM_222"
    223 = "CUSTOM_223"
    224 = "CUSTOM_224"
    225 = "CUSTOM_225"
    226 = "CUSTOM_226"
    227 = "CUSTOM_227"
    228 = "CUSTOM_228"
    229 = "CUSTOM_229"
    230 = "CUSTOM_230"
    231 = "CUSTOM_231"
    232 = "CUSTOM_232"
    233 = "CUSTOM_233"
    234 = "CUSTOM_234"
    235 = "CUSTOM_235"
    236 = "CUSTOM_236"
    237 = "CUSTOM_237"
    238 = "CUSTOM_238"
    239 = "CUSTOM_239"
    240 = "CUSTOM_240"
    241 = "CUSTOM_241"
    242 = "CUSTOM_242"
    243 = "CUSTOM_243"
    244 = "CUSTOM_244"
    245 = "CUSTOM_245"
    246 = "CUSTOM_246"
    247 = "CUSTOM_247"
    248 = "CUSTOM_248"
    249 = "CUSTOM_249"
    250 = "CUSTOM_250"
    251 = "CUSTOM_251"
    252 = "CUSTOM_252"
    253 = "CUSTOM_253"
    254 = "CUSTOM_254"
    255 = "RAW"
    256 = "ANY"
}

<#
Script wide variables
#>
$script:AssetsWithBlockResults = @()
$script:AssetsWithMfaResults
function Test-ResponseForError {
    param(
        [Parameter(Mandatory = $true)]
        $Response
    )
    if($Response -is [ZeroNetworks.PowerShell.Cmdlets.Api.Models.Error]) {
        throw "ZeroNetworks API returned an error: $($Response | ConvertTo-Json -Compress | Out-String)"
    }
}

function Convert-IsoTimestampToMs {
    <#
    .SYNOPSIS
        Converts an ISO formatted timestamp string to a milliseconds integer timestamp.
    .PARAMETER IsoTimestamp
        ISO formatted timestamp string (e.g., "2024-01-15T12:00:00.000Z"). Assumes local timezone if no timezone indicator is present.
    .OUTPUTS
        Returns an integer representing the Unix timestamp in milliseconds.
    .NOTES
        This function parses the ISO timestamp and converts it to Unix epoch milliseconds. If the timestamp doesn't include timezone information, it assumes the system's local timezone.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$IsoTimestamp
    )
    
    # Check if the timestamp has timezone information
    $HasTimezone = $IsoTimestamp -match '[Zz]' -or $IsoTimestamp -match '[+-]\d{2}:?\d{2}$'
    
    if ($HasTimezone) {
        # Parse with timezone info - DateTimeOffset.Parse will handle it correctly
        $DateTimeOffset = [DateTimeOffset]::Parse($IsoTimestamp)
    }
    else {
        # No timezone info - parse as DateTime (assumes local) and create DateTimeOffset with local timezone
        $DateTime = [DateTime]::Parse($IsoTimestamp)
        $LocalOffset = [TimeZoneInfo]::Local.GetUtcOffset($DateTime)
        $DateTimeOffset = [DateTimeOffset]::new($DateTime, $LocalOffset)
    }
    
    return $DateTimeOffset.ToUnixTimeMilliseconds()
}

function Convert-MsTimestampToIso {
    <#
    .SYNOPSIS
        Converts a milliseconds integer timestamp to an ISO formatted timestamp string.
    .PARAMETER MsTimestamp
        Integer representing the Unix timestamp in milliseconds (e.g., 1766466000000).
    .OUTPUTS
        Returns a string representing the ISO formatted timestamp in the system's local timezone (e.g., "2024-01-15T12:00:00.000-05:00").
    .NOTES
        This function converts a Unix epoch milliseconds timestamp to ISO 8601 format using the system's local timezone.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [long]$MsTimestamp
    )
    
    # Convert from Unix milliseconds (UTC) to local time
    $UtcDateTimeOffset = [DateTimeOffset]::FromUnixTimeMilliseconds($MsTimestamp)
    $LocalDateTimeOffset = $UtcDateTimeOffset.ToLocalTime()
    
    # Format as ISO string with timezone offset
    return $LocalDateTimeOffset.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
}

function Convert-DateTimeToLocal {
    <#
    .SYNOPSIS
        Converts a DateTime object to the system's local timezone.
    .PARAMETER DateTime
        The DateTime object to convert to local timezone. Can be null.
    .OUTPUTS
        Returns a DateTimeOffset object representing the DateTime in the system's local timezone, or null if input is null.
    .NOTES
        This function handles DateTime objects with different kinds (UTC, Local, Unspecified) and converts them to local timezone. Returns null if the input DateTime is null.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [Nullable[DateTime]]$DateTime
    )
    
    # Return null if input is null
    if ($null -eq $DateTime) {
        return $null
    }
    
    # Handle different DateTime kinds
    switch ($DateTime.Kind) {
        "Utc" {
            # Convert UTC to local
            $LocalDateTime = $DateTime.ToLocalTime()
            $LocalOffset = [TimeZoneInfo]::Local.GetUtcOffset($LocalDateTime)
            return [DateTimeOffset]::new($LocalDateTime, $LocalOffset)
        }
        "Local" {
            # Already local, just create DateTimeOffset with local offset
            $LocalOffset = [TimeZoneInfo]::Local.GetUtcOffset($DateTime)
            return [DateTimeOffset]::new($DateTime, $LocalOffset)
        }
        "Unspecified" {
            # Treat as local time
            $LocalOffset = [TimeZoneInfo]::Local.GetUtcOffset($DateTime)
            return [DateTimeOffset]::new($DateTime, $LocalOffset)
        }
    }
}

function Invoke-ZeroNetworksApiCall {
    <#
    .SYNOPSIS
        Makes an API call to ZeroNetworks API and validates the response.
    .PARAMETER Headers
        Hashtable containing HTTP headers for the API request (e.g., Authorization, Content-Type).
    .PARAMETER Method
        HTTP method to use for the API call (e.g., GET, POST, PUT, DELETE).
    .PARAMETER Url
        Full URL for the API endpoint.
    .PARAMETER Body
        Hashtable or object containing the request body. Will be converted to JSON if provided.
    .OUTPUTS
        Returns the response from the API call if successful.
    .NOTES
        This function validates that the response is successful (HTTP status code 200-299) and throws an error if not.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $false)]
        $Body
    )

    try {
        #Write-Host "Invoking API call to $Url with method $Method" -ForegroundColor Green
        $InvokeParams = @{
            Uri = $Url
            Method = $Method
            Headers = $Headers
            ErrorAction = "Stop"
        }

        if ($Body) {
            $BodyJson = $Body | ConvertTo-Json -Depth 10
            $InvokeParams.Body = $BodyJson
        }

        $Response = Invoke-RestMethod @InvokeParams
        return $Response
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        $ErrorMessage = $_.Exception.Message
        
        if ($_.ErrorDetails.Message) {
            $ErrorMessage = $_.ErrorDetails.Message
        }
        
        throw "API call failed with status code $StatusCode : $ErrorMessage"
    }
}

function Get-RequiredZnAssets {
    param(
        [Parameter(Mandatory = $false)]
        [string]$AssetId,
        [Parameter(Mandatory = $false)]
        [switch]$SkipLearningFilter
    )

    $FilterList = [System.Collections.ArrayList]@(
        @{
            "id"            = "protectionStatus"
            "includeValues" = @("5","10","11","12","13","14","15","16","17","18")
            "excludeValues" = @()
        }
    )

    if ($SkipLearningFilter) {
        Write-Host "Skipping filtering for only assets in learning mode!" -ForegroundColor Red
        $null = $FilterList.RemoveAt(0)
    }

    if ($AssetId) {
        Write-Host "Getting only single asset by id: $($AssetId)" -ForegroundColor Green
        $null = $FilterList.Add(@{
            "id"            = "assetId"
            "includeValues" = @($AssetId)
            "excludeValues" = @()
        })
    }

    $Response = Get-ZnAsset -Limit 300 -Filters ($FilterList | ConvertTo-Json -Depth 10 -AsArray -Compress)
    #Write-Host "---`n$($Response| ConvertTo-Json -Depth 10 -Compress | Out-String)`n---"
    Test-ResponseForError -Response $Response
    $Assets = $Response.Items
    #Write-Host "---`n$($Assets | ConvertTo-Json -Depth 10 -Compress | Out-String)`n---"

    if (-not $AssetId) {
        while($Assets.Count -lt $Response.Count) {
            if ($SkipLearningFilter) {
                $Response = Get-ZnAsset -Limit 300 -Offset $Response.NextOffset
            } else {
                $Response = Get-ZnAsset -Limit 300 -Filters ($FilterList | ConvertTo-Json -Depth 10 -AsArray -Compress) -Offset $Response.NextOffset
            }
            Test-ResponseForError -Response $Response
            $Assets = $Assets + $Response.Items
        }
    }

    Write-Host "Retrieved $($Assets.Count) asset(s) from ZeroNetworks API" -ForegroundColor Green
    #Write-Host "---`n$($Assets | ConvertTo-Json -Depth 10 -Compress | Out-String)`n---"
    return $Assets
}

function Get-AssetSegmentSimulationResults {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AssetId,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Incoming", "Outgoing")]
        [string]$Direction = "Incoming",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Both", "Internal", "External")]
        [string]$TrafficType = "Both",

        [Parameter(Mandatory = $false)]
        [bool]$IgnorePendingRules = $false,

        [Parameter(Mandatory = $true)]
        [Int64]$From,

        [Parameter(Mandatory = $false)]
        [switch]$ShowDisabledRules
    )

    # Convert Direction and TrafficType to their corresponding codes
    $DirectionCode = $script:DirectionToDirectionCode[$Direction]
    $TrafficTypeCode = $script:TrafficTypeToTrafficTypeCode[$TrafficType]

    # Create the full URL, including the API endpoint for segment simulation
    $FullUrl = "$Script:ApiUrl/protection/$AssetId/simulate-access"

    # Set up rule states
    $RuleStates = [System.Collections.ArrayList]@(
        1 # Enabled rules
        2 # Pending rules
    )
    if ($IgnorePendingRules) {
        $null = $RuleStates.Remove(2) # Pending rules
    }
    if ($ShowDisabledRules) {
        $null = $RuleStates.Add(3) # Disabled rules
    }

    # Create body
    $BodyHashTable = @{
        "from" = $From
        "direction" = $DirectionCode
        "trafficType" = $TrafficTypeCode
        "ruleStates" = $RuleStates
    }

    if ($FullUrl.contains("dev")) {
        Write-Host "Running in development environment, using early access request body syntax (removing ruleStates, using includePendingRules instead)" -ForegroundColor DarkYellow
        $BodyHashTable.Add("includePendingRules", $IgnorePendingRules)
        $BodyHashTable.Remove("ruleStates")
    }
    
    $Response = Invoke-ZeroNetworksApiCall -Headers $Script:Headers -Method POST -Url $FullUrl -Body $BodyHashTable
    Test-ResponseForError -Response $Response
    Write-Host "Retrieved segment simulation results for asset $($AssetId) from ZeroNetworks API" -ForegroundColor Green
    return $Response.items

   
}

function Write-SeparatorLine {
    <#
    .SYNOPSIS
        Writes a separator line of characters based on terminal width.
    .PARAMETER DivisionFactor
        The number to divide the terminal width by to determine line length.
    .PARAMETER Characters
        The character(s) to use for the separator line. Defaults to "~".
    .PARAMETER ForegroundColor
        The foreground color for the separator line. If null, uses default terminal color.
    .PARAMETER BackgroundColor
        The background color for the separator line. If null, uses default terminal color.
    .PARAMETER TabCount
        The number of tabs to prepend to the separator line. Defaults to 0.
    .OUTPUTS
        Writes a separator line to the host.
    .NOTES
        Defaults to terminal width of 80 if unable to determine actual width.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [int]$DivisionFactor = 3,

        [Parameter(Mandatory = $false)]
        [string]$Characters = "~",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$ForegroundColor = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow", "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$BackgroundColor = $null,

        [Parameter(Mandatory = $false)]
        [int]$TabCount = 0
    )
    
    $TerminalWidth = $Host.UI.RawUI.BufferSize.Width
    if (-not $TerminalWidth) {
        $TerminalWidth = 80  # Default fallback
    }
    $LineLength = [math]::Floor($TerminalWidth / $DivisionFactor)
    $SeparatorLine = $Characters * $LineLength
    
    # Prepend tabs if TabCount is greater than 0
    if ($TabCount -gt 0) {
        $SeparatorLine = $("`t" * $TabCount) + $SeparatorLine
    }
    
    $WriteHostParams = @{
        Object = $SeparatorLine
    }
    
    if ($null -ne $ForegroundColor -and $ForegroundColor -ne "") {
        try {
            $WriteHostParams.ForegroundColor = [ConsoleColor]$ForegroundColor
        }
        catch {
            Write-Warning "Invalid foreground color '$ForegroundColor'. Using default color."
        }
    }
    
    if ($null -ne $BackgroundColor -and $BackgroundColor -ne "") {
        try {
            $WriteHostParams.BackgroundColor = [ConsoleColor]$BackgroundColor
        }
        catch {
            Write-Warning "Invalid background color '$BackgroundColor'. Using default color."
        }
    }
    
    Write-Host @WriteHostParams
}

function Write-AssetSegmentSimulationResults {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Asset
    )
    Write-Host "`n"
    Write-SeparatorLine -DivisionFactor 4 -Characters "-" -ForegroundColor DarkMagenta
    Write-Host "Segmentation Simulation Results for: $($Asset.Name) ($($Asset.Id))" -ForegroundColor DarkMagenta

    # If the protectAt timestamp is $null, it is set to indefinite learning
    if ($null -eq $Asset.ProtectAt) {
        Write-host "⚠️   Asset is set to indefinite Learning Mode!" -ForegroundColor DarkYellow
    } else {
        Write-Host "Will Be Segmented On: $(Convert-MsTimestampToIso -MsTimestamp $Asset.ProtectAt)" -ForegroundColor DarkMagenta
    }
    Write-SeparatorLine -DivisionFactor 4 -Characters "-" -ForegroundColor DarkMagenta
    # Enumerate the segment simulation results
    foreach ($Result in $Asset.SegmentSimulationResults) {
        Write-SeparatorLine -DivisionFactor 3 -Characters "-" -ForegroundColor DarkCyan -TabCount 1
        $ValidProcesses = $Result.localProcessesList | Where-Object { $_ -ne "Unknown" -and $_ -ne "" }
        # Need to cast the protocolType to an int32 integer to use the mapping table - the value from the result is int64
        Write-Host "$("`t"*1)$($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) --> $($Asset.Name) ($($Asset.Id))" -ForegroundColor Cyan
        Write-Host "$("`t"*1)Number of Occurences: $($Result.occurred)" -ForegroundColor DarkCyan
        Write-Host "$("`t"*1)Last observed at: $(((Convert-DateTimeToLocal -DateTime $Result.lastTimeSeen).Datetime).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz"))" -ForegroundColor DarkCyan
        if (($null -ne $ValidProcesses) -and ($ValidProcesses.Count -gt 0)) {
            Write-Host "$("`t"*1)Connections landed on local processes:" -ForegroundColor DarkCyan
            foreach ($Process in $ValidProcesses) {
                Write-Host "$("`t"*2) - $($Process)" -ForegroundColor DarkCyan
            }
        }
        if ($Result.coveredEntities.Count -gt 0) {
            Write-SeparatorLine -DivisionFactor 4 -Characters "=" -ForegroundColor DarkGreen -TabCount 1
            Write-Host "$("`t"*1)The following entities will be allowed to connect to $($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port)after semgnetation:" -ForegroundColor DarkGreen
            foreach ($Entity in $Result.coveredEntities) {
                Write-Host "$("`t"*2)✅   - $($Entity.name) ($($Entity.id)) -✅-> $($Asset.Name):$($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) - Observed $($Entity.count) times" -ForegroundColor DarkGreen
            }
            Write-SeparatorLine -DivisionFactor 4 -Characters "=" -ForegroundColor DarkGreen -TabCount 1
        } else {
            Write-Host "$("`t"*1) ⚠️   There are no observed entities that will be OUTRIGHT allowed to connect to $($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) after semgnetation!" -ForegroundColor DarkYellow
        }
        if ($Result.coveredByMfaEntities.Count -gt 0) {
            Write-SeparatorLine -DivisionFactor 4 -Characters "=" -ForegroundColor DarkBlue -TabCount 1
            Write-Host "$("`t"*1)The following entities will be prompoted for MFA to connect to $($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) after semgnetation:" -ForegroundColor DarkBlue
            foreach ($Entity in $Result.coveredByMfaEntities) {
                Write-Host "$("`t"*2)⚠️   - $($Entity.name) ($($Entity.id)) -⏳-> $($Asset.Name):$($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) - Observed $($Entity.count) times" -ForegroundColor DarkBlue
            }
            Write-SeparatorLine -DivisionFactor 4 -Characters "=" -ForegroundColor DarkBlue -TabCount 1
        }
        else {
            Write-Host "$("`t"*1) ℹ️   There are no observed entities that will be prompoted for MFA to connect to $($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) after semgnetation!" -ForegroundColor DarkBlue
        }
        if ($Result.uncoveredEntities.Count -gt 0) {
            Write-SeparatorLine -DivisionFactor 4 -Characters "=" -ForegroundColor Red -TabCount 1
            Write-Host "$("`t"*1)The following entities will be BLOCKED FROM CONNECTING to $($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) after semgnetation:" -ForegroundColor Red
            foreach ($Entity in $Result.uncoveredEntities) {
                Write-Host "$("`t"*2)📛   - $($Entity.name) ($($Entity.id)) -❌-> $($Asset.Name):$($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) - Observed $($Entity.count) times" -ForegroundColor Red
            }
            Write-SeparatorLine -DivisionFactor 4 -Characters "=" -ForegroundColor Red -TabCount 1
        } else {
            Write-Host "$("`t"*1) ℹ️   There were no observed entities that will be OUTRIGHT blocked from connecting to $($script:ProtocolTypeMap[[int]$Result.protocolType])/$($Result.port) after semgnetation!" -ForegroundColor Green
        }
        Write-SeparatorLine -DivisionFactor 3 -Characters "-" -ForegroundColor DarkCyan -TabCount 1
    }
    Write-Host "`n"
}

<#
MAIN SCRIPT EXECUTION BEGINS HERE
#>
# Display Zero Networks ASCII art banner
Write-Host @"
.---------------------------------------------------------------------------------.
|                                                                                 |
|                                                                                 |
|   /\/|  _____                _   _      _                      _          /\/|  |
|  |/\/  |__  /___ _ __ ___   | \ | | ___| |___      _____  _ __| | _____  |/\/   |
|          / // _ | '__/ _ \  |  \| |/ _ | __\ \ /\ / / _ \| '__| |/ / __|        |
|         / /|  __| | | (_) | | |\  |  __| |_ \ V  V | (_) | |  |   <\__ \        |
|        /____\___|_|  \___/  |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_|___/        |
|                                                                                 |
|                                                                                 |
'---------------------------------------------------------------------------------'
"@ -ForegroundColor DarkBlue
Write-Host ""


# Set API Key for ZeroNetworks module - If key invalid, this will throw an error
Set-ZnApiKey -ApiKey $ApiKey
Write-Host "API Key set successfully" -ForegroundColor Green

<#
 Try to extract environment details from API Key, and configure HTTP headers 
 and API URL for custom API calls that are not supported by the ZeroNetworks module
#>
$TokenDetails = Read-ZNJWTtoken -token $ApiKey
if (-not ($TokenDetails.e_name -and $TokenDetails.aud)) {
    throw "Failed to extract environment details from API Key"
}
else {
    $Environment = $TokenDetails.e_name
    $BaseUrl = $TokenDetails.aud
    Write-Host "Extracted environment details from API Key:" -ForegroundColor Green
    Write-Host "Environment: $($Environment)`nBase URL: $($BaseUrl)" -ForegroundColor Green

    $Script:ApiUrl = "https://$BaseUrl/api/v1"
    $Script:Headers = @{
        "Authorization" = "$($ApiKey)"
        "Content-Type"  = "application/json"
    }
    Write-Host "Configured HTTP headers and API URL for custom API calls" -ForegroundColor Green  
}

# Calculate From timestamp if not provided (default to 7 days ago)
if (-not $From) {
    $From = (Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    Write-Host "From timestamp not provided, using -From value of 7 days ago: $From" -ForegroundColor Yellow
}

# Convert $From ISO timestamp string to milliseconds integer timestamp
$FromMsTimestamp = Convert-IsoTimestampToMs -IsoTimestamp $From
Write-Host "Converted From timestamp to milliseconds: $FromMsTimestamp" -ForegroundColor Green

# Retrieve the relevant assets using ZeroNetworks module. 
# If AssetId is provided, retrieve only the single asset with that ID.
# If AssetId is not provided, retrieve all assets currently in learning mode.
if ($AssetId) {
    $Assets = @(Get-RequiredZnAssets -AssetId $AssetId -SkipLearningFilter:$SkipLearningFilter)
}
else {
    $Assets = @(Get-RequiredZnAssets -SkipLearningFilter:$SkipLearningFilter)   
}

#Write-Host "---`n$($Assets | ConvertTo-Json -Depth 10 -Compress -AsArray | Out-String)`n---"

# Iterate over all retrieve assets and run segment simulation for each asset
foreach ($Asset in $Assets) {
    $Results = @(Get-AssetSegmentSimulationResults -AssetId $Asset.Id -Direction $Direction -TrafficType $TrafficType -IgnorePendingRules:$IgnorePendingRules -From $FromMsTimestamp -ShowDisabledRules:$ShowDisabledRules)
    $Asset | Add-Member -MemberType NoteProperty -Name "SegmentSimulationResults" -Value $Results
}
Write-Host "Finished retrieving segment simulation results for $($Assets.Count) assets" -ForegroundColor Green

# Filter $Assets to only include assets that have > 0 segment simulation results
$AssetsWithResults = $Assets | Where-Object { $_.SegmentSimulationResults.Count -gt 0 }
# If there are assets with results, print them for each asset
if ($AssetsWithResults.Count -gt 0) {
    Write-Host "Filtered down to $($AssetsWithResults.Count) assets that returned segment simulation results" -ForegroundColor Green
    # Iterate over the filtered assets and print the segment simulation results
    foreach ($Asset in $AssetsWithResults) {
        Write-AssetSegmentSimulationResults -Asset $Asset
    }
} else {
    # Else exit with a warning
    Write-Host "No assets returned segment simulation results. Exiting..." -ForegroundColor DarkYellow
}