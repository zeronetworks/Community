#=============================================================================
# Export Inbound Rules for Members of a Zero Networks Group
#=============================================================================
#
# VERSION:
# 1.0.0 - Initial release
# - Basic functionality for exporting inbound rules for group members
# - CSV export with detailed rule information
# - Console output with formatted table view
#
# AUTHOR:
# Anthony Williams (@anthonws)
# GitHub: https://github.com/anthonws
#
# LEGAL DISCLAIMER:
# This script is provided "AS IS" without warranty of any kind, either express
# or implied, including but not limited to the implied warranties of merchantability
# and fitness for a particular purpose. The entire risk arising out of the use or
# performance of this script remains with you. In no event shall the authors or
# copyright holders be liable for any damages whatsoever (including, without
# limitation, damages for loss of business profits, business interruption, loss
# of business information, or other pecuniary loss) arising out of the use of or
# inability to use this script.
#
# OVERVIEW:
# This PowerShell script exports inbound rules for all assets that are members
# of a specified Zero Networks group. It provides a comprehensive view of the
# inbound access rules that apply to group members, including source, destination,
# protocols, ports, and rule states.
#
# SYNOPSIS:
# .\Export_Inbound_Rules_Members_of_Group.ps1 [-TargetGroupId <string>]
#
# DESCRIPTION:
# The script performs the following operations:
# 1. Connects to Zero Networks using API credentials
# 2. Retrieves all groups and assets from the Zero Networks environment
# 3. Identifies assets that are members of the specified group
# 4. Collects all inbound rules for those assets
# 5. Exports the results to a CSV file and displays them in a formatted table
#
# OUTPUT:
# - CSV file: Contains detailed information about all inbound rules
#   - Asset name
#   - Source and destination entities
#   - Destination process
#   - Protocol and port information
#   - Rule type (Allow/Block/Monitor)
#   - Rule state (Active/Inactive)
#   - Rule description
#
# - Console output: Displays a formatted table of the rules
#
# PARAMETERS:
# -TargetGroupId: The ID of the Zero Networks group to analyze
#                Format examples:
#                - g:c:cccccccc (Custom group)
#                - g:s:ssssssss (System group)
#                - g:a:aaaaaaaa (Active Directory group)
#                - g:t:tttttttt (Tags group)
#                - g:o:oooooooo (OT/IoT group)
#                - g:u:uuuuuuuu (Organizational Unit group)
#
# REQUIREMENTS:
# - PowerShell 5.1 or higher
# - Zero Networks PowerShell module
# - Valid Zero Networks API key
#
#=============================================================================

param(
    [string]$TargetGroupId
)

# If no TargetGroupId is provided, prompt for it
if (-not $TargetGroupId) {
    Write-Host "`nZero Networks Group ID Examples:"
    Write-Host "- g:c:cccccccc (Custom group)"
    Write-Host "- g:s:ssssssss (System group)"
    Write-Host "- g:a:aaaaaaaa (Active Directory group)"
    Write-Host "- g:t:tttttttt (Tags group)"
    Write-Host "- g:o:oooooooo (OT/IoT group)"
    Write-Host "- g:u:uuuuuuuu (Organizational Unit group)"
    $TargetGroupId = Read-Host "`nEnter the Zero Networks Group ID"
}

Write-Host "`nInitializing Zero Networks connection..."
Set-ZNApiKey -ApiKey ''

$protocolMap = @{
    1 = "ICMP"
    2 = "IGMP"
    6 = "TCP"
    17 = "UDP"
    47 = "GRE"
    50 = "ESP"
    51 = "AH"
    132 = "SCTP"
    255 = "Other"
    256 = "Any"
}

$actionMap = @{
    1 = "Allow"
    2 = "Block"
    3 = "Monitor"
}

Write-Host "Fetching groups..."
# Get all groups
$offset = 0
$limit = 400
$allGroups = @()

do {
    $groupResponse = Get-ZnGroup -Limit $limit -Offset $offset
    if ($groupResponse) {
        $allGroups += $groupResponse.Items
    }
    $offset += $limit
} while ($groupResponse.Items.Count -eq $limit)

# Find target group
$targetGroup = $allGroups | Where-Object { $_.id -eq $TargetGroupId }
if (-not $targetGroup) {
    Write-Warning "Could not find target group with ID: $TargetGroupId"
    exit
}

Write-Host "Fetching assets..."
# Get all assets
$assets = @()
$offset = 0
$limit = 400

do {
    $assetResponse = Get-ZnAsset -Limit $limit -Offset $offset
    if ($assetResponse) {
        $assets += $assetResponse.Items
    }
    $offset += $limit
} while ($assetResponse.Items.Count -eq $limit)

Write-Host "Finding group members..."
# Filter assets in target group
$matchingAssets = @()
foreach ($asset in $assets) {
    if (-not $asset.id) { continue }
    
    $memberResponse = Get-ZNAssetMemberOf -AssetId $asset.id
    $memberOf = if ($memberResponse.PSObject.Properties.Name -contains 'Items') {
        $memberResponse.Items
    } else {
        $memberResponse
    }
    
    if ($memberOf | Where-Object { $_.id -eq $TargetGroupId }) {
        $matchingAssets += @{
            Name = $asset.name
            Id = $asset.id
        }
    }
}

Write-Host "Found $($matchingAssets.Count) assets in group. Fetching inbound rules..."

# Get inbound rules for matching assets
$results = @()
foreach ($asset in $matchingAssets) {
    Write-Host "Processing rules for $($asset.Name)..."
    $offset = 0
    $inboundRules = @()
    
    do {
        $ruleResponse = Get-ZnAssetInboundRule -AssetId $asset.Id -Limit $limit -Offset $offset
        if ($ruleResponse) {
            $inboundRules += $ruleResponse.Items
        }
        $offset += $limit
    } while ($ruleResponse.Items.Count -eq $limit)

    foreach ($rule in $inboundRules) {
        # Get source and destination based on rule direction
        $source = if ($rule.Direction -eq 1) {  # Inbound
            if ($rule.RemoteEntityInfos.Count -gt 0) {
                $rule.RemoteEntityInfos[0].Name
            } else { "Any" }
        } else {  # Outbound
            if ($rule.LocalEntityInfos.Count -gt 0) {
                $rule.LocalEntityInfos[0].Name
            } else { "Any" }
        }
        
        $destination = if ($rule.Direction -eq 1) {  # Inbound
            if ($rule.LocalEntityInfos.Count -gt 0) {
                $rule.LocalEntityInfos[0].Name
            } else { "Any" }
        } else {  # Outbound
            if ($rule.RemoteEntityInfos.Count -gt 0) {
                $rule.RemoteEntityInfos[0].Name
            } else { "Any" }
        }

        # Get destination process
        $destinationProcess = if ($rule.LocalProcessesList -and $rule.LocalProcessesList -ne "*") {
            $rule.LocalProcessesList
        } else { 
            "Any" 
        }

        # Get protocol and port
        $protocols = @()
        $ports = @()
        
        if ($rule.PortsList.Count -gt 0) {
            foreach ($portInfo in $rule.PortsList) {
                if ($portInfo.ProtocolType -ne $null) {
                    $protocolName = if ($protocolMap.ContainsKey($portInfo.ProtocolType)) {
                        $protocolMap[$portInfo.ProtocolType]
                    } else {
                        "Unknown ($($portInfo.ProtocolType))"
                    }
                    $protocols += $protocolName
                }
                if ($portInfo.Ports) {
                    $ports += $portInfo.Ports
                }
            }
        }

        $protocol = if ($protocols.Count -gt 0) {
            ($protocols | Select-Object -Unique) -join ", "
        } else { "Any" }

        $port = if ($ports.Count -gt 0) {
            ($ports | Select-Object -Unique) -join ", "
        } else { "Any" }

        $results += [PSCustomObject]@{
            Asset = $asset.Name
            Source = $source
            Destination = $destination
            DestinationProcess = $destinationProcess
            Protocol = $protocol
            Port = $port
            RuleType = $actionMap[$rule.Action]
            State = if ($rule.State -eq 1) { "Active" } else { "Inactive" }
            Description = if ($rule.Description) { $rule.Description } else { "" }
        }
    }
}

# Export to CSV
$safeGroupId = $TargetGroupId -replace ':', '_'
$csvPath = Join-Path $PSScriptRoot "InboundRules_For_Group_$safeGroupId.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

# Display results in table format
Write-Host "`nInbound Rules for Members of Group: $($targetGroup.name)"
Write-Host "----------------------------------------"
$results | Format-Table -Property @(
    @{Label="Source"; Expression={$_.Source}; Width=20},
    @{Label="Destination"; Expression={$_.Destination}; Width=20},
    @{Label="Destination Process"; Expression={$_.DestinationProcess}; Width=30},
    @{Label="Protocol"; Expression={$_.Protocol}; Width=10},
    @{Label="Port"; Expression={$_.Port}; Width=10},
    @{Label="Rule Type"; Expression={$_.RuleType}; Width=10},
    @{Label="State"; Expression={$_.State}; Width=10}
) -AutoSize

Write-Host "`nResults exported to: $csvPath"