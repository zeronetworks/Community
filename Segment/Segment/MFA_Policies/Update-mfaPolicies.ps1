<#
.SYNOPSIS
    Audits and optionally updates inbound reactive policies to set `useDefaultIdp` = true.
.DESCRIPTION
    Fetches MFA inbound reactive policies from Zero Networks Segment API endpoint.
    Computes the percentage that do not use the default IdP.
    Prompts user for approval before performing idempotent updates.
.PARAMETER baseURI
    The base API URI (e.g., https://zncustlabs-admin.zeronetworks.com/api/v1/).
.PARAMETER APIKey
    The API key used for authentication.
.PARAMETER DryRun
    Optional switch to simulate updates without changing policies.
.EXAMPLE
    .\Update-mfaPolicies.ps1 -baseURI "https://zncustlabs-admin.zeronetworks.com/api/v1/" -APIKey "eyJHx***********************Mg" -DryRun
.NOTES
    Author: Ken Ward : Galaxy AI (GPT-5)
    Date: 2026-02-04
#>
param (
    [Parameter(Mandatory=$true)][string]$envID = "",
    [Parameter(Mandatory=$true)][string]$baseURI,
    [Parameter(Mandatory=$true)][string]$APIKey,
    [switch]$DryRun
)

# --- Input Validation ---
if ([string]::IsNullOrWhiteSpace($APIKey)) { throw "APIKey cannot be empty." }
if ([string]::IsNullOrWhiteSpace($baseURI)) { throw "baseURI cannot be empty." }
$baseURI = $baseURI.TrimEnd('/')

# --- Header Initialization ---
$znHeaders = @{
    "Authorization" = $APIKey
    "Content-Type"  = "application/json"
    "zn-env-id"     = $envID
}

# --- Retrieve All Policies with Pagination ---
$allPolicies = @()
$offset = 0
do {
    $endpoint = "$baseURI/protection/reactive-policies/inbound?_limit=100&_offset=$offset&_add_builtins=false&_add_ancestors=true&order=desc&orderColumns[]=createdAt"
    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method Get -Headers $znHeaders -ErrorAction Stop
        $batch = $response.items
        if ($batch) { $allPolicies += $batch }
        $offset += 100
    }
    catch {
        Write-Error "Failed to retrieve policies: $_"
        break
    }
} while ($batch.Count -gt 0)

if (-not $allPolicies) { Write-Warning "No policies retrieved. Exiting."; return }

# --- Analysis ---
$totalPolicies = $allPolicies.Count
$defaultIdpFalse = $allPolicies | Where-Object { $_.useDefaultIdp -eq $false }
$percentageFalse = [math]::Round(($defaultIdpFalse.Count / $totalPolicies) * 100, 2)

Write-Host "$percentageFalse% of policies have 'useDefaultIdp' set to false." -ForegroundColor Yellow

# --- Prompt for Update ---
if (-not $DryRun) {
    $updateChoice = Read-Host "Would you like to set 'useDefaultIdp' to true for all false policies? (Y/N)"
    if ($updateChoice -ne 'Y') { Write-Host "Aborted by user."; return }
} else {
    Write-Host "[Dry-Run] No policies will be modified." -ForegroundColor Cyan
}

foreach ($policy in $defaultIdpFalse) {
    $policyId = $policy.id
    $updateUri = "$baseURI/protection/reactive-policies/inbound/$policyId"

    # --- Build Payload ---
    $payload = @{}
    $policy.PSObject.Properties | ForEach-Object {
        if ($_.Name -ne 'id' -and $_.Name -ne 'context') { $payload[$_.Name] = $_.Value }
    }
    $payload['useDefaultIdp'] = $true
    $jsonPayload = $payload | ConvertTo-Json -Depth 8

    if ($DryRun) {
        Write-Host "[DRY-RUN] Would update policy $policyId (useDefaultIdp -> true)"
        continue
    }

    try {
        Invoke-RestMethod -Uri $updateUri -Method Put -Headers $znHeaders -Body $jsonPayload -ErrorAction Stop
        Write-Host "Updated policy $policyId" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to update $policyId : $_"
    }
}