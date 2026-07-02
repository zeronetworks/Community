<#
.SYNOPSIS
    Zero Networks -> Microsoft Sentinel log ingestion setup (Az PowerShell).

.DESCRIPTION
    PowerShell equivalent of deploy.sh for environments without the Az CLI.
    Runs as the signed-in Az PowerShell user (must be able to create Entra apps
    and assign RBAC roles). It:
      1. Creates (or reuses) an Entra application + service principal.
      2. Generates a client secret.
      3. Deploys azuredeploy.json (DCE, custom tables, DCR, role assignment),
         passing the service principal object ID into the template.
      4. Prints all outputs: app/client ID, tenant, secret, ingestion endpoint,
         and DCR immutable ID.

    Prereqs: Az PowerShell modules installed (Az.Accounts, Az.Resources) and
    connected (`Connect-AzAccount`), correct subscription selected
    (`Set-AzContext -Subscription <sub>`). The target resource group and
    Sentinel workspace must already exist.

.EXAMPLE
    ./deploy.ps1 -ResourceGroup my-rg -WorkspaceName my-sentinel-ws
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string] $WorkspaceName,

    [string] $AppName     = "ZeroNetworks-LogIngestion",
    [string] $Location    = "",
    [string] $DceName     = "dce-zeronetworks",
    [string] $DcrName     = "dcr-zeronetworks",
    [int]    $SecretYears = 2
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$TemplateFile = Join-Path $PSScriptRoot "azuredeploy.json"

# --- preflight ---
if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
    throw "Az PowerShell module 'Az.Resources' not found. Install with: Install-Module Az -Scope CurrentUser"
}
$ctx = Get-AzContext
if (-not $ctx) {
    throw "Not connected. Run Connect-AzAccount (and Set-AzContext -Subscription <sub>) first."
}
$TenantId = $ctx.Tenant.Id

if ([string]::IsNullOrEmpty($Location)) {
    $Location = (Get-AzResourceGroup -Name $ResourceGroup).Location
}

# --- Entra application ---
Write-Host "==> Creating / reusing Entra application '$AppName'..."
$app = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $app) {
    $app = New-AzADApplication -DisplayName $AppName -SignInAudience AzureADMyOrg
}
$AppId = $app.AppId

Write-Host "==> Ensuring service principal exists..."
$sp = Get-AzADServicePrincipal -ApplicationId $AppId -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sp) {
    $sp = New-AzADServicePrincipal -ApplicationId $AppId
}
$SpObjectId = $sp.Id

# Allow Entra a moment to replicate the new app before resetting credentials.
for ($i = 0; $i -lt 6; $i++) {
    if (Get-AzADApplication -ApplicationId $AppId -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Seconds 10
}

Write-Host "==> Generating client secret..."
$cred = New-AzADAppCredential -ApplicationId $AppId `
    -StartDate (Get-Date) `
    -EndDate (Get-Date).AddYears($SecretYears)
$ClientSecret = $cred.SecretText

# --- ARM deployment ---
Write-Host "==> Deploying ARM template (DCE, tables, DCR, role assignment)..."
$deployName = "zn-ingestion-{0}" -f (Get-Date -Format "yyyyMMddHHmmss")
$deployment = New-AzResourceGroupDeployment `
    -ResourceGroupName $ResourceGroup `
    -Name $deployName `
    -TemplateFile $TemplateFile `
    -workspaceName $WorkspaceName `
    -servicePrincipalObjectId $SpObjectId `
    -location $Location `
    -dceName $DceName `
    -dcrName $DcrName

$IngestEndpoint = $deployment.Outputs["logIngestionEndpoint"].Value
$DcrImmutableId = $deployment.Outputs["dcrImmutableId"].Value

# --- summary ---
@"

================ Zero Networks ingestion setup complete ================
Tenant ID:                   $TenantId
Application (client) ID:     $AppId
Service principal objectId:  $SpObjectId
Client secret:               $ClientSecret
Logs ingestion endpoint:     $IngestEndpoint
DCR immutable ID:            $DcrImmutableId
Stream names:                Custom-ZeroNetworksAudit_CL
                             Custom-ZeroNetworksNetworkActivity_CL
                             Custom-ZeroNetworksIdentityActivity_CL
                             Custom-ZeroNetworksRpcActivity_CL
========================================================================
Store the client secret now - Azure will not show it again.
"@ | Write-Host
