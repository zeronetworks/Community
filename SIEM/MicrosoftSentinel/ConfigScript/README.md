# Zero Networks → Microsoft Sentinel — Log Ingestion Setup

This package provisions the Azure side of the Zero Networks log ingestion pipeline:

- An **Entra application** + service principal with a **client secret**
- A **Data Collection Endpoint (DCE)**
- Four **custom Log Analytics tables** — one per Zero Networks log type
- A **Data Collection Rule (DCR)** bound to the DCE
- A **Monitoring Metrics Publisher** role assignment on the DCR for the app

## Files

| File | Purpose |
|------|---------|
| `azuredeploy.json` | ARM template — DCE, tables, DCR, and the role assignment. |
| `deploy.sh` | Bash wrapper (Az CLI) — creates the Entra app + secret, then deploys the template. |
| `deploy.ps1` | PowerShell wrapper (Az PowerShell module) — same flow, for environments without the Az CLI. |

Use **either** `deploy.sh` **or** `deploy.ps1` — they do the same thing. Both read `azuredeploy.json`.

## Why a wrapper script?

ARM templates cannot create Entra (Azure AD) applications natively — app registrations live in Microsoft Graph. The wrapper runs as **you** (the signed-in user), creates the app + secret first, then passes the service principal's object ID into the template for the role assignment. This avoids needing a privileged managed identity inside the deployment.

## Prerequisites

- An **existing** resource group containing your **Sentinel / Log Analytics workspace**.
- Permission to **create Entra applications** (e.g. Application Administrator or Application Developer).
- **Owner** or **User Access Administrator** on the resource group (required for the role assignment).
- One of:
  - **Az CLI** (`az`) — for `deploy.sh`
  - **Az PowerShell** modules `Az.Accounts` + `Az.Resources` — for `deploy.ps1`

## Usage

### Bash / Az CLI

```bash
az login
az account set -s <subscription-id-or-name>

./deploy.sh -g <resource-group> -w <sentinel-workspace-name>
```

Options: `-n` app name, `-l` location, `--dce-name`, `--dcr-name`, `--secret-years`. Run `./deploy.sh -h` for details.

### PowerShell / Az module

```powershell
Connect-AzAccount
Set-AzContext -Subscription <subscription-id-or-name>

./deploy.ps1 -ResourceGroup <resource-group> -WorkspaceName <sentinel-workspace-name>
```

Options: `-AppName`, `-Location`, `-DceName`, `-DcrName`, `-SecretYears`.

> The resource group is the deployment target; the location defaults to the resource group's region if not specified.

## Outputs

On success the script prints everything needed to configure Zero Networks:

- **Tenant ID**
- **Application (client) ID**
- **Service principal object ID**
- **Client secret** — *shown once; store it now*
- **Logs ingestion endpoint** (from the DCE)
- **DCR immutable ID**
- **Stream names** for the four log types

## Log tables / streams

| Log type | Table | DCR stream |
|----------|-------|------------|
| Audit | `ZeroNetworksAudit_CL` | `Custom-ZeroNetworksAudit_CL` |
| Network activity | `ZeroNetworksNetworkActivity_CL` | `Custom-ZeroNetworksNetworkActivity_CL` |
| Identity activity | `ZeroNetworksIdentityActivity_CL` | `Custom-ZeroNetworksIdentityActivity_CL` |
| RPC activity | `ZeroNetworksRpcActivity_CL` | `Custom-ZeroNetworksRpcActivity_CL` |

> **Placeholder schemas:** each table and its matching DCR stream currently define only `TimeGenerated` + `RawData`. Replace these `columns` in `azuredeploy.json` with the real schema for each log type before going to production. The table schema and the DCR `streamDeclarations` must match; any field shaping goes in each data flow's `transformKql` (currently `source`, a straight passthrough).

## Re-running

The wrapper is safe to re-run: it reuses the existing app/service principal if one with the same display name exists, and the ARM deployment is idempotent. Note that re-running **generates a new client secret** each time.
