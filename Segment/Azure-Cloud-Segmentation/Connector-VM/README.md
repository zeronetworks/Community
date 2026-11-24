# Zero Networks Azure Connector: Connector VM

This ARM template creates the VM that runs the Zero Networks Azure Connector and, optionally, installs the connector on it:

- A **Windows Server VM** (default `2025-datacenter-azure-edition`, Trusted Launch) with a **system-assigned managed identity**
- A **network interface with no public IP address**, and optionally a **network security group with no custom rules** (no inbound access)
- Optionally a **new virtual network and subnet**, with your choice of outbound path: a new **NAT gateway**, an existing NAT gateway, Azure default outbound access, or none. Or the VM joins an **existing subnet**
- The **Storage Blob Data Reader** role for the VM's managed identity on each **log storage account** you list, in any resource group or subscription
- Optionally a **Custom Script Extension** that downloads the connector package, extracts it, and runs `install.ps1 -Token <installation token>`

## Deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzeronetworks%2FCommunity%2Fmaster%2FSegment%2FAzure-Cloud-Segmentation%2FConnector-VM%2Fazuredeploy.json)

Deploy into the resource group that will hold the VM. Create the resource group first if needed.

## Get the Zero Networks inputs

The installation needs two values from the Zero Networks portal. **Both are temporary**, so get them right before you deploy:

1. Navigate to **Settings ⇒ Entity repositories ⇒ Cloud environments** and open the tenant.
2. In the **Clusters** section, open the cluster and generate an **installation token** (Admin user only. API keys cannot generate it).
3. Copy the **download link** of the package instead of downloading it. The link is also available from the API (`GET /api/v1/download/azure-connector/installer`, `.url`).

Pass them as `installationToken` and `packageDownloadUrl`. Both are `securestring` parameters and reach the VM only through the extension's `protectedSettings`. If the deployment fails or you redeploy later, generate a new token and link.

To create the VM without installing the connector, leave both empty. You can then install manually (see the Zero Networks docs) or redeploy with both values.

## Prerequisites and permissions

- **Contributor** (or equivalent) on the target resource group.
- **Owner**, **User Access Administrator**, or **Role Based Access Control Administrator** on each log storage account (or a scope above it), to create the role assignments.
- Outbound HTTPS (TCP 443) from the VM subnet to:
  - the package download link host,
  - your environment's two Azure Connector domains (Zero Networks portal, **Settings ⇒ System ⇒ Domains**),
  - the log storage accounts.
  The connector does not support a proxy.
- When you use an **existing subnet**, it must already have an outbound path (NAT gateway, firewall route, or default outbound access), in the same region as the VM. The template does not change an existing subnet.
- When you use an **existing NAT gateway**, it must be in the same region as the VM, and you need permission to join it (`Microsoft.Network/natGateways/join/action`, included in **Network Contributor**).

## Parameters

### VM

| Parameter | Default | Description |
|-----------|---------|-------------|
| `location` | Resource group region | Region for the VM and network resources |
| `vmName` | `znCloudCollectorVm01` | Azure resource name of the VM |
| `computerName` | `znCollector01` | Windows computer name, 15 characters or fewer |
| `vmSize` | `Standard_B2s` | Example size. It must support Trusted Launch and be available in your region, zone, and quota |
| `imageSku` | `2025-datacenter-azure-edition` | `MicrosoftWindowsServer/WindowsServer` image SKU |
| `enableHotpatching` | `true` | Set to `false` if you choose a non-Azure-Edition image |
| `osDiskType` | `StandardSSD_LRS` | OS disk type |
| `osDiskSizeGB` | `0` | OS disk size in GB. `0` keeps the image default (127 GB). The connector needs at least 5 GB free |
| `availabilityZone` | empty | `1`, `2`, or `3` to pin the VM, and the new NAT gateway and its public IP, to a zone. Empty for no zone |
| `licenseType` | `None` | `Windows_Server` applies Azure Hybrid Benefit with your own Windows Server licenses |
| `enableBootDiagnostics` | `true` | Boot diagnostics with a Microsoft-managed storage account |
| `adminUsername` / `adminPassword` | Required | Local administrator. The password is a `securestring` |

### Network

| Parameter | Default | Description |
|-----------|---------|-------------|
| `existingSubnetId` | empty | Existing subnet resource ID. Empty creates a new virtual network. With an existing subnet, the outbound parameters below are ignored |
| `newVnetName`, `newVnetAddressPrefix`, `newSubnetName`, `newSubnetAddressPrefix` | `zn-azure-connector-vnet`, `10.10.0.0/16`, `zn-azure-connector-subnet`, `10.10.0.0/24` | New virtual network settings |
| `outboundAccess` | `NewNatGateway` | Outbound path of the new subnet, see [Outbound access](#outbound-access) |
| `existingNatGatewayId` | empty | NAT gateway resource ID, for `ExistingNatGateway` |
| `natGatewayName` | `<vmName>-natgw` | Name of the new NAT gateway. Its public IP is named `<natGatewayName>-pip` |
| `natGatewayIdleTimeoutMinutes` | `4` | TCP idle timeout of the new NAT gateway, 4 to 120 minutes |
| `createNsg` | `true` | Create an NSG with no custom rules on the network interface. Set to `false` if the subnet's NSG already covers the VM |
| `privateIpAddress` | empty | Static private IP address. Empty for a dynamic address |

### Connector

| Parameter | Default | Description |
|-----------|---------|-------------|
| `logStorageAccountIds` | `[]` | JSON array of log storage account resource IDs, for example `["/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/znccweu"]` |
| `installationToken` | empty | Installation token (`securestring`) |
| `packageDownloadUrl` | empty | Package download link (`securestring`) |
| `tags` | `{}` | Tags for every resource the template creates, for example `{"owner": "secops"}` |

### Outbound access

The connector makes outbound connections only, but it needs a path to the internet to download the package and reach Zero Networks. New subnets are private by default with current Azure API versions, so choose one of:

| `outboundAccess` | What the template does |
|------------------|------------------------|
| `NewNatGateway` | Creates a NAT gateway with its own static public IP and attaches it to the subnet. The VM gets no public IP. The NAT gateway's public IP is the source address of the connector's traffic, which helps if you allowlist it |
| `ExistingNatGateway` | Attaches the NAT gateway in `existingNatGatewayId`, for example a shared one used by other subnets |
| `DefaultOutboundAccess` | Turns on Azure default outbound access for the subnet. Microsoft is retiring it, so use it only for short-lived tests |
| `None` | Creates a private subnet with no internet path. Add your own route, for example through your firewall or a virtual network peering, before the install runs, or leave the install values empty and install later |

## Outputs

- `vmName`
- `managedIdentityPrincipalId`: grant this principal **Storage Blob Data Reader** on any log storage account you add later
- `privateIpAddress`
- `natGatewayPublicIp`: the public IP of the new NAT gateway, empty when the template does not create one

## Azure CLI / PowerShell

### Azure CLI

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-uri https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Azure-Cloud-Segmentation/Connector-VM/azuredeploy.json \
  --parameters adminUsername=<admin-username> \
               logStorageAccountIds='["/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>"]'
```

The CLI prompts for `adminPassword`. To also install the connector, add `installationToken=<token> packageDownloadUrl='<download-link>'` (quote the link: it contains `&`).

### PowerShell (Az module)

```powershell
$params = @{
    ResourceGroupName    = '<resource-group>'
    TemplateUri          = 'https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Azure-Cloud-Segmentation/Connector-VM/azuredeploy.json'
    adminUsername        = '<admin-username>'
    adminPassword        = (Read-Host -AsSecureString 'Local administrator password')
    logStorageAccountIds = @('/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>')
    installationToken    = (Read-Host -AsSecureString 'Installation token')
    packageDownloadUrl   = (Read-Host -AsSecureString 'Package download link')
}
New-AzResourceGroupDeployment @params
```

Run `what-if` first (`az deployment group what-if` / `New-AzResourceGroupDeployment -WhatIf`) to preview the changes.

## After the deployment

- Confirm the connector shows as **Connected** in its cluster in the Zero Networks portal.
- Add each storage account as a **log source** in the same tenant settings page.
- On the VM, the service is `ZeroAzureConnector`, its data is under `%ProgramData%\ZeroNetworks\AzureConnector`, and it logs to `zn-azure-connector.log`. The extension downloads and extracts the package to `%ProgramData%\ZeroNetworks\AzureConnectorSetup`. Extension output is under `C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension`.

## Limitations

- **Temporary inputs.** The token and download link expire. A deployment that runs after they expire fails at the extension step; generate new values and redeploy.
- **Updates and redeploying.** The installer also adds the `ZeroAzureConnectorUpdater` service, which keeps the connector up to date, so do not redeploy to upgrade. The extension runs again whenever its settings change (a new token or link), and each `install.ps1` run registers the VM as an additional connector in its cluster. Redeploy with new install values only to retry a failed install.
- **Role propagation.** Azure role assignments can take several minutes to take effect. The connector may log access errors for the storage accounts during that window.
- **VM size availability.** `Standard_B2s` may be capacity-restricted or out of quota in some regions and subscriptions. Choose another size that supports Trusted Launch if validation reports `SkuNotAvailable` or `QuotaExceeded`.
- **Same-region subnet.** `existingSubnetId` must be in the VM's region.
- **Storage accounts added later** need a manual **Storage Blob Data Reader** grant to `managedIdentityPrincipalId`, or a redeploy with the updated list.
