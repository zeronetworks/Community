# Zero Networks Azure Connector: Logging Policies

These ARM templates use Azure Policy to keep the Azure logs the Zero Networks Azure Connector reads turned on and routed to a log storage account. Each assignment covers existing resources (through remediation) and resources created later.

| Template | Scope | What it assigns |
|----------|-------|-----------------|
| `allLogs-subscription.json` | Subscription | Built-in initiative **Enable allLogs category group resource logging for supported resources to storage** (`b6b86da9-e527-49de-ac59-6af0a9db10b8`), plus remediation tasks |
| `allLogs-managementGroup.json` | Management group | Same initiative, no remediation tasks (see [Remediation at management group scope](#remediation-at-management-group-scope)) |
| `blobLogs-subscription.json` | Subscription | Custom definition `zn-blob-logs-to-storage` (blob `StorageRead`, `StorageWrite`, `StorageDelete` logs), its assignment, plus a remediation task |
| `blobLogs-managementGroup.json` | Management group | Same custom definition, created at the management group, and its assignment |

Each template also:

- gives the assignment a **system-assigned managed identity**,
- with the `DeployIfNotExists` effect, grants that identity **Log Analytics Contributor** (`92aaf0da-9dab-42b6-94a3-d43ce8d16293`) at the assignment scope. This is the role that every member definition of the initiative, and the custom definition, declares.
- optionally grants the same role on the **log storage account**, wherever it lives (`grantRoleOnStorageAccount`, default `true`).

With `AuditIfNotExists` or `Disabled`, the template creates no role assignments, because the assignment deploys nothing. To switch to `DeployIfNotExists` later, redeploy the template with that effect so it adds the roles.

## Which scope to use

- **Subscription**: the default choice. Remediation tasks are created with the assignment and re-evaluate compliance first, so existing resources are fixed without a second step. Expect about 20 minutes before remediated resources show as compliant.
- **Management group**: to cover every current and future subscription under a management group with one assignment. Azure creates remediation tasks for management group assignments only after the first compliance evaluation, so you run remediation as a second step.

Both use the same `#create/Microsoft.Template/uri/` portal link; the portal picks the scope from the template schema and asks for the subscription or management group.

## Deploy

**allLogs (Key Vault, Event Hubs, Service Bus, MySQL and PostgreSQL flexible servers)**

Subscription:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzeronetworks%2FCommunity%2Fmaster%2FSegment%2FAzure-Cloud-Segmentation%2FLogging-Policy%2FallLogs-subscription.json)

Management group:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzeronetworks%2FCommunity%2Fmaster%2FSegment%2FAzure-Cloud-Segmentation%2FLogging-Policy%2FallLogs-managementGroup.json)

**Blob logs (storage accounts)**

Subscription:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzeronetworks%2FCommunity%2Fmaster%2FSegment%2FAzure-Cloud-Segmentation%2FLogging-Policy%2FblobLogs-subscription.json)

Management group:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fzeronetworks%2FCommunity%2Fmaster%2FSegment%2FAzure-Cloud-Segmentation%2FLogging-Policy%2FblobLogs-managementGroup.json)

## Prerequisites and permissions

- An existing **log storage account** per region. Diagnostic settings require a regional resource and its storage destination to be in the same region.
- **Owner**, or **Resource Policy Contributor** plus **User Access Administrator** (or **Role Based Access Control Administrator**), at the target subscription or management group. The template creates a policy assignment and role assignments. The blob templates also create a policy definition.
- With `grantRoleOnStorageAccount`, the same role-assignment permission on the log storage account.
- No Zero Networks inputs are needed. After logging is on, add each log storage account as a log source in the Zero Networks portal and grant the connector VM's managed identity **Storage Blob Data Reader** on it (see [Connector-VM](../Connector-VM/README.md)).

## Parameters

### allLogs templates

| Parameter | Default | Description |
|-----------|---------|-------------|
| `storageAccountId` | Required | Resource ID of the log storage account |
| `resourceLocation` | Required | Region of the resources to cover. Must match the storage account's region. **Assign once per region** |
| `resourceTypeList` | MySQL flexible server, PostgreSQL flexible server, Key vault, Event Hubs namespace, Service Bus namespace | Lowercase resource types to cover, from the initiative's allowed list |
| `diagnosticSettingName` | `setByPolicy-Storage` | Name of the diagnostic setting created on each resource |
| `effect` | `DeployIfNotExists` | Or `AuditIfNotExists` / `Disabled`, which create no role assignments |
| `assignmentName` | `zn-logs-<resourceLocation>` | Up to 64 characters at subscription scope, 24 at management group scope (the default is trimmed to fit) |
| `grantRoleOnStorageAccount` | `true` | Also grant the role on the storage account |
| `createRemediation` (subscription only) | `true` | Create one remediation task per resource type, filtered to `resourceLocation` |
| `location` | Deployment region | Region of the assignment's managed identity |

### blobLogs templates

| Parameter | Default | Description |
|-----------|---------|-------------|
| `storageAccountId` | Required | Resource ID of the log storage account. The policy skips this account, because Azure does not allow a storage account to send these logs to itself |
| `policyDefinitionName` | `zn-blob-logs-to-storage` | Custom definition name. Redeploying updates it |
| `diagnosticSettingName` | `zn-blob-logs` | Name of the diagnostic setting on each blob service |
| `effect` | `DeployIfNotExists` | Or `AuditIfNotExists` / `Disabled`, which create no role assignments |
| `assignmentName` | `zn-blob-logs-<hash of storageAccountId>` | Up to 64 characters at subscription scope, 24 at management group scope |
| `grantRoleOnStorageAccount` | `true` | Also grant the role on the storage account |
| `createRemediation` (subscription only) | `true` | Create a remediation task that re-evaluates compliance first |
| `location` | Deployment region | Region of the assignment's managed identity |

## Azure CLI / PowerShell

Deploy at subscription scope:

```bash
az deployment sub create --location <region> \
  --template-uri https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Azure-Cloud-Segmentation/Logging-Policy/allLogs-subscription.json \
  --parameters storageAccountId=<storage-account-resource-id> resourceLocation=<region>
```

```powershell
New-AzSubscriptionDeployment -Location <region> `
  -TemplateUri 'https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Azure-Cloud-Segmentation/Logging-Policy/allLogs-subscription.json' `
  -storageAccountId '<storage-account-resource-id>' -resourceLocation '<region>'
```

Deploy at management group scope:

```bash
az deployment mg create --management-group-id <management-group-id> --location <region> \
  --template-uri https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Azure-Cloud-Segmentation/Logging-Policy/blobLogs-managementGroup.json \
  --parameters storageAccountId=<storage-account-resource-id>
```

```powershell
New-AzManagementGroupDeployment -ManagementGroupId <management-group-id> -Location <region> `
  -TemplateUri 'https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Azure-Cloud-Segmentation/Logging-Policy/blobLogs-managementGroup.json' `
  -storageAccountId '<storage-account-resource-id>'
```

Swap in the other template file names the same way. Run `what-if` first (`az deployment sub|mg what-if`, or `-WhatIf`) to preview.

## Remediation at management group scope

After the assignment's first compliance evaluation (it can take up to about 30 minutes; you can start an on-demand scan per subscription with `az policy state trigger-scan --subscription <id>`), create the remediation tasks. For the allLogs initiative, create one per resource type:

```bash
MG=<management-group-id>
ASSIGNMENT=zn-logs-<region>
for REF in dbformysql-flexibleservers dbforpostgresql-flexibleservers keyvault-vaults eventhub-namespaces servicebus-namespaces; do
  az policy remediation create --management-group "$MG" --name "$ASSIGNMENT-$REF" \
    --policy-assignment "/providers/Microsoft.Management/managementGroups/$MG/providers/Microsoft.Authorization/policyAssignments/$ASSIGNMENT" \
    --definition-reference-id "$REF" --location-filters <region>
done
```

For the blob logs assignment, run one `az policy remediation create` without `--definition-reference-id`. Remediation tasks are also available in the Azure portal under **Policy ⇒ Remediation**.

## Removing an assignment

Delete the role assignments before the policy assignment. Deleting the policy assignment also deletes its managed identity, which leaves the role assignments behind as **Identity not found** entries.

```bash
PRINCIPAL=$(az policy assignment show --name <assignment-name> --query identity.principalId -o tsv)
az role assignment delete --assignee "$PRINCIPAL" --scope /subscriptions/<subscription-id>
az role assignment delete --assignee "$PRINCIPAL" --scope <storage-account-resource-id>
az policy assignment delete --name <assignment-name>
```

At management group scope, add `--scope /providers/Microsoft.Management/managementGroups/<management-group-id>` to the `az policy assignment` commands and use the same management group as the role assignment scope. The diagnostic settings the policy created stay on the resources. For the blob templates, also delete the custom definition with `az policy definition delete` (add `--management-group` at management group scope).

## Limitations

- **One assignment per region.** The initiative's member definitions only act on resources in `resourceLocation`, and each region needs its own log storage account.
- **Blob logs and regions.** The custom definition has no region filter (blob services expose no location to filter on). Remediation fails for storage accounts outside the log storage account's region, because diagnostic settings require a same-region storage destination. Those accounts stay non-compliant. Use the subscription or management group whose storage accounts share the log account's region, or turn on blob logging for the others with scripts.
- **Not covered here.** Azure SQL auditing (built-in `Configure SQL servers to have auditing enabled`, `f4c68484-132f-41f9-9b6d-3e4b1cb55036`) and virtual network flow logs (built-in `Deploy a Flow Log resource with target virtual network`, `cd6f7aff-2845-4dab-99f2-6d1754a754b0`) need their own assignments. MySQL flexible server also needs the `audit_log_enabled` and `audit_log_events` (`CONNECTION_V2`) server parameters, which no policy here sets.
- **Role propagation.** The remediation tasks start right after the role assignments are created. If Azure has not propagated the role yet, some remediation deployments fail with an authorization error; rerun the remediation task a few minutes later.
- **Built-in definitions change.** Microsoft versions the initiative (1.1.0 when these templates were written). Check the current version before assigning.
