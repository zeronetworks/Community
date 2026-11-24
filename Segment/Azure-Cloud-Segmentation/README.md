# Zero Networks Azure Cloud Segmentation: Deploy to Azure

ARM templates that automate the Azure side of the Zero Networks **Azure Connector**: the connector VM and the Azure logs it reads. Each folder has its own README with a **Deploy to Azure** button, parameters, and Azure CLI / PowerShell commands.

| Folder | Deploys | Scope |
|--------|---------|-------|
| [`Connector-VM`](Connector-VM/README.md) | Windows Server VM with a managed identity and no public IP, optional new virtual network with a NAT gateway, Storage Blob Data Reader on the log storage accounts, and optional connector installation | Resource group |
| [`Logging-Policy`](Logging-Policy/README.md) | Azure Policy assignments that route resource logs and blob logs to a log storage account, with remediation | Subscription or management group |

## Order

1. Create the log storage accounts (one per region, dedicated to these logs).
2. Deploy **Logging-Policy** for each region, so resources write their logs to those accounts.
3. In the Zero Networks portal (cloud environment, **Clusters** section), generate an installation token and copy the package download link. **Both are temporary.**
4. Deploy **Connector-VM** with the token, the download link, and the storage account IDs.
5. In the Zero Networks portal, add each storage account as a log source and confirm the connector shows as **Connected**.

## Prerequisites

- A Zero Networks tenant with cloud network segmentation enabled, and the Azure tenant connected with synced subscriptions.
- A Zero Networks Admin user, to generate the installation token. API keys cannot generate it.
- Azure permissions listed in each folder's README.

These templates are examples to adapt to your environment. Review them and test them outside production first.
