#!/usr/bin/env bash
#
# deploy.sh — Zero Networks -> Microsoft Sentinel log ingestion setup.
#
# Runs as the signed-in az user (must be able to create Entra apps and assign
# RBAC roles). It:
#   1. Creates (or reuses) an Entra application + service principal.
#   2. Generates a client secret.
#   3. Deploys azuredeploy.json (DCE, custom tables, DCR, role assignment),
#      passing the service principal object ID into the template.
#   4. Prints all outputs: app/client ID, tenant, secret, ingestion endpoint,
#      and DCR immutable ID.
#
# Prereqs: az CLI logged in (`az login`), correct subscription selected
# (`az account set -s <sub>`). The target resource group and Sentinel
# workspace must already exist.
#
# Usage:
#   ./deploy.sh -g <resource-group> -w <workspace-name> [options]
#
# Options:
#   -g, --resource-group   (required) RG containing the Sentinel workspace
#   -w, --workspace-name   (required) existing Log Analytics / Sentinel workspace
#   -n, --app-name         Entra app display name (default: ZeroNetworks-LogIngestion)
#   -l, --location         Azure region (default: the resource group's location)
#       --dce-name         DCE name (default: dce-zeronetworks)
#       --dcr-name         DCR name (default: dcr-zeronetworks)
#       --secret-years     Client secret lifetime in years (default: 2)
#   -h, --help             Show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="$SCRIPT_DIR/azuredeploy.json"

RESOURCE_GROUP=""
WORKSPACE_NAME=""
APP_NAME="ZeroNetworks-LogIngestion"
LOCATION=""
DCE_NAME="dce-zeronetworks"
DCR_NAME="dcr-zeronetworks"
SECRET_YEARS="2"

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--resource-group) RESOURCE_GROUP="$2"; shift 2 ;;
    -w|--workspace-name)  WORKSPACE_NAME="$2"; shift 2 ;;
    -n|--app-name)        APP_NAME="$2"; shift 2 ;;
    -l|--location)        LOCATION="$2"; shift 2 ;;
    --dce-name)           DCE_NAME="$2"; shift 2 ;;
    --dcr-name)           DCR_NAME="$2"; shift 2 ;;
    --secret-years)       SECRET_YEARS="$2"; shift 2 ;;
    -h|--help)            usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$RESOURCE_GROUP" || -z "$WORKSPACE_NAME" ]]; then
  echo "ERROR: --resource-group and --workspace-name are required." >&2
  usage
  exit 1
fi

command -v az >/dev/null || { echo "ERROR: az CLI not found." >&2; exit 1; }

if [[ -z "$LOCATION" ]]; then
  LOCATION=$(az group show --name "$RESOURCE_GROUP" --query location -o tsv)
fi

echo "==> Creating / reusing Entra application '$APP_NAME'..."
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
if [[ -z "$APP_ID" ]]; then
  APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
fi

echo "==> Ensuring service principal exists..."
SP_OID=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv)
if [[ -z "$SP_OID" ]]; then
  SP_OID=$(az ad sp create --id "$APP_ID" --query id -o tsv)
fi

# Allow AAD a moment to replicate the new app before resetting credentials.
for _ in 1 2 3 4 5 6; do
  if az ad app show --id "$APP_ID" --query id -o tsv >/dev/null 2>&1; then break; fi
  sleep 10
done

echo "==> Generating client secret..."
CLIENT_SECRET=$(az ad app credential reset --id "$APP_ID" --years "$SECRET_YEARS" --display-name "zn-ingestion" --query password -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo "==> Deploying ARM template (DCE, tables, DCR, role assignment)..."
DEPLOY_NAME="zn-ingestion-$(date +%Y%m%d%H%M%S)"
az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$DEPLOY_NAME" \
  --template-file "$TEMPLATE_FILE" \
  --parameters \
      workspaceName="$WORKSPACE_NAME" \
      servicePrincipalObjectId="$SP_OID" \
      location="$LOCATION" \
      dceName="$DCE_NAME" \
      dcrName="$DCR_NAME" \
  --output none

INGEST_ENDPOINT=$(az deployment group show -g "$RESOURCE_GROUP" -n "$DEPLOY_NAME" --query properties.outputs.logIngestionEndpoint.value -o tsv)
DCR_IMMUTABLE_ID=$(az deployment group show -g "$RESOURCE_GROUP" -n "$DEPLOY_NAME" --query properties.outputs.dcrImmutableId.value -o tsv)

cat <<EOF

================ Zero Networks ingestion setup complete ================
Tenant ID:                   $TENANT_ID
Application (client) ID:     $APP_ID
Service principal objectId:  $SP_OID
Client secret:               $CLIENT_SECRET
Logs ingestion endpoint:     $INGEST_ENDPOINT
DCR immutable ID:            $DCR_IMMUTABLE_ID
Stream names:                Custom-ZeroNetworksAudit_CL
                             Custom-ZeroNetworksNetworkActivity_CL
                             Custom-ZeroNetworksIdentityActivity_CL
                             Custom-ZeroNetworksRpcActivity_CL
========================================================================
Store the client secret now — Azure will not show it again.
EOF
