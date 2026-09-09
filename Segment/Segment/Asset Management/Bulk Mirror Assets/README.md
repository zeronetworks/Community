# Bulk Mirror Assets

Bulk-validate and apply Zero Networks asset mirroring relationships from a CSV.

> **Note:** This tool only supports IT assets. OT/IoT assets are not supported, though support could be added if needed.

## Mirroring prerequisites

Zero Networks enforces the following rules on any mirror relationship:

- The target asset must be active (not deleted or inactive).
- If the source asset is an Active Directory asset, it can only be mirrored to another AD asset.
- If the source asset is an OT/IoT asset, it can only be mirrored to another OT/IoT asset.
- Standard (non-AD, non-OT) assets can be mirrored to any other eligible active asset.
- The source asset cannot be mirrored to itself.

This script's validation step only confirms the target is a valid mirror candidate for the source (which incorporates the rules above) before mirroring — it does not otherwise enforce or check these rules itself.

## What mirroring copies

Once a mirror relationship is confirmed, the following are copied from the source asset onto the target asset:

- Group memberships
- Network segmentation rules
- MFA / reactive policies
- RPC segmentation rules
- Switch rules
- Connect (VPN) role assignments

Mirroring does **not** change the target asset's segmentation status.

## Setup

```bash
uv sync
cp .env.example .env  # then fill in ZN_API_BASE_URL and ZN_API_KEY
# ZN_API_BASE_URL is your portal base URL, e.g. https://<your-org>-admin.zeronetworks.com
# (no /api/v1 suffix - the script appends it automatically)
```

## Usage

Input CSV must have at minimum these columns: `srcAssetId,srcAssetName,dstAssetId,dstAssetName`.

```bash
uv run mirror_assets.py --input assets.csv [--batch-size 25] [--output-dir outputs] [-v]
```

## Output

CSVs are written to the output directory (default `./outputs`), timestamped by date:

- `mirrored-success-<YYYY-MM-DD>.csv` — assets mirrored successfully
- `mirrored-failures-<YYYY-MM-DD>.csv` — assets that failed validation or the mirror call, with a `reason` column (only written if at least one asset failed)

A summary is also logged to the console at the end of the run.
