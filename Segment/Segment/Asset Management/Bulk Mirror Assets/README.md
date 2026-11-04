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

## Manual mirroring (`manual_mirror_assets.py`)

`manual_mirror_assets.py` copies a source asset's configuration onto a target asset by making individual API calls. It works for any source-to-target pair. The script does not itself require the source or target to be a particular OS, an AD asset, or a Segment Connector asset; the API's own rules still apply, and the categories that only make sense for some targets (identity, RPC) are gated per target.

### What it copies

- **Group memberships:** the target is added to the source's writable custom and tag groups. AD, system and OT groups are read-only through the API and are reported as `skipped_readonly`. Rule-based (conditional) groups, whose membership is defined by conditions such as `Asset Type: Server`, cannot take manual members (the API answers HTTP 412), so they are reported as `skipped_conditional` with the conditions in the reason; the target joins them automatically only if it matches.
- **Owner-side network rules:** rules the source owns are recreated with the target as the local asset. The source is replaced by the target in remote lists.
- **Remote-side network rules:** where the source is a remote source (inbound rules) or a remote destination (outbound rules), a new rule is created whose remote list is `[target]` only. Its description starts with a marker, `[zn-mirror rule=<original rule id> dst=<T>]`, which records the original rule ID, followed by as much of the original rule's description as fits. The API limits descriptions to 100 characters.
- **MFA (reactive) policies**, inbound and outbound.
- **Identity rules and identity MFA policies**, only for AD (source 3) and Azure AD (source 9) targets. Other targets get one `incompatible_target` row.
- **RPC rules**, only for Windows targets. Other targets get an `incompatible_target` row.
- **Switch rules**, only with `--include-switch`. Rules auto-derived from network rules are skipped as `skipped_derived`.
- **External access policies**, only with `--include-external-access`.
- **Connect (VPN) roles:** the target is added next to the source in the allowed assets, excluded assets or destinations of each user access config that references the source.

### How it differs from the native mirror

- The native mirror (`mirror_assets.py`) calls the portal's mirror action (`/assets/actions/mirror`). This script never calls that action. It recreates each object itself, and every copy is a separate row in the report, so results can be reviewed one by one and rolled back.
- The script never deletes or consolidates existing rules on either side. It is not a duplicate-cleanup tool. Re-runs skip objects the target already has.

### Usage

```bash
# Dry run (default): GET requests only, writes a plan CSV
uv run manual_mirror_assets.py --input assets.csv

# Review outputs/<YYYY-MM-DD>/manual-mirror-plan-<timestamp>.csv, then perform the writes
uv run manual_mirror_assets.py --input assets.csv --apply

# Dry run that also writes per-pair folders for review (see "Verbose dry run" below)
uv run manual_mirror_assets.py --input assets.csv --verbose-dry-run
```

The input CSV has the columns `srcAssetId,srcAssetName,dstAssetId,dstAssetName`. Credentials come from the same `.env` file used by the native mirror script (`ZN_API_BASE_URL`, `ZN_API_KEY`).

| Flag | Purpose |
| --- | --- |
| `--input`, `-i` | Input CSV of source and target pairs. Required unless `--rollback` is given. |
| `--output-dir` | Base directory for reports and state files (default `outputs`). Files go into a `<YYYY-MM-DD>` subdirectory of it. |
| `--verbose`, `-v` | Enable debug logging. |
| `--verbose-dry-run` (alias `--verboseDryRun`) | Dry run only: also write the per-pair verbose folders. Ignored with `--apply`. |
| `--concurrency` | Maximum in-flight API calls (default 5). Connect updates are never concurrent. |
| `--apply` | Perform writes. Without it, only GET requests are made. |
| `--skip-groups` | Do not add the target to the source's groups. |
| `--skip-owner-rules` | Do not copy rules the source owns. |
| `--skip-inbound-remote` | Do not copy inbound rules where the source is the remote side. |
| `--skip-outbound-remote` | Do not copy outbound rules where the source is the remote side. |
| `--include-pending` | Copy pending-review rules and policies to the target as disabled. |
| `--self-ref-both` | Also emit the remote copy for rules where the source is both local and remote. |
| `--skip-mfa` | Do not copy MFA (reactive) policies. |
| `--skip-identity` | Do not copy identity rules or identity MFA policies. |
| `--skip-rpc` | Do not copy RPC rules. |
| `--skip-connect` | Do not add the target to Connect roles. |
| `--include-switch` | Also copy switch rules (off by default). |
| `--include-external-access` | Also copy external access policies (off by default). |
| `--resume STATE.csv` | With `--apply`, skip actions the given state file records as done. |
| `--rollback REPORT.csv` | Delete the objects a results report created (dry run unless `--apply`). |

### Output files

All files go to a dated subdirectory `outputs/<YYYY-MM-DD>/` (the date of the run) of the output directory, with a timestamp suffix:

- `outputs/<YYYY-MM-DD>/manual-mirror-plan-<ts>.csv`: dry run. One row per planned action. The headers and values are written for people to read: for example `Status` shows "Will be created" or "Skipped: already on target", `Category` shows "Rule owned by the source asset", and `Request Body (JSON)` holds the body the script would send. In this file, "Source Asset ID" / "Source Asset Name" is the asset being mirrored, and "Target Asset ID" / "Target Asset Name" is the mirror target.
- `outputs/<YYYY-MM-DD>/manual-mirror-results-<ts>.csv`: `--apply` run. Machine-readable: the column names and status codes (`planned`, `created`, `skipped_exists`, ...) are unchanged, with the result of each write and `newObjectId`. `--rollback` reads this file, so pass it there, not the plan.
- `outputs/<YYYY-MM-DD>/manual-mirror-state-<ts>.csv`: `--apply` run. Machine-readable progress log used by `--resume`.
- `outputs/<YYYY-MM-DD>/manual-mirror-rollback-plan-<ts>.csv` and `outputs/<YYYY-MM-DD>/manual-mirror-rollback-<ts>.csv`: rollback dry run and rollback run.

`--resume` and `--rollback` take explicit file paths, so pass the file from the dated folder (for example `--rollback outputs/<YYYY-MM-DD>/manual-mirror-results-<ts>.csv`).

Rollback deletes the objects created by a results report. Run it as a dry run first, then add `--apply`. Connect config updates are not reverted automatically; the rollback report marks them `rollback_unsupported` so they can be reverted by hand. Removing a group membership (the `DELETE` with a JSON body on the group's members endpoint) has been verified against a real tenant with a tag group.

### Verbose dry run

With `--verbose-dry-run`, a dry run also writes one folder per pair, `outputs/<YYYY-MM-DD>/<srcHost>_to_<dstHost>/` (for example `outputs/<YYYY-MM-DD>/srv-linux-01_to_srv-win-01/`). The host label is the short name (text before the first `.`), with characters other than letters, digits, `.`, `_` and `-` replaced by `_`. If two different pairs would share a folder, the dst asset id suffix `-<last 8 chars>` is added to the colliding names. Each folder holds six CSVs, named with the run timestamp and header-only when empty:

- `inbound-allow-<ts>.csv`, `inbound-block-<ts>.csv`, `outbound-allow-<ts>.csv`, `outbound-block-<ts>.csv`: network rules, split by direction and action. Includes skipped rules with their status and reason, the copy type, the rule state, the original and new remote assets (IDs and names), the original and new asset that owns the rule, ports, processes, services, expiry and the new rule description. Source columns come first in both directions: inbound files list the source columns and then the destination (rule owner); outbound files list the source (rule owner) and then the destination columns. Both the original and the new rule owner are shown (ID and name): on an owner copy the target becomes the owner, so the sources can be unchanged while the destination (inbound) or source (outbound) changes; on a remote-side copy the owner is unchanged. Values are readable (for example "Owner copy (target becomes the rule owner)" or "Never" for no expiry; expiry dates are shown in UTC).
- `groups-added-<ts>.csv`: group memberships the run would add (`Group ID`, `Group Name`, `Group Type`, `HTTP Method`, `API Path`).
- `groups-not-added-<ts>.csv`: groups that are not added, with the status and reason (read-only, already a member, or redundant).

**Who owns the rule depends on the file.** Column headers are chosen per direction:

| File | "Original / New ... Asset ID (rule owner)" columns | "Original / New ... Asset IDs" columns |
| --- | --- | --- |
| `inbound-*` | `Original Destination Asset ID (rule owner)` and `New Destination Asset ID (rule owner)`: the asset the original rule protects, and the asset the new rule protects | `Source Asset IDs`: the remote list, i.e. the sources |
| `outbound-*` | `Original Source Asset ID (rule owner)` and `New Source Asset ID (rule owner)`: the asset the original rule is written on, and the asset the new rule is written on | `Destination Asset IDs`: the remote list, i.e. the destinations |

So in an inbound rule the local asset is the destination, not the source. The source appears only in the remote list.

The verbose folders are for review only. The plan CSV is still written as before. Secondary categories (MFA, identity, RPC, switch, external access, Connect) are not included in the verbose folders. With `--apply`, the flag is ignored and a warning is logged.

### Statuses

`planned`, `created`, `updated`, `rolled_back`, `skipped_exists`, `skipped_state`, `skipped_pending`, `skipped_expired`, `skipped_group_inherited`, `skipped_readonly`, `skipped_conditional`, `skipped_redundant`, `skipped_derived`, `skipped_resumed`, `exclusion_not_mirrored`, `incompatible_target`, `failed`. Pre-checks report `ok`, `warning` or `failed`.

These are the codes written to the results, state and rollback CSVs. The plan and verbose CSVs show a plain-language label instead, for example "Will be created" for `planned`, "Will be added" for a group membership, and "Skipped: already on target" for `skipped_exists`.

### Idempotency

Before planning, the script reads the target's existing rules and policies. An object is skipped as `skipped_exists` when a `zn-mirror` marker already points from the same source object to the target, or when an identical object already exists. Objects that would duplicate each other within one run are also skipped. A re-run after a partial run therefore creates only what is still missing. `--resume` skips writes that the state file records as done.

### Safety notes

- The script does not change the target's segmentation status.
- It never calls `/assets/actions/mirror`.
- Rules that reach the source only through group membership are not copied (`skipped_group_inherited`).
- AD, system and OT groups are read-only through the API, so the target cannot be added to them.
- Original rule IDs are written into descriptions. The API caps descriptions at 100 characters; the marker is always kept and any original text is trimmed with `...` first. Descriptions written by earlier versions of this script (`[zn-mirror src-rule=... src=... dst=...]`) are still recognized when checking whether an object already exists.
- Pre-flight checks: before anything is sent, each planned write is checked against known API limits (description length; required fields and a non-empty remote list for network rules). A write that fails is reported as `failed` with a reason starting `pre-flight check:` in the dry run and is never sent.
- Connect updates run one at a time. Each one re-reads the config and rebuilds the body from the fresh copy, so concurrent edits are not overwritten.

### Verify before first production run

Confirm these behaviours against the live API. The script was written from the OpenAPI spec and has not been run against a live tenant.

- Rule listing with `entityParams` `direction=3` returns rules where the source is only the remote side.
- Rule create accepts `state` for pending-review objects (the script sends them as disabled).
- Switch rule create: the spec declares `remoteEntitiesIdList` as a property but requires `remoteEntityIdsList`. The script sends `remoteEntityIdsList`. Confirm which one the API accepts.
- Connect user access config `PUT` replaces the whole object. Confirm the body rebuilt from the re-read config keeps every other setting.
- MFA policy listing with `_entityId`: confirm whether it matches the policy destination only or also the source assets.
- Identity rule listing: the response schema does not declare `nextCursor`. The script stops with an error if a full page arrives without one.
