# Create Custom Groups from CSV

A PowerShell script that creates Zero Networks custom groups from a CSV file. Each CSV row adds one member to a target group, and a member can be an active asset, an existing custom group, an IP address or subnet, an FQDN, or a wildcard domain. Groups can be nested through a `parentGroup` column. A `-SiteGroups` mode enforces the rules of the Sites (Early Access) customer guide.

## Requirements

- **PowerShell 7.0 or higher**
- **Zero Networks API key** with permission to manage groups
- **Portal URL** for your tenant, for example `mycompany-admin.zeronetworks.com`. The script accepts a value with or without `https://` and a trailing `/` or `/api/v1`, and normalizes it.

## Setup

Pass the portal URL and API key on the command line. If you leave out `-ApiKey`, the script prompts for it.

```
-PortalUrl mycompany-admin.zeronetworks.com -ApiKey '<your-api-key>'
```

Do not commit API keys or CSV files that contain tenant-specific data.

## CSV format

The header row must be exactly:

```csv
entityName,targetGroupName,newGroupDescription,parentGroup
```

| Column | Required | Meaning |
|---|---|---|
| `entityName` | Yes, except for parent-only rows | The member to add. Leave it empty to define a group with no members (see [Nested groups](#nested-groups)). |
| `targetGroupName` | Yes | The custom group the member belongs to. Created if it does not exist. |
| `newGroupDescription` | No | Description for the group. |
| `parentGroup` | No | Parent custom group that this group should be added to. |

Each row is one member of `targetGroupName`. The script reads the group-level values as follows:

- **Description:** the first non-empty `newGroupDescription` for the group is used. If other rows give a different value, the script warns and keeps the first one. The description is applied when the group is created. Existing groups keep their current description.
- **Parent:** the first non-empty `parentGroup` for the group is used. If other rows give a different value, the script warns and keeps the first one.
- Blank lines are skipped. Rows with an empty `targetGroupName` are an error.

See [groups.example.csv](groups.example.csv) for a complete sample.

## Supported `entityName` kinds

The script classifies each `entityName` in this order and encodes it for the API.

| Kind | Example | How it is resolved or encoded |
|---|---|---|
| Active asset name | `WEB-PROD-01` | Looked up by name among **active** assets only. Exactly one match is required. |
| Existing custom group name | `Helpdesk-Tier1` | Looked up by name among `custom` groups only (other group types are not supported). Used as a member of the target group. |
| IPv4 subnet (CIDR) | `10.20.0.0/16` | Encoded as an IPv4 subnet. Host bits are masked, so `10.20.5.17/16` becomes `10.20.0.0/16`. |
| IPv6 subnet (CIDR) | `2001:db8:10::/48` | Encoded as an IPv6 subnet. Host bits are masked. |
| Bare IPv4 address | `10.20.5.17` | Converted to a `/32` subnet. |
| Bare IPv6 address | `2001:db8::17` | Converted to a `/128` subnet. |
| FQDN | `backup.example.com` | Encoded as a domain member, lowercased. |
| Wildcard domain | `*.corp.example.com` | Encoded as a wildcard domain member. |

Notes:

- IP ranges (for example `10.20.0.1-10.20.0.50`) are not supported.
- Names that look like a dotted hostname are matched against active asset names first. If no asset matches and no group matches, they are treated as FQDNs.
- Asset lookup ignores inactive assets. A name that matches only an inactive asset is not used as an asset. If it has valid FQDN syntax and matches no group either, it is treated as an FQDN.
- A name that matches both an active asset and a group is an ambiguous error. Rename one of them, or use the IP or FQDN form.

## Ordering and nested groups

All rows are checked before anything is changed. The script then creates groups in dependency order:

1. The CSV is parsed. Every `entityName` is classified and resolved.
2. The script checks that every `parentGroup` and every group-type `entityName` either already exists or is a `targetGroupName` in this CSV. Otherwise the run stops.
3. Groups are sorted so that referenced groups are created first. Child groups can therefore be listed before their parent in the CSV.
4. Groups are created, then members are added, then child groups are added to their parents.

A cycle in the parent or member references (for example, A contains B and B contains A) is rejected before any change.

### Nested groups

To nest a group, put its name in `parentGroup` on its rows. The parent is defined by its own rows. A row with an empty `entityName` defines a group that has no members of its own, which is how a parent that holds only child groups is written. In the sample, `Finance-Apps` is listed before `Finance-All`, and `Finance-Apps` is then added to `Finance-All`.

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-CsvPath` | Yes | Path to the input CSV. |
| `-PortalUrl` | Yes | Tenant portal host, for example `mycompany-admin.zeronetworks.com`. |
| `-ApiKey` | No | Zero Networks API key. If omitted, the script prompts for it. The key is masked in logs. |
| `-SkipResolveErrors` | No | Skip members that cannot be resolved, and list them at the end, instead of stopping. See [Resolve errors](#resolve-errors). |
| `-SiteGroups` | No | Validate the CSV against the Sites rules. See [Site groups](#site-groups--sitegroups). |
| `-RemoveMembers` | No | **Destructive.** Remove the listed members from their groups. See [Warning](#warning-destructive-switches). |
| `-RemoveGroupsAndMembers` | No | **Destructive.** Empty and delete the groups named in the CSV. See [Warning](#warning-destructive-switches). |
| `-Force` | No | Skip the confirmation prompt for the removal modes. |
| `-WhatIf` | No | Show what would change without making changes. |
| `-Verbose` | No | Show detailed logging, including per-member decisions and API requests. The API key is masked. |

`-RemoveMembers` and `-RemoveGroupsAndMembers` cannot be used together. Without either, the script runs in create mode.

## Resolve errors

Resolution runs over all rows before any change is made. The following are resolve errors:

- An asset name with zero or more than one active asset match.
- An ambiguous name (matches both an asset and a group).
- An invalid IP address or CIDR value.
- A name that cannot be resolved to an asset, group, or FQDN.

By default, the run stops before any write and reports every resolve error. With `-SkipResolveErrors`, each bad member is skipped and recorded, and all skipped entities are listed at the end of the report. Skipping never changes the rest of the run.

`-SkipResolveErrors` does not bypass `-SiteGroups` rule violations or structural errors such as missing parents and cycles. Those always stop the run.

## Existing groups

- If `targetGroupName` already exists, the group is reused and its members are not replaced. Only missing members are added, so re-running the same CSV is safe.
- A group that is created by the run is reported as `Created`. A group that already exists and receives members is reported as `Updated`. A group with no changes is reported as `Unchanged`.
- If a `parentGroup` already exists, the child group is added to it.

## WARNING: destructive switches

> **WARNING:** `-RemoveMembers` and `-RemoveGroupsAndMembers` change or delete live group membership. Run them first with `-WhatIf`, and check the summary carefully.

- **`-RemoveMembers`** removes only the members listed in the CSV rows from their groups. The groups themselves are kept. Members that are not in the group are reported as `NotAMember`. Missing target groups are an error (skippable with `-SkipResolveErrors`).
- **`-RemoveGroupsAndMembers`** removes **all** members of each `targetGroupName` in the CSV, then **deletes the group**. Zero Networks custom groups have no inactive state, so emptying and deleting is the only way to retire one. Group membership that is not listed in the CSV is removed too, and the group is unlinked from any parent group it belongs to before it is deleted (best-effort: if the unlink lookup fails, a warning is printed and the delete is still attempted). Groups are processed children first, so nested groups delete cleanly. If the API refuses to delete a group (for example, because a rule references it), the group is reported as `Emptied, DeleteFailed` with the API error, and the run continues.
- In both removal modes `newGroupDescription` is ignored, and `parentGroup` is never used to change membership (in `-RemoveGroupsAndMembers` it is only used to order deletions, children first). To unlink a child group from a parent in `-RemoveMembers` mode, list the child group as an `entityName` row of the parent.
- Both modes run the full resolve pre-flight first and print a summary per group (members to remove, groups to delete). They then prompt you to type `yes` to continue. Any other answer aborts the run. Use `-Force` to skip the prompt for automated runs.
- In a non-interactive session without `-Force`, the script stops with an error instead of waiting for input.

## Site groups (`-SiteGroups`)

`-SiteGroups` validates the CSV against the Sites (Early Access) customer guide before any change is made. Sites let you segment your network at the subnet level. Site groups are used as the source of rules, and the Automation Engine uses them in place of Internal Subnets when a match exists.

The `-SiteGroups` checks are:

- **Naming:** every target group and every parent group must start with `Site_`, for example `Site_NewYork`. The check is case-sensitive.
- **Contents of a leaf Site group:** subnets only, in CIDR notation. A bare IP address is converted to a `/32` (or `/128` for IPv6) host subnet. Assets, FQDNs, wildcard domains, IP ranges, and non-Site groups are rejected.
- **Contents of a parent Site group:** only child Site groups, added either through `parentGroup` or as a group-type `entityName` that starts with `Site_`. A group may not mix subnets and child groups.
- **Depth:** the guide recommends 2 to 3 levels. Deeper hierarchies produce a warning, not an error.
- **Violations** are CSV authoring errors. They stop the run even when `-SkipResolveErrors` is used.

After the groups are created, Zero Networks must enable the Sites feature for your tenant. There is no portal switch. Contact your Zero Networks representative or open a support request once the Site groups are ready. Zero Networks then handles the migration of existing rules.

See [site-groups.example.csv](site-groups.example.csv) for a valid Sites sample: a `Site_US` parent with `Site_NewYork` and `Site_Boston` children holding subnets, and a single host added as a bare IP.

## Report output

At the end of a run the script prints a report with:

- **Groups:** each group with its result (`Created`, `Updated`, or `Unchanged`) and its group ID.
- **Members:** the members added to each group, with their type and resolved ID.
- **Parent links:** each child-to-parent link made.
- **Skipped entities:** each skipped member and the reason (only with `-SkipResolveErrors`).
- **Failures:** any API or validation failure.
- **Totals.** The script exits with a non-zero code if anything failed.

In the removal modes the report uses `Removed`, `NotAMember`, `Skipped`, `Emptied`, `Deleted`, and `DeleteFailed` instead, with per-item detail.

## Examples

Preview the changes for the sample CSV, without making any:

```powershell
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -ApiKey '<your-api-key>' -WhatIf
```

Validate and create the Sites hierarchy:

```powershell
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\site-groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -ApiKey '<your-api-key>' -SiteGroups
```

## Troubleshooting

- **"Asset name matched 0 (or more than 1) active assets."** Check the spelling of the name. Inactive assets are not considered. If several active assets share the name, rename one of them in the portal, or use an IP address for that member.
- **"Name matches both an asset and a group."** Rename the group, or use the asset's IP address.
- **"Parent group ... is not an existing group and not defined in this CSV."** Check the spelling of `parentGroup`, or add a row that defines the parent.
- **Cycle detected.** Remove the reference that makes a group contain itself, directly or through other groups.
- **Site violation.** Read the message for the offending row. Common causes are a group name without the `Site_` prefix, a hostname or asset in a Site group, or a Site group that mixes subnets and child groups.
- **A description or parent warning.** The CSV has conflicting values for the same group. Only the first non-empty value is used.
- **Delete failed.** The group is still referenced, for example by a rule. Remove the reference in the portal and re-run the removal.
- **HTTP 401 or 403.** The API key is wrong, expired, or does not have permission to manage groups. Check `-PortalUrl` as well, since the key is sent to that tenant.
- **Rate limiting (HTTP 429).** The script retries with backoff. Large runs may take longer.
