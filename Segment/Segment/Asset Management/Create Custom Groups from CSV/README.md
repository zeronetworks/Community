# Create Custom Groups from CSV

A PowerShell script that creates Zero Networks custom groups from a CSV file. Each CSV row adds one member to a target group. A member can be any entity kind: an active asset, a group of any kind (custom, Active Directory, or built-in), a user account, an IP alias, an IP address or subnet, an FQDN, or a wildcard domain. Target groups and parent groups must be custom groups. Groups can be nested through a `parentGroup` column. A `-SiteGroups` mode enforces the rules of the Sites (Early Access) customer guide.

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
| `targetGroupName` | Yes | The custom group the member belongs to. Created if it does not exist. Must be a custom group (see [Custom groups only](#custom-groups-only)). |
| `newGroupDescription` | No | Description for the group. |
| `parentGroup` | No | Parent custom group that this group should be added to. Must be a custom group. |

Each row is one member of `targetGroupName`. The script reads the group-level values as follows:

- **Description:** the first non-empty `newGroupDescription` for the group is used. If other rows give a different value, the script warns and keeps the first one. The description is applied when the group is created. Existing groups keep their current description.
- **Parent:** the first non-empty `parentGroup` for the group is used. If other rows give a different value, the script warns and keeps the first one.
- Blank lines are skipped. Rows with an empty `targetGroupName` are an error.

See [groups.example.csv](groups.example.csv) for a complete sample.

## Supported `entityName` kinds

The script classifies each `entityName` in this order and encodes it for the API. Names that are not IP addresses, subnets, or wildcard domains are looked up in the tiers shown below. Only `targetGroupName` and `parentGroup` are restricted to custom groups. `entityName` can be any entity kind.

| Kind | Example | How it is resolved or encoded |
|---|---|---|
| Active asset | `WEB-PROD-01` | Name lookup among **active** assets (tier 1). |
| Group of any kind | `Backup Operators`, `Helpdesk-Tier1` | Name lookup among all groups (tier 2): custom groups, Active Directory and built-in groups, and other system groups. A group defined as `targetGroupName` in the same CSV also matches here. |
| User account | `jane.admin` | Exact name match among user accounts (tier 3). |
| IP alias | `Office-Gateway` | Exact name match among IP aliases (tier 4). |
| IPv4 subnet (CIDR) | `10.20.0.0/16` | Encoded as an IPv4 subnet. Host bits are masked, so `10.20.5.17/16` becomes `10.20.0.0/16`. |
| IPv6 subnet (CIDR) | `2001:db8:10::/48` | Encoded as an IPv6 subnet. Host bits are masked. |
| Bare IPv4 address | `10.20.5.17` | Converted to a `/32` subnet. |
| Bare IPv6 address | `2001:db8::17` | Converted to a `/128` subnet. |
| FQDN | `backup.example.com` | Encoded as a domain member, lowercased. Used only when the name matches nothing in tiers 1 to 4. |
| Wildcard domain | `*.corp.example.com` | Encoded as a wildcard domain member. |

Notes:

- Name matching is exact and case-insensitive. Asset lookup ignores inactive assets.
- Groups are looked up among all group kinds. A name that matches a group, such as `Backup Operators`, is added as that group's member.
- IP ranges (for example `10.20.0.1-10.20.0.50`) are not supported.
- When a name matches more than one tier, the highest-priority match is used. See [Name collisions](#name-collisions).
- A name that matches only one entity of one kind is used as that kind. It is never reported as a collision.

### Name collisions

The priority order is fixed: **asset > group > user > alias**. When a name matches entities of more than one kind, the script uses the match with the highest priority and prints a warning that names every kind that matched and the kind it used, for example:

```
WARNING: 'Backup Operators' matched group, user; used group (priority: asset > group > user > alias)
```

The warning appears in the pre-flight plan (also with `-WhatIf` and `-DryRun`), in the final report under **Name collisions resolved by priority**, and in `-Verbose` output. Each colliding name is reported once, even if it appears in several rows. If the preferred entity is not the one you wanted, rename one of the objects in the portal, or use the IP address for that member, because IP addresses are not matched by name.

Two entities of the same kind with the same name (for example two active assets named `Dup`, or two user accounts) are a resolve error. See [Resolve errors](#resolve-errors).

### Custom groups only

Only `targetGroupName` and `parentGroup` must be custom groups. A `targetGroupName` or `parentGroup` that matches only a non-custom group (for example an Active Directory group with the same name) is a pre-flight error. The run stops before any change is made.

### Built-in system groups

The Zero Networks API itself refuses certain built-in system groups as members, for example the all-servers, all-clients, and quarantined groups. The script does not check for these. When such a group is listed as an `entityName`, it is resolved, but adding it as a member fails with an API error. The target group that holds the row is reported as `Failed`, and the API error is listed under failures. The run continues with the other groups.

## Ordering and nested groups

All rows are checked before anything is changed. The script then creates groups in dependency order:

1. The CSV is parsed. Every `entityName` is classified and resolved.
2. The script checks that every `parentGroup` is an existing custom group or a `targetGroupName` in this CSV, and that every group-type `entityName` is an existing group or a `targetGroupName` in this CSV. Otherwise the run stops.
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
| `-SkipResolveErrors` | No | Skip members that cannot be resolved, and list them at the end, instead of stopping. See [Resolve errors](#resolve-errors). Name collisions are not errors and are not skipped. |
| `-SiteGroups` | No | Validate the CSV against the Sites rules. See [Site groups](#site-groups--sitegroups). |
| `-SiteMapPath` | No | Markdown file for the site hierarchy map. Requires `-SiteGroups`; not allowed with a removal switch. See [Site hierarchy map](#site-hierarchy-map). |
| `-RemoveMembers` | No | **Destructive.** Remove the listed members from their groups. See [Warning](#warning-destructive-switches). |
| `-RemoveGroupsAndMembers` | No | **Destructive.** Empty and delete the groups named in the CSV. See [Warning](#warning-destructive-switches). |
| `-Force` | No | Skip the confirmation prompt for the removal modes. |
| `-WhatIf` | No | Show what would change without making changes. Lookups and validation still run (read-only). |
| `-DryRun` | No | Same as `-WhatIf`. |
| `-Verbose` | No | Show detailed logging, including per-member decisions and API requests. The API key is masked. |

`-RemoveMembers` and `-RemoveGroupsAndMembers` cannot be used together. Without either, the script runs in create mode.

## Resolve errors

Resolution runs over all rows before any change is made. The following are resolve errors:

- A name where one kind of entity matches more than one object, for example two active assets with the same name, two groups with the same name, or two user accounts with the same name.
- An invalid IP address or CIDR value.
- A name that matches no asset, group, user account, or IP alias, and is not a valid FQDN.

Names that match entities of different kinds are not errors. They are resolved by priority and reported as [name collisions](#name-collisions).

By default, the run stops before any write and reports every resolve error. With `-SkipResolveErrors`, each bad member is skipped and recorded, and all skipped entities are listed at the end of the report. Skipping never changes the rest of the run.

`-SkipResolveErrors` does not bypass `-SiteGroups` rule violations or structural errors such as missing parents and cycles. Those always stop the run.

## Existing groups

- If `targetGroupName` already exists, the group is reused and its members are not replaced. Only missing members are added, so re-running the same CSV is safe.
- A group that is created by the run is reported as `Created`. A group that already exists and receives members is reported as `Updated`. A group with no changes is reported as `Unchanged`.
- If a `parentGroup` already exists, the child group is added to it.

## WARNING: destructive switches

> **WARNING:** `-RemoveMembers` and `-RemoveGroupsAndMembers` change or delete live group membership. Run them first with `-WhatIf` (or `-DryRun`), and check the summary carefully.

- **`-RemoveMembers`** removes only the members listed in the CSV rows from their groups. The groups themselves are kept. Members that are not in the group are reported as `NotAMember`. Missing target groups are an error (skippable with `-SkipResolveErrors`).
- **`-RemoveGroupsAndMembers`** removes **all** members of each `targetGroupName` in the CSV, then **deletes the group**. Zero Networks custom groups have no inactive state, so emptying and deleting is the only way to retire one. Group membership that is not listed in the CSV is removed too, and the group is unlinked from any parent group it belongs to before it is deleted (best-effort: if the unlink lookup fails, a warning is printed and the delete is still attempted). Groups are processed children first, so nested groups delete cleanly. If the API refuses to delete a group (for example, because a rule references it), the group is reported as `Emptied, DeleteFailed` with the API error, and the run continues.
- In both removal modes `newGroupDescription` is ignored, and `parentGroup` is never used to change membership (in `-RemoveGroupsAndMembers` it is only used to order deletions, children first). To unlink a child group from a parent in `-RemoveMembers` mode, list the child group as an `entityName` row of the parent.
- Both modes run the full resolve pre-flight first and print a summary per group (members to remove, groups to delete). They then prompt you to type `yes` to continue. Any other answer aborts the run. Use `-Force` to skip the prompt for automated runs.
- In a non-interactive session without `-Force`, the script stops with an error instead of waiting for input.

## Site groups (`-SiteGroups`)

`-SiteGroups` validates the CSV against the Sites (Early Access) customer guide before any change is made. Sites let you segment your network at the subnet level. Site groups are used as the source of rules, and the Automation Engine uses them in place of Internal Subnets when a match exists.

The `-SiteGroups` checks are:

- **Naming:** every target group and every parent group must start with `Site_`, for example `Site_NewYork`. The check is case-sensitive.
- **Contents of a leaf Site group:** subnets only, in CIDR notation. A bare IP address is converted to a `/32` (or `/128` for IPv6) host subnet. Every other member kind is rejected: assets, user accounts, IP aliases, FQDNs, wildcard domains, IP ranges, and non-custom groups (including Active Directory and built-in groups, even when their names start with `Site_`).
- **Contents of a parent Site group:** only child Site groups, added either through `parentGroup` or as a group-type `entityName` that starts with `Site_`. Child groups must be custom groups. A group may not mix subnets and child groups.
- **Depth:** the guide recommends 2 to 3 levels. Deeper hierarchies produce a warning, not an error.
- **Violations** are CSV authoring errors. They stop the run even when `-SkipResolveErrors` is used.

After the groups are created, Zero Networks must enable the Sites feature for your tenant. There is no portal switch. Contact your Zero Networks representative or open a support request once the Site groups are ready. Zero Networks then handles the migration of existing rules.

See [site-groups.example.csv](site-groups.example.csv) for a valid Sites sample: a `Site_US` parent with `Site_NewYork` and `Site_Boston` children holding subnets, and a single host added as a bare IP.

## Site hierarchy map

With `-SiteGroups`, the script also writes a Markdown map of the group hierarchy. The map is written after the Sites rules pass, in both dry runs (`-WhatIf` or `-DryRun`) and real runs. If validation fails, no map is written.

The map contains:

- **Header:** generation time, tenant host, CSV file name, mode (`Dry run preview` or `Executed`), group and subnet totals, maximum depth, and a warning when the hierarchy is more than 3 levels deep. The footer reminds you to enable Sites in Zero Networks.
- **Mermaid graph:** one node per group and one edge from each parent to each child. Leaf groups list their subnets. Colors show each group's status.
- **Text tree:** the same hierarchy with subnet counts, for viewers that cannot render Mermaid.
- **Table:** each group with its parent, level, status, subnet count, and full subnet list.

A parent group that exists in the tenant but is not defined in the CSV is shown as an extra node labelled `(existing)`.

Statuses depend on the mode. A dry run shows `Planned` (the group will be created) or `Existing` (the group already exists and will be reused). A real run shows `Created`, `Updated`, `Unchanged`, or `Failed`.

By default the file is `site-hierarchy-<yyyyMMdd-HHmmss>.md` in the current directory, meaning the folder you run the script from. Use `-SiteMapPath` to choose another file. An existing file at that path is overwritten, and any missing folders are created. The script prints the final path at the end of the run. If the map cannot be written, a warning is printed and the run is not marked as failed.

`-SiteMapPath` is an error without `-SiteGroups`, and it is also an error with `-RemoveMembers` or `-RemoveGroupsAndMembers`, because the map is not written in the removal modes.

To view the map:

- **GitHub:** the Mermaid block is drawn when the Markdown file is viewed on github.com.
- **VS Code:** the built-in Markdown preview does not draw Mermaid diagrams. Install a Markdown extension that supports Mermaid, for example "Markdown Preview Mermaid Support", then open the Markdown preview. The tree and table are readable without it.

See [site-hierarchy.example.md](site-hierarchy.example.md) for an example map. It was generated in dry-run mode from a sample Sites structure, with a fixed timestamp.

## Report output

At the end of a run the script prints a report with:

- **Groups:** each group with its result (`Created`, `Updated`, or `Unchanged`) and its group ID.
- **Members:** the members added to each group, with their type (`Asset`, `Group`, `User`, `Alias`, `Subnet`, `Fqdn`, or `Domain`) and resolved ID.
- **Name collisions resolved by priority:** each colliding name and the kind that was used (only when there are collisions).
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

- **"'X' was not found as an active asset, group, user account or IP alias ..."** Check the spelling of the name. Inactive assets are not considered. A name that matches nothing and is not a valid FQDN, IP, or subnet is an error.
- **"N active assets are named ..."** Two active assets share the name. Rename one of them in the portal, or use an IP address for that member.
- **"N groups are named ..."**, **"N user accounts are named ..."**, or **"N IP aliases are named ..."**. Two objects of the same kind share the name. Rename one of them, or use its IP address.
- **"... matched group, user; used group"** (a name collision warning). The script used the higher-priority match. Rename an object if the wrong one was used.
- **"targetGroupName must be a custom group"** or **"parentGroup must be a custom group"**. The name matches only a non-custom group (for example an Active Directory group). Use a different name for the custom group.
- **A member fails with an API error when added.** The API refuses some built-in system groups (for example all-servers, all-clients, or quarantined) as members. Remove that entry from the CSV.
- **"Parent group ... is not an existing group and not defined in this CSV."** Check the spelling of `parentGroup`, or add a row that defines the parent.
- **Cycle detected.** Remove the reference that makes a group contain itself, directly or through other groups.
- **Site violation.** Read the message for the offending row. Common causes are a group name without the `Site_` prefix, a hostname or asset in a Site group, or a Site group that mixes subnets and child groups.
- **A description or parent warning.** The CSV has conflicting values for the same group. Only the first non-empty value is used.
- **Delete failed.** The group is still referenced, for example by a rule. Remove the reference in the portal and re-run the removal.
- **HTTP 401 or 403.** The API key is wrong, expired, or does not have permission to manage groups. Check `-PortalUrl` as well, since the key is sent to that tenant.
- **Rate limiting (HTTP 429).** The script retries with backoff. Large runs may take longer.
