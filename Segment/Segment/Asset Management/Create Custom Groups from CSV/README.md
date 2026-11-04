# Create Custom Groups from CSV

A PowerShell script that creates Zero Networks custom groups from a CSV file. Each CSV row adds one member to a target group. A member can be any entity kind: an active asset, a group of any kind (custom, Active Directory, or built-in), a user account, an IP alias, an IP address or subnet, an FQDN, or a wildcard domain. Target groups and parent groups must be custom groups. Groups can be nested through a `parentGroup` column. A member can also be given by its tenant ID in an optional `entityId` column (see [Member IDs](#member-ids-entityid)). The `-SiteGroups` mode checks the CSV against the Sites rules and writes a hierarchy map. See [SITE-GROUPS.md](SITE-GROUPS.md) for how to use it.

## Requirements

- **PowerShell 7.0 or higher**
- **Zero Networks API key** with permission to read assets, groups, users and IP aliases (for name lookups and `entityId` checks), and to manage groups
- **Portal URL** for your tenant, for example `mycompany-admin.zeronetworks.com`. The script accepts a value with or without `https://` and a trailing `/` or `/api/v1`, and normalizes it.

## Setup

Pass the portal URL on the command line and leave out `-ApiKey`. The script then prompts for the key as a secure string. A key passed on the command line stays in your shell history.

```
-PortalUrl mycompany-admin.zeronetworks.com
```

The prompt only works in an interactive session. In a non-interactive session, pass `-ApiKey` or the run stops with an error.

Do not commit API keys or CSV files that contain tenant-specific data.

## CSV format

The header row must contain these columns. Header names are matched case-insensitively and surrounding spaces are ignored. The `entityId` column is optional and may be left out:

```csv
entityName,targetGroupName,newGroupDescription,parentGroup
```

With the optional column:

```csv
entityName,entityId,targetGroupName,newGroupDescription,parentGroup
```

| Column | Required | Meaning |
|---|---|---|
| `entityName` | Yes, unless `entityId` is set or the row only defines a group | The member to add, by name. Leave it empty to define a group with no members (see [Nested groups](#nested-groups)). |
| `entityId` | No | The tenant ID of the member, for example `a:x:XXXXXXXX`. When it is set, it is used instead of `entityName` (see [Member IDs](#member-ids-entityid)). |
| `targetGroupName` | Yes | The custom group the member belongs to. Created if it does not exist. Must be a custom group (see [Custom groups only](#custom-groups-only)). |
| `newGroupDescription` | No | Description for the group. |
| `parentGroup` | No | Parent custom group that this group should be added to. Must be a custom group. |

Each row is one member of `targetGroupName`. The script reads the group-level values as follows:

- **Description:** the first non-empty `newGroupDescription` for the group is used. If other rows give a different value, the script warns and keeps the first one. The description is applied when the group is created. Existing groups keep their current description. If no row gives one, the group is created with the description `Created by New-ZNCustomGroupsFromCsv.ps1`.
- **Parent:** the first non-empty `parentGroup` for the group is used. If other rows give a different value, the script warns and keeps the first one.
- Blank lines are skipped. A row with an empty `targetGroupName` stops the run with `CSV data row N : targetGroupName is required.`

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
- IP ranges (for example `10.20.0.1-10.20.0.50`) are not supported. They are resolve errors.
- When a name matches more than one tier, the highest-priority match is used. See [Name collisions](#name-collisions).
- A name that matches only one entity of one kind is used as that kind. It is never reported as a collision.

### Name collisions

The priority order is fixed: **asset > group > user > alias**. When a name matches entities of more than one kind, the script uses the match with the highest priority and prints a warning that names every kind that matched and the kind it used, for example:

```
WARNING: 'Backup Operators' matched group, user; used group (priority: asset > group > user > alias)
```

The warning appears in the pre-flight output, before the confirmation prompt (also with `-WhatIf` and `-DryRun`). In a real run it is also repeated in the final report under **Name collisions resolved by priority**. With `-Verbose` each collision is also logged per row. Each colliding name is reported once, even if it appears in several rows. If the preferred entity is not the one you wanted, rename one of the objects in the portal, or use the IP address for that member, because IP addresses are not matched by name.

Two entities of the same kind with the same name (for example two active assets named `Dup`, or two user accounts) are a resolve error. See [Resolve errors](#resolve-errors).

### Custom groups only

Only `targetGroupName` and `parentGroup` must be custom groups. A `targetGroupName` or `parentGroup` that matches only a non-custom group (for example an Active Directory group with the same name) is a pre-flight error. The run stops before any change is made.

### Built-in system groups

The Zero Networks API refuses certain built-in system groups as members, for example the all-servers, all-clients, and quarantined groups. The script does not check for these. When such a group is listed as an `entityName`, it is resolved, but adding it as a member fails with an API error. The target group that holds the row is reported as `Failed`, and the API error is listed under failures. The run continues with the other groups.

## Member IDs (`entityId`)

Use the optional `entityId` column when you already know the tenant ID of a member. The ID identifies one object exactly, so a duplicate name is not a problem when you give the ID of the object you mean.

**Precedence**

- A row with an `entityId` uses that ID. `entityName` is not used for resolution, and no name lookup is made for that row.
- A row with an empty `entityId` resolves by `entityName`, as described above.
- If both are set and `entityName` names a different entity from the one `entityId` resolves to, the script prints a warning and continues:

  ```
  WARNING: row 3: entityName 'WEB-PROD-01' ignored; entityId resolves to 'WEB-PROD-02'
  ```

  Names are compared case-insensitively. A subnet or FQDN in `entityName` is compared by its encoded value, so `10.20.0.0/16` matches `b:120a14000010`. No warning is printed when the two agree. The warning appears in the pre-flight output (also with `-WhatIf`) and, in a real run, in the final report under **Warnings**.

**Accepted ID formats and the check for each**

Each ID is classified by its format, and then checked against the tenant before any change is made.

| ID format | Entity | Check |
|---|---|---|
| `a:<lowercase letter>:<8 letters or digits>` | Asset | Must exist and be **active**. An inactive asset is reported as "exists but is not active". |
| `g:<lowercase letter>:<8 letters or digits>` | Group of any kind (`g:c:` is a custom group) | Must exist. |
| `u:<lowercase letter>:<8 letters or digits>` | User account | Must exist. |
| `e:i:<8 letters or digits>` | IP alias | Must exist. |
| `b:12` + 10 hex digits | IPv4 subnet | Format only. Decoded for display, for example `b:120a14000010` is shown as `10.20.0.0/16`. |
| `b:15` + 34 hex digits | IPv6 subnet | Format only. Decoded for display, for example `2001:db8::/32`. |
| `b:17` + a fully qualified domain name | FQDN | Format only. |
| `b:18*.` + a domain name | Wildcard domain | Format only. |

Anything else is an error. IP ranges (`b:14` and `b:16`) and other ID prefixes are rejected as `unsupported entity ID type`. An ID that does not match its format is rejected as `malformed entity ID`. A subnet, FQDN, or wildcard domain ID is an encoded value and has no object to look up, so only its format is checked.

**Rules that still apply**

- An ID that fails a check is a resolve error. The run stops before any change unless `-SkipResolveErrors` is given, in which case the row is skipped and listed at the end of the report.
- With `-SiteGroups`, the rules apply to the kind of entity the ID resolves to. Subnet IDs are accepted as given, with no automatic `/32` conversion. Assets, user accounts, IP aliases, FQDNs, wildcard domains, and groups that are not custom or do not start with `Site_` are rejected, and a Site rule violation is never skipped. See [SITE-GROUPS.md](SITE-GROUPS.md).
- With `-RemoveMembers`, the validated ID is the member that is removed. With `-RemoveGroupsAndMembers`, the entity columns are not resolved; they only set the order of deletions.
- A group ID that equals an existing `targetGroupName` in the same CSV is treated as that group, so ordering, nesting and cycle detection still apply. A group cannot contain itself: an `entityId` equal to its own `targetGroupName` is a resolve error.
- `targetGroupName` and `parentGroup` remain name-based and must be custom groups. There are no ID columns for them.

**IDs are specific to each tenant.** The same object has a different ID in another tenant. Take IDs from the tenant you run the script against, and do not reuse them across tenants or keep tenant IDs in a shared CSV.

**Example.** The IDs below are placeholders and will not resolve. Replace them with IDs from your tenant. The shipped `groups.example.csv` does not use `entityId`.

```csv
entityName,entityId,targetGroupName,newGroupDescription,parentGroup
WEB-PROD-01,a:x:XXXXXXXX,Web Tier,Production web servers,
,b:120a14000010,Office Networks,Office subnet,
Backup Operators,g:a:XXXXXXXX,Backup Admins,Backup operator access,
```

## Ordering and nested groups

All rows are checked before anything is changed. The script then creates groups in dependency order:

1. The CSV is parsed. Every `entityName` and `entityId` is classified and resolved.
2. The script checks that every `parentGroup` is an existing custom group or a `targetGroupName` in this CSV. Otherwise the run stops.
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
| `-ApiKey` | No | Zero Networks API key. If omitted, the script prompts for it as a secure string. Leave it out to keep the key out of your shell history. The key is masked in logs. |
| `-SkipResolveErrors` | No | Skip members that cannot be resolved, and list them at the end, instead of stopping. See [Resolve errors](#resolve-errors). Name collisions are not errors and are not skipped. Site rule violations are never skipped. |
| `-SiteGroups` | No | Validate the CSV against the Sites rules and write a hierarchy map. See [SITE-GROUPS.md](SITE-GROUPS.md) and [Site groups](#site-groups--sitegroups). |
| `-SiteMapPath` | No | Markdown file for the hierarchy map. Requires `-SiteGroups`; not allowed with a removal switch. See [SITE-GROUPS.md](SITE-GROUPS.md#6-hierarchy-map). |
| `-RemoveMembers` | No | **Destructive.** Remove the listed members from their groups. See [Warning](#warning-destructive-switches). |
| `-RemoveGroupsAndMembers` | No | **Destructive.** Empty and delete the groups named in the CSV. See [Warning](#warning-destructive-switches). |
| `-Force` | No | Skip the confirmation prompt, in the create mode and in the removal modes. |
| `-WhatIf` | No | Show what would change without making changes. Lookups and validation still run (read-only). |
| `-DryRun` | No | Same as `-WhatIf`. |
| `-Confirm` | No | Standard PowerShell switch. Asks for confirmation before each change, in addition to the script's own prompt. |
| `-Verbose` | No | Show detailed logging, including per-member decisions and API requests. The API key is masked. |

`-RemoveMembers` and `-RemoveGroupsAndMembers` cannot be used together. Without either, the script runs in create mode.

## What a run prints

A run prints its output in this order:

1. The tenant line, with the key masked, for example `Tenant API: https://mycompany-admin.zeronetworks.com/api/v1 (key ********abcd)`.
2. The pre-flight plan summary. In create mode it starts with `Plan: create N group(s) [...]`, then `reuse N existing group(s)` and `add up to N member(s) across N group(s); N parent link(s).`. In the removal modes it starts with `Plan: remove ...` or `Plan: empty and DELETE ...`.
3. Pre-flight warnings and name collisions, each prefixed with `WARNING:`.
4. The confirmation prompt, `Apply these changes. Type 'yes' to continue`, or the removal-mode prompt. It is not shown with `-WhatIf` or `-DryRun`, and it is skipped with `-Force`.
5. Progress lines in a real run, such as `Created group 'X' (id)` and `Group 'X': added N of M member(s).`
6. The report, under a heading such as `=== Create custom groups from CSV ===`. It has the group table, member detail, and the sections **Warnings**, **Name collisions resolved by priority**, **Skipped entities** and **Failures** (each only when it has entries).
7. In site mode, a `Reminder` line and the `Totals:` line, then the map path (see [Report output](#report-output)).

With `-WhatIf` or `-DryRun`, the report is replaced by `No changes made (WhatIf or declined).`

## Resolve errors

Resolution runs over all rows before any change is made. The following are resolve errors:

- A name where one kind of entity matches more than one object, for example two active assets with the same name, two groups with the same name, or two user accounts with the same name.
- An invalid IP address or CIDR value, or an IP range.
- A name that matches no asset, group, user account, or IP alias, and is not a valid FQDN.
- An `entityId` that is malformed, uses an unsupported type, does not exist, or (for an asset) is not active. See [Member IDs](#member-ids-entityid).

Names that match entities of different kinds are not errors. They are resolved by priority and reported as [name collisions](#name-collisions).

By default, the run stops before any write and prints every resolve error in one message, `Could not resolve N entit(y/ies); no changes were made. Fix the CSV or re-run with -SkipResolveErrors:`, followed by one line per row. With `-SkipResolveErrors`, each bad member is skipped and recorded, and all skipped entities are listed at the end of the report. Skipping never changes the rest of the run.

`-SkipResolveErrors` does not bypass `-SiteGroups` rule violations or structural errors such as missing parents and cycles. Those always stop the run.

## Existing groups

- If `targetGroupName` already exists, the group is reused and its members are not replaced. Only missing members are added, so re-running the same CSV is safe.
- Status values in a real run: a group created by the run is `Created`. A group that already exists and receives members or a parent link is `Updated`. A group with no changes is `Unchanged`. A group that fails is `Failed`.
- If a `parentGroup` already exists, the child group is added to it.
- If the name of a `targetGroupName` matches more than one custom group, the run stops with `Group 'X': N custom groups share this name; cannot choose one.`

## WARNING: destructive switches

> **WARNING:** `-RemoveMembers` and `-RemoveGroupsAndMembers` change or delete live group membership. Run them first with `-WhatIf` (or `-DryRun`), and check the summary carefully.

- **`-RemoveMembers`** removes only the members listed in the CSV rows from their groups. The groups themselves are kept. Members that are not in the group are reported as `NotAMember`. Missing target groups are a resolve error (skippable with `-SkipResolveErrors`).
- **`-RemoveGroupsAndMembers`** removes **all** members of each `targetGroupName` in the CSV, then **deletes the group**. Zero Networks custom groups have no inactive state, so emptying and deleting is the only way to retire one. Group membership that is not listed in the CSV is removed too, and the group is unlinked from any parent group it belongs to before it is deleted. The unlink lookup is best-effort: if it fails, a warning `Could not look up parent groups of ...` is printed and the delete is still attempted. Groups are deleted in the order shown in the pre-flight summary. If the API refuses to delete a group, the group is reported as `Emptied, DeleteFailed` with the API error, and the run continues.
- In both removal modes `newGroupDescription` is ignored, and `parentGroup` is never used to change membership (in `-RemoveGroupsAndMembers` it is only used to order the plan). To unlink a child group from a parent in `-RemoveMembers` mode, list the child group as an `entityName` row of the parent.
- Both modes run the full resolve pre-flight first and print a summary per group (members to remove, groups to delete). They then prompt you to type `yes` to continue. Any other answer prints `Aborted. No changes made.` and the run ends without changes. Use `-Force` to skip the prompt for automated runs.
- In a non-interactive session without `-Force`, the script stops with `Confirmation required but the session is non-interactive. Re-run with -Force to proceed.`

## Site groups (`-SiteGroups`)

`-SiteGroups` checks the CSV against the Sites (Early Access) rules before any change is made, and writes a Markdown hierarchy map. Sites let you segment your network at the subnet level, and Site groups are used as the source of rules.

- **Names:** every target group and every parent group must start with `Site_`, for example `Site_NewYork`. The check is case-sensitive.
- **Contents:** a group that holds subnets may hold only subnets, and a bare IP is converted to a `/32` (`/128` for IPv6). A parent group holds only child custom `Site_` groups. A group may not mix subnets and child groups.
- **Violations are never skipped:** a Site rule violation stops the run, even with `-SkipResolveErrors`. The depth above 3 levels is a warning only.
- **Hierarchy map:** after the rules pass, the script writes `site-hierarchy-<yyyyMMdd-HHmmss>.md` to the current folder, or the file given with `-SiteMapPath`. It is written in dry runs and real runs.
- **Enablement:** after the groups exist, Zero Networks must enable Sites for your tenant. There is no portal switch.

See [SITE-GROUPS.md](SITE-GROUPS.md) for the full guide: CSV samples, the rules, the workflow, the map layout, and common violations.

## Report output

At the end of a real run the script prints a report with:

- **Groups:** each group with its result (`Created`, `Updated`, `Unchanged`, or `Failed`) and its group ID.
- **Members:** the members added to each group, with their type (`Asset`, `Group`, `User`, `Alias`, `Subnet`, `Fqdn`, or `Domain`) and resolved ID. Each parent link is listed as a `ParentLink` row.
- **Warnings:** pre-flight warnings, such as an `entityName` that was ignored because an `entityId` was given (only when there are any).
- **Name collisions resolved by priority:** each colliding name and the kind that was used (only when there are collisions).
- **Skipped entities:** each skipped member and the reason (only with `-SkipResolveErrors`, and only when there are skipped rows).
- **Failures:** any API or validation failure.
- **Totals:** a `Totals:` line with the count of each status, `skipped=` and `failures=`.
- **Site hierarchy map:** in `-SiteGroups` mode, the last line is `Site hierarchy map written: <full path>`. It is also printed for a dry run. If the map cannot be written, a warning `Could not write the site hierarchy map: ...` is printed instead, and the run is not marked as failed.

In the removal modes the report uses `Removed` and `NotAMember` for members, and `Deleted`, `Deleted (unlink failed)`, `Emptied, DeleteFailed` and `EmptyFailed` for groups.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The run completed with no failures. This includes a dry run, a run that you declined at the prompt (`Aborted. No changes made.`), and a run that skipped rows with `-SkipResolveErrors`. |
| `1` | Any failure in the report, or the run stopped on an error. An error stops the run for a CSV problem, an unresolved member without `-SkipResolveErrors`, a validation failure (including a Site rule), an API error during lookup, or a non-interactive session without `-Force`. |

## Examples

Preview the changes for the sample CSV, without making any. The script prompts for the API key:

```powershell
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -WhatIf
```

Validate the Sites sample and write its hierarchy map, without making any changes:

```powershell
.\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\site-groups.example.csv -PortalUrl mycompany-admin.zeronetworks.com -SiteGroups -DryRun
```

## Troubleshooting

Messages are shown exactly as the script prints them. `...` stands for a value that changes from run to run.

- **`'...' was not found as an active asset, group, user account or IP alias, and is not a valid FQDN, IP, or subnet.`** Check the spelling of the name. Inactive assets are not considered. An IP range is also reported this way, because ranges are not supported. Use individual subnets instead.
- **`N active assets are named '...'; cannot choose one.`**, **`N groups are named '...'; cannot choose one.`**, **`N user accounts are named '...'; cannot choose one.`**, or **`N IP aliases are named '...'; cannot choose one.`** Two objects of the same kind share the name. Rename one of them in the portal, or use an IP address for that member.
- **`unsupported entity ID type '...'`** or **`malformed entity ID '...'`**. The `entityId` is not in a supported format. Copy the ID from your tenant again. IP ranges (`b:14`, `b:16`) are not supported; list the individual subnets instead.
- **`asset ID '...' exists but is not active; only active assets can be members.`** The asset ID belongs to an inactive asset. Use an active asset, or remove the row.
- **`asset ID '...' was not found.`** (also `group ID`, `user account ID`, or `IP alias ID` in place of `asset ID`). The ID does not exist in the tenant you are running against. IDs are tenant-specific.
- **`WARNING: row N: entityName '...' ignored; entityId resolves to '...'`**. The row's `entityId` and `entityName` name different objects, and the ID was used. Fix whichever value is wrong.
- **`WARNING: '...' matched ...; used ... (priority: asset > group > user > alias)`**. A name collision. The script used the higher-priority match. Rename an object if the wrong one was used.
- **`Group '...': a non-custom group has this name, but targetGroupName must be a custom group. Choose a different targetGroupName.`** The target name matches only a non-custom group (for example an Active Directory group). Use a different name for the custom group.
- **`Group '...': parent group '...' matches only a non-custom group; parentGroup must be a custom group.`** The parent name matches only a non-custom group. Use the name of a custom group.
- **`Group '...': parent group '...' does not exist as a custom group and is not defined in the CSV.`** Check the spelling of `parentGroup`, or add a row that defines the parent.
- **`Circular group dependency detected: ... Remove the loop from parentGroup or entityName references.`** The chain is listed in place of `...`, for example `A -> B -> A`. Remove the reference that makes a group contain itself, directly or through other groups.
- **`Pre-flight validation failed; no changes were made:`** followed by one ` - ` line per problem. Read each line. A `Site rule: ...` line is a Sites violation. See [SITE-GROUPS.md](SITE-GROUPS.md#7-common-violations-and-fixes).
- **`WARNING: Group '...': conflicting newGroupDescription values; using the first ('...').`** (or `conflicting parentGroup values`). The CSV has conflicting values for the same group. Only the first non-empty value is used.
- **`entityId '...' is the target group itself; a group cannot be a member of itself.`** The `entityId` is the ID of the row's own `targetGroupName`. Remove the row.
- **`Add members to '...': API request ... failed with HTTP ...`** The API refused a member, for example some built-in system groups. Remove that entry from the CSV.
- **`Delete group '...': API request ... failed with HTTP ...`** The API refused to delete the group, for example because another object still depends on it. The status is `Emptied, DeleteFailed`. Remove the dependency in the portal and re-run the removal.
- **`API request ... failed with HTTP 401.`** or **`... failed with HTTP 403.`** The API key is wrong, expired, or does not have the permissions listed under [Requirements](#requirements). Check `-PortalUrl` as well, since the key is sent to that tenant.
- **`WARNING: HTTP 429 (rate limited) from ... Retrying in N second(s) (attempt X of 3).`** The script retries with a backoff of 1 and then 2 seconds. If the third attempt is also rate limited, the request fails with `failed with HTTP 429`. Large runs may take longer.
- **`-ApiKey was not supplied and no interactive console is available to prompt for it.`** Run the script in an interactive session, or pass `-ApiKey`.
- **`Confirmation required but the session is non-interactive. Re-run with -Force to proceed.`** Add `-Force` for automated runs, or run the script in an interactive session.
- **`CSV '...' is missing required column(s): ...`** The header row must contain `entityName`, `targetGroupName`, `newGroupDescription` and `parentGroup`.
- **`WARNING: Could not look up parent groups of ... Continuing without unlinking it.`** The best-effort unlink lookup failed in `-RemoveGroupsAndMembers`. The delete is still attempted. Check the group's parents in the portal after the run.
