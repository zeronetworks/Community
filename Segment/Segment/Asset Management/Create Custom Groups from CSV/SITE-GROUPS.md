# Site groups (`-SiteGroups`)

This guide covers only the `-SiteGroups` mode of `New-ZNCustomGroupsFromCsv.ps1`. For the CSV columns, setup, how members are resolved and the removal switches, see [README.md](README.md).

## 1. What Site mode does

Sites let you segment your network at the subnet level. You group subnets into named **Site groups**, for example one per office or network segment. When the Automation Engine creates rules from traffic that reaches an asset from many internal sources, it can open the asset to the matching Site group (or its parent group) instead of to Internal Subnets.

With `-SiteGroups`, the script:

1. Checks the CSV against the Sites rules. Nothing is changed if a rule is broken.
2. Creates or updates the custom groups, as in the normal mode.
3. Writes a Markdown map of the hierarchy (section 6).

The script does not enable Sites. Zero Networks does that after the groups exist (section 5, step 4).

The Sites model in brief:

- A Site group is a custom group whose name starts with `Site_`, for example `Site_NewYork`. Groups without that prefix are not used as Site groups.
- A Site group is used as the **source** of a rule only, never as a destination.
- A leaf Site group holds subnets only. A parent Site group holds only child Site groups.
- Hierarchies are supported. Two to three levels are recommended.

## 2. Before you start

- **Plan your sites.** Decide which subnet belongs to which site. Each subnet should belong to the site that best describes where it lives. The script does not check this.
- **Decide the hierarchy.** Keep it to 2 or 3 levels. Optional parents, such as a region, roll their child sites up.
- **Check access.** You need PowerShell 7 and a portal host. The API key must be able to read assets, groups, users and IP aliases, and to manage groups. See [Requirements](README.md#requirements) and [Setup](README.md#setup).
- **Dry run first.** Step 1 in section 5 shows the plan and the map without changing anything.
- **Keep your data private.** Your CSVs and maps show your network layout. Do not commit them.

## 3. Preparing the CSV

Site mode uses the same columns as the normal mode. The optional `entityId` column is covered in [Member IDs](README.md#member-ids-entityid).

```csv
entityName,targetGroupName,newGroupDescription,parentGroup
```

Conventions:

- Name every site `Site_<Location>`. The prefix is case-sensitive and applies to parent groups too.
- Write one row per subnet. Put the CIDR in `entityName` and the site name in `targetGroupName`.
- A bare IP address is a single host. It is converted to a `/32` (or `/128` for IPv6) and appears as `/32` in the map. Writing `10.50.40.15/32` gives the same result.
- A subnet given as an `entityId` (for example `b:120a14000010`) is accepted as given, with no `/32` conversion.
- Define a parent with a row whose `entityName` is empty. Set `parentGroup` on each child row to link it to the parent.
- Rows can be in any order. A child row may come before the row that defines its parent.
- Put `newGroupDescription` on any row of a group. If rows give different values, the first non-empty one is used and a warning is printed.
- IP ranges such as `10.20.0.1-10.20.0.50` are not supported. List the subnets, or single hosts as `/32`, instead.

The samples below use generic names and RFC 1918 addresses. Each CSV is followed by the hierarchy the script builds from it. The trees are copied from the dry-run map for each sample.

### 3.1 Sample: flat sites

Three independent sites, no parent.

```csv
entityName,targetGroupName,newGroupDescription,parentGroup
10.10.0.0/16,Site_NewYork,New York office,
10.20.0.0/16,Site_London,London office,
10.30.0.0/16,Site_Singapore,Singapore office,
```

```text
Site_NewYork  [Planned]  (1 subnet)
    └── 10.10.0.0/16
Site_London  [Planned]  (1 subnet)
    └── 10.20.0.0/16
Site_Singapore  [Planned]  (1 subnet)
    └── 10.30.0.0/16
```

### 3.2 Sample: regional grouping (2 levels)

Sites are grouped by region. Each region is an empty-entity row, and each site names its region in `parentGroup`.

```csv
entityName,targetGroupName,newGroupDescription,parentGroup
,Site_US,US region (parent),
10.10.0.0/16,Site_NewYork,New York,Site_US
10.11.0.0/16,Site_Boston,Boston,Site_US
10.12.0.0/16,Site_Chicago,Chicago,Site_US
,Site_EMEA,EMEA region (parent),
10.20.0.0/16,Site_London,London,Site_EMEA
10.21.0.0/16,Site_Frankfurt,Frankfurt,Site_EMEA
```

```text
Site_US  [Planned]
├── Site_NewYork  [Planned]  (1 subnet)
│   └── 10.10.0.0/16
├── Site_Boston  [Planned]  (1 subnet)
│   └── 10.11.0.0/16
└── Site_Chicago  [Planned]  (1 subnet)
    └── 10.12.0.0/16
Site_EMEA  [Planned]
├── Site_London  [Planned]  (1 subnet)
│   └── 10.20.0.0/16
└── Site_Frankfurt  [Planned]  (1 subnet)
    └── 10.21.0.0/16
```

### 3.3 Sample: environment, region and location (3 levels)

This sample lists child rows before their parents. That is allowed. The deepest path here is `Site_CorpNewYork`, `Site_CorpUS`, `Site_Corporate`, which is 3 levels.

```csv
entityName,targetGroupName,newGroupDescription,parentGroup
10.10.0.0/16,Site_CorpNewYork,New York,Site_CorpUS
10.12.0.0/16,Site_CorpChicago,Chicago,Site_CorpUS
,Site_CorpUS,US,Site_Corporate
10.20.0.0/16,Site_CorpLondon,London,Site_CorpEMEA
,Site_CorpEMEA,EMEA,Site_Corporate
,Site_Corporate,Corporate,
10.100.0.0/16,Site_ProdDC1,Production DC1,Site_Production
10.101.0.0/16,Site_ProdDC2,Production DC2,Site_Production
,Site_Production,Production,
```

```text
Site_Corporate  [Planned]
├── Site_CorpUS  [Planned]
│   ├── Site_CorpNewYork  [Planned]  (1 subnet)
│   │   └── 10.10.0.0/16
│   └── Site_CorpChicago  [Planned]  (1 subnet)
│       └── 10.12.0.0/16
└── Site_CorpEMEA  [Planned]
    └── Site_CorpLondon  [Planned]  (1 subnet)
        └── 10.20.0.0/16
Site_Production  [Planned]
├── Site_ProdDC1  [Planned]  (1 subnet)
│   └── 10.100.0.0/16
└── Site_ProdDC2  [Planned]  (1 subnet)
    └── 10.101.0.0/16
```

### 3.4 Sample: segment-based sites with a single host

Sites can describe network segments inside one location. A single host is added as a `/32` (here written as a bare IP, which the script converts).

```csv
entityName,targetGroupName,newGroupDescription,parentGroup
10.50.0.0/20,Site_HQ_Users,HQ user workstations,Site_HQ
10.50.16.0/20,Site_HQ_Servers,HQ server segment,Site_HQ
10.50.32.0/24,Site_HQ_Management,HQ management segment,Site_HQ
10.50.40.15,Site_HQ_Management,,
,Site_HQ,HQ site (parent),
```

```text
Site_HQ  [Planned]
├── Site_HQ_Users  [Planned]  (1 subnet)
│   └── 10.50.0.0/20
├── Site_HQ_Servers  [Planned]  (1 subnet)
│   └── 10.50.16.0/20
└── Site_HQ_Management  [Planned]  (2 subnets)
    ├── 10.50.32.0/24
    └── 10.50.40.15/32
```

## 4. Rules enforced

All rules are checked in the pre-flight, before any change, in both dry runs and real runs. Only the lookups are read-only.

| Rule | What is checked | Outcome |
|---|---|---|
| Site name | Every `targetGroupName` and every `parentGroup` starts with `Site_` (case-sensitive). | Violation. The run stops. |
| Leaf contents | A group that holds subnets may hold only subnets. Bare IPs count as `/32` or `/128`. | Violation for an asset, user account, IP alias, FQDN, wildcard domain, or non-custom group. |
| Parent contents | A group that holds child groups may hold only child groups that are custom groups named `Site_...`. | Violation for any other member. |
| No mixing | A group may not hold subnets and child groups at the same time. | Violation. |
| Depth | The number of levels from the top group down to the deepest leaf. | More than 3 levels: a warning only. The run continues. |
| IP ranges | A member written as a range, such as `10.20.0.1-10.20.0.50`. | Not a Site violation. It is a resolve error, so the run stops unless `-SkipResolveErrors` skips the row. |
| Never skipped | Any Site violation, and also a missing parent or a cycle. | `-SkipResolveErrors` does not bypass them. The run stops. |

Violations are printed as `Pre-flight validation failed; no changes were made:` followed by one ` - Site rule: ...` line for each problem. Section 7 lists the messages and fixes.

## 5. Step-by-step workflow

The commands below assume the CSV is `.\sites.csv`. Replace the portal host with your own if it is different. The API key is not on the command line, so the script asks for it.

1. **Dry run and read the map.**

   ```powershell
   .\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\sites.csv -PortalUrl mycompany-admin.zeronetworks.com -SiteGroups -DryRun
   ```

   Fix any `Site rule:` line and run it again. Open the map and check that the hierarchy and subnets are what you intended. Statuses in a dry run are `Planned` or `Existing`.

2. **Create the groups.** Run the same command without `-DryRun`. Type `yes` when asked. Use `-Force` only in automated runs.

   ```powershell
   .\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\sites.csv -PortalUrl mycompany-admin.zeronetworks.com -SiteGroups
   ```

3. **Verify in the portal.** Check that each site is a custom group with the `Site_` name, that its subnets are members, and that each parent contains its child groups. Compare with the map. The map from the real run has statuses `Created`, `Updated` or `Unchanged`.

4. **Ask Zero Networks to enable Sites.** Contact your Zero Networks representative or open a support request. Tell them your Site groups are ready. There is no portal switch. Zero Networks enables the feature for your tenant and handles the migration of existing rules, so no action is needed from you during that step.

5. **Maintain the sites.** When a new subnet appears, add a row for it to the CSV and run the same command again, first with `-DryRun`, then without. A re-run only adds members that are missing. It does not remove members. Until a new subnet is in a Site group, its traffic follows the standard behavior.

6. **Retire a site.** Use a removal mode with `-SiteGroups` and `-WhatIf` first. A CSV with one row per site to retire is enough, for example a row with an empty `entityName`. In `-RemoveGroupsAndMembers` mode, the Site check covers the group names only, because the entity columns are not resolved. In `-RemoveMembers` mode it also checks the kind of each member. Removal modes write no map. The removal rules are in [Warning: destructive switches](README.md#warning-destructive-switches).

   ```powershell
   .\New-ZNCustomGroupsFromCsv.ps1 -CsvPath .\retire-sites.csv -PortalUrl mycompany-admin.zeronetworks.com -SiteGroups -RemoveGroupsAndMembers -WhatIf
   ```

## 6. Hierarchy map

- **When it is written.** Only with `-SiteGroups`, and only after the Site rules pass. It is written in a dry run (`-WhatIf` or `-DryRun`) and in a real run. It is not written when validation fails, when you answer anything other than `yes` at the prompt, or in the removal modes.
- **Default file.** `site-hierarchy-<yyyyMMdd-HHmmss>.md` in the folder you run the script from.
- **`-SiteMapPath`.** Sets another file. Relative paths are resolved from the current folder. An existing file at that path is overwritten. Missing folders are created. It is an error without `-SiteGroups`, and an error with `-RemoveMembers` or `-RemoveGroupsAndMembers`. If the map cannot be written, the script prints `Could not write the site hierarchy map: ...` as a warning. The run is not marked as failed.
- **Where to find it.** The last line of the output gives the full path: `Site hierarchy map written: <path>`.
- **Layout.** The map has these parts, in order:
  - A header with the generation time, tenant host, CSV file name, mode (`Dry run preview` or `Executed`), group and subnet totals, maximum depth and, if there are any, the number of existing groups outside the CSV.
  - A warning block when the hierarchy is more than 3 levels deep.
  - `## Hierarchy`: a text tree in a code block. Each group line shows its status and subnet count, for example `Site_NewYork  [Planned]  (1 subnet)`. Child groups are listed under their parent in CSV order. Each subnet is a leaf line with no status. A group with no parent is at the top.
  - `## Table`: one row per group, with its parent, level (1 is the top), status, subnet count and full subnet list.
  - A reminder that Zero Networks must enable Sites.
- **Statuses.**

  | Mode | Status values |
  |---|---|
  | Dry run (`-WhatIf` or `-DryRun`) | `Existing`: the group is already in the tenant and will be reused. `Planned`: the group will be created. |
  | Real run | `Created`: the group was made by this run. `Updated`: an existing group that received members or a parent link. `Unchanged`: an existing group with nothing to add. `Failed`: an API error, listed in the report's Failures section. |

- **`(existing)` groups.** A parent or child group that is already in the tenant but is not defined in the CSV appears in the tree as `Site_Legacy  (existing)`. It has no status. In the table its level and subnet count are `-`.

A sample map from the sample in section 3.1 (a dry run, with a fixed timestamp):

````markdown
# Site hierarchy map

- **Generated:** 2026-11-04 10:00:00
- **Tenant:** mycompany-admin.zeronetworks.com
- **CSV file:** site-groups.csv
- **Mode:** Dry run preview
- **Groups:** 3
- **Subnets:** 3
- **Max depth:** 1 level(s)

## Hierarchy

```text
Site_NewYork  [Planned]  (1 subnet)
    └── 10.10.0.0/16
Site_London  [Planned]  (1 subnet)
    └── 10.20.0.0/16
Site_Singapore  [Planned]  (1 subnet)
    └── 10.30.0.0/16
```

## Table

| Group | Parent | Level | Status | Subnet count | Subnets |
|---|---|---|---|---|---|
| Site_NewYork | - | 1 | Planned | 1 | 10.10.0.0/16 |
| Site_London | - | 1 | Planned | 1 | 10.20.0.0/16 |
| Site_Singapore | - | 1 | Planned | 1 | 10.30.0.0/16 |

> **Reminder:** Zero Networks must enable Sites after these groups exist.
````

The file [site-hierarchy.example.md](site-hierarchy.example.md) is a longer example, generated in dry-run mode from a generic structure.

## 7. Common violations and fixes

The messages in the first table stop the run before any change is made. `-SkipResolveErrors` does not skip them. Fix the CSV and run it again.

| Message (the text after `Site rule:`, or the full line where marked) | Cause | Fix |
|---|---|---|
| `group 'NewYork' must start with 'Site_' (case-sensitive) in -SiteGroups mode.` | A target group has no `Site_` prefix, or uses another case such as `site_`. | Rename it, for example `Site_NewYork`. |
| `parent group 'Office-US' of group 'Site_NewYork' must start with 'Site_'.` | The `parentGroup` value has no prefix. | Rename the parent and use the same name in every row. |
| `group 'Site_NewYork' contains 'backup.example.com' (an FQDN); Site groups accept only subnets (parents accept only child Site_ groups).` | A non-subnet member. The message names the kind: `(an asset)`, `(a user account)`, `(an IP alias)`, `(an FQDN)` or `(a wildcard domain)`. | Replace the member with its subnet, or with `/32` for a single host. Move the object out of the Site group. |
| `group 'Site_NewYork' contains 'Backup Operators', which is a non-custom group; Site groups accept only subnets and custom Site_ groups (as child groups).` | An Active Directory, built-in or other non-custom group. | Remove the row. Child groups must be custom groups named `Site_...`. |
| `group 'Site_NewYork' contains group 'Team Legacy', which is not a Site_ group.` | A custom child group without the `Site_` prefix. | Rename the child group, or remove it from this parent. |
| `group 'Site_NewYork' mixes subnets with child groups; leaf Site groups hold subnets only and parent Site groups hold only child Site_ groups.` | The same group has subnet rows and child-group rows. | Keep subnets in a leaf `Site_` group. Put child groups in a parent that has no subnet rows. |

Other messages you may see in a Site run. The first two stop the run; the third is a warning:

| Message | Cause | Fix |
|---|---|---|
| `Could not resolve 1 entit(y/ies); no changes were made.` followed by `'10.20.0.1-10.20.0.50' was not found as an active asset, group, user account or IP alias, and is not a valid FQDN, IP, or subnet.` | An IP range, which is not supported. | List the individual subnets. Do not use `-SkipResolveErrors` for this: the skipped subnet would be missing from the site. |
| `Group 'Site_NewYork': parent group 'Office-US' does not exist as a custom group and is not defined in the CSV.` | The parent is neither in the CSV nor an existing custom group. This is not a Site rule, and `-SkipResolveErrors` does not skip it. | Add a row that defines the parent, or correct the spelling. |
| `WARNING: The hierarchy is 4 levels deep; the Sites guide recommends 2 to 3.` | More than 3 levels. A warning only. | Flatten the hierarchy if you can. The run continues. |

## 8. Notes and limits

- **IP ranges are not supported.** List the subnets instead, or single hosts as `/32`.
- **Site groups are rule sources only.** A Site group can be the source of a rule but never its destination. This is stated in the Sites guide. The script does not enforce it, because it only validates the CSV.
- **Overlapping subnets are not checked.** The script does not check that subnets in different sites do not overlap, or that the sites cover all your addresses.
- **The script does not enable Sites.** Zero Networks does that. The script only creates the groups and checks their layout.
- **Depth.** More than 3 levels gives a warning. It is not an error.
- **Tenant data.** CSVs and maps contain your network layout and group names. Do not commit them. The example files in this folder are generic.
