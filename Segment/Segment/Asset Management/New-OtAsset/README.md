# New-OtAsset

PowerShell scripts for creating OT/IoT assets in Zero Networks, one at a time or in bulk from a CSV file. Every row is validated against your tenant before anything is created, so a bad row is reported with a clear reason instead of failing halfway through a run.

## Requirements

- **PowerShell 7.0 or higher**
- **Zero Networks API key.** `New-OtAsset.ps1` needs a read-write key. `Get-OtAssetTypes.ps1` works with any key, including a read-only one. Create a key in the portal under **Settings -> System -> Integrations -> API**.
- Prefer setting the key in an environment variable, `$Env:ZN_API_KEY`, over passing `-ApiKey` on the command line. This keeps the key out of your shell history.

## Files

| File | Purpose |
| --- | --- |
| `New-OtAsset.ps1` | Creates OT/IoT assets, either one at a time (`-Ip`/`-Name`) or from a CSV file (`-CsvFilePath`). |
| `Get-OtAssetTypes.ps1` | Lists the OT/IoT asset types available in your tenant and writes them to a CSV file. |
| `OtAssetCommon.ps1` | Shared helper functions, dot-sourced by the scripts above. |
| `New-OtAsset.format.ps1xml` | Table layout for the results of `New-OtAsset.ps1`. Loaded automatically. |
| `new-otasset.template.csv` | Example CSV with the expected columns. Copy it and fill it in. |

**Keep the three `.ps1` files and `New-OtAsset.format.ps1xml` in the same folder.** The scripts load `OtAssetCommon.ps1` from their own folder and will not run without it. `New-OtAsset.ps1` also loads `New-OtAsset.format.ps1xml` from that folder to show its results as a table. Without it, the results are still written, but as a long list.

## Quick start

1. Run `./Get-OtAssetTypes.ps1`. This creates `OtAssetTypes.csv` with the type names your tenant accepts.
2. Copy `new-otasset.template.csv` and fill in your assets.
3. Validate without creating anything: `./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -DryRun`
4. When the dry run is clean, run it again without `-DryRun`.

## Usage examples

Single asset, with the default type (`OT Device`):

```powershell
./New-OtAsset.ps1 `
    -Ip 192.0.2.50 `
    -Name "Boiler Room PLC"
```

Single asset with a type and an FQDN:

```powershell
./New-OtAsset.ps1 `
    -Ip 192.0.2.51 `
    -Name "Boiler Room PLC 2" `
    -Type "PLC" `
    -Fqdn plc1.example.com
```

Bulk create from a CSV file:

```powershell
./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv
```

Validate a CSV file without creating anything:

```powershell
./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -DryRun
```

Add `-Verbose` to also see the JSON body that would be sent for each row:

```powershell
./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -DryRun -Verbose
```

Create the valid rows and skip the invalid ones:

```powershell
./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -ContinueOnError
```

Skip downloading the existing asset list (duplicate IPs are then reported by the server, row by row, as `Skipped`):

```powershell
./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv -SkipExistingCheck
```

Target a specific tenant:

```powershell
./New-OtAsset.ps1 `
    -CsvFilePath ./my-assets.csv `
    -PortalUrl https://yourtenant-admin.zeronetworks.com
```

List the OT/IoT types for your tenant:

```powershell
./Get-OtAssetTypes.ps1 -IncludeId
./Get-OtAssetTypes.ps1 -OutputPath ./types.csv -Force
./Get-OtAssetTypes.ps1 -PassThru
```

Save the results of a bulk run to a file:

```powershell
./New-OtAsset.ps1 -CsvFilePath ./my-assets.csv | Export-Csv ./results.csv -NoTypeInformation
```

The file has every result property, including `Request`, the JSON body sent for each created row.

## Parameters: New-OtAsset.ps1

- `-CsvFilePath` - CSV mode. Required in CSV mode; the file must exist.
- `-Ip` - Single mode. Required; dotted IPv4 address.
- `-Name` - Single mode. Required; display name.
- `-Fqdn` - Optional. If omitted, the server defaults it to the display name.
- `-Type` - Single mode. Defaults to `"OT Device"`. Accepts a type name or a numeric ID.
- `-SwitchId` and `-InterfaceName` - Single mode, optional. Must be used together.
- `-ApiKey` - Defaults to `$Env:ZN_API_KEY`.
- `-PortalUrl` - Optional. Overrides the API host that is otherwise read from the API key, which falls back to `portal.zeronetworks.com`.
- `-DryRun` - Runs all validation, including the read-only API lookups. Nothing is created. Add `-Verbose` to see each request body; the body is also in the `Request` property of each result.
- `-ContinueOnError` - Creates the valid rows and skips the invalid ones, and keeps going after API failures. The exit code is still non-zero if any row was not created.
- `-SkipExistingCheck` - Skips downloading the existing OT asset list. Duplicate IPs are then reported by the server, per row, as `Skipped`.

## Parameters: Get-OtAssetTypes.ps1

- `-ApiKey` - Defaults to `$Env:ZN_API_KEY`.
- `-PortalUrl` - Optional. Same behavior as in `New-OtAsset.ps1`.
- `-OutputPath` - Where to write the CSV. Defaults to `./OtAssetTypes.csv`.
- `-IncludeId` - Adds an `id` column.
- `-Force` - Overwrites an existing file. Without it, the script refuses to overwrite.
- `-PassThru` - Also writes the rows to the pipeline.

The output file is UTF-8 with a BOM, so it opens cleanly in spreadsheet apps. It has one `type` column (plus `id` with `-IncludeId`).

## CSV format

The first line is the header. Columns:

| Column | Required | Rules |
| --- | --- | --- |
| `ipv4` | Yes | Dotted IPv4 address. No CIDR, no leading zeros. `0.0.0.0`, `127.0.0.1` and `255.255.255.255` are not allowed. |
| `type` | Yes | OT/IoT type name or numeric ID. See [How `type` works](#how-type-works). |
| `displayName` | Yes | Name of the asset in the portal. |
| `fqdn` | No | Fully qualified domain name. |
| `switchId` | No | Format `w:x:XXXXXXXX`, as shown in the switch details in the portal. |
| `interfaceName` | No | Exact, case-sensitive name of an interface that exists on that switch. |

Notes:

- Header names are case-insensitive.
- Extra columns are ignored, with a warning.
- Fully blank lines are skipped.
- "Row N" in messages and results counts the lines after the header, so the first data line is Row 1. Skipped blank lines still count.

CSV only. If you build the list in Excel, use File -> Save As -> 'CSV UTF-8 (Comma delimited)'.

### How `type` works

- Use the tenant's current display name (for example `IP camera`, `Printer` or `OT Device`) or its numeric ID.
- Names are read live from your tenant on every run, so new types added by Zero Networks work immediately.
- Matching ignores case, spaces and punctuation, but is otherwise exact. `IP camera` and `Security cameras` are different types.
- If two names normalize to the same text, use the numeric ID. `Get-OtAssetTypes.ps1` writes the ID for those.
- Only OT/IoT types are accepted. The generic type 1001 (`OT/IoT`) is accepted with a warning.
- Unknown names get "Did you mean" suggestions.

## Validation

Before anything is created, every row is checked and all problems are reported at once:

- Required columns are present.
- `ipv4` is a valid IPv4 address.
- `displayName` is not blank.
- `type` resolves to exactly one OT/IoT type.
- `switchId` and `interfaceName` are provided together, and `switchId` has the correct format.
- No duplicate IP or display name inside the file.
- No OT asset with the same name (case-insensitive) or the same IP already exists in the tenant.
- The switch exists.
- The interface exists on that switch.

By default, one bad row means nothing is created.

## Results and exit codes

`New-OtAsset.ps1` writes one object per row and shows the objects as a table. Example with `-ContinueOnError` and one invalid row:

```text
WARNING: Row 4: type 'Nonsense' is not a recognized OT/IoT type for this tenant. Run Get-OtAssetTypes.ps1 to list valid names.
Validated 4 row(s): 3 valid, 1 invalid
Summary: Created 3, Invalid 1

 Row Name                             Ip              Type Status       Detail
 --- ----                             --              ---- ------       ------
   1 Lobby Cam                        10.0.0.20          4 Created      a:o:Xk3Pq9W1
   2 Floor2 Printer                   10.0.0.21          8 Created      a:o:Xk3Pq9W2
   3 Line PLC                         10.0.0.22        135 Created      a:o:Xk3Pq9W3
   4 Invalid Row                      10.0.0.99            Invalid      type 'Nonsense' is not a recognized
                                                                        OT/IoT type for this tenant. Run
                                                                        Get-OtAssetTypes.ps1 to list valid
                                                                        names.
```

`Detail` is the new asset ID for created rows and the reason for rows that were not created. Each object has the properties `Row`, `Name`, `Ip`, `TypeId`, `Status`, `AssetId`, `Error` and `Request`. `Request` is the JSON body and is set for `Created` and `DryRun` rows. To see every property, add `| Format-List *`. To keep them, add `| Export-Csv`.

Status values:

- `Created` - the asset was created.
- `DryRun` - the row is valid; nothing was created because of `-DryRun`.
- `Skipped` - the asset already exists on the server.
- `Invalid` - the row failed validation.
- `Failed` - the API rejected the request.
- `NotAttempted` - the row was valid, but the run stopped before it was sent.

The validation count, the summary and the dry-run hint are written to the information stream, so they print above the table. Silence them with `-InformationAction SilentlyContinue`. Per-row progress and request bodies are written to the verbose stream; add `-Verbose` to see them. Validation problems are written as warnings (`Row N: ...`).

Exit codes:

- `New-OtAsset.ps1`: `0` = every row was created (or was a dry run). `1` = at least one row was not created. `2` = setup error, such as a missing API key, an unreadable CSV or missing columns, a failure to read the type list or the existing assets, or a missing helper file.
- `Get-OtAssetTypes.ps1`: `0` = success. `1` = failure.

## Troubleshooting

- **HTTP 401:** the API key is bad or expired.
- **HTTP 403 on create:** the API key is read-only. `New-OtAsset.ps1` needs a read-write key.
- **Wrong tenant or host:** pass `-PortalUrl` with your tenant's admin URL.
- **"type ... is not a recognized OT/IoT type":** run `Get-OtAssetTypes.ps1` to list the valid names.
- **"ambiguous":** use the numeric ID for that type.
- **"the switch API is not available for this tenant":** OT switch features are not enabled for this tenant. Remove the `switchId` and `interfaceName` columns.
- **"interface ... not found on switch":** interface names are case-sensitive and belong to one switch. Check the spelling against that switch.
- **"already exists" or `Skipped`:** an asset already holds that static IP or name.
- **"Required helper file 'OtAssetCommon.ps1' was not found":** keep all three `.ps1` files in the same folder.
- **Results are shown as a long list instead of a table:** `New-OtAsset.format.ps1xml` is missing from the script folder.

## Related

- [`../Import-Asimily/`](../Import-Asimily/) - for importing OT assets from an Asimily export.
