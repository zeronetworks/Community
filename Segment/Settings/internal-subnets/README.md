# Set-ZNClientSubnets

Bulk-manage the Zero Networks **client subnets** setting (Settings → Internal Subnets → Client subnets) from a CSV.

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- A Zero Networks API key with permission to change settings

## Client Subnets Upper Limit

Zero Networks supports **up to 300 unique client subnets**. This is a hard limit - if you have more than 300 unique client subnets, you will need to consolidate the ranges to fit within the limit.

**Before making any change, the script reads the limit from the portal and checks the size the list would be afterwards. If that exceeds the limit, the script stops and changes nothing.** For example, in the default append mode a 250-row CSV fails if the portal already has 100 client subnets.

## CSV format

Use a `Subnet` column (or `CIDR`) with one IPv4 CIDR per row. IPv6 entries are rejected because the client-subnets API only accepts IPv4. Other columns are ignored, and so are blank lines. A file with no header, just one CIDR per line, also works.

```csv
Subnet
10.50.0.0/16
192.168.10.0/24
```

The script validates every entry before calling the API. An entry must be a real address with a valid prefix, and its host bits can't be set: `10.0.0.5/24` is rejected and the script suggests `10.0.0.0/24`. By default, invalid entries are reported and skipped. Pass `-RaiseErrorOnInvalidSubnet` to stop on the first invalid entry instead.

## Modes

**By default, the script appends the CSV subnets to the current client subnet list.** Subnets that are already in the list are skipped. 

The script also supports the following modes/operations if needed:

| Switch | What it does |
|---|---|
| `-RemoveSubnets` | Removes the CSV subnets from the current list. |
| `-ReplaceSubnets` | Replaces the **entire** list with the CSV subnets. You have to type `REPLACE` to confirm. |
| `-ExportClientSubnets` | Writes the current list to a CSV in the input format, and changes nothing. Default path: `./client-subnets-export-<timestamp>.csv`. |

## Parameters

The script has several supported parameters outside of the mode options previously discussed. `-CsvPath` is **required**, except with `-ExportClientSubnets`. If you leave out `-ApiKey`, the script prompts for it securely.

| Parameter | Description |
|---|---|
| `-CsvPath` | Input CSV. With `-ExportClientSubnets`, this is the output file. |
| `-PortalBaseUrl` | Portal URL. Default: `https://portal.zeronetworks.com`. |
| `-ApiKey` | API key. If you leave it out, you're prompted for it securely. |
| `-Force` | With `-ExportClientSubnets`, overwrites an existing output file. |
| `-RaiseErrorOnInvalidSubnet` | Stops with an error on the first invalid CSV entry. |
| `-DryRun` | Shows the changes and the request body without applying anything. |
| `-Verbose` | Shows detailed logging: CSV parsing, per-subnet decisions, and HTTP requests and responses. The API key is masked. |

## Examples

```powershell
# Preview an append
./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -ApiKey $key -DryRun

# Append
./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -ApiKey $key

# Remove
./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -ApiKey $key -RemoveSubnets

# Back up the current list, then replace it
./Set-ZNClientSubnets.ps1 -ExportClientSubnets -CsvPath ./backup.csv -ApiKey $key
./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -ApiKey $key -ReplaceSubnets

# Use a tenant-specific portal URL
./Set-ZNClientSubnets.ps1 -CsvPath ./subnets.csv -PortalBaseUrl https://<org>-admin.zeronetworks.com -ApiKey $key
```

## Notes

- The API replaces the whole list on every update. The script reads the current list, applies your changes, and writes the full list back.
- The script checks the portal's maximum number of client subnets (`maxClientSubnets`) before writing. It makes no changes if the result would exceed that limit.
