# Asimily to Zero Networks OT Asset Integration

**Author:** Olaf Gradin (Zero Networks)  
**Version:** 1.0  
**Created:** September 15, 2025

This PowerShell script processes Asimily asset export files and automatically creates OT assets in Zero Networks with intelligent device type mapping.

## Prerequisites

### 1. PowerShell Environment Setup

**Set Execution Policy** (run as Administrator):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Install Required Module** (script can do this automatically):
```powershell
Install-Module ImportExcel -Scope CurrentUser
```

### 2. Zero Networks API Key

1. Browse to your branded Zero Networks portal
2. Sign in with your email and verify with the emailed code
3. Navigate to **Settings → System → Integrations → API**
4. Click **Add new token** and configure:
   - **Token name:** (e.g., "Asimily Integration")
   - **Access type:** Full Access (required for creating OT assets)
   - **Expiry:** Choose appropriate duration (1-36 months)
5. Click **Add** and **copy the token** (it won't be shown again)
6. Set the API key as an environment variable (or include as a parameter to the script):

```powershell
# Set for current session
$env:ZN_API_KEY = "your-api-key-here"

# Set permanently for current user
[Environment]::SetEnvironmentVariable("ZN_API_KEY", "your-api-key-here", "User")
```

### 3. Asimily Data Export

Export your asset data from Asimily with the filename pattern: `{TenantName}_mainAssetsGrid.xlsx`

**Required Fields in Export:**
- Device ID
- Hostname
- IP Address
- Device Type
- Manufacturer
- Device Model
- MAC Address
- OS

## Usage

### Basic Usage
```powershell
# Process all Asimily files and create OT assets
.\Parse-AsimilyExport.ps1

# Process specific tenant files
.\Parse-AsimilyExport.ps1 -TenantName "CustomerA"
```

### Testing Mode
```powershell
# Test what would be created without making API calls
.\Parse-AsimilyExport.ps1 -TenantName "CustomerA" -DryRun
```

### File Processing Only
```powershell
# Process files without Zero Networks integration
.\Parse-AsimilyExport.ps1 -SkipZNIntegration
```

### Advanced Usage
```powershell
# Capture results for inspection
$result = .\Parse-AsimilyExport.ps1 -TenantName "CustomerA"

# View new records
$result.NewRecords | Format-Table

# Check device type mappings
$result.DeviceTypeMappings | Format-Table

# View integration results
$result.ZeroNetworksIntegration
```

## Device Type Mapping

The script uses Asimily's **Device Type** field to map to Zero Networks OT asset categories:

| Asimily Device Type | Zero Networks Type | Category |
|--------------------|--------------------|----------|
| IP Camera | 4 | IP camera |
| Printer | 8 | Printer |
| VoIP Phone | 59 | VoIP Phone |
| Access Point | 18 | Wireless access point |
| Smart TV | 5 | Smart TV |
| IT Server | 136 | OT Server |
| Network Appliance | 11 | Router |
| Controller | 57 | Controller |
| *Unknown/Empty* | 135 | OT Device (generic) |

### Updating Manufacturer Mappings

Edit the `Get-ManufacturerBaseName` function to add new manufacturer short names for hostname construction:

```powershell
$manufacturerMap = @{
    "Your New Manufacturer Ltd" = "YourBrand"
    "Long Company Name Inc" = "ShortName"
    # ... existing mappings
}
```

## File Management

The script uses a simplified file management approach:
- **Automatically finds** all Asimily export files including browser download copies (e.g., `file (1).xlsx`, `file (2).xlsx`)
- **Compares** multiple export files by timestamp
- **Newest file** becomes the master dataset
- **Old files** are automatically deleted after processing
- **Master file** is renamed to clean original filename (removes (1), (2) increments)
- **Working dataset** exists in memory and return object only
- **No backup files** or comparison files are created

**Example:** If you have `customer_mainAssetsGrid.xlsx` and `customer_mainAssetsGrid (1).xlsx`, after processing you'll have only `customer_mainAssetsGrid.xlsx` with all the data.

## Hostname Construction

For assets missing hostnames, the script constructs names using:
- **Manufacturer** (shortened, e.g., "Cisco Systems" → "Cisco")
- **Device Model** (truncated to fit 32-character limit)
- **MAC Address** (last 4 hex digits as suffix)

**Format:** `Manufacturer-DeviceModel-MAC4`  
**Example:** `Cisco-Catalyst2960-A1B2`

## Troubleshooting

### Common Issues

**"ImportExcel module required"**
```powershell
Install-Module ImportExcel -Scope CurrentUser -Force
```

**"API call failed: Unauthorized"**
- Verify your API key is set correctly
- Ensure the API key has "Full Access" permissions
- Check the API key hasn't expired

**"No Asimily export files found"**
- Verify file naming pattern: `*_mainAssetsGrid.xlsx` or `*_mainAssetsGrid (1).xlsx`
- The script automatically finds browser download copies (e.g., file (1).xlsx, file (2).xlsx)
- Check file location (script searches current directory)
- Use `-TenantName` parameter to filter files

**Device type mapping issues**
- Check the Device Type values in your Asimily export
- Unmapped types default to 135 (Generic OT Device)

### Verbose Output
```powershell
$VerbosePreference = "Continue"
.\Parse-AsimilyExport.ps1 -Verbose
```

### Getting Help
```powershell
Get-Help .\Parse-AsimilyExport.ps1 -Full
Get-Help .\Parse-AsimilyExport.ps1 -Examples
```

## Support

For questions or issues:
- **Zero Networks Support:** support@zeronetworks.zendesk.com
- **Script Issues:** Contact olaf.gradin@zeronetworks.com

## Version History

- **v1.0** (September 2025): Initial release with direct Asimily Device Type mapping and simplified file management
