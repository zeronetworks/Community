# Hunt for RMMs

A threat hunting tool that searches Zero Networks tenant activities for indicators of potentially malicious or unauthorized Remote Management and Monitoring (RMM) software usage.

## Overview

This tool automates the detection of RMM software in your Zero Networks environment by:

- Cloning the [RMML repository](https://github.com/LivingInSyn/RMML) to obtain known RMM software signatures
- Querying Zero Networks API for network activities matching RMM indicators (domains, processes, ports)
- Analyzing and aggregating results to identify potential threats
- Providing CSV export of found activities (all_indicating_activities.csv)

## Features

- **Automated RMM Detection**: Searches for known RMM software based on domains, executable processes, and network ports
- **Concurrent Processing**: Uses multi-threaded execution for efficient hunting across multiple RMM signatures
- **Comprehensive Logging**: Detailed logging with multiple verbosity levels (INFO, DEBUG, TRACE)
- **Flexible Time Ranges**: Query activities within custom time ranges or use sensible defaults
- **Activity Analysis**: Aggregates and analyzes discovered activities by source assets, destinations, ports, and processes
- **CSV Export**: Exports all discovered activities to CSV files for further analysis
- **ISO8601 Timestamp Validation**: Validates timestamp formats to ensure proper query execution

## Requirements
- Python 3.13 or later
- Zero Networks API key
- Internet connection (for cloning RMML repository)
- Git (for repository cloning)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd "Hunt For RMMLs"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Or using the project configuration:
```bash
pip install -e .
```

## Configuration
### Environment Variables

Set the Zero Networks API key as an environment variable:

**Linux/macOS:**
```bash
export ZN_API_KEY="your-api-key-here"
```

**Windows (Command Prompt):**
```cmd
set ZN_API_KEY=your-api-key-here
```

**Windows (PowerShell):**
```powershell
$env:ZN_API_KEY="your-api-key-here"
```

## Usage

### Basic Usage

Run the script with default settings (searches last 7 days):

```bash
python hunt.py
```

### Command-Line Arguments

```bash
python hunt.py [OPTIONS]
```

**Options:**

- `-v, --verbose`: Enable verbose logging
  - `-v`: DEBUG level (detailed debugging information)
  - `-vv`: TRACE level (very verbose - large log files and potentially sensitive info logged)
- `--from TIMESTAMP`: Start datetime for querying (ISO8601 format, e.g., `2024-01-01T00:00:00Z`)
  - Defaults to one week ago if not specified
  - Must be in valid ISO8601 format
- `--to TIMESTAMP`: End datetime for querying (ISO8601 format, e.g., `2024-01-31T23:59:59Z`)
  - Defaults to current time if not specified
  - Must be in valid ISO8601 format
- `--repo-url URL`: URL of the RMML repository to clone
  - Defaults to `https://github.com/LivingInSyn/RMML.git`
- `--no-csv`: Do not export observed activities to CSV

### Examples

**Query with default time range (last 7 days):**
```bash
python hunt.py
```

**Query with custom time range:**
```bash
python hunt.py --from "2024-01-01T00:00:00Z" --to "2024-01-31T23:59:59Z"
```

**Query with timezone offset:**
```bash
python hunt.py -v --from "2024-01-01T00:00:00-05:00"
```

**Enable debug logging:**
```bash
python hunt.py -v
```

**Enable trace logging:**
```bash
python hunt.py -vv
```

**Use custom RMML repository:**
You can fork ()[https://github.com/LivingInSyn/RMML] and add your own RMM YAML files, if you **You must retain the same directory structure!"

This functionality does make it possible to write custom YAML for software other than RMMs, though!
```bash
python hunt.py --repo-url "https://github.com/custom/repo.git"
```

## Output

### Logging

The script generates logs in two locations:

1. **Console Output**: Colorized log messages with timestamps, log levels, process/thread IDs, and function locations
2. **File Logging**: Detailed logs saved to `logs/hunt.log` with automatic rotation (10 MB), retention (5 files), and compression

**Log Levels:**
- `INFO`: General information about script execution
- `DEBUG`: Detailed debugging information (use `-v`)
- `TRACE`: Very detailed trace information (use `-vv`)

### Results
The script generates the following outputs:

1. **CSV Export**: By default, exports all discovered activities to `all_indicating_activities.csv` (or `all_indicating_activities_N.csv` if file exists)
   - Contains all network activities matching RMM indicators
   - Includes metadata such as timestamps, source/destination information, protocols, ports, and indicator types
   - Columns are prioritized for readability

## How It Works
1. **Initialization**: 
   - Loads Zero Networks API key from environment
   - Clones RMML repository to get RMM software signatures
   - Initializes Zero Networks API client

2. **Hunting Process**:
   - For each RMM software definition:
     - Builds filters based on domains, processes, and ports
     - Queries Zero Networks API for matching network activities
     - Collects and aggregates results

3. **Analysis**:
   - Decodes discovered activities, mapping integer ID fields to human-readable strings
   - Deduplicates activities based on event record IDs
   - Resolves asset IDs to asset names

4. **Reporting**:
   - Exports CSV containing all activities seen across all RMMs

## Timestamp Format
The script requires timestamps in ISO8601 format. Supported formats include:
- `2024-01-01T00:00:00Z` (UTC with Z suffix)
- `2024-01-01T00:00:00+00:00` (UTC with offset)
- `2024-01-01T00:00:00-05:00` (Timezone offset)
- `2024-01-01T00:00:00.123456Z` (With microseconds)

The script validates timestamp formats and will exit with an error if invalid formats are provided.

## Add Your Own Signatures
You can fork the [RMML repository](https://github.com/LivingInSyn/RMML), and add your own RMM-style YAML files within the RMMs folder of your fork!

Then, provide the `--repo-url` parameter to download your RMMs! Keep in mind that your repository MUST BE PUBLIC (or you must have git globally set up with permissions to access it, as the script launches a git subprocess to clone the repo)

## Troubleshooting

### API Key Issues

If you see an error about the API key:
```
API key validation failed: ZN_API_KEY environment variable is not set or empty
```

Ensure the `ZN_API_KEY` environment variable is set correctly.

### Timestamp Format Issues

If you see an error about timestamp format:
```
Invalid --from timestamp format: Timestamp '...' is not in valid ISO8601 format
```

Ensure your timestamps are in valid ISO8601 format. Examples:
- `2024-01-01T00:00:00Z`
- `2024-01-01T00:00:00+00:00`
- `2024-01-01T00:00:00-05:00`

### Network Issues

If the script fails to clone the RMML repository, check your internet connection and verify the repository URL is accessible.

### Logging Issues

Logs are written to the `logs/` directory. If you encounter issues:
- Check that the `logs/` directory exists and is writable
- Review log files for detailed error messages
- Use `-v` or `-vv` flags for more detailed logging

## Contributing

This is a community project. Contributions are welcome!

## License

MIT License

## Author

**Thomas Obarowski**  
Email: thomas.obarowski@zeronetworks.com

## Acknowledgments

- RMM software signatures from the [RMML repository](https://github.com/LivingInSyn/RMML)
- Zero Networks for the API and platform

