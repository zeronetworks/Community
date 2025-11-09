# Zero Threat Hunt Tools

A Python library for performing threat hunting operations on Zero Networks activities. This tool provides a high-level interface for querying and analyzing network activities to identify potential security threats.

## Features

- **Domain-based hunting**: Search for network activities connecting to specific domains
- **Process-based hunting**: Find activities by source or destination processes
- **Port-based hunting**: Identify traffic to specific destination ports
- **IP-based hunting**: Search for activities connecting to specific IP addresses
- **Flexible filtering**: Support for timestamp ranges, text search, entity filtering, appending additional network activity filters, and more
- **Automatic pagination**: Handles large result sets automatically
- **Type-safe**: Full type hints and validation

## Installation

### Prerequisites

- Python 3.14 or higher
- Zero Networks API key

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd "Community/Segment/Threat Hunting/Hunt Any Threat"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set your Zero Networks API key using one of the following methods:

   **Option A: Environment variable (recommended)**
   
   Set the API key in your shell environment:
   ```bash
   export ZN_API_KEY=your-zero-networks-api-key-here
   ```
   
   For Windows PowerShell:
   ```powershell
   $env:ZN_API_KEY="your-zero-networks-api-key-here"
   ```
   
   **Option B: Using .env file (optional)**
   
   If you prefer using a `.env` file, install the optional `python-dotenv` dependency:
   ```bash
   pip install python-dotenv
   ```
   
   Then create a `.env` file in the project root:
   ```env
   ZN_API_KEY=your-zero-networks-api-key-here
   ```
   
   Note: The `example.py` file uses `python-dotenv` to load from `.env` files, but it's not required if you set the environment variable directly.

## Quick Start

```python
from src.zero_threat_hunt_tools import ZeroThreatHuntTools

# Initialize the threat hunting tools
hunter = ZeroThreatHuntTools(api_key="your-api-key")

# Search for activities to specific domains
domains = ["suspicious-domain.com", "malicious-site.net"]
activities = hunter.get_activities_to_domains(
    domains,
    from_timestamp="2024-01-01T00:00:00Z",
    limit=100
)

print(f"Found {len(activities)} activities")
```

## Usage Examples

See `example.py` for comprehensive usage examples. Here are some common use cases:

### Search by Domains

```python
hunter = ZeroThreatHuntTools(api_key=API_KEY)

# Basic domain search
domains = ["example.com", "test.com"]
activities = hunter.get_activities_to_domains(domains)

# With timestamp filtering
from datetime import datetime, timedelta, timezone
now = datetime.now(timezone.utc)
one_week_ago = now - timedelta(days=7)

activities = hunter.get_activities_to_domains(
    domains,
    from_timestamp=one_week_ago.isoformat(),
    to_timestamp=now.isoformat()
)
```

### Search by Source Processes

```python
# Find activities from specific processes (e.g., RMM tools)
process_paths = [
    "/usr/bin/teamviewer",
    "C:\\Program Files\\TeamViewer\\TeamViewer.exe"
]

activities = hunter.get_activities_from_source_processes(
    process_paths,
    from_timestamp="2024-01-01T00:00:00Z"
)
```

### Search by Destination Ports

```python
# Find activities to specific ports
ports = [5938, 443, 80, 3389]

activities = hunter.get_activities_to_destination_ports(
    ports,
    from_timestamp="2024-01-01T00:00:00Z",
    limit=200
)
```

### Search by Destination IPs

```python
# Find activities to specific IP addresses
ip_addresses = ["192.168.1.100", "10.0.0.50"]

activities = hunter.get_activities_to_destination_ips(
    ip_addresses,
    from_timestamp="2024-01-01T00:00:00Z"
)
```

### Using Additional Filters

All methods support additional keyword arguments for filtering:

```python
activities = hunter.get_activities_to_domains(
    domains=["example.com"],
    from_timestamp="2024-01-01T00:00:00Z",
    to_timestamp="2024-12-31T23:59:59Z",
    _search="suspicious",  # Text search
    _entityId="u:a:12345678",  # Filter by entity
    limit=50,  # Results per page
    order="desc"  # Sort order: "asc" or "desc"
)
```

## Code Documentation

### ZeroThreatHuntTools

Main class for performing threat hunting operations.

#### `__init__(api_key: str, zn_base_url: Optional[str] = None)`

Initialize the ZeroThreatHuntTools class.

**Parameters:**
- `api_key` (str): Zero Networks API key (JWT token)
- `zn_base_url` (Optional[str]): Base URL for the Zero Networks API. If not provided, will be extracted from the JWT if possible.

**Raises:**
- `ValueError`: If network filters cannot be retrieved from the API
- `ZeroNetworksAPIError`: If the API client initialization fails

#### `get_activities_to_domains(domains: list[str], **kwargs: Any) -> list[dict[str, Any]]`

Retrieve network activities that connect to the specified domains.

**Parameters:**
- `domains` (list[str]): List of domain strings to search for
- `**kwargs`: Optional keyword arguments:
  - `from_timestamp` (str): Start datetime ISO8601 timestamp string
  - `to_timestamp` (str): End datetime ISO8601 timestamp string
  - `_search` (str): Search string for text-based filtering
  - `_entityId` (str): Entity ID to filter by
  - `limit` (int): Maximum number of results per page (default: 100)
  - `order` (str): Sort order ("asc" or "desc", default: "desc")

**Returns:**
- `list[dict[str, Any]]`: List of activity dictionaries

**Raises:**
- `ZeroThreatHuntInvalidValues`: If domains list is empty or contains non-string values
- `ZeroNetworksAPIError`: If the API request fails
- `ValueError`: If datetime strings cannot be parsed

#### `get_activities_from_source_processes(process_paths: list[str], **kwargs: Any) -> list[dict[str, Any]]`

Retrieve network activities that originate from the specified source processes.

**Parameters:**
- `process_paths` (list[str]): List of process path strings
- `**kwargs`: Same optional keyword arguments as `get_activities_to_domains`

**Returns:**
- `list[dict[str, Any]]`: List of activity dictionaries

#### `get_activities_to_destination_processes(process_paths: list[str], **kwargs: Any) -> list[dict[str, Any]]`

Retrieve network activities that connect to the specified destination processes.

**Parameters:**
- `process_paths` (list[str]): List of process path strings
- `**kwargs`: Same optional keyword arguments as `get_activities_to_domains`

**Returns:**
- `list[dict[str, Any]]`: List of activity dictionaries

#### `get_activities_to_destination_ports(ports: list[int], **kwargs: Any) -> list[dict[str, Any]]`

Retrieve network activities that connect to the specified destination ports.

**Parameters:**
- `ports` (list[int]): List of port numbers (integers between 1 and 65535)
- `**kwargs`: Same optional keyword arguments as `get_activities_to_domains`

**Returns:**
- `list[dict[str, Any]]`: List of activity dictionaries

**Raises:**
- `ZeroThreatHuntInvalidValues`: If ports list is empty or contains invalid port values

#### `get_activities_to_destination_ips(ip_addresses: list[str], **kwargs: Any) -> list[dict[str, Any]]`

Retrieve network activities that connect to the specified destination IP addresses.

**Parameters:**
- `ip_addresses` (list[str]): List of IP address strings
- `**kwargs`: Same optional keyword arguments as `get_activities_to_domains`

**Returns:**
- `list[dict[str, Any]]`: List of activity dictionaries

## Timestamp Formats

The library supports multiple ISO8601 timestamp formats:

- **UTC with Z indicator**: `"2024-01-01T12:00:00Z"`
- **Timezone offset**: `"2024-01-01T12:00:00+05:00"`
- **No timezone (defaults to UTC)**: `"2024-01-01T12:00:00"`

You can also use Python datetime objects converted to ISO format:

```python
from datetime import datetime, timezone

now = datetime.now(timezone.utc)
timestamp_str = now.isoformat()
```

## Error Handling

The library provides custom exceptions for better error handling:

```python
from src.zero_threat_hunt_exceptions import ZeroThreatHuntInvalidValues

try:
    activities = hunter.get_activities_to_domains([])
except ZeroThreatHuntInvalidValues as e:
    print(f"Invalid input: {e}")
    print(f"Details: {e.details}")
except ValueError as e:
    print(f"Value error: {e}")
```

### Exception Classes

- **`ZeroThreatHuntError`**: Base exception class for all threat hunting errors
- **`ZeroThreatHuntInvalidValues`**: Raised when invalid values are provided

## Testing

Run tests using pytest:

```bash
pytest
```

Make sure you have set the `ZN_API_KEY` environment variable (or have it in a `.env` file) for the tests to run.

**Note on test data**: The pytest test cases use hard-coded IP addresses, domains, ports, and process paths that may not exist in your Zero Networks environment. If one or more tests fail due to no activities being found for these values, this is expected behavior. You can update the test cases in the `tests/` directory with environment-relevant values if you want the tests to find actual data in your environment.

## Project Structure

```
.
├── src/
│   ├── zero_threat_hunt_tools.py      # Main threat hunting tools
│   ├── zero_threat_hunt_exceptions.py # Custom exceptions
│   └── zero_networks/
│       └── api.py                     # Zero Networks API client
├── tests/                             # Test files
├── example.py                         # Usage examples
├── requirements.txt                   # Python dependencies
├── pyproject.toml                    # Project configuration
└── README.md                          # This file
```

## Dependencies

- `loguru`: Logging
- `requests`: HTTP requests
- `python-dotenv`: Environment variable management (optional, only needed if using `.env` files)

## Contributing

Refer to the instructions provided in the main Community [README.md](https://github.com/zeronetworks/Community/blob/master/README.md#contributing).

## Changelog

### Version 0.1.0
- Initial release
- Support for domain, process, port, and IP-based hunting
- Timestamp filtering and additional query parameters
- Automatic pagination handling

