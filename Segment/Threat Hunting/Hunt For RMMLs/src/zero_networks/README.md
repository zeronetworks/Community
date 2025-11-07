# Zero Networks API Client

A lightweight, well-structured Python client for the Zero Networks REST API. This client provides a clean interface for interacting with the Zero Networks portal API, featuring automatic cursor-based pagination, comprehensive error handling, and full type hint support.

## Features

- **Automatic Cursor Pagination**: Built-in generator support for iterating through paginated results
- **Comprehensive Error Handling**: Custom exception classes for different error types (401, 403, 404, 500, etc.)
- **Type Safety**: Full type hints throughout for better IDE support and code clarity
- **Environment Support**: Easily switch between production, development, and localhost environments
- **Request Logging**: Integrated with loguru for request/response logging
- **Thread-Safe**: Uses `requests.Session` for connection pooling and efficient resource management
- **Context Manager Support**: Can be used with Python's `with` statement for automatic cleanup

## Installation

The API client requires the following dependencies:

```bash
pip install requests loguru
```

## Quick Start

### Basic Usage

```python
from src.zero_networks.api import ZeroNetworksAPI

# Initialize the client
api = ZeroNetworksAPI(api_key="your-api-key-here")

# Make a simple request
domains = api.get("/active-directory/domains")
print(f"Found {len(domains.get('items', []))} domains")
```

### Using Cursor Pagination

The API client automatically handles cursor-based pagination through the `iter_paginated()` method:

```python
from src.zero_networks.api import ZeroNetworksAPI

api = ZeroNetworksAPI(api_key="your-api-key-here")

# Iterate through all logon activities
for activity in api.iter_paginated("/activities/logon", limit=100):
    print(f"Activity ID: {activity.get('id')}")
    # Process each activity...
```

### Convenience Functions

The module includes convenience functions for common operations:

```python
from src.zero_networks.api import ZeroNetworksAPI, iter_logon_activities, get_ad_domains
from datetime import datetime, timedelta

api = ZeroNetworksAPI(api_key="your-api-key-here")

# Get activities from the last 7 days
from_time = int((datetime.now() - timedelta(days=7)).timestamp() * 1000)

# Use the convenience function with automatic pagination
for activity in iter_logon_activities(api, from_time=from_time, limit=100):
    print(f"Logon: {activity}")

# Get AD domains
domains_response = get_ad_domains(api)
print(f"Domains: {domains_response}")
```

### Context Manager

The client can be used as a context manager for automatic resource cleanup:

```python
with ZeroNetworksAPI(api_key="your-api-key-here") as api:
    data = api.get("/activities/logon", params={"limit": 10})
    # Session is automatically closed when exiting the context
```

## API Reference

### ZeroNetworksAPI Class

#### `__init__(api_key, base_url=None, timeout=30, max_retries=3)`

Initialize the Zero Networks API client.

**Parameters:**
- `api_key` (str): Zero Networks API key for authentication (required)
- `base_url` (str, optional): Base URL for the API. Defaults to production URL:
  - Production: `https://portal.zeronetworks.com/api/v1`
  - Development: `https://portal-dev.zeronetworks.com/api/v1`
  - Localhost: `http://localhost:4000/api/v1`
- `timeout` (int): Request timeout in seconds (default: 30)
- `max_retries` (int): Maximum number of retry attempts for failed requests (default: 3)

**Raises:**
- `ValueError`: If `api_key` is empty or None

#### `get(endpoint, params=None, **kwargs)`

Make a GET request to the API.

**Parameters:**
- `endpoint` (str): API endpoint path (e.g., "/activities/logon")
- `params` (dict, optional): Query parameters
- `**kwargs`: Additional arguments passed to `requests.request()`

**Returns:**
- `dict[str, Any]`: Parsed JSON response from the API

**Raises:**
- `ZeroNetworksAPIError`: For any API errors
- `requests.RequestException`: For network/connection errors

#### `post(endpoint, json_data=None, params=None, **kwargs)`

Make a POST request to the API.

**Parameters:**
- `endpoint` (str): API endpoint path
- `json_data` (dict, optional): JSON body to send
- `params` (dict, optional): Query parameters
- `**kwargs`: Additional arguments passed to `requests.request()`

**Returns:**
- `dict[str, Any]`: Parsed JSON response from the API

#### `put(endpoint, json_data=None, params=None, **kwargs)`

Make a PUT request to the API.

**Parameters:**
- `endpoint` (str): API endpoint path
- `json_data` (dict, optional): JSON body to send
- `params` (dict, optional): Query parameters
- `**kwargs`: Additional arguments passed to `requests.request()`

**Returns:**
- `dict[str, Any]`: Parsed JSON response from the API

#### `delete(endpoint, params=None, **kwargs)`

Make a DELETE request to the API.

**Parameters:**
- `endpoint` (str): API endpoint path
- `params` (dict, optional): Query parameters
- `**kwargs`: Additional arguments passed to `requests.request()`

**Returns:**
- `dict[str, Any]`: Parsed JSON response from the API

#### `iter_paginated(endpoint, items_key="items", cursor_key="nextCursor", cursor_param="_cursor", limit=None, params=None, **kwargs)`

Iterate through paginated API responses using cursor-based pagination.

This generator automatically handles cursor pagination by making requests and following the cursor until all data is retrieved.

**Parameters:**
- `endpoint` (str): API endpoint path (e.g., "/activities/logon")
- `items_key` (str): Key in response JSON containing the items array (default: "items")
- `cursor_key` (str): Key in response JSON containing the next cursor value (default: "nextCursor")
- `cursor_param` (str): Query parameter name for the cursor (default: "_cursor")
- `limit` (int, optional): Maximum number of items per page
- `params` (dict, optional): Additional query parameters to include in all requests
- `**kwargs`: Additional arguments passed to `requests.request()`

**Yields:**
- `dict[str, Any]`: Individual items from the paginated response

**Example:**
```python
# Iterate through all logon activities
for activity in api.iter_paginated("/activities/logon", limit=100):
    print(f"Activity ID: {activity.get('id')}")

# With additional query parameters
params = {"_entityId": "u:a:123", "from": 1647308838000}
for activity in api.iter_paginated("/activities/logon", params=params):
    process_activity(activity)
```

#### `close()`

Close the HTTP session and clean up resources. Should be called when done with the API client.

## Exception Classes

The module defines several custom exception classes for different error scenarios:

### ZeroNetworksAPIError
Base exception class for all Zero Networks API errors. Contains:
- `message`: Human-readable error message
- `status_code`: HTTP status code
- `response_body`: Full response body (if available)

### ZeroNetworksAuthenticationError
Raised when authentication fails (401 Unauthorized). Typically means the API key is missing, invalid, or expired.

### ZeroNetworksAuthorizationError
Raised when authorization fails (403 Forbidden). The API key is valid but doesn't have permission for the requested resource.

### ZeroNetworksNotFoundError
Raised when a requested resource is not found (404 Not Found).

### ZeroNetworksBadRequestError
Raised when the API request is malformed (400 Bad Request). Usually indicates invalid parameters or missing required fields.

### ZeroNetworksServerError
Raised when the API server encounters an error (500+ Internal Server Error).

## Error Handling Example

```python
from src.zero_networks.api import (
    ZeroNetworksAPI,
    ZeroNetworksAuthenticationError,
    ZeroNetworksNotFoundError
)

api = ZeroNetworksAPI(api_key="your-api-key")

try:
    data = api.get("/activities/logon")
except ZeroNetworksAuthenticationError as e:
    print(f"Authentication failed: {e}")
    print(f"Status code: {e.status_code}")
except ZeroNetworksNotFoundError as e:
    print(f"Resource not found: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Advanced Usage

### Custom Query Parameters

```python
api = ZeroNetworksAPI(api_key="your-api-key")

# Custom query with filters
params = {
    "_entityId": "u:a:123",
    "from": 1647308838000,
    "to": 1647913638000,
    "_search": "admin",
    "_limit": 50
}

response = api.get("/activities/logon", params=params)
```

### Using Different Environments

```python
# Production (default)
api_prod = ZeroNetworksAPI(api_key="your-key")

# Development
api_dev = ZeroNetworksAPI(
    api_key="your-key",
    base_url=ZeroNetworksAPI.DEV_BASE_URL
)

# Localhost
api_local = ZeroNetworksAPI(
    api_key="your-key",
    base_url=ZeroNetworksAPI.LOCAL_BASE_URL
)
```

### Custom Timeout and Retry Settings

```python
# Increase timeout for slow connections
api = ZeroNetworksAPI(
    api_key="your-key",
    timeout=60,
    max_retries=5
)
```

### Processing Large Datasets

When processing large datasets, use the pagination generator to avoid loading everything into memory:

```python
from src.zero_networks.api import ZeroNetworksAPI

api = ZeroNetworksAPI(api_key="your-key")

# Process activities one at a time (memory efficient)
count = 0
for activity in api.iter_paginated("/activities/logon", limit=1000):
    # Process each activity
    process_activity(activity)
    count += 1
    
    if count % 1000 == 0:
        print(f"Processed {count} activities...")

print(f"Total activities processed: {count}")
```

## Best Practices

1. **Always use context managers** when possible:
   ```python
   with ZeroNetworksAPI(api_key="key") as api:
       data = api.get("/endpoint")
   ```

2. **Handle exceptions appropriately**:
   ```python
   try:
       data = api.get("/endpoint")
   except ZeroNetworksAuthenticationError:
       # Handle auth errors
   except ZeroNetworksAPIError as e:
       # Handle other API errors
   ```

3. **Use pagination for large datasets**:
   ```python
   # Good: Memory efficient
   for item in api.iter_paginated("/endpoint"):
       process(item)
   
   # Bad: May load too much data into memory
   data = api.get("/endpoint")
   for item in data["items"]:
       process(item)
   ```

4. **Set appropriate timeouts**:
   ```python
   # For slow connections or large queries
   api = ZeroNetworksAPI(api_key="key", timeout=120)
   ```

5. **Use environment variables for API keys**:
   ```python
   import os
   api_key = os.getenv("ZN_API_KEY")
   api = ZeroNetworksAPI(api_key=api_key)
   ```

## Integration with Existing Code

This API client is designed to work seamlessly with the existing threat hunting script. Here's how to integrate it:

```python
from src.zero_networks.api import ZeroNetworksAPI, iter_logon_activities
from datetime import datetime, timedelta

# In your main script
api_key = os.getenv("ZN_API_KEY")
api = ZeroNetworksAPI(api_key=api_key)

# Get activities from a specific time period
from_time = int(from_datetime.timestamp() * 1000)
to_time = int(datetime.now().timestamp() * 1000)

# Iterate through activities
for activity in iter_logon_activities(api, from_time=from_time, to_time=to_time):
    # Process activity data
    process_activity(activity)
```

## Logging

The API client uses `loguru` for logging. To enable debug logging:

```python
from loguru import logger

# Enable debug logging
logger.add("api.log", level="DEBUG")

api = ZeroNetworksAPI(api_key="your-key")
# All API requests/responses will be logged
```

## Thread Safety

The `ZeroNetworksAPI` class uses `requests.Session` which is thread-safe for making concurrent requests. However, each instance should be used by a single thread, or you can create separate instances for each thread.

## License

This code is part of the Zero Networks Community repository.

## Support

For issues or questions:
- Email: support@zeronetworks.com
- Support Portal: https://support.zeronetworks.com


