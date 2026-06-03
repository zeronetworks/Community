#!/usr/bin/env python3

"""
Zero Networks API Client

File: api.py
Author: Thomas Obarowski
Email: thomas.obarowski@zeronetworks.com
Created: 2025-01-27

A lightweight Python client for the Zero Networks REST API. This module provides
a clean interface for interacting with the Zero Networks portal API, including
automatic cursor pagination handling, comprehensive error handling, and type-safe
response parsing.

Key Features:
    - Automatic cursor-based pagination with generator support
    - Comprehensive error handling with custom exceptions
    - Type hints throughout for better IDE support and code clarity
    - Configurable base URL for different environments (prod, dev, localhost)
    - Request/response logging support via loguru
    - Thread-safe session management with requests.Session
"""

import base64
import binascii
import json
from typing import Any, Generator, Optional
from urllib.parse import urljoin

import requests
from loguru import logger

# ============================================================================
# Custom Exception Classes
# ============================================================================


class ZeroNetworksAPIError(Exception):
    """
    Base exception class for all Zero Networks API errors.

    This exception is raised when the API returns an error response. It includes
    the HTTP status code, error message, and optionally the full response body
    for debugging purposes.

    :param message: Human-readable error message
    :type message: str
    :param status_code: HTTP status code from the API response
    :type status_code: int
    :param response_body: Optional response body from the API (for debugging)
    :type response_body: Optional[dict[str, Any]]
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        response_body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_body = response_body

    def __str__(self) -> str:
        """Return a formatted string representation of the error."""
        base_msg = f"Zero Networks API Error ({self.status_code}): {self.message}"
        if self.response_body:
            return f"{base_msg}\nResponse: {json.dumps(self.response_body, indent=2)}"
        return base_msg


class ZeroNetworksAuthenticationError(ZeroNetworksAPIError):
    """
    Exception raised when authentication fails (401 Unauthorized).

    This typically means the API key is missing, invalid, or expired.
    """

    pass


class ZeroNetworksAuthorizationError(ZeroNetworksAPIError):
    """
    Exception raised when authorization fails (403 Forbidden).

    This means the API key is valid but doesn't have permission to access
    the requested resource.
    """

    pass


class ZeroNetworksNotFoundError(ZeroNetworksAPIError):
    """
    Exception raised when a requested resource is not found (404 Not Found).
    """

    pass


class ZeroNetworksBadRequestError(ZeroNetworksAPIError):
    """
    Exception raised when the API request is malformed (400 Bad Request).

    This usually indicates invalid parameters or missing required fields.
    """

    pass


class ZeroNetworksServerError(ZeroNetworksAPIError):
    """
    Exception raised when the API server encounters an error (500 Internal Server Error).
    """

    pass


# ============================================================================
# API Client Class
# ============================================================================


class ZeroNetworksAPI:
    """
    Lightweight client for the Zero Networks REST API.

    This class provides a clean, Pythonic interface to the Zero Networks API
    with automatic pagination handling, error management, and type safety.

    Features:
        - Automatic cursor-based pagination with generator support
        - Comprehensive error handling with specific exception types
        - Configurable base URL for different environments
        - Request/response logging integration
        - Thread-safe HTTP session management

    Example:
        .. code-block:: python

            # Initialize the client
            api = ZeroNetworksAPI(api_key="your-api-key")

            # Make a simple request
            domains = api.get_ad_domains()

            # Use pagination for large datasets
            for activity in api.iter_logon_activities(limit=100):
                print(f"Activity: {activity}")

            # Custom request with query parameters
            response = api.get("/activities/logon", params={"_entityId": "u:a:123"})
    """

    # Default base URLs for different environments
    DEFAULT_BASE_URL = "https://portal.zeronetworks.com"
    DEFAULT_API_PATH_URI = "/api/v1"

    @staticmethod
    def decode_jwt_api_key(api_key: str) -> dict[str, Any]:
        """
        Decode a JWT API key and extract its payload.

        This static method decodes the JWT token without verification (since we only need
        to extract configuration data, not verify the signature). It extracts the
        payload portion of the JWT and returns it as a dictionary.

        :param api_key: JWT token string
        :type api_key: str
        :return: Decoded JWT payload as a dictionary
        :rtype: dict[str, Any]
        :raises ValueError: If the API key is not a valid JWT format

        Example:
            .. code-block:: python

                payload = ZeroNetworksAPI.decode_jwt_api_key("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
                base_url = payload.get("base_url")
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")

        # JWT tokens have three parts separated by dots: header.payload.signature
        parts = api_key.strip().split(".")

        if len(parts) != 3:
            raise ValueError(f"Invalid JWT format: expected 3 parts separated by '.', got {len(parts)}")

        # Extract the payload (second part)
        payload_encoded = parts[1]

        try:
            # Decode base64url (JWT uses URL-safe base64 encoding)
            # Add padding if necessary (base64 requires length to be multiple of 4)
            padding = len(payload_encoded) % 4
            if padding:
                payload_encoded += "=" * (4 - padding)

            # Decode base64url to bytes
            payload_bytes = base64.urlsafe_b64decode(payload_encoded)

            # Decode bytes to string and parse JSON
            payload_str = payload_bytes.decode("utf-8")
            payload = json.loads(payload_str)

            return payload

        except binascii.Error as e:
            raise ValueError(f"Failed to decode base64url payload: {e}") from e
        except UnicodeDecodeError as e:
            raise ValueError(f"Failed to decode payload as UTF-8: {e}") from e
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JWT payload as JSON: {e}") from e

    @staticmethod
    def extract_base_url_from_api_key(api_key: str) -> Optional[str]:
        """
        Extract the base URL from a Zero Networks JWT API key.

        This static method decodes the JWT API key and extracts the base URL from the
        payload. The base URL is typically stored in fields like 'iss', 'base_url',
        'portal_url', or 'api_url' in the JWT payload.

        :param api_key: JWT API key token
        :type api_key: str
        :return: Base URL extracted from the JWT, or None if not found
        :rtype: Optional[str]
        :raises ValueError: If the API key cannot be decoded

        Example:
            .. code-block:: python

                api_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                base_url = ZeroNetworksAPI.extract_base_url_from_api_key(api_key)
                if base_url:
                    api = ZeroNetworksAPI(api_key, base_url=base_url)
        """

        payload = ZeroNetworksAPI.decode_jwt_api_key(api_key)
        base_url: str = payload.get("aud")
        if not base_url or not base_url.strip():
            raise ValueError("AUD field not found in JWT payload")
        return base_url

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        api_path_uri: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """
        Initialize the Zero Networks API client.

        :param api_key: Zero Networks API key for authentication
        :type api_key: str
        :param base_url: Base URL for the API (defaults to production "portal.zeronetworks.com")
        :type base_url: Optional[str]
        :param timeout: Request timeout in seconds (default: 30)
        :type timeout: int
        :param max_retries: Maximum number of retry attempts for failed requests
        :type max_retries: int
        :raises ValueError: If api_key is empty or None
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")

        self.api_key = api_key.strip()

        self.api_path_uri = api_path_uri or self.DEFAULT_API_PATH_URI
        if not self.api_path_uri.startswith("/"):
            self.api_path_uri = f"/{self.api_path_uri}"

        try:
            self.base_url = ZeroNetworksAPI.extract_base_url_from_api_key(api_key)
        except ValueError as e:
            logger.error(f"Failed to extract base URL from API key: {e}")

            if base_url:
                self.base_url = base_url.strip()
            else:
                self.base_url = self.DEFAULT_BASE_URL.strip()

        self.timeout = timeout
        self.max_retries = max_retries

        # Create a session for connection pooling and cookie management
        # Using a session allows us to persist headers and connection settings
        # across multiple requests, improving performance
        self.session = requests.Session()

        # Set default headers for all requests
        # The Authorization header is required for all API requests
        self.session.headers.update(
            {
                "Authorization": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        logger.debug(f"Initialized Zero Networks API client with base URL: {self.base_url}")

    def _handle_response(self, response: requests.Response) -> dict[str, Any]:
        """
        Handle HTTP response and raise appropriate exceptions for errors.

        This method centralizes error handling logic, converting HTTP status codes
        into appropriate Python exceptions with detailed error messages.

        :param response: HTTP response object from requests library
        :type response: requests.Response
        :return: Parsed JSON response body
        :rtype: dict[str, Any]
        :raises ZeroNetworksAuthenticationError: For 401 Unauthorized
        :raises ZeroNetworksAuthorizationError: For 403 Forbidden
        :raises ZeroNetworksNotFoundError: For 404 Not Found
        :raises ZeroNetworksBadRequestError: For 400 Bad Request
        :raises ZeroNetworksServerError: For 500+ Server Errors
        :raises ZeroNetworksAPIError: For other HTTP errors
        """
        # Try to parse JSON error response
        try:
            response_body = response.json() if response.content else {}
        except (ValueError, json.JSONDecodeError):
            # If JSON parsing fails, use text content or empty dict
            response_body = {"detail": response.text} if response.text else {}

        # Handle different HTTP status codes
        if response.status_code == 200:
            # Success - return parsed JSON
            return response_body

        # Map HTTP status codes to specific exceptions
        error_messages = {
            400: "Bad Request - Invalid parameters or malformed request",
            401: "Unauthorized - Invalid or missing API key",
            403: "Forbidden - API key does not have permission for this resource",
            404: "Not Found - The requested resource does not exist",
            500: "Internal Server Error - The API server encountered an error",
            502: "Bad Gateway - The API gateway received an invalid response",
            503: "Service Unavailable - The API service is temporarily unavailable",
        }

        # Get error message from response body or use default
        error_msg = (
            response_body.get("message")
            or response_body.get("error")
            or response_body.get("detail")
            or error_messages.get(response.status_code, f"HTTP {response.status_code} Error")
        )

        # Raise appropriate exception based on status code
        if response.status_code == 401:
            raise ZeroNetworksAuthenticationError(error_msg, response.status_code, response_body)
        elif response.status_code == 403:
            raise ZeroNetworksAuthorizationError(error_msg, response.status_code, response_body)
        elif response.status_code == 404:
            raise ZeroNetworksNotFoundError(error_msg, response.status_code, response_body)
        elif response.status_code == 400:
            raise ZeroNetworksBadRequestError(error_msg, response.status_code, response_body)
        elif response.status_code >= 500:
            raise ZeroNetworksServerError(error_msg, response.status_code, response_body)
        else:
            # Generic API error for other status codes
            raise ZeroNetworksAPIError(error_msg, response.status_code, response_body)

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict[str, Any]] = None,
        json_data: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """
        Make an HTTP request to the Zero Networks API.

        This is the core method that all other API methods use. It handles:
        - URL construction
        - Request/response logging
        - Error handling
        - Retry logic

        :param method: HTTP method (GET, POST, PUT, DELETE, etc.)
        :type method: str
        :param endpoint: API endpoint path (e.g., "/activities/logon")
        :type endpoint: str
        :param params: Query parameters to include in the request
        :type params: Optional[dict[str, Any]]
        :param json_data: JSON body to include in the request (for POST/PUT)
        :type json_data: Optional[dict[str, Any]]
        :param kwargs: Additional arguments to pass to requests.request()
        :type kwargs: Any
        :return: Parsed JSON response from the API
        :rtype: dict[str, Any]
        :raises ZeroNetworksAPIError: For any API errors
        :raises requests.RequestException: For network/connection errors
        """
        # Construct full URL
        # Ensure endpoint starts with / and join with base_url
        # This might seem redundant, but it ensures that the endpoint is always has a
        # leading slash to strip lol
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        url = urljoin("https://" + self.base_url + self.api_path_uri + "/", endpoint.lstrip("/"))

        # Log request details
        logger.debug(f"API Request: {method} {url}")
        if params:
            logger.debug(f"Query parameters: {params}")
        if json_data:
            logger.debug(f"Request body: {json.dumps(json_data, indent=2)}")

        # Make the request with retry logic
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    json=json_data,
                    timeout=self.timeout,
                    **kwargs,
                )

                # Log response status
                logger.debug(f"API Response: {response.status_code} for {method} {url}")

                # Handle response (will raise exceptions for errors)
                return self._handle_response(response)

            except (requests.Timeout, requests.ConnectionError) as e:
                # Network errors - retry if we have attempts left
                last_exception = e

                # If we have attempts left, retry
                if attempt < self.max_retries - 1:
                    logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}. Retrying...")
                    continue
                else:
                    # Out of retries - raise the exception
                    logger.error(f"Request failed after {self.max_retries} attempts: {e}")
                    raise

        # This should never be reached, but just in case
        if last_exception:
            raise last_exception

    def get(self, endpoint: str, params: Optional[dict[str, Any]] = None, **kwargs: Any) -> dict[str, Any]:
        """
        Make a GET request to the API.

        :param endpoint: API endpoint path (e.g., "/activities/logon")
        :type endpoint: str
        :param params: Query parameters
        :type params: Optional[dict[str, Any]]
        :param kwargs: Additional arguments for requests
        :type kwargs: Any
        :return: Parsed JSON response
        :rtype: dict[str, Any]
        """
        return self._request("GET", endpoint, params=params, **kwargs)

    def post(
        self,
        endpoint: str,
        json_data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Make a POST request to the API.

        :param endpoint: API endpoint path
        :type endpoint: str
        :param json_data: JSON body to send
        :type json_data: Optional[dict[str, Any]]
        :param params: Query parameters
        :type params: Optional[dict[str, Any]]
        :param kwargs: Additional arguments for requests
        :type kwargs: Any
        :return: Parsed JSON response
        :rtype: dict[str, Any]
        """
        return self._request("POST", endpoint, params=params, json_data=json_data, **kwargs)

    def put(
        self,
        endpoint: str,
        json_data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Make a PUT request to the API.

        :param endpoint: API endpoint path
        :type endpoint: str
        :param json_data: JSON body to send
        :type json_data: Optional[dict[str, Any]]
        :param params: Query parameters
        :type params: Optional[dict[str, Any]]
        :param kwargs: Additional arguments for requests
        :type kwargs: Any
        :return: Parsed JSON response
        :rtype: dict[str, Any]
        """
        return self._request("PUT", endpoint, params=params, json_data=json_data, **kwargs)

    def delete(self, endpoint: str, params: Optional[dict[str, Any]] = None, **kwargs: Any) -> dict[str, Any]:
        """
        Make a DELETE request to the API.

        :param endpoint: API endpoint path
        :type endpoint: str
        :param params: Query parameters
        :type params: Optional[dict[str, Any]]
        :param kwargs: Additional arguments for requests
        :type kwargs: Any
        :return: Parsed JSON response
        :rtype: dict[str, Any]
        """
        return self._request("DELETE", endpoint, params=params, **kwargs)

    def iter_paginated(
        self,
        endpoint: str,
        items_key: str = "items",
        cursor_key: str = "scrollCursor",
        cursor_param: str = "_cursor",
        limit: Optional[int] = None,
        params: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Generator[dict[str, Any], None, None]:
        """
        Iterate through paginated API responses using cursor-based pagination.

        This generator automatically handles cursor pagination by:
        1. Making the initial request
        2. Yielding each item from the response
        3. Extracting the next cursor from the response
        4. Making subsequent requests with the cursor until no more data

        The generator handles both integer timestamp cursors and string cursors
        as specified in the Zero Networks API documentation.

        :param endpoint: API endpoint path (e.g., "/activities/logon")
        :type endpoint: str
        :param items_key: Key in response JSON containing the items array
        :type items_key: str
        :param cursor_key: Key in response JSON containing the next cursor value
        :type cursor_key: str
        :param cursor_param: Query parameter name for the cursor (default: "_cursor")
        :type cursor_param: str
        :param limit: Maximum number of items per page (optional)
        :type limit: Optional[int]
        :param params: Additional query parameters to include in all requests
        :type params: Optional[dict[str, Any]]
        :param kwargs: Additional arguments for requests
        :type kwargs: Any
        :yield: Individual items from the paginated response
        :rtype: Generator[dict[str, Any], None, None]

        Example:
            .. code-block:: python

                # Iterate through all logon activities
                for activity in api.iter_paginated("/activities/logon", limit=100):
                    print(f"Activity ID: {activity.get('id')}")

                # With additional query parameters
                params = {"_entityId": "u:a:123", "from": 1647308838000}
                for activity in api.iter_paginated("/activities/logon", params=params):
                    process_activity(activity)
        """
        # Initialize query parameters
        query_params = params.copy() if params else {}
        if limit:
            query_params["_limit"] = limit

        # Track cursor for pagination
        cursor: Optional[str | int] = None
        page_count = 0

        logger.debug(f"Starting paginated iteration for endpoint: {endpoint}")

        while True:
            # Add cursor to query parameters if we have one
            if cursor is not None:
                query_params[cursor_param] = cursor

            # Make the request
            try:
                response = self.get(endpoint, params=query_params, **kwargs)
            except ZeroNetworksAPIError as e:
                logger.error(f"Error during pagination at page {page_count + 1}: {e}")
                raise

            # Extract items from response
            items = response.get(items_key, [])
            if not isinstance(items, list):
                logger.warning(f"Expected list in '{items_key}', got {type(items)}. " f"Treating as empty list.")
                items = []

            # Yield each item
            for item in items:
                yield item

            # Check for next cursor
            # The API may return nextCursor, scrollCursor, or nextOffset
            next_cursor = response.get(cursor_key)

            # If no cursor, we've reached the end
            if not next_cursor or len(next_cursor) == 0:
                logger.debug(
                    f"Pagination complete. Processed {page_count + 1} page(s). "
                    f"Total items: {len(items) if page_count == 0 else 'unknown'}"
                )
                break

            # Update cursor for next iteration
            cursor = next_cursor
            page_count += 1

            # Remove cursor from params dict (it will be added back next iteration)
            # This ensures we don't accumulate cursor values
            query_params.pop(cursor_param, None)

            # If we got fewer items than the limit, we're probably at the end
            # (though this is not guaranteed - the API might return partial pages)
            if limit and len(items) < limit:
                logger.debug(
                    f"Received fewer items than limit ({len(items)} < {limit}). " f"Assuming end of pagination."
                )
                break
        logger.trace("Breaking out of pagination loop...")

    def close(self) -> None:
        """
        Close the HTTP session and clean up resources.

        This method should be called when you're done with the API client
        to properly close the underlying HTTP session and release resources.
        """
        self.session.close()
        logger.debug("Zero Networks API client session closed")

    def __enter__(self) -> "ZeroNetworksAPI":
        """
        Context manager entry - allows usage with 'with' statement.

        Example:
            .. code-block:: python

                with ZeroNetworksAPI(api_key="key") as api:
                    data = api.get("/activities/logon")
        """
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """
        Context manager exit - automatically closes the session.
        """
        self.close()
