from typing import Optional, Any, Callable
from loguru import logger
from src.zero_networks.api import ZeroNetworksAPI
import json
from datetime import datetime, timezone


# ============================================================================
# Custom Exception Classes
# ============================================================================

class ZeroThreatHuntError(Exception):
    """
    Base exception class for all Zero Threat Hunt errors.
    
    This exception is raised when an error occurs during threat hunting operations.
    It provides a base class for more specific threat hunting exceptions.
    
    :param message: Human-readable error message describing what went wrong
    :type message: str
    :param details: Optional additional details about the error (e.g., invalid values, context)
    :type details: Optional[dict[str, Any]]
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[dict[str, Any]] = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details
    
    def __str__(self) -> str:
        """Return a formatted string representation of the error."""
        base_msg = f"Zero Threat Hunt Error: {self.message}"
        if self.details:
            return f"{base_msg}\nDetails: {json.dumps(self.details, indent=2)}"
        return base_msg


class ZeroThreatHuntInvalidValues(ZeroThreatHuntError):
    """
    Exception raised when invalid values are provided to threat hunting operations.
    
    This exception is raised when input values don't meet the expected format,
    type, or validation requirements for threat hunting methods.
    
    :param message: Human-readable error message describing the validation failure
    :type message: str
    :param invalid_values: Optional dictionary containing the invalid values and their context
    :type invalid_values: Optional[dict[str, Any]]
    :param expected_format: Optional description of the expected format or values
    :type expected_format: Optional[str]
    
    Example:
        .. code-block:: python
        
            raise ZeroThreatHuntInvalidValues(
                "Empty domains list provided",
                invalid_values={"domains": []},
                expected_format="Non-empty list of domain strings"
            )
    """
    
    def __init__(
        self,
        message: str,
        invalid_values: Optional[dict[str, Any]] = None,
        expected_format: Optional[str] = None
    ) -> None:
        details = {}
        if invalid_values:
            details["invalid_values"] = invalid_values
        if expected_format:
            details["expected_format"] = expected_format
        
        super().__init__(message, details if details else None)
        self.invalid_values = invalid_values
        self.expected_format = expected_format


class ZeroThreatHuntTools:
    """
    Class for performing threat hunting operations on Zero Networks activities.
    
    This class provides a high-level interface for querying and analyzing network
    activities in Zero Networks to identify potential security threats. It coordinates
    between the Zero Networks API client and provides convenient methods for common
    threat hunting queries such as searching for activities to specific domains,
    ports, or processes.
    
    The class automatically handles API authentication, filter management, pagination,
    and parameter conversion to simplify threat hunting workflows.
    
    Example:
        .. code-block:: python
        
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
    """

    def __init__(self, api_key: str, zn_base_url: Optional[str] = None):
        """
        Initialize the ZeroThreatHuntTools class.
        
        Sets up the Zero Networks API client and fetches available network activity
        filters from the API. These filters define the queryable fields and values
        that can be used to search network activities.
        
        :param api_key: Zero Networks API key for authentication (JWT token)
        :type api_key: str
        :param zn_base_url: Optional base URL for the Zero Networks API. If not provided,
                          will be extracted from the JWT API key if possible.
        :type zn_base_url: Optional[str]
        :raises ValueError: If network filters cannot be retrieved from the API
        :raises ZeroNetworksAPIError: If the API client initialization fails
        """
        logger.info("Initializing ZN Threat Hunting Tools...")

        # Initialize the Zero Networks API client
        # The API client will attempt to extract the base URL from the JWT if not provided
        self.api = ZeroNetworksAPI(api_key, zn_base_url)

        # Fetch and cache network activity filters from the API
        # These filters define what fields can be queried and their possible values
        self.network_filters: list[dict[str, Any]] = self._get_network_filters()
        logger.info(
            f"Loaded {len(self.network_filters)} network filters into ZN Hunt Ops..."
        )

        logger.info("ZN Hunt Ops initialized successfully...")



    @staticmethod
    def datetime_to_timestamp_ms(dt: datetime) -> int:
        """
        Convert a datetime object to milliseconds since epoch.
        
        This utility method converts a Python datetime object to Unix timestamp
        in milliseconds, which is the format required by the Zero Networks API
        for time-based queries.
        
        :param dt: Datetime object to convert
        :type dt: datetime
        :return: Milliseconds since epoch (Unix timestamp in milliseconds)
        :rtype: int
        
        Example:
            .. code-block:: python
            
                from datetime import datetime
                dt = datetime(2024, 1, 1, 12, 0, 0)
                timestamp = ZeroThreatHuntTools.datetime_to_timestamp_ms(dt)
                # Returns: 1704110400000
        """
        logger.trace(f"Converting datetime {dt} to milliseconds since epoch")
        timestamp_ms = int(dt.timestamp() * 1000)
        logger.trace(f"Converted to timestamp: {timestamp_ms}")
        return timestamp_ms

    @staticmethod
    def _filter_object_builder(
        field_name: str,
        include_values: list[str] | str | int = [],
        exclude_values: list[str] | str | int = [],
    ) -> dict[str, list[Any]]:
        """
        Build a filter object for a single field to be used in API queries.
        
        This method creates a filter object that can be used to filter network activities
        by a specific field. The filter object follows the Zero Networks API filter format
        and can include values to match (include) or exclude.
        
        :param field_name: Name of the field to filter on (e.g., "dstAsset", "srcProcessPath")
        :type field_name: str
        :param include_values: Values to include in the filter. Can be a single value or a list.
                              If a single value is provided, it will be converted to a list.
        :type include_values: list[str] | str | int
        :param exclude_values: Values to exclude from the filter. Can be a single value or a list.
                              If a single value is provided, it will be converted to a list.
        :type exclude_values: list[str] | str | int
        :return: Filter object dictionary with "id", "includeValues", and "excludeValues" keys
        :rtype: dict[str, Any]
        :raises ValueError: If both include_values and exclude_values are empty
        
        Example:
            .. code-block:: python
            
                # Filter for specific domains
                filter_obj = ZeroThreatHuntTools._filter_object_builder(
                    field_name="dstAsset",
                    include_values=["example.com", "test.com"]
                )
                # Returns: {"id": "dstAsset", "includeValues": ["example.com", "test.com"], "excludeValues": []}
        """
        logger.trace(f"Building filter object for field: {field_name}")
        
        # Normalize include_values to a list if it's a single value
        # This allows the method to accept both single values and lists for convenience
        if not isinstance(include_values, list):
            logger.trace(f"Converting include_values from {type(include_values)} to list")
            include_values = [include_values]
        
        # Normalize exclude_values to a list if it's a single value
        if not isinstance(exclude_values, list):
            logger.trace(f"Converting exclude_values from {type(exclude_values)} to list")
            exclude_values = [exclude_values]

        # Validate that at least one filter criteria is provided
        # A filter must have either include or exclude values to be meaningful
        if len(include_values) <= 0 and len(exclude_values) <= 0:
            logger.error("Attempted to create filter with empty include and exclude values")
            raise ValueError("Both include_values and exclude_values cannot be empty!")

        # Build and return the filter object in the format expected by the Zero Networks API
        filter_obj = {
            "id": field_name,
            "includeValues": include_values,
            "excludeValues": exclude_values,
        }
        
        logger.debug(
            f"Created filter object for {field_name}: "
            f"{len(include_values)} include values, {len(exclude_values)} exclude values"
        )
        
        return filter_obj

    @staticmethod
    def _filter_json_builder(*args: list[dict[str, Any]]) -> str:
        """
        Convert filter objects to a JSON string for API requests.
        
        This method takes one or more filter objects and converts them to a compact
        JSON string that can be passed to the Zero Networks API as the "_filters"
        query parameter. The JSON is compact (no indentation) to minimize request size.
        
        :param *args: Variable number of filter dictionaries to combine into a JSON array
        :type *args: list[dict[str, Any]]
        :return: JSON string representation of the filter objects
        :rtype: str
        
        Example:
            .. code-block:: python
            
                filter1 = {"id": "dstAsset", "includeValues": ["example.com"]}
                filter2 = {"id": "dstPort", "includeValues": [443]}
                json_str = ZeroThreatHuntTools._filter_json_builder(filter1, filter2)
                # Returns: '[{"id":"dstAsset","includeValues":["example.com"]},{"id":"dstPort","includeValues":[443]}]'
        """
        logger.trace(f"Converting {len(args)} filter object(s) to JSON string")
        json_str = json.dumps(args, indent=None, separators=(",", ":"))
        logger.trace(f"Generated JSON filter string (length: {len(json_str)} characters)")
        return json_str

    @staticmethod
    def _transform_network_filters_to_dict(
        network_filters: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Transform the network filters list into a dictionary keyed by filter ID.
        
        This method converts a list of network filter objects into a dictionary
        where each filter is accessible by its ID. Additionally, if a filter has
        selections, it creates lookup dictionaries for selections by name and by ID
        to enable efficient filtering operations.
        
        :param network_filters: List of filter dictionaries from the API
        :type network_filters: list[dict[str, Any]]
        :return: Dictionary of network filters keyed by filter ID, with additional
                 selectionsByName and selectionsById dictionaries for filters with selections
        :rtype: dict[str, Any]
        
        Example:
            .. code-block:: python
            
                filters_list = [
                    {"id": "dstAsset", "selections": [{"id": "sel1", "name": "Selection 1"}]},
                    {"id": "dstPort", "selections": []}
                ]
                filters_dict = ZeroThreatHuntTools._transform_network_filters_to_dict(filters_list)
                # Returns: {
                #     "dstAsset": {
                #         "id": "dstAsset",
                #         "selections": [...],
                #         "selectionsByName": {"Selection 1": "sel1"},
                #         "selectionsById": {"sel1": "Selection 1"}
                #     },
                #     "dstPort": {"id": "dstPort", "selections": []}
                # }
        """
        logger.trace(f"Transforming {len(network_filters)} network filters to dictionary")
        
        # Create new dictionary to store the transformed network filters
        # This allows O(1) lookup by filter ID instead of O(n) list search
        network_filters_dict: dict[str, Any] = {}

        # Iterate through the network filters and transform each one
        for filter in network_filters:
            # Skip if the filter already exists in the dictionary (duplicate ID)
            # This prevents overwriting filters with the same ID
            if network_filters_dict.get(filter["id"]):
                logger.debug(f"Skipping duplicate filter ID: {filter['id']}")
                continue

            # Make shallow copy of the filter to avoid modifying the original
            filter_obj: dict[str, Any] = filter.copy()

            # If the filter has selections, create lookup dictionaries for efficient access
            # selectionsByName: maps selection name -> selection ID
            # selectionsById: maps selection ID -> selection name
            # This enables bidirectional lookup when building filter queries
            if filter_obj.get("selections", None):
                logger.trace(
                    f"Creating selection lookup dictionaries for filter {filter_obj['id']} "
                    f"with {len(filter_obj['selections'])} selections"
                )
                filter_obj["selectionsByName"] = {
                    selection["name"]: selection["id"]
                    for selection in filter_obj["selections"]
                }
                filter_obj["selectionsById"] = {
                    selection["id"]: selection["name"]
                    for selection in filter_obj["selections"]
                }

            # Add the transformed filter to the dictionary, keyed by its ID
            network_filters_dict[filter_obj["id"]] = filter_obj

        logger.debug(f"Transformed {len(network_filters_dict)} unique filters to dictionary")
        return network_filters_dict

    @staticmethod
    def _parse_iso8601_to_timestamp_ms(iso8601_str: str) -> int:
        """
        Parse an ISO8601 timestamp string and convert it to milliseconds since epoch.
        
        This method parses ISO8601 timestamp strings with support for:
        - Timezone offset (e.g., "2024-01-01T12:00:00+05:00")
        - UTC timezone indicator "Z" (e.g., "2024-01-01T12:00:00Z")
        - No timezone (defaults to UTC, e.g., "2024-01-01T12:00:00")
        
        :param iso8601_str: ISO8601 formatted timestamp string
        :type iso8601_str: str
        :return: Milliseconds since epoch (Unix timestamp in milliseconds)
        :rtype: int
        :raises ValueError: If the ISO8601 string cannot be parsed
        
        Example:
            .. code-block:: python
            
                # With timezone offset
                timestamp = ZeroThreatHuntTools._parse_iso8601_to_timestamp_ms("2024-01-01T12:00:00+05:00")
                
                # With UTC indicator
                timestamp = ZeroThreatHuntTools._parse_iso8601_to_timestamp_ms("2024-01-01T12:00:00Z")
                
                # Without timezone (defaults to UTC)
                timestamp = ZeroThreatHuntTools._parse_iso8601_to_timestamp_ms("2024-01-01T12:00:00")
        """
        logger.trace(f"Parsing ISO8601 timestamp: {iso8601_str}")
        
        # Preserve original string for error messages
        original_str = iso8601_str
        
        try:
            # Replace 'Z' with '+00:00' for UTC timezone indicator
            # This makes it compatible with fromisoformat()
            if iso8601_str.endswith('Z'):
                iso8601_str = iso8601_str[:-1] + '+00:00'
            
            # Parse the ISO8601 string
            dt = datetime.fromisoformat(iso8601_str)
            
            # If the datetime is naive (no timezone), assume UTC
            if dt.tzinfo is None:
                logger.trace("No timezone in ISO8601 string, defaulting to UTC")
                dt = dt.replace(tzinfo=timezone.utc)
            
            # Convert to UTC if it has a timezone
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc)
            
            # Convert to milliseconds timestamp
            timestamp_ms = ZeroThreatHuntTools.datetime_to_timestamp_ms(dt)
            logger.trace(f"Converted ISO8601 '{original_str}' to timestamp: {timestamp_ms}")
            return timestamp_ms
            
        except ValueError as e:
            logger.error(f"Failed to parse ISO8601 timestamp '{original_str}': {e}")
            raise ValueError(
                f"Invalid ISO8601 timestamp format: {original_str}. "
                f"Expected ISO8601 format (e.g., '2024-01-01T12:00:00Z', '2024-01-01T12:00:00+05:00', '2024-01-01T12:00:00')"
            ) from e

    @staticmethod
    def _parse_kwargs_for_params(kwargs: dict[str, Any]) -> dict[str, Any]:
        """
        Parse keyword arguments and convert them to API query parameters.
        
        This method takes keyword arguments and converts them into the format
        expected by the Zero Networks API. It handles datetime conversion,
        parameter name mapping, and provides sensible defaults.
        
        :param kwargs: Dictionary of keyword arguments to parse. Supported keys:
                      - from_timestamp: Start datetime ISO8601 timestamp string
                                       (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - to_timestamp: End datetime ISO8601 timestamp string
                                     (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - _search: Search string for text-based filtering
                      - _entityId: Entity ID to filter by
                      - limit: Maximum number of results per page (overrides default 100)
                      - order: Sort order ("asc" or "desc", defaults to "desc")
        :type kwargs: dict[str, Any]
        :return: Dictionary of API query parameters ready for use in API requests
        :rtype: dict[str, Any]
        :raises ValueError: If ISO8601 timestamp strings cannot be parsed
        
        Example:
            .. code-block:: python
            
                kwargs = {
                    "from_timestamp": "2024-01-01T00:00:00Z",
                    "limit": 50,
                    "_search": "example.com"
                }
                params = ZeroThreatHuntTools._parse_kwargs_for_params(kwargs)
                # Returns: {
                #     "order": "desc",
                #     "_limit": 50,
                #     "from": 1704067200000,
                #     "_search": "example.com"
                # }
        """
        logger.trace(f"Parsing {len(kwargs)} keyword arguments into API parameters")
        
        # Initialize default parameters
        # These defaults ensure the API call has sensible values even if no kwargs provided
        params: dict[str, Any] = {
            "order": "desc",  # Default to descending order (newest first)
            "_limit": 100,     # Default page size
        }
        
        # Parse and convert from_timestamp if provided
        # The ISO8601 timestamp string is converted to milliseconds since epoch for the API
        if kwargs.get("from_timestamp"):
            from_timestamp_str = kwargs.get("from_timestamp")
            logger.trace(f"Parsing from_timestamp: {from_timestamp_str}")
            try:
                params["from"] = ZeroThreatHuntTools._parse_iso8601_to_timestamp_ms(from_timestamp_str)
                logger.debug(f"Set 'from' parameter to timestamp: {params['from']}")
            except ValueError as e:
                logger.error(f"Failed to parse from_timestamp '{from_timestamp_str}': {e}")
                raise
        
        # Parse and convert to_timestamp if provided
        if kwargs.get("to_timestamp"):
            to_timestamp_str = kwargs.get("to_timestamp")
            logger.trace(f"Parsing to_timestamp: {to_timestamp_str}")
            try:
                params["to"] = ZeroThreatHuntTools._parse_iso8601_to_timestamp_ms(to_timestamp_str)
                logger.debug(f"Set 'to' parameter to timestamp: {params['to']}")
            except ValueError as e:
                logger.error(f"Failed to parse to_timestamp '{to_timestamp_str}': {e}")
                raise
        
        # Add search parameter if provided
        if kwargs.get("_search"):
            params["_search"] = kwargs.get("_search")
            logger.debug(f"Added search parameter: {params['_search']}")
        
        # Add entity ID filter if provided
        if kwargs.get("_entityId"):
            params["_entityId"] = kwargs.get("_entityId")
            logger.debug(f"Added entity ID filter: {params['_entityId']}")
        
        # Override default limit if provided
        if kwargs.get("limit"):
            params["_limit"] = kwargs.get("limit")
            logger.debug(f"Set limit to: {params['_limit']}")
        
        # Override default order if provided
        if kwargs.get("order"):
            params["order"] = kwargs.get("order")
            logger.debug(f"Set order to: {params['order']}")
        
        logger.trace(f"Parsed parameters: {list(params.keys())}")
        return params

    def _get_network_filters(self) -> list[dict[str, Any]]:
        """
        Retrieve available network activity filters from the Zero Networks API.

        This method queries the Zero Networks API to get the list of available filters
        that can be used when querying network activities. Filters define the queryable
        fields (such as source IP, destination IP, ports, protocols, etc.) and their
        possible values that can be used to search and filter network activity data.

        The filters are cached in the instance attribute `network_filters` during
        initialization for use in subsequent hunt operations.

        :return: List of filter dictionaries, each containing filter definitions with
                 field names, types, and possible values
        :rtype: list[dict[str, Any]]
        :raises ValueError: If the API response contains no filters or the request fails
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)

        Example:
            .. code-block:: python

                filters = hunter.get_network_filters()
                # filters might contain entries like:
                # [
                #     {"field": "srcIp", "type": "string", "values": [...]},
                #     {"field": "dstPort", "type": "integer", "values": [...]},
                #     ...
                # ]
        """
        logger.debug("Getting network filters from Zero Networks API...")

        # Make API request to get network activity filters
        # The API returns a JSON object with a "filters" key containing the filter list
        filters_object: dict[str, Any] = self.api.get("/activities/network/filters")

        # Extract the filters list from the response
        # Default to empty list if "filters" key is missing
        filters_list: list[dict[str, Any]] = filters_object.get("filters", [])

        # Validate that filters were returned
        # An empty filter list indicates the API might be misconfigured or unavailable
        if len(filters_list) == 0:
            logger.error("No network filters found...")
            raise ValueError("No network filters found...")
        logger.debug(f"Loaded {len(filters_list)} network filters...")

        return ZeroThreatHuntTools._transform_network_filters_to_dict(filters_list)

    def _parse_kwargs_for_network_filters(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        _filters: dict[str,Any] = {}
        for key,value in kwargs.items():
            if key in self.network_filters.keys():
                logger.trace(f"Found additional network filter {key} in kwargs.")
                _filters.update({key:value})
        return _filters
        

    def _get_activities(
        self, params: dict[str, Any], _limit: int = 100
    ) -> list[dict[str, Any]]:
        """
        Retrieve network activities from Zero Networks API with pagination support.
        
        This method queries the Zero Networks API for network activities using the provided
        filter parameters. It automatically handles cursor-based pagination to retrieve all
        matching activities across multiple API pages. The method collects all activities
        into a list before returning.
        
        :param params: Query parameters for filtering network activities. Common parameters
                      include:
                      - "from": Start time in epoch milliseconds
                      - "to": End time in epoch milliseconds
                      - "_search": Search string for text-based filtering
                      - "_filters": JSON-encoded filter object for advanced filtering
                      - "_entityId": Filter by entity ID (user, group, or asset)
        :type params: dict[str, Any]
        :param _limit: Maximum number of activities to retrieve per API page. This controls
                      the page size for pagination, not the total number of results.
                      Defaults to 100.
        :type _limit: int
        :return: List of all activity dictionaries retrieved from all pages
        :rtype: list[dict[str, Any]]
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)
        
        Example:
            .. code-block:: python
            
                params = {
                    "from": 1647308838000,
                    "_entityId": "u:a:12345678"
                }
                activities = hunter._get_activities(params, _limit=100)
        """
        logger.debug(f"Retrieving network activities with parameters: {list(params.keys())}")
        logger.trace(f"Activity query parameters: {params}")
        
        activities: list[dict[str, Any]] = []
        activity_count = 0
        
        # Iterate through paginated results from the API
        # The iter_paginated method automatically handles cursor-based pagination,
        # making multiple API requests as needed to retrieve all matching activities
        for activity in self.api.iter_paginated(
            "/activities/network", limit=_limit, params=params
        ):
            activities.append(activity)
            activity_count += 1
        
        logger.info(f"Retrieved {activity_count} network activities")
        logger.debug(f"Returning {len(activities)} activities")
        return activities


    def _get_activities_by_filter(
        self,
        field_name: str,
        values: list[Any],
        value_name: str,
        filter_description: str,
        expected_format: str,
        validate_value: Optional[Callable[[Any, str], None]] = None,
        **kwargs: Any
    ) -> list[dict[str, Any]]:
        """
        Generalized method to retrieve network activities filtered by a specific field.
        
        This private method handles the common logic for querying activities by a specific
        filter field. It validates input, builds filter objects, makes API calls, and
        returns results. This reduces code duplication across the various get_activities_*
        methods.
        
        :param field_name: The API field name to filter on (e.g., "dstAsset", "srcProcessPath")
        :type field_name: str
        :param values: List of values to filter by. Type depends on the field (strings, integers, etc.)
        :type values: list[Any]
        :param value_name: Name of the value type for error messages (e.g., "domains", "ports")
        :type value_name: str
        :param filter_description: Description of the filter for logging (e.g., "domain", "source process path")
        :type filter_description: str
        :type expected_format: str
        :param validate_value: Optional callable that validates individual values.
                              Should raise ZeroThreatHuntInvalidValues if invalid.
                              Signature: (value: Any, value_name: str) -> None
        :type validate_value: Optional[callable]
        :param kwargs: Optional keyword arguments for additional filtering (passed to _parse_kwargs_for_params)
        :type kwargs: Any
        :return: List of activity dictionaries matching the filter
        :rtype: list[dict[str, Any]]
        :raises ZeroThreatHuntInvalidValues: If values list is empty or contains invalid values
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)
        :raises ValueError: If datetime strings in kwargs cannot be parsed
        """
        logger.info(f"Retrieving activities by {filter_description} filter: {len(values)} {value_name}")
        logger.debug(f"{value_name.capitalize()}: {values}")
        
        # Build query parameters dynamically based on kwargs
        # Default parameters (order: desc, _limit: 100) are returned if no kwargs provided
        params: dict[str, Any] = ZeroThreatHuntTools._parse_kwargs_for_params(kwargs)

        # Check kwargs for any additional filter fields provided
        additional_filters: dict[str,Any] = self._parse_kwargs_for_network_filters(kwargs=kwargs)

        # Validate that values list is not empty
        # An empty list would result in no meaningful filter
        if len(values) == 0:
            logger.error(f"The list of values provided for {filter_description} was empty!")
            raise ZeroThreatHuntInvalidValues(
                f"The list of values provided for {filter_description} was empty!",
                invalid_values={value_name: values},
                expected_format=expected_format
            )

        # Validate individual values if a validation function is provided
        # This allows custom validation logic for different value types (e.g., port range checking)
        if validate_value:
            for value in values:
                validate_value(value, value_name)

        logger.trace(f"Building filter object for {field_name} field with {len(values)} value(s)")
        
        # Create empty list that will hold filters - you will see why
        filters: list[dict[str,dict]] = []

        # Build filter object for the specified field
        # This filter will match activities where the field value is one of the provided values
        field_filter: dict[str, list[Any]] = ZeroThreatHuntTools._filter_object_builder(
            field_name=field_name,
            include_values=values
        )
        # Append the original filter to list of filters
        filters.append(field_filter)

        # If additional filters were passed, create filter objects those as well
        # And add them to filters list
        if additional_filters and len(additional_filters) > 0:
            for field_name,field_values in additional_filters.items():
                filters.append(
                    ZeroThreatHuntTools._filter_object_builder(
                        field_name=field_name,
                        include_values=field_values
                    )
                )
        
        # Convert list of filter objects to json string, which is what API expects
        # Doing *fitlers will UNPACK the list into separate NON-keyword args.
        # This is what _filter_json_builder expects, and it itself uses the args 
        # as a list
        _filters_for_api_call: str = ZeroThreatHuntTools._filter_json_builder(*filters)
        logger.trace("Generated filter JSON string to attach to API parameters.")
        
        # Add the filter to the query parameters
        # This will be sent to the API as the _filters query parameter
        params.update({"_filters": _filters_for_api_call})
        logger.debug("Added _filters parameter to query")

        # Make API call to retrieve activities matching the filter
        # This will automatically handle pagination and return all matching activities
        logger.debug("Initiating API call to retrieve activities")
        activities: list[dict[str, Any]] = self._get_activities(params=params)

        logger.info(f"Retrieved {len(activities)} activities matching {filter_description} filter")
        return activities


    def get_activities_to_domains(self, domains: list[str], **kwargs: Any) -> list[dict[str, Any]]:
        """
        Retrieve network activities that connect to the specified domains.
        
        This method queries the Zero Networks API for network activities where the
        destination asset matches any of the provided domains. It automatically handles
        pagination to retrieve all matching activities.
        
        :param domains: List of domain strings to search for in destination assets.
                       Each domain must be a string. Empty list will raise an exception.
        :type domains: list[str]
        :param kwargs: Optional keyword arguments for additional filtering:
                      - from_timestamp: Start datetime ISO8601 timestamp string
                                       (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - to_timestamp: End datetime ISO8601 timestamp string
                                     (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - _search: Search string for text-based filtering
                      - _entityId: Entity ID to filter by
                      - limit: Maximum number of results per page (default: 100)
                      - order: Sort order ("asc" or "desc", default: "desc")
        :type kwargs: Any
        :return: List of activity dictionaries where destination asset matches any provided domain
        :rtype: list[dict[str, Any]]
        :raises ZeroThreatHuntInvalidValues: If domains list is empty or contains non-string values
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)
        :raises ValueError: If datetime strings in kwargs cannot be parsed
        
        Example:
            .. code-block:: python
            
                # Search for activities to specific domains
                domains = ["example.com", "test.com"]
                activities = hunter.get_activities_to_domains(
                    domains,
                    from_timestamp="2024-01-01T00:00:00Z",
                    limit=50
                )
        """
        # Validation function for domain strings
        def validate_domain(domain: Any) -> None:
            """Validate that a domain is a string."""
            if not isinstance(domain, str):
                logger.error(f"Invalid domain type provided: {type(domain)} (value: {domain})")
                raise ZeroThreatHuntInvalidValues(
                    "Invalid domain provided",
                    invalid_values={"domain": domain, "domain_type": str(type(domain))},
                    expected_format="String domain"
                )
        
        return self._get_activities_by_filter(
            field_name="dstAsset",
            values=domains,
            filter_description="domain",
            expected_format="Non-empty list of domain strings",
            validate_value=validate_domain,
            **kwargs
        )

    
    def get_activities_from_source_processes(self, process_paths: list[str], **kwargs: Any) -> list[dict[str, Any]]:
        """
        Retrieve network activities that originate from the specified source processes.
        
        This method queries the Zero Networks API for network activities where the
        source process path matches any of the provided process paths. It automatically
        handles pagination to retrieve all matching activities.
        
        This is useful for threat hunting scenarios where you want to identify network
        traffic originating from specific processes, such as RMM software executables
        or suspicious processes.
        
        :param process_paths: List of process path strings to search for in source processes.
                             Each process path must be a string (e.g., "/usr/bin/teamviewer",
                             "C:\\Program Files\\TeamViewer\\TeamViewer.exe"). Empty list will raise an exception.
        :type process_paths: list[str]
        :param kwargs: Optional keyword arguments for additional filtering:
                      - from_timestamp: Start datetime ISO8601 timestamp string
                                       (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - to_timestamp: End datetime ISO8601 timestamp string
                                     (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - _search: Search string for text-based filtering
                      - _entityId: Entity ID to filter by
                      - limit: Maximum number of results per page (default: 100)
                      - order: Sort order ("asc" or "desc", default: "desc")
        :type kwargs: Any
        :return: List of activity dictionaries where source process path matches any provided process path
        :rtype: list[dict[str, Any]]
        :raises ZeroThreatHuntInvalidValues: If process_paths list is empty or contains non-string values
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)
        :raises ValueError: If datetime strings in kwargs cannot be parsed
        
        Example:
            .. code-block:: python
            
                # Search for activities from specific processes
                process_paths = [
                    "/usr/bin/teamviewer",
                    "C:\\Program Files\\TeamViewer\\TeamViewer.exe"
                ]
                activities = hunter.get_activities_from_source_processes(
                    process_paths,
                    from_timestamp="2024-01-01T00:00:00Z",
                    limit=50
                )
        """
        # Validation function for process path strings
        def validate_process_path(process_path: Any) -> None:
            """Validate that a process path is a string."""
            if not isinstance(process_path, str):
                logger.error(f"Invalid process path type provided: {type(process_path)} (value: {process_path})")
                raise ZeroThreatHuntInvalidValues(
                    "Invalid process path provided",
                    invalid_values={"process_path": process_path, "process_path_type": str(type(process_path))},
                    expected_format="String process path"
                )
        
        return self._get_activities_by_filter(
            field_name="srcProcessPath",
            values=process_paths,
            filter_description="source process path",
            expected_format="Non-empty list of process path strings",
            validate_value=validate_process_path,
            **kwargs
        )

    
    def get_activities_to_destination_processes(self, process_paths: list[str], **kwargs: Any) -> list[dict[str, Any]]:
        """
        Retrieve network activities that connect to the specified destination processes.
        
        This method queries the Zero Networks API for network activities where the
        destination process path matches any of the provided process paths. It automatically
        handles pagination to retrieve all matching activities.
        
        This is useful for threat hunting scenarios where you want to identify network
        traffic terminating at specific processes, such as RMM software executables
        or suspicious processes.
        
        :param process_paths: List of process path strings to search for in destination processes.
                             Each process path must be a string (e.g., "/usr/bin/teamviewer",
                             "C:\\Program Files\\TeamViewer\\TeamViewer.exe"). Empty list will raise an exception.
        :type process_paths: list[str]
        :param kwargs: Optional keyword arguments for additional filtering:
                      - from_timestamp: Start datetime ISO8601 timestamp string
                                       (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - to_timestamp: End datetime ISO8601 timestamp string
                                     (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - _search: Search string for text-based filtering
                      - _entityId: Entity ID to filter by
                      - limit: Maximum number of results per page (default: 100)
                      - order: Sort order ("asc" or "desc", default: "desc")
        :type kwargs: Any
        :return: List of activity dictionaries where destination process path matches any provided process path
        :rtype: list[dict[str, Any]]
        :raises ZeroThreatHuntInvalidValues: If process_paths list is empty or contains non-string values
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)
        :raises ValueError: If datetime strings in kwargs cannot be parsed
        
        Example:
            .. code-block:: python
            
                # Search for activities to specific destination processes
                process_paths = [
                    "/usr/bin/teamviewer",
                    "C:\\Program Files\\TeamViewer\\TeamViewer.exe"
                ]
                activities = hunter.get_activities_to_destination_processes(
                    process_paths,
                    from_timestamp="2024-01-01T00:00:00Z",
                    limit=50
                )
        """
        # Validation function for process path strings
        def validate_process_path(process_path: Any) -> None:
            """Validate that a process path is a string."""
            if not isinstance(process_path, str):
                logger.error(f"Invalid process path type provided: {type(process_path)} (value: {process_path})")
                raise ZeroThreatHuntInvalidValues(
                    "Invalid process path provided",
                    invalid_values={"process_path": process_path, "process_path_type": str(type(process_path))},
                    expected_format="String process path"
                )
        
        return self._get_activities_by_filter(
            field_name="dstProcessPath",
            values=process_paths,
            filter_description="destination process path",
            expected_format="Non-empty list of process path strings",
            validate_value=validate_process_path,
            **kwargs
        )

    
    def get_activities_to_destination_ports(self, ports: list[int], **kwargs: Any) -> list[dict[str, Any]]:
        """
        Retrieve network activities that connect to the specified destination ports.
        
        This method queries the Zero Networks API for network activities where the
        destination port matches any of the provided port numbers. It automatically
        handles pagination to retrieve all matching activities.
        
        This is useful for threat hunting scenarios where you want to identify network
        traffic to specific ports, such as those commonly used by RMM software or
        suspicious services.
        
        :param ports: List of port numbers (integers) to search for in destination ports.
                     Each port must be an integer between 1 and 65535. Empty list will raise an exception.
        :type ports: list[int]
        :param kwargs: Optional keyword arguments for additional filtering:
                      - from_timestamp: Start datetime ISO8601 timestamp string
                                       (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - to_timestamp: End datetime ISO8601 timestamp string
                                     (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - _search: Search string for text-based filtering
                      - _entityId: Entity ID to filter by
                      - limit: Maximum number of results per page (default: 100)
                      - order: Sort order ("asc" or "desc", default: "desc")
        :type kwargs: Any
        :return: List of activity dictionaries where destination port matches any provided port
        :rtype: list[dict[str, Any]]
        :raises ZeroThreatHuntInvalidValues: If ports list is empty or contains invalid port values
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)
        :raises ValueError: If datetime strings in kwargs cannot be parsed
        
        Example:
            .. code-block:: python
            
                # Search for activities to specific ports
                ports = [5938, 443, 80]
                activities = hunter.get_activities_to_destination_ports(
                    ports,
                    from_timestamp="2024-01-01T00:00:00Z",
                    limit=50
                )
        """
        # Validation function for port integers
        def validate_port(port: Any) -> None:
            """Validate that a port is an integer within valid range (1-65535)."""
            if not isinstance(port, int):
                logger.error(f"Invalid port type provided: {type(port)} (value: {port})")
                raise ZeroThreatHuntInvalidValues(
                    "Invalid port provided",
                    invalid_values={"port": port, "port_type": str(type(port))},
                    expected_format="Integer port number (1-65535)"
                )
            if port < 1 or port > 65535:
                logger.error(f"Port out of valid range: {port}")
                raise ZeroThreatHuntInvalidValues(
                    "Port out of valid range",
                    invalid_values={"port": port},
                    expected_format="Integer port number between 1 and 65535"
                )
        
        return self._get_activities_by_filter(
            field_name="dstPort",
            values=ports,
            filter_description="destination port",
            expected_format="Non-empty list of port integers (1-65535)",
            validate_value=validate_port,
            **kwargs
        )

    
    def get_activities_to_destination_ips(self, ip_addresses: list[str], **kwargs: Any) -> list[dict[str, Any]]:
        """
        Retrieve network activities that connect to the specified destination IP addresses.
        
        This method queries the Zero Networks API for network activities where the
        destination IP address matches any of the provided IP addresses. It automatically
        handles pagination to retrieve all matching activities.
        
        This is useful for threat hunting scenarios where you want to identify network
        traffic to specific IP addresses, such as those associated with RMM software
        command and control servers or suspicious endpoints.
        
        :param ip_addresses: List of IP address strings to search for in destination IPs.
                            Each IP must be a string in IPv4 format (e.g., "192.168.1.1").
                            Empty list will raise an exception.
        :type ip_addresses: list[str]
        :param kwargs: Optional keyword arguments for additional filtering:
                      - from_timestamp: Start datetime ISO8601 timestamp string
                                       (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - to_timestamp: End datetime ISO8601 timestamp string
                                     (e.g., "2024-01-01T12:00:00Z", "2024-01-01T12:00:00+05:00", "2024-01-01T12:00:00")
                      - _search: Search string for text-based filtering
                      - _entityId: Entity ID to filter by
                      - limit: Maximum number of results per page (default: 100)
                      - order: Sort order ("asc" or "desc", default: "desc")
        :type kwargs: Any
        :return: List of activity dictionaries where destination IP address matches any provided IP
        :rtype: list[dict[str, Any]]
        :raises ZeroThreatHuntInvalidValues: If ip_addresses list is empty or contains invalid IP addresses
        :raises ZeroNetworksAPIError: If the API request fails (handled by the API client)
        :raises ValueError: If datetime strings in kwargs cannot be parsed
        
        Example:
            .. code-block:: python
            
                # Search for activities to specific IP addresses
                ip_addresses = ["192.168.1.100", "10.0.0.50"]
                activities = hunter.get_activities_to_destination_ips(
                    ip_addresses,
                    from_timestamp="2024-01-01T00:00:00Z",
                    limit=50
                )
        """
        # Validation function for IP address strings
        def validate_ip_address(ip_address: Any) -> None:
            """Validate that an IP address is a string."""
            if not isinstance(ip_address, str):
                logger.error(f"Invalid IP address type provided: {type(ip_address)} (value: {ip_address})")
                raise ZeroThreatHuntInvalidValues(
                    "Invalid IP address provided",
                    invalid_values={"ip_address": ip_address, "ip_address_type": str(type(ip_address))},
                    expected_format="String IP address"
                )
        
        return self._get_activities_by_filter(
            field_name="dstIpAddress",
            values=ip_addresses,
            filter_description="destination IP address",
            expected_format="Non-empty list of IP address strings",
            validate_value=validate_ip_address,
            **kwargs
        )
