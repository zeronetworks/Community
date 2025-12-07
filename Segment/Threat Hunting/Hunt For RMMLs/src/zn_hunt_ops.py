# pyright: reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
# pylint: disable=no-name-in-module

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Optional

from loguru import logger
import pandas as pd

from src.rmmdata import RMMData
from src.zero_threat_hunt_tools.zero_threat_hunt_tools import ZeroThreatHuntTools
from src.zero_networks.api import ZeroNetworksNotFoundError


# This is needed as some of the attribute keys returned by the API
# do not match their respective attribute names returned from the
# /activities/network/filters endpoint.
INCONSISTENT_FIELD_NAME_MAP: dict[str, str] = {
    "protocol": "protocolType",
    "networkProtectionState": "srcAssetProtectionState",
    "assetType": "srcAssetType",
}


class ZNHuntOps:
    """
    Class for performing threat hunting operations on Zero Networks activities from downloaded RMM data.

    This class orchestrates threat hunting workflows by coordinating between the Zero Networks
    API client and RMM (Remote Management and Monitoring) data to search for indicators of
    potentially malicious or unauthorized RMM software usage in network activities.

    The class loads network activity filters from the Zero Networks API and provides methods
    to query and analyze network activities for RMM-related indicators based on domains, processes,
    ports, and other signatures defined in the RMM data.
    """

    max_workers: int = 5  # Maximum number of concurrent workers for hunting operations

    unique_source_assets_seen: dict[str, dict] = {}
    asset_id_to_asset_name_map: dict[str, str] = {}
    all_indicating_activities: list[dict[str, Any]] = []

    ############################################################
    # Initialization
    ############################################################

    def __init__(
        self, api_key: str, rmm_data: RMMData, zn_base_url: Optional[str] = None, **kwargs: Optional[dict[str, Any]]
    ):
        """
        Initialize the ZN Hunt Ops coordinator.

        Sets up the Zero Networks API client, loads RMM data, and fetches available network
        activity filters from the API. These filters define the queryable fields and values
        that can be used to search network activities.

        :param api_key: Zero Networks API key for authentication (JWT token)
        :type api_key: str
        :param rmm_data: RMM data loaded from YAML files containing RMM software signatures
        :type rmm_data: RMMData
        :param zn_base_url: Optional base URL for the Zero Networks API. If not provided,
                          will be extracted from the JWT API key if possible.
        :type zn_base_url: Optional[str]
        :raises ValueError: If network filters cannot be retrieved from the API
        """
        logger.info("Initializing ZN Hunt Ops...")

        if kwargs:
            logger.info(f"Initializing ZN Hunt Ops with kwargs: {kwargs}...")
            if "max_workers" in kwargs:
                try:
                    self.max_workers = int(kwargs.get("max_workers"))
                except ValueError:
                    logger.error(
                        f"Failed to set max_workers to {kwargs.get('max_workers')}."
                        +f"Using default value of {self.max_workers}..."
                    )
        else:
            logger.info("Initializing ZN Hunt Ops without kwargs...")

        self._zero_threat_hunt_tools: ZeroThreatHuntTools = ZeroThreatHuntTools(
            api_key=api_key, zn_base_url=zn_base_url
        )

        self._zero_threat_hunt_tools.network_filters = self._load_additional_filter_mappings_if_exists(
            network_filters=self._zero_threat_hunt_tools.network_filters, path="src/static/addt_filter_mappings.json"
        )

        # Store the RMM data for use in hunting operations
        # This contains domains, processes, ports, and other indicators for RMM software
        self.rmm_data: RMMData = rmm_data
        logger.info(f"Loaded {len(self.rmm_data.rmm_list)} RMMLs into ZN Hunt Ops...")

        logger.info("ZN Hunt Ops initialized successfully...")

    ############################################################
    # File Helper Functions
    ############################################################

    @staticmethod
    def _load_additional_filter_mappings_if_exists(
        network_filters: dict[str, dict[str, Any]], path: str
    ) -> dict[str, Any]:
        """
        Load additional filter mappings from a JSON file if it exists.

        Attempts to load additional network filter mappings from a specified JSON file path.
        If the file exists, it merges the additional mappings into the provided network filters
        dictionary. Mappings that already exist in the network filters are skipped.

        :param network_filters: Dictionary of existing network filters to merge with
        :type network_filters: dict[str, dict[str, Any]]
        :param path: File path to the JSON file containing additional filter mappings
        :type path: str
        :returns: Updated network filters dictionary with additional mappings, or empty dict if file doesn't exist
        :rtype: dict[str, Any]
        """
        if os.path.exists(path):
            with open(path, mode="r", encoding="utf-8") as file:
                additional_filter_mappings: dict[str, list[dict[str, Any]]] = json.load(file)
                for key, value in additional_filter_mappings.items():
                    if key in network_filters:
                        logger.trace(f"Key: {key} already exists in network filters. Skipping...")
                        continue
                    else:
                        logger.trace(f"Key: {key} does not exist in network filters. Adding...")
                        base_dict: dict[str, Any] = {
                            "id": key,
                            "selections": value,
                            "selectionsByName": {selection["name"]: selection["id"] for selection in value},
                            "selectionsById": {selection["id"]: selection["name"] for selection in value},
                        }
                        network_filters.update({key: base_dict})
                logger.info(
                    f"Loaded {len(additional_filter_mappings)} additional filter mappings from {path}..."
                )
            return network_filters
        else:
            logger.warning(
                f"Additional filter mappings file does not exist at {path}. Skipping..."
            )
        return {}

    @staticmethod
    def _get_unique_filename(filename: str) -> str:
        """
        Get a unique filename by incrementing the name if the file already exists.

        Checks if the provided filename exists in the current working directory.
        If it exists, appends an incrementing number (e.g., file.txt -> file_1.txt, file_2.txt)
        until a unique filename is found. If the file does not exist, returns the original filename.

        :param filename: The filename to check and potentially increment
        :type filename: str
        :returns: The original filename if it doesn't exist, or an incremented version if it does
        :rtype: str
        """
        if not os.path.exists(filename):
            return filename

        # Split filename into base name and extension
        base_name, extension = os.path.splitext(filename)

        # Start incrementing from 1
        counter = 1
        while True:
            new_filename = f"{base_name}_{counter}{extension}"
            if not os.path.exists(new_filename):
                logger.trace(f"File {filename} exists. Using incremented name: {new_filename}")
                return new_filename
            counter += 1

    ############################################################
    # Helper functions to build filters for RMMLs
    ############################################################

    def _rmm_process_path_builder(
        self,
        os_executables: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Build filter objects for source and destination process paths from RMM executables.

        Processes a dictionary of OS-specific executables and creates filter objects for both
        source and destination process paths. This allows searching for network activities
        originating from or destined to any of the specified executable processes.

        :param os_executables: Dictionary mapping OS names to lists of executable paths
        :type os_executables: dict[str, Any]
        :returns: Tuple containing source process path filter and destination process path filter
        :rtype: tuple[dict[str, Any], dict[str, Any]]
        """
        # Create empty placeholder lists for the process paths
        src_process_path_list: list[str] = []
        dst_process_path_list: list[str] = []

        # Iterate through each OS and its executables
        for op_sys, executables in os_executables.items():
            logger.trace(f"Building filters for {len(executables)} {op_sys} executables...")
            # Iterate through each executable for the current OS
            for executable in executables:
                logger.trace(f"Adding executable: {executable} to filters...")
                # Add the executable to the lists for both source and destination process paths
                src_process_path_list.append(executable)
                dst_process_path_list.append(executable)

        # Create filter objects for the source and destination process paths
        src_process_path_filter: dict[str, Any] = self._zero_threat_hunt_tools.filter_object_builder(
            field_name="srcProcessPath", include_values=src_process_path_list
        )
        dst_process_path_filter: dict[str, Any] = self._zero_threat_hunt_tools.filter_object_builder(
            field_name="dstProcessPath", include_values=dst_process_path_list
        )

        # Return the filter objects for the source and destination process paths as a tuple
        return src_process_path_filter, dst_process_path_filter

    def _build_filters_for_rmm(self, rmm: dict[str, str | list[dict[str, Any]] | list[str]]) -> dict[str, Any]:
        """
        Build filter objects for all RMM indicators (executables, domains, ports).

        Constructs a comprehensive set of filter objects based on the RMM definition,
        including filters for executable processes (both source and destination), domains,
        and destination ports. These filters are used to query the Zero Networks API for
        matching network activities.

        :param rmm: Dictionary containing RMM metadata and indicators (executables, domains, ports)
        :type rmm: dict[str, str | list[dict[str, Any]] | list[str]]
        :returns: Dictionary containing filter objects keyed by filter type
        :rtype: dict[str, Any]
        """
        filter_holder: dict[str, Any] = {}

        # Build filters for executables.
        # I want to build filters that can be used to filter for
        # traffic either coming FROM (source) or TO (destination) an executable.
        if rmm.get("executables"):
            src_process_path_filter, dst_process_path_filter = self._rmm_process_path_builder(
                os_executables=rmm.get("executables")
            )
            filter_holder["srcProcessPath"] = src_process_path_filter
            filter_holder["dstProcessPath"] = dst_process_path_filter

        # Build filters for domains.
        if rmm.get("domains"):
            domain_list: list[str] = rmm.get("domains")
            domain_filter: dict[str, Any] = self._zero_threat_hunt_tools.filter_object_builder(
                field_name="dstAsset", include_values=domain_list
            )
            filter_holder["dstAsset"] = domain_filter

        if rmm.get("ports"):
            # Build filters for ports.
            port_list: list[int] = rmm.get("ports")
            port_filter: dict[str, Any] = self._zero_threat_hunt_tools.filter_object_builder(
                field_name="dstPort", include_values=port_list
            )
            filter_holder["dstPort"] = port_filter

        return filter_holder

    ####################################
    # Functions to filter RMML results
    ####################################
    def _filter_results_to_only_include_rmmls_with_indicators(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Filter hunt results to only include RMMLs that have discovered indicators.

        Removes RMMLs from the results that have no discovered activities across all
        indicator types (executables, domains, ports). Only RMMLs with at least one
        matching activity are retained in the filtered results.

        :param results: List of hunt result dictionaries, one per RMML
        :type results: list[dict[str, Any]]
        :returns: Filtered list containing only RMMLs with discovered indicators
        :rtype: list[dict[str, Any]]
        """
        logger.debug(f"Starting with {len(results)} RMMLs that may or may not have indicators...")
        # Filter to only results that have >1 activities in exectuables, domains, or port activities
        rmmls_with_indicators: list[dict[str, str | list[dict[str, Any]] | list[str]]] = [
            result
            for result in results
            if (
                len(result.get("executable_activities_discovered", [])) > 0
                or len(result.get("domain_activities_discovered", [])) > 0
                or len(result.get("port_activities_discovered", [])) > 0
            )
        ]
        logger.info(
            f"Filtered RRMLs to a resultant set of {len(rmmls_with_indicators)} RMMLs which have indicators..."
        )
        return rmmls_with_indicators


    ############################################################
    # Functions to deduplicate and decode 
    # RMMLs with indicators
    ############################################################

    def _deduplicate_and_decode_rmml_activities(self, rmmls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Deduplicate activities and transform integer IDs to human-readable values.

        Processes each RMML's discovered activities by removing duplicates based on event
        record IDs and converting integer field values (such as protocol types, asset types)
        to their human-readable string equivalents. Also adds ISO8601 timestamps and resolves
        asset IDs to asset names.

        :param rmmls: List of RMML result dictionaries with discovered activities
        :type rmmls: list[dict[str, Any]]
        :returns: List of RMML dictionaries with deduplicated and decoded activities
        :rtype: list[dict[str, Any]]
        """
        logger.info(f"Deduplicating activities and decoding integer values to human readable text for {len(rmmls)} RMMLs...")
        for rmml in rmmls:
            logger.info(f"Deduplicating activities for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")
            rmml = self._get_unique_rmml_activities(rmml=rmml)
            logger.info(f"Decoding activity fields to string format for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")
            rmml = self._transform_unique_activities_to_human_readable(rmml=rmml)
        logger.info(f"Ndeduplicated and decoded {len(rmmls)} RMMLs...")
        return rmmls

    def _get_unique_rmml_activities(
        self, rmml: dict[str, str | list[dict[str, Any]] | list[str]]
    ) -> dict[str, str | list[dict[str, Any]] | list[str]]:
        """
        Deduplicate activities for a single RMML based on event record IDs.

        Processes all discovered activities for an RMML and creates a unique activities map
        keyed by event record ID. Activities with the same event record ID are consolidated,
        with their indicator types (executable, domain, port) tracked in the indicators field.

        :param rmml: RMML dictionary containing discovered activities
        :type rmml: dict[str, str | list[dict[str, Any]] | list[str]]
        :returns: RMML dictionary with unique_activities_map field added
        :rtype: dict[str, str | list[dict[str, Any]] | list[str]]
        """
        logger.debug(
            f"Finding unique indicator activities for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        unique_activities_map: dict[str, dict[str, dict[str, bool] | dict[str, Any]]] = {}
        if len(rmml.get("executable_activities_discovered", [])) > 0:
            for activity in rmml.get("executable_activities_discovered", []):
                unique_activities_map = self.__is_activity_unique(
                    activity=activity,
                    indicator_type="executable",
                    unique_activities_map=unique_activities_map,
                )
        if len(rmml.get("domain_activities_discovered", [])) > 0:
            for activity in rmml.get("domain_activities_discovered", []):
                unique_activities_map = self.__is_activity_unique(
                    activity=activity,
                    indicator_type="domain",
                    unique_activities_map=unique_activities_map,
                )
        if len(rmml.get("port_activities_discovered", [])) > 0:
            for activity in rmml.get("port_activities_discovered", []):
                unique_activities_map = self.__is_activity_unique(
                    activity=activity,
                    indicator_type="port",
                    unique_activities_map=unique_activities_map,
                )
        logger.debug(
            f"Found {len(unique_activities_map)} unique indicator activities "
            f"for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        rmml.update({"unique_activities_map": list(unique_activities_map.values())})
        return rmml

    @staticmethod
    def __is_activity_unique(
        activity: dict[str, Any], indicator_type: str, unique_activities_map: dict[str, Any]
    ) -> dict[str, dict[str, bool] | dict[str, Any]]:
        """
        Check if an activity is unique and add it to the unique activities map.

        Determines if an activity (identified by its event record ID) already exists in the
        unique activities map. If it doesn't exist, adds it with the specified indicator type.
        If it exists, adds the indicator type to the existing activity's indicators.

        :param activity: Network activity dictionary to check for uniqueness
        :type activity: dict[str, Any]
        :param indicator_type: Type of indicator that matched this activity (executable, domain, port)
        :type indicator_type: str
        :param unique_activities_map: Dictionary mapping event record IDs to unique activity data
        :type unique_activities_map: dict[str, Any]
        :returns: Updated unique activities map with the activity added or updated
        :rtype: dict[str, dict[str, bool] | dict[str, Any]]
        """
        event_record_id: str = str(activity.get("src", {}).get("eventRecordId", ""))

        # Check if the activity is already in the map
        if event_record_id not in unique_activities_map:
            logger.trace(f"Activity: {activity} does not exist in unique activities map. Adding it...")
            # If the activity is not in the map, add it, and add the indicator type to indicators
            unique_activities_map.update(
                {
                    event_record_id: {
                        "indicators": {
                            indicator_type: True,
                        },
                        "activity": activity,
                    }
                }
            )
            logger.trace(
                f"Added new event record ID {event_record_id} to "
                f"unique activities map with indicator: {indicator_type}..."
            )
        else:
            logger.trace(
                f"Activity has {event_record_id} already exists in "
                f"unique activities map. Adding indicator: {indicator_type}..."
            )
            unique_activities_map[event_record_id]["indicators"].update({indicator_type: True})
            logger.trace(
                f"Updated activity hash {event_record_id} in "
                f"unique_activities_map with indicator: {indicator_type}..."
            )
        return unique_activities_map

    def _transform_unique_activities_to_human_readable(
        self, rmml: dict[str, str | list[dict[str, Any]] | list[str]]
    ) -> dict[str, str | list[dict[str, Any]] | list[str]]:
        """
        Transform unique activities by converting IDs to human-readable values.

        Processes each unique activity in the RMML's unique_activities_map, adding ISO8601
        timestamps, resolving asset IDs to asset names, and recursively converting all
        integer ID values to their human-readable string equivalents using network filter
        mappings.

        :param rmml: RMML dictionary containing unique_activities_map
        :type rmml: dict[str, str | list[dict[str, Any]] | list[str]]
        :returns: RMML dictionary with transformed activities
        :rtype: dict[str, str | list[dict[str, Any]] | list[str]]
        """
        if len(rmml.get("unique_activities_map", [])) > 0:
            for activity in rmml.get("unique_activities_map", []):
                # If the integer timestamp is present in the activity, add a new human readable ISO8601 timestamp
                if activity.get("activity", {}).get("timestamp", None) and isinstance(
                    activity.get("activity", {}).get("timestamp"), int
                ):
                    # Add a new key/value -> "iso_timestamp" to the activity, 
                    # set to the timestamp converted to ISO8601 format (UTC timezone)
                    activity.get("activity", {}).update(
                        {
                            "iso_timestamp": datetime.fromtimestamp(
                                activity.get("activity", {}).get("timestamp") / 1000, tz=timezone.utc
                            ).isoformat()
                        }
                    )
                asset_id: str = str(activity.get("activity", {}).get("src", {}).get("assetId", ""))
                activity.get("activity", {}).get("src", {}).update(
                    {"srcAssetName": self._resolve_asset_id_to_asset_name(asset_id=asset_id)}
                )

                # The function called here will recsurively 
                # enumerate all key/value pairs in the activity,
                # and transform the key/values that are integer 
                # IDs (like protocolType=2) to human readable 
                # values (like "TCP")
                activity = self._recursively_transform_all_id_values_to_human_readable(
                    data=activity.get("activity", {})
                )
        else:
            logger.warning(
                f"No unique activities map found for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
            )

        return rmml

    def _recursively_transform_all_id_values_to_human_readable(self, data: dict[str, Any]) -> Any:
        """
        Recursively transform all integer ID values to human-readable strings.

        Traverses a nested dictionary structure and converts integer and string values that
        correspond to ID fields (such as protocol types, asset types) to their human-readable
        equivalents using network filter mappings. Handles nested dictionaries and lists
        recursively.

        :param data: Dictionary containing activity data with potential ID values to transform
        :type data: dict[str, Any]
        :returns: Dictionary with all ID values transformed to human-readable strings
        :rtype: Any
        """
        # Sure, this isn't the best recursive function ever written, but until
        # some of the API attributes are fixed to match their respective network filter field names,
        # this is the simplest way to do this recursively and dynamically.

        for key, value in data.items():
            if isinstance(value, int) or isinstance(value, str):
                logger.trace(f"Key: {key} is a {type(value)}. Value: {value}")
                new_value = self._map_id_value_to_human_readable(value=value, key=key)
                data.update({key: new_value})
            elif isinstance(value, list):
                logger.trace(f"Key: {key} is a list. Value: {value}")
                for item in value:
                    if isinstance(item, int) or isinstance(item, str):
                        new_item = self._map_id_value_to_human_readable(value=item, key=key)
                        value.remove(item)
                        value.append(new_item)
                    elif isinstance(item, dict):
                        item = self._recursively_transform_all_id_values_to_human_readable(data=item)
            elif isinstance(value, dict):
                logger.trace(f"Key: {key} is a dict. Resurcively enumerating all nested fields...")
                value = self._recursively_transform_all_id_values_to_human_readable(data=value)
        return data

    @staticmethod
    def _check_for_inconsistent_field_name(key: str) -> str:
        """
        Check if a field name has an inconsistent mapping and return the mapped name.

        Some API attribute keys don't match their corresponding network filter field names.
        This function checks if a key exists in the inconsistent field name mapping and
        returns the mapped field name if found, otherwise returns the original key.

        :param key: Field name to check for inconsistent mapping
        :type key: str
        :returns: Mapped field name if inconsistent mapping exists, otherwise original key
        :rtype: str
        """
        if key in INCONSISTENT_FIELD_NAME_MAP:
            return INCONSISTENT_FIELD_NAME_MAP.get(key, "N/A")
        else:
            return key

    def _map_id_value_to_human_readable(self, value: str, key: str) -> str:
        """
        Map an integer or string ID value to its human-readable equivalent.

        Converts ID values (such as protocol type IDs, asset type IDs) to human-readable
        strings by looking them up in the network filter mappings. First checks for
        inconsistent field name mappings, then looks up the value in the appropriate
        network filter's selectionsById dictionary.

        :param value: Integer or string ID value to convert
        :type value: str
        :param key: Field name associated with the value
        :type key: str
        :returns: Human-readable string value if mapping exists, otherwise original value
        :rtype: str
        """
        # I found that some attributes returned in activities
        # did not match the field names in network filters
        # So to dynamically map them to human-readable values,
        # we need to map the inconsistent field names to thier
        # respective network filter field names.

        # We have to have two key variables because the if we
        # update the key variable, we will lose the original key value.
        # So og_key will be used to update the data in the dictionary,
        # so the original attribute name is preserved.
        # og_key: str = key
        key = ZNHuntOps._check_for_inconsistent_field_name(key=key)
        # If a network filter exists for the key, and it has a selectionsById dictionary,
        # we can map the value to a human-readable value by looking up the value in the selectionsById dictionary.
        if (
            network_filter := self._zero_threat_hunt_tools.network_filters.get(key)
        ) and "selectionsById" in network_filter:
            logger.trace(f"Key: {key} maps to a network filter. Mapping value to human readable...")
            # Get the mapping value (human readable value) from the selectionsById dictionary.
            value_from_id: str = network_filter.get("selectionsById", {}).get(str(value), value)
            logger.trace(f"Updated value for key: {key} from {value} to: {value_from_id}")
            return value_from_id
        else:
            logger.trace(f"Key: {key} does not map to a network filter. Skipping...")
            return value

    def _resolve_asset_id_to_asset_name(self, asset_id: str) -> str:
        """
        Resolve an asset ID to its human-readable asset name.

        Looks up an asset name by its ID, using a cached mapping if available. If the asset
        ID is not in the cache, queries the Zero Networks API to retrieve the asset name
        and caches it for future lookups.

        :param asset_id: Asset ID to resolve to a name
        :type asset_id: str
        :returns: Asset name if found, "N/A" if not found or on error
        :rtype: str
        """
        if asset_id in self.asset_id_to_asset_name_map:
            return self.asset_id_to_asset_name_map[asset_id]
        else:
            try:
                asset_name = (
                    self._zero_threat_hunt_tools.api.get(endpoint=f"/assets/{asset_id}")
                    .get("entity", {})
                    .get("name", "N/A")
                )
                self.asset_id_to_asset_name_map[asset_id] = asset_name
                return asset_name
            except ZeroNetworksNotFoundError:
                logger.warning(
                    f"Unable to resolve asset ID {asset_id} to asset name."
                    "Safely ignore this warning unless you notice valid asset IDs are not being resolved to asset names!"
                )
                return "N/A"
            

    @staticmethod
    def _aggregate_all_activities_into_list(rmmls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Aggregate all unique activities from all RMMLs into a single list.

        Combines all unique activities from all RMMLs into a flat list, enriching each
        activity with RMML metadata (name and ID) and a comma-separated string of
        indicator types that matched the activity.

        :param rmmls: List of RMML dictionaries, each containing unique_activities_map
        :type rmmls: list[dict[str, Any]]
        :returns: Flat list of all activities from all RMMLs with metadata added
        :rtype: list[dict[str, Any]]
        """
        # This list will hold all the indicating activities from all the RMMLs
        all_indicating_activities: list[dict[str, Any]] = []

        # Iterate through each RMML and add its indicating activities to the all_indicating_activities list
        for rmml in rmmls:
            for activity_info in rmml.get("unique_activities_map", []):
                activity: dict[str, Any] = activity_info.get("activity", {})
                # Make list of indicator types that are True
                activity_indicators: list[str] = [
                    key for key, item in activity_info.get("indicators", {}).items() if item is True
                ]
                activity_indicators_str: str = ", ".join(activity_indicators)
                # Update each activity with the RMML name and ID, and the indicators
                activity.update(
                    {
                        "rmml_name": rmml.get("rmm_name"),
                        "rmml_id": rmml.get("rmm_id"),
                        "indicators": activity_indicators_str,
                    }
                )
                all_indicating_activities.append(activity)

        logger.debug(
            f"Combined {len(all_indicating_activities)} indicating "
            "activities from all RMMLs into single list for exporting to CSV..."
        )

        return all_indicating_activities

    ####################################
    # Format/print/export results
    ####################################
    def _export_all_indicating_activities_to_csv(self, rmmls: list[dict[str, Any]]) -> None:
        """
        Export all indicating activities to a CSV file.

        Converts all aggregated indicating activities to a pandas DataFrame, prioritizes
        certain columns for better readability, and exports to a CSV file. If a file with
        the same name already exists, generates a unique filename by appending an incrementing
        number.

        :param rmmls: List of RMML dictionaries (used for logging context)
        :type rmmls: list[dict[str, Any]]
        :returns: None
        :rtype: None
        """
        logger.info(
            f"Exporting all indicating activities to CSV for {len(rmmls)} RMMLs..."
        )
            

        # Convert the list of activities to a pandas DataFrame
        df: pd.DataFrame = pd.json_normalize(self.all_indicating_activities)

        # Prioritize (order) certain columns
        priority_columns: list[str] = [
            "iso_timestamp",
            "rmml_name",
            "rmml_id",
            "indicators",
            "state",
            "src.srcAssetName",
            "src.ip",
            "src.userName",
            "src.assetType",
            "src.networkProtectionState",
            "src.processName",
            "dst.fqdn",
            "dst.ip",
            "protocol",
            "dst.port",
            "dst.fqdn",
            "dst.assetType",
            "dst.networkProtectionState",
            "dst.processName",
            "trafficType"
        ]

        # Recreate the DataFrame with the priority columns first, then the other columns
        other_columns = [col for col in df.columns if col not in priority_columns]
        df: pd.DataFrame = df[priority_columns + other_columns]

        filename: str = self._get_unique_filename("all_indicating_activities.csv")
        df.to_csv(filename, index=False,)
        logger.info(
            f"Exported {len(self.all_indicating_activities)} indicating activities to CSV file: {filename}..."
        )

    ####################################
    # Functions to drive each section of hunt workflow
    ####################################

    def _start_multithreaded_hunt(self, from_timestamp: int | str, to_timestamp: int | str) -> list[dict[str, Any]]:
        """
        Execute concurrent hunting operations for all RMMLs using thread pool.

        Submits hunt tasks for all RMMLs to a thread pool executor and collects results
        as they complete. Uses the configured max_workers setting to control concurrency.
        Handles exceptions for individual RMMLs without stopping the overall hunt process.

        :param from_timestamp: Start timestamp for the hunt query (ISO8601 string or milliseconds)
        :type from_timestamp: int | str
        :param to_timestamp: End timestamp for the hunt query (ISO8601 string or milliseconds)
        :type to_timestamp: int | str
        :returns: List of hunt result dictionaries, one per RMML
        :rtype: list[dict[str, Any]]
        """
        results: list[dict[str, Any]] = []
        logger.info(
            f"Starting concurrent hunt for {len(self.rmm_data.rmm_simplified_list)}"
            f"RMMLs with {self.max_workers} workers..."
        )
         # Use ThreadPoolExecutor for concurrent execution of hunt operations
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all hunt tasks to the executor
            future_to_rmm = {
                executor.submit(
                    self._hunt_for_rmm, rmm=rmm, from_timestamp=from_timestamp, to_timestamp=to_timestamp
                ): rmm
                for rmm in self.rmm_data.rmm_simplified_list
            }

            # Collect results as they complete
            for future in as_completed(future_to_rmm):
                rmm = future_to_rmm[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.debug(
                        f"Completed hunt for RMM: {rmm.get('meta', {}).get('name')} - "
                        f"{rmm.get('meta', {}).get('id')}"
                    )
                # pylint: disable=broad-exception-caught
                except Exception as exc:
                    logger.error(
                        f"RMM {rmm.get('meta', {}).get('name')} - {rmm.get('meta', {}).get('id')} "
                        f"generated an exception: {exc}"
                    )

        logger.info(f"Finished hunting for activities from {len(results)} RMMLs...")
        return results

    def _hunt_for_rmm(self, rmm: dict[str, Any], from_timestamp: int | str, to_timestamp: int | str) -> dict[str, Any]:
        """
        Hunt for network activities matching a specific RMM's indicators.

        Searches for network activities matching the RMM's executables (source and destination
        processes), domains, and ports within the specified time range. Filters out common
        ports (80, 443) from port searches to reduce noise. Aggregates all discovered activities
        into a result dictionary with indicator flags.

        :param rmm: RMM dictionary containing metadata and indicators (executables, domains, ports)
        :type rmm: dict[str, Any]
        :param from_timestamp: Start timestamp for the hunt query (ISO8601 string or milliseconds)
        :type from_timestamp: int | str
        :param to_timestamp: End timestamp for the hunt query (ISO8601 string or milliseconds)
        :type to_timestamp: int | str
        :returns: Dictionary containing RMM metadata and discovered activities by indicator type
        :rtype: dict[str, Any]
        """
        logger.info(
            f"Starting hunt for RMM: {rmm.get('meta',{}).get('name')} - {rmm.get('meta',{}).get('id')}"
        )

        # Dictionary to hold results
        results: dict[str, Any] = {
            "rmm_name": rmm.get("meta", {}).get("name"),
            "rmm_id": rmm.get("meta", {}).get("id"),
            "rmm_executables": rmm.get("executables"),
            "rmm_domains": rmm.get("domains"),
            "rmm_ports": rmm.get("ports"),
            "has_indicators": False,
            "executable_activities_discovered": [],
            "domain_activities_discovered": [],
            "port_activities_discovered": [],
            "unique_activities_map": [],
        }

        # Temporary list to hold activities
        src_process_path_activities: list[dict[str, Any]] = []
        dst_process_path_activities: list[dict[str, Any]] = []
        dst_asset_activities: list[dict[str, Any]] = []
        dst_port_activities: list[dict[str, Any]] = []

        filter_holder: dict[str, Any] = self._build_filters_for_rmm(rmm=rmm)

        # Search for activities that are sourced FROM a listed executable
        if filter_holder.get("srcProcessPath"):
            logger.debug(
                f"Searching for activities from source processes: {filter_holder.get('srcProcessPath')}"
            )
            src_process_path_activities = self._zero_threat_hunt_tools.get_activities_from_source_processes(
                process_paths=filter_holder.get("srcProcessPath", {}).get("includeValues"),
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
            )
            logger.debug(
                f"Found {len(src_process_path_activities)} activities with traffic coming from an executable "
                f"used by {rmm.get('meta',{}).get('name')} - {rmm.get('meta',{}).get('id')}..."
            )

        # Search for activities that are sourced FROM a listed executable
        if filter_holder.get("dstProcessPath"):
            logger.debug(
                f"Searching for activities to destination processes: {filter_holder.get('dstProcessPath')}"
            )
            dst_process_path_activities = self._zero_threat_hunt_tools.get_activities_to_destination_processes(
                process_paths=filter_holder.get("dstProcessPath", {}).get("includeValues"),
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
            )
            logger.debug(
                f"Found {len(dst_process_path_activities)} activities with traffic coming from an executable "
                f"used by {rmm.get('meta',{}).get('name')} - {rmm.get('meta',{}).get('id')}..."
            )

        if filter_holder.get("dstAsset"):
            logger.debug(
                f"Searching for activities to domains: {filter_holder.get('dstAsset')}"
            )
            dst_asset_activities = self._zero_threat_hunt_tools.get_activities_to_domains(
                domains=filter_holder.get("dstAsset", {}).get("includeValues"),
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
            )
            logger.debug(
                f"Found {len(dst_asset_activities)} activities with traffic coming from an executable "
                f"used by {rmm.get('meta',{}).get('name')} - {rmm.get('meta',{}).get('id')}..."
            )

        if filter_holder.get("dstPort"):
            # If only ports are 80 and 443, avoid searching for them
            # Do not want to remove from original list (for reporting)
            # So, we will create a copy to validate with
            port_validation_list: list[int] = filter_holder.get("dstPort", {}).get("includeValues").copy()
            if "80" in port_validation_list:
                port_validation_list.remove("80")
            if "443" in port_validation_list:
                port_validation_list.remove("443")

            if len(port_validation_list) > 0:
                logger.debug(f"Searching for activities to ports: {port_validation_list}")
                dst_port_activities = self._zero_threat_hunt_tools.get_activities_to_destination_ports(
                    ports=port_validation_list,
                    from_timestamp=from_timestamp,
                    to_timestamp=to_timestamp,
                )
                logger.debug(
                    f"Found {len(dst_port_activities)} activities with traffic coming from an executable used "
                    f"by {rmm.get('meta',{}).get('name')} - {rmm.get('meta',{}).get('id')}..."
                )
            else:
                logger.debug(
                    "No ports to search for other than 80 and 443 for "
                    +f"{rmm.get('meta',{}).get('name')} - {rmm.get('meta',{}).get('id')}. "
                    +"Skipping search as these are common ports..."
                )
                dst_port_activities: list[dict[str, Any]] = []

        if len(src_process_path_activities) > 0:
            results["has_indicators"] = True
            results["executable_activities_discovered"].extend(src_process_path_activities)
        if len(dst_process_path_activities) > 0:
            results["has_indicators"] = True
            results["executable_activities_discovered"].extend(dst_process_path_activities)
        if len(dst_asset_activities) > 0:
            results["has_indicators"] = True
            results["domain_activities_discovered"].extend(dst_asset_activities)
        if len(dst_port_activities) > 0:
            results["has_indicators"] = True
            results["port_activities_discovered"].extend(dst_port_activities)

        logger.info(
            f"Finished hunting for {rmm.get('meta',{}).get('name')} - {rmm.get('meta',{}).get('id')}..."
        )
        return results

    def _prepare_data_for_analysis(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Prepare hunt results for analysis by filtering, deduplicating, and aggregating.

        Processes raw hunt results through multiple stages: filters to only RMMLs with
        indicators, deduplicates activities and converts IDs to human-readable values,
        and aggregates all activities into a single list for export.

        :param results: List of raw hunt result dictionaries from the multithreaded hunt
        :type results: list[dict[str, Any]]
        :returns: List of processed RMML dictionaries ready for analysis and export
        :rtype: list[dict[str, Any]]
        """
        logger.info("Preparing data for analysis...")
        filter_rmmls_with_indicators: list[dict[str, Any]] = self._filter_results_to_only_include_rmmls_with_indicators(results=results)
        normalized_rmmls_with_indicators: list[dict[str, Any]] = self._deduplicate_and_decode_rmml_activities(rmmls=filter_rmmls_with_indicators)
        self.all_indicating_activities = self._aggregate_all_activities_into_list(rmmls=normalized_rmmls_with_indicators)
        return normalized_rmmls_with_indicators

    ############################################################
    # Main functions to execute the hunt
    ############################################################

    def execute_hunt(self, from_timestamp: str, to_timestamp: Optional[str] = None, **_kwargs: Optional[dict[str, Any]]):
        """
        Execute the complete threat hunting workflow for RMMLs.

        Orchestrates the entire threat hunting process: performs concurrent hunts for all
        RMMLs, prepares the data for analysis (filtering, deduplication, transformation),
        and exports results to CSV. If to_timestamp is not provided, defaults to current time.

        :param from_timestamp: Start timestamp for the hunt query in ISO8601 format
        :type from_timestamp: str
        :param to_timestamp: Optional end timestamp for the hunt query in ISO8601 format
        :type to_timestamp: Optional[str]
        :param _kwargs: Optional keyword arguments (currently unused, reserved for future features)
        :type _kwargs: Optional[dict[str, Any]]
        :returns: List of processed RMML dictionaries with discovered activities
        :rtype: list[dict[str, Any]]
        """
        # 1. Hunt activities
        logger.info("Starting RMMs hunt...")
        
        # Get the start and end timestamps
        if not to_timestamp:
            to_timestamp = str(self._zero_threat_hunt_tools.datetime_to_timestamp_ms(datetime.now()))
            logger.debug(
                f"Converted to_timestamp to milliseconds since epoch: {to_timestamp}"
            )

        # 1. Hunt for activities
        hunt_results: list[dict[str, Any]] = self._start_multithreaded_hunt(from_timestamp=from_timestamp, to_timestamp=to_timestamp)
       
        # 2. Prepare data for analysis
        prepared_data: list[dict[str, Any]] = self._prepare_data_for_analysis(results=hunt_results)

        # 3. Export results to CSV
        self._export_all_indicating_activities_to_csv(rmmls=prepared_data)

        return prepared_data
