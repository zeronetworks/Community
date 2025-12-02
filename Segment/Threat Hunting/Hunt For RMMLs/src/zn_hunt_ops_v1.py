# pyright: reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
# pylint: disable=no-name-in-module

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Optional

from loguru import logger
import pandas as pd
from tabulate import tabulate

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
        if key in INCONSISTENT_FIELD_NAME_MAP:
            return INCONSISTENT_FIELD_NAME_MAP.get(key, "N/A")
        else:
            return key

    def _map_id_value_to_human_readable(self, value: str, key: str) -> str:
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
            except ZeroNetworksNotFoundError as e:
                logger.warning(
                    f"Unable to resolve asset ID {asset_id} to asset name."
                    "Safely ignore this warning unless you notice valid asset IDs are not being resolved to asset names!"
                )
                return "N/A"
            

    ############################################################
    # Functions to perform granular data analysis on RMMLs
    ############################################################

    def _get_advanced_stats(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Analyze the results of the hunt and return a summary of the findings.
        """
        logger.info(f"Analyzing results for {len(results)} RMMLs...")

        

        """logger.info(
            f"Filtered RRMLs to a resultant set of {len(rmmls_with_indicators)} RMMLs which have indicators..."
        )
        for rmml in results:
            rmml_analysis_results = self._run_statistical_analysis(rmml=rmml)
            rmml.update({"analysis": rmml_analysis_results})

        return results"""

    def _run_statistical_analysis(self, rmml: dict[str, Any]) -> dict[str, Any]:
        logger.info(
            f"Running statistical analysis for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        # Create a pandas dataframe from the unique activities map
        df: pd.DataFrame = pd.json_normalize(rmml.get("unique_activities_map", []))
        logger.trace(
            f"Created pandas dataframe from unique activities map for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )

        ####################################
        #
        # Analyze the indicating activities by indicator type
        #
        ####################################
        # Get the count of indicating activities by indicator type
        logger.trace(
            f"Getting count of indicating activities by indicator type "
            f"for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        indicator_type_counts: dict[str, int] = {
            "domain": int(df["indicators.domain"].notna().sum() if "indicators.domain" in df.columns else 0),
            "port": int(df["indicators.port"].notna().sum() if "indicators.port" in df.columns else 0),
            "executable": int(
                df["indicators.executable"].notna().sum() if "indicators.executable" in df.columns else 0
            ),
        }
        indicator_type_counts = dict(sorted(indicator_type_counts.items(), key=lambda x: x[1], reverse=True))
        logger.trace(
            "Indicator type counts for {} - {}: {}",
            rmml.get("rmm_name"),
            rmml.get("rmm_id"),
            json.dumps(indicator_type_counts),
        )

        # Get the top indicator type
        top_indicator_type: str = max(indicator_type_counts, key=indicator_type_counts.get)
        logger.trace(
            f"Top indicator type for {rmml.get('rmm_name')} - {rmml.get('rmm_id')} is {top_indicator_type}..."
        )

        ####################################
        #
        # Analyze the indicating activities by destination
        #
        ####################################

        # Use a custom function to group and count unique destinations - do this to handle missing FQDNs more gracefully
        logger.trace(
            f"Grouping and counting unique destinations for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        destination_counts: dict[str, int] = self._group_and_count_unique_destinations(rmml=rmml)
        destination_counts = dict(sorted(destination_counts.items(), key=lambda x: x[1], reverse=True))
        logger.trace(
            "Aggregated destinations for {} - {}: {}",
            rmml.get("rmm_name"),
            rmml.get("rmm_id"),
            json.dumps(destination_counts),
        )

        # Get the top destination
        top_destination: str = max(destination_counts, key=destination_counts.get)
        logger.trace(
            f"Top destination for {rmml.get('rmm_name')} - {rmml.get('rmm_id')} is {top_destination}..."
        )

        ####################################
        #
        # Analyze the indicating activities by port protocol
        #
        ####################################

        # Create a new column for the port protocol combo (e.g. "TCP/80")
        df["port_protocol"] = (
            df["activity.protocol"].fillna("").astype(str) + "/" + df["activity.dst.port"].fillna("").astype(str)
        )

        # Get the count of unique port protocol combos
        port_protocol_counts: dict[str, int] = df["port_protocol"].value_counts().to_dict()
        port_protocol_counts = dict(sorted(port_protocol_counts.items(), key=lambda x: x[1], reverse=True))
        logger.trace(
            "Port protocol counts for {} - {}: {}",
            rmml.get("rmm_name"),
            rmml.get("rmm_id"),
            json.dumps(port_protocol_counts),
        )

        # Get the top port protocol combo
        top_port_protocol: str = max(port_protocol_counts, key=port_protocol_counts.get)
        logger.trace(
            f"Top port protocol combo for {rmml.get('rmm_name')} - {rmml.get('rmm_id')} is {top_port_protocol}..."
        )

        ####################################
        #
        # Analyze the indicating activities by source process
        #
        ####################################
        # Create new DF column which strips the PID from the src process name if present
        df["source_process_names"] = (
            df["activity.src.processName"].fillna("N/A").astype(str).str.replace(r"\s\(\d+\)$", "", regex=True)
        )

        # Get the count of unique source processes
        logger.trace(
            f"Grouping and counting unique source processes for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        source_process_counts: dict[str, int] = (
            df["source_process_names"].fillna("N/A").astype(str).value_counts().to_dict()
        )
        source_process_counts = dict(sorted(source_process_counts.items(), key=lambda x: x[1], reverse=True))
        logger.trace(
            "Source process counts for {} - {}: {}",
            rmml.get("rmm_name"),
            rmml.get("rmm_id"),
            json.dumps(source_process_counts),
        )

        # Get the top source process
        top_source_process: str = max(source_process_counts, key=source_process_counts.get)
        logger.trace(
            f"Top source process for {rmml.get('rmm_name')} - {rmml.get('rmm_id')} is {top_source_process}..."
        )

        ####################################
        #
        # Analyze the indicating activities by destination process
        #
        ####################################

        # Create new DF column which strips the PID from the dst process name if present
        df["destination_process_names"] = (
            df["activity.dst.processName"].fillna("N/A").astype(str).str.replace(r"\s\(\d+\)$", "", regex=True)
        )

        # Get destination process counts
        logger.trace(
            f"Grouping and counting unique destination processes for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        destination_process_counts: dict[str, int] = (
            df["destination_process_names"].fillna("N/A").astype(str).value_counts().to_dict()
        )
        destination_process_counts = dict(sorted(destination_process_counts.items(), key=lambda x: x[1], reverse=True))
        logger.trace(
            "Destination process counts for {} - {}: {}",
            rmml.get("rmm_name"),
            rmml.get("rmm_id"),
            json.dumps(destination_process_counts),
        )

        # Get the top destination process
        top_destination_process: str = max(
            destination_process_counts,
            key=destination_process_counts.get,
        )
        logger.trace(
            f"Top destination process for {rmml.get('rmm_name')} - {rmml.get('rmm_id')} is {top_destination_process}..."
        )

        ####################################
        #
        # Analyze the indicating activities by source asset name
        #
        ####################################
        # Get the top source asset names
        logger.trace(
            f"Grouping and counting unique source asset names for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        source_asset_name_counts: dict[str, int] = (
            df["activity.src.srcAssetName"].fillna("N/A").astype(str).value_counts().to_dict()
        )
        logger.trace(
            "Source asset name counts for {} - {}: {}",
            rmml.get("rmm_name"),
            rmml.get("rmm_id"),
            json.dumps(source_asset_name_counts),
        )

        # Get the top source asset name
        top_source_asset_name: str = max(
            source_asset_name_counts,
            key=source_asset_name_counts.get,
        )
        logger.trace(
            f"Top source asset name for {rmml.get('rmm_name')} - {rmml.get('rmm_id')} is {top_source_asset_name}..."
        )

        # Populate table to unique assets Ids seen in this RMML
        for _, row in df.iterrows():
            asset_id: str = str(row["activity.src.assetId"])
            asset_name: str = str(row["activity.src.srcAssetName"])

            # If this unique asset ID is not in the map, we add it
            if asset_id not in self.unique_source_assets_seen:
                self.unique_source_assets_seen[asset_id] = {
                    "asset_id": asset_id,
                    "asset_name": asset_name,
                    # We are going to add a key/value pair to the map to 
                    # track the number of occurences of this asset ID in this RMML
                    "occurences_by_rmml": {rmml.get("rmm_name"): int(df["activity.src.assetId"].count())},
                }

        return {
            "total_indicating_activities": len(rmml.get("unique_activities_map", [])),
            "top_indicator_type": top_indicator_type,
            "indicator_type_counts": indicator_type_counts,
            "top_destination": top_destination,
            "destination_counts": destination_counts,
            "top_port_protocol": top_port_protocol,
            "port_protocol_counts": port_protocol_counts,
            "top_source_process": top_source_process,
            "source_process_counts": source_process_counts,
            "top_destination_process": top_destination_process,
            "destination_process_counts": destination_process_counts,
            "top_source_asset_name": top_source_asset_name,
            "source_asset_name_counts": source_asset_name_counts,
        }

    @staticmethod
    def _group_and_count_unique_destinations(rmml: dict[str, str | list[dict[str, Any]] | list[str]]) -> dict[str, int]:
        logger.trace(f"Calculating top destinations for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")
        # Track local IP to FQDN mappings seen in these activities
        ip_to_fqdn_map: dict[str, str] = {}
        # Track unique destinations seen in these activities
        unique_destinations_map: dict[str, int] = {}
        # Iterate through each unique activity in the RMML
        for unique_activity_info in rmml.get("unique_activities_map", []):
            # Get the destination asset from the activity
            dst_ip_address: str = unique_activity_info.get("activity", {}).get("dst", {}).get("ip", "")
            # Get the destination asset from the activity
            dst_asset: str = unique_activity_info.get("activity", {}).get("dst", {}).get("dstAsset", "")
            # Get the FQDN from the activity
            dst_fqdn: str = unique_activity_info.get("activity", {}).get("dst", {}).get("fqdn", "")
            # If the destination FQDN exists
            if dst_fqdn and len(dst_fqdn) > 0:
                # Add the IP address to FQDN mapping to the map
                ip_to_fqdn_map[dst_ip_address] = dst_fqdn
                # Set the unique map key to the FQDN
                unique_destinations_map_key = dst_fqdn
            elif dst_asset and len(dst_asset) > 0:
                # Set the unique map key to the destination asset
                unique_destinations_map_key = dst_asset
            else:
                # Set the unique map key to the IP address
                if dst_ip_address in ip_to_fqdn_map:
                    unique_destinations_map_key = ip_to_fqdn_map[dst_ip_address]
                else:
                    unique_destinations_map_key = dst_ip_address

            if len(unique_destinations_map_key) == 0:
                logger.warning(
                    f"Skipping unique destination aggregation for event record id "
                    f"{unique_activity_info.get('activity',{}).get('src',{}).get('eventRecordId',"")} "
                    f"as unique destination map key is empty"
                )
                continue

            # If the unique map key exists in the map, increment the count
            if unique_destinations_map_key in unique_destinations_map:
                unique_destinations_map[unique_destinations_map_key] += 1
                logger.trace(
                    f"Updated count for unique destination {unique_destinations_map_key} "
                    +f"to {unique_destinations_map[unique_destinations_map_key]} "
                    +f"for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
                )
            else:
                unique_destinations_map[unique_destinations_map_key] = 1
                logger.trace(
                    f"Added new unique destination {unique_destinations_map_key} "
                    f"to unique destinations map for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
                )
        return unique_destinations_map

    
    ####################################
    # Functions to perform macro-level data analysis on RMMLs
    ####################################
    
    def _run_macro_analysis(self, rmmls: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("Running macro-level analysis (trend analysis across all RMMLs)")
        rmml_counts: dict[str, Any] = self._get_activity_counts_by_rmml(rmmls=rmmls)
        aggregated_top_stats: dict[str, Any] = self._get_activities_top_stats(activities=self.all_indicating_activities)
        logger.trace("RMML counts: {}", json.dumps(rmml_counts))
        logger.trace("Aggregated top stats: {}", json.dumps(aggregated_top_stats))

        macro_statistics: dict[str, Any] = {
            "rmm_counts": rmml_counts,
            "aggregated_top_stats": aggregated_top_stats,
        }

        logger.info("Macro-level analysis completed...")
        return macro_statistics

    @staticmethod
    def _aggregate_all_activities_into_list(rmmls: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

    @staticmethod
    def _get_activities_top_stats(activities: list[dict[str, Any]]) -> dict[str, Any]:
        logger.debug("Getting activities top stats...")
        top_stats: dict[str, Any] = {
            "top_destination": "",
            "destination_counts": {},
            "top_destination_on_port_protocol": "",
            "destination_on_port_protocol_counts": {},
            "top_port_protocol": "",
            "port_protocol_counts": {},
            "top_source_process": "",
            "source_process_counts": {},
            "top_destination_process": "",
            "destination_process_counts": {},
            "top_source_asset_name": "",
            "source_asset_name_counts": {},
        }

        df: pd.DataFrame = pd.json_normalize(activities)

        df["destination"] = df["dst.fqdn"].fillna(df["dst.ip"]).astype(str)
        df['protocol_port'] = df['protocol'] + '/' + df['dst.port'].astype(str)
        df['destination_on_port_protocol'] = df['destination'] + ':' + df['protocol_port']
        df["source_process_no_pid"] = (
            df["src.processName"].astype(str).str.replace(r"\s\(\d+\)$", "", regex=True)
        )
        df["destination_process_no_pid"] = (
            df["dst.processName"].astype(str).str.replace(r"\s\(\d+\)$", "", regex=True)
        )

        destination_counts: dict[str, int] = df["destination"].value_counts().to_dict()
        destination_counts = dict(sorted(destination_counts.items(), key=lambda x: x[1], reverse=True))
        top_destination: str = max(destination_counts, key=destination_counts.get)
        top_stats["top_destination"] = top_destination
        top_stats["destination_counts"] = destination_counts

        destination_on_port_protocol_counts: dict[str, int] = df["destination_on_port_protocol"].value_counts().to_dict()
        destination_on_port_protocol_counts = dict(sorted(destination_on_port_protocol_counts.items(), key=lambda x: x[1], reverse=True))
        top_destination_on_port_protocol: str = max(destination_on_port_protocol_counts, key=destination_on_port_protocol_counts.get)
        top_stats["top_destination_on_port_protocol"] = top_destination_on_port_protocol
        top_stats["destination_on_port_protocol_counts"] = destination_on_port_protocol_counts

        port_protocol_counts: dict[str, int] = df["protocol_port"].value_counts().to_dict()
        port_protocol_counts = dict(sorted(port_protocol_counts.items(), key=lambda x: x[1], reverse=True))
        top_port_protocol: str = max(port_protocol_counts, key=port_protocol_counts.get)
        top_stats["top_port_protocol"] = top_port_protocol
        top_stats["port_protocol_counts"] = port_protocol_counts

        source_process_counts = df.loc[df['source_process_no_pid'].notna() & (df['source_process_no_pid'] != ''), 'source_process_no_pid'].value_counts()
        source_process_counts = dict(sorted(source_process_counts.items(), key=lambda x: x[1], reverse=True))
        top_source_process: str = max(source_process_counts, key=source_process_counts.get)
        top_stats["top_source_process"] = top_source_process
        top_stats["source_process_counts"] = source_process_counts

        destination_process_counts = df.loc[df['destination_process_no_pid'].notna() & (df['destination_process_no_pid'] != ''), 'destination_process_no_pid'].value_counts()        
        destination_process_counts = dict(sorted(destination_process_counts.items(), key=lambda x: x[1], reverse=True))
        top_destination_process: str = max(destination_process_counts, key=destination_process_counts.get)
        top_stats["top_destination_process"] = top_destination_process
        top_stats["destination_process_counts"] = destination_process_counts

        source_asset_name_counts: dict[str, int] = df["src.srcAssetName"].value_counts().to_dict()
        source_asset_name_counts = dict(sorted(source_asset_name_counts.items(), key=lambda x: x[1], reverse=True))
        top_source_asset_name: str = max(source_asset_name_counts, key=source_asset_name_counts.get)
        top_stats["top_source_asset_name"] = top_source_asset_name
        top_stats["source_asset_name_counts"] = source_asset_name_counts

        return top_stats

    @staticmethod
    def _get_activity_counts_by_rmml(rmmls: list[dict[str, Any]]) -> dict[str, Any]:
        logger.debug("Getting activity counts by RMML...")
        rmml_counts: dict[str, str|int|dict[str, int]] = {
            "unique_rmms_seen": len(rmmls),
            "most_seen_rmml_name": "",
            "most_seen_rmml_id": "",
            "total_activities_all_rmmls": 0,
            "total_executable_activities_all_rmmls": 0,
            "total_domain_activities_all_rmmls": 0,
            "total_port_activities_all_rmmls": 0,
            "rmml_activities_counts": {}
        }
        

        # track the largest count seen so far
        largest_count: int = 0

        # Iterate through each RMML and various counts of activities to the rmml_counts dictionary
        for rmml in rmmls:
            rmml_all_activities_count: int = len(rmml.get("unique_activities_map", []))
            len_executable_activities: int = len(rmml.get("executable_activities_discovered", []))
            len_domain_activities: int = len(rmml.get("domain_activities_discovered", []))
            len_port_activities: int = len(rmml.get("port_activities_discovered", []))

            # Update the largest count seen so far
            if rmml_all_activities_count > largest_count:
                largest_count = rmml_all_activities_count
                rmml_counts["most_seen_rmml_name"] = rmml.get("rmm_name")
                rmml_counts["most_seen_rmml_id"] = rmml.get("rmm_id")

            rmml_counts["total_activities_all_rmmls"] += rmml_all_activities_count
            rmml_counts["total_executable_activities_all_rmmls"] += len_executable_activities
            rmml_counts["total_domain_activities_all_rmmls"] += len_domain_activities
            rmml_counts["total_port_activities_all_rmmls"] += len_port_activities

            rmml_counts["rmml_activities_counts"][rmml.get("rmm_name")] = {
                "total_activities": rmml_all_activities_count,
                "executable_activities": len_executable_activities,
                "domain_activities": len_domain_activities,
                "port_activities": len_port_activities,
            }

        return rmml_counts

    ####################################
    # Format/print/export results
    ####################################
    def _export_all_indicating_activities_to_csv(self, rmmls: list[dict[str, Any]]) -> None:
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


    def _log_macro_level_statistics(self, macro_stats: dict[str, Any]) -> None:
        
        """
        Log macro-level statistics in tabular format.
        """
        # Prepare table data
        table_data = [
            {
                "Metric": "Total RMMs Observed",
                "Value": macro_stats.get('rmm_counts',{}).get("unique_rmms_seen", 0)
            },
            {
                "Metric": "Most Seen RMM",
                "Value": f"{macro_stats.get('rmm_counts',{}).get("most_seen_rmml_name", "N/A")} - {macro_stats.get('rmm_counts',{}).get("most_seen_rmml_id", "N/A")}"
            },
            {
                "Metric": "Total number of activities matching RMM signatures",
                "Value": macro_stats.get('rmm_counts',{}).get("total_activities_all_rmmls", 0)
            },
            {
                "Metric": "Total number of executable activities that match RMM signatures",
                "Value": macro_stats.get('rmm_counts',{}).get("total_executable_activities_all_rmmls", 0)
            },
            {
                "Metric": "Total number of domain activities that match RMM signatures",
                "Value": macro_stats.get('rmm_counts',{}).get("total_domain_activities_all_rmmls", 0)
            },
            {
                "Metric": "Total number of port activities that match RMM signatures",
                "Value": macro_stats.get('rmm_counts',{}).get("total_port_activities_all_rmmls", 0)
            },
        ]
        
        # Create table string
        table_str = tabulate(table_data, headers="keys", tablefmt="grid", showindex=False)
        
        # Log entire table at once
        logger.info(f"\n{'='*80}\nHigh Level Macro-Level Statistics\n{'='*80}\n{table_str}\n{'='*80}")

        rmm_table_data = []
        for rmm_name,stats in macro_stats.get("rmm_counts", {}).get("rmml_activities_counts", {}).items():
            rmm_table_data.append({
                "RMM Name": rmm_name,
                "Activities Count": stats.get("total_activities"),
                "Executable Activities Count": stats.get("executable_activities"),
                "Domain Activities Count": stats.get("domain_activities"),
                "Port Activities Count": stats.get("port_activities"),
            })

        rmm_table_str = tabulate(rmm_table_data, headers="keys", tablefmt="grid", showindex=False)
        logger.info(f"\n{'='*80}\nRMMs Observed by Activity Count\n{'='*80}\n{rmm_table_str}\n{'='*80}")

        destination_port_protocol_table_data = []
        for destination,count in dict(list(macro_stats.get('aggregated_top_stats').get("destination_on_port_protocol_counts", {}).items())[:10]):
            destination_port_protocol_table_data.append({
                "Destination": destination,
                "Count": count,
            })

        destination_port_protocol_table_str = tabulate(destination_port_protocol_table_data, headers="keys", tablefmt="grid", showindex=False)
        logger.info(
            f"\n{'='*80}\nTop 10 destinations by protocol/port and activity count\n{'='*80}\n"
            f"Top Destination by Protocol/Port:\t{macro_stats.get('aggregated_top_stats').get('top_destination_on_port_protocol')}"
            f"\n{'='*80}"
            f"\n{destination_port_protocol_table_str}\n{'='*80}"
        )

        source_process_table_data = []
        for source_process,count in dict(list(macro_stats.get('aggregated_top_stats').get("source_process_counts", {}).items())[:10]):
            source_process_table_data.append({
                "Source Process": source_process,
                "Count": count,
            })

        source_process_table_str = tabulate(source_process_table_data, headers="keys", tablefmt="grid", showindex=False)
        logger.info(
            f"\n{'='*80}\nTop 10 source processes by activity count\n{'='*80}\n"
            f"Top Source Process:\t{macro_stats.get('aggregated_top_stats').get('top_source_process')}"
            f"\n{'='*80}"
            f"\n{source_process_table_str}\n{'='*80}"
        )

        destination_process_table_data = []
        for destination_process,count in dict(list(macro_stats.get('aggregated_top_stats').get("destination_process_counts", {}).items())[:10]):
            destination_process_table_data.append({
                "Destination Process": destination_process,
                "Count": count,
            })

        destination_process_table_str = tabulate(destination_process_table_data, headers="keys", tablefmt="grid", showindex=False)
        logger.info(
            f"\n{'='*80}\nTop 10 destination processes by activity count\n{'='*80}\n"
            f"Top Destination Process:\t{macro_stats.get('aggregated_top_stats').get('top_destination_process')}"
            f"\n{'='*80}"
            f"\n{destination_process_table_str}\n{'='*80}"
        )

        source_asset_name_table_data = []
        for source_asset_name,count in dict(list(macro_stats.get('aggregated_top_stats').get("source_asset_name_counts", {}).items())[:10]):
            source_asset_name_table_data.append({
                "Source Asset Name": source_asset_name,
                "Count": count,
            })

        source_asset_name_table_str = tabulate(source_asset_name_table_data, headers="keys", tablefmt="grid", showindex=False)
        logger.info(
            f"\n{'='*80}\nTop 10 source assets by activity count\n{'='*80}\n"
            f"Top Source Asset Name:\t{macro_stats.get('aggregated_top_stats').get('top_source_asset_name')}"
            f"\n{'='*80}"
            f"\n{source_asset_name_table_str}\n{'='*80}"
        )

        return None

    ####################################
    # Functions to drive each section of hunt workflow
    ####################################

    def _start_multithreaded_hunt(self, from_timestamp: int | str, to_timestamp: int | str) -> list[dict[str, Any]]:
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
        logger.info("Preparing data for analysis...")
        filter_rmmls_with_indicators: list[dict[str, Any]] = self._filter_results_to_only_include_rmmls_with_indicators(results=results)
        normalized_rmmls_with_indicators: list[dict[str, Any]] = self._deduplicate_and_decode_rmml_activities(rmmls=filter_rmmls_with_indicators)
        self.all_indicating_activities = self._aggregate_all_activities_into_list(rmmls=normalized_rmmls_with_indicators)
        return normalized_rmmls_with_indicators

    ############################################################
    # Main functions to execute the hunt
    ############################################################

    def execute_hunt(self, from_timestamp: str, to_timestamp: Optional[str] = None, **kwargs: Optional[dict[str, Any]]):
        #TODO refactor and re-organize execution sequence to
        # 1. Hunt activities
        # 2. Filter results to only include RMMLs with indicators
        # 3. Normalize results
        # 4. Export results to CSV
        # 5. Execute macro-level analysis
        # 6. Log macro-level statistics
        # 6. Execute advanced-level analysis
        # 7. Log advanced-level statistics
        # 8. Return results
        
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

        # 4. Run analytics workflows
        # If kwargs have no_basic_stats = True, this conditional will
        # skip the macro-level analysis 
        if not kwargs.get("no_basic_stats", False):
            macro_stats: dict[str, Any] = self._run_macro_analysis(rmmls=prepared_data)
            self._log_macro_level_statistics(macro_stats=macro_stats)
        
        # If kwargs have advanced_stats = True, this conditional will
        # run the advanced-level analysis
        if kwargs.get("advanced_stats", False):
            logger.info("Running advanced-level analysis...")
            advanced_stats: dict[str, Any] = self._get_advanced_stats(results=prepared_data)
        logger.info("Analysis and reporting workflows completed...")
        return prepared_data
