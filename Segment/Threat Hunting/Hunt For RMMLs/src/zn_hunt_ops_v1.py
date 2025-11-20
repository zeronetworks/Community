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

    ############################################################
    # Functions to normalize RMMLs with indicators (part of anaylsis)
    ############################################################

    def _normalize_rmml_with_indicators(
        self, rmml: dict[str, str | list[dict[str, Any]] | list[str]]
    ) -> dict[str, str | list[dict[str, Any]] | list[str]]:
        """
        Analyze an RMML that has indicators and return a summary of the findings.
        """
        logger.info(
            f"Normalizing results for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        rmml = self._get_unique_rmml_activities(rmml=rmml)
        rmml = self._transform_unique_activities_to_human_readable(rmml=rmml)
        logger.info(
            f"Normalized indicators for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        return rmml

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
            asset_name = (
                self._zero_threat_hunt_tools.api.get(endpoint=f"/assets/{asset_id}")
                .get("entity", {})
                .get("name", "N/A")
            )
            self.asset_id_to_asset_name_map[asset_id] = asset_name
            return asset_name

    ############################################################
    # Functions to perform data analysis on RMMLs
    ############################################################

    def analyze_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Analyze the results of the hunt and return a summary of the findings.
        """
        logger.info(f"Analyzing results for {len(results)} RMMLs...")

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
        for rmml in rmmls_with_indicators:
            rmml = self._normalize_rmml_with_indicators(rmml=rmml)
            rmml_analysis_results = self._run_statistical_analysis(rmml=rmml)
            rmml.update({"analysis": rmml_analysis_results})

        return rmmls_with_indicators

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
    #
    # Format/print/export results
    #
    ####################################
    def _export_all_indicating_activities_to_csv(self, rmmls: list[dict[str, Any]]) -> None:
        logger.info(
            f"Exporting all indicating activities to CSV for {len(rmmls)} RMMLs..."
        )

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

        # Convert the list of activities to a pandas DataFrame
        df: pd.DataFrame = pd.json_normalize(all_indicating_activities)

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
            f"Exported {len(all_indicating_activities)} indicating activities to CSV file: {filename}..."
        )

    def _run_reporting_workflow(self, rmmls: list[dict[str, Any]]) -> None:
        logger.info("Running reporting workflow...")
        self._export_all_indicating_activities_to_csv(rmmls=rmmls)
        #TODO add statistics functions at a macro level to analyze which RMMs most common, etc
        # TODO create string with statistics per RMML - log and save to .txt
        logger.info("Reporting workflow completed...")

    ####################################
    # Functions to execute the hunt
    ####################################

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
                logger.warning(
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

    ############################################################
    # Main functions to execute the hunt
    ############################################################

    def execute_hunt(self, from_timestamp: str, to_timestamp: Optional[str] = None):

        logger.info("Starting RRMs hunt...")
        # Get the start and end timestamps
        if not to_timestamp:
            to_timestamp = str(self._zero_threat_hunt_tools.datetime_to_timestamp_ms(datetime.now()))
            logger.debug(
                f"Converted to_timestamp to milliseconds since epoch: {to_timestamp}"
            )

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

        rmmls_with_analysis: list[dict[str, Any]] = self.analyze_results(results=results)
        self._run_reporting_workflow(rmmls=rmmls_with_analysis)

        return results
