import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from loguru import logger

from src.rmmdata import RMMData
from src.zero_threat_hunt_tools.zero_threat_hunt_tools import ZeroThreatHuntTools

"""
    This is needed as some of the attribute keys returned by the API 
    do not match their respective attribute names returned from the 
    /activities/network/filters endpoint.
"""
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

    ############################################################
    # Helper Functions
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
                logger.info(f"Loaded {len(additional_filter_mappings)} additional filter mappings from {path}...")
            return network_filters
        else:
            logger.warning(f"Additional filter mappings file does not exist at {path}. Skipping...")
        return {}

    ############################################################
    # Initialization
    ############################################################
    def __init__(self, api_key: str, rmm_data: RMMData, zn_base_url: Optional[str] = None):
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
    # Functions to analyze and format results
    ############################################################
    def analyze_results(self, results: list[dict[str, Any]]) -> None:
        """
        Analyze the results of the hunt and return a summary of the findings.
        """
        logger.info(f"Analyzing {len(results)} RMMLs...")
        # Filter to only results that have >1 activities in exectuables, domains, or port activities
        rmmls_within_indicators: list[dict[str, str | list[dict[str, Any]] | list[str]]] = [
            result
            for result in results
            if (
                len(result.get("executable_activities_discovered", [])) > 0
                or len(result.get("domain_activities_discovered", [])) > 0
                or len(result.get("port_activities_discovered", [])) > 0
            )
        ]

        logger.info(
            f"Filtered RRMLs to a resultant set of {len(rmmls_within_indicators)} RMMLs which have indicators..."
        )
        for rmml in rmmls_within_indicators:
            self._normalize_rmml_with_indicators(rmml=rmml)

        return None


    ############################################################
    # Functions to perform data analysis on RMMLs
    ############################################################
    def _analyze_rmml_with_indicators(self, rmml: dict[str, str | list[dict[str, Any]] | list[str]]) -> dict[str,Any]:
        """
        Analyze an RMML that has indicators and return a summary of the findings.
        """
        logger.info(f"Analyzing RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")

        count_of_indicating_activities_by_indicator_type: dict[str, int] = self._get_sum_of_each_indicator_type(rmml=rmml)
        top_indicator_type: str = max(count_of_indicating_activities_by_indicator_type.items(), key=lambda x: x[1])[0]
        top_destinations: dict[str, int] = self._get_unique_destinations_and_count(rmml=rmml)

        rmml_analysis_results: dict[str, Any] = {
            "rmm_name": rmml.get("rmm_name"),
            "rmm_id": rmml.get("rmm_id"),
            "indicating_activities": rmml.get("unique_activities_map"),
            'statistics': {
                'total_indicating_activities': len(rmml.get("unique_activities_map",[])),
            },
            'aggregations': {
                'top_indicator_type': top_indicator_type,
                'count_of_indicating_activities_by_indicator_type': count_of_indicating_activities_by_indicator_type,
                'top_destinations': top_destinations,
            }
        }
        #TODO write function to return top domain, top ports, top processes
        return rmml_analysis_results

    @staticmethod
    def _get_unique_destinations_and_count(rmml: dict[str, str | list[dict[str, Any]] | list[str]]) -> dict[str,int]:
        logger.trace(f"Calculating top destinations for {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")
        # TODO finish this function
        for unique_activity_info in rmml.get('unique_activities_map',[]):
            dst: str = unique_activity_info.get('activity',{}).get(f"dst",{}).get('dstAsset',"")
            dst_fqdn: str = unique_activity_info.get('activity',{}).get(f"dst",{}).get('fqdn',"")


    
    def _get_sum_of_each_indicator_type(self, rmml: dict[str, Any]) -> dict[str, Any]:
        """
        Get the indicating activities by indicator type.
        """
        return {
            'executable': len([activity for activity in rmml.get("unique_activities_map", []) if activity.get("indicators", {}).get("executable", False)]),
            'domain': len([activity for activity in rmml.get("unique_activities_map", []) if activity.get("indicators", {}).get("domain", False)]),
            'port': len([activity for activity in rmml.get("unique_activities_map", []) if activity.get("indicators", {}).get("port", False)]),
        }

    ############################################################
    # Functions to normalize RMMLs with indicators (part of anaylsis)
    ############################################################
    def _normalize_rmml_with_indicators(self, rmml: dict[str, str | list[dict[str, Any]] | list[str]]) -> None:
        # TODO finish this function
        """
        Analyze an RMML that has indicators and return a summary of the findings.
        """
        logger.info(f"Normalizing indicators for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")
        rmml = self._get_unique_rmml_activities(rmml=rmml)
        rmml = self._transform_unique_activities_to_human_readable(rmml=rmml)
        logger.info(f"Normalized indicators for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")
        return rmml


    def _get_unique_rmml_activities(
        self, rmml: dict[str, str | list[dict[str, Any]] | list[str]]
    ) -> dict[str, str | list[dict[str, Any]] | list[str]]:
        logger.debug(f"Finding unique indicator activities for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")
        hashed_activities: dict[str, dict[str, dict[str, bool] | dict[str, Any]]] = {}
        if len(rmml.get("executable_activities_discovered", [])) > 0:
            for activity in rmml.get("executable_activities_discovered", []):
                hashed_activities = self.__is_activity_unique(
                    activity=activity,
                    indicator_type="executable",
                    hashed_activities=hashed_activities,
                )
        if len(rmml.get("domain_activities_discovered", [])) > 0:
            for activity in rmml.get("domain_activities_discovered", []):
                hashed_activities = self.__is_activity_unique(
                    activity=activity,
                    indicator_type="domain",
                    hashed_activities=hashed_activities,
                )
        if len(rmml.get("port_activities_discovered", [])) > 0:
            for activity in rmml.get("port_activities_discovered", []):
                hashed_activities = self.__is_activity_unique(
                    activity=activity,
                    indicator_type="port",
                    hashed_activities=hashed_activities,
                )
        logger.debug(
            f"Found {len(hashed_activities)} unique indicator activities for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}..."
        )
        rmml.update({"unique_activities_map": list(hashed_activities.values())})
        return rmml


    @staticmethod
    def __is_activity_unique(
        activity: dict[str, Any], indicator_type: str, hashed_activities: dict[str, Any]
    ) -> dict[str, dict[str, bool] | dict[str, Any]]:
        # Hash a string dump of the activity dictionary
        dict_str = json.dumps(activity, sort_keys=True, default=str)
        logger.trace(f"Hashing activity: {dict_str}...")
        hashed_activity: str = hashlib.sha256(dict_str.encode()).hexdigest()
        logger.trace(f"SHA256 hash of activity: {hashed_activity}...")

        # Check if the activity is already in the map
        if hashed_activity not in hashed_activities:
            logger.trace(f"Activity: {activity} does not exist in hashed_activities map. Adding it...")
            # If the activity is not in the map, add it, and add the indicator type to indicators
            hashed_activities.update(
                {
                    hashed_activity: {
                        "indicators": {
                            indicator_type: True,
                        },
                        "activity": activity,
                    }
                }
            )
            logger.trace(
                f"Added new activity hash {hashed_activity} to hashed_activities map with indicator: {indicator_type}..."
            )
        else:
            logger.trace(
                f"Activity has {hashed_activity} already exists in hashed_activities map. Adding indicator: {indicator_type}..."
            )
            hashed_activities[hashed_activity]["indicators"].update({indicator_type: True})
            logger.trace(
                f"Updated activity hash {hashed_activity} in hashed_activities map with indicator: {indicator_type}..."
            )
        return hashed_activities



    def _transform_unique_activities_to_human_readable(
        self, rmml: dict[str, str | list[dict[str, Any]] | list[str]]
    ) -> dict[str, str | list[dict[str, Any]] | list[str]]:
        if len(rmml.get("unique_activities_map", [])) > 0:
            for activity in rmml.get("unique_activities_map", []):
                # If the integer timestamp is present in the activity, add a new human readable ISO8601 timestamp
                if activity.get("activity", {}).get("timestamp", None) and isinstance(
                    activity.get("activity", {}).get("timestamp"), int
                ):
                    # Add a new key/value -> "iso_timestamp" to the activity, set to the timestamp converted to ISO8601 format (UTC timezone)
                    activity.get("activity", {}).update(
                        {
                            "iso_timestamp": datetime.fromtimestamp(
                                activity.get("activity", {}).get("timestamp")/1000,
                                tz=timezone.utc
                            ).isoformat()
                        }
                    )
                # The function called here will recsurively enumerate all key/value pairs in the activity, 
                # and transform the key/values that are integer IDs (like protocolType=2) to human readable values (like "TCP")
                activity = self._recursively_transform_all_id_values_to_human_readable(
                    data=activity.get("activity", {})
                )
        else:
            logger.warning(f"No unique activities map found for RMML: {rmml.get('rmm_name')} - {rmml.get('rmm_id')}...")

        return rmml


    def _recursively_transform_all_id_values_to_human_readable(self, data: dict[str, Any]) -> Any:
        for key, value in data.items():
            if isinstance(value, int) or isinstance(value, str):
                logger.trace(f"Key: {key} is a {type(value)}. Value: {value}")

                # I found that some attributes returned in activities
                # did not match the field names in network filters
                # So to dynamically map them to human-readable values,
                # we need to map the inconsistent field names to thier
                # respective network filter field names.

                # We have to have two key variables because the if we
                # update the key variable, we will lose the original key value.
                # So og_key will be used to update the data in the dictionary,
                # so the original attribute name is preserved.
                og_key: str = key
                if key in INCONSISTENT_FIELD_NAME_MAP:
                    logger.trace(
                        f"Key: {key} is inconsistent with the network filter field name. Mapping to consistent name..."
                    )
                    key = INCONSISTENT_FIELD_NAME_MAP.get(og_key)
                    logger.trace(f"Mapped key: {og_key} to {key}")

                # If a network filter exists for the key, and it has a selectionsById dictionary,
                # we can map the value to a human-readable value by looking up the value in the selectionsById dictionary.
                if (
                    network_filter := self._zero_threat_hunt_tools.network_filters.get(key)
                ) and "selectionsById" in network_filter:
                    logger.trace(f"Key: {key} maps to a network filter. Mapping value to human readable...")
                    # Get the mapping value (human readable value) from the selectionsById dictionary.
                    value_from_id = network_filter.get("selectionsById", {}).get(str(value), value)
                    # Update the activity data to have human readable value.
                    data.update({og_key: value_from_id})
                    logger.trace(f"Updated value for key: {og_key} from {value} to: {value_from_id}")
                    value_from_id = None
                else:
                    # TODO need to submit a dev bug stating that API attributes names and filter field names are not consistent
                    if isinstance(value, int) and key != "timestamp" and key != "port" and key != "ipThreatScore" and key != "eventRecordId" and key != "processId" and key != "updateId" and key != "ipSpace":
                        print("Test")
                    logger.trace(f"Key: {key} does not map to a network filter. Skipping...")
                    continue
            elif isinstance(value, list):
                logger.trace(f"Key: {key} is a list. Value: {value}")
                for item in value:
                    item = self._recursively_transform_all_id_values_to_human_readable(data=item)
            elif isinstance(value, dict):
                logger.trace(f"Key: {key} is a dict. Resurcively enumerating all nested fields...")
                value = self._recursively_transform_all_id_values_to_human_readable(data=value)
        return data


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
        for os, executables in os_executables.items():
            logger.trace(f"Building filters for {len(executables)} {os} executables...")
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
    # Main functions to execute the hunt
    ############################################################
    def execute_hunt(self, from_timestamp: str, to_timestamp: Optional[str] = None):
        logger.info("Starting RRMs hunt...")
        # Get the start and end timestamps
        if not to_timestamp:
            to_timestamp = str(self._zero_threat_hunt_tools.datetime_to_timestamp_ms(datetime.now()))
            logger.debug(f"Converted to_timestamp to milliseconds since epoch: {to_timestamp}")

        results: list[dict[str, Any]] = []
        # TODO add multithreading to speed up the hunt
        for rmm in self.rmm_data.rmm_simplified_list:
            results.append(self._hunt_for_rmm(rmm=rmm, from_timestamp=from_timestamp, to_timestamp=to_timestamp))

        logger.info(f"Finished hunting for {len(results)} RMMLs...")

        logger.info("Analyzing results...")
        self.analyze_results(results=results)
        logger.info("Returning results...")

        return results


    def _hunt_for_rmm(self, rmm: dict[str, Any], from_timestamp: int | str, to_timestamp: int | str) -> dict[str, Any]:
        logger.info(f"Starting hunt for RMM: {rmm.get('meta',{}).get('name')} - {rmm.get('meta').get('id')}")

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

        params: dict[str, Any] = {
            "order": "desc",
            "from": from_timestamp,
            "to": to_timestamp,
        }

        filter_holder: dict[str, Any] = self._build_filters_for_rmm(rmm=rmm)

        # Search for activities that are sourced FROM a listed executable
        if filter_holder.get("srcProcessPath"):
            logger.debug(f"Searching for activities from source processes: {filter_holder.get('srcProcessPath')}")
            src_process_path_activities = self._zero_threat_hunt_tools.get_activities_from_source_processes(
                process_paths=filter_holder.get("srcProcessPath").get("includeValues"),
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
            )
            logger.debug(
                f"Found {len(src_process_path_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
            )

        # Search for activities that are sourced FROM a listed executable
        if filter_holder.get("dstProcessPath"):
            logger.debug(f"Searching for activities to destination processes: {filter_holder.get('dstProcessPath')}")
            dst_process_path_activities = self._zero_threat_hunt_tools.get_activities_to_destination_processes(
                process_paths=filter_holder.get("dstProcessPath").get("includeValues"),
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
            )
            logger.debug(
                f"Found {len(dst_process_path_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
            )

        if filter_holder.get("dstAsset"):
            logger.debug(f"Searching for activities to domains: {filter_holder.get('dstAsset')}")
            dst_asset_activities = self._zero_threat_hunt_tools.get_activities_to_domains(
                domains=filter_holder.get("dstAsset").get("includeValues"),
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
            )
            logger.debug(
                f"Found {len(dst_asset_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
            )

        if filter_holder.get("dstPort"):
            # If only ports are 80 and 443, avoid searching for them
            # Do not want to remove from original list (for reporting)
            # So, we will create a copy to validate with
            port_validation_list: list[int] = filter_holder.get("dstPort").get("includeValues").copy()
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
                    f"Found {len(dst_port_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
                )
            else:
                logger.warning(
                    f"No ports to search for other than 80 and 443 for {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}. Skipping search as these are common ports..."
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

        logger.info(f"Finished hunting for {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}...")
        return results
