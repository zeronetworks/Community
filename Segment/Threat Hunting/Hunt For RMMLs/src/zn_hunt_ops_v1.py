import json
from datetime import datetime
from typing import Any, Optional

from loguru import logger

from src.rmmdata import RMMData
from src.zero_networks.api import ZeroNetworksAPI
from src.zero_threat_hunt_tools.zero_threat_hunt_tools import ZeroThreatHuntTools


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

    def __init__(
        self, api_key: str, rmm_data: RMMData, zn_base_url: Optional[str] = None
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

        self._zero_threat_hunt_tools: ZeroThreatHuntTools = ZeroThreatHuntTools(
            api_key=api_key, zn_base_url=zn_base_url
        )

        # Store the RMM data for use in hunting operations
        # This contains domains, processes, ports, and other indicators for RMM software
        self.rmm_data: RMMData = rmm_data
        logger.info(f"Loaded {len(self.rmm_data.rmm_list)} RMMLs into ZN Hunt Ops...")

        logger.info("ZN Hunt Ops initialized successfully...")

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
        src_process_path_filter: dict[str, Any] = (
            self._zero_threat_hunt_tools.filter_object_builder(
                field_name="srcProcessPath", include_values=src_process_path_list
            )
        )
        dst_process_path_filter: dict[str, Any] = (
            self._zero_threat_hunt_tools.filter_object_builder(
                field_name="dstProcessPath", include_values=dst_process_path_list
            )
        )

        # Return the filter objects for the source and destination process paths as a tuple
        return src_process_path_filter, dst_process_path_filter

    def _build_filters_for_rmm(self, rmm: dict[str, Any]) -> dict[str, Any]:
        filter_holder: dict[str, Any] = {}

        # Build filters for executables.
        # I want to build filters that can be used to filter for
        # traffic either coming FROM (source) or TO (destination) an executable.
        if rmm.get("executables"):
            src_process_path_filter, dst_process_path_filter = (
                self._rmm_process_path_builder(os_executables=rmm.get("executables"))
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

    def execute_hunt(self, from_timestamp: str, to_timestamp: Optional[str] = None):
        logger.info("Starting RRMs hunt...")
        # Get the start and end timestamps
        if not to_timestamp:
            to_timestamp = ZeroThreatHuntTools.datetime_to_timestamp_ms(datetime.now())
            logger.debug(
                f"Converted to_timestamp to milliseconds since epoch: {to_timestamp}"
            )

        results: list[dict[str, Any]] = []
        #TODO add multithreading to speed up the hunt
        for rmm in self.rmm_data.rmm_simplified_list:
            results.append(
                self._hunt_for_rmm(
                    rmm=rmm, from_timestamp=from_timestamp, to_timestamp=to_timestamp
                )
            )
        
        logger.info(f"Finished hunting for {len(results)} RMMLs... returning results...")
        return results

    def _hunt_for_rmm(
        self, rmm: dict[str, Any], from_timestamp: int, to_timestamp: int
    ) -> dict[str, Any]:
        logger.info(
            f"Starting hunt for RMM: {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}"
        )

        # Dictionary to hold results
        results: dict[str, Any] = {
            "rmm_name": rmm.get("meta").get("name"),
            "rmm_id": rmm.get("meta").get("id"),
            "rmm_executables": rmm.get("executables"),
            "rmm_domains": rmm.get("domains"),
            "rmm_ports": rmm.get("ports"),
            "has_indicators": False,
            "executable_activities_discovered": [],
            "domain_activities_discovered": [],
            "port_activities_discovered": [],
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
                to_timestamp=to_timestamp
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
                to_timestamp=to_timestamp
            )
            logger.debug(
                f"Found {len(dst_process_path_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
            )

        if filter_holder.get("dstAsset"):
            logger.debug(f"Searching for activities to domains: {filter_holder.get('dstAsset')}")
            dst_asset_activities = self._zero_threat_hunt_tools.get_activities_to_domains(
                domains=filter_holder.get("dstAsset").get("includeValues"),
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp
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
                    to_timestamp=to_timestamp
                )
                logger.debug(
                    f"Found {len(dst_port_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
                )
            else:
                logger.warning(f"No ports to search for other than 80 and 443 for {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}. Skipping search as these are common ports...")
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