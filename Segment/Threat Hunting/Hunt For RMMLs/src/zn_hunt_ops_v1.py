import json
from datetime import datetime
from typing import Any, Optional

from loguru import logger

from src.rmmdata import RMMData
from src.zero_networks.api import ZeroNetworksAPI
from src.zero_threat_hunt_tools import ZeroThreatHuntTools


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


    @staticmethod
    def rmm_process_path_builder(
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
        src_process_path_filter: dict[str, Any] = ZeroThreatHuntTools.filter_object_builder(
            field_name="srcProcessPath", include_values=src_process_path_list
        )
        dst_process_path_filter: dict[str, Any] = ZeroThreatHuntTools.filter_object_builder(
            field_name="dstProcessPath", include_values=dst_process_path_list
        )

        # Return the filter objects for the source and destination process paths as a tuple
        return src_process_path_filter, dst_process_path_filter

    @staticmethod
    def build_filters_for_rmm(rmm: dict[str, Any]) -> dict[str, Any]:
        filter_holder: dict[str, Any] = {}

        # Build filters for executables.
        # I want to build filters that can be used to filter for
        # traffic either coming FROM (source) or TO (destination) an executable.
        if rmm.get("executables"):
            src_process_path_filter, dst_process_path_filter = (
                ZNHuntOps.rmm_process_path_builder(
                    os_executables=rmm.get("executables")
                )
            )
            filter_holder["srcProcessPath"] = src_process_path_filter
            filter_holder["dstProcessPath"] = dst_process_path_filter

        # Build filters for domains.
        if rmm.get("domains"):
            domain_list: list[str] = rmm.get("domains")
            domain_filter: dict[str, Any] = ZeroThreatHuntTools.filter_object_builder(
                field_name="dstAsset", include_values=domain_list
            )
            filter_holder["dstAsset"] = domain_filter

        if rmm.get("ports"):
            # Build filters for ports.
            # Since 80 and 443 are really common, we will exclude them from ports that we filter for
            if 80 in rmm.get("ports"):
                logger.trace("Removing port 80 from ports list...")
                rmm.get("ports").remove(80)
            if 443 in rmm.get("ports"):
                logger.trace("Removing port 443 from ports list...")
                rmm.get("ports").remove(443)
            port_list: list[int] = rmm.get("ports")
            port_filter: dict[str, Any] = ZeroThreatHuntTools.filter_object_builder(
                field_name="dstPort", include_values=port_list
            )
            filter_holder["dstPort"] = port_filter

        return filter_holder

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

        # Initialize the Zero Networks API client
        # The API client will attempt to extract the base URL from the JWT if not provided
        self.api = ZeroNetworksAPI(api_key, zn_base_url)

        # Store the RMM data for use in hunting operations
        # This contains domains, processes, ports, and other indicators for RMM software
        self.rmm_data: RMMData = rmm_data
        logger.info(f"Loaded {len(self.rmm_data.rmm_list)} RMMLs into ZN Hunt Ops...")

        # Fetch and cache network activity filters from the API
        # These filters define what fields can be queried and their possible values
        self.network_filters: list[dict[str, Any]] = self._get_network_filters()
        logger.info(
            f"Loaded {len(self.network_filters)} network filters into ZN Hunt Ops..."
        )

        logger.info("ZN Hunt Ops initialized successfully...")


    def execute_hunt(self, from_timestamp: datetime):
        logger.info("Starting RRMs hunt...")
        # Get the start and end timestamps
        # Convert from_timestamp to milliseconds since epoch
        from_timestamp = self.datetime_to_timestamp_ms(from_timestamp)
        logger.debug(
            f"Converted from_timestamp to milliseconds since epoch: {from_timestamp}"
        )
        to_timestamp = self.datetime_to_timestamp_ms(datetime.now())
        logger.debug(
            f"Converted to_timestamp to milliseconds since epoch: {to_timestamp}"
        )

        results: list[dict[str, Any]] = []
        for rmm in self.rmm_data.rmm_simplified_list:
            results.append(
                self._hunt_for_rmm(
                    rmm=rmm, from_timestamp=from_timestamp, to_timestamp=to_timestamp
                )
            )

    
    def _hunt_for_rmm(
        self, rmm: dict[str, Any], from_timestamp: int, to_timestamp: int
    ) -> dict[str, Any]:
        logger.info(
            f"Starting hunt for RMM: {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}"
        )

        results: dict[str, Any] = {
            "rmm_name": rmm.get("meta").get("name"),
            "rmm_id": rmm.get("meta").get("id"),
            "has_indicators": False,
            "executable_activities": [],
            "domain_activities": [],
            "port_activities": [],
        }

        params: dict[str, Any] = {
            "order": "desc",
            "from": from_timestamp,
            "to": to_timestamp,
        }

        filter_holder: dict[str, Any] = self.build_filters_for_rmm(rmm=rmm)

        # Search for activities that are sourced FROM a listed executable
        if filter_holder.get("srcProcessPath"):
            params["_filters"] = ZNHuntOps._filter_json_builder(
                filter_holder["srcProcessPath"]
            )
            src_process_path_activities = self.get_activities(params=params)
            logger.debug(
                f"Found {len(src_process_path_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
            )

        # Search for activities that are sourced FROM a listed executable
        if filter_holder.get("dstProcessPath"):
            params["_filters"] = ZNHuntOps._filter_json_builder(
                filter_holder["dstProcessPath"]
            )
            dst_process_path_activities = self.get_activities(params=params)
            logger.debug(
                f"Found {len(dst_process_path_activities)} activities with traffic coming from an executable used by {rmm.get('meta').get('name')} - {rmm.get('meta').get('id')}..."
            )

