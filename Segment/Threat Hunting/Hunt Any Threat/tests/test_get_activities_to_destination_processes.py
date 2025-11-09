"""
Tests for ZeroThreatHuntTools.get_activities_to_destination_processes method.
"""

import pytest

from src.zero_threat_hunt_exceptions import ZeroThreatHuntInvalidFilter, ZeroThreatHuntInvalidValues


class TestGetActivitiesToDestinationProcesses:
    """
    Test suite for get_activities_to_destination_processes method.
    """

    @pytest.fixture
    def process_paths(self) -> list[str]:
        """
        Fixture providing test process paths.

        :return: List of test process path strings
        :rtype: list[str]
        """
        return [
            "/usr/bin/curl",
            "C:\\Windows\\System32\\cmd.exe",
            "OneDrive.exe",
            "onedrive.exe",
            "msedge.exe",
            "chrome.exe",
        ]

    def test_get_activities_to_destination_processes_basic(
        self, threat_hunt_tools, process_paths, from_timestamp
    ) -> None:
        """
        Test basic functionality of get_activities_to_destination_processes.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param process_paths: Test process paths fixture
        :type process_paths: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_processes(
            [process_paths[0]], from_timestamp=from_timestamp
        )

        assert isinstance(activities, list)

        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_to_destination_processes_with_timestamp(
        self, threat_hunt_tools, process_paths, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_processes with timestamp filters.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param process_paths: Test process paths fixture
        :type process_paths: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_processes(
            process_paths, from_timestamp=from_timestamp, to_timestamp=to_timestamp
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_processes_with_iso8601_z(
        self, threat_hunt_tools, process_paths, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_processes with ISO8601 timestamp using Z format.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param process_paths: Test process paths fixture
        :type process_paths: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_processes(
            process_paths,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_processes_with_timezone_offset(
        self, threat_hunt_tools, process_paths, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_processes with ISO8601 timestamp using timezone offset.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param process_paths: Test process paths fixture
        :type process_paths: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_processes(
            process_paths,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_processes_with_limit(
        self, threat_hunt_tools, process_paths, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_processes with limit parameter.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param process_paths: Test process paths fixture
        :type process_paths: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_processes(
            process_paths, from_timestamp=from_timestamp, limit=50
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_processes_empty_list(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_processes with empty list raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidFilter):
            threat_hunt_tools.get_activities_to_destination_processes(
                [], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_processes_invalid_type(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_processes with invalid process path type raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_destination_processes(
                [123, "/usr/bin/bash"], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_processes_multiple_paths(
        self, threat_hunt_tools, process_paths, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_processes with multiple process paths.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param process_paths: Test process paths fixture
        :type process_paths: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_processes(
            process_paths, from_timestamp=from_timestamp
        )

        assert isinstance(activities, list)
