"""
Tests for ZeroThreatHuntTools.get_activities_to_destination_ports method.
"""

import pytest

from src.zero_threat_hunt_tools.zero_threat_hunt_exceptions import (
    ZeroThreatHuntInvalidFilter, ZeroThreatHuntInvalidValues)


class TestGetActivitiesToDestinationPorts:
    """
    Test suite for get_activities_to_destination_ports method.
    """

    @pytest.fixture
    def ports(self) -> list[int]:
        """
        Fixture providing test ports.

        :return: List of test port integers
        :rtype: list[int]
        """
        return [22, 3389, 445]

    def test_get_activities_to_destination_ports_basic(
        self, threat_hunt_tools, ports, from_timestamp
    ) -> None:
        """
        Test basic functionality of get_activities_to_destination_ports.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ports: Test ports fixture
        :type ports: list[int]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ports(
            ports, from_timestamp=from_timestamp
        )

        assert isinstance(activities, list)

        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_to_destination_ports_with_timestamp(
        self, threat_hunt_tools, ports, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with timestamp filters.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ports: Test ports fixture
        :type ports: list[int]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ports(
            ports, from_timestamp=from_timestamp, to_timestamp=to_timestamp
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ports_with_iso8601_z(
        self, threat_hunt_tools, ports, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with ISO8601 timestamp using Z format.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ports: Test ports fixture
        :type ports: list[int]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ports(
            ports,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ports_with_timezone_offset(
        self, threat_hunt_tools, ports, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with ISO8601 timestamp using timezone offset.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ports: Test ports fixture
        :type ports: list[int]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ports(
            ports,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ports_with_limit(
        self, threat_hunt_tools, ports, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with limit parameter.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ports: Test ports fixture
        :type ports: list[int]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ports(
            ports, from_timestamp=from_timestamp, limit=50
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ports_empty_list(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with empty list raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidFilter):
            threat_hunt_tools.get_activities_to_destination_ports(
                [], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_ports_invalid_type(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with invalid port type raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_destination_ports(
                ["443", 1234567], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_ports_out_of_range_low(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with port < 1 raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_destination_ports(
                [0, 443], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_ports_out_of_range_high(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with port > 65535 raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_destination_ports(
                [65536, 443], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_ports_valid_range(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with valid port range boundaries.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        ports = [1, 65535]

        activities = threat_hunt_tools.get_activities_to_destination_ports(
            ports, from_timestamp=from_timestamp
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ports_multiple_ports(
        self, threat_hunt_tools, ports, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ports with multiple ports.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ports: Test ports fixture
        :type ports: list[int]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ports(
            ports, from_timestamp=from_timestamp
        )

        assert isinstance(activities, list)
