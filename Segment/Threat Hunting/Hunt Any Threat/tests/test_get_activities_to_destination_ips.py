"""
Tests for ZeroThreatHuntTools.get_activities_to_destination_ips method.
"""

import pytest

from src.zero_threat_hunt_exceptions import ZeroThreatHuntInvalidFilter, ZeroThreatHuntInvalidValues


class TestGetActivitiesToDestinationIPs:
    """
    Test suite for get_activities_to_destination_ips method.
    """

    @pytest.fixture
    def ip_addresses(self) -> list[str]:
        """
        Fixture providing test IP addresses.

        :return: List of test IP address strings
        :rtype: list[str]
        """
        return ["10.0.0.0/8"]

    def test_get_activities_to_destination_ips_basic(
        self, threat_hunt_tools, ip_addresses, from_timestamp
    ) -> None:
        """
        Test basic functionality of get_activities_to_destination_ips.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses, from_timestamp=from_timestamp
        )

        assert isinstance(activities, list)

        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_to_destination_ips_with_timestamp(
        self, threat_hunt_tools, ip_addresses, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ips with timestamp filters.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses, from_timestamp=from_timestamp, to_timestamp=to_timestamp
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_with_iso8601_z(
        self, threat_hunt_tools, ip_addresses, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ips with ISO8601 timestamp using Z format.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_with_timezone_offset(
        self, threat_hunt_tools, ip_addresses, from_timestamp, to_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ips with ISO8601 timestamp using timezone offset.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        :param to_timestamp: Timestamp fixture for current time
        :type to_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_with_limit(
        self, threat_hunt_tools, ip_addresses, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ips with limit parameter.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses, from_timestamp=from_timestamp, limit=50
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_empty_list(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ips with empty list raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidFilter):
            threat_hunt_tools.get_activities_to_destination_ips(
                [], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_ips_invalid_type(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ips with invalid IP address type raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_destination_ips(
                [123, "192.168.1.1"], from_timestamp=from_timestamp
            )

    def test_get_activities_to_destination_ips_multiple_ips(
        self, threat_hunt_tools, ip_addresses, from_timestamp
    ) -> None:
        """
        Test get_activities_to_destination_ips with multiple IP addresses.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        ip_addresses.append("172.16.0.0/12")
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses, from_timestamp=from_timestamp
        )

        assert isinstance(activities, list)
