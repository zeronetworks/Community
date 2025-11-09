"""
Tests for ZeroThreatHuntTools.get_activities_to_destination_ips method.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.zero_threat_hunt_exceptions import ZeroThreatHuntInvalidValues


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
        self, threat_hunt_tools, ip_addresses
    ) -> None:
        """
        Test basic functionality of get_activities_to_destination_ips.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(ip_addresses)

        assert isinstance(activities, list)

        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_to_destination_ips_with_timestamp(
        self, threat_hunt_tools, ip_addresses
    ) -> None:
        """
        Test get_activities_to_destination_ips with timestamp filters.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        """
        one_week_ago = datetime.now(timezone.utc) - timedelta(weeks=1)
        now = datetime.now(timezone.utc)

        from_timestamp = one_week_ago.isoformat()
        to_timestamp = now.isoformat()

        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses, from_timestamp=from_timestamp, to_timestamp=to_timestamp
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_with_iso8601_z(
        self, threat_hunt_tools, ip_addresses
    ) -> None:
        """
        Test get_activities_to_destination_ips with ISO8601 timestamp using Z format.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses,
            from_timestamp="2024-01-01T00:00:00Z",
            to_timestamp="2024-12-31T23:59:59Z",
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_with_timezone_offset(
        self, threat_hunt_tools, ip_addresses
    ) -> None:
        """
        Test get_activities_to_destination_ips with ISO8601 timestamp using timezone offset.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses,
            from_timestamp="2024-01-01T00:00:00-05:00",
            to_timestamp="2024-12-31T23:59:59-05:00",
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_with_limit(
        self, threat_hunt_tools, ip_addresses
    ) -> None:
        """
        Test get_activities_to_destination_ips with limit parameter.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_destination_ips(
            ip_addresses, limit=50
        )

        assert isinstance(activities, list)

    def test_get_activities_to_destination_ips_empty_list(
        self, threat_hunt_tools
    ) -> None:
        """
        Test get_activities_to_destination_ips with empty list raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_destination_ips([])

    def test_get_activities_to_destination_ips_invalid_type(
        self, threat_hunt_tools
    ) -> None:
        """
        Test get_activities_to_destination_ips with invalid IP address type raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_destination_ips([123, "192.168.1.1"])

    def test_get_activities_to_destination_ips_multiple_ips(
        self, threat_hunt_tools, ip_addresses
    ) -> None:
        """
        Test get_activities_to_destination_ips with multiple IP addresses.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param ip_addresses: Test IP addresses fixture
        :type ip_addresses: list[str]
        """
        ip_addresses.append("172.16.0.0/12")
        activities = threat_hunt_tools.get_activities_to_destination_ips(ip_addresses)

        assert isinstance(activities, list)
