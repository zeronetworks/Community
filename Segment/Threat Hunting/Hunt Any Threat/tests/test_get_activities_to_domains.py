"""
Tests for ZeroThreatHuntTools.get_activities_to_domains method.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.zero_threat_hunt_exceptions import ZeroThreatHuntInvalidValues


class TestGetActivitiesToDomains:
    """
    Test suite for get_activities_to_domains method.
    """

    @pytest.fixture
    def domains(self) -> list[str]:
        """
        Fixture providing test domains.

        :return: List of test domain strings
        :rtype: list[str]
        """
        return [
            "teamviewer.com",
            "microsoft.com",
            "msn.com",
        ]

    def test_get_activities_to_domains_basic(self, threat_hunt_tools, domains) -> None:
        """
        Test basic functionality of get_activities_to_domains.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param domains: Test domains fixture
        :type domains: list[str]
        """
        # Get activities for the domains
        activities = threat_hunt_tools.get_activities_to_domains([domains[0]])

        # Verify result is a list
        assert isinstance(activities, list)

        # If activities are returned, verify structure
        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_to_domains_with_timestamp(
        self, threat_hunt_tools, domains
    ) -> None:
        """
        Test get_activities_to_domains with timestamp filters.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param domains: Test domains fixture
        :type domains: list[str]
        """
        # Create timestamps for one week ago to now
        one_week_ago = datetime.now(timezone.utc) - timedelta(weeks=1)
        now = datetime.now(timezone.utc)

        from_timestamp = one_week_ago.isoformat()
        to_timestamp = now.isoformat()

        activities = threat_hunt_tools.get_activities_to_domains(
            domains, from_timestamp=from_timestamp, to_timestamp=to_timestamp
        )

        assert isinstance(activities, list)

    def test_get_activities_to_domains_with_iso8601_z(
        self, threat_hunt_tools, domains
    ) -> None:
        """
        Test get_activities_to_domains with ISO8601 timestamp using Z format.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param domains: Test domains fixture
        :type domains: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_domains(
            domains,
            from_timestamp="2024-01-01T00:00:00Z",
            to_timestamp="2024-12-31T23:59:59Z",
        )

        assert isinstance(activities, list)

    def test_get_activities_to_domains_with_timezone_offset(
        self, threat_hunt_tools, domains
    ) -> None:
        """
        Test get_activities_to_domains with ISO8601 timestamp using timezone offset.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param domains: Test domains fixture
        :type domains: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_domains(
            domains,
            from_timestamp="2024-01-01T00:00:00-05:00",
            to_timestamp="2024-12-31T23:59:59-05:00",
        )

        assert isinstance(activities, list)

    def test_get_activities_to_domains_with_limit(
        self, threat_hunt_tools, domains
    ) -> None:
        """
        Test get_activities_to_domains with limit parameter.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param domains: Test domains fixture
        :type domains: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_domains(domains, limit=50)

        assert isinstance(activities, list)

    def test_get_activities_to_domains_empty_list(self, threat_hunt_tools) -> None:
        """
        Test get_activities_to_domains with empty domains list raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_domains(domains=[])

    def test_get_activities_to_domains_invalid_domain_type(
        self, threat_hunt_tools
    ) -> None:
        """
        Test get_activities_to_domains with invalid domain type raises exception.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        """
        with pytest.raises(ZeroThreatHuntInvalidValues):
            threat_hunt_tools.get_activities_to_domains([123, "example.com"])

    def test_get_activities_to_domains_multiple_domains(
        self, threat_hunt_tools, domains
    ) -> None:
        """
        Test get_activities_to_domains with multiple domains.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param domains: Test domains fixture
        :type domains: list[str]
        """
        activities = threat_hunt_tools.get_activities_to_domains(domains)

        assert isinstance(activities, list)
