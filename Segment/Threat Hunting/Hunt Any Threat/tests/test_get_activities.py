"""
Tests for ZeroThreatHuntTools.get_activities method.
"""

from src.zero_threat_hunt_exceptions import ZeroThreatHuntInvalidFilter
import pytest  # pyright: ignore[reportUnusedImport]


class TestGetActivities:
    """
    Test suite for get_activities method.
    """

    def test_get_activities_with_no_filter_kwargs(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities with kwargs for dstPort and trafficType.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities(
            from_timestamp=from_timestamp,
        )

        assert isinstance(activities, list)

        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_with_kwargs(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities with kwargs for dstPort and trafficType.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """
        activities = threat_hunt_tools.get_activities(
            from_timestamp=from_timestamp,
            dstPort=443,
            trafficType=2
        )

        assert isinstance(activities, list)

        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_with_kwargs_include_exclude(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities with kwargs for include and exclude.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """

        dstPort = {
            "include_values": [80, 443],
            "exclude_values": [8080]
        }

        trafficType = {
            "include_values": [2],
            "exclude_values": []
        }

        activities = threat_hunt_tools.get_activities(
            dstPort = dstPort,
            trafficType = trafficType,
            from_timestamp = from_timestamp
        )

        assert isinstance(activities, list)

        if len(activities) > 0:
            assert isinstance(activities[0], dict)

    def test_get_activities_with_excludes_not_supported_raises_error(
        self, threat_hunt_tools, from_timestamp
    ) -> None:
        """
        Test get_activities with kwargs for include and exclude.

        :param threat_hunt_tools: ZeroThreatHuntTools instance fixture
        :type threat_hunt_tools: ZeroThreatHuntTools
        :param from_timestamp: Timestamp fixture for one day ago
        :type from_timestamp: str
        """

        dstPort = {
            "include_values": [80, 443],
            "exclude_values": [8080]
        }

        trafficType = {
            "include_values": [],
            "exclude_values": [2]
        }

        with pytest.raises(ZeroThreatHuntInvalidFilter):
            threat_hunt_tools.get_activities(
                from_timestamp=from_timestamp,
                dstPort=dstPort,
                trafficType=trafficType
            )