"""
Example usage of ZeroThreatHuntTools for threat hunting operations.

This file demonstrates various ways to use the ZeroThreatHuntTools class
to search for network activities in Zero Networks.
"""

import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from src.zero_threat_hunt_tools.zero_threat_hunt_exceptions import \
    ZeroThreatHuntInvalidValues
from src.zero_threat_hunt_tools.zero_threat_hunt_tools import \
    ZeroThreatHuntTools

# Load environment variables
load_dotenv()

# Get API key from environment
API_KEY = os.getenv("ZN_API_KEY")
if not API_KEY:
    raise ValueError(
        "ZN_API_KEY environment variable is not set. "
        "Please set it in your .env file or environment."
    )


def example_1_basic_domain_search():
    """
    Example 1: Basic domain search.

    Search for network activities connecting to specific domains.
    """
    print("\n=== Example 1: Basic Domain Search ===")

    # Initialize the threat hunting tools
    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    # Search for activities to specific domains
    domains = ["example.com", "test.com"]
    activities = hunter.get_activities_to_domains(domains)

    print(f"Found {len(activities)} activities to domains: {domains}")
    if activities:
        print(f"First activity: {activities[0]}")


def example_2_domain_search_with_est_timestamp():
    """
    Example 2: Domain search with timestamp filtering.

    Search for activities within a specific time range.
    """
    print("\n=== Example 2: Domain Search with Timestamp ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    # Calculate timestamps for the last 7 days in EST timezone
    est_tz: timezone = timezone(timedelta(hours=-5))
    now = datetime.now(est_tz)
    one_week_ago = now - timedelta(days=7)

    # You can also just provide your own iso8601 timestamp with timezone offset
    # 2025-01-01T00:00:00-05:00

    domains = ["suspicious-domain.com"]
    activities = hunter.get_activities_to_domains(
        domains,
        from_timestamp=one_week_ago.isoformat(),
        to_timestamp=now.isoformat(),
        limit=50,
    )

    print(f"Found {len(activities)} activities in the last 7 days")
    print(f"Time range: {one_week_ago.isoformat()} to {now.isoformat()}")


def example_3_domain_search_with_iso8601_z():
    """
    Example 3: Domain search using ISO8601 format with Z timezone.

    Using ISO8601 timestamps with UTC timezone indicator.
    """
    print("\n=== Example 3: Domain Search with ISO8601 Z Format ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    domains = ["example.com"]
    activities = hunter.get_activities_to_domains(
        domains,
        from_timestamp="2024-01-01T00:00:00Z",
        to_timestamp="2024-12-31T23:59:59Z",
    )

    print(f"Found {len(activities)} activities in 2024")


def example_4_search_by_source_processes():
    """
    Example 4: Search by source processes.

    Find network activities originating from specific processes.
    Useful for finding RMM software or suspicious processes.
    """
    print("\n=== Example 4: Search by Source Processes ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    # Search for activities from RMM or remote access tools
    process_paths = [
        "/usr/bin/teamviewer",
        "C:\\Program Files\\TeamViewer\\TeamViewer.exe",
        "msedge.exe",
        "chrome.exe",
    ]

    activities = hunter.get_activities_from_source_processes(
        process_paths, from_timestamp="2024-01-01T00:00:00Z", limit=100
    )

    print(f"Found {len(activities)} activities from source processes")
    if activities:
        # Group by process
        process_counts = {}
        for activity in activities:
            proc = activity.get("srcProcessPath", "Unknown")
            process_counts[proc] = process_counts.get(proc, 0) + 1

        print("Activities by process:")
        for proc, count in process_counts.items():
            print(f"  {proc}: {count}")


def example_5_search_by_destination_processes():
    """
    Example 5: Search by destination processes.

    Find network activities terminating at specific processes.
    """
    print("\n=== Example 5: Search by Destination Processes ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    process_paths = ["onedrive.exe", "OneDrive.exe"]

    activities = hunter.get_activities_to_destination_processes(
        process_paths, from_timestamp="2024-01-01T00:00:00Z"
    )

    print(f"Found {len(activities)} activities to destination processes")


def example_6_search_by_destination_ports():
    """
    Example 6: Search by destination ports.

    Find network activities connecting to specific ports.
    Useful for finding traffic to suspicious or RMM ports.
    """
    print("\n=== Example 6: Search by Destination Ports ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    # Common RMM and suspicious ports
    ports = [5938, 443, 80, 3389, 22]

    activities = hunter.get_activities_to_destination_ports(
        ports, from_timestamp="2024-01-01T00:00:00Z", limit=200
    )

    print(f"Found {len(activities)} activities to ports: {ports}")

    # Group by port
    port_counts = {}
    for activity in activities:
        port = activity.get("dstPort", "Unknown")
        port_counts[port] = port_counts.get(port, 0) + 1

    print("Activities by port:")
    for port, count in sorted(port_counts.items()):
        print(f"  Port {port}: {count}")


def example_7_search_by_destination_ips():
    """
    Example 7: Search by destination IP addresses.

    Find network activities connecting to specific IP addresses.
    Useful for finding traffic to known malicious IPs or C2 servers.
    """
    print("\n=== Example 7: Search by Destination IPs ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    # Example suspicious IP addresses
    ip_addresses = ["192.168.1.100", "10.0.0.50"]

    activities = hunter.get_activities_to_destination_ips(
        ip_addresses, from_timestamp="2024-01-01T00:00:00Z"
    )

    print(f"Found {len(activities)} activities to IPs: {ip_addresses}")


def example_8_add_additional_filters():
    """
    Example 8: Using additional filters with kwargs.

    You can add additional kwargs using the filter field names that
    the activities API supports to add additional filter.

    E.g., to filter to traffic from source username, add kwarg:
    srcUser="myusername"
    or
    srcUser=["myuser","myuser2"]

    """
    print("\n=== Example 8: Combined Filters ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    # Search for domains with additional filters
    domains = ["example.com"]
    activities = hunter.get_activities_to_domains(
        domains,
        from_timestamp="2024-01-01T00:00:00Z",
        to_timestamp="2024-12-31T23:59:59Z",
        limit=50,
        order="desc",
        srcUser="labuser",  # TODO add test cases to test this works
    )

    print(f"Found {len(activities)} activities with combined filters")


def example_9_error_handling():
    """
    Example 9: Error handling.

    Demonstrates how to handle various exceptions.
    """
    print("\n=== Example 9: Error Handling ===")

    hunter = ZeroThreatHuntTools(api_key=API_KEY)

    # Example 1: Empty list
    try:
        hunter.get_activities_to_domains([])
    except ZeroThreatHuntInvalidValues as e:
        print(f"Caught expected error: {e}")

    # Example 2: Invalid domain type
    try:
        hunter.get_activities_to_domains([123, "example.com"])
    except ZeroThreatHuntInvalidValues as e:
        print(f"Caught expected error: {e}")

    # Example 3: Invalid port range
    try:
        hunter.get_activities_to_destination_ports([70000])  # Port out of range
    except ZeroThreatHuntInvalidValues as e:
        print(f"Caught expected error: {e}")

    # Example 4: Invalid timestamp format
    try:
        hunter.get_activities_to_domains(
            ["example.com"], from_timestamp="invalid-timestamp"
        )
    except ValueError as e:
        print(f"Caught expected error: {e}")


def main():
    """
    Run all examples.

    Uncomment the examples you want to run.
    """
    print("Zero Threat Hunt Tools - Usage Examples")
    print("=" * 50)

    # Run examples
    try:
        example_1_basic_domain_search()
        # example_2_domain_search_with_timestamp()
        # example_3_domain_search_with_iso8601_z()
        # example_4_search_by_source_processes()
        # example_5_search_by_destination_processes()
        # example_6_search_by_destination_ports()
        # example_7_search_by_destination_ips()
        # example_8_combined_filters()
        # example_9_error_handling()
        # example_10_activity_analysis()

    except Exception as e:
        print(f"\nError running examples: {e}")
        raise


if __name__ == "__main__":
    main()
