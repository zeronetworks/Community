# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "httpx",
#     "python-dotenv",
#     "tenacity",
# ]
# ///
"""Audit unmonitored sources that talk to a Zero Networks destination.

An "unmonitored source" is a host that has network activity toward a
destination asset (or an asset group) but has no Zero Networks asset record,
so it is not protected or visible in the portal. This tool pulls network
activities for the destination over a time window, keeps the ones whose
source is unmonitored, and writes three outputs:

    * A raw CSV with every kept activity, newest first, streamed to disk
      page by page (one row per activity, the full activity kept in raw_json).
    * A Markdown report: run summary, scale estimates, and the top 50
      unique source -> destination pairs (ports and protocols are listed per pair).
    * A console summary and a top-N table of the same pairs (see --top).

Configuration is read from a ``.env`` file next to the script (or from the
environment): ``ZN_API_BASE_URL`` and ``ZN_API_KEY``. See ``.env.example``.

Usage:
    uv run audit_unmonitored_sources.py --dstAssetId <asset-id>
    uv run audit_unmonitored_sources.py --dstGroupId <group-id> \\
        --from 2026-11-01T00:00:00Z --to 2026-11-08T00:00:00Z
    uv run audit_unmonitored_sources.py --dstGroupId <group-id> --no-excludeDstGroupAsSource
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TextIO

import httpx
from dotenv import load_dotenv
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

ACTIVITIES_PATH = "/activities/network"
PAGE_LIMIT = 400
RETRY_ATTEMPTS = 3
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
DEFAULT_WINDOW = timedelta(days=7)
DEFAULT_TOP = 50
REPORT_TOP = 50  # rows in the Markdown report, independent of --top
DEFAULT_OUTPUT_DIR = "./reports"
MAX_PORTS_SHOWN = 10

# Scale estimates: (label, hours). One week is 168 hours.
SCALE_WINDOWS: list[tuple[str, int]] = [("8 hours", 8), ("12 hours", 12), ("24 hours", 24), ("1 week", 168)]

# Monitored-asset attributes. A source that carries none of these is unmonitored.
MONITORED_SOURCE_FIELDS = ("assetSrc", "networkProtectionState", "assetType")

PROTOCOL_NAMES: dict[int, str] = {1: "ICMP", 6: "TCP", 17: "UDP"}

RAW_COLUMNS = [
    "timestamp_utc",
    "timestamp_ms",
    "source_ip",
    "source_fqdn",
    "source_port",
    "destination_asset",
    "destination_asset_id",
    "destination_ip",
    "destination_port",
    "protocol",
    "raw_json",
]

# Characters that make a spreadsheet interpret a cell as a formula.
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

logger = logging.getLogger("audit_unmonitored_sources")


class CLIError(Exception):
    """An expected, user-facing error. Reported without a traceback; exit code 1."""


@dataclass
class Config:
    """Runtime configuration loaded from the environment (.env)."""

    base_url: str
    api_key: str


@dataclass
class SourceRow:
    """One deduplicated (source IP, destination) row.

    Ports are not part of the key: ``ports`` counts each (destination port,
    protocol) pair seen for this source -> destination combination.
    """

    source_ip: str
    source_fqdn: str
    destination_asset: str
    destination_asset_id: str
    destination_ip: str
    ports: dict[tuple[Any, str], int] = field(default_factory=dict)
    occurrences: int = 0
    first_seen_ms: int | None = None
    last_seen_ms: int | None = None


@dataclass
class GroupMembers:
    """Members of a destination group, indexed for matching activity sources.

    Built by fetch_group_members(). A source matches when its assetId is in
    ``ids``, its IP is in ``ips``, or its FQDN (case-insensitive) is in ``fqdns``.
    """

    group_id: str
    endpoint: str = ""
    ids: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    fqdns: set[str] = field(default_factory=set)

    def matches(self, src: dict[str, Any]) -> bool:
        """Return True if an activity's "src" object is one of the group's members."""
        asset_id = src.get("assetId")
        if asset_id and str(asset_id) in self.ids:
            return True
        ip = src.get("ip")
        if ip and str(ip) in self.ips:
            return True
        fqdn = src.get("fqdn")
        return bool(fqdn) and str(fqdn).casefold() in self.fqdns


@dataclass
class PageStats:
    """Per-page numbers returned by Aggregation.add_page.

    ``kept`` holds the unwrapped activity dicts counted as unmonitored on this
    page (the raw CSV rows). The caller writes them out and drops them.
    """

    retrieved: int = 0
    unmonitored: int = 0
    excluded: int = 0
    kept: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Aggregation:
    """Incrementally built result: deduplicated rows plus summary counters.

    Pages are fed through add_page() and discarded by the caller; only the
    deduplicated rows and counters are kept. Call finalize() once after the
    last page to build the sorted ``rows`` list.
    """

    rows: list[SourceRow] = field(default_factory=list)
    activities_retrieved: int = 0
    activities_in_scope: int = 0
    unmonitored_activities: int = 0
    unmonitored_sources: set[str] = field(default_factory=set)
    excluded_group_member_activities: int = 0
    _rows: dict[tuple, SourceRow] = field(default_factory=dict, init=False, repr=False)

    def add_page(
        self,
        items: Iterable[Any],
        dst_asset_id: str | None = None,
        exclude: GroupMembers | None = None,
    ) -> PageStats:
        """Filter one page of activities and fold it into the running totals.

        Filter order: dst re-check, then the unmonitored check, then the
        destination-group member exclusion. Only activities that would otherwise
        be reported are counted as excluded, and excluded activities are not
        counted as unmonitored.

        Args:
            items: raw activity items from one page (an "activity" wrapper is accepted).
            dst_asset_id: when given, only activities whose dst.assetId equals this
                value are counted (the server-side asset filter is text-based).
            exclude: when given, unmonitored activities whose source is a member of
                this group are dropped and counted in excluded_group_member_activities.

        Returns:
            PageStats with the number of activities retrieved, unmonitored and
            excluded on this page, plus the kept (unmonitored) activities in
            the order the API returned them.
        """
        stats = PageStats()
        for item in items:
            self.activities_retrieved += 1
            stats.retrieved += 1
            activity = item.get("activity", item) if isinstance(item, dict) else {}
            src = activity.get("src") or {}
            dst = activity.get("dst") or {}

            if dst_asset_id and dst.get("assetId") != dst_asset_id:
                continue
            self.activities_in_scope += 1

            src_ip = src.get("ip")
            if not src_ip or not is_unmonitored(src):
                continue
            if exclude is not None and exclude.matches(src):
                self.excluded_group_member_activities += 1
                stats.excluded += 1
                continue
            self.unmonitored_activities += 1
            stats.unmonitored += 1
            stats.kept.append(activity)
            self.unmonitored_sources.add(src_ip)

            src_fqdn = src.get("fqdn") or ""
            dst_ip = dst.get("ip") or ""
            dst_display = dst.get("fqdn") or dst_ip
            dst_port = dst.get("port")
            protocol = _protocol_name(activity.get("protocol"))
            key = (src_ip, dst_display)

            row = self._rows.get(key)
            if row is None:
                row = SourceRow(
                    source_ip=src_ip,
                    source_fqdn=src_fqdn,
                    destination_asset=dst_display,
                    destination_asset_id=dst.get("assetId") or "",
                    destination_ip=dst_ip,
                )
                self._rows[key] = row

            port_key = (dst_port, protocol)
            row.ports[port_key] = row.ports.get(port_key, 0) + 1
            row.occurrences += 1
            ts = _to_ms(activity.get("timestamp"))
            if ts is not None:
                if row.first_seen_ms is None or ts < row.first_seen_ms:
                    row.first_seen_ms = ts
                if row.last_seen_ms is None or ts > row.last_seen_ms:
                    row.last_seen_ms = ts
        return stats

    def finalize(self) -> None:
        """Build the ranked ``rows`` list. Call once, after the last page."""
        self.rows = sorted(self._rows.values(), key=_row_sort_key)


def load_config() -> Config:
    """Load ZN_API_BASE_URL and ZN_API_KEY from the environment / .env file.

    Returns:
        Config with the base URL (trailing slash stripped, "/api/v1" appended)
        and API key.

    Raises:
        CLIError: if either required variable is missing.
    """
    load_dotenv()
    base_url = os.environ.get("ZN_API_BASE_URL", "").strip().rstrip("/")
    if base_url:
        base_url += "/api/v1"
    api_key = os.environ.get("ZN_API_KEY", "").strip()

    missing = [
        name
        for name, value in (("ZN_API_BASE_URL", base_url), ("ZN_API_KEY", api_key))
        if not value
    ]
    if missing:
        raise CLIError(
            f"Missing required setting(s): {', '.join(missing)}. "
            "Copy .env.example to .env next to this script and fill in the values."
        )
    return Config(base_url=base_url, api_key=api_key)


def setup_logging(verbose: bool) -> None:
    """Configure root logging to stderr.

    Args:
        verbose: when True, set DEBUG level; otherwise INFO.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: argument list to parse (defaults to sys.argv[1:]).

    Returns:
        Parsed argparse.Namespace.
    """
    parser = argparse.ArgumentParser(
        description="Find unmonitored sources that talk to a Zero Networks "
        "destination asset or asset group, and write a CSV and Markdown report."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--dstAssetId",
        dest="dst_asset_id",
        help="Destination asset ID to audit (e.g. a:a:...).",
    )
    target.add_argument(
        "--dstGroupId",
        dest="dst_group_id",
        help="Destination asset group ID to audit.",
    )
    parser.add_argument(
        "--from",
        dest="from_time",
        help="Window start, ISO 8601 (e.g. 2026-11-01T00:00:00Z). Naive values are "
        "treated as UTC. Default: 7 days before --to.",
    )
    parser.add_argument(
        "--to",
        dest="to_time",
        help="Window end, ISO 8601. Naive values are treated as UTC. Default: now (UTC).",
    )
    parser.add_argument(
        "--customHeader",
        dest="custom_header",
        default=None,
        help='JSON object of extra HTTP headers sent with every request, e.g. '
        '\'{"x-example-header":"value"}\'.',
    )
    parser.add_argument(
        "--outputDir",
        dest="output_dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for the CSV and Markdown reports (default: {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP,
        help=f"Number of rows to print to the console (default: {DEFAULT_TOP}; "
        "0 prints all). The CSV and Markdown files always contain every row.",
    )
    parser.add_argument(
        "--excludeDstGroupAsSource",
        dest="exclude_dst_group_as_source",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Drop activities whose source is a member of the destination group "
        "(matched by asset ID, IP or FQDN; nested and inactive members included). "
        "On by default when --dstGroupId is used; pass --no-excludeDstGroupAsSource to "
        "turn it off. Passing --excludeDstGroupAsSource with --dstAssetId is an error.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging (request URLs and header names; never header values or the API key).",
    )
    args = parser.parse_args(argv)
    if args.top < 0:
        parser.error("--top must be 0 or a positive integer.")
    if args.exclude_dst_group_as_source and not args.dst_group_id:
        parser.error("--excludeDstGroupAsSource requires --dstGroupId")
    # Default (flag not given): on for a destination group, off (not applicable) for an asset.
    args.exclude_explicit = args.exclude_dst_group_as_source is True
    if args.exclude_dst_group_as_source is None:
        args.exclude_dst_group_as_source = bool(args.dst_group_id)
    return args


def parse_iso_utc(value: str, label: str) -> datetime:
    """Parse an ISO 8601 timestamp into an aware UTC datetime.

    Args:
        value: the timestamp string (offsets and a trailing "Z" are accepted).
        label: flag name used in error messages.

    Returns:
        A timezone-aware datetime in UTC. Naive input is treated as UTC.

    Raises:
        CLIError: if the value is not a valid ISO 8601 timestamp.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise CLIError(
            f"{label} is not a valid ISO 8601 timestamp: {value!r} "
            "(example: 2026-11-01T00:00:00Z)."
        ) from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def resolve_window(
    from_arg: str | None, to_arg: str | None, now: datetime | None = None
) -> tuple[datetime, datetime]:
    """Resolve the audit window from --from/--to, applying defaults.

    Args:
        from_arg: raw --from value, or None.
        to_arg: raw --to value, or None.
        now: the current time (injectable for tests); defaults to UTC now.

    Returns:
        (start, end) as aware UTC datetimes with start < end.

    Raises:
        CLIError: on invalid timestamps or when start is not before end.
    """
    end = parse_iso_utc(to_arg, "--to") if to_arg else (now or datetime.now(timezone.utc))
    start = parse_iso_utc(from_arg, "--from") if from_arg else end - DEFAULT_WINDOW
    if start >= end:
        raise CLIError(
            f"--from ({start.isoformat()}) must be earlier than --to ({end.isoformat()})."
        )
    return start, end


def to_epoch_ms(moment: datetime) -> int:
    """Convert an aware datetime to epoch milliseconds."""
    return int(moment.timestamp() * 1000)


def parse_custom_header(raw: str | None) -> dict[str, str]:
    """Parse the --customHeader JSON object into a str->str mapping.

    Args:
        raw: the raw JSON string from the command line, or None.

    Returns:
        Header name/value pairs (empty dict when raw is None).

    Raises:
        CLIError: if the value is not valid JSON, not an object, or has
            non-string names or values.
    """
    if raw is None:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CLIError(f"--customHeader is not valid JSON: {exc.msg}.") from exc
    if not isinstance(parsed, dict):
        raise CLIError('--customHeader must be a JSON object, e.g. \'{"name":"value"}\'.')
    for key, value in parsed.items():
        if not isinstance(value, str):
            raise CLIError(f"--customHeader value for {key!r} must be a string.")
    return dict(parsed)


def build_filters(asset_name: str | None = None, group_id: str | None = None) -> list[dict]:
    """Build the server-side _filters list for the activities query.

    This is the only place that knows the filter ids. The destination asset
    filter is text-based, so the caller must also re-check dst.assetId
    client-side (see aggregate()).

    Args:
        asset_name: destination asset name or FQDN (for --dstAssetId).
        group_id: destination asset group ID (for --dstGroupId).

    Returns:
        A list of filter objects (empty when no target is given).
    """
    if group_id:
        return [{"id": "dstAssetsInGroup", "includeValues": [group_id], "excludeValues": []}]
    if asset_name:
        return [{"id": "dstAsset", "includeValues": [asset_name], "excludeValues": []}]
    return []


def is_unmonitored(src: dict[str, Any]) -> bool:
    """Return True if a network activity source has no monitored-asset attributes.

    A monitored source carries assetSrc, networkProtectionState and assetType.
    An unmonitored source carries none of them.

    Args:
        src: the activity's "src" object.

    Returns:
        True when none of MONITORED_SOURCE_FIELDS is present.
    """
    return all(src.get(name) is None for name in MONITORED_SOURCE_FIELDS)


def _protocol_name(value: Any) -> str:
    """Map a protocol number to its name (6 -> TCP); pass other values through."""
    if value is None or value == "":
        return ""
    if isinstance(value, int) and value in PROTOCOL_NAMES:
        return PROTOCOL_NAMES[value]
    return str(value)


def _to_ms(value: Any) -> int | None:
    """Coerce an epoch-millisecond timestamp (int or numeric string) to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _format_page_time(ms: int) -> str:
    """Format epoch milliseconds as e.g. '11-18-2026 1:00 PM' (UTC)."""
    moment = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    hour = moment.hour % 12 or 12
    return f"{moment:%m-%d-%Y} {hour}:{moment:%M} {'AM' if moment.hour < 12 else 'PM'}"


def _page_time_range(items: list[Any]) -> str:
    """Describe the earliest and latest activity timestamps in a page.

    Args:
        items: raw activity items from one page (an "activity" wrapper is accepted).

    Returns:
        " | From <earliest> -> <latest> UTC", or "" when no item has a timestamp.
    """
    stamps = [
        ms
        for item in items
        if isinstance(item, dict)
        for ms in [_to_ms((item.get("activity", item) or {}).get("timestamp"))]
        if ms is not None
    ]
    if not stamps:
        return ""
    return f" | From {_format_page_time(min(stamps))} -> {_format_page_time(max(stamps))} UTC"


def _ip_sort_key(ip: str) -> tuple[int, int, int, str]:
    """Sort IPs numerically; unparseable values sort after valid ones."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return (1, 0, 0, ip)
    return (0, parsed.version, int(parsed), ip)


def _row_sort_key(row: SourceRow) -> tuple:
    """Order rows by occurrences (desc), source IP, then destination."""
    return (-row.occurrences, _ip_sort_key(row.source_ip), row.destination_asset)


def _port_sort_key(entry: tuple[tuple[Any, str], int]) -> tuple:
    """Order (port, protocol) entries by count (desc), then port number (asc)."""
    (port, protocol), count = entry
    is_number = isinstance(port, int)
    return (-count, not is_number, port if is_number else 0, str(port), protocol)


def format_ports(ports: dict[tuple[Any, str], int], limit: int = MAX_PORTS_SHOWN) -> str:
    """Format a row's (port, protocol) counts for display, e.g. "445/TCP, 135/TCP".

    Entries are sorted by count (desc), then port number (asc). A missing port
    shows as "?". When there are more than ``limit`` entries the first ``limit``
    are shown followed by ", +N more".

    Args:
        ports: mapping of (port, protocol) -> count.
        limit: maximum number of entries to show.

    Returns:
        The formatted string, or "" when there are no ports.
    """
    entries = sorted(ports.items(), key=_port_sort_key)
    parts = []
    for (port, protocol), _count in entries[:limit]:
        port_text = "?" if port is None or port == "" else str(port)
        parts.append(f"{port_text}/{protocol}" if protocol else port_text)
    if len(entries) > limit:
        parts.append(f"+{len(entries) - limit} more")
    return ", ".join(parts)


def scale_estimates(unmonitored_count: int, window: timedelta) -> list[tuple[str, int]]:
    """Linearly extrapolate an unmonitored-activity count to longer periods.

    Args:
        unmonitored_count: unmonitored activities observed in ``window``.
        window: the observed window's duration.

    Returns:
        [(label, estimate)] for 8 hours, 12 hours, 24 hours and 1 week, or []
        when the window is zero or negative.
    """
    window_hours = window.total_seconds() / 3600
    if window_hours <= 0:
        return []
    return [
        (label, round(unmonitored_count / window_hours * hours))
        for label, hours in SCALE_WINDOWS
    ]


def aggregate(activities: Iterable[dict[str, Any]], dst_asset_id: str | None = None) -> Aggregation:
    """Reduce activities to ranked unmonitored source -> destination rows in one call.

    Thin wrapper over Aggregation.add_page() and finalize(), kept for callers
    that have every activity at hand.

    Args:
        activities: activity objects as returned by the API.
        dst_asset_id: when given, only activities whose dst.assetId equals this
            value are counted (the server-side asset filter is text-based).

    Returns:
        Aggregation with rows sorted by occurrences (descending), then source IP,
        then destination.
    """
    agg = Aggregation()
    agg.add_page(activities, dst_asset_id=dst_asset_id)
    agg.finalize()
    return agg


def _format_ms(ms: int | None) -> str:
    """Format epoch milliseconds as UTC ISO 8601 (e.g. 2026-11-01T00:00:00Z)."""
    if ms is None:
        return ""
    moment = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def ranked_records(rows: list[SourceRow]) -> list[dict[str, Any]]:
    """Convert ranked rows into display dicts, with 1-based ranks.

    Keys: rank, source_ip, source_fqdn, destination_asset, ports (formatted by
    format_ports), occurrences, first_seen, last_seen.
    """
    records = []
    for rank, row in enumerate(rows, start=1):
        records.append(
            {
                "rank": rank,
                "source_ip": row.source_ip,
                "source_fqdn": row.source_fqdn,
                "destination_asset": row.destination_asset,
                "ports": format_ports(row.ports),
                "occurrences": row.occurrences,
                "first_seen": _format_ms(row.first_seen_ms),
                "last_seen": _format_ms(row.last_seen_ms),
            }
        )
    return records


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in string cells (FQDNs come from network data)."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def activity_to_csv_row(activity: dict[str, Any]) -> dict[str, Any]:
    """Map one unwrapped activity to a raw CSV row keyed by RAW_COLUMNS.

    Args:
        activity: the activity dict (src, dst, timestamp, protocol, ...).

    Returns:
        A dict with every RAW_COLUMNS key. raw_json is the full activity as JSON.
        Strings are not formula-guarded here; RawActivityWriter does that.
    """
    src = activity.get("src") or {}
    dst = activity.get("dst") or {}
    ts = _to_ms(activity.get("timestamp"))
    src_port = src.get("port")
    dst_port = dst.get("port")
    return {
        "timestamp_utc": _format_ms(ts),
        "timestamp_ms": "" if ts is None else ts,
        "source_ip": src.get("ip") or "",
        "source_fqdn": src.get("fqdn") or "",
        "source_port": "" if src_port is None else src_port,
        "destination_asset": dst.get("fqdn") or dst.get("ip") or "",
        "destination_asset_id": dst.get("assetId") or "",
        "destination_ip": dst.get("ip") or "",
        "destination_port": "" if dst_port is None else dst_port,
        "protocol": _protocol_name(activity.get("protocol")),
        "raw_json": json.dumps(activity),
    }


class RawActivityWriter:
    """Streams kept activities into the raw CSV, one row per activity.

    The header is written on construction. write_page() appends one page's
    activities and keeps no reference to them. Pages arrive newest first
    (the API is queried with order=desc), so the file is newest -> oldest;
    rows are never re-sorted.
    """

    def __init__(self, handle: TextIO) -> None:
        self._writer = csv.DictWriter(handle, fieldnames=RAW_COLUMNS)
        self._writer.writeheader()
        self.rows_written = 0

    def write_page(self, activities: Iterable[dict[str, Any]]) -> None:
        """Append one row per activity, with spreadsheet formula guarding."""
        for activity in activities:
            row = activity_to_csv_row(activity)
            self._writer.writerow({key: _csv_safe(value) for key, value in row.items()})
            self.rows_written += 1


def _md_cell(value: Any) -> str:
    """Escape a value for use inside a Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def write_markdown(
    agg: Aggregation,
    target_label: str,
    start: datetime,
    end: datetime,
    path: Path,
    members: GroupMembers | None = None,
) -> None:
    """Write the Markdown report: run summary, scale estimates, and the top pairs.

    The pair table is capped at REPORT_TOP rows regardless of --top. The raw
    activities CSV from the same run has every activity.

    Args:
        agg: aggregation result.
        target_label: human-readable target, e.g. "Asset a:a:... (name)".
        start: window start (UTC).
        end: window end (UTC).
        path: destination file path.
        members: the destination group's members when --excludeDstGroupAsSource
            is on; adds the exclusion rows and note. None leaves the report unchanged.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Unmonitored sources report",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| Target | {_md_cell(target_label)} |",
        f"| Window start (UTC) | {start.strftime('%Y-%m-%d %H:%M:%S')} |",
        f"| Window end (UTC) | {end.strftime('%Y-%m-%d %H:%M:%S')} |",
        f"| Generated | {generated} |",
        f"| Activities retrieved | {agg.activities_retrieved} |",
        f"| Activities in scope | {agg.activities_in_scope} |",
        f"| Unmonitored activities | {agg.unmonitored_activities} |",
        f"| Unique unmonitored sources | {len(agg.unmonitored_sources)} |",
        f"| Unique unmonitored src+dst rows | {len(agg.rows)} |",
    ]
    if members is not None:
        lines += [
            f"| Group members (IDs / IPs / FQDNs) | {len(members.ids)} / {len(members.ips)} / {len(members.fqdns)} |",
            f"| Excluded (dst group members) | {agg.excluded_group_member_activities} |",
        ]
    lines.append("")
    if members is not None:
        lines += [
            f"Sources that are members of {_md_cell(target_label)} were excluded (--excludeDstGroupAsSource).",
            "",
        ]

    window = end - start
    estimates = scale_estimates(agg.unmonitored_activities, window)
    if estimates:
        lines += [
            "## Scale estimates",
            "",
            "| Window | Estimated unmonitored activities |",
            "| --- | --- |",
        ]
        lines += [f"| {_md_cell(label)} | {count} |" for label, count in estimates]
        lines += [
            "",
            f"Linear extrapolation of this {_md_cell(_format_duration(window))} window. "
            "Unique source and pair counts do not scale linearly, so they are not estimated.",
            "",
        ]

    lines.append(f"## Top {REPORT_TOP} unmonitored source -> destination pairs")
    lines.append("")
    if not agg.rows:
        lines += ["No unmonitored sources found in this window.", ""]
    else:
        headers = ["#", "Source IP", "Source FQDN", "Destination", "Ports/Protocols", "Occurrences", "First seen", "Last seen"]
        keys = ["rank", "source_ip", "source_fqdn", "destination_asset", "ports", "occurrences", "first_seen", "last_seen"]
        lines += [
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
        ]
        top_records = ranked_records(agg.rows[:REPORT_TOP])
        for record in top_records:
            lines.append("| " + " | ".join(_md_cell(record[k]) for k in keys) + " |")
        lines.append("")
        if len(agg.rows) > REPORT_TOP:
            lines += [
                f"Showing the top {REPORT_TOP} of {len(agg.rows)} rows. "
                "The raw activities CSV from this run has every activity.",
                "",
            ]
    path.write_text("\n".join(lines), encoding="utf-8")


def _format_duration(window: timedelta) -> str:
    """Describe a window in hours, or days when it is a whole number of days."""
    hours = window.total_seconds() / 3600
    if hours and hours % 24 == 0:
        days = int(hours // 24)
        return f"{days} day" + ("" if days == 1 else "s")
    return f"{hours:g} hour" + ("" if hours == 1 else "s")


def render_console_table(rows: list[SourceRow], top: int) -> str:
    """Render the top rows as an aligned plain-text table.

    Args:
        rows: ranked rows.
        top: maximum number of rows to show (0 = all).

    Returns:
        The table text (without a trailing newline).
    """
    shown = rows if top == 0 else rows[:top]
    headers = ["#", "SOURCE IP", "SOURCE FQDN", "DESTINATION", "PORTS/PROTO", "COUNT"]
    body = []
    for record in ranked_records(shown):
        body.append(
            [
                str(record["rank"]),
                str(record["source_ip"]),
                str(record["source_fqdn"]),
                str(record["destination_asset"]),
                str(record["ports"]),
                str(record["occurrences"]),
            ]
        )
    widths = [len(h) for h in headers]
    for cells in body:
        widths = [max(w, len(c)) for w, c in zip(widths, cells)]

    def fmt(cells: list[str]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()

    return "\n".join([fmt(headers), fmt(["-" * w for w in widths]), *(fmt(c) for c in body)])


def build_client(
    config: Config,
    custom_headers: dict[str, str],
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """Create the shared httpx client with auth and custom headers on every request.

    Args:
        config: loaded configuration.
        custom_headers: extra headers from --customHeader (values are never logged).
        transport: optional transport override (used by tests).

    Returns:
        A configured httpx.Client.
    """
    headers = {"Authorization": config.api_key, "Accept": "application/json"}
    for name in custom_headers:
        if name.lower() == "authorization":
            logger.warning("--customHeader overrides the Authorization header.")
        logger.debug("Adding custom header: %s", name)
    headers.update(custom_headers)
    return httpx.Client(
        base_url=config.base_url,
        headers=headers,
        timeout=60.0,
        transport=transport,
    )


def _is_retryable_error(exc: BaseException) -> bool:
    """Return True for transient errors worth retrying."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in RETRY_STATUS_CODES
    return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))


@retry(
    reraise=True,
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception(_is_retryable_error),
)
def _get(client: httpx.Client, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """GET a JSON document, retrying transient failures.

    Raises:
        httpx.HTTPStatusError: on a non-2xx response that is not retried.
    """
    logger.debug("GET %s params=%s", path, sorted((params or {}).keys()))
    response = client.get(path, params=params)
    response.raise_for_status()
    return response.json()


def _http_error_message(exc: httpx.HTTPError, context: str) -> str:
    """Turn an httpx error into a short, customer-facing message."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status in (401, 403):
            return (
                f"{context}: the API rejected the request (HTTP {status}). "
                "Check ZN_API_KEY and that the key has access to this data."
            )
        if status == 404:
            return f"{context}: not found (HTTP 404)."
        return f"{context}: the API returned HTTP {status}."
    return f"{context}: could not reach the API ({exc.__class__.__name__}). Check ZN_API_BASE_URL."


def resolve_asset_name(client: httpx.Client, asset_id: str) -> str:
    """Look up a destination asset and return the name (or FQDN) used by the filter.

    Raises:
        CLIError: if the asset does not exist or the API call fails.
    """
    try:
        data = _get(client, f"/assets/{asset_id}")
    except httpx.HTTPError as exc:
        if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404:
            raise CLIError(f"Destination asset not found: {asset_id}.") from exc
        raise CLIError(_http_error_message(exc, "Looking up the destination asset failed")) from exc

    entity = data.get("entity") or {}
    name = entity.get("name") or entity.get("fqdn") or ""
    if not name:
        raise CLIError(f"Destination asset {asset_id} has no name or FQDN to filter on.")
    return str(name)


def _name_from(data: Any) -> str:
    """Pull a group name out of a detail or list response (shape is tolerant)."""
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return _name_from(items[0]) if items else ""
        entity = data.get("entity")
        if isinstance(entity, dict):
            return str(entity.get("name") or "")
        return str(data.get("name") or "")
    return ""


def resolve_group_label(client: httpx.Client, group_id: str) -> str:
    """Best-effort lookup of a group's name for report labels. Never fails.

    Tries the typed detail path, the bare detail path, then an id-filtered list
    query; the first that yields a name wins.
    """
    parts = group_id.split(":")
    kind = GROUP_KIND_BY_LETTER.get(parts[1]) if len(parts) > 1 else None
    id_filter = json.dumps([{"id": "id", "includeValues": [group_id], "excludeValues": []}])
    attempts: list[tuple[str, dict[str, Any] | None]] = []
    if kind:
        attempts.append((f"/groups/{kind}/{group_id}", None))
    attempts += [
        (f"/groups/{group_id}", None),
        ("/groups", {"_limit": 1, "_filters": id_filter}),
    ]
    for path, params in attempts:
        try:
            name = _name_from(_get(client, path, params))
        except httpx.HTTPError as exc:
            logger.debug("Group name lookup via %s failed (non-fatal): %s", path, exc)
            continue
        if name:
            logger.debug("Group name resolved via %s", path)
            return f"Group - {name} - {group_id}"
    logger.warning("Could not resolve the group name for %s; run with -v for details.", group_id)
    return f"Group - {group_id}"


GROUP_KIND_BY_LETTER = {"c": "custom", "t": "tag", "s": "system"}
MEMBER_ENDPOINT_MISSING_CODES = {404, 405}
MAX_MEMBER_PAGES = 1000


def _group_member_candidates(group_id: str) -> list[str]:
    """Ordered member-endpoint paths to try for a group.

    The group ID letter (g:<letter>:...) selects the kind path. The member
    endpoint is not uniform across the API and is unverified for every kind, so
    several shapes are tried in order; the first one that answers wins.
    """
    candidates: list[str] = []
    parts = group_id.split(":")
    kind = GROUP_KIND_BY_LETTER.get(parts[1]) if len(parts) >= 2 and parts[0] == "g" else None
    if kind:
        candidates.append(f"/groups/{kind}/{group_id}/members")
        candidates.append(f"/groups/{kind}/{group_id}/successors")
    candidates.append(f"/groups/{group_id}/members")
    return candidates


def _member_items(data: Any) -> list[Any]:
    """Extract the item list from a members response (a bare list or an items wrapper)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items") or data.get("entities") or []
        return items if isinstance(items, list) else []
    return []


def _fetch_member_items(client: httpx.Client, path: str) -> list[Any]:
    """Read every member of one endpoint, paging with _limit/_offset."""
    items: list[Any] = []
    for page_no in range(MAX_MEMBER_PAGES):
        params = {
            "_limit": PAGE_LIMIT,
            "_offset": page_no * PAGE_LIMIT,
            "includeNestedMembers": "true",
            "showInactive": "true",
        }
        page = _member_items(_get(client, path, params=params))
        items.extend(page)
        if len(page) < PAGE_LIMIT:
            return items
    logger.warning("Group member listing hit the %d-page limit; the member list may be incomplete.", MAX_MEMBER_PAGES)
    return items


def _add_member_keys(members: GroupMembers, item: Any) -> None:
    """Index one member item's asset ID, IP(s) and FQDN/name. Tolerant of shape."""
    if not isinstance(item, dict):
        return
    member = item.get("entity") if isinstance(item.get("entity"), dict) else item
    asset_id = member.get("assetId") or member.get("id")
    if asset_id:
        members.ids.add(str(asset_id))
    for key in ("ip", "ipAddress", "ipAddresses", "address"):
        value = member.get(key)
        for ip in value if isinstance(value, list) else [value]:
            if isinstance(ip, str) and ip.strip():
                members.ips.add(ip.strip())
    for key in ("fqdn", "name"):
        value = member.get(key)
        if isinstance(value, str) and value.strip():
            members.fqdns.add(value.strip().casefold())


def fetch_group_members(client: httpx.Client, group_id: str) -> GroupMembers:
    """Load the members of a destination group for --excludeDstGroupAsSource.

    Nested members and inactive members are included. Endpoint candidates are
    tried in order: a 404 or 405 moves on to the next one, and any other HTTP
    error stops with a clear message.

    Raises:
        CLIError: if no member endpoint answers, or a request fails for another reason.
    """
    tried: list[str] = []
    for path in _group_member_candidates(group_id):
        tried.append(path)
        try:
            items = _fetch_member_items(client, path)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in MEMBER_ENDPOINT_MISSING_CODES:
                logger.debug("Group member endpoint %s not available (HTTP %d)", path, exc.response.status_code)
                continue
            raise CLIError(_http_error_message(exc, f"Fetching members of group {group_id}")) from exc
        except httpx.HTTPError as exc:
            raise CLIError(_http_error_message(exc, f"Fetching members of group {group_id}")) from exc

        members = GroupMembers(group_id=group_id, endpoint=path)
        for item in items:
            _add_member_keys(members, item)
        logger.debug(
            "Group members via %s: %d items, %d ids, %d ips, %d fqdns",
            path,
            len(items),
            len(members.ids),
            len(members.ips),
            len(members.fqdns),
        )
        return members

    raise CLIError(
        f"Could not read the members of group {group_id}: no member endpoint answered "
        f"({', '.join(tried)}). Check the group ID, or run with --no-excludeDstGroupAsSource."
    )


def iter_pages(
    client: httpx.Client,
    start_ms: int,
    end_ms: int,
    filters: list[dict],
) -> Iterator[list[dict[str, Any]]]:
    """Yield one list of network activity items per page, following cursor pagination.

    Pages are yielded as they are fetched, so callers can filter each one and
    let it go before the next request.

    Raises:
        CLIError: if a page request fails after retries.
    """
    cursor: str | None = None
    seen_cursors: set[str] = set()
    page = 0
    while True:
        params: dict[str, Any] = {
            "from": start_ms,
            "to": end_ms,
            "_limit": PAGE_LIMIT,
            "order": "desc",
        }
        if filters:
            params["_filters"] = json.dumps(filters, separators=(",", ":"))
        if cursor is not None:
            params["_cursor"] = cursor

        page += 1
        try:
            data = _get(client, ACTIVITIES_PATH, params=params)
        except httpx.HTTPError as exc:
            raise CLIError(_http_error_message(exc, f"Fetching network activities (page {page})")) from exc

        items = data.get("items") or []
        yield items

        next_cursor = data.get("scrollCursor") or data.get("nextCursor")
        if not items or not next_cursor:
            return
        if str(next_cursor) in seen_cursors:
            logger.warning("Pagination cursor repeated; stopping early to avoid a loop.")
            return
        seen_cursors.add(str(next_cursor))
        cursor = str(next_cursor)


def _safe_filename_part(value: str) -> str:
    """Make an ID safe for use in a file name."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "target"


def report_paths(output_dir: Path, kind: str, target_id: str, generated: datetime) -> tuple[Path, Path]:
    """Build the raw activities CSV and Markdown file paths for this run."""
    stamp = generated.strftime("%Y%m%dT%H%M%SZ")
    stem = f"unmonitored-sources_{kind}-{_safe_filename_part(target_id)}_{stamp}"
    return output_dir / f"{stem}_activities.csv", output_dir / f"{stem}.md"


def run(args: argparse.Namespace, transport: httpx.BaseTransport | None = None) -> int:
    """Execute the audit for parsed arguments.

    Args:
        args: parsed CLI arguments.
        transport: optional httpx transport override (used by tests).

    Returns:
        Process exit code (0 on success).

    Raises:
        CLIError: for expected, user-facing failures.
    """
    start, end = resolve_window(args.from_time, args.to_time)
    custom_headers = parse_custom_header(args.custom_header)
    config = load_config()
    output_dir = Path(args.output_dir)

    if args.dst_asset_id:
        kind, target_id = "asset", args.dst_asset_id
    else:
        kind, target_id = "group", args.dst_group_id

    logger.info("Auditing %s %s from %s to %s (UTC)", kind, target_id, start.isoformat(), end.isoformat())

    client = build_client(config, custom_headers, transport)
    with client:
        if args.dst_asset_id:
            asset_name = resolve_asset_name(client, args.dst_asset_id)
            filters = build_filters(asset_name=asset_name)
            target_label = f"Asset {args.dst_asset_id} ({asset_name})"
        else:
            filters = build_filters(group_id=args.dst_group_id)
            target_label = resolve_group_label(client, args.dst_group_id)

        if args.verbose:
            logger.debug("Filters: %s", json.dumps(filters))
        members: GroupMembers | None = None
        if args.exclude_dst_group_as_source:
            try:
                members = fetch_group_members(client, args.dst_group_id)
            except CLIError as exc:
                if args.exclude_explicit:
                    raise
                # On by default: don't fail the whole audit if membership can't be read.
                logger.warning(
                    "%s Continuing WITHOUT excluding group members "
                    "(pass --no-excludeDstGroupAsSource to silence this).",
                    exc,
                )
        output_dir.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc)
        csv_path, md_path = report_paths(output_dir, kind, target_id, generated)

        agg = Aggregation()
        pages = iter_pages(client, to_epoch_ms(start), to_epoch_ms(end), filters)
        # The raw CSV is opened before paging and closed even if a page fails.
        # Each page's kept activities are written as they arrive, then dropped.
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            raw_writer = RawActivityWriter(handle)
            for page_no, items in enumerate(pages, start=1):
                stats = agg.add_page(items, dst_asset_id=args.dst_asset_id, exclude=members)
                raw_writer.write_page(stats.kept)
                if members is None:
                    logger.info(
                        "Fetched page %d: %d activit%s (%d total so far)%s | %d unmonitored (%d unique sources so far)",
                        page_no,
                        stats.retrieved,
                        "y" if stats.retrieved == 1 else "ies",
                        agg.activities_retrieved,
                        _page_time_range(items),
                        stats.unmonitored,
                        len(agg.unmonitored_sources),
                    )
                else:
                    logger.info(
                        "Fetched page %d: %d activit%s (%d total so far)%s | %d unmonitored (%d unique sources so far) | %d excluded",
                        page_no,
                        stats.retrieved,
                        "y" if stats.retrieved == 1 else "ies",
                        agg.activities_retrieved,
                        _page_time_range(items),
                        stats.unmonitored,
                        len(agg.unmonitored_sources),
                        stats.excluded,
                    )
        agg.finalize()

    write_markdown(agg, target_label, start, end, md_path, members=members)

    print(f"{'Target:':<30}{target_label}")
    if args.dst_group_id:
        if not args.exclude_dst_group_as_source:
            member_count = "not loaded"
        elif members is None:
            member_count = "unavailable"
        else:
            member_count = str(max(len(members.ids), len(members.ips), len(members.fqdns)))
        print(f"{'Group Member Count:':<30}{member_count}")
    print(f"{'Window (UTC):':<30}{start:%Y-%m-%d %H:%M:%S} to {end:%Y-%m-%d %H:%M:%S}")
    print(f"{'Activities retrieved:':<30}{agg.activities_retrieved}")
    print(f"{'Unmonitored activities:':<30}{agg.unmonitored_activities}")
    print(f"{'Unique unmonitored sources:':<30}{len(agg.unmonitored_sources)}")
    print(f"{'Unique unmonitored src+dst:':<30}{len(agg.rows)}")
    print()
    if not agg.rows:
        print("No unmonitored sources found in this window.")
    else:
        print(render_console_table(agg.rows, args.top))
        if 0 < args.top < len(agg.rows):
            print(
                f"\nShowing top {args.top} of {len(agg.rows)} rows. The Markdown report has the "
                f"top {REPORT_TOP} and the CSV has every raw activity."
            )
    print()
    print(f"CSV:      {csv_path.resolve()}")
    print(f"Markdown: {md_path.resolve()}")
    return 0


def main(argv: list[str] | None = None, transport: httpx.BaseTransport | None = None) -> int:
    """Entry point: parse args, configure logging, run, and map errors to exit codes.

    Args:
        argv: argument list (defaults to sys.argv[1:]).
        transport: optional httpx transport override (used by tests).

    Returns:
        Process exit code: 0 on success, 1 on expected errors.
    """
    args = parse_args(argv)
    setup_logging(args.verbose)
    try:
        return run(args, transport=transport)
    except CLIError as exc:
        logger.error("%s", exc)
        return 1
    except OSError as exc:
        logger.error("Could not write the report: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
