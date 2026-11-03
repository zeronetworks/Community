# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "httpx",
#     "python-dotenv",
#     "tenacity",
# ]
# ///
"""Manually re-create asset mirroring through the Zero Networks API.

For every source asset S -> target asset T pair in the input CSV this script
copies S's network rules and group memberships onto T with individual API
calls. It never calls /assets/actions/mirror.

Without --apply the script is a dry run: it performs only GET requests and
writes a plan CSV. With --apply it performs the writes, recording progress in
a state CSV so an interrupted run can be continued with --resume.

Usage:
    uv run manual_mirror_assets.py --input pairs.csv                 # dry run
    uv run manual_mirror_assets.py --input pairs.csv --apply         # write
    uv run manual_mirror_assets.py --input pairs.csv --apply --resume outputs/manual-mirror-state-<ts>.csv
    uv run manual_mirror_assets.py --rollback outputs/manual-mirror-results-<ts>.csv --apply
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

REQUIRED_CSV_COLUMNS = ("srcAssetId", "srcAssetName", "dstAssetId", "dstAssetName")
RESULT_COLUMNS = (
    "srcAssetId",
    "srcAssetName",
    "dstAssetId",
    "dstAssetName",
    "category",
    "sourceObjectId",
    "operation",
    "status",
    "newObjectId",
    "reason",
    "bodyJson",
)
STATE_COLUMNS = (
    "srcAssetId",
    "dstAssetId",
    "category",
    "sourceObjectId",
    "operation",
    "bodyHash",
    "state",
    "newObjectId",
    "reason",
)
PAGE_LIMIT = 400
RETRY_ATTEMPTS = 3
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
DESCRIPTION_MAX_LENGTH = 512
DESCRIPTION_ORIG_PREFIX = " | orig: "

ACTION_ALLOW = 1
ACTION_BLOCK = 2
DIRECTION_CODES = {"inbound": 1, "outbound": 2}
DIRECTION_BOTH = 3
AD_SOURCE = 3
GROUP_ENDPOINTS = {"c": "custom", "t": "tag"}

RULE_STATE_ENABLED = 1
RULE_STATE_DISABLED = 2
RULE_STATE_DELETED = 3
RULE_STATE_PENDING = 4
RULE_STATE_PENDING_AUTO = 5
RULE_STATE_REJECTED = 6
RULE_STATE_EXCLUDED = 7
PENDING_STATES = (RULE_STATE_PENDING, RULE_STATE_PENDING_AUTO)
SKIP_STATES = (RULE_STATE_DELETED, RULE_STATE_REJECTED, RULE_STATE_EXCLUDED)

KIND_OWNER = "owner"
KIND_REMOTE = "remote"
KIND_BOTH = "both"
KIND_GROUP_INHERITED = "group_inherited"
KIND_EXCLUSION = "exclusion_not_mirrored"
KIND_SKIP_STATE = "skip_state"
KIND_SKIP_PENDING = "skip_pending"
KIND_SKIP_EXPIRED = "skip_expired"

SKIP_STATUS = {
    KIND_SKIP_STATE: "skipped_state",
    KIND_SKIP_PENDING: "skipped_pending",
    KIND_SKIP_EXPIRED: "skipped_expired",
    KIND_GROUP_INHERITED: "skipped_group_inherited",
    KIND_EXCLUSION: "exclusion_not_mirrored",
}
SKIP_REASON = {
    KIND_SKIP_STATE: "rule is deleted, rejected or excluded",
    KIND_SKIP_PENDING: "rule is pending review (use --include-pending to create it disabled)",
    KIND_SKIP_EXPIRED: "rule expiry is in the past",
    KIND_GROUP_INHERITED: "source reaches rule only through group membership; not mirrored",
    KIND_EXCLUSION: "source is in excludedLocalIdsList of a rule it does not own; not mirrored",
}

RULE_CATEGORIES = ("owner_rule", "inbound_remote_rule", "outbound_remote_rule")
SECONDARY_CATEGORIES = (
    "mfa_policy",
    "identity_rule",
    "identity_mfa_policy",
    "rpc_rule",
    "switch_rule",
    "external_access_policy",
    "connect_role",
)
IDENTITY_SOURCES = (3, 9)  # Active Directory, Azure Active Directory
MFA_DIRECTIONS = ("inbound", "outbound")
CONNECT_OPERATION = "update_connect_config"
CONNECT_LISTS = ("allowedAssetIds", "excludedAssetIds", "allowedDestinations")
MARKER_RE = re.compile(r"\[zn-mirror src-rule=([^\s\]]+) src=([^\s\]]+) dst=([^\s\]]+)\]")

logger = logging.getLogger("manual_mirror_assets")


@dataclass
class Config:
    """Runtime configuration loaded from the environment (.env)."""

    base_url: str
    api_key: str


@dataclass(frozen=True)
class AssetPair:
    """One source -> target asset pair from the input CSV."""

    src_id: str
    src_name: str
    dst_id: str
    dst_name: str


@dataclass
class RunOptions:
    """Behaviour switches derived from the CLI arguments."""

    apply: bool = False
    include_pending: bool = False
    self_ref_both: bool = False
    skip_groups: bool = False
    skip_owner_rules: bool = False
    skip_inbound_remote: bool = False
    skip_outbound_remote: bool = False
    skip_mfa: bool = False
    skip_identity: bool = False
    skip_rpc: bool = False
    skip_connect: bool = False
    include_switch: bool = False
    include_external_access: bool = False
    concurrency: int = 5
    now_ms: int = 0


@dataclass
class Action:
    """One planned (or executed) step for a pair, reported as one CSV row."""

    pair: AssetPair
    category: str
    source_object_id: str
    operation: str
    method: str = ""
    path: str = ""
    body: dict[str, Any] | None = None
    status: str = "planned"
    new_id: str = ""
    reason: str = ""


@dataclass
class TargetIndex:
    """Existing rules on the target, used for idempotency checks."""

    fingerprints: set[tuple] = field(default_factory=set)
    markers: set[tuple[str, str]] = field(default_factory=set)

    def add_rules(self, direction_code: int, rules: Iterable[dict[str, Any]]) -> None:
        """Index a batch of existing target rules.

        Args:
            direction_code: 1 for inbound rules, 2 for outbound rules.
            rules: rule dicts as returned by the rules list endpoint.
        """
        for rule in rules:
            self.fingerprints.add(rule_fingerprint(direction_code, rule))
            parsed = parse_marker(rule.get("description", ""))
            if parsed is not None:
                original_rule_id, _src, dst = parsed
                self.markers.add((original_rule_id, dst))


@dataclass
class ObjectIndex:
    """Existing target objects of one secondary category, used for idempotency."""

    fingerprints: set[tuple] = field(default_factory=set)
    markers: set[tuple[str, str]] = field(default_factory=set)

    def add(self, fingerprint: tuple, description: str | None) -> None:
        """Index one existing target object.

        Args:
            fingerprint: comparable identity built by a category's fingerprint function.
            description: the object's description, scanned for a zn-mirror marker.
        """
        self.fingerprints.add(fingerprint)
        parsed = parse_marker(description)
        if parsed is not None:
            original_id, _src, dst = parsed
            self.markers.add((original_id, dst))


# ---------------------------------------------------------------------------
# Configuration, logging and CLI
# ---------------------------------------------------------------------------


def load_config() -> Config:
    """Load ZN_API_BASE_URL and ZN_API_KEY from the environment / .env file.

    Returns:
        Config with the base URL (trailing slash stripped, "/api/v1" appended)
        and API key.

    Raises:
        SystemExit: if either required variable is missing.
    """
    load_dotenv()
    base_url = os.environ.get("ZN_API_BASE_URL", "").rstrip("/")
    if base_url:
        base_url += "/api/v1"
    api_key = os.environ.get("ZN_API_KEY", "")

    missing = [
        name
        for name, value in (("ZN_API_BASE_URL", base_url), ("ZN_API_KEY", api_key))
        if not value
    ]
    if missing:
        logger.error(
            "Missing required environment variable(s): %s. "
            "Copy .env.example to .env and fill in the values.",
            ", ".join(missing),
        )
        raise SystemExit(1)

    return Config(base_url=base_url, api_key=api_key)


def setup_logging(verbose: bool) -> None:
    """Configure root logging.

    Args:
        verbose: when True, set DEBUG level; otherwise INFO.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
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
        description="Manually mirror Zero Networks asset rules and groups (dry run by default)."
    )
    parser.add_argument(
        "--input",
        "-i",
        help="CSV with columns srcAssetId,srcAssetName,dstAssetId,dstAssetName.",
    )
    parser.add_argument("--output-dir", default="outputs", help="Directory for CSV reports.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--concurrency", type=int, default=5, help="Max in-flight API calls (default: 5)."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform writes. Without this flag only GET requests are made.",
    )
    parser.add_argument("--skip-groups", action="store_true", help="Do not add T to S's groups.")
    parser.add_argument(
        "--skip-owner-rules", action="store_true", help="Do not copy rules S owns onto T."
    )
    parser.add_argument(
        "--skip-inbound-remote",
        action="store_true",
        help="Do not copy inbound rules where S is the remote side.",
    )
    parser.add_argument(
        "--skip-outbound-remote",
        action="store_true",
        help="Do not copy outbound rules where S is the remote side.",
    )
    parser.add_argument(
        "--include-pending",
        action="store_true",
        help="Create pending-review rules on T as disabled.",
    )
    parser.add_argument(
        "--self-ref-both",
        action="store_true",
        help="Also emit the remote copy for rules where S is both local and remote.",
    )
    parser.add_argument("--skip-mfa", action="store_true", help="Do not copy MFA (reactive) policies.")
    parser.add_argument(
        "--skip-identity",
        action="store_true",
        help="Do not copy identity rules or identity MFA policies (AD/Azure AD targets only).",
    )
    parser.add_argument(
        "--skip-rpc", action="store_true", help="Do not copy RPC rules (Windows targets only)."
    )
    parser.add_argument(
        "--skip-connect", action="store_true", help="Do not add the target to Connect (VPN) roles."
    )
    parser.add_argument(
        "--include-switch",
        action="store_true",
        help="Also copy switch rules (off by default; skipped when auto-derived from network rules).",
    )
    parser.add_argument(
        "--include-external-access",
        action="store_true",
        help="Also copy external access policies (off by default).",
    )
    parser.add_argument(
        "--resume",
        metavar="STATE.csv",
        help="With --apply, skip actions already marked done in this state CSV.",
    )
    parser.add_argument(
        "--rollback",
        metavar="REPORT.csv",
        help="Delete objects created by a results report (dry run unless --apply).",
    )
    args = parser.parse_args(argv)
    if not args.rollback and not args.input:
        parser.error("--input is required unless --rollback is given")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    return args


def build_options(args: argparse.Namespace) -> RunOptions:
    """Translate CLI arguments into RunOptions, stamping the run time.

    Args:
        args: parsed CLI arguments.

    Returns:
        RunOptions for this run.
    """
    return RunOptions(
        apply=args.apply,
        include_pending=args.include_pending,
        self_ref_both=args.self_ref_both,
        skip_groups=args.skip_groups,
        skip_owner_rules=args.skip_owner_rules,
        skip_inbound_remote=args.skip_inbound_remote,
        skip_outbound_remote=args.skip_outbound_remote,
        skip_mfa=args.skip_mfa,
        skip_identity=args.skip_identity,
        skip_rpc=args.skip_rpc,
        skip_connect=args.skip_connect,
        include_switch=args.include_switch,
        include_external_access=args.include_external_access,
        concurrency=args.concurrency,
        now_ms=int(time.time() * 1000),
    )


def read_pairs_csv(path: str) -> dict[tuple[str, str], AssetPair]:
    """Read the input CSV into AssetPair objects keyed by (srcId, dstId).

    Args:
        path: path to the input CSV file.

    Returns:
        Dict mapping (srcAssetId, dstAssetId) -> AssetPair. A source may appear
        on several rows with different targets.

    Raises:
        SystemExit: if the file is missing or required columns are absent.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        logger.error("Input CSV not found: %s", csv_path)
        raise SystemExit(1)

    pairs: dict[tuple[str, str], AssetPair] = {}
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED_CSV_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            logger.error("Input CSV is missing required column(s): %s", ", ".join(missing))
            raise SystemExit(1)
        for row_num, row in enumerate(reader, start=2):
            src_id = row["srcAssetId"].strip()
            dst_id = row["dstAssetId"].strip()
            if not src_id or not dst_id:
                logger.warning("Skipping row %d: empty srcAssetId or dstAssetId", row_num)
                continue
            key = (src_id, dst_id)
            if key in pairs:
                logger.debug("Duplicate pair on row %d ignored: %s -> %s", row_num, src_id, dst_id)
                continue
            pairs[key] = AssetPair(
                src_id=src_id,
                src_name=row["srcAssetName"].strip(),
                dst_id=dst_id,
                dst_name=row["dstAssetName"].strip(),
            )

    logger.info("Loaded %d asset pair(s) from %s", len(pairs), csv_path)
    return pairs


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _is_retryable_error(exc: BaseException) -> bool:
    """Return True if an exception represents a transient/retryable read error."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in RETRY_STATUS_CODES
    return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))


def _is_rate_limited(exc: BaseException) -> bool:
    """Return True for a 429 response. Writes are retried only for this case."""
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429


async def api_request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> httpx.Response:
    """Send one API request with retries; non-2xx responses are returned, not raised.

    Reads are retried on 429/5xx and transport errors. Writes are retried only on
    429, because a 5xx or dropped connection on a POST may already have created the
    object and a retry could duplicate it.

    Args:
        client: shared httpx AsyncClient.
        method: HTTP method.
        path: path relative to the client base URL.
        params: optional query parameters.
        json_body: optional JSON request body.

    Returns:
        The final httpx.Response.
    """
    is_write = method.upper() != "GET"
    retry_predicate = _is_rate_limited if is_write else _is_retryable_error
    retry_statuses = {429} if is_write else RETRY_STATUS_CODES

    retrying = AsyncRetrying(
        reraise=True,
        stop=stop_after_attempt(RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception(retry_predicate),
    )
    response: httpx.Response | None = None
    async for attempt in retrying:
        with attempt:
            response = await client.request(method, path, params=params, json=json_body)
            if response.status_code in retry_statuses:
                response.raise_for_status()
    assert response is not None  # the loop always runs at least once
    return response


async def get_items(client: httpx.AsyncClient, path: str) -> list[dict[str, Any]]:
    """GET a single (non-paginated) endpoint and return its "items" list.

    Args:
        client: shared httpx AsyncClient.
        path: endpoint path.

    Returns:
        The "items" list (empty if absent).

    Raises:
        httpx.HTTPStatusError: on a non-2xx response.
    """
    response = await api_request(client, "GET", path)
    response.raise_for_status()
    return response.json().get("items", [])


async def paginate_offset(
    client: httpx.AsyncClient,
    path: str,
    params: dict[str, Any],
    limit: int = PAGE_LIMIT,
) -> list[dict[str, Any]]:
    """Fetch every page of an offset-paginated list endpoint.

    Requests pages of `limit` items, advancing `_offset` by `limit`, and stops
    after the first page that returns fewer than `limit` items. A page of exactly
    `limit` items therefore triggers one more request, which normally returns empty.

    Args:
        client: shared httpx AsyncClient.
        path: list endpoint path.
        params: extra query parameters (merged with _limit/_offset).
        limit: page size (API maximum is 400).

    Returns:
        All items across pages.

    Raises:
        httpx.HTTPStatusError: on a non-2xx response.
    """
    items: list[dict[str, Any]] = []
    offset = 0
    while True:
        query = {**params, "_limit": limit, "_offset": offset}
        response = await api_request(client, "GET", path, params=query)
        response.raise_for_status()
        page = response.json().get("items", [])
        items.extend(page)
        if len(page) < limit:
            break
        offset += limit
    return items


async def paginate_cursor(
    client: httpx.AsyncClient,
    path: str,
    params: dict[str, Any],
    limit: int = PAGE_LIMIT,
) -> list[dict[str, Any]]:
    """Fetch every page of a cursor-paginated list endpoint.

    Follows the "nextCursor" field of each response and sends it back as "_cursor".
    A full page without a "nextCursor" is an error, because the remaining items
    could not be reached.

    Args:
        client: shared httpx AsyncClient.
        path: list endpoint path.
        params: extra query parameters.
        limit: page size.

    Returns:
        All items across pages.

    Raises:
        RuntimeError: if the cursor is missing on a full page or does not advance.
        httpx.HTTPStatusError: on a non-2xx response.
    """
    items: list[dict[str, Any]] = []
    cursor: Any = None
    while True:
        query = {**params, "_limit": limit}
        if cursor is not None:
            query["_cursor"] = cursor
        response = await api_request(client, "GET", path, params=query)
        response.raise_for_status()
        payload = response.json()
        page = payload.get("items", [])
        items.extend(page)
        next_cursor = payload.get("nextCursor")
        if not next_cursor:
            if len(page) >= limit:
                raise RuntimeError(f"{path}: full page returned without nextCursor")
            return items
        if next_cursor == cursor:
            raise RuntimeError(f"{path}: cursor did not advance")
        cursor = next_cursor


async def fetch_rules(
    client: httpx.AsyncClient, asset_id: str, direction: str
) -> list[dict[str, Any]]:
    """List every rule in one direction that references an asset (as local or remote).

    Args:
        client: shared httpx AsyncClient.
        asset_id: asset whose rules to list.
        direction: "inbound" or "outbound".

    Returns:
        All matching rule dicts.
    """
    entity = json.dumps({"id": asset_id, "direction": DIRECTION_BOTH}, separators=(",", ":"))
    params = {
        "entityParams": entity,
        "_add_builtins": "false",
        "_add_ancestors": "false",
        "_enrich_remote_ips": "false",
    }
    return await paginate_offset(client, f"/protection/rules/{direction}", params, PAGE_LIMIT)


# ---------------------------------------------------------------------------
# Pure rule / group logic
# ---------------------------------------------------------------------------


def group_writable_kind(group_id: str) -> str | None:
    """Return the membership endpoint type for a group id, or None if read-only.

    Group ids look like g:<letter>:<id>. Letter c is a custom group and t is a tag
    group (both writable). Letters a (AD), s (system), o (OT) and anything else are
    read-only.

    Args:
        group_id: group id such as "g:c:1a2b3c4d".

    Returns:
        "custom", "tag", or None.
    """
    parts = group_id.split(":")
    if len(parts) < 3 or parts[0] != "g":
        return None
    return GROUP_ENDPOINTS.get(parts[1])


def minimal_groups(group_ids: list[str], ancestors_of: dict[str, set[str]]) -> list[str]:
    """Keep only the most specific groups from a list.

    A group is dropped when it is an ancestor of another group in the list, since
    membership in the child already implies membership in the parent.

    Args:
        group_ids: candidate group ids.
        ancestors_of: group id -> set of its ancestor group ids.

    Returns:
        The group ids (original order) that are not ancestors of another listed group.
    """
    listed = set(group_ids)
    redundant: set[str] = set()
    for child in group_ids:
        for ancestor in ancestors_of.get(child, set()) & listed:
            if ancestor != child:
                redundant.add(ancestor)
    return [gid for gid in group_ids if gid not in redundant]


def is_ot_or_iot(asset_id: str) -> bool:
    """Return True for OT/IoT asset ids (prefix a:o or a:t)."""
    return asset_id.startswith(("a:o", "a:t"))


def target_inactive(asset: dict[str, Any]) -> bool:
    """Return True if an asset is inactive (inactiveSince set or inactiveReason non-null)."""
    return bool(asset.get("inactiveSince")) or asset.get("inactiveReason") is not None


def is_ad_asset(asset: dict[str, Any]) -> bool:
    """Return True if the asset originates from Active Directory (source == 3)."""
    return asset.get("source") == AD_SOURCE


def classify_rule(
    rule: dict[str, Any], src_id: str, *, include_pending: bool, now_ms: int
) -> str:
    """Decide how a source rule is handled.

    Checks run in this order: state (deleted/rejected/excluded skipped), pending
    review (skipped unless include_pending), expiry in the past (skipped), then
    ownership. A rule whose excludedLocalIdsList names the source but which the
    source does not own is reported as exclusion_not_mirrored.

    Args:
        rule: rule dict from the API.
        src_id: source asset id S.
        include_pending: whether pending-review rules are processed.
        now_ms: current time in epoch milliseconds.

    Returns:
        One of the KIND_* constants.
    """
    state = rule.get("state") or RULE_STATE_ENABLED
    if state in SKIP_STATES:
        return KIND_SKIP_STATE
    if state in PENDING_STATES and not include_pending:
        return KIND_SKIP_PENDING
    expires = rule.get("expiresAt") or 0
    if expires > 0 and expires < now_ms:
        return KIND_SKIP_EXPIRED

    remote_ids = rule.get("remoteEntityIdsList") or []
    if rule.get("localEntityId") == src_id:
        return KIND_BOTH if src_id in remote_ids else KIND_OWNER
    if src_id in (rule.get("excludedLocalIdsList") or []):
        return KIND_EXCLUSION
    if src_id in remote_ids:
        return KIND_REMOTE
    return KIND_GROUP_INHERITED


def effective_state(rule: dict[str, Any]) -> int:
    """Return the state to send on create: pending review becomes disabled (2)."""
    state = rule.get("state") or RULE_STATE_ENABLED
    if state in PENDING_STATES:
        return RULE_STATE_DISABLED
    return state


def make_description(rule_id: str, pair: AssetPair, original: str | None) -> str:
    """Build the description for a mirrored rule.

    The marker "[zn-mirror src-rule=<id> src=<S> dst=<T>]" is always kept. The
    original description is appended after " | orig: " and is trimmed first when
    the total would exceed 512 characters.

    Args:
        rule_id: id of the source rule being mirrored.
        pair: the asset pair.
        original: the source rule's description, if any.

    Returns:
        The description string (at most 512 characters).
    """
    marker = f"[zn-mirror src-rule={rule_id} src={pair.src_id} dst={pair.dst_id}]"
    head = f"{marker} Mirrored from rule {rule_id} ({pair.src_name} -> {pair.dst_name})"
    if len(head) > DESCRIPTION_MAX_LENGTH:
        head = f"{marker} Mirrored from rule {rule_id}"

    original_text = (original or "").strip()
    room = DESCRIPTION_MAX_LENGTH - len(head) - len(DESCRIPTION_ORIG_PREFIX)
    if not original_text or room <= 0:
        return head
    return f"{head}{DESCRIPTION_ORIG_PREFIX}{original_text[:room]}"


def parse_marker(description: str | None) -> tuple[str, str, str] | None:
    """Extract (origRuleId, srcId, dstId) from a zn-mirror marker, if present."""
    match = MARKER_RE.search(description or "")
    return match.groups() if match else None


def _dedupe(items: list[str]) -> list[str]:
    """Remove duplicates while preserving order."""
    return list(dict.fromkeys(items))


def _build_body(
    rule: dict[str, Any], pair: AssetPair, local_id: str, remote_ids: list[str]
) -> dict[str, Any]:
    """Build a create body from a source rule, copying only the allowed fields.

    Args:
        rule: source rule dict.
        pair: the asset pair (for description and S removal).
        local_id: localEntityId for the new rule.
        remote_ids: remoteEntityIdsList for the new rule.

    Returns:
        Request body for POST /protection/rules/{direction}.
    """
    action = rule.get("action")
    body: dict[str, Any] = {
        "action": action,
        "localEntityId": local_id,
        "localProcessesList": list(rule.get("localProcessesList") or []),
        "portsList": list(rule.get("portsList") or []),
        "remoteEntityIdsList": remote_ids,
        "state": effective_state(rule),
        "description": make_description(str(rule.get("id", "")), pair, rule.get("description")),
    }
    if rule.get("servicesList") is not None:
        body["servicesList"] = list(rule["servicesList"])
    if rule.get("expiresAt"):
        body["expiresAt"] = rule["expiresAt"]
    if rule.get("excludedLocalIdsList") is not None:
        body["excludedLocalIdsList"] = [x for x in rule["excludedLocalIdsList"] if x != pair.src_id]
    if rule.get("srcUsersList") is not None:
        body["srcUsersList"] = rule["srcUsersList"]
    if action == ACTION_ALLOW and rule.get("ipSecOpt") is not None:
        body["ipSecOpt"] = rule["ipSecOpt"]
    return body


def build_owner_rule(rule: dict[str, Any], pair: AssetPair) -> dict[str, Any]:
    """Build the copy of a rule S owns, now owned by T.

    S in remoteEntityIdsList is replaced by T (self-reference), duplicates are
    removed, and S is removed from excludedLocalIdsList.

    Args:
        rule: source rule whose localEntityId is S.
        pair: the asset pair.

    Returns:
        Create body with localEntityId = T.
    """
    remote = [pair.dst_id if x == pair.src_id else x for x in rule.get("remoteEntityIdsList") or []]
    return _build_body(rule, pair, local_id=pair.dst_id, remote_ids=_dedupe(remote))


def build_remote_rule(rule: dict[str, Any], pair: AssetPair) -> dict[str, Any]:
    """Build the copy of a rule where S is the remote side: remote list becomes [T].

    The local side keeps its original value.

    Args:
        rule: source rule where S appears in remoteEntityIdsList.
        pair: the asset pair.

    Returns:
        Create body with remoteEntityIdsList = [T].
    """
    return _build_body(
        rule, pair, local_id=rule.get("localEntityId", ""), remote_ids=[pair.dst_id]
    )


def rule_fingerprint(direction_code: int, rule: dict[str, Any]) -> tuple:
    """Build a comparable identity for a rule, used to detect existing duplicates.

    Lists are sorted, ports are compared as (protocolType, ports) pairs, a missing
    expiry equals 0, and ipSecOpt only counts for allow rules (defaulting to 1).

    Args:
        direction_code: 1 for inbound, 2 for outbound.
        rule: rule dict (existing or planned body).

    Returns:
        A hashable tuple.
    """
    action = rule.get("action")
    ports = tuple(
        sorted((str(p.get("protocolType")), str(p.get("ports"))) for p in rule.get("portsList") or [])
    )
    ipsec = None
    if action == ACTION_ALLOW:
        ipsec = rule.get("ipSecOpt") if rule.get("ipSecOpt") is not None else 1
    return (
        direction_code,
        action,
        rule.get("localEntityId"),
        tuple(sorted(str(x) for x in rule.get("remoteEntityIdsList") or [])),
        ports,
        tuple(sorted(str(x) for x in rule.get("localProcessesList") or [])),
        tuple(sorted(str(x) for x in rule.get("servicesList") or [])),
        tuple(sorted(str(x) for x in rule.get("excludedLocalIdsList") or [])),
        ipsec,
        rule.get("expiresAt") or 0,
    )


def body_hash(body: dict[str, Any] | None) -> str:
    """Stable short hash of a request body, used as the state-file key."""
    if body is None:
        return ""
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def rule_category(owner_side: bool, direction: str) -> str:
    """Report category for a rule row: owner_rule if S is local, else the remote copy category."""
    return "owner_rule" if owner_side else f"{direction}_remote_rule"


def _skip_action(pair: AssetPair, category: str, rule_id: str, status: str, reason: str) -> Action:
    """Build a report-only action for a rule that will not be written."""
    return Action(
        pair=pair,
        category=category,
        source_object_id=rule_id,
        operation="skip",
        status=status,
        reason=reason,
    )


def _plan_create(
    rule: dict[str, Any],
    direction: str,
    pair: AssetPair,
    category: str,
    body: dict[str, Any],
    target: TargetIndex,
    planned: set[tuple],
) -> Action:
    """Turn one body into a POST action, or a skipped_exists action if it already exists."""
    rule_id = str(rule.get("id", ""))
    base = dict(
        pair=pair,
        category=category,
        source_object_id=rule_id,
        operation=f"create_{direction}_rule",
        method="POST",
        path=f"/protection/rules/{direction}",
        body=body,
    )
    if (rule_id, pair.dst_id) in target.markers:
        return Action(**base, status="skipped_exists", reason="marker for this source rule already on target")

    fingerprint = rule_fingerprint(DIRECTION_CODES[direction], body)
    if fingerprint in target.fingerprints:
        return Action(**base, status="skipped_exists", reason="identical rule already on target")
    if fingerprint in planned:
        return Action(**base, status="skipped_exists", reason="duplicate of a rule already planned in this run")
    planned.add(fingerprint)

    note = "pending-review source rule; created disabled" if rule.get("state") in PENDING_STATES else ""
    return Action(**base, status="planned", reason=note)


def plan_rule_actions(
    rule: dict[str, Any],
    direction: str,
    pair: AssetPair,
    opts: RunOptions,
    target: TargetIndex,
    planned: set[tuple],
) -> list[Action]:
    """Plan the writes (or skips) for one source rule.

    Args:
        rule: source rule from the listing for `direction`.
        direction: "inbound" or "outbound" (the list it came from).
        pair: the asset pair.
        opts: run options (skip flags, include_pending, self_ref_both, now_ms).
        target: existing target rules, for idempotency.
        planned: fingerprints already planned in this run, mutated.

    Returns:
        Zero or more Action objects.
    """
    rule_id = str(rule.get("id", ""))
    kind = classify_rule(rule, pair.src_id, include_pending=opts.include_pending, now_ms=opts.now_ms)
    owner_side = rule.get("localEntityId") == pair.src_id

    if kind in SKIP_STATUS:
        category = rule_category(owner_side, direction)
        return [_skip_action(pair, category, rule_id, SKIP_STATUS[kind], SKIP_REASON[kind])]

    actions: list[Action] = []
    if kind in (KIND_OWNER, KIND_BOTH) and not opts.skip_owner_rules:
        body = build_owner_rule(rule, pair)
        actions.append(_plan_create(rule, direction, pair, "owner_rule", body, target, planned))

    remote_wanted = kind == KIND_REMOTE or (kind == KIND_BOTH and opts.self_ref_both)
    skip_remote = opts.skip_inbound_remote if direction == "inbound" else opts.skip_outbound_remote
    if remote_wanted and not skip_remote:
        body = build_remote_rule(rule, pair)
        category = f"{direction}_remote_rule"
        actions.append(_plan_create(rule, direction, pair, category, body, target, planned))
    return actions


SECONDARY_DELETE_CATEGORIES = (
    "mfa_policy", "identity_rule", "identity_mfa_policy", "rpc_rule",
    "switch_rule", "external_access_policy",
)


def _secondary_delete_path(category: str, operation: str, new_id: str) -> str:
    """DELETE path that removes an object created by a secondary category."""
    direction = "inbound" if "inbound" in operation else "outbound"
    if category == "mfa_policy":
        return f"/protection/reactive-policies/{direction}/{new_id}"
    if category == "identity_rule":
        return f"/protection/identity-rules/{new_id}"
    if category == "identity_mfa_policy":
        return f"/protection/identity/reactive-policies/{new_id}"
    if category == "rpc_rule":
        return f"/protection/rpc-rules/{new_id}"
    if category == "switch_rule":
        return f"/protection/switch-rules/{direction}/{new_id}"
    return f"/protection/external-access-policies/{new_id}"


def plan_rollback(rows: Iterable[dict[str, str]]) -> list[Action]:
    """Build DELETE actions that undo the created objects listed in a results report.

    Rule rows use the direction recorded in their operation. Group rows remove the
    target from the group that was added.

    Args:
        rows: rows of a results CSV.

    Returns:
        DELETE actions for rows with status "created".
    """
    actions: list[Action] = []
    for row in rows:
        if row.get("status") not in ("created", "updated"):
            continue
        pair = AssetPair(
            src_id=row["srcAssetId"],
            src_name=row["srcAssetName"],
            dst_id=row["dstAssetId"],
            dst_name=row["dstAssetName"],
        )
        category = row["category"]
        source_id = row["sourceObjectId"]
        if category == "connect_role":
            actions.append(Action(
                pair, category, source_id, "rollback", status="rollback_unsupported",
                reason="Connect config updates are not reverted automatically; revert the config by hand",
            ))
            continue
        if category in SECONDARY_DELETE_CATEGORIES:
            new_id = row.get("newObjectId", "")
            if new_id:
                actions.append(Action(
                    pair, category, source_id, "rollback", "DELETE",
                    _secondary_delete_path(category, row.get("operation", ""), new_id),
                ))
            continue
        if category in RULE_CATEGORIES:
            new_id = row.get("newObjectId", "")
            if not new_id:
                continue
            direction = "inbound" if "inbound" in row.get("operation", "") else "outbound"
            actions.append(
                Action(pair, category, source_id, "rollback", "DELETE",
                       f"/protection/rules/{direction}/{new_id}")
            )
        elif category == "group":
            kind = group_writable_kind(source_id)
            if kind is None:
                continue
            actions.append(
                Action(pair, category, source_id, "rollback", "DELETE",
                       f"/groups/{kind}/{source_id}/members",
                       body={"membersId": [pair.dst_id]})
            )
    return actions


# ---------------------------------------------------------------------------
# Pair collection (read-only)
# ---------------------------------------------------------------------------


def _entity(response: httpx.Response) -> dict[str, Any]:
    """Return the "entity" object of a single-asset response."""
    return response.json().get("entity", {})


async def precheck_pair(
    client: httpx.AsyncClient, pair: AssetPair
) -> tuple[Action, str | None, dict[str, Any] | None]:
    """Run the pre-checks for one pair (read-only).

    Fails the pair for: same source and target, a 404 on either asset, an inactive
    target, or an OT/IoT asset on either side. Warns (pair continues) for an OS
    mismatch or an AD source mirrored to a non-AD target.

    Args:
        client: shared httpx AsyncClient.
        pair: the asset pair.

    Returns:
        Tuple of (precheck Action, target protectionState before the run, target
        asset entity). The last two are None if the pair failed.
    """

    def result(
        status: str, reason: str, before: str | None = None, target: dict[str, Any] | None = None
    ) -> tuple[Action, str | None, dict[str, Any] | None]:
        action = Action(pair, "precheck", pair.src_id, "validate", status=status, reason=reason)
        return action, before, target

    if pair.src_id == pair.dst_id:
        return result("failed", "source and target are the same asset")

    failures: list[str] = []
    assets: dict[str, dict[str, Any]] = {}
    for asset_id in (pair.src_id, pair.dst_id):
        response = await api_request(client, "GET", f"/assets/{asset_id}")
        if response.status_code == 404:
            failures.append(f"asset not found: {asset_id}")
        elif response.status_code >= 300:
            failures.append(f"HTTP {response.status_code} fetching asset {asset_id}")
        else:
            assets[asset_id] = _entity(response)
        if is_ot_or_iot(asset_id):
            failures.append(f"OT/IoT asset not supported: {asset_id}")

    if failures:
        return result("failed", "; ".join(failures))

    src, tgt = assets[pair.src_id], assets[pair.dst_id]
    if target_inactive(tgt):
        return result("failed", "target asset is inactive")

    warnings: list[str] = []
    if src.get("operatingSystem") != tgt.get("operatingSystem"):
        warnings.append(
            f"OS mismatch: source={src.get('operatingSystem')} target={tgt.get('operatingSystem')}"
        )
    if is_ad_asset(src) and not is_ad_asset(tgt):
        warnings.append("source is an AD asset but target is not")
    status = "warning" if warnings else "ok"
    return result(status, "; ".join(warnings), tgt.get("protectionState"), tgt)


async def collect_group_actions(client: httpx.AsyncClient, pair: AssetPair) -> list[Action]:
    """Plan group memberships to add T to (read-only).

    Args:
        client: shared httpx AsyncClient.
        pair: the asset pair.

    Returns:
        group actions: add_member (PUT) for writable groups, or skipped_* rows.
    """
    src_groups = await get_items(client, f"/assets/{pair.src_id}/ancestors")
    target_group_ids = {g.get("id") for g in await get_items(client, f"/assets/{pair.dst_id}/ancestors")}

    actions: list[Action] = []
    writable: list[str] = []
    kinds: dict[str, str] = {}
    for group in src_groups:
        gid = group.get("id", "")
        kind = group_writable_kind(gid)
        if kind is None:
            actions.append(Action(pair, "group", gid, "skip", status="skipped_readonly",
                                  reason="group type is read-only (AD, system or OT)"))
        elif gid in target_group_ids:
            actions.append(Action(pair, "group", gid, "skip", status="skipped_exists",
                                  reason="target is already a member"))
        else:
            writable.append(gid)
            kinds[gid] = kind

    ancestors_of: dict[str, set[str]] = {}
    for gid in writable:
        parents = await get_items(client, f"/groups/{kinds[gid]}/{gid}/ancestors")
        ancestors_of[gid] = {p.get("id") for p in parents}
    keep = set(minimal_groups(writable, ancestors_of))

    for gid in writable:
        if gid not in keep:
            actions.append(Action(pair, "group", gid, "skip", status="skipped_redundant",
                                  reason="a more specific listed group already implies membership"))
            continue
        kind = kinds[gid]
        actions.append(Action(
            pair, "group", gid, "add_member", method="PUT",
            path=f"/groups/{kind}/{gid}/members", body={"membersId": [pair.dst_id]},
        ))
    return actions


async def collect_rule_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan rule copies for both directions (read-only).

    Args:
        client: shared httpx AsyncClient.
        pair: the asset pair.
        opts: run options.
        planned: fingerprints already planned in this run, shared across pairs.

    Returns:
        Rule actions (creates and skips) for both directions.
    """
    target = TargetIndex()
    for direction, code in DIRECTION_CODES.items():
        target.add_rules(code, await fetch_rules(client, pair.dst_id, direction))

    actions: list[Action] = []
    for direction in DIRECTION_CODES:
        for rule in await fetch_rules(client, pair.src_id, direction):
            actions.extend(plan_rule_actions(rule, direction, pair, opts, target, planned))
    return actions


async def collect_pair_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> tuple[list[Action], str | None]:
    """Run every read-only step for one pair and return its actions.

    Args:
        client: shared httpx AsyncClient.
        pair: the asset pair.
        opts: run options.
        planned: fingerprints already planned in this run.

    Returns:
        Tuple of (actions, target protectionState before the run or None).
    """
    precheck, before, target = await precheck_pair(client, pair)
    actions = [precheck]
    if precheck.status == "failed":
        return actions, None
    if not opts.skip_groups:
        actions.extend(await collect_group_actions(client, pair))
    if not (opts.skip_owner_rules and opts.skip_inbound_remote and opts.skip_outbound_remote):
        actions.extend(await collect_rule_actions(client, pair, opts, planned))
    else:
        logger.info("All rule steps skipped for %s -> %s", pair.src_id, pair.dst_id)
    actions.extend(await collect_secondary_actions(client, pair, opts, planned, target or {}))
    return actions, before


async def build_plan(
    client: httpx.AsyncClient, pairs: list[AssetPair], opts: RunOptions
) -> tuple[list[Action], dict[AssetPair, str | None]]:
    """Collect actions for all pairs concurrently (read-only).

    A failure inside one pair is recorded as a failed row and does not stop the others.

    Args:
        client: shared httpx AsyncClient.
        pairs: pairs to process.
        opts: run options.

    Returns:
        Tuple of (all actions, dict of pair -> target protectionState before the run).
    """
    semaphore = asyncio.Semaphore(opts.concurrency)
    planned: set[tuple] = set()

    async def collect_one(pair: AssetPair) -> tuple[list[Action], str | None]:
        async with semaphore:
            try:
                return await collect_pair_actions(client, pair, opts, planned)
            except Exception as exc:  # noqa: BLE001 - reported per pair
                logger.exception("Planning failed for %s -> %s", pair.src_id, pair.dst_id)
                failed = Action(pair, "precheck", pair.src_id, "collect", status="failed",
                                reason=f"unexpected error: {type(exc).__name__}: {exc}")
                return [failed], None

    results = await asyncio.gather(*(collect_one(p) for p in pairs))
    actions: list[Action] = []
    befores: dict[AssetPair, str | None] = {}
    for pair, (pair_actions, before) in zip(pairs, results):
        actions.extend(pair_actions)
        if before is not None:
            befores[pair] = before
    return actions, befores


async def check_protection_states(
    client: httpx.AsyncClient, befores: dict[AssetPair, str | None]
) -> None:
    """Re-read each target's protectionState and log any change (read-only).

    Args:
        client: shared httpx AsyncClient.
        befores: pair -> protectionState recorded before the run.
    """
    for pair, before in befores.items():
        try:
            response = await api_request(client, "GET", f"/assets/{pair.dst_id}")
            after = _entity(response).get("protectionState")
        except Exception as exc:  # noqa: BLE001 - informational only
            logger.warning("Could not re-read protectionState for %s: %s", pair.dst_id, exc)
            continue
        if after != before:
            logger.warning("protectionState of target %s changed during run: %s -> %s",
                           pair.dst_id, before, after)
        else:
            logger.debug("protectionState of target %s unchanged (%s)", pair.dst_id, after)


# ---------------------------------------------------------------------------
# Secondary categories (read-only collectors and pure body builders)
# ---------------------------------------------------------------------------
#
# Each category follows the network-rule pattern: a collector lists the source
# and target objects with GET requests, builds the create body for every copy,
# and returns Action objects. Bodies are built by pure functions so they can be
# tested without a backend.


def _ids(entries: Any) -> list[str]:
    """Return the "id" of every dict entry in a list; other entries are ignored."""
    return [str(e["id"]) for e in entries or [] if isinstance(e, dict) and e.get("id")]


def _strs(values: Any) -> list[str]:
    """Return every entry of a list as a string (None becomes an empty list)."""
    return [str(v) for v in values or []]


def _sorted_set(values: Any, cast: Callable[[Any], Any] = str) -> tuple:
    """Order- and duplicate-insensitive tuple used inside fingerprints."""
    return tuple(sorted({cast(v) for v in values or []}))


def _insert_after(items: list[str], anchor: str, new: str) -> list[str]:
    """Insert `new` right after `anchor`, unless `new` is present or `anchor` is absent."""
    if new in items or anchor not in items:
        return list(items)
    index = items.index(anchor) + 1
    return [*items[:index], new, *items[index:]]


def _user_ids_any(obj: dict[str, Any]) -> list[str]:
    """Return user ids from whichever shape the object uses (id list or id-object list)."""
    if obj.get("srcUserIdsList") is not None:
        return _strs(obj["srcUserIdsList"])
    if obj.get("srcUserInfos") is not None:
        return _ids(obj["srcUserInfos"])
    return _ids(obj.get("srcUsersList"))


def _expired(obj: dict[str, Any], now_ms: int) -> bool:
    """Return True if the object has an expiry in the past."""
    expires = obj.get("expiresAt") or 0
    return 0 < expires < now_ms


def state_gate(state: int | None, *, include_pending: bool) -> tuple[str | None, str, int]:
    """Decide whether an object in this state is copied and which state to send.

    Args:
        state: the source object's state (None is treated as enabled).
        include_pending: whether pending-review objects are copied (as disabled).

    Returns:
        (skip_status, note, state_to_send). skip_status is None when the object is
        copied; otherwise note holds the reason. note is informational for copies.
    """
    value = state or RULE_STATE_ENABLED
    if value in SKIP_STATES:
        return SKIP_STATUS[KIND_SKIP_STATE], SKIP_REASON[KIND_SKIP_STATE], value
    if value in PENDING_STATES:
        if include_pending:
            return None, "pending-review source object; created disabled", RULE_STATE_DISABLED
        return SKIP_STATUS[KIND_SKIP_PENDING], SKIP_REASON[KIND_SKIP_PENDING], value
    return None, "", value


def _plan_post(
    *,
    pair: AssetPair,
    category: str,
    source_id: str,
    operation: str,
    path: str,
    body: dict[str, Any],
    fingerprint: tuple,
    index: ObjectIndex,
    planned: set[tuple],
    note: str = "",
) -> Action:
    """Turn one create body into a POST action, or skipped_exists if the target has it."""
    base = dict(
        pair=pair, category=category, source_object_id=source_id, operation=operation,
        method="POST", path=path, body=body,
    )
    if (source_id, pair.dst_id) in index.markers:
        return Action(**base, status="skipped_exists", reason="marker for this source object already on target")
    if fingerprint in index.fingerprints:
        return Action(**base, status="skipped_exists", reason="identical object already on target")
    key = (category, fingerprint)
    if key in planned:
        return Action(**base, status="skipped_exists", reason="duplicate of an object already planned in this run")
    planned.add(key)
    return Action(**base, status="planned", reason=note)


def _incompatible(pair: AssetPair, category: str, reason: str) -> Action:
    """Report row for a category that cannot be copied to this target."""
    return Action(pair, category, pair.src_id, "skip", status="incompatible_target", reason=reason)


async def _run_category(
    category: str, pair: AssetPair, collector: Callable[[], Awaitable[list[Action]]]
) -> list[Action]:
    """Run one category collector; a failure becomes a failed row and does not stop others."""
    try:
        return await collector()
    except Exception as exc:  # noqa: BLE001 - isolated per category
        logger.exception("%s planning failed for %s -> %s", category, pair.src_id, pair.dst_id)
        return [Action(pair, category, pair.src_id, "collect", status="failed",
                       reason=f"unexpected error: {type(exc).__name__}: {exc}")]


# --- MFA (reactive) policies ------------------------------------------------


async def fetch_mfa_policies(
    client: httpx.AsyncClient, asset_id: str, direction: str
) -> list[dict[str, Any]]:
    """List MFA policies that reference an asset (the list filters on _entityId)."""
    params = {"_entityId": asset_id, "_add_builtins": "false", "_add_ancestors": "false"}
    return await paginate_offset(client, f"/protection/reactive-policies/{direction}", params)


def classify_mfa_policy(policy: dict[str, Any], src_id: str) -> str | None:
    """Return owner (S is the destination), remote (S is a source), exclusion, or None."""
    if (policy.get("dstEntityInfo") or {}).get("id") == src_id:
        return KIND_OWNER
    if src_id in _ids(policy.get("srcEntityInfos")):
        return KIND_REMOTE
    if src_id in _ids(policy.get("excludedSrcEntityInfos")):
        return KIND_EXCLUSION
    return None


def mfa_fingerprint(direction_code: int, policy: dict[str, Any]) -> tuple:
    """Identity of an MFA policy for duplicate detection (works on responses and bodies)."""
    return (
        direction_code,
        (policy.get("dstEntityInfo") or {}).get("id"),
        _sorted_set(_ids(policy.get("srcEntityInfos"))),
        str(policy.get("dstPort", "")),
        policy.get("protocolType"),
        _sorted_set(policy.get("mfaMethods"), int),
    )


def build_mfa_body(
    policy: dict[str, Any], pair: AssetPair, *, owner: bool, state: int
) -> dict[str, Any]:
    """Build the create body for one MFA policy copy.

    Owner copy: the destination becomes T and S is replaced by T in the source list.
    Remote copy: the destination is unchanged and the source list becomes [T].
    Every *Infos list is reduced to [{"id": ...}] objects; S is removed from excluded lists.

    Args:
        policy: source policy from the list endpoint.
        pair: the asset pair.
        owner: True when S is the destination of the policy.
        state: state to send (1 or 2).

    Returns:
        Body for POST /protection/reactive-policies/{inbound|outbound}.
    """
    src_id = pair.src_id
    srcs = _ids(policy.get("srcEntityInfos"))
    if owner:
        dst_id = pair.dst_id
        new_srcs = _dedupe([pair.dst_id if x == src_id else x for x in srcs])
    else:
        dst_id = (policy.get("dstEntityInfo") or {}).get("id", "")
        new_srcs = [pair.dst_id]
    excluded = _dedupe([x for x in _ids(policy.get("excludedSrcEntityInfos")) if x != src_id])
    return {
        "description": make_description(str(policy.get("id", "")), pair, policy.get("description")),
        "dstEntityInfo": {"id": dst_id},
        "dstPort": str(policy.get("dstPort", "")),
        "dstProcessNames": _strs(policy.get("dstProcessNames")),
        "excludedSrcEntityInfos": [{"id": x} for x in excluded],
        "excludedSrcProcesses": _strs(policy.get("excludedSrcProcesses")),
        "fallbackToLoggedOnUser": bool(policy.get("fallbackToLoggedOnUser", False)),
        "mfaMethods": [int(m) for m in policy.get("mfaMethods") or []],
        "overrideBuiltins": bool(policy.get("overrideBuiltins", False)),
        "protocolType": policy.get("protocolType"),
        "restrictLoginToOriginatingUser": bool(policy.get("restrictLoginToOriginatingUser", False)),
        "ruleDuration": policy.get("ruleDuration"),
        "srcEntityInfos": [{"id": x} for x in _dedupe(new_srcs)],
        "srcProcessNames": _strs(policy.get("srcProcessNames")),
        "srcUserInfos": [{"id": x} for x in _user_ids_any(policy)],
        "state": state,
        "additionalPortsList": list(policy.get("additionalPortsList") or []),
    }


def plan_mfa_policy(
    policy: dict[str, Any], direction: str, pair: AssetPair, opts: RunOptions,
    index: ObjectIndex, planned: set[tuple],
) -> list[Action]:
    """Plan the copy (or skip row) for one source MFA policy."""
    kind = classify_mfa_policy(policy, pair.src_id)
    if kind is None:
        return []
    rule_id = str(policy.get("id", ""))
    category = "mfa_policy"
    if kind == KIND_EXCLUSION:
        return [_skip_action(pair, category, rule_id, SKIP_STATUS[KIND_EXCLUSION], SKIP_REASON[KIND_EXCLUSION])]
    skip_status, note, state = state_gate(policy.get("state"), include_pending=opts.include_pending)
    if skip_status:
        return [_skip_action(pair, category, rule_id, skip_status, note)]
    owner = kind == KIND_OWNER
    body = build_mfa_body(policy, pair, owner=owner, state=state)
    reason = note or ("owner copy" if owner else "remote copy: source asset is a source of this policy")
    return [_plan_post(
        pair=pair, category=category, source_id=rule_id,
        operation=f"create_{direction}_mfa_policy",
        path=f"/protection/reactive-policies/{direction}", body=body,
        fingerprint=mfa_fingerprint(DIRECTION_CODES[direction], body),
        index=index, planned=planned, note=reason,
    )]


async def collect_mfa_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan MFA policy copies in both directions (read-only)."""
    actions: list[Action] = []
    for direction in MFA_DIRECTIONS:
        index = ObjectIndex()
        for policy in await fetch_mfa_policies(client, pair.dst_id, direction):
            index.add(mfa_fingerprint(DIRECTION_CODES[direction], policy), policy.get("description"))
        for policy in await fetch_mfa_policies(client, pair.src_id, direction):
            actions.extend(plan_mfa_policy(policy, direction, pair, opts, index, planned))
    return actions


# --- Identity rules (AD / Azure AD targets) ---------------------------------


async def fetch_identity_rules(client: httpx.AsyncClient, asset_id: str) -> list[dict[str, Any]]:
    """List the identity rules of one asset (cursor-paginated)."""
    params = {"_add_builtins": "false", "_add_ancestors": "false"}
    return await paginate_cursor(client, f"/assets/{asset_id}/protection/identity-rules", params)


def identity_rule_fingerprint(rule: dict[str, Any]) -> tuple:
    """Identity of an identity rule for duplicate detection (responses and bodies)."""
    return (
        rule.get("action"),
        _sorted_set(rule.get("identityProtectionCategoryList"), int),
        _sorted_set(rule.get("userIdsList")),
        _sorted_set(rule.get("excludedAssetIdsList")),
        rule.get("expiresAt") or 0,
    )


def build_identity_rule_body(rule: dict[str, Any], pair: AssetPair, state: int) -> dict[str, Any]:
    """Build the create body for an identity rule of S, now assigned to T.

    Args:
        rule: source identity rule.
        pair: the asset pair.
        state: state to send (1 or 2).

    Returns:
        Body for POST /protection/identity-rules.
    """
    body: dict[str, Any] = {
        "assetId": pair.dst_id,
        "action": rule.get("action"),
        "identityProtectionCategoryList": [int(c) for c in rule.get("identityProtectionCategoryList") or []],
        "state": state,
        "userIdsList": _strs(rule.get("userIdsList")),
        "excludedAssetIdsList": _dedupe([x for x in _strs(rule.get("excludedAssetIdsList")) if x != pair.src_id]),
        "description": make_description(str(rule.get("id", "")), pair, rule.get("description")),
    }
    if rule.get("expiresAt"):
        body["expiresAt"] = rule["expiresAt"]
    return body


async def collect_identity_rule_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan identity rule copies (read-only)."""
    index = ObjectIndex()
    for rule in await fetch_identity_rules(client, pair.dst_id):
        index.add(identity_rule_fingerprint(rule), rule.get("description"))

    actions: list[Action] = []
    for rule in await fetch_identity_rules(client, pair.src_id):
        rule_id = str(rule.get("id", ""))
        if _expired(rule, opts.now_ms):
            actions.append(_skip_action(pair, "identity_rule", rule_id,
                                        SKIP_STATUS[KIND_SKIP_EXPIRED], SKIP_REASON[KIND_SKIP_EXPIRED]))
            continue
        skip_status, note, state = state_gate(rule.get("state"), include_pending=opts.include_pending)
        if skip_status:
            actions.append(_skip_action(pair, "identity_rule", rule_id, skip_status, note))
            continue
        body = build_identity_rule_body(rule, pair, state)
        actions.append(_plan_post(
            pair=pair, category="identity_rule", source_id=rule_id,
            operation="create_identity_rule", path="/protection/identity-rules", body=body,
            fingerprint=identity_rule_fingerprint(body), index=index, planned=planned,
            note=note or "owner copy",
        ))
    return actions


# --- Identity MFA policies (AD / Azure AD targets) ---------------------------


async def fetch_identity_mfa_policies(
    client: httpx.AsyncClient, asset_id: str
) -> list[dict[str, Any]]:
    """List the identity MFA policies of one asset (offset-paginated)."""
    params = {"_add_builtins": "false", "_add_ancestors": "false"}
    return await paginate_offset(client, f"/assets/{asset_id}/protection/identity/reactive-policies", params)


def classify_identity_mfa(policy: dict[str, Any], src_id: str) -> str | None:
    """Return owner (S is the destination), remote (S is a source), exclusion, or None."""
    if policy.get("dstAssetId") == src_id:
        return KIND_OWNER
    if src_id in _strs(policy.get("srcAssetIdsList")):
        return KIND_REMOTE
    if src_id in _strs(policy.get("excludedSrcAssetIdsList")):
        return KIND_EXCLUSION
    return None


def identity_mfa_fingerprint(policy: dict[str, Any]) -> tuple:
    """Identity of an identity MFA policy for duplicate detection (responses and bodies)."""
    return (
        policy.get("dstAssetId"),
        _sorted_set(policy.get("srcAssetIdsList")),
        _sorted_set(_user_ids_any(policy)),
        _sorted_set(policy.get("mfaMethodsList"), int),
        _sorted_set(policy.get("identityProtectionCategoryList"), int),
    )


def build_identity_mfa_body(
    policy: dict[str, Any], pair: AssetPair, *, owner: bool, state: int
) -> dict[str, Any]:
    """Build the create body for one identity MFA policy copy (same S -> T rules as MFA).

    Args:
        policy: source identity MFA policy.
        pair: the asset pair.
        owner: True when S is the destination asset.
        state: state to send (1 or 2).

    Returns:
        Body for POST /protection/identity/reactive-policies.
    """
    src_id = pair.src_id
    if owner:
        dst_id = pair.dst_id
        new_srcs = _dedupe([pair.dst_id if x == src_id else x for x in _strs(policy.get("srcAssetIdsList"))])
    else:
        dst_id = policy.get("dstAssetId") or ""
        new_srcs = [pair.dst_id]
    return {
        "description": make_description(str(policy.get("id", "")), pair, policy.get("description")),
        "dstAssetId": dst_id,
        "excludedDstAssetIdsList": [x for x in _strs(policy.get("excludedDstAssetIdsList")) if x != src_id],
        "excludedSrcAssetIdsList": [x for x in _strs(policy.get("excludedSrcAssetIdsList")) if x != src_id],
        "extraIdentityProtectionCategoryList": [int(c) for c in policy.get("extraIdentityProtectionCategoryList") or []],
        "fallbackToSingleLoggedOnUser": bool(policy.get("fallbackToSingleLoggedOnUser", False)),
        "identityProtectionCategoryList": [int(c) for c in policy.get("identityProtectionCategoryList") or []],
        "mfaMethodsList": [int(m) for m in policy.get("mfaMethodsList") or []],
        "overrideBuiltins": bool(policy.get("overrideBuiltins", False)),
        "restrictLoginToOriginatingUser": bool(policy.get("restrictLoginToOriginatingUser", False)),
        "ruleDuration": policy.get("ruleDuration"),
        "srcAssetIdsList": _dedupe(new_srcs),
        "srcUserIdsList": _user_ids_any(policy),
        "state": state,
    }


async def collect_identity_mfa_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan identity MFA policy copies (read-only)."""
    index = ObjectIndex()
    for policy in await fetch_identity_mfa_policies(client, pair.dst_id):
        index.add(identity_mfa_fingerprint(policy), policy.get("description"))

    actions: list[Action] = []
    category = "identity_mfa_policy"
    for policy in await fetch_identity_mfa_policies(client, pair.src_id):
        policy_id = str(policy.get("id", ""))
        kind = classify_identity_mfa(policy, pair.src_id)
        if kind is None:
            continue
        if kind == KIND_EXCLUSION:
            actions.append(_skip_action(pair, category, policy_id,
                                        SKIP_STATUS[KIND_EXCLUSION], SKIP_REASON[KIND_EXCLUSION]))
            continue
        skip_status, note, state = state_gate(policy.get("state"), include_pending=opts.include_pending)
        if skip_status:
            actions.append(_skip_action(pair, category, policy_id, skip_status, note))
            continue
        owner = kind == KIND_OWNER
        body = build_identity_mfa_body(policy, pair, owner=owner, state=state)
        reason = note or ("owner copy" if owner else "remote copy: source asset is a source of this policy")
        actions.append(_plan_post(
            pair=pair, category=category, source_id=policy_id,
            operation="create_identity_mfa_policy", path="/protection/identity/reactive-policies",
            body=body, fingerprint=identity_mfa_fingerprint(body), index=index,
            planned=planned, note=reason,
        ))
    return actions


# --- RPC rules (Windows targets) --------------------------------------------


def is_windows(asset: dict[str, Any]) -> bool:
    """Return True if the asset's operatingSystem text names Windows."""
    return "windows" in str(asset.get("operatingSystem") or "").lower()


async def fetch_rpc_rules(client: httpx.AsyncClient, asset_id: str) -> list[dict[str, Any]]:
    """List the RPC rules of one asset (offset-paginated)."""
    params = {"_add_builtins": "false", "_add_ancestors": "false"}
    return await paginate_offset(client, f"/assets/{asset_id}/protection/rpc-rules", params)


def classify_rpc_rule(rule: dict[str, Any], src_id: str) -> str | None:
    """Return owner (S is local), remote (S is in remoteAssetIdsList), exclusion, or None."""
    if rule.get("localAssetId") == src_id:
        return KIND_OWNER
    if src_id in _strs(rule.get("remoteAssetIdsList")):
        return KIND_REMOTE
    if src_id in _strs(rule.get("excludedAssetIdsList")):
        return KIND_EXCLUSION
    return None


def rpc_fingerprint(rule: dict[str, Any]) -> tuple:
    """Identity of an RPC rule for duplicate detection (responses and bodies)."""
    return (
        rule.get("action"),
        rule.get("localAssetId"),
        _sorted_set(rule.get("remoteAssetIdsList")),
        _sorted_set(rule.get("excludedAssetIdsList")),
        _sorted_set(rule.get("interfaceUuidsList")),
        _sorted_set(rule.get("opNumbersList")),
        _sorted_set(rule.get("protocolsList")),
        _sorted_set(rule.get("userIdsList")),
        rule.get("expiresAt") or 0,
    )


def build_rpc_body(rule: dict[str, Any], pair: AssetPair, *, owner: bool, state: int) -> dict[str, Any]:
    """Build the create body for one RPC rule copy.

    Owner copy: localAssetId becomes T and S is replaced by T in remoteAssetIdsList.
    Remote copy: localAssetId is kept and remoteAssetIdsList becomes [T].
    The description always carries the zn-mirror marker, because it is required.

    Args:
        rule: source RPC rule.
        pair: the asset pair.
        owner: True when S is the local asset.
        state: state to send (1 or 2).

    Returns:
        Body for POST /protection/rpc-rules.
    """
    src_id = pair.src_id
    if owner:
        local_id = pair.dst_id
        remote = _dedupe([pair.dst_id if x == src_id else x for x in _strs(rule.get("remoteAssetIdsList"))])
    else:
        local_id = str(rule.get("localAssetId") or "")
        remote = [pair.dst_id]
    body: dict[str, Any] = {
        "action": rule.get("action"),
        "description": make_description(str(rule.get("id", "")), pair, rule.get("description")),
        "excludedAssetIdsList": [x for x in _strs(rule.get("excludedAssetIdsList")) if x != src_id],
        "interfaceUuidsList": list(rule.get("interfaceUuidsList") or []),
        "localAssetId": local_id,
        "opNumbersList": list(rule.get("opNumbersList") or []),
        "protocolsList": list(rule.get("protocolsList") or []),
        "remoteAssetIdsList": remote,
        "state": state,
        "userIdsList": _strs(rule.get("userIdsList")),
    }
    if rule.get("expiresAt"):
        body["expiresAt"] = rule["expiresAt"]
    return body


async def collect_rpc_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan RPC rule copies (read-only). The caller has already checked the target OS."""
    index = ObjectIndex()
    for rule in await fetch_rpc_rules(client, pair.dst_id):
        index.add(rpc_fingerprint(rule), rule.get("description"))

    actions: list[Action] = []
    category = "rpc_rule"
    for rule in await fetch_rpc_rules(client, pair.src_id):
        rule_id = str(rule.get("id", ""))
        kind = classify_rpc_rule(rule, pair.src_id)
        if kind is None:
            continue
        if kind == KIND_EXCLUSION:
            actions.append(_skip_action(pair, category, rule_id,
                                        SKIP_STATUS[KIND_EXCLUSION], SKIP_REASON[KIND_EXCLUSION]))
            continue
        if _expired(rule, opts.now_ms):
            actions.append(_skip_action(pair, category, rule_id,
                                        SKIP_STATUS[KIND_SKIP_EXPIRED], SKIP_REASON[KIND_SKIP_EXPIRED]))
            continue
        skip_status, note, state = state_gate(rule.get("state"), include_pending=opts.include_pending)
        if skip_status:
            actions.append(_skip_action(pair, category, rule_id, skip_status, note))
            continue
        owner = kind == KIND_OWNER
        body = build_rpc_body(rule, pair, owner=owner, state=state)
        reason = note or ("owner copy" if owner else "remote copy: source asset is a remote of this rule")
        actions.append(_plan_post(
            pair=pair, category=category, source_id=rule_id, operation="create_rpc_rule",
            path="/protection/rpc-rules", body=body, fingerprint=rpc_fingerprint(body),
            index=index, planned=planned, note=reason,
        ))
    return actions


# --- Switch rules (opt-in, --include-switch) --------------------------------

SWITCH_DERIVED_FIELDS = ("mirrorNetworkRuleId", "switchParentRuleId", "policyParentRuleId")


def _switch_remote(rule: dict[str, Any]) -> list[str]:
    """Return the remote ids of a switch rule.

    The response uses remoteEntitiesIdList, the create body uses remoteEntityIdsList.
    """
    if "remoteEntityIdsList" in rule:
        return _strs(rule["remoteEntityIdsList"])
    return _strs(rule.get("remoteEntitiesIdList"))


def classify_switch_rule(rule: dict[str, Any], src_id: str) -> str | None:
    """Return owner (S is local), remote (S is in the remote list), or None."""
    if rule.get("localEntityId") == src_id:
        return KIND_OWNER
    if src_id in _switch_remote(rule):
        return KIND_REMOTE
    return None


def switch_fingerprint(direction_code: int, rule: dict[str, Any]) -> tuple:
    """Identity of a switch rule for duplicate detection (responses and bodies)."""
    return (
        direction_code,
        rule.get("action"),
        rule.get("localEntityId"),
        _sorted_set(_switch_remote(rule)),
        _sorted_set(rule.get("localProcessesList")),
        _sorted_set(rule.get("servicesList")),
        _sorted_set(rule.get("excludedLocalIdsList")),
        tuple(sorted({json.dumps(p, sort_keys=True) for p in rule.get("protocolsList") or []})),
        _sorted_set(_user_ids_any(rule)),
        rule.get("expiresAt") or 0,
    )


def build_switch_body(
    rule: dict[str, Any], direction: str, pair: AssetPair, *, owner: bool, state: int
) -> dict[str, Any]:
    """Build the create body for one switch rule copy.

    The switchRuleBody schema declares `remoteEntitiesIdList` as a property but lists
    `remoteEntityIdsList` as required. This builder sends `remoteEntityIdsList` (the
    required name). This is an unresolved spec conflict, to be confirmed live.

    shouldBuildMirrorRules is sent as false so that the server does not generate
    network rules, which this tool already copies separately.

    Args:
        rule: source switch rule.
        direction: "inbound" or "outbound" (the list it came from).
        pair: the asset pair.
        owner: True when S is the local asset.
        state: state to send (1 or 2).

    Returns:
        Body for POST /protection/switch-rules/{direction}.
    """
    src_id = pair.src_id
    if owner:
        local_id = pair.dst_id
        remote = _dedupe([pair.dst_id if x == src_id else x for x in _switch_remote(rule)])
    else:
        local_id = str(rule.get("localEntityId") or "")
        remote = [pair.dst_id]
    body: dict[str, Any] = {
        "action": rule.get("action"),
        "direction": DIRECTION_CODES[direction],
        "description": make_description(str(rule.get("id", "")), pair, rule.get("description")),
        "excludedLocalIdsList": [x for x in _strs(rule.get("excludedLocalIdsList")) if x != src_id],
        "localEntityId": local_id,
        "localProcessesList": _strs(rule.get("localProcessesList")),
        "protocolsList": [dict(p) for p in rule.get("protocolsList") or []],
        "remoteEntityIdsList": remote,
        "servicesList": _strs(rule.get("servicesList")),
        "shouldBuildMirrorRules": False,
        "state": state,
    }
    users = _user_ids_any(rule)
    if users:
        body["srcUsersList"] = [{"id": u} for u in users]
    if rule.get("expiresAt"):
        body["expiresAt"] = rule["expiresAt"]
    return body


async def fetch_switch_rules(client: httpx.AsyncClient, direction: str) -> list[dict[str, Any]]:
    """List every switch rule of one direction (the endpoint has no entity filter)."""
    params = {"_add_builtins": "false", "_add_ancestors": "false"}
    return await paginate_offset(client, f"/protection/switch-rules/{direction}", params)


async def collect_switch_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan switch rule copies (read-only). Rules auto-derived from network rules are skipped."""
    actions: list[Action] = []
    category = "switch_rule"
    for direction, code in DIRECTION_CODES.items():
        rules = await fetch_switch_rules(client, direction)
        index = ObjectIndex()
        for rule in rules:
            index.add(switch_fingerprint(code, rule), rule.get("description"))
        for rule in rules:
            rule_id = str(rule.get("id", ""))
            kind = classify_switch_rule(rule, pair.src_id)
            if kind is None:
                continue
            if any(rule.get(name) for name in SWITCH_DERIVED_FIELDS):
                actions.append(_skip_action(
                    pair, category, rule_id, "skipped_derived",
                    "auto-created from a network rule (mirror or parent rule id is set)",
                ))
                continue
            if _expired(rule, opts.now_ms):
                actions.append(_skip_action(pair, category, rule_id,
                                            SKIP_STATUS[KIND_SKIP_EXPIRED], SKIP_REASON[KIND_SKIP_EXPIRED]))
                continue
            skip_status, note, state = state_gate(rule.get("state"), include_pending=opts.include_pending)
            if skip_status:
                actions.append(_skip_action(pair, category, rule_id, skip_status, note))
                continue
            owner = kind == KIND_OWNER
            body = build_switch_body(rule, direction, pair, owner=owner, state=state)
            reason = note or ("owner copy" if owner else "remote copy: source asset is a remote of this rule")
            actions.append(_plan_post(
                pair=pair, category=category, source_id=rule_id,
                operation=f"create_{direction}_switch_rule",
                path=f"/protection/switch-rules/{direction}", body=body,
                fingerprint=switch_fingerprint(code, body), index=index, planned=planned, note=reason,
            ))
    return actions


# --- External access policies (opt-in, --include-external-access) -----------


async def fetch_external_access_policies(
    client: httpx.AsyncClient, asset_id: str
) -> list[dict[str, Any]]:
    """List the external access policies of one asset (offset-paginated)."""
    params = {"_add_builtins": "false", "_add_ancestors": "false"}
    return await paginate_offset(client, f"/assets/{asset_id}/protection/external-access-policies", params)


def external_access_fingerprint(policy: dict[str, Any]) -> tuple:
    """Identity of an external access policy for duplicate detection (responses and bodies)."""
    return (
        policy.get("dstAssetId"),
        tuple(sorted({(str(p.get("protocolType")), str(p.get("ports")))
                      for p in policy.get("dstPortsList") or []})),
        _sorted_set(policy.get("dstProcessNamesList")),
        _sorted_set(policy.get("srcUserIdsList")),
        policy.get("ruleDuration"),
    )


def build_external_access_body(policy: dict[str, Any], pair: AssetPair, state: int) -> dict[str, Any]:
    """Build the create body that recreates an external access policy for T (dstAssetId = T).

    Args:
        policy: source policy where S is the destination.
        pair: the asset pair.
        state: state to send (1 or 2).

    Returns:
        Body for POST /assets/{T}/protection/external-access-policies.
    """
    body: dict[str, Any] = {
        "description": make_description(str(policy.get("id", "")), pair, policy.get("description")),
        "dstAssetId": pair.dst_id,
        "dstPortsList": list(policy.get("dstPortsList") or []),
        "dstProcessNamesList": _strs(policy.get("dstProcessNamesList")),
        "name": str(policy.get("name") or ""),
        "ruleDuration": policy.get("ruleDuration"),
        "srcUserIdsList": _strs(policy.get("srcUserIdsList")),
        "state": state,
    }
    if policy.get("url"):
        body["url"] = policy["url"]
    return body


async def collect_external_access_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan external access policy copies for policies where S is the destination (read-only)."""
    index = ObjectIndex()
    for policy in await fetch_external_access_policies(client, pair.dst_id):
        index.add(external_access_fingerprint(policy), policy.get("description"))

    actions: list[Action] = []
    category = "external_access_policy"
    for policy in await fetch_external_access_policies(client, pair.src_id):
        policy_id = str(policy.get("id", ""))
        if policy.get("dstAssetId") != pair.src_id:
            continue
        if _expired(policy, opts.now_ms):
            actions.append(_skip_action(pair, category, policy_id,
                                        SKIP_STATUS[KIND_SKIP_EXPIRED], SKIP_REASON[KIND_SKIP_EXPIRED]))
            continue
        skip_status, note, state = state_gate(policy.get("state"), include_pending=opts.include_pending)
        if skip_status:
            actions.append(_skip_action(pair, category, policy_id, skip_status, note))
            continue
        body = build_external_access_body(policy, pair, state)
        actions.append(_plan_post(
            pair=pair, category=category, source_id=policy_id,
            operation="create_external_access_policy",
            path=f"/assets/{pair.dst_id}/protection/external-access-policies", body=body,
            fingerprint=external_access_fingerprint(body), index=index, planned=planned,
            note=note or "owner copy",
        ))
    return actions


# --- Connect (VPN) user access configs (serial, full-replace PUT) ------------


async def fetch_connect_configs(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """List every Connect user access config (offset-paginated)."""
    return await paginate_offset(client, "/settings/connect/user-access-config", {})


def connect_missing_lists(config: dict[str, Any], pair: AssetPair) -> list[str]:
    """Return the config lists that contain S but not T, in CONNECT_LISTS order."""
    return [
        key for key in CONNECT_LISTS
        if pair.src_id in _ids(config.get(key)) and pair.dst_id not in _ids(config.get(key))
    ]


def build_connect_body(config: dict[str, Any], pair: AssetPair) -> dict[str, Any] | None:
    """Build the full-replace PUT body for a Connect config with T added next to S.

    The response uses allowedAssetIds / excludedAssetIds / allowedDestinations,
    while the body uses loginAuthorizedEntities.allowedAssetIdsList, and so on.
    Every field is sent again, because the PUT replaces the whole config.

    Args:
        config: a Connect config as read from the list endpoint.
        pair: the asset pair.

    Returns:
        The body, or None when T is already present wherever S is.
    """
    missing = connect_missing_lists(config, pair)
    if not missing:
        return None
    lists = {key: _ids(config.get(key)) for key in CONNECT_LISTS}
    for key in missing:
        lists[key] = _insert_after(lists[key], pair.src_id, pair.dst_id)
    body: dict[str, Any] = {
        "name": config.get("name", ""),
        "allowedRegions": _ids(config.get("allowedRegions")),
        "connectivityStateAfterReboot": config.get("connectivityStateAfterReboot"),
        "dstEntityIdsList": lists["allowedDestinations"],
        "forceSsoAuthentication": bool(config.get("forceSsoAuthentication", False)),
        "loginAuthorizedEntities": {
            "allowedAssetIdsList": lists["allowedAssetIds"],
            "allowedAssetsSourcesList": _ids(config.get("allowedAssetSources")),
            "allowedUsersIdsList": _ids(config.get("allowedUserIds")),
            "excludedAssetIdsList": lists["excludedAssetIds"],
            "excludedUserIdsList": _ids(config.get("excludedUserIds")),
        },
        "sessionTtlHours": config.get("sessionTtlHours"),
    }
    if config.get("description"):
        body["description"] = config["description"]
    return body


async def collect_connect_actions(
    client: httpx.AsyncClient, pair: AssetPair, opts: RunOptions, planned: set[tuple]
) -> list[Action]:
    """Plan Connect config updates for every config that references S (read-only)."""
    actions: list[Action] = []
    category = "connect_role"
    for config in await fetch_connect_configs(client):
        config_id = str(config.get("id", ""))
        if not any(pair.src_id in _ids(config.get(key)) for key in CONNECT_LISTS):
            continue
        body = build_connect_body(config, pair)
        if body is None:
            actions.append(_skip_action(pair, category, config_id, "skipped_exists",
                                        "target already present in every Connect list that holds the source"))
            continue
        actions.append(Action(
            pair, category, config_id, CONNECT_OPERATION, method="PUT",
            path=f"/settings/connect/user-access-config/{config_id}", body=body,
            reason=f"adds target next to source in: {', '.join(connect_missing_lists(config, pair))}",
        ))
    return actions


# --- Dispatcher --------------------------------------------------------------


async def collect_secondary_actions(
    client: httpx.AsyncClient,
    pair: AssetPair,
    opts: RunOptions,
    planned: set[tuple],
    target: dict[str, Any],
) -> list[Action]:
    """Run the secondary categories in order: MFA, identity, RPC, switch, external access, Connect.

    Each category runs in isolation. Identity and RPC are gated on the target asset
    (AD/Azure AD source, Windows OS) and report one incompatible_target row otherwise.

    Args:
        client: shared httpx AsyncClient.
        pair: the asset pair.
        opts: run options.
        planned: fingerprints already planned in this run.
        target: target asset entity from the precheck.

    Returns:
        Actions (creates, updates and skip rows) for all enabled secondary categories.
    """
    actions: list[Action] = []
    if not opts.skip_mfa:
        actions += await _run_category("mfa_policy", pair,
                                       lambda: collect_mfa_actions(client, pair, opts, planned))

    if not opts.skip_identity:
        if target.get("source") in IDENTITY_SOURCES:
            actions += await _run_category("identity_rule", pair,
                                           lambda: collect_identity_rule_actions(client, pair, opts, planned))
            actions += await _run_category("identity_mfa_policy", pair,
                                           lambda: collect_identity_mfa_actions(client, pair, opts, planned))
        else:
            actions.append(_incompatible(
                pair, "identity_rule",
                "target asset is not Active Directory or Azure AD; identity rules and identity MFA policies not copied",
            ))

    if not opts.skip_rpc:
        if is_windows(target):
            actions += await _run_category("rpc_rule", pair,
                                           lambda: collect_rpc_actions(client, pair, opts, planned))
        else:
            actions.append(_incompatible(pair, "rpc_rule", "target asset is not Windows; RPC rules not copied"))

    if opts.include_switch:
        actions += await _run_category("switch_rule", pair,
                                       lambda: collect_switch_actions(client, pair, opts, planned))

    if opts.include_external_access:
        actions += await _run_category("external_access_policy", pair,
                                       lambda: collect_external_access_actions(client, pair, opts, planned))

    if not opts.skip_connect:
        actions += await _run_category("connect_role", pair,
                                       lambda: collect_connect_actions(client, pair, opts, planned))
    return actions


# ---------------------------------------------------------------------------
# Execution, state and reports
# ---------------------------------------------------------------------------


def state_key(action: Action) -> tuple[str, ...]:
    """Key identifying one planned write across runs (used for --resume)."""
    return (
        action.pair.src_id,
        action.pair.dst_id,
        action.category,
        action.source_object_id,
        action.operation,
        body_hash(action.body),
    )


def load_state(path: Path) -> dict[tuple[str, ...], str]:
    """Read a state CSV and return the last recorded state per action key.

    Args:
        path: state CSV written by a previous --apply run.

    Returns:
        Dict of state_key -> last state ("pending", "done" or "failed").
    """
    states: dict[tuple[str, ...], str] = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (
                row["srcAssetId"], row["dstAssetId"], row["category"],
                row["sourceObjectId"], row["operation"], row["bodyHash"],
            )
            states[key] = row["state"]
    return states


def append_state(path: Path | None, action: Action, state: str, new_id: str = "") -> None:
    """Append one progress row to the state CSV (no-op when path is None)."""
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.exists() or path.stat().st_size == 0
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(STATE_COLUMNS)
        writer.writerow((
            action.pair.src_id, action.pair.dst_id, action.category, action.source_object_id,
            action.operation, body_hash(action.body), state, new_id, action.reason,
        ))


def _extract_id(response: httpx.Response) -> str:
    """Return item.id from a create response, or "" when absent."""
    try:
        payload = response.json() if response.content else {}
    except ValueError:
        return ""
    item = payload.get("item") or {}
    return str(item.get("id", ""))


def _finish(action: Action, status: str, reason: str, state_path: Path | None,
            state: str, new_id: str = "") -> None:
    """Record the final status of an executed action and its state row."""
    action.status = status
    action.reason = reason
    action.new_id = new_id
    append_state(state_path, action, state, new_id)


async def execute_action(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    action: Action,
    state_path: Path | None,
    done: dict[tuple[str, ...], str],
) -> None:
    """Perform one write action, recording pending/done/failed in the state CSV.

    Args:
        client: shared httpx AsyncClient.
        semaphore: bounds in-flight writes.
        action: planned action with method set; status is updated in place.
        state_path: state CSV to append to, or None.
        done: state keys already completed (resume), skipped here.
    """
    if state_key(action) in done:
        action.status = "skipped_resumed"
        action.reason = "already done in resumed state file"
        return

    async with semaphore:
        append_state(state_path, action, "pending")
        try:
            response = await api_request(client, action.method, action.path, json_body=action.body)
        except Exception as exc:  # noqa: BLE001 - reported per action
            _finish(action, "failed", f"{type(exc).__name__}: {exc}", state_path, "failed")
            return

    code = response.status_code
    if 200 <= code < 300:
        success = "rolled_back" if action.method == "DELETE" else "created"
        _finish(action, success, "", state_path, "done", _extract_id(response))
    elif code == 409 and action.method == "POST":
        _finish(action, "skipped_exists", "HTTP 409: already exists", state_path, "done")
    else:
        _finish(action, "failed", f"HTTP {code}: {response.text[:300]}", state_path, "failed")
    logger.debug("%s %s -> %s", action.method, action.path, action.status)


async def execute_connect_action(
    client: httpx.AsyncClient, action: Action, state_path: Path | None
) -> None:
    """Apply one Connect config update. Called serially, never through the pool.

    The Connect config is global and its PUT replaces the whole object, so the
    config is re-read immediately before the write and the body is rebuilt from
    that fresh copy. This keeps concurrent edits (including earlier updates in
    this run) from being overwritten. Resume uses this re-check instead of the
    state file: an update that already landed is seen as present and skipped.

    Args:
        client: shared httpx AsyncClient.
        action: planned PUT action; its body and reason are replaced by the fresh body.
        state_path: state CSV to append to, or None.
    """
    try:
        configs = await fetch_connect_configs(client)
    except Exception as exc:  # noqa: BLE001 - reported per action
        _finish(action, "failed", f"could not re-read Connect configs: {type(exc).__name__}: {exc}",
                state_path, "failed")
        return

    config = next((c for c in configs if str(c.get("id")) == action.source_object_id), None)
    if config is None:
        _finish(action, "failed", "Connect config no longer exists", state_path, "failed")
        return

    body = build_connect_body(config, action.pair)
    if body is None:
        _finish(action, "skipped_exists", "target already present in the re-read Connect config",
                state_path, "done")
        return

    action.body = body
    action.reason = f"adds target next to source in: {', '.join(connect_missing_lists(config, action.pair))}"
    append_state(state_path, action, "pending")
    try:
        response = await api_request(client, "PUT", action.path, json_body=body)
    except Exception as exc:  # noqa: BLE001 - reported per action
        _finish(action, "failed", f"{type(exc).__name__}: {exc}", state_path, "failed")
        return

    if 200 <= response.status_code < 300:
        _finish(action, "updated", action.reason, state_path, "done")
    else:
        _finish(action, "failed", f"HTTP {response.status_code}: {response.text[:300]}",
                state_path, "failed")


async def execute_actions(
    client: httpx.AsyncClient,
    actions: list[Action],
    concurrency: int,
    state_path: Path | None,
    done: dict[tuple[str, ...], str],
) -> None:
    """Execute every planned write: rule and object creates concurrently, Connect serially.

    Args:
        client: shared httpx AsyncClient.
        actions: all actions; only status "planned" with a method are executed.
        concurrency: maximum in-flight writes for the concurrent group.
        state_path: state CSV to append to, or None.
        done: completed state keys to skip (concurrent group only).
    """
    semaphore = asyncio.Semaphore(concurrency)
    writes = [a for a in actions if a.method and a.status == "planned"]
    logger.info("Executing %d write(s)", len(writes))
    concurrent = [a for a in writes if a.operation != CONNECT_OPERATION]
    serial = [a for a in writes if a.operation == CONNECT_OPERATION]
    await asyncio.gather(*(execute_action(client, semaphore, a, state_path, done) for a in concurrent))
    for action in serial:
        await execute_connect_action(client, action, state_path)


def action_to_row(action: Action) -> dict[str, str]:
    """Convert an action to a report row keyed by RESULT_COLUMNS."""
    return {
        "srcAssetId": action.pair.src_id,
        "srcAssetName": action.pair.src_name,
        "dstAssetId": action.pair.dst_id,
        "dstAssetName": action.pair.dst_name,
        "category": action.category,
        "sourceObjectId": action.source_object_id,
        "operation": action.operation,
        "status": action.status,
        "newObjectId": action.new_id,
        "reason": action.reason,
        "bodyJson": json.dumps(action.body, sort_keys=True) if action.body is not None else "",
    }


def write_csv(path: Path, columns: tuple[str, ...], rows: Iterable[dict[str, str]]) -> None:
    """Write rows to a CSV file, creating the parent directory if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def read_result_rows(path: Path) -> list[dict[str, str]]:
    """Read a results CSV written by a previous run."""
    if not path.is_file():
        logger.error("Results CSV not found: %s", path)
        raise SystemExit(1)
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def print_summary(actions: list[Action], report_path: Path) -> None:
    """Log a per-status count and the report location."""
    counts = Counter(action.status for action in actions)
    logger.info("Summary (%d action(s)):", len(actions))
    for status, count in sorted(counts.items()):
        logger.info("  %-26s %d", status, count)
    logger.info("Report: %s", report_path)


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------


async def run_forward(
    client: httpx.AsyncClient, args: argparse.Namespace, opts: RunOptions,
    output_dir: Path, ts: str,
) -> int:
    """Plan (and with --apply, execute) mirroring for every pair in the input CSV.

    Args:
        client: shared httpx AsyncClient.
        args: parsed CLI arguments.
        opts: run options.
        output_dir: directory for reports and state.
        ts: timestamp suffix for output file names.

    Returns:
        Exit code: 1 if any action failed, else 0.
    """
    pairs = list(read_pairs_csv(args.input).values())
    if not pairs:
        logger.warning("No asset pairs to process.")
        return 0

    actions, befores = await build_plan(client, pairs, opts)

    if opts.apply:
        state_path: Path | None = output_dir / f"manual-mirror-state-{ts}.csv"
        done: dict[tuple[str, ...], str] = {}
        if args.resume:
            state_path = Path(args.resume)
            if not state_path.is_file():
                logger.error("Resume state CSV not found: %s", state_path)
                return 1
            done = {k: v for k, v in load_state(state_path).items() if v == "done"}
            logger.info("Resuming: %d completed action(s) will be skipped", len(done))
        await execute_actions(client, actions, opts.concurrency, state_path, done)
        report_path = output_dir / f"manual-mirror-results-{ts}.csv"
    else:
        if args.resume:
            logger.warning("--resume has no effect without --apply")
        for action in actions:
            if action.method:
                logger.info("PLAN %s %s %s %s", action.pair.src_id, action.pair.dst_id,
                            action.method, action.path)
        logger.info("Dry run: no writes performed. Re-run with --apply to execute.")
        report_path = output_dir / f"manual-mirror-plan-{ts}.csv"

    await check_protection_states(client, befores)
    write_csv(report_path, RESULT_COLUMNS, (action_to_row(a) for a in actions))
    print_summary(actions, report_path)
    return 1 if any(a.status == "failed" for a in actions) else 0


async def run_rollback(
    client: httpx.AsyncClient, opts: RunOptions, report: str, output_dir: Path, ts: str,
) -> int:
    """Plan (and with --apply, execute) deletion of objects created by a results report.

    Args:
        client: shared httpx AsyncClient.
        opts: run options (apply flag and concurrency).
        report: path to a manual-mirror-results CSV.
        output_dir: directory for the rollback CSV.
        ts: timestamp suffix.

    Returns:
        Exit code: 1 if any delete failed, else 0.
    """
    actions = plan_rollback(read_result_rows(Path(report)))
    if opts.apply:
        await execute_actions(client, actions, opts.concurrency, None, {})
        report_path = output_dir / f"manual-mirror-rollback-{ts}.csv"
    else:
        logger.info("Rollback dry run: no deletes performed. Re-run with --apply to execute.")
        report_path = output_dir / f"manual-mirror-rollback-plan-{ts}.csv"
    write_csv(report_path, RESULT_COLUMNS, (action_to_row(a) for a in actions))
    print_summary(actions, report_path)
    return 1 if any(a.status == "failed" for a in actions) else 0


async def main_async(args: argparse.Namespace) -> int:
    """Load config, then run either the forward mirror or the rollback.

    Args:
        args: parsed CLI arguments.

    Returns:
        Process exit code.
    """
    config = load_config()
    opts = build_options(args)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output_dir)
    headers = {"Authorization": config.api_key}

    async with httpx.AsyncClient(base_url=config.base_url, headers=headers, timeout=30.0) as client:
        if args.rollback:
            return await run_rollback(client, opts, args.rollback, output_dir, ts)
        return await run_forward(client, args, opts, output_dir, ts)


def main() -> None:
    """Entry point: parse args, configure logging, run the async pipeline."""
    args = parse_args()
    setup_logging(args.verbose)
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
