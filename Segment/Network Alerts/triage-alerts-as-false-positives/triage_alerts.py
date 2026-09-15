# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "httpx",
#     "python-dotenv",
#     "tenacity",
# ]
# ///
"""Bulk-triage Zero Networks network alerts from a CSV export.

Reads a CSV export of network alerts (as downloaded from the portal's
Network Alerts page), and applies a state change and/or classification
change to every alert ID in it via the Network Alerts API.

Usage:
    uv run triage_alerts.py --input alerts.csv --state closed \
        --classification false-positive --classification-category not-malicious
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
from dotenv import load_dotenv
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

ID_COLUMN = "ID"
RETRY_ATTEMPTS = 3
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}

logger = logging.getLogger("triage_alerts")

# State: CLI kebab-case value -> API slug. Confirmed against real PATCH
# responses. "new" is deliberately excluded: the API rejects it as a target
# state ("state failed custom validation because value must be one of
# [in_progress, closed, reopened]") - it's only a state alerts start in, not
# one you can transition back to.
STATE_SLUGS: dict[str, str] = {
    "in-progress": "in_progress",
    "closed": "closed",
    "reopened": "reopened",
}

# Classification: (CLI classification, CLI classification-category) -> API
# slug for the single `userAlertClassification` field. Built from the 14
# labels returned by GET /alerts/filters. Only false-positive/not-malicious
# ("not_malicious") is confirmed against a real PATCH response - every other
# row is a best-effort guess at the API's naming convention. The two "Other"
# categories (under True positive / Informational) are disambiguated with a
# per-parent suffix since both share the label "Other" but must map to
# distinct slugs - that disambiguation scheme is also a guess.
CLASSIFICATION_SLUGS: dict[tuple[str, str], str] = {
    ("true-positive", "multi-staged-attack"): "multi_staged_attack",
    ("true-positive", "malware"): "malware",
    ("true-positive", "malicious-user-activity"): "malicious_user_activity",
    ("true-positive", "unwanted-software"): "unwanted_software",
    ("true-positive", "phishing"): "phishing",
    ("true-positive", "compromised-account"): "compromised_account",
    ("true-positive", "other"): "true_positive_other",
    ("informational", "security-testing"): "security_testing",
    ("informational", "confirmed-activity"): "confirmed_activity",
    ("informational", "line-of-business-application"): "line_of_business_application",
    ("informational", "other"): "informational_other",
    ("false-positive", "not-malicious"): "not_malicious",
    ("false-positive", "not-enough-data"): "not_enough_data",
    ("false-positive", "other"): "false_positive_other",
}

CLASSIFICATION_CHOICES = sorted({c for c, _ in CLASSIFICATION_SLUGS})
CLASSIFICATION_CATEGORY_CHOICES = sorted({cat for _, cat in CLASSIFICATION_SLUGS})


@dataclass
class Config:
    """Runtime configuration loaded from the environment (.env)."""

    base_url: str
    api_key: str


@dataclass
class TriageResult:
    """Outcome of triaging a single alert."""

    alert_id: str
    error: str | None = None


def load_config() -> Config:
    """Load ZN_API_BASE_URL and ZN_API_KEY from the environment / .env file.

    Returns:
        Config with the base URL (trailing slash stripped, "/api/v1" appended)
        and API key.

    Raises:
        SystemExit: if either required variable is missing.
    """
    load_dotenv()
    import os

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
        description="Bulk-triage Zero Networks network alerts from a CSV export."
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to the network alerts CSV export (must have an 'ID' column).",
    )
    parser.add_argument(
        "--state",
        choices=sorted(STATE_SLUGS),
        help="New alert state to set on every alert in the CSV.",
    )
    parser.add_argument(
        "--classification",
        choices=CLASSIFICATION_CHOICES,
        help="Top-level classification bucket. Requires --classification-category "
        "(or use --classification-slug instead of this pair).",
    )
    parser.add_argument(
        "--classification-category",
        choices=CLASSIFICATION_CATEGORY_CHOICES,
        help="Specific classification reason within --classification.",
    )
    parser.add_argument(
        "--classification-slug",
        help="Raw API classification slug to send verbatim, bypassing the "
        "--classification/--classification-category lookup table (use this if a "
        "guessed slug turns out wrong - see README for the confirmed/guessed table).",
    )
    parser.add_argument(
        "--comment",
        default=None,
        help="Optional comment to set on every alert.",
    )
    parser.add_argument(
        "--assigneeEmail",
        dest="assignee_email",
        default=None,
        help="Email of the account to assign every alert to. Looked up via "
        "GET /users (filtered by email) and resolved to its entity ID for "
        "assigneeUserId; terminates if no matching account is found.",
    )
    parser.add_argument(
        "--change-ticket",
        default=None,
        help="Optional change ticket value to set on every alert.",
    )
    parser.add_argument(
        "--customHeaders",
        dest="custom_headers",
        default=None,
        help='JSON-encoded object of extra headers to append to every request, '
        'e.g. \'{"zn-env-id":"..."}\'.',
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Maximum number of concurrent in-flight PATCH calls (default: 10).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would be sent for each alert without calling the API.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging (includes per-HTTP-request detail).",
    )
    args = parser.parse_args(argv)

    if bool(args.classification) != bool(args.classification_category):
        parser.error("--classification and --classification-category must be given together.")
    if args.classification and args.classification_slug:
        parser.error(
            "Use either --classification/--classification-category or "
            "--classification-slug, not both."
        )
    if not any(
        (args.state, args.classification, args.classification_slug, args.assignee_email)
    ):
        parser.error(
            "Nothing to do: provide --state, --classification/"
            "--classification-category (or --classification-slug), and/or "
            "--assigneeEmail."
        )

    return args


def resolve_classification_slug(args: argparse.Namespace) -> str | None:
    """Resolve the API classification slug from CLI arguments.

    Args:
        args: parsed CLI arguments.

    Returns:
        The API slug to send, or None if no classification change was requested.

    Raises:
        SystemExit: if --classification/--classification-category names a
            combination not present in the lookup table.
    """
    if args.classification_slug:
        return args.classification_slug
    if not args.classification:
        return None

    key = (args.classification, args.classification_category)
    slug = CLASSIFICATION_SLUGS.get(key)
    if slug is None:
        logger.error(
            "No known mapping for --classification %s --classification-category %s. "
            "See README for valid combinations, or pass --classification-slug directly.",
            args.classification,
            args.classification_category,
        )
        raise SystemExit(1)
    return slug


def read_alert_ids(path: str) -> list[str]:
    """Read alert IDs from the CSV export's ID column.

    Args:
        path: path to the input CSV file.

    Returns:
        Deduplicated (order-preserving) list of non-empty alert IDs.

    Raises:
        SystemExit: if the file is missing or the ID column is absent.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        logger.error("Input CSV not found: %s", csv_path)
        raise SystemExit(1)

    ids: list[str] = []
    seen: set[str] = set()
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or ID_COLUMN not in reader.fieldnames:
            logger.error("Input CSV is missing required column: %s", ID_COLUMN)
            raise SystemExit(1)

        for row_num, row in enumerate(reader, start=2):
            alert_id = (row.get(ID_COLUMN) or "").strip()
            if not alert_id:
                logger.warning("Skipping row %d: empty %s", row_num, ID_COLUMN)
                continue
            if alert_id in seen:
                logger.warning("Skipping row %d: duplicate alert ID %s", row_num, alert_id)
                continue
            seen.add(alert_id)
            ids.append(alert_id)

    logger.info("Loaded %d alert ID(s) from %s", len(ids), csv_path)
    return ids


def build_shared_body(
    args: argparse.Namespace,
    classification_slug: str | None,
    assignee_user_id: str | None,
) -> dict:
    """Build the PATCH body fields shared across every alert.

    Args:
        args: parsed CLI arguments.
        classification_slug: resolved API classification slug, if any.
        assignee_user_id: resolved portal user entity ID to assign, if any.

    Returns:
        Dict of body fields to merge with each alert's "alertId".
    """
    body: dict = {}
    if args.state:
        body["state"] = STATE_SLUGS[args.state]
    if classification_slug:
        body["userAlertClassification"] = classification_slug
    if assignee_user_id is not None:
        body["assigneeUserId"] = assignee_user_id
    if args.comment is not None:
        body["comment"] = args.comment
    if args.change_ticket is not None:
        body["changeTicket"] = args.change_ticket
    return body


async def resolve_assignee_id(client: httpx.AsyncClient, email: str) -> str:
    """Look up a Zero Networks account by email and return its entity ID.

    Args:
        client: shared httpx AsyncClient.
        email: email address of the account to assign alerts to.

    Returns:
        The matching account's entity ID (e.g. "u:a:...").

    Raises:
        SystemExit: if no account, or more than one account, matches the email.
    """
    filters = [{"id": "email", "includeValues": [email], "excludeValues": []}]
    params = {
        "_limit": 100,
        "_offset": 0,
        "_search": "",
        "with_count": "true",
        "_filters": json.dumps(filters),
        "order": "asc",
        "orderColumns[]": "name",
        "showInactive": "false",
    }
    response = await client.get("/users", params=params)
    response.raise_for_status()
    items = response.json().get("items", [])
    matches = [u for u in items if (u.get("email") or "").lower() == email.lower()]

    if not matches:
        logger.error("No account found with email: %s", email)
        raise SystemExit(1)
    if len(matches) > 1:
        logger.error(
            "Multiple accounts found with email: %s (ids: %s)",
            email,
            ", ".join(m.get("id", "?") for m in matches),
        )
        raise SystemExit(1)

    account_id = matches[0]["id"]
    logger.info("Resolved assignee %s to account ID %s", email, account_id)
    return account_id


def _is_retryable_error(exc: BaseException) -> bool:
    """Return True if an exception represents a transient/retryable API error."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in RETRY_STATUS_CODES
    return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))


@retry(
    reraise=True,
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception(_is_retryable_error),
)
async def _patch_alert(client: httpx.AsyncClient, alert_id: str, body: dict) -> None:
    """Issue the PATCH request to update one alert.

    Args:
        client: shared httpx AsyncClient.
        alert_id: the alert's "n:d:..." id.
        body: shared body fields (state/classification/comment/changeTicket).

    Raises:
        httpx.HTTPStatusError: on a non-2xx response (retried if transient).
    """
    response = await client.patch(
        f"/network/alerts/{alert_id}",
        json={"alertId": alert_id, **body},
    )
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise httpx.HTTPStatusError(
            f"{exc}. Response body: {response.text}",
            request=exc.request,
            response=exc.response,
        ) from exc


async def triage_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    alert_id: str,
    body: dict,
    dry_run: bool,
) -> TriageResult:
    """Triage a single alert, catching (not raising) any final failure.

    Args:
        client: shared httpx AsyncClient.
        semaphore: bounds concurrent in-flight PATCH calls.
        alert_id: the alert's "n:d:..." id.
        body: shared body fields to send.
        dry_run: if True, log the intended request without calling the API.

    Returns:
        TriageResult with error=None on success, or a reason string on failure.
    """
    if dry_run:
        logger.info("[dry-run] Would PATCH alert %s with %s", alert_id, body)
        return TriageResult(alert_id=alert_id)

    async with semaphore:
        try:
            await _patch_alert(client, alert_id, body)
        except Exception as exc:  # noqa: BLE001 - intentionally broad, reported per-alert
            logger.error("Failed to triage alert %s: %s", alert_id, exc)
            return TriageResult(alert_id=alert_id, error=str(exc))
        logger.info("Triaged alert %s", alert_id)
        return TriageResult(alert_id=alert_id)


async def run_triage(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    alert_ids: list[str],
    body: dict,
    dry_run: bool,
) -> list[TriageResult]:
    """Concurrently triage every alert in alert_ids.

    Args:
        client: shared httpx AsyncClient.
        semaphore: bounds concurrent in-flight PATCH calls.
        alert_ids: alert IDs to update.
        body: shared body fields to send.
        dry_run: if True, don't call the API.

    Returns:
        List of TriageResult, one per alert.
    """
    return await asyncio.gather(
        *(triage_one(client, semaphore, alert_id, body, dry_run) for alert_id in alert_ids)
    )


def print_summary(results: list[TriageResult]) -> None:
    """Log a console summary of the run's results.

    Args:
        results: one TriageResult per alert processed.
    """
    failures = [r for r in results if r.error is not None]
    if failures:
        logger.info(
            "%d alert(s) triaged successfully, %d failed:",
            len(results) - len(failures),
            len(failures),
        )
        for failure in failures:
            logger.info("  %s: %s", failure.alert_id, failure.error)
    else:
        logger.info("%d alert(s) triaged successfully, none failed.", len(results))


async def main_async(args: argparse.Namespace) -> int:
    """Orchestrate the full read -> triage -> summarize pipeline.

    Args:
        args: parsed CLI arguments.

    Returns:
        Process exit code (0 if no alerts failed, else 1).
    """
    classification_slug = resolve_classification_slug(args)

    custom_headers: dict = {}
    if args.custom_headers:
        try:
            custom_headers = json.loads(args.custom_headers)
        except json.JSONDecodeError as exc:
            logger.error("--customHeaders is not valid JSON: %s", exc)
            raise SystemExit(1) from exc
        if not isinstance(custom_headers, dict):
            logger.error("--customHeaders must be a JSON object, e.g. '{\"key\":\"value\"}'.")
            raise SystemExit(1)

    alert_ids = read_alert_ids(args.input)
    if not alert_ids:
        logger.warning("No alert IDs to process.")
        return 0

    # A client is needed even in dry-run mode when an assignee must be resolved,
    # since that lookup is a real (read-only) API call, not part of the dry run.
    needs_client = args.assignee_email is not None or not args.dry_run
    client: httpx.AsyncClient | None = None
    if needs_client:
        config = load_config()
        headers = {"Authorization": config.api_key, **custom_headers}
        client = httpx.AsyncClient(base_url=config.base_url, headers=headers, timeout=30.0)

    try:
        assignee_user_id = None
        if args.assignee_email:
            assignee_user_id = await resolve_assignee_id(client, args.assignee_email)

        body = build_shared_body(args, classification_slug, assignee_user_id)
        logger.info(
            "Triaging %d alert(s) with %s%s",
            len(alert_ids),
            body,
            " (dry run)" if args.dry_run else "",
        )

        if args.dry_run:
            results = await run_triage(
                client=None, semaphore=None, alert_ids=alert_ids, body=body, dry_run=True
            )
        else:
            semaphore = asyncio.Semaphore(args.batch_size)
            results = await run_triage(client, semaphore, alert_ids, body, dry_run=False)
    finally:
        if client is not None:
            await client.aclose()

    print_summary(results)
    return 1 if any(r.error for r in results) else 0


def main() -> None:
    """Entry point: parse args, configure logging, run the async pipeline."""
    args = parse_args()
    setup_logging(args.verbose)
    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
