"""Bulk-validate and apply Zero Networks asset mirroring relationships.

Reads a CSV of srcAssetId/dstAssetId pairs, confirms via the Zero Networks API
that each dstAssetId is a valid mirror candidate for its srcAssetId, mirrors
the pairs that validate, and writes success/failure CSV reports to ./outputs.

Usage:
    uv run mirror_assets.py --input assets.csv [--batch-size 25] [-v]
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import httpx
from dotenv import load_dotenv
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

REQUIRED_CSV_COLUMNS = ("srcAssetId", "srcAssetName", "dstAssetId", "dstAssetName")
MIRROR_CANDIDATES_PAGE_SIZE = 400
RETRY_ATTEMPTS = 3
RETRY_STATUS_CODES = {429, 500, 502, 503, 504}

logger = logging.getLogger("mirror_assets")


@dataclass
class Config:
    """Runtime configuration loaded from the environment (.env)."""

    base_url: str
    api_key: str


@dataclass
class AssetRecord:
    """One src/dst asset pair being validated and mirrored."""

    src_asset_id: str
    src_asset_name: str
    dst_asset_id: str
    dst_asset_name: str
    mirror_relationship_valid: bool = False


@dataclass
class MirrorFailure:
    """A record that could not be mirrored, with the reason why."""

    record: AssetRecord
    reason: str


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
        Parsed argparse.Namespace with input, batch_size, output_dir, verbose.
    """
    parser = argparse.ArgumentParser(
        description="Bulk-validate and mirror Zero Networks assets from a CSV."
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to the input CSV (columns: srcAssetId,srcAssetName,dstAssetId,dstAssetName).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=25,
        help="Maximum number of concurrent in-flight API calls (default: 25).",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs",
        help="Directory to write result CSVs into (default: ./outputs).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args(argv)


def read_input_csv(path: str) -> dict[str, AssetRecord]:
    """Read the input CSV into a dict of AssetRecord keyed by srcAssetId.

    Args:
        path: path to the input CSV file.

    Returns:
        Dict mapping srcAssetId -> AssetRecord (mirrorRelationshipValid=False).

    Raises:
        SystemExit: if the file is missing or required columns are absent.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        logger.error("Input CSV not found: %s", csv_path)
        raise SystemExit(1)

    records: dict[str, AssetRecord] = {}
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing_columns = [c for c in REQUIRED_CSV_COLUMNS if c not in (reader.fieldnames or [])]
        if missing_columns:
            logger.error(
                "Input CSV is missing required column(s): %s", ", ".join(missing_columns)
            )
            raise SystemExit(1)

        for row_num, row in enumerate(reader, start=2):
            src_id = row["srcAssetId"].strip()
            if not src_id:
                logger.warning("Skipping row %d: empty srcAssetId", row_num)
                continue
            records[src_id] = AssetRecord(
                src_asset_id=src_id,
                src_asset_name=row["srcAssetName"].strip(),
                dst_asset_id=row["dstAssetId"].strip(),
                dst_asset_name=row["dstAssetName"].strip(),
            )

    logger.info("Loaded %d asset pair(s) from %s", len(records), csv_path)
    return records


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
async def _get_mirror_candidates_page(
    client: httpx.AsyncClient, asset_id: str, offset: int
) -> list[dict]:
    """Fetch one page of mirror candidates for an asset.

    Args:
        client: shared httpx AsyncClient.
        asset_id: the source asset id to look up candidates for.
        offset: pagination offset.

    Returns:
        The "items" list from the API response for this page.

    Raises:
        httpx.HTTPStatusError: on a non-2xx response (retried if transient).
    """
    response = await client.get(
        f"/assets/{asset_id}/mirror-candidates",
        params={"_limit": MIRROR_CANDIDATES_PAGE_SIZE, "_offset": offset},
    )
    response.raise_for_status()
    return response.json().get("items", [])


async def fetch_mirror_candidates(client: httpx.AsyncClient, asset_id: str) -> set[str]:
    """Fetch the full (paginated) set of mirror candidate asset ids.

    Args:
        client: shared httpx AsyncClient.
        asset_id: the source asset id to look up candidates for.

    Returns:
        Set of candidate asset ids.

    Raises:
        httpx.HTTPStatusError, httpx.TransportError: if retries are exhausted.
    """
    candidate_ids: set[str] = set()
    offset = 0
    while True:
        items = await _get_mirror_candidates_page(client, asset_id, offset)
        candidate_ids.update(item["id"] for item in items if "id" in item)
        if len(items) < MIRROR_CANDIDATES_PAGE_SIZE:
            break
        offset += MIRROR_CANDIDATES_PAGE_SIZE
    return candidate_ids


async def _validate_one(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, record: AssetRecord
) -> None:
    """Validate a single record's mirror relationship, mutating it in place."""
    async with semaphore:
        try:
            candidate_ids = await fetch_mirror_candidates(client, record.src_asset_id)
        except Exception:
            logger.exception(
                "Failed to fetch mirror candidates for srcAssetId=%s", record.src_asset_id
            )
            record.mirror_relationship_valid = False
            return

        record.mirror_relationship_valid = record.dst_asset_id in candidate_ids
        if record.mirror_relationship_valid:
            logger.info(
                "Validated %s / %s can be mirrored to %s / %s",
                record.src_asset_name,
                record.src_asset_id,
                record.dst_asset_name,
                record.dst_asset_id,
            )
        logger.debug(
            "src=%s dst=%s valid=%s",
            record.src_asset_id,
            record.dst_asset_id,
            record.mirror_relationship_valid,
        )


async def validate_relationships(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, assets: dict[str, AssetRecord]
) -> None:
    """Concurrently validate mirrorRelationshipValid for every asset record.

    Args:
        client: shared httpx AsyncClient.
        semaphore: bounds concurrent in-flight mirror-candidates lookups.
        assets: dict of srcAssetId -> AssetRecord, mutated in place.
    """
    await asyncio.gather(*(_validate_one(client, semaphore, r) for r in assets.values()))


def split_invalid_relationships(
    assets: dict[str, AssetRecord]
) -> tuple[dict[str, AssetRecord], dict[str, AssetRecord]]:
    """Split assets into (valid, invalid) dicts based on mirrorRelationshipValid.

    Args:
        assets: dict of srcAssetId -> AssetRecord.

    Returns:
        Tuple of (valid_assets, invalid_mirror_relationships) dicts. The input
        dict is left containing only the valid entries.
    """
    invalid_ids = [
        src_id for src_id, record in assets.items() if not record.mirror_relationship_valid
    ]
    invalid_mirror_relationships = {src_id: assets.pop(src_id) for src_id in invalid_ids}
    return assets, invalid_mirror_relationships


@retry(
    reraise=True,
    stop=stop_after_attempt(RETRY_ATTEMPTS),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception(_is_retryable_error),
)
async def _post_mirror(client: httpx.AsyncClient, record: AssetRecord) -> None:
    """Issue the mirror action API call for one record.

    Args:
        client: shared httpx AsyncClient.
        record: the asset pair to mirror.

    Raises:
        httpx.HTTPStatusError: on a non-2xx response (retried if transient).
    """
    response = await client.post(
        "/assets/actions/mirror",
        json={"originalAssetId": record.src_asset_id, "targetAssetId": record.dst_asset_id},
    )
    response.raise_for_status()


async def mirror_asset(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, record: AssetRecord
) -> tuple[AssetRecord, Exception | None]:
    """Mirror one asset pair, catching (not raising) any final failure.

    Args:
        client: shared httpx AsyncClient.
        semaphore: bounds concurrent in-flight mirror calls.
        record: the asset pair to mirror.

    Returns:
        Tuple of (record, error). error is None on success, otherwise the
        exception raised after retries were exhausted.
    """
    async with semaphore:
        try:
            await _post_mirror(client, record)
        except Exception as exc:  # noqa: BLE001 - intentionally broad, reported per-task
            logger.error(
                "Mirror API call failed for srcAssetId=%s dstAssetId=%s: %s",
                record.src_asset_id,
                record.dst_asset_id,
                exc,
            )
            return record, exc
        logger.info(
            "Successfully mirrored %s / %s --> %s / %s",
            record.src_asset_name,
            record.src_asset_id,
            record.dst_asset_name,
            record.dst_asset_id,
        )
        logger.debug("Mirrored src=%s onto dst=%s", record.src_asset_id, record.dst_asset_id)
        return record, None


async def run_mirroring(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, valid_assets: dict[str, AssetRecord]
) -> tuple[list[AssetRecord], list[MirrorFailure]]:
    """Concurrently mirror every valid asset pair.

    Args:
        client: shared httpx AsyncClient.
        semaphore: bounds concurrent in-flight mirror calls.
        valid_assets: dict of srcAssetId -> AssetRecord that passed validation.

    Returns:
        Tuple of (successes, failures) where failures carry a human-readable reason.
    """
    results = await asyncio.gather(
        *(mirror_asset(client, semaphore, r) for r in valid_assets.values())
    )
    successes = [record for record, error in results if error is None]
    failures = [
        MirrorFailure(record=record, reason=f"mirror API call failed: {error}")
        for record, error in results
        if error is not None
    ]
    return successes, failures


def write_output_csvs(
    successes: list[AssetRecord],
    failures: list[MirrorFailure],
    output_dir: str,
) -> tuple[Path, Path | None]:
    """Write the success and failure CSV reports.

    Args:
        successes: records mirrored successfully.
        failures: records that failed validation or the mirror call, with reasons.
        output_dir: directory to write the CSVs into (created if missing).

    Returns:
        Tuple of (success_csv_path, failure_csv_path). failure_csv_path is None
        if no assets failed validation or mirroring.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()

    success_path = out_dir / f"mirrored-success-{today}.csv"
    with success_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(REQUIRED_CSV_COLUMNS)
        for record in successes:
            writer.writerow(
                (record.src_asset_id, record.src_asset_name, record.dst_asset_id, record.dst_asset_name)
            )

    if not failures:
        return success_path, None

    failure_path = out_dir / f"mirrored-failures-{today}.csv"
    with failure_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow((*REQUIRED_CSV_COLUMNS, "reason"))
        for failure in failures:
            record = failure.record
            writer.writerow(
                (
                    record.src_asset_id,
                    record.src_asset_name,
                    record.dst_asset_id,
                    record.dst_asset_name,
                    failure.reason,
                )
            )

    return success_path, failure_path


def print_summary(
    successes: list[AssetRecord],
    invalid_relationships: dict[str, AssetRecord],
    mirror_failures: list[MirrorFailure],
    success_csv: Path,
    failure_csv: Path | None,
) -> None:
    """Log a console summary of the run's results.

    Args:
        successes: records mirrored successfully.
        invalid_relationships: records that failed validation (dst not a mirror candidate).
        mirror_failures: records that failed the mirror API call.
        success_csv: path to the written success CSV.
        failure_csv: path to the written failure CSV, or None if nothing failed.
    """
    total_failed = len(invalid_relationships) + len(mirror_failures)
    if failure_csv is not None:
        logger.info(
            "%d asset(s) successfully mirrored, %d failed "
            "(%d failed validation, %d failed the mirror call) - see %s for details",
            len(successes),
            total_failed,
            len(invalid_relationships),
            len(mirror_failures),
            failure_csv,
        )
    else:
        logger.info("%d asset(s) successfully mirrored, none failed.", len(successes))
    logger.info("Success report: %s", success_csv)


async def main_async(args: argparse.Namespace) -> int:
    """Orchestrate the full validate -> split -> mirror -> report pipeline.

    Args:
        args: parsed CLI arguments.

    Returns:
        Process exit code (0 if no mirror-call failures occurred, else 1).
    """
    config = load_config()
    assets = read_input_csv(args.input)
    if not assets:
        logger.warning("No asset pairs to process.")
        return 0

    semaphore = asyncio.Semaphore(args.batch_size)
    headers = {"Authorization": config.api_key}

    async with httpx.AsyncClient(base_url=config.base_url, headers=headers, timeout=30.0) as client:
        await validate_relationships(client, semaphore, assets)
        valid_assets, invalid_relationships = split_invalid_relationships(assets)
        successes, mirror_failures = await run_mirroring(client, semaphore, valid_assets)

    invalid_failures = [
        MirrorFailure(record=record, reason="invalid mirror relationship")
        for record in invalid_relationships.values()
    ]
    success_csv, failure_csv = write_output_csvs(
        successes, invalid_failures + mirror_failures, args.output_dir
    )
    print_summary(successes, invalid_relationships, mirror_failures, success_csv, failure_csv)

    return 1 if mirror_failures else 0


def main() -> None:
    """Entry point: parse args, configure logging, run the async pipeline."""
    args = parse_args()
    setup_logging(args.verbose)
    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
