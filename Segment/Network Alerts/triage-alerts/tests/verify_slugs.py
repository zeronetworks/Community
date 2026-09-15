# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "httpx",
#     "python-dotenv",
# ]
# ///
"""Verify the guessed --state / --classification slugs in ../triage_alerts.py.

For each STATE_SLUGS / CLASSIFICATION_SLUGS entry, PATCHes a single field on
one of two dev alerts, then GETs the alert back and checks the returned
`state` / `userAlertClassification` integer matches the expected position in
the live `GET /network/alerts/filters` response (the API's own ground truth
for what each integer means). Safe to re-run: it only mutates the two
hardcoded dev alert IDs below, and every value tested is a real, settable
state/classification.

Usage (from the repo root):
    uv run tests/verify_slugs.py --assigneeEmail you@example.com \
        [--customHeaders '{"zn-env-id":"..."}']

`--assigneeEmail` is required: setting `state` to anything but `new` fails
API-side validation ("missing assignee") unless the alert already has one, so
this script assigns both dev alerts up front. Requires the same .env as
../triage_alerts.py (ZN_API_BASE_URL, ZN_API_KEY) - looked up automatically
from the repo root regardless of the current working directory.
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import os
import sys

import httpx
from dotenv import load_dotenv

# Same dev alerts used throughout this repo's manual testing.
DEV_ALERT_IDS = ["n:d:C7ZCfAa1", "n:d:PeFaX0vK"]

# CLI value -> (API slug, expected `state` int from /network/alerts/filters).
STATE_SLUGS: dict[str, tuple[str, int]] = {
    "in-progress": ("in_progress", 2),
    "closed": ("closed", 3),
    "reopened": ("reopened", 4),
}

# (CLI classification, CLI category) -> (API slug, expected
# `userAlertClassification` int - its 1-indexed position in the filters
# "classification" selections list).
CLASSIFICATION_SLUGS: dict[tuple[str, str], tuple[str, int]] = {
    ("true-positive", "multi-staged-attack"): ("multi_staged_attack", 1),
    ("true-positive", "malware"): ("malware", 2),
    ("true-positive", "malicious-user-activity"): ("malicious_user_activity", 3),
    ("true-positive", "unwanted-software"): ("unwanted_software", 4),
    ("true-positive", "phishing"): ("phishing", 5),
    ("true-positive", "compromised-account"): ("compromised_account", 6),
    ("true-positive", "other"): ("true_positive_other", 7),
    ("informational", "security-testing"): ("security_testing", 8),
    ("informational", "confirmed-activity"): ("confirmed_activity", 9),
    ("informational", "line-of-business-application"): ("line_of_business_application", 10),
    ("informational", "other"): ("informational_other", 11),
    ("false-positive", "not-malicious"): ("not_malicious", 12),
    ("false-positive", "not-enough-data"): ("not_enough_data", 13),
    ("false-positive", "other"): ("false_positive_other", 14),
}


def load_config() -> tuple[str, str]:
    load_dotenv()
    base_url = os.environ.get("ZN_API_BASE_URL", "").rstrip("/")
    api_key = os.environ.get("ZN_API_KEY", "")
    if not base_url or not api_key:
        print(
            "Missing ZN_API_BASE_URL / ZN_API_KEY - copy .env.example to .env and fill in.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return base_url + "/api/v1", api_key


async def resolve_assignee_id(client: httpx.AsyncClient, email: str) -> str:
    """Same lookup as triage_alerts.py's resolve_assignee_id: GET /users filtered by email."""
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
        print(f"No account found with email: {email}", file=sys.stderr)
        raise SystemExit(1)
    return matches[0]["id"]


async def ensure_assigned(client: httpx.AsyncClient, alert_id: str, assignee_user_id: str) -> None:
    resp = await client.patch(
        f"/network/alerts/{alert_id}",
        json={"alertId": alert_id, "assigneeUserId": assignee_user_id},
    )
    resp.raise_for_status()


async def fetch_filters_ground_truth(client: httpx.AsyncClient) -> dict[str, dict[int, str]]:
    """Return {"state": {1: "New", ...}, "classification": {1: "...", ...}}."""
    response = await client.get("/network/alerts/filters")
    response.raise_for_status()
    filters = response.json()["filters"]
    return {
        f["id"]: {int(s["id"]): s["name"] for s in f["selections"]}
        for f in filters
        if f["id"] in ("state", "classification")
    }


def _raise_with_body(resp: httpx.Response) -> None:
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise httpx.HTTPStatusError(
            f"{exc}. Response body: {resp.text}", request=exc.request, response=exc.response
        ) from exc


async def _patch_field(client: httpx.AsyncClient, alert_id: str, field: str, value: str) -> None:
    """PATCH a single field, treating a no-op ("no fields to update", i.e. the
    alert was already at that value) as success rather than an error."""
    resp = await client.patch(f"/network/alerts/{alert_id}", json={"alertId": alert_id, field: value})
    if resp.status_code == 400 and "no fields to update" in resp.text:
        return
    _raise_with_body(resp)


async def check_state(client: httpx.AsyncClient, alert_id: str, cli_value: str, slug: str) -> dict:
    # `state` is a workflow, not a free-form field - e.g. an alert can only be
    # "reopened" after it's been "closed". Callers must run these in the
    # natural pipeline order (in-progress -> closed -> reopened) on the same
    # alert rather than jumping to an arbitrary state.
    await _patch_field(client, alert_id, "state", slug)
    get_resp = await client.get(f"/network/alerts/{alert_id}")
    _raise_with_body(get_resp)
    returned_id = get_resp.json()["alert"]["state"]
    return {"kind": "state", "cli": cli_value, "slug": slug, "returned_id": returned_id}


async def check_classification(
    client: httpx.AsyncClient, alert_id: str, cli_classification: str, cli_category: str, slug: str
) -> dict:
    # A classification change apparently requires a non-empty comment.
    resp = await client.patch(
        f"/network/alerts/{alert_id}",
        json={
            "alertId": alert_id,
            "userAlertClassification": slug,
            "comment": f"verify_slugs.py: {slug}",
        },
    )
    if not (resp.status_code == 400 and "no fields to update" in resp.text):
        _raise_with_body(resp)
    get_resp = await client.get(f"/network/alerts/{alert_id}")
    _raise_with_body(get_resp)
    returned_id = get_resp.json()["alert"]["userAlertClassification"]
    return {
        "kind": "classification",
        "cli": f"{cli_classification}/{cli_category}",
        "slug": slug,
        "returned_id": returned_id,
    }


async def main_async(assignee_email: str, custom_headers: dict) -> int:
    base_url, api_key = load_config()
    headers = {"Authorization": api_key, **custom_headers}

    async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=30.0) as client:
        assignee_user_id = await resolve_assignee_id(client, assignee_email)
        for alert_id in DEV_ALERT_IDS:
            await ensure_assigned(client, alert_id, assignee_user_id)

        ground_truth = await fetch_filters_ground_truth(client)
        alert_cycle = itertools.cycle(DEV_ALERT_IDS)
        results = []

        # State is a workflow (in-progress -> closed -> reopened), so all
        # three must be walked in order on a single alert rather than jumping
        # to an arbitrary target state on a fresh alert each time.
        state_alert_id = DEV_ALERT_IDS[0]
        for cli_value, (slug, expected_id) in STATE_SLUGS.items():
            result = await check_state(client, state_alert_id, cli_value, slug)
            result["expected_id"] = expected_id
            results.append(result)

        for (cli_classification, cli_category), (slug, expected_id) in CLASSIFICATION_SLUGS.items():
            alert_id = next(alert_cycle)
            result = await check_classification(client, alert_id, cli_classification, cli_category, slug)
            result["expected_id"] = expected_id
            results.append(result)

    ok_count = 0
    print(f"{'kind':14} {'cli':45} {'slug':30} {'returned':>8} {'expected':>8} {'label':45} status")
    for r in results:
        label_map = ground_truth.get(r["kind"], {})
        label = label_map.get(r["returned_id"], f"<unknown id {r['returned_id']}>")
        status = "OK" if r["returned_id"] == r["expected_id"] else "MISMATCH"
        ok_count += status == "OK"
        print(
            f"{r['kind']:14} {r['cli']:45} {r['slug']:30} "
            f"{r['returned_id']:>8} {r['expected_id']:>8} {label:45} {status}"
        )

    print(f"\n{ok_count}/{len(results)} confirmed.")
    return 0 if ok_count == len(results) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--assigneeEmail",
        dest="assignee_email",
        required=True,
        help="Email of the account to assign the dev alerts to before testing state transitions.",
    )
    parser.add_argument(
        "--customHeaders",
        dest="custom_headers",
        default=None,
        help='JSON-encoded object of extra headers, e.g. \'{"zn-env-id":"..."}\'.',
    )
    args = parser.parse_args()

    custom_headers = {}
    if args.custom_headers:
        custom_headers = json.loads(args.custom_headers)

    sys.exit(asyncio.run(main_async(args.assignee_email, custom_headers)))


if __name__ == "__main__":
    main()
