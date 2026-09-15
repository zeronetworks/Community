# Triage Alerts as False Positives

Bulk-apply a state change and/or classification change to every alert in a Network Alerts CSV export, via the Zero Networks API.

> **Note:** The Network Alerts API used by this script (`/api/v1/network/alerts/*`) is not part of the published Zero Networks OpenAPI spec — it's the same internal endpoint the portal's Network Alerts page uses. Every `--state` and `--classification`/`--classification-category` value in the tables below has been confirmed against a real API response.

## Setup

```bash
cp .env.example .env  # then fill in ZN_API_BASE_URL and ZN_API_KEY
# ZN_API_BASE_URL is your portal base URL, e.g. https://<your-org>-admin.zeronetworks.com
# (no /api/v1 suffix - the script appends it automatically)
```

The script is a self-contained `uv` script (dependencies declared inline) — no separate install step is needed beyond having `uv` available.

## Usage

Input CSV must be a Network Alerts export with at minimum an `ID` column (as produced by the portal's "Export" button).

```bash
uv run triage_alerts.py --input "alerts.csv" \
    --state closed \
    --classification false-positive --classification-category not-malicious \
    [--comment "..."] [--assigneeEmail "you@example.com"] [--change-ticket "..."] \
    [--customHeaders '{"zn-env-id":"..."}'] \
    [--batch-size 10] [--dry-run] [-v]
```

Provide at least one of `--state`, `--classification`/`--classification-category` (or `--classification-slug`), or `--assigneeEmail`; the script errors out if there's nothing to change.

### Flags

| Flag | Description |
|---|---|
| `--input`, `-i` | Path to the alert CSV export (required). |
| `--state` | New state to set on every alert. One of: `in-progress`, `closed`, `reopened`. (`new` is not a settable target state - the API rejects it; see below.) |
| `--classification` | Top-level classification bucket. One of: `true-positive`, `informational`, `false-positive`. Requires `--classification-category`. |
| `--classification-category` | Specific reason within `--classification`. See table below for valid combinations. |
| `--classification-slug` | Raw API classification string, sent verbatim. Use instead of `--classification`/`--classification-category` to send a value not in the lookup table. |
| `--comment` | Optional comment set on every alert. |
| `--assigneeEmail` | Email of the account to assign every alert to, resolved to its entity ID via `GET /users` (filtered by email). Terminates if no matching account is found. Required before setting `--state` on an alert that doesn't already have an assignee - the API rejects that with "missing assignee". |
| `--change-ticket` | Optional change ticket value set on every alert. |
| `--customHeaders` | JSON-encoded object of extra headers appended to every request, e.g. `'{"zn-env-id":"..."}'`. |
| `--batch-size` | Max concurrent in-flight PATCH calls (default: 10). |
| `--dry-run` | Log what would be sent for each alert without calling the API. |
| `--verbose`, `-v` | Debug logging, including per-HTTP-request detail. Standard logging only shows per-alert progress and the final summary. |

### `--state` values

`new` is deliberately not a settable value: the API rejects it as a target state (`state failed custom validation because value must be one of [in_progress, closed, reopened]`) - it's the state an alert starts in, not one you can transition back to. `state` is otherwise a workflow, not a free-form field: an alert can only be `reopened` after it's been `closed`.

| `--state` | API slug sent | Confirmed? |
|---|---|---|
| `in-progress` | `in_progress` | **confirmed** |
| `closed` | `closed` | **confirmed** |
| `reopened` | `reopened` | **confirmed** |

### `--classification` / `--classification-category` values

| `--classification` | `--classification-category` | API slug sent | Confirmed? |
|---|---|---|---|
| `true-positive` | `multi-staged-attack` | `multi_staged_attack` | **confirmed** |
| `true-positive` | `malware` | `malware` | **confirmed** |
| `true-positive` | `malicious-user-activity` | `malicious_user_activity` | **confirmed** |
| `true-positive` | `unwanted-software` | `unwanted_software` | **confirmed** |
| `true-positive` | `phishing` | `phishing` | **confirmed** |
| `true-positive` | `compromised-account` | `compromised_account` | **confirmed** |
| `true-positive` | `other` | `true_positive_other` | **confirmed** |
| `informational` | `security-testing` | `security_testing` | **confirmed** |
| `informational` | `confirmed-activity` | `confirmed_activity` | **confirmed** |
| `informational` | `line-of-business-application` | `line_of_business_application` | **confirmed** |
| `informational` | `other` | `informational_other` | **confirmed** |
| `false-positive` | `not-malicious` | `not_malicious` | **confirmed** |
| `false-positive` | `not-enough-data` | `not_enough_data` | **confirmed** |
| `false-positive` | `other` | `false_positive_other` | **confirmed** |

## Output

A summary is logged to the console at the end of the run: how many alerts were triaged successfully, how many failed, and the failure reason for each. The process exits non-zero if any alert failed.

## Example

Close every alert in the export and mark it a false positive (not malicious):

```bash
uv run triage_alerts.py \
    --input "Zero Networks network alerts 9_11_2026.csv" \
    --state closed \
    --classification false-positive --classification-category not-malicious \
    --dry-run -v
```

Drop `--dry-run` once you've confirmed the logged request bodies look correct.
