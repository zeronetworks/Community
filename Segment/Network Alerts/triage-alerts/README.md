# Triage Alerts as False Positives

Bulk-apply a state change and/or classification change to every alert in a Network Alerts CSV export, via the Zero Networks API.

## Requirements
Running the script has the following requirements:
- **Zero Networks Full Access API Token**: Generate token within portal at Settings > Integrations > API > Generate token 

## Usage

The script is a self-contained `uv` script (dependencies declared inline) — no separate install step is needed beyond having `uv` available.

### 1. Export a CSV of the alerts to triage

In the portal, navigate to **Network > Alerts**, filter the list down to the alerts you want to triage, then click the **Export to CSV** in the top right of the alerts table.

### 2. Set up your `.env` file

```bash
cp .env.example .env  # then fill in ZN_API_BASE_URL and ZN_API_KEY
# ZN_API_BASE_URL is your portal base URL, e.g. https://<your-org>-admin.zeronetworks.com
# (no /api/v1 suffix - the script appends it automatically)
```

To generate an API key, navigate to **Settings > Integrations > API** and generate a **Full Access** API token (super admin).

### 3. Run the script

Provide the CSV you exported in step 1 via `--input`, along with the `--classification`/`--classification-category` (and/or `--state`) you want to apply:

```bash
uv run triage_alerts.py --input "alerts.csv" \
    --state closed \
    --classification false-positive --classification-category not-malicious \
    [--comment "..."] [--assigneeEmail "you@example.com"] [--change-ticket "..."] \
    [--batch-size 10] [--dry-run] [-v]
```

Provide at least one of `--state`, `--classification`/`--classification-category` (or `--classification-slug`), or `--assigneeEmail`; the script errors out if there's nothing to change. Run with `--dry-run` first to confirm the request bodies look correct before applying changes for real.

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
| `--customHeaders` | JSON-encoded object of extra headers appended to every request, e.g. `'{"zn-env-id":"..."}'`. **This is only required if you are an MSP managing multiple environments.** |
| `--batch-size` | Max concurrent in-flight PATCH calls (default: 10). |
| `--dry-run` | Log what would be sent for each alert without calling the API. |
| `--verbose`, `-v` | Debug logging, including per-HTTP-request detail. Standard logging only shows per-alert progress and the final summary. |

### `--state` values

***A network alert starts in a `new` state by default - once you move an alert to a different state (e.g., in-progress, closed) you CANNOT move a network alert back to the `new` state. If you close an alert, you can open it again by setting it's state to either `in-progress` or `reopened`.

| `--state` |
|---|
| `in-progress` |
| `closed` |
| `reopened` |

### `--classification` / `--classification-category` values

| `--classification` | `--classification-category` |
|---|---|
| `true-positive` | `multi-staged-attack` |
| `true-positive` | `malware` |
| `true-positive` | `malicious-user-activity` |
| `true-positive` | `unwanted-software` |
| `true-positive` | `phishing` |
| `true-positive` | `compromised-account` |
| `true-positive` | `other` |
| `informational` | `security-testing` |
| `informational` | `confirmed-activity` |
| `informational` | `line-of-business-application` |
| `informational` | `other` |
| `false-positive` | `not-malicious` |
| `false-positive` | `not-enough-data` |
| `false-positive` | `other` |

## Output

A summary is logged to the console at the end of the run: how many alerts were triaged successfully, how many failed, and the failure reason for each. The process exits non-zero if any alert failed.

## Example

### Perform dry run against alerts
First, run a dry run against every alert in the export.

```bash
uv run triage_alerts.py \
    --input "alerts.csv" \
    --state closed \
    --classification false-positive --classification-category not-malicious \
    --dry-run
```

Then, drop the --dry-run parameter to classify the alerts as `false-positive` and categorize them as `not-malicious`. 

```bash
uv run triage_alerts.py \
    --input "alerts.csv" \
    --state closed \
    --classification false-positive --classification-category not-malicious \
```

### Assign alerts to user

Use the --assigneeEmail parameter to assign alerts to particular user. The script will search your Zero Networks environment for a user account matching this email, and assign it as the `assigned-user` of the alert. 

 ```bash
uv run triage_alerts.py \
    --input "alerts.csv" \
    --assigneeEmail "user.email@mycompany.com"
```
