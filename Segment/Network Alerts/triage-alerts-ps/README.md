# Triage Alerts as False Positives (PowerShell)

Bulk-apply a state change and/or classification change to every alert in a Network Alerts CSV export, via the Zero Networks API.

This is the PowerShell 7 version of [`triage-alerts-py`](../triage-alerts-py) - same features and behaviour, no Python required.

## Requirements
Running the script has the following requirements:
- **Zero Networks Full Access API Token**: Generate token within portal at Settings > Integrations > API > Generate token
- **[PowerShell 7+](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)** (`pwsh`). Windows PowerShell 5.1 is not supported.
- No additional modules - the script only uses built-in cmdlets.

## Usage

### 1. Export a CSV of the alerts to triage

In the portal, navigate to **Network > Alerts**, filter the list down to the alerts you want to triage, then click the **Export to CSV** in the top right of the alerts table.

### 2. Set up your `.env` file

```powershell
Copy-Item .env.example .env  # then fill in ZN_API_BASE_URL and ZN_API_KEY
# ZN_API_BASE_URL is your portal base URL, e.g. https://<your-org>-admin.zeronetworks.com
# (no /api/v1 suffix - the script appends it automatically)
```

To generate an API key, navigate to **Settings > Integrations > API** and generate a **Full Access** API token (super admin).

Alternatively, set `ZN_API_BASE_URL` and `ZN_API_KEY` as environment variables - they take precedence over the `.env` file.

### 3. Run the script

Provide the CSV you exported in step 1 via `-InputFile`, along with the `-Classification`/`-ClassificationCategory` (and/or `-State`) you want to apply:

```powershell
./Triage-Alerts.ps1 -InputFile "alerts.csv" `
    -State closed `
    -Classification false-positive -ClassificationCategory not-malicious `
    [-Comment "..."] [-AssigneeEmail "you@example.com"] [-ChangeTicket "..."] `
    [-BatchSize 10] [-DryRun] [-Verbose]
```

Provide at least one of `-State`, `-Classification`/`-ClassificationCategory` (or `-ClassificationSlug`), or `-AssigneeEmail`; the script errors out if there's nothing to change. Run with `-DryRun` first to confirm the request bodies look correct before applying changes for real.

Parameter values tab-complete in PowerShell, and `Get-Help ./Triage-Alerts.ps1 -Full` shows the full parameter reference.

> **Windows tip:** if PowerShell refuses to run the script because it was downloaded from the internet, run `Unblock-File ./Triage-Alerts.ps1` once, or launch it with `pwsh -ExecutionPolicy Bypass -File ./Triage-Alerts.ps1 ...`.

### Parameters

| Parameter | Description |
|---|---|
| `-InputFile`, `-i` | Path to the alert CSV export (required). |
| `-State` | New state to set on every alert. One of: `in-progress`, `closed`, `reopened`. (`new` is not a settable target state - the API rejects it; see below.) |
| `-Classification` | Top-level classification bucket. One of: `true-positive`, `informational`, `false-positive`. Requires `-ClassificationCategory`. |
| `-ClassificationCategory` | Specific reason within `-Classification`. See table below for valid combinations. |
| `-ClassificationSlug` | Raw API classification string, sent verbatim. Use instead of `-Classification`/`-ClassificationCategory` to send a value not in the lookup table. |
| `-Comment` | Optional comment set on every alert. |
| `-AssigneeEmail` | Email of the account to assign every alert to, resolved to its entity ID via `GET /users` (filtered by email). Terminates if no matching account is found. Required before setting `-State` on an alert that doesn't already have an assignee - the API rejects that with "missing assignee". |
| `-ChangeTicket` | Optional change ticket value set on every alert. |
| `-BatchSize` | Max concurrent in-flight PATCH calls (default: 10). |
| `-DryRun` | Log what would be sent for each alert without calling the API. |
| `-Verbose` | Debug logging, including per-HTTP-request detail. Standard logging only shows per-alert progress and the final summary. |

### `-State` values

***A network alert starts in a `new` state by default - once you move an alert to a different state (e.g., in-progress, closed) you CANNOT move a network alert back to the `new` state. If you close an alert, you can open it again by setting it's state to either `in-progress` or `reopened`.

| `-State` |
|---|
| `in-progress` |
| `closed` |
| `reopened` |

### `-Classification` / `-ClassificationCategory` values

| `-Classification` | `-ClassificationCategory` |
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

```powershell
./Triage-Alerts.ps1 `
    -InputFile "alerts.csv" `
    -State closed `
    -Classification false-positive -ClassificationCategory not-malicious `
    -DryRun
```

Then, drop the -DryRun parameter to classify the alerts as `false-positive` and categorize them as `not-malicious`.

```powershell
./Triage-Alerts.ps1 `
    -InputFile "alerts.csv" `
    -State closed `
    -Classification false-positive -ClassificationCategory not-malicious
```

### Assign alerts to user

Use the -AssigneeEmail parameter to assign alerts to particular user. The script will search your Zero Networks environment for a user account matching this email, and assign it as the `assigned-user` of the alert.

```powershell
./Triage-Alerts.ps1 `
    -InputFile "alerts.csv" `
    -AssigneeEmail "user.email@mycompany.com"
```
