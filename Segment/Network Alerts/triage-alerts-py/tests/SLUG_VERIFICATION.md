# `--state` / `--classification` slug verification

Internal reference for the API slugs `triage_alerts.py` sends for each
`--state` and `--classification`/`--classification-category` value, and
their confirmation status. Not part of the customer-facing README.

The Network Alerts API (`/api/v1/network/alerts/*`) is not part of the
published Zero Networks OpenAPI spec — it's the same internal endpoint the
portal's Network Alerts page uses. Every value below has been confirmed
against a real API response: each was PATCHed individually against a dev
alert, then read back via `GET /network/alerts/{id}` and cross-checked
against that environment's own `GET /network/alerts/filters` enum labels.
`verify_slugs.py` in this directory is the script that did this - re-run it
if the portal API ever changes.

## `--state` values

`new` is deliberately not a settable value: the API rejects it as a target
state (`state failed custom validation because value must be one of
[in_progress, closed, reopened]`) - it's the state an alert starts in, not
one you can transition back to. `state` is otherwise a workflow, not a
free-form field: an alert can only be `reopened` after it's been `closed`.

| `--state` | API slug sent | Confirmed? |
|---|---|---|
| `in-progress` | `in_progress` | **confirmed** |
| `closed` | `closed` | **confirmed** |
| `reopened` | `reopened` | **confirmed** |

## `--classification` / `--classification-category` values

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
