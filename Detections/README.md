# Zero Networks - SIEM Detection Library

Detection rules for Microsoft Sentinel (KQL), Splunk (SPL), Elastic (EQL), and Chronicle (YARA-L) built on Zero Networks connection event telemetry.

---

## Repository Structure

```
Detections/
│
├── sentinel/
│   ├── lateral_movement/
│   │   ├── new_internal_asset_pair.kql
│   │   ├── internal_port_fanout.kql
│   │   ├── first_smb_rdp_winrm.kql
│   │   ├── ot_it_boundary_crossing.kql
│   │   └── rpc_new_pair.kql
│   ├── ransomware_precursor/
│   │   ├── smb_share_fanout.kql
│   │   ├── mass_write_to_shares.kql
│   │   ├── dormant_host_activity.kql
│   │   └── rapid_sequential_ports.kql
│   ├── c2_exfil/
│   │   ├── first_external_destination.kql
│   │   ├── beaconing_pattern.kql
│   │   ├── high_outbound_volume.kql
│   │   └── cloud_storage_connection.kql
│   ├── privilege_abuse/
│   │   ├── service_account_to_workstation.kql
│   │   ├── multi_machine_auth.kql
│   │   ├── off_hours_dc_access.kql
│   │   └── dcsync_samr_rpc.kql
│   └── shared/
│       ├── zn_baseline_asset_pairs.kql       ← run to populate ZN_KnownAssetPairs watchlist
│       ├── zn_baseline_workstation_ports.kql ← run to populate ZN_KnownWorkstationPorts watchlist
│       ├── zn_baseline_rpc_pairs.kql         ← run to populate ZN_KnownRPCPairs watchlist
│       └── watchlists/
│           └── zn_known_pairs_schema.json
│
├── splunk/
│   ├── lateral_movement/
│   │   ├── new_internal_asset_pair.spl
│   │   ├── internal_port_fanout.spl
│   │   ├── first_smb_rdp_winrm.spl
│   │   ├── ot_it_boundary_crossing.spl
│   │   └── rpc_new_pair.spl
│   ├── ransomware_precursor/
│   │   ├── smb_share_fanout.spl
│   │   ├── mass_write_to_shares.spl
│   │   ├── dormant_host_activity.spl
│   │   └── rapid_sequential_ports.spl
│   ├── c2_exfil/
│   │   ├── first_external_destination.spl
│   │   ├── beaconing_pattern.spl
│   │   ├── high_outbound_volume.spl
│   │   └── cloud_storage_connection.spl
│   ├── privilege_abuse/
│   │   ├── service_account_to_workstation.spl
│   │   ├── multi_machine_auth.spl
│   │   ├── off_hours_dc_access.spl
│   │   └── dcsync_samr_rpc.spl
│   └── savedsearches.conf
│
├── elastic/
│   ├── lateral_movement/
│   │   ├── new_internal_asset_pair.eql
│   │   ├── internal_port_fanout.eql
│   │   ├── first_smb_rdp_winrm.eql
│   │   ├── ot_it_boundary_crossing.eql
│   │   └── rpc_new_pair.eql
│   ├── ransomware_precursor/
│   │   ├── smb_share_fanout.eql
│   │   ├── mass_write_to_shares.eql
│   │   ├── dormant_host_activity.eql
│   │   └── rapid_sequential_ports.eql
│   ├── c2_exfil/
│   │   ├── first_external_destination.eql
│   │   ├── beaconing_pattern.eql
│   │   ├── high_outbound_volume.eql
│   │   └── cloud_storage_connection.eql
│   ├── privilege_abuse/
│   │   ├── service_account_to_workstation.eql
│   │   ├── multi_machine_auth.eql
│   │   ├── off_hours_dc_access.eql
│   │   └── dcsync_samr_rpc.eql
│   └── rules/
│       └── lateral_movement_bundle.ndjson  ← importable rule package
│
├── chronicle/
│   ├── lateral_movement/
│   │   ├── new_internal_asset_pair.yaral
│   │   ├── internal_port_fanout.yaral
│   │   ├── first_smb_rdp_winrm.yaral
│   │   ├── ot_it_boundary_crossing.yaral
│   │   └── rpc_new_pair.yaral
│   ├── ransomware_precursor/
│   │   ├── smb_share_fanout.yaral
│   │   ├── mass_write_to_shares.yaral
│   │   ├── dormant_host_activity.yaral
│   │   └── rapid_sequential_ports.yaral
│   ├── c2_exfil/
│   │   ├── first_external_destination.yaral
│   │   ├── beaconing_pattern.yaral
│   │   ├── high_outbound_volume.yaral
│   │   └── cloud_storage_connection.yaral
│   ├── privilege_abuse/
│   │   ├── service_account_to_workstation.yaral
│   │   ├── multi_machine_auth.yaral
│   │   ├── off_hours_dc_access.yaral
│   │   └── dcsync_samr_rpc.yaral
│   └── reference_lists/
│       ├── zn_lateral_movement_ports.txt
│       └── zn_cloud_storage_domains.txt
│
├── tests/
│   ├── sample_events/
│   │   ├── networkactivity.json
│   │   ├── identityactivity.json
│   │   └── rpcactivity.json
│   └── expected_alerts/
│       └── lateral_movement_test_cases.json
│
├── README.md               ← this file
└── FIELD_REFERENCE.md      ← schema, enums, MITRE mapping
```

---

## Event Sources

This library is built on three Zero Networks event types:

| Type | Primary use in detections |
|---|---|
| `networkactivity` | Connection-level lateral movement, C2, exfil, OT/IT boundary |
| `identityactivity` | Authentication abuse, off-hours DC access, multi-machine auth |
| `rpcactivity` | RPC-based lateral movement, DCSync, WMI, remote task creation |

Full field reference: [`FIELD_REFERENCE.md`](./FIELD_REFERENCE.md)

---

## Detection Coverage

### Lateral Movement

| Detection | Event Source | Technique |
|---|---|---|
| New internal asset pair (established or blocked) | networkactivity | T1021.* |
| Internal port fanout - single source to many destinations | networkactivity | T1046 |
| First-ever SMB / RDP / WinRM from a workstation | networkactivity | T1021.001/002/006 |
| OT asset connecting to IT network (boundary crossing) | networkactivity | T1599 |
| New RPC pair - any dangerous interface | rpcactivity | T1047, T1053.005, T1003.006 |

### Ransomware Precursors

| Detection | Event Source | Technique |
|---|---|---|
| SMB share fanout - source to 5+ distinct file shares in 5m | networkactivity | T1021.002 |
| New SMB source - first-ever SMB from any asset type | networkactivity | T1021.002, T1486 |
| Dormant host reactivation - silent 30d+ now active | networkactivity | T1078 |
| Rapid sequential port scan - 15+ ports on same target in 5m | networkactivity | T1046 |

### C2 / Exfiltration

| Detection | Event Source | Technique |
|---|---|---|
| First-ever external destination (new src+dst_ip pair) | networkactivity | T1071, T1041 |
| Beaconing pattern - 6+ hourly connection buckets to same external IP | networkactivity | T1071.001 |
| High outbound connection volume - 50+ connections to same external IP in 1h | networkactivity | T1041, T1048 |
| Cloud storage connection - first-ever connection to Dropbox, MEGA, Drive, etc. | networkactivity | T1567.002 |

### Privilege & Credential Abuse

| Detection | Event Source | Technique |
|---|---|---|
| Service account initiating connection to workstation | networkactivity | T1078.002 |
| Multi-machine authentication - 1 account to 10+ machines in 1h | identityactivity | T1550.002, T1550.003 |
| Off-hours DC access - Kerberos/LDAP to DC outside business hours | identityactivity | T1558, T1087.002 |
| DCSync / samr RPC from non-DC source (any occurrence) | rpcactivity | T1003.006, T1087.002 |

---

## Prerequisites

### Before deploying any rule

1. **Build baselines** - each anomaly detection needs a populated baseline. Run baseline queries for at least 7 days (14 recommended) before enabling alerting. See platform-specific baseline instructions below.
2. **Tune thresholds** - fanout thresholds (e.g. "more than 20 distinct destinations") are set conservatively. Adjust to your environment's normal behavior.
3. **Validate table names** - default table/index names in all rules follow the conventions in `FIELD_REFERENCE.md`. Update to match your ingestion pipeline before deploying.

---

## Platform Setup

### Microsoft Sentinel

**Recommended table names** (Custom Log via DCR or Legacy MMA):
- `ZNNetworkActivity_CL`
- `ZNIdentityActivity_CL`
- `ZNRPCActivity_CL`

**Baseline approach**: Each anomaly rule includes a commented-out baseline materialization block using `materialize()` over a configurable lookback window (`_lookbackDays`). On first deploy, run the baseline query standalone and save output as a Watchlist.

**Deployment**: Rules are provided as raw KQL. Import into Sentinel Analytics via the portal, ARM templates, or Sentinel-as-Code pipelines (Bicep/Terraform).

**Severity mapping**:
- `established` connection, anomalous → High
- `blocked` attempt, anomalous → Medium
- `blocked_at_source`, anomalous → Low

### Splunk

**Recommended index**: `zeronetworks`

**Recommended sourcetypes**:
- `zn:network` (networkactivity)
- `zn:identity` (identityactivity)
- `zn:rpc` (rpcactivity)

**Baseline approach**: Each detection ships with a companion `| outputlookup` search to populate a KV Store baseline. Schedule it to run every 24 hours. The detection search uses `| inputlookup` to compare against baseline.

**Deployment**: Two options:
- **Via Splunk UI**: Copy each `.spl` file's query into a new Saved Search. Set scheduling and alerting in the UI.
- **Via `savedsearches.conf`**: The conf file uses named macros (e.g. `` `zn_new_internal_asset_pair` ``). Before importing, create a `macros.conf` defining each macro from the corresponding `.spl` file body. See the `savedsearches.conf` header for the exact format. Adjust `cron_schedule` and `alert.suppress` settings to match your SOC's runbook.

### Elastic

**Recommended index pattern**: `logs-zn.*`

**Baseline approach**: Use a scheduled transform to build a `zn-baseline-asset-pairs` index. Detection rules use `enrich` or `terms` aggregations against this index.

**Deployment**: Rules are provided as EQL with metadata headers. Import via Kibana Detection Engine API or the NDJSON bundle in `elastic/rules/`.

### Chronicle

**Recommended log type**: `ZN_NETWORK`, `ZN_IDENTITY`, `ZN_RPC`

**Baseline approach**: Use Chronicle reference lists (`zn_lateral_movement_ports.txt`) for static lists. For dynamic baselines (new asset pairs), use YARA-L `FIRST_SEEN` aggregation or a scheduled rule to populate a reference list.

**Deployment**: Copy `.yaral` files into Chronicle SOAR detection rules. Reference lists in `chronicle/reference_lists/` are imported separately via the Chronicle UI or API.

---

## Tuning Guide

### Reducing false positives

| Scenario | Recommendation |
|---|---|
| IT admin tools (PSExec, SCCM) flagging as lateral movement | Add `Src.AssetID` or `Src.UserName` to an exclusion watchlist/lookup |
| Backup agents hitting many hosts | Exclude `Src.ProcessPath` matching known backup agent paths |
| Vulnerability scanners | Exclude by `Src.AssetID` of known scanner assets |
| New asset onboarding | Suppress alerts for assets where `AssetNetworkSegmentationState == "In learning"` |
| Domain controllers generating fanout alerts (network rules) | Exclude `Src.AssetType == "Domain Controller"` from network fanout rules |
| Domain controllers generating auth alerts (identity rules) | Exclude DC asset IDs via the same watchlist/lookup used in the DC access rules |

### Increasing sensitivity

- Reduce fanout threshold from 20 to 10 destinations for high-value network segments
- Add `Src.AssetType == "Server"` filter to flag any server-to-server new pair (not just workstation)
- Lower the baseline lookback window from 14 to 7 days in high-churn environments

---

## Versioning & Contributing

- Rule files are versioned with a `-- Version:` comment header
- Each rule includes `-- Last modified:`, `-- MITRE:`, and `-- Severity:` headers
- When updating thresholds, update the header and add a comment explaining the change
- Test against `tests/sample_events/` before committing

---

## TODO (confirm before production)

- [ ] Validate table/index names match your ingestion pipeline
- [ ] Build and validate baselines for 14 days before enabling anomaly rules
- [ ] Populate dormant host reference list (`zn_dormant_candidates`) via scheduled export before enabling dormant_host_activity rules
- [ ] Confirm service account regex pattern matches your organisation's naming convention (service_account_to_workstation)
- [ ] Adjust off-hours thresholds in off_hours_dc_access rules to match local business hours / timezone
- [ ] Review cloud storage domain list in cloud_storage_connection rules and add any approved services to exclusion watchlist
