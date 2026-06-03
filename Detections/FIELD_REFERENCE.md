# Zero Networks - SIEM Field Reference

## Event Types & Table Names

| Event Type | Sentinel Table | Splunk Index/Sourcetype | Elastic Index | Chronicle Log Type |
|---|---|---|---|---|
| Network activity | `ZNNetworkActivity_CL` | `index=zeronetworks sourcetype=zn:network` | `logs-zn.network-*` | `ZN_NETWORK` |
| Identity activity | `ZNIdentityActivity_CL` | `index=zeronetworks sourcetype=zn:identity` | `logs-zn.identity-*` | `ZN_IDENTITY` |
| RPC activity | `ZNRPCActivity_CL` | `index=zeronetworks sourcetype=zn:rpc` | `logs-zn.rpc-*` | `ZN_RPC` |

> **Note**: Adjust table/index names to match your ingestion pipeline. These are the recommended naming conventions used throughout this library.

---

## networkactivity Fields

| Field | Type | Description | Example Values |
|---|---|---|---|
| `TimestampEpoch` | int | Unix epoch (seconds) | `1234567890` |
| `TimestampIso8601` | string | ISO 8601 UTC timestamp | `"2023-10-01T12:00:00Z"` |
| `ProtocolType` | int | IP protocol number | `6` (TCP), `17` (UDP), `1` (ICMP) |
| `ConnectionStatus` | string | Outcome of the connection | `"blocked"`, `"requested"`, `"established"`, `"blocked_at_source"` |
| `TrafficType` | string | Network traffic classification | `"Internal"`, `"External"` |
| `InboundRuleIds` | string[] | ZN rule GUIDs that matched inbound | `["guid1", "guid2"]` |
| `OutboundRuleIds` | string[] | ZN rule GUIDs that matched outbound | `["guid1"]` |
| `Src.AssetID` | string | ZN internal asset identifier (source) | `"12435"` |
| `Src.AssetSource` | string | Where asset is managed | `"Network"`, `"AD"`, `"Azure"` |
| `Src.AssetType` | string | Asset classification | `"Workstation"`, `"Server"`, `"Domain Controller"` |
| `Src.AssetNetworkSegmentationState` | string | ZN segmentation enforcement state | see Segmentation States below |
| `Src.Fqdn` | string | Fully qualified domain name | `"ws01.corp.local"` |
| `Src.IP` | string | Source IP address | `"10.0.1.50"` |
| `Src.Port` | int | Source port | `54321` |
| `Src.ProcessID` | int | PID of initiating process | `4512` |
| `Src.ProcessPath` | string | Full path of initiating process | `"C:\\Windows\\System32\\svchost.exe"` |
| `Src.UserID` | string | User SID or ID | `"S-1-5-21-..."` |
| `Src.UserName` | string | Username | `"CORP\\jsmith"` |
| `Src.IPThreatScore` | int | ZN threat intelligence score (0–100) | `0` (clean), `85` (high threat) |
| `Src.EventRecordID` | string | Windows event record ID | |
| `Src.WFPFilterName` | string | Windows Filtering Platform filter name | |
| `Src.WFPFilterSublayer` | string | WFP sublayer | |
| `Src.WFPFilterLayer` | string | WFP layer | |
| `Src.OTSwitchID` | string | OT switch identifier (populated for OT assets) | |
| `Src.OTSwitchInterfaceName` | string | OT switch interface name | |
| `Src.MAC` | string | MAC address | `"00:1A:2B:3C:4D:5E"` |
| `Src.IsoCode` | string | ISO country code (external IPs) | `"US"`, `"CN"`, `"RU"` |
| `Dst.*` | - | All Src fields mirrored on destination | - |

---

## identityactivity Fields

| Field | Type | Description | Example Values |
|---|---|---|---|
| `timestamp` | int | Unix epoch (milliseconds) | `1771178109374` |
| `recordId` | int | Event record ID | `32323232` |
| `eventType` | int | Event type code | `1` |
| `logonType` | int | Logon type code | `3` (Network) — see Logon Type Enum below |
| `failureReason` | int | 0 = success; non-zero = failure code | `0`, `6` |
| `authenticationPackageName` | string | Authentication package used | `"Kerberos"`, `"NTLM"`, `"Negotiate"` |
| `logonProvider` | string | Logon provider | `"Authz"` |
| `processName` | string | Process name initiating the auth | `"process.exe"` |
| `processId` | string | Process ID | `"1111"` |
| `ruleMatches` | array | Matched ZN rule entries | `[]` |
| `subjectUser.name` | string | Subject (acting) username | `"NT AUTHORITY\\SYSTEM"` |
| `subjectUser.sid` | string | Subject user SID | `"S-1-5-18"` |
| `targetUser.name` | string | Target username | `"-\\"` |
| `src` | object\|null | Source asset; **may be null** | `null` |
| `dst.assetId` | string | Destination asset identifier | `"yyyyy"` |
| `dst.fqdn` | string | Destination FQDN | `"a.sample.com"` |
| `dst.assetType` | int | Destination asset type enum | `1` = CLIENT, `2` = SERVER - see Asset Type Enum below |
| `dst.assetSrc` | int | Asset management source enum | `3` = Active Directory - see Asset Source Enum below |
| `dst.networkProtectionState` | int | ZN network protection state | `3` — see Network Protection State Enum below |
| `dst.identityProtectionState` | int | ZN identity protection state | `1` — see Identity Protection State Enum below |
| `ipSpace` | int | IP space classification | `0` |

### Asset Type Enum

Domain Controllers have **no dedicated asset type** - they are classified as SERVER (`2`). To identify DCs precisely, maintain a watchlist/lookup of known DC asset IDs populated from ZN's asset inventory.

| Value | Name | Description |
|---|---|---|
| `0` | `ASSET_TYPE_UNKNOWN` | Unknown / unclassified |
| `1` | `CLIENT` | Workstation / client endpoint |
| `2` | `SERVER` | Server (includes Domain Controllers) |
| `3` | `CLUSTER` | Cluster node |
| `4` | `CAMERA` | IP camera |
| `11` | `ROUTER` | Router |
| `12` | `HYPERVISOR` | Hypervisor host |
| `15` | `SWITCH` | Network switch |
| `75` | `TABLET` | Tablet |
| `135` | `OT_DEVICE` | Generic OT device |

> Values 4-134 and 136+ cover OT/IoT device categories.

### Asset Source Enum

Indicates how the asset was discovered or imported into ZN.

| Value | Name |
|---|---|
| `0` | Unspecified |
| `1` | Access portal |
| `2` | SSP |
| `3` | Active Directory |
| `4` | Custom |
| `5` | System |
| `6` | Ansible |
| `7` | Manual OT/IoT |
| `8` | Workgroup |
| `9` | Azure Active Directory |
| `10` | Azure |
| `11` | AWS |
| `12` | GCP |
| `13` | Tag |
| `14` | Jamf |
| `15` | Manual Linux |
| `16` | IBM Cloud |
| `17` | Oracle Cloud |
| `18` | VMware Cloud |
| `19` | Alibaba Cloud |
| `20` | Lumen Cloud |
| `21` | OVH Cloud |
| `22` | Connect |
| `23` | AI |
| `24` | SNOW |
| `25` | Google Workspace |
| `26` | OU |
| `27` | Environment |
| `28` | Conditional |
| `29` | Claroty OT |
| `30` | Manual Mac |

### SIEM field name translations

| Raw JSON field | Sentinel (`_CL`) | Splunk (`spath path=`) | Elastic / EQL | Chronicle UDM |
|---|---|---|---|---|
| `subjectUser.name` | `subjectUser_name_s` | `"subjectUser.name"` | `subjectUser.name` | `additional.fields["SubjectUserName"]` |
| `subjectUser.sid` | `subjectUser_sid_s` | `"subjectUser.sid"` | `subjectUser.sid` | `additional.fields["SubjectUserSID"]` |
| `targetUser.name` | `targetUser_name_s` | `"targetUser.name"` | `targetUser.name` | `additional.fields["TargetUserName"]` |
| `failureReason` | `failureReason_d` | `"failureReason"` | `failureReason` | `additional.fields["FailureReason"]` (stringified) |
| `authenticationPackageName` | `authenticationPackageName_s` | `"authenticationPackageName"` | `authenticationPackageName` | `additional.fields["AuthPackage"]` |
| `dst.assetId` | `dst_assetId_s` | `"dst.assetId"` | `dst.assetId` | `target.asset.asset_id` |
| `dst.fqdn` | `dst_fqdn_s` | `"dst.fqdn"` | `dst.fqdn` | `target.hostname` |
| `dst.assetType` | `dst_assetType_d` | `"dst.assetType"` | `dst.assetType` | `additional.fields["DstAssetType"]` (stringified) |
| `eventType` | `eventType_d` | `"eventType"` | `eventType` | `additional.fields["EventType"]` |
| `logonType` | `logonType_d` | `"logonType"` | `logonType` | `additional.fields["LogonType"]` |
| `processName` | `processName_s` | `"processName"` | `processName` | `additional.fields["ProcessName"]` |

> **Note**: `src` can be null in identityactivity events. Do not filter on source asset fields; group/correlate on destination and subject user only.

### Network Protection State Enum

Integer field `dst.networkProtectionState` in identityactivity (and `Src.AssetNetworkSegmentationState` string label in networkactivity — see Segmentation States section).

| Value | Name |
|---|---|
| `0` | Unspecified |
| `1` | Unsegmented |
| `2` | Unsegmenting |
| `3` | Segmented |
| `4` | Segmenting |
| `5` | Learning until |
| `6` | Forced Unprotected |
| `7` | Unsegmenting (policy) |
| `8` | Segmented (policy) |
| `9` | Segmenting (policy) |
| `10` | Learning until (policy) |
| `11` | Learning done |
| `12` | Learning done (policy) |
| `13` | Applying queued with blocks |
| `14` | Applying queued with blocks (policy) |
| `15` | Queued with blocks |
| `16` | Queued with blocks (policy) |
| `17` | Queued with blocks done |
| `18` | Queued with blocks done (policy) |

### Identity Protection State Enum

Integer field `dst.identityProtectionState` in identityactivity.

| Value | Name |
|---|---|
| `0` | Unspecified |
| `1` | Unsegmented |
| `2` | Unspecified (variant) |
| `3` | Segmented |
| `4` | Unsegmented (variant) |
| `5` | In learning |
| `6` | Forced Unprotected |
| `7` | Forced Removing Protection |
| `8` | Protected (policy) |
| `9` | Applying Protection (policy) |
| `10` | In learning (policy) |
| `11` | Learning Done |
| `12` | In learning (policy) done |

### Logon Type Enum

Integer field `logonType` in identityactivity.

| Value | Name |
|---|---|
| `1` | Locally |
| `2` | Network |
| `3` | Batch |
| `4` | Service |
| `5` | RDP |

### Connection State Enum (networkactivity)

Integer representation of the connection outcome. The SIEM export surfaces this as the string `ConnectionStatus` field; the underlying API uses integer values.

| Value | String form (`ConnectionStatus`) | Description |
|---|---|---|
| `1` | `blocked` | ZN policy blocked the connection |
| `2` | `requested` | Connection pending / at MFA gate |
| `3` | `established` | Connection succeeded |
| `4` | `blocked_at_source` | Blocked before leaving the host |
| `5` | — | Blocked by third-party policy |
| `6` | — | Blocked at source by third-party policy |

---

## rpcactivity Fields

rpcactivity has its own distinct schema — it does **not** share the identityactivity structure. Key fields for detection are `Operation.Name` (the RPC interface) and the `Src`/`Dst` asset objects.

| Field | Type | Description | Example Values |
|---|---|---|---|
| `TimestampEpoch` | int | Unix epoch (seconds) | `1234567890` |
| `TimestampIso8601` | string | ISO 8601 UTC timestamp | `"2023-10-01T12:00:00Z"` |
| `Status` | string | Connection outcome | `""` |
| `TrafficType` | int | Traffic classification (integer) | `1` (Internal), `2` (External) |
| `ProtocolType` | int | IP protocol number | `6` (TCP) |
| `Interface.UUID` | string | RPC interface UUID | `"123e4567-e89b-12d3-a456-426614174000"` |
| `Interface.Name` | string | RPC interface name | `"drsuapi"` |
| `Operation.Number` | int | RPC operation number | `123` |
| `Operation.Name` | string | RPC operation/interface name — primary detection field | `"drsuapi"`, `"samr"` |
| `User.Name` | string | Calling user name | `"CORP\\jsmith"` |
| `User.SID` | string | Calling user SID | `"S-1-5-21-..."` |
| `RuleIDs` | string[] | Matched ZN rule IDs | `["123", "456"]` |
| `Src.AssetID` | string | Source asset identifier | |
| `Src.AssetSource` | string | Source asset management origin | |
| `Src.AssetType` | string | Source asset classification | |
| `Src.AssetRPCSegmentationState` | string | ZN RPC segmentation state | |
| `Src.Fqdn` | string | Source FQDN | |
| `Src.IP` | string | Source IP | |
| `Src.Port` | int | Source port | |
| `Src.EventRecordID` | int | Windows event record ID | |
| `Src.Endpoint` | string | RPC endpoint | |
| `Src.ProcessID` | int | Source process ID | |
| `Src.ProcessPath` | string | Source process path | |
| `Dst.*` | - | All Src fields mirrored on destination | - |

### Notable Operation.Name values

| Operation.Name | Threat relevance |
|---|---|
| `ITaskSchedulerService` | Remote scheduled task creation (T1053.005) |
| `IWbemServices` | WMI lateral movement (T1047) |
| `winreg` | Remote registry access (T1112) |
| `svcctl` | Remote service manipulation (T1543.003) |
| `drsuapi` | DCSync / credential dumping (T1003.006) |
| `samr` | Account enumeration (T1087.002) |

---

## Segmentation States

String labels exported by the ZN event exporter for networkactivity (`Src.AssetNetworkSegmentationState`, `Dst.AssetNetworkSegmentationState`). These correspond to the integer `protectionState` enum — see Network Protection State Enum above.

| State string | Meaning | Alert relevance |
|---|---|---|
| `Segmented` | Full ZN policy enforcement active | Baseline expected state |
| `Segmented (policy)` | Policy-driven segmentation | Baseline expected state |
| `In learning` | ZN profiling traffic, not enforcing | Elevated risk - treat as unprotected |
| `In learning (policy)` | Policy-driven learning mode | Elevated risk |
| `In learning with blocks` | Learning with block rules active | Monitor closely |
| `In learning with blocks (policy)` | Policy-driven learning with blocks | Monitor closely |
| `Learning done` | Learning phase complete, not yet enforcing | Brief window of risk |
| `Learning (policy) done` | Policy learning complete | Brief window of risk |
| `Learning with blocks done` | Learning with blocks complete | Brief window of risk |
| `Learning with blocks (policy) done` | Policy learning with blocks complete | Brief window of risk |
| `Not segmented` | No ZN enforcement | High risk - any outbound is uncontrolled |
| `Not segmented (manual)` | Manually removed from enforcement | High risk |
| `Segmenting` | Transitioning to segmented | Transient state |
| `Segmenting (policy)` | Policy-driven transition to segmented | Transient state |
| `Unsegmenting` | Transitioning away from enforcement | High risk - monitor |
| `Unsegmenting (manual)` | Manually initiated unsegmentation | High risk |
| `Enforcing block rules` | Actively enforcing block rules | Expected enforcement state |
| `Enforcing block rules (policy)` | Policy-driven block enforcement | Expected enforcement state |

**ConnectionStatus values**:
- `blocked` - ZN policy blocked the connection
- `requested` - connection pending / at MFA gate
- `established` - connection succeeded
- `blocked_at_source` - blocked before leaving the host

---

## Key Port Reference (for lateral movement rules)

| Port | Protocol | Relevance |
|---|---|---|
| 445 | SMB | File share access, ransomware staging, lateral movement |
| 139 | NetBIOS | Legacy SMB |
| 3389 | RDP | Remote desktop lateral movement |
| 5985 | WinRM HTTP | PowerShell remoting |
| 5986 | WinRM HTTPS | PowerShell remoting (encrypted) |
| 22 | SSH | Linux/network device lateral movement |
| 135 | RPC Endpoint Mapper | RPC lateral movement precursor |
| 389 | LDAP | AD enumeration |
| 636 | LDAPS | AD enumeration (encrypted) |
| 88 | Kerberos | Auth abuse, Pass-the-Ticket |
| 1433 | MSSQL | Database lateral movement |
| 5432 | PostgreSQL | Database lateral movement |

---

## ConnectionStatus Decision Matrix

| Status | Blocked? | Severity guidance |
|---|---|---|
| `established` | No - connection succeeded | High severity if anomalous (new pair, new port) |
| `requested` | Pending / MFA gate | Medium - monitor for completion |
| `blocked` | Yes - ZN policy blocked | Medium - attempted lateral movement |
| `blocked_at_source` | Yes - blocked before leaving host | Low-Medium - policy working, but log the attempt |

---

## Baseline Strategy

All anomaly-based detections in this library require a **lookback baseline window**. Recommended approach:

- **Sentinel**: Use `materialize()` with a 14-day lookback, summarized as `(Src.AssetID, Dst.AssetID, Dst.Port)` tuples
- **Splunk**: Use `inputlookup`/`outputlookup` with a scheduled search to maintain a baseline KV store
- **Elastic**: Use `enrich` processor or a baseline index populated by a recurring transform
- **Chronicle**: Use `FIRST_SEEN` UDM enrichment or a reference list populated by a scheduled rule

Minimum recommended baseline: **7 days**. Recommended: **14–30 days**. Do not alert during the initial baseline build period.

---

## MITRE ATT&CK Mapping

| Detection | Technique | ID |
|---|---|---|
| New internal asset pair | Lateral Movement | T1021.* |
| Internal port fanout | Network Service Discovery | T1046 |
| First SMB from workstation | SMB/Windows Admin Shares | T1021.002 |
| First RDP | Remote Desktop Protocol | T1021.001 |
| First WinRM | Windows Remote Management | T1021.006 |
| OT/IT boundary crossing | Network Boundary Bridging | T1599 |
| RPC new pair (ITaskScheduler) | Scheduled Task/Job: Remote | T1053.005 |
| RPC new pair (IWbemServices) | Windows Management Instrumentation | T1047 |
| RPC new pair (drsuapi) | OS Credential Dumping: DCSync | T1003.006 |
| Service account → workstation | Valid Accounts | T1078 |
| Multi-machine auth | Use Alternate Auth Material | T1550 |
