# Site hierarchy map

- **Generated:** 2026-11-04 10:00:00
- **Tenant:** mycompany-admin.zeronetworks.com
- **CSV file:** site-groups.csv
- **Mode:** Dry run preview
- **Groups:** 7
- **Subnets:** 6
- **Max depth:** 3 level(s)

## Graph (Mermaid)

```mermaid
flowchart TD
    n0["Site_Corp"]
    n1["Site_US"]
    n2["Site_EMEA"]
    n3["Site_NewYork<br/>10.98.10.0/24<br/>10.98.11.0/24"]
    n4["Site_Boston<br/>10.98.12.0/24<br/>10.98.12.50/32"]
    n5["Site_London<br/>10.98.20.0/22"]
    n6["Site_Standalone<br/>10.98.30.0/24"]
    n0 --> n1
    n0 --> n2
    n1 --> n3
    n1 --> n4
    n2 --> n5
    classDef planned fill:#C6C6FF,stroke:#667FFF,color:#08084C
    classDef created fill:#04B88E,stroke:#04B88E,color:#FFFFFF
    classDef updated fill:#667FFF,stroke:#08084C,color:#FFFFFF
    classDef unchanged fill:#EDEDF9,stroke:#08084C,color:#08084C
    classDef failed fill:#FFFFFF,stroke:#B3261E,color:#B3261E,stroke-width:3px
    classDef external fill:#FFFFFF,stroke:#08084C,color:#08084C,stroke-dasharray:5 5
    class n0,n1,n2,n3,n4,n5,n6 planned
```

## Tree

```text
Site_Corp  (0 subnets)  [Planned]
├── Site_US  (0 subnets)  [Planned]
│   ├── Site_NewYork  (2 subnets)  [Planned]
│   └── Site_Boston  (2 subnets)  [Planned]
└── Site_EMEA  (0 subnets)  [Planned]
    └── Site_London  (1 subnet)  [Planned]
Site_Standalone  (1 subnet)  [Planned]
```

## Table

| Group | Parent | Level | Status | Subnet count | Subnets |
|---|---|---|---|---|---|
| Site_Corp | - | 1 | Planned | 0 | - |
| Site_US | Site_Corp | 2 | Planned | 0 | - |
| Site_EMEA | Site_Corp | 2 | Planned | 0 | - |
| Site_NewYork | Site_US | 3 | Planned | 2 | 10.98.10.0/24, 10.98.11.0/24 |
| Site_Boston | Site_US | 3 | Planned | 2 | 10.98.12.0/24, 10.98.12.50/32 |
| Site_London | Site_EMEA | 3 | Planned | 1 | 10.98.20.0/22 |
| Site_Standalone | - | 1 | Planned | 1 | 10.98.30.0/24 |

> **Reminder:** Zero Networks must enable Sites after these groups exist.
