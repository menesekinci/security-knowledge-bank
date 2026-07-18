---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "6. Data Flow Diagrams"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 8/13
---

## 6. Data Flow Diagrams

Data Flow Diagrams (DFDs) are the backbone of threat modeling. They describe *what* data moves *where* without prescribing *how* (no implementation details).

### DFD Elements

| Shape | Element | Meaning | STRIDE Relevance |
|---|---|---|---|
| Rectangle | External Entity | User, third-party system, or device outside the system boundary | Spoofing, Repudiation |
| Circle / Rounded Rect | Process | Component that transforms data | All six categories |
| Parallel Lines | Data Store | Database, file, cache, bucket | Tampering, Repudiation, Info Disclosure, DoS |
| Arrow | Data Flow | Movement of data between elements | Tampering, Info Disclosure |
| Dotted Line | Trust Boundary | Boundary between trust zones | All — crossing a boundary adds risk |

### Trust Boundaries

A trust boundary is any point where data moves from a higher-trust zone to a lower-trust zone, or vice versa. **Every trust boundary crossing is a security control point.**

Common trust boundaries:
- **Network boundary:** Public internet → VPC
- **Auth boundary:** Unauthenticated → Authenticated
- **Privilege boundary:** Standard user → Admin
- **Process boundary:** Web server → Database
- **Environment boundary:** Dev → Staging → Production
- **Tenant boundary:** Customer A's data → Customer B's data

### Drawing a DFD: Rules

1. **Start at the boundary.** Draw the system boundary rectangle. Everything inside is in scope.
2. **Add external entities** outside the boundary that interact with the system.
3. **Draw processes** — the internal components.
4. **Add data stores** — where data rests.
5. **Connect with data flows** — arrows that show the direction of data movement.
6. **Mark trust boundaries** — any line where the trust level changes.
7. **Validate** — does every data flow connect two elements? Is every data store reachable?

### Example DFD (Textual)

```
┌───────────────────────────────────── System Boundary ─────────────────────────────────────┐
│                                                                                           │
│  [Browser/User] ───HTTPS──→ [API Gateway] ───gRPC──→ [Order Service] ───SQL──→ [(Orders DB)]  │
│      ↑                          ↓                      │                                   │
│      │                       [Auth Service]             │                                   │
│      │                          │                      │                                   │
│      └──────────────────────────┘                      gRPC                                 │
│                                                          ↓                                   │
│                                                    [Payment Service] ───SQL──→ [(Payment DB)]│
│                                                          │                                   │
│                                                    [Fraud Check API] ←─── HTTP (3rd party)  │
│                                                          │                                   │
│                                                    [Audit Logger] → [(Audit Log)]            │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
Trust boundaries:
1. Browser ↔ API Gateway  (← Internet → VPC)
2. All service-to-service (← internal VPC)
3. Services ↔ Databases     (← application → data tier)
```

---