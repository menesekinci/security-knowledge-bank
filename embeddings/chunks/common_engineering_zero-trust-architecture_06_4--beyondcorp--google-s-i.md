---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "4. BeyondCorp: Google's Implementation"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 6/10
---

## 4. BeyondCorp: Google's Implementation

Google's BeyondCorp (documented in a series of papers 2014–2021) is the most influential real-world Zero Trust implementation. It removed the corporate VPN and moved access control from the network perimeter to the device and user.

### Key Insights from BeyondCorp

**1. No privileged network**

In Google's model, there is no "corporate network" that implies trust. All access to internal applications goes through an access proxy that authenticates the user, checks device inventory, and evaluates policy — regardless of whether the request comes from a Google office, a coffee shop, or a home office.

**2. Device inventory is foundational**

Before BeyondCorp, Google built a comprehensive device inventory service (the "Inventory" service in their model). Every device that accesses corporate resources must be registered, managed, and continuously verified for compliance. Without a device inventory, device-based access decisions are impossible.

**3. The access proxy is the only gate**

All access to internal applications goes through a small number of access proxies (the "Access Proxy" — think of it as a highly scalable, highly available reverse proxy). The proxy evaluates:
- **User identity** (via SSO)
- **Device identity and health** (device certificate, inventory status)
- **Context** (what resource, what action, what time)

Only if all checks pass does the proxy forward the request to the application.

**4. Migration is gradual**

Google did not flip a switch. They migrated application by application over several years:
- First, build the device inventory and certificate infrastructure.
- Second, deploy access proxies for a small set of internal tools.
- Third, migrate the most sensitive applications first.
- Fourth, gradually expand to all applications.
- Finally, remove the VPN — not before.

### BeyondCorp Architecture (Simplified)

```
[User Device] ──mTLS──→ [Access Proxy] ────→ [Internal App]
                               │
                    ┌──────────┴──────────┐
                    │  Policy Engine       │
                    │   ┌──────────────┐   │
                    │   │ User Identity │   │
                    │   │ Device State  │   │
                    │   │ Context       │   │
                    │   │ Policy Rules  │   │
                    │   └──────────────┘   │
                    └─────────────────────┘
```

### Open-Source Alternatives to BeyondCorp

| Project | Description | Best For |
|---|---|---|
| **Pomerium** | Identity-aware proxy, open-source | Teams wanting a self-hosted BeyondCorp-like proxy |
| **Cloudflare Access** | Cloud identity-aware proxy | Teams already on Cloudflare; no infrastructure to manage |
| **Tailscale** | WireGuard-based mesh VPN with SSO integration | Small teams wanting simple, identity-based networking |
| **Teleport** | SSH/K8s/database access with identity-based controls | Teams needing granular infrastructure access |
| **OAuth2 Proxy** | Lightweight reverse proxy that adds OAuth | Simple web app authentication gate |

---