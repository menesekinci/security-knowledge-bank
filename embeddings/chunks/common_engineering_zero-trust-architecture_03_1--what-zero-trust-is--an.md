---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "1. What Zero Trust Is (and Isn't)"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 3/10
---

## 1. What Zero Trust Is (and Isn't)

### What It Is

Zero Trust is a security model that eliminates implicit trust from a network. It operates on the premise that no entity — user, device, application, or network — should be trusted by default, regardless of whether it is inside or outside the corporate perimeter.

**The core shift:**

| Traditional "Castle-and-Moat" | Zero Trust |
|---|---|
| Trusts anything inside the network | Trusts nothing by default |
| Perimeter is the security boundary | Identity + device posture is the security boundary |
| Once inside, broad lateral access | Least-privilege access per session |
| Network location determines trust | Continuous verification determines trust |
| VPN as the entry gate | Direct, authenticated access to specific resources |

### What It Is NOT

- **Not a product** — you cannot buy "Zero Trust" from a vendor. It is an architecture principle. Vendors selling "Zero Trust switches" or "Zero Trust firewalls" are selling point solutions that support a ZTA, not the ZTA itself.
- **Not "no trust"** — trust still exists; it is just explicit, conditional, and continuously verified.
- **Not VPN replacement** — removing VPN is a *consequence* of Zero Trust, not the goal. The goal is removing implicit trust.
- **Not a one-time project** — Zero Trust is an ongoing security operating model, not a milestone you reach and declare done.
- **Not just for enterprises** — startups can (and should) adopt Zero Trust principles from day one with cloud-native tooling.

---