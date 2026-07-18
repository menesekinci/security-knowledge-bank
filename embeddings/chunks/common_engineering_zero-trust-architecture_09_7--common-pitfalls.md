---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "7. Common Pitfalls"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 9/10
---

## 7. Common Pitfalls

### Pitfall 1: Buying a "Zero Trust" Product and Calling It Done

No single product delivers Zero Trust. If a vendor says "buy our switch/firewall/agent for Zero Trust," they are selling a piece of the puzzle, not the whole picture. Zero Trust is an architecture, implemented through policies, processes, and multiple controls across all five pillars.

### Pitfall 2: Zero Trust = No VPN (Oversimplification)

Removing the VPN is a *result* of Zero Trust, not the definition. If you remove the VPN but still allow broad network access from any corporate device without continuous verification, you have not achieved Zero Trust — you have just made your network perimeter invisible but equally vulnerable.

### Pitfall 3: Ignoring the Human Element

Zero Trust controls can create significant friction if not designed well. If developers need to request JIT access for every small change, they will find ways around the system. **Apply Psychological Acceptability** (see [security-principles.md](security-principles.md)) — make the secure path the easy path.

### Pitfall 4: Micro-segmentation Without Monitoring

Micro-segmentation that blocks lateral movement is good. Micro-segmentation with no monitoring means you never know when a segmentation policy is misconfigured or when an attacker is probing the boundaries. **Monitor policy violations** — a blocked lateral movement attempt is a security incident worth investigating.

### Pitfall 5: Over-Complex Policy Engine

A policy engine with 500 rules that nobody understands is no better than a flat network. Start with 5–10 clear policies and expand only when you understand the impact of each new rule. **Policy as code** (e.g., Open Policy Agent / Rego) helps here — policies can be reviewed, tested, and versioned.

### Pitfall 6: Treating Zero Trust as an IT Project

Zero Trust is not something the IT team "implements" and then the rest of the company ignores. It requires:
- **Engineering buy-in** — developers must adopt secure defaults, least-privilege service accounts, and application-level auth
- **Product buy-in** — user-facing features must support SSO, MFA, and secure sessions
- **Executive buy-in** — Zero Trust controls sometimes slow down development velocity in the short term; leadership must understand the trade-off
- **Security team support** — policy design, incident response, and continuous improvement require dedicated security resources

### Pitfall 7: Not Planning for "What Happens When the IdP Is Down"

If your SSO provider goes down and *every* access decision depends on it, you have a single point of failure. Plan for:
- **Offline access tokens** — short-lived tokens can be validated without contacting the IdP
- **Cache policies** — the access proxy can use cached device posture data for a limited time when the IdP is unreachable
- **Emergency break-glass** — documented, audited emergency accounts for critical operations when the primary identity system fails

### Pitfall 8: Ignoring Legacy Systems

Not every system in your portfolio can support OIDC, mTLS, or device certificates. Legacy systems need special treatment:
- **Wrap with a proxy** — put an identity-aware proxy in front of legacy apps that cannot change
- **Isolate** — place legacy systems on a separate network segment with strict egress controls
- **Replace** — plan to decommission or modernize systems that cannot participate in Zero Trust

---