---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "2. Core Principles"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 4/10
---

## 2. Core Principles

Zero Trust rests on three foundational principles. Every Zero Trust control should trace back to one or more of these.

### Principle 1: Never Trust, Always Verify

**Every access request is fully authenticated, authorized, and encrypted before granting access — regardless of where the request originates.**

This applies to:
- A developer's laptop at home accessing production logs
- A microservice calling another microservice within the same Kubernetes cluster
- A third-party API fetching data from your public endpoint
- An admin console request from inside the corporate office

**Implementation signals:**
- **Identity:** Who is making the request? (User, service account, machine)
- **Device:** Is the device healthy? (Patched, managed, anti-malware running)
- **Context:** Where is the request coming from? (Geolocation, IP reputation, time of day)
- **Data sensitivity:** What data is being accessed? (Classification label)
- **Behavior:** Is this request anomalous? (First time, unusual volume)

### Principle 2: Assume Breach

**Design every system as if an attacker is already inside the network.**

This is not pessimism — it is operational reality. The median dwell time (time between compromise and detection) for intrusions is measured in weeks or months, not hours. Assume the perimeter has already been breached and design controls for that reality.

**Consequences of Assume Breach:**
- **Micro-segmentation** — lateral movement is restricted even if a host is compromised
- **End-to-end encryption** — data is protected even if the network or intermediate hops are compromised
- **Continuous monitoring** — every access is logged, every anomaly is alerted
- **Blast radius containment** — a compromised identity gets minimal access; compromise does not cascade
- **Just-in-time access** — standing privileges are minimized; access is elevated only when needed and for limited duration

### Principle 3: Least Privilege

**Grant the minimum access necessary for the minimum time necessary.**

This principle (already covered in depth in [security-principles.md](security-principles.md)) is a pillar of Zero Trust. In a Zero Trust context, least privilege means:

- **Per-session permissions** — a user's permissions are evaluated for each session, not granted once at login
- **Dynamic policies** — permissions change based on context (device health, location, risk score)
- **No standing privileges** — administrative access is granted on-demand and expires automatically
- **Resource-level scoping** — "access to Servers" is too broad; "access to `server-42` on TCP/443 for 2 hours" is scoped correctly

---