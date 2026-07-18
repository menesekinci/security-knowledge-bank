---
source: "common/ssrf.md"
title: "Server-Side Request Forgery (SSRF)"
heading: "What Is SSRF?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [cloud, code, common-vuln, fixed, metadata, vibe, vulnerable, what]
chunk: 2/10
---

## What Is SSRF?

SSRF occurs when an attacker **makes the server perform HTTP requests** to internal or external resources that the attacker controls. The attacker can:

- Access internal services (databases, Redis, cloud metadata endpoints)
- Read internal files (`file:///etc/passwd`)
- Scan internal networks bypassing firewalls
- Reach cloud provider metadata services (AWS `169.254.169.254`, GCP `metadata.google.internal`)

**The root cause:** The application fetches a URL provided by user input without validating the destination.