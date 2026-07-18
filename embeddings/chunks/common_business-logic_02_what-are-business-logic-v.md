---
source: "common/business-logic.md"
title: "Business Logic Vulnerabilities"
heading: "What Are Business Logic Vulnerabilities?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [business, checklist, common, common-vuln, detection, prevention, strategies, vibe, what]
chunk: 2/8
---

## What Are Business Logic Vulnerabilities?

Business logic flaws are **design-level vulnerabilities** where attackers abuse the intended functionality of an application to gain unauthorized benefits. Unlike technical vulnerabilities (SQLi, XSS), these don't involve injection or bypassing controls — the attacker simply uses the application in a way the developers didn't anticipate.

**Examples:** Applying the same discount code 100 times, buying a $1000 item for $10 by manipulating quantity, skipping payment step, resetting another user's password.