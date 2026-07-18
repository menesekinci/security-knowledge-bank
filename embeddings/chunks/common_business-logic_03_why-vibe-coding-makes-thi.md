---
source: "common/business-logic.md"
title: "Business Logic Vulnerabilities"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [business, checklist, common, common-vuln, detection, prevention, strategies, vibe, what]
chunk: 3/8
---

## Why Vibe Coding Makes This Worse

- **AI doesn't understand business context:** AI writes code for "apply coupon" but doesn't implement "apply coupon once per user"
- **AI assumes honest users:** Generated workflows don't anticipate adversarial behavior
- **AI generates linear happy paths:** "Step 1 → Step 2 → Step 3" but doesn't enforce ordering
- **AI uses client-side trust:** AI puts business rules in JavaScript that runs on the user's browser
- **No rate limiting on business actions:** AI forgets to limit coupon redemptions, balance checks, etc.