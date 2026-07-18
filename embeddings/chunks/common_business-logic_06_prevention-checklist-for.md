---
source: "common/business-logic.md"
title: "Business Logic Vulnerabilities"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [business, checklist, common, common-vuln, detection, prevention, strategies, vibe, what]
chunk: 6/8
---

## Prevention Checklist for AI Prompts

```
✅ BUSINESS LOGIC REQUIREMENTS:
- Never trust client-side values for prices, discounts, or quantities
- Validate every business operation against server-side state
- Enforce workflow ordering — don't allow step skipping
- Implement per-user rate limiting on all business operations
- Add usage limits for discounts, referral codes, and promotions
- Use idempotency keys to prevent duplicate operations
- Log all business operations for audit trail
- Add fraud detection: flag unusual patterns (many accounts from same IP)
- Validate that quantities are positive and within sensible ranges
- Enforce minimum/maximum order values server-side
```

---