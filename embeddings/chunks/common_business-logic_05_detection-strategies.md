---
source: "common/business-logic.md"
title: "Business Logic Vulnerabilities"
heading: "Detection Strategies"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [business, checklist, common, common-vuln, detection, prevention, strategies, vibe, what]
chunk: 5/8
---

## Detection Strategies

| Technique | What to Look For |
|---|---|
| Workflow fuzzing | Try steps out of order, skip steps, repeat steps |
| Parameter tampering | Change prices, quantities, discount values in requests |
| Race conditions | Send parallel requests for coupon redemptions, transfers |
| State manipulation | Modify cookies, tokens to change workflow state |
| Integer overflow | MAX_INT + 1 = negative (free money!) |
| Negative values | Negative quantity → negative price (store pays you) |

---