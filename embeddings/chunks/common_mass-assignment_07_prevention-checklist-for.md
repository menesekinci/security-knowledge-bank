---
source: "common/mass-assignment.md"
title: "Mass Assignment / Auto Binding"
heading: "Prevention Checklist for AI Prompts"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common, common-vuln, fixed, mass, vibe, vulnerable, what]
chunk: 7/9
---

## Prevention Checklist for AI Prompts

```
✅ MASS ASSIGNMENT PREVENTION:
- Never use __all__ or spread/merge entire request bodies into models
- Always use an allowlist of updatable fields
- Use Data Transfer Objects (DTOs) with only API-accessible fields
- Set read_only_fields on sensitive model properties
- Keep user-facing models separate from internal domain models
- Use libraries: Strong Parameters (Rails), @JsonIgnore (Spring), ModelSerializer.fields (DRF)
- Add middleware to strip unwanted parameters
- Test by sending extra fields in requests to verify they're ignored
```

---