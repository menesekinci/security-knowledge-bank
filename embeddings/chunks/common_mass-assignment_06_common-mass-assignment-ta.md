---
source: "common/mass-assignment.md"
title: "Mass Assignment / Auto Binding"
heading: "Common Mass Assignment Targets"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common, common-vuln, fixed, mass, vibe, vulnerable, what]
chunk: 6/9
---

## Common Mass Assignment Targets

| Field | Why Attackers Want It |
|---|---|
| `role`, `is_admin`, `is_staff` | Privilege escalation |
| `balance`, `credits`, `points` | Financial fraud |
| `is_verified`, `email_verified` | Bypass verification |
| `password`, `password_hash` | Account takeover |
| `api_key`, `secret` | API access |
| `is_active`, `is_banned` | Account manipulation |

---