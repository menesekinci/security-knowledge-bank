---
source: "common/incident-response.md"
title: "🚨 Incident Response for Developers"
heading: "5. Recovery"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, containment, detection, eradication, phases, recovery]
chunk: 6/18
---

## 5. Recovery

### Restoring Operations

- [ ] Verify all systems are patched
- [ ] Restore from clean backup if data was corrupted
- [ ] Validate data integrity (DB checksums, replication lag)
- [ ] Gradually return services to normal traffic
- [ ] Monitor for re-attempt (attacker may return)
- [ ] Communicate resolution to affected users
- [ ] Confirm bug bounty/reward payout (if applicable)

### Recovery Checklist by Data Impact

| Data Compromised         | Recovery Steps                                           |
|--------------------------|----------------------------------------------------------|
| **User passwords**       | Force reset all passwords, notify users                  |
| **PII/Personal data**    | Notify affected individuals per regulation (GDPR 72h)    |
| **Financial data**       | Notify compliance team, potentially regulators           |
| **API keys**             | Rotate all, update all consuming services                |
| **Session tokens**       | Invalidate all sessions, require re-login                |
| **Source code**          | Rotate all repo secrets, audit for backdoors in code     |
| **Encryption keys**      | Rotate KMS keys, re-encrypt all data                     |

---