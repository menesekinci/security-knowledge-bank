---
source: "common/incident-response.md"
title: "🚨 Incident Response for Developers"
heading: "4. Eradication"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, containment, detection, eradication, phases, recovery]
chunk: 5/18
---

## 4. Eradication

### Removing the Root Cause

```
AFTER CONTAINMENT
├── 1. IDENTIFY ROOT CAUSE
│   ├── Forensic analysis
│   ├── Code review (git blame the change)
│   ├── Log analysis (who, what, when)
│   └── Vulnerability reproduction
│
├── 2. DEVELOP FIX
│   ├── Pair with security engineer
│   ├── Write/update test that catches the vuln
│   ├── Get second reviewer (security SME)
│   └── Apply to all affected branches/versions
│
├── 3. REMOVE MALICIOUS ARTIFACTS
│   ├── Clean up compromised data
│   ├── Remove backdoors/persistence
│   ├── Reset API keys, deploy keys, tokens
│   └── Purge unauthorized user accounts
│
├── 4. UPDATE DEFENSES
│   ├── Add SAST rule to prevent reoccurrence
│   ├── Update dependency allow/denylist
│   ├── Add detection rule to SIEM
│   └── Harden CI/CD security gates
│
└── 5. VERIFY FIX
    ├── Penetration test the fix
    ├── Run full test suite with security tests
    └── Deploy to isolated environment first
```

### Patching Process

```yaml
1. [ ] Create fix branch from vulnerability detection commit
2. [ ] Apply fix + regression test
3. [ ] Security review of fix
4. [ ] Merge to main with deployment freeze
5. [ ] Deploy to staging, run DAST + full test suite
6. [ ] Deploy to production (canary or rolling)
7. [ ] Monitor for 24-48 hours post-deploy
8. [ ] Confirm fix with penetration test
```

---