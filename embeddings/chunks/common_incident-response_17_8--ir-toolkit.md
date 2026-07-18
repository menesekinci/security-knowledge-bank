---
source: "common/incident-response.md"
title: "🚨 Incident Response for Developers"
heading: "8. IR Toolkit"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, containment, detection, eradication, phases, recovery]
chunk: 17/18
---

## 8. IR Toolkit

### Developer IR Toolbox

| Tool                 | Use Case                                          |
|----------------------|---------------------------------------------------|
| **git bisect**       | Find the exact commit that introduced the vuln    |
| **git log --grep**   | Search for dangerous patterns in commit messages  |
| **tcpdump/Wireshark**| Capture network traffic evidence                  |
| **jq**               | Parse and query JSON logs                         |
| **grep/ripgrep**     | Search codebase for similar vulnerable patterns   |
| **Semgrep**          | Find all occurrences of the vulnerable pattern    |
| **docker diff**      | Check container for unauthorized changes          |
| **Vault**            | Emergency credential rotation                     |
| **Gitleaks**         | Scan entire git history for exposed secrets       |

### Critical Contacts List

```
SECURITY TEAM:     #security-channel in Slack/Teams
INCIDENT COMMANDER: <on-call rotation>
LEGAL/PR:          <office hours + emergency contact>
COMPLIANCE:        <data protection officer>
EXECUTIVE SPONSOR: <CISO or VP Engineering>
```

---