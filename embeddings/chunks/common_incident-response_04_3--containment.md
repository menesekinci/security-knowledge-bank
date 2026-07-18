---
source: "common/incident-response.md"
title: "🚨 Incident Response for Developers"
heading: "3. Containment"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, containment, detection, eradication, phases, recovery]
chunk: 4/18
---

## 3. Containment

### Immediate Actions (Critical/High Severity)

```
SECONDS-TO-MINUTES
├── 1. Do NOT reboot/shutdown (lose forensic data)
├── 2. Isolate affected systems
│   ├── Remove from load balancer
│   ├── Block IP at WAF/firewall
│   └── Take instance snapshot (cloud)
├── 3. Rotate ALL credentials that may be exposed
│   ├── API keys, database passwords, cloud access keys
│   └── CI/CD tokens (GitHub PAT, npm token, etc.)
├── 4. Revoke/rotate session tokens
├── 5. Enable enhanced logging on affected systems
└── 6. Notify security team + incident commander
```

### Short-Term Containment by Type

| Vulnerability Type         | Containment Strategy                                   |
|----------------------------|--------------------------------------------------------|
| **RCE / code injection**   | Take pod/instance offline, block exploit path at WAF   |
| **SQL injection**          | Disable vulnerable endpoint, add WAF rule              |
| **Authentication bypass**  | Force all user sessions to re-authenticate             |
| **Sensitive data leak**    | Take down exposed endpoint, revoke API key             |
| **Supply chain compromise**| Pin vulnerable package to safe version, rebuild        |
| **Secret leak**            | Rotate leaked secret, remove from git history          |
| **SSRF**                   | Block outbound traffic from app, restrict metadata API |
| **XSS**                    | Add CSP, sanitize output at CDN                        |

### Communication Template

```
Subject: [SECURITY] Incident <ID> — <Severity> — <Type>

Summary:
<one-line description>

Status: Active / Contained / Resolved
Severity: Critical / High / Medium / Low
Affected: <systems, users, data>

Timeline:
- HH:MM — Detection via <source>
- HH:MM — Initial triage completed
- HH:MM — Containment action taken

Next Actions:
- <what's being done>
- <expected resolution time>
```

---