# 🚨 Incident Response for Developers

> **Category:** Common / Incident Response
> **Last Updated:** July 2026
> **Description:** Incident response methodology tailored for developers. Covers detection, containment, eradication, and recovery with specific guidance for vulnerabilities found in AI-generated code.

---

## 1. IR Phases (NIST 800-61 Aligned)

```
┌──────────────────────────────────────────────────────────┐
│               INCIDENT RESPONSE LIFECYCLE                  │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  1. PREPARATION ──── Toolkit, playbooks, runbooks         │
│        │                                                  │
│  2. DETECTION & ANALYSIS ──── Alert, triage, scope        │
│        │                                                  │
│  3. CONTAINMENT ──── Stop the bleeding                    │
│        │                                                  │
│  4. ERADICATION ──── Remove the root cause                │
│        │                                                  │
│  5. RECOVERY ──── Restore normal operations               │
│        │                                                  │
│  6. POST-MORTEM ──── Lessons learned, update playbooks    │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Detection

### How Incidents Are Detected

| Source                     | Example Trigger                                      | Response Time |
|----------------------------|------------------------------------------------------|---------------|
| **Security scanner**       | SAST/DAST finding in CI                              | Minutes       |
| **SIEM alert**             | Anomalous network traffic, repeated 401s             | Minutes       |
| **Intrusion detection**    | IDS/IPS signature match                              | < 1 hour      |
| **User report**            | Customer reports data breach                         | < 1 hour      |
| **Bug bounty**             | Validated vulnerability report                       | < 24 hours    |
| **Threat intel feed**      | CVE announced with active exploitation               | < 24 hours    |
| **Cloud provider notice**  | AWS GuardDuty finding, GCP Security Command Center   | < 1 hour      |
| **Dependency alert**       | Dependabot/GitHub Advisory with malicious package    | < 1 hour      |
| **Production monitoring**  | Error budget burn, increased 5xx rate                | < 5 minutes   |
| **AI behavior anomaly**    | AI-generated code behaves unexpectedly in prod       | ASAP          |

### Detection Checklist

- [ ] Are we monitoring auth failures (401s, repeated login attempts)?
- [ ] Are we tracking dependency CVE disclosures?
- [ ] Do we have a way to detect secret leaks (GitGuardian, Gitleaks CI)?
- [ ] Are we alerting on anomalous API usage patterns?
- [ ] Do we monitor cloud API calls for credential abuse?
- [ ] Are we checking SBOMs against known vulnerability databases?
- [ ] Is there a channel for users to report security issues?

### Severity Classification

| Severity | CVSS Range | Examples                                  | Response Time   |
|----------|------------|-------------------------------------------|-----------------|
| 🚨 Critical | 9.0–10.0 | RCE, auth bypass, data breach            | < 1 hour        |
| 🔴 High    | 7.0–8.9   | SQL injection, SSRF, significant data leak | < 4 hours       |
| 🟡 Medium  | 4.0–6.9   | XSS, CSRF, IDOR limited scope            | < 24 hours      |
| 🟢 Low     | 0.1–3.9   | Information disclosure, minor misconfig   | < 1 week        |

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

## 6. Post-Mortem

### Post-Mortem Template

```markdown
# Security Incident Post-Mortem

## Incident Summary
- **ID:** INC-2025-XXXX
- **Date:** YYYY-MM-DD
- **Severity:** Critical / High / Medium / Low
- **Detection Source:** <tool/human/report>
- **Time to Detect:** <elapsed time>
- **Time to Contain:** <elapsed time>
- **Time to Resolve:** <elapsed time>

## Timeline
| Time (UTC) | Event |
|------------|-------|
| HH:MM      | Detection |
| HH:MM      | Initial triage |
| HH:MM      | Containment action |
| HH:MM      | Root cause identified |
| HH:MM      | Fix deployed to production |
| HH:MM      | Monitoring confirmed |

## Root Cause Analysis
<what caused the vulnerability, not just the bug>

## Affected Systems & Data
<list systems, data types, user counts>

## Containment Actions
<what was done to stop the bleeding>

## Remediation
<code changes, config changes, process changes>

## Lessons Learned
### What went well
- 

### What went wrong
- 

### What to improve
- 

## Action Items
| # | Item | Owner | Due Date |
|---|------|-------|----------|
| 1 |      |       |          |
| 2 |      |       |          |
```

---

## 7. AI-Generated Code: Special Considerations

### When a Vulnerability is Found in AI-Generated Code

```
1. PRESERVE THE AI PROMPT CONTEXT
   ├── Save the exact prompt(s) used to generate the vulnerable code
   ├── Record the AI model, version, and timestamp
   └── Document the conversation context (what was the intent?)

2. ANALYZE THE VULNERABILITY PATTERN
   ├── Is it a common AI failure mode?
   │   ├── Hallucinated API/library usage?
   │   ├── Missing security boundary check?
   │   ├── Incorrect implementation of security feature?
   │   ├── Outdated/best-before-cutoff pattern?
   │   └── Copy-pasted insecure Stack Overflow pattern?
   ├── Is it reproducible with the same prompt?
   └── Did the AI actively bypass a security measure, or was it accidental?

3. FIX THE PROMPT (NOT JUST THE CODE)
   ├── Update your prompt templates to prevent recurrence
   ├── Add explicit security requirements (e.g., "use parameterized queries")
   ├── Add negative constraints (e.g., "never use eval()")
   └── Store vulnerability patterns in team knowledge base

4. ASSESS IMPACT
   ├── Is the AI generating other code with the same pattern?
   ├── Run a search across all AI-generated code for similar patterns
   └── Expand detection scope to catch variants

5. UPDATE PROCESS
   ├── Add new SAST rule for this pattern
   ├── Increase review depth for AI-generated code
   ├── Add automated test checking for the vulnerability
   └── Consider if AI should be restricted from writing security-critical code
```

### Known AI-Generated Code Failure Modes

| Pattern | AI Tends To | Why It's Dangerous |
|---------|-------------|-------------------|
| **Auth logic** | Write bypassable middleware | AI doesn't understand multi-layer auth |
| **Crypto** | Use broken algorithms (MD5, SHA1) | Trained on outdated docs |
| **Access control** | Forget to check permissions | Focuses on happy path |
| **Input validation** | Trust user input unconditionally | Assumes clean data |
| **Error handling** | Expose stack traces, verbose errors | Debug-era code in prod |
| **Secret management** | Hardcode secrets for "simplicity" | No concept of security hygiene |
| **Regular expressions** | Write ReDoS-vulnerable patterns | No understanding of catastrophic backtracking |

### Reporting Responsibilities

When you find a vulnerability in AI-generated code:

1. **Internal**: Report through normal security channels
2. **Vendor**: If the AI model itself was exploited (prompt injection causing insecure code), report to the AI vendor
3. **CVE**: If the vulnerability is in a library/package hallucinated or misused by AI, report to the package maintainer
4. **Community**: Share anonymized vulnerability patterns to help improve AI security

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

## References

- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [OWASP Incident Response Playbook](https://owasp.org/www-project-incident-response-playbook/)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [FIRST CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [PagerDuty Incident Response Docs](https://response.pagerduty.com/)
- [Atlassian Incident Management Handbook](https://www.atlassian.com/incident-management)
- [GitLab Incident Response Runbook](https://gitlab.com/gitlab-com/runbooks)
- [Google SRE Book — Managing Incidents](https://sre.google/sre-book/managing-incidents/)
