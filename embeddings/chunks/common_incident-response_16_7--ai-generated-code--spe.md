---
source: "common/incident-response.md"
title: "🚨 Incident Response for Developers"
heading: "7. AI-Generated Code: Special Considerations"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, containment, detection, eradication, phases, recovery]
chunk: 16/18
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