---
source: "common/engineering/secrets-management.md"
title: "Secrets Management Engineering Guide"
heading: "6. Secret Detection"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [anti-patterns, common, common-vuln, counts, encryption, management, rotation, secret, secrets, what]
chunk: 7/8
---

## 6. Secret Detection

### 6.1 Tools

| Tool | Approach | Best For |
|---|---|---|
| **truffleHog** | Scans git history for high-entropy strings (shannon entropy). Finds secrets that regex might miss. | Deep git history scanning, finding secrets that don't match a known pattern |
| **Gitleaks** | Regex + entropy — supports hundreds of built-in rules (AWS keys, GitHub tokens, Slack tokens). | CI/CD integration, blocking PRs with secrets |
| **git-secrets** | Pre-commit hooks + git history scanning. Prevents patterns, not entropy. | Simple, lightweight git-native approach |
| **Secret scanner (GitHub Advanced Security)** | Native GitHub scanning on push and history. Automatically alerts repo admins. | GitHub-hosted repos with GHAS license |
| **Detect Secrets (Yelp)** | Custom rules via regex, entropy, and path/file-type allowlists. | Highly customized scanning pipelines |
| **Trivy** | Vulnerability scanner — also detects hardcoded secrets in filesystem and container images. | Container image scanning, IaC scanning |

### 6.2 Pre-Commit Hooks vs. CI Scanning

| Approach | Timing | Pros | Cons |
|---|---|---|---|
| **Pre-commit hook** | Before the commit is created | Catches secrets before they enter history — **no record to clean up** | Bypassable (`git commit --no-verify`), not enforceable on all developers |
| **Pre-receive hook (server-side)** | After `git push`, before the server accepts | Cannot be bypassed by developers; enforced on all pushes | Must be configured on the git server (GitHub/GitLab/Bitbucket) |
| **CI scan (PR stage)** | After push, on pull request | Catches secrets in PRs; automated blocking; integrates with code review | Secret is already in the remote branch (retracted push still leaves a trace) |
| **Scheduled scan** | Daily/weekly full history scan | Catches secrets that bypassed other checks | Post-facto — secret has been in history for hours or days |

**Recommended stack:**
1. **Pre-commit hook** (truffleHog or Gitleaks with `protect` mode) — stops 90% of accidental commits.
2. **CI scan** (Gitleaks on PRs) — catches the 10% that bypassed pre-commit (`--no-verify`).
3. **Scheduled scan** (truffleHog on full git history weekly) — catches anything missed and monitors for historical leaks.
4. **Alert on push** (GitHub push protection) — real-time alerting for known secret patterns.

### 6.3 Incident Response for Leaked Secrets

If you discover a secret has been leaked:

**Immediate (within 1 hour):**
1. **Rotate the secret** — generate a new one and update all legitimate consumers. Do not wait for investigation.
2. **Revoke the leaked secret** — invalidate it at the source (cloud IAM, vendor portal, database user).
3. **Assess exposure window** — when was the commit made? When was it pushed? Who has access to the repo?

**Investigation (within 24 hours):**
4. **Check access logs** — was the leaked secret used to access any resource between the commit and revocation? Cloud provider logs (CloudTrail, audit logs) show API calls made with that credential.
5. **Check downstream clones** — if the repo is public or has many forks, the secret is compromised widely. Assume the worst.
6. **Determine root cause** — was it a developer mistake, CI misconfiguration, or a targeted attack?

**Remediation (within 1 week):**
7. **Remove the secret from git history** — use `git-filter-repo` or BFG Repo-Cleaner. Note: this rewrites history and impacts all collaborators. Coordinate carefully.
8. **Enforce additional controls** — add pre-commit hooks, enhance CI scanning, restrict repo permissions.
9. **Update incident timeline** — include in postmortem and update the risk register.

**Key principle:** Rotating the secret is non-negotiable. Even if you think no one used it, rotate. Assume the worst — the cost of a false alarm is a single credential rotation; the cost of not rotating is a breach.

---