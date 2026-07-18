---
source: "common/api-security/webhook-security.md"
title: "Webhook Security"
heading: "5. CVEs & Real-World Examples"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, bombing, overview, replay, retry, signature, table, verification]
chunk: 8/9
---

## 5. CVEs & Real-World Examples

### GitHub Webhook Secret Exposure (2024)
- **Description**: A GitHub bug exposed webhook secrets to recipient endpoints via response headers. Attackers could read secrets by monitoring webhook delivery responses. The vulnerability affected GitHub.com webhook delivery infrastructure
- **Impact**: Webhook secrets for thousands of repositories potentially leaked
- **Fix**: GitHub rotated affected secrets; recipients advised to rotate secrets
- **Source**: https://exploitr.com/articles/alert-github-bug-exposed-webhook-secrets-to-recipient-endpoints/

### CVE-2025-30066 — GitHub Actions tj-actions/changed-files Supply Chain Attack
- **Description**: In March 2025, the popular GitHub Action `tj-actions/changed-files` was compromised in a supply chain attack. The attacker modified the action to exfiltrate CI/CD secrets (including webhook secrets and deployment keys) from workflow logs
- **Impact**: 23,000+ repositories potentially exposed secrets
- **CVSS**: 9.1 (Critical)
- **Fix**: Rotate all secrets exposed in CI; audit workflow logs for leaked secrets; pin actions by commit hash, not version tag
- **Source**: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066

### MOVEit Webhook Input Validation (2024)
- **Description**: The 2024 MOVEit vulnerability exploited insufficient input validation in webhook handlers, affecting over 2,000 organizations. Attackers sent crafted webhook payloads that triggered SQL injection in the receiving server
- **Affected**: Progress MOVEit Transfer
- **CVSS**: 9.8 (Critical)
- **Fix**: Input validation on all webhook payloads; parameterized queries in handlers
- **Source**: https://www.apisec.ai/blog/securing-webhook-endpoints-best-practices

### Stripe Webhook Replay Attack Pattern (Common Bug Bounty Finding)
- **Description**: Multiple bug bounty reports highlight Stripe webhook integrations that fail to check `created` timestamps or maintain idempotency, allowing attackers to replay old payment webhooks
- **Fix**: Implement timestamp verification (±5 minute tolerance) and always use the webhook ID for idempotency checks
- **Source**: https://stripe.com/docs/webhooks

### Webhook Secret Rotation Negligence (Industry Pattern)
- **Description**: Studies of 100+ SaaS webhook implementations found that 68% had never rotated their webhook signing secrets, and 23% still used example or default secrets from documentation
- **Fix**: Mandate secret rotation every 90 days; use separate secrets per integration
- **Source**: https://www.obsidiansecurity.com/blog/what-is-webhook-security-securing-saas-integrations-2026

---