---
source: "common/engineering/incident-response-deep.md"
title: "🔴 Incident Response — Deep Engineering Guide"
heading: "4. Practical IR for Startups"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, communication, detection, philosophy, practical, signals]
chunk: 5/22
---

## 4. Practical IR for Startups

Startups don't have a 24/7 SOC, dedicated IR team, or six-figure tooling. What matters most is having the right *capabilities*, not the right *headcount*.

### What Matters Most (In Order)

1. **Access to logs** — You cannot respond to what you cannot see. Prioritize centralized logging before any other IR investment.
2. **A single runbook** — One-page playbook for "what do I do when the alert fires?" Better than 50 detailed runbooks nobody reads.
3. **Credential rotation automation** — Script or tool to rotate all cloud keys, API tokens, and database passwords in under 5 minutes.
4. **Notification tree** — Who calls who, in what order, and what's the fallback. Print it out. Tape it to the wall.
5. **Image snapshots** — Automated daily snapshots of critical instances. Immutable backups with 30-day retention.
6. **A post-mortem habit** — Every incident gets a post-mortem, even if it's 5 bullet points in a shared doc.

### Runbook Template

```markdown
# 🚨 Incident Runbook: <Incident Type>