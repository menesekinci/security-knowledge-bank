---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "5. Zero Trust for AI-Augmented Systems"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 7/10
---

## 5. Zero Trust for AI-Augmented Systems

AI agents, LLM integrations, and autonomous systems introduce new entities that need Zero Trust treatment. An AI agent is an identity — it needs authentication, authorization, and auditing just like a human or a service account.

### AI Agents as Identities

| Challenge | Zero Trust Response |
|---|---|
| **Agent identity** | Each AI agent gets a unique identity (service account / workload identity) with scoped permissions |
| **Credential management** | Agents authenticate via short-lived tokens, not static API keys |
| **Authorization scope** | Agents have least-privilege access to exactly the tools and data they need — no broader |
| **Continuous verification** | Agent actions are continuously monitored; anomalous behavior triggers re-verification or suspension |
| **Audit trail** | Every agent action is logged with agent identity, human sponsor, and tool used |

### Practical Controls for AI Agents

**1. Tool-level authorization**

An AI coding agent should have read access to the source repo but write access only to a specific branch. It should not have access to production secrets, even if the engineer operating it does.

```yaml
# AI agent policy
agent: code-reviewer-bot
permissions:
  - resource: github.com/myorg/myrepo
    actions: [read:code, read:issues]
    scope: all-branches
  - resource: github.com/myorg/myrepo
    actions: [write:code, create:pr]
    scope: feature-branches-only
  - resource: vault.prod.internal
    actions: []  # Explicitly denied
```

**2. Human-in-the-loop for high-risk actions**

AI agents should be able to request access to sensitive operations, but approval should require a human with appropriate privileges.

```
Agent → "Write deployment manifest for prod"
   ↓
Policy Engine → Requires human-in-the-loop approval
   ↓
Senior engineer approves (or denies)
   ↓
Agent executes with time-limited, operation-scoped credentials
```

**3. Context-aware rate limiting**

AI agents can be highly automated and fast — limiting their blast radius means limiting their velocity. Apply per-agent rate limits and concurrency limits.

### Zero Trust for Model Access

If your system uses an LLM or other ML model, the model itself (and its training data) are assets that need protection:

- **Model access** — who can invoke the model? Is it behind an identity-aware proxy?
- **Training data** — is it encrypted at rest? Are access logs reviewed?
- **Model weights** — are proprietary weights protected like source code?
- **Model output** — could an attacker extract training data via prompt injection? (Apply inference-time privacy controls)

---