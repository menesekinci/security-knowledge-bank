---
source: "common/engineering/incident-response-deep.md"
title: "🔴 Incident Response — Deep Engineering Guide"
heading: "1. IR Philosophy"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, communication, detection, philosophy, practical, signals]
chunk: 2/22
---

## 1. IR Philosophy

### Blameless Culture: Why It Matters

A blameless post-mortem culture is the single highest-leverage investment you can make in incident response. When engineers fear retribution, they hide mistakes, delay disclosure, and destroy evidence. The goal is to find *the root cause*, not *the person*.

**Blameless ≠ No Accountability**

| Blameless | Not Blameless |
|-----------|---------------|
| "The deployment pipeline lacked a canary gate" | "Bob deployed without checking" |
| "The alert threshold was too high" | "Alice ignored the warning" |
| "The runbook didn't cover this case" | "Nobody knew what to do" |
| "Secrets were hardcoded in the config repo" | "Sara committed the key" |

**How to practice blameless analysis:**
1. Assume every action made sense given the information available at the time
2. Ask "what system failure allowed this to happen?" — never "who failed?"
3. Praise the reporter — make it safe to surface problems early
4. Write post-mortems in first-person plural ("we failed to...", "our pipeline...")

### The Five Whys — Root Cause Discovery

The Five Whys is a simple but powerful technique for drilling past symptoms into systemic root causes.

```
SYMPTOM: Production database credentials were exposed in GitHub

Why? → A developer committed a config file containing the password.

Why? → The dev environment used a template that included hardcoded credentials.

Why? → The onboarding documentation told engineers to copy the template without sanitizing secrets.

Why? → There was no process to review or scan onboarding materials for secrets.

Why? → Security team was not involved in developer tooling setup process.

ROOT CAUSE: No security review gate exists for developer tooling and onboarding
             materials. System failure, not individual.
```

### Speed vs. Thoroughness: The Trade-off

In an active incident, you are always trading off between speed (contain the blast radius) and thoroughness (preserve evidence, understand the full scope).

```
                    URGENCY
         ┌─────────────────────────┐
         │     CONTAIN FAST       │  First 15-60 minutes
         │   ┌─────────────────┐ │
         │   │  The Trade-off  │ │
         │   │                 │ │
THOROUGH │   │  Document       │ │  After containment
         │   │  everything     │ │
         │   │  for post-mortem│ │
         │   └─────────────────┘ │
         │     LEARN DEEP        │  Recovery + lessons
         └─────────────────────────┘
                     TIME
```

**Rule of thumb:** First 30 minutes are pure speed. After containment, shift to thoroughness. Never sacrifice containment speed for documentation completeness.

---