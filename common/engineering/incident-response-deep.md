# 🔴 Incident Response — Deep Engineering Guide

> **Category:** Common / Engineering
> **Last Updated:** July 2026
> **Description:** In-depth incident response guidance for security engineers — philosophy, advanced process, communication, startup practicality, and incident classification. This is a deeper companion to the [Developer IR Guide](../incident-response.md). Read that first for the tactical runbook.

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

## 2. The IR Process (Deep Dive)

### 2.1 Preparation

Preparation is the phase that determines whether an incident response will be effective. It's also the most commonly neglected.

**Runbook requirements:**
- Every runbook must answer: *What does this look like?* (symptoms), *Who do I call?* (escalation), *What do I do?* (step-by-step), *What do I NOT do?* (anti-patterns)
- Runbooks should fit in a single terminal pane (~40 lines)
- Test runbooks in tabletop exercises every quarter

**Tooling checklist:**
- [ ] Centralized logging (SIEM or log aggregation): Elastic, Splunk, Loki
- [ ] Endpoint detection and response (EDR): CrowdStrike, SentinelOne, Wazuh
- [ ] Cloud-native detection: GuardDuty, Security Command Center, Azure Sentinel
- [ ] Incident tracking: Jira, ServiceNow, TheHive
- [ ] Communication: Slack/PagerDuty with dedicated incident channels
- [ ] Evidence collection: tooling for memory capture (LiME), disk imaging (dd), packet capture (tcpdump)
- [ ] Backup verification: tested restore process, offline/immutable backups

### 2.2 Detection

Detection is about reducing MTTD (Mean Time to Detect). The faster you detect, the less damage an attacker can do.

**Detection layers (defense in depth):**

| Layer | Detection Mechanism | Typical MTTD |
|-------|-------------------|--------------|
| **L1 — Infrastructure** | Cloud trail, network flow logs, VPC flow logs | Minutes to hours |
| **L2 — Host** | EDR agents, syslog, auditd | Seconds to minutes |
| **L3 — Application** | WAF, API gateway logs, app-level audit | Sub-second to seconds |
| **L4 — Identity** | IAM anomaly detection, failed auth patterns | Minutes |
| **L5 — Data** | DLP alerts, database audit logs, S3 access logs | Hours to days |
| **L6 — Human** | Bug reports, user complaints, dark web intel | Days to weeks |

**Anomaly detection signals that matter:**
- Unusual geographic origin of admin logins
- API key used from an unexpected service/user agent
- Spike in 403/401 responses followed by 200s (credential stuffing success)
- First-time execution of `kubectl exec` or `aws s3 cp` in prod
- Outbound network connections to known-bad IPs or new domains
- Database query volume spike (potential data exfiltration)

### 2.3 Triage

Triage is the most cognitively demanding phase — you have incomplete information and must make high-stakes decisions quickly.

**Triage questions (answer in order):**
1. Is this real? (False positive vs. genuine incident)
2. Is this active? (Still happening or post-factum detection)
3. What's the blast radius? (Systems, data, users affected)
4. What's the access level? (Read, write, admin, root)
5. Is there evidence of lateral movement?
6. What's the sensitivity of data accessed?
7. Can we contain without disrupting business operations?

**The Triage Matrix:**

```
                 ┌─────────┬──────────────────────────────────┐
                 │         │         CONTAINMENT EFFORT        │
                 │         ├─────────────┬────────────────────┤
                 │         │   High      │     Low             │
                 ├─────────┼─────────────┼────────────────────┤
                 │  High   │  CONTAIN    │  MONITOR CLOSELY    │
                 │         │  IMMEDIATELY│  + prep containment │
                 │BLAST    ├─────────────┼────────────────────┤
                 │RADIUS   │  CONTAIN    │  LOG AND TRACK      │
                 │         │  WITHIN     │  (low urgency)      │
                 │  Low    │  BUSINESS   │                     │
                 │         │  HOURS      │                     │
                 └─────────┴─────────────┴────────────────────┘
```

### 2.4 Containment

Containment is about *stopping the bleed* — preventing the attacker from causing more damage or exfiltrating more data.

**Containment strategies by scenario:**

| Scenario | Immediate Containment | Long-Term Containment |
|----------|-----------------------|-----------------------|
| **Compromised web server** | Remove from LB, block egress at firewall | Replace instance, analyze root cause |
| **Exposed S3 bucket** | Block public access, rotate all data keys | Full audit, add SCP to prevent recurrence |
| **Malware / ransomware** | Network isolate, take disk snapshot before shutdown | Rebuild from trusted image, scan network for spread |
| **Compromised user account** | Force password reset, revoke sessions, disable keys | MFA enforcement, review recent actions |
| **Data exfiltration in progress** | Block outbound IP/domain at firewall, rate-limit API | Identify exfiltrated data, notify DPO if PII |
| **Supply chain compromise** | Pin safe versions, block malicious packages, rebuild all images | Audit all builds for the affected scope |

**Evidence preservation (critical):**
- Take memory capture BEFORE killing processes or rebooting
- Preserve system logs (journalctl, /var/log, Windows Event Logs)
- Save network flow data for the incident window
- Record exact timestamps of each containment action
- Do NOT delete or modify files on compromised systems until forensics is complete

### 2.5 Eradication

Eradication is removing the threat completely from your environment. Containment buys you time; eradication buys you safety.

**Eradication depth:**
1. **Surface** — Remove the known bad (malware files, backdoors, malicious IAM roles)
2. **Deep** — Audit all systems the attacker may have touched (lateral movement)
3. **Systemic** — Fix the vulnerability or misconfiguration that allowed initial access

**Common eradication pitfalls:**
- Only cleaning the system where the alert fired (attacker has likely moved laterally)
- Rotating credentials but not revoking existing sessions or tokens
- Patching the symptom but not the root cause (e.g., blocking an IP instead of fixing SSRF)
- Not checking for persistence mechanisms (cron jobs, service installations, startup scripts, K8s CronJobs)

### 2.6 Recovery

Recovery is about restoring normal operations with confidence that the threat is gone.

**Recovery gates (must all pass before returning to production):**
1. ☐ All affected systems have been eradicated and rebuilt from trusted sources
2. ☐ Compromised credentials rotated and verified
3. ☐ Patches applied to fix root cause
4. ☐ Security monitoring enhanced to detect re-attempt
5. ☐ Staged rollout complete (canary → 10% → 50% → 100%)
6. ☐ Rollback plan documented and ready
7. ☐ Business owners have approved return to service

**Recovery monitoring (post-incident observation period):**
- 24h: Every 4-hour check on key security metrics
- 48h: Daily incident-specific monitoring
- 7d: Weekly review, hand off to normal SOC operations

### 2.7 Lessons Learned

The post-mortem is the most valuable phase — it's where you invest in preventing the next incident.

**Elements of an effective post-mortem:**
1. **Timeline** — Single source of truth for what happened, when
2. **Causal analysis** — Why it happened (Five Whys or similar)
3. **Impact assessment** — What was affected (data, users, revenue, reputation)
4. **Detection gaps** — Why wasn't this caught earlier?
5. **Process failures** — Where did the process break down?
6. **Action items** — Specific, owner-assigned, deadline-driven fixes
7. **Metrics** — TTD, TTC, TTR (see [Security Metrics](security-metrics.md))

**Post-mortem do's and don'ts:**

| ✅ Do | ❌ Don't |
|-------|----------|
| Focus on systems and processes | Blame individuals |
| Include all relevant parties in review | Let it be driven by leadership only |
| Create specific, measurable action items | Write vague "improve visibility" items |
| Share openly (anonymized if needed) | Keep it a secret "for compliance reasons" |
| Track action items to completion | File the post-mortem and never look at it again |

---

## 3. Communication

### Internal Communication

During an incident, communication must be precise, timely, and documented.

**Communication roles:**

| Role | Responsibility | Who |
|------|---------------|-----|
| **Incident Commander (IC)** | Single decision-maker, coordinates all actions | Security lead or SRE on call |
| **Scribe** | Documents timeline, decisions, and actions | Rotating engineering role |
| **Subject Matter Experts (SMEs)** | Technical investigation and remediation | Engineers from affected teams |
| **Liaison** | Communication bridge to execs, legal, PR | Engineering manager or PM |

**Incident communication channels:**
- **Dedicated Slack channel** — `#incident-<id>` — all technical discussion
- **Bridge call / Zoom** — For IC, SMEs, scribe (real-time coordination)
- **Status page** — Customer-facing updates (for external incidents)

**Communication cadence:**
```
ONGOING INCIDENT ─── STATUS UPDATES ─────────────────────────────
│
├── Every 30 min (Critical) / 60 min (High)
│   └── IC brief to stakeholders via Slack thread or email
│
├── Every update includes:
│   ├── Current status (Active / Contained / Recovering)
│   ├── What we know (facts only, no speculation)
│   ├── What we're doing (current containment/remediation)
│   ├── What we need (cross-team help, approvals)
│   └── ETA for next update
│
└── Keep the scribe timeline updated after every action
```

### External Communication

**When to notify externally:**
- Customer data has been accessed or exfiltrated
- Service is degraded or unavailable due to security incident
- Regulatory requirement triggered (GDPR 72h, CCPA, PCI-DSS)
- Attacker has publicly claimed responsibility

**External notification tiers:**

| Tier | Audience | Content | Channel |
|------|----------|---------|---------|
| **T1** | All customers | Service degradation only | Status page |
| **T2** | Affected customers only | Data incident, remediation steps | Email + direct notification |
| **T3** | Regulatory bodies | Breach notification per regulation | Formal breach report |
| **T4** | Public / press | Major breach with public impact | Press release, blog post |

### Regulatory Disclosure Requirements

| Regulation | Notification Trigger | Timeline | Method |
|-----------|---------------------|----------|--------|
| **GDPR** | Personal data breach | Within 72 hours of awareness | Email + supervisory authority |
| **CCPA/CPRA** | Unauthorized access to PII | No specific timeline, "without unreasonable delay" | Email, mail, or account notification |
| **PCI-DSS** | Account data compromise (CDE) | ASAP, within 24 hours for acquiring banks | Formal incident report to acquirer |
| **HIPAA** | Breach of unsecured PHI | Within 60 days of discovery | Email or mail + HHS notification |
| **SOC 2** | Security incident affecting controls | Per contractual SLA (typically 48–72h) | Incident report to customers |

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

## 1. Detection Signals
- Signal A: <what to look for>
- Signal B: <what to look for>
- False positive check: <how to verify it's real>

## 2. Triage
- [ ] Is this real? (check [ ])
- [ ] Is this active?
- [ ] Severity: <SEV-1/2/3/4>
- [ ] Notify: <who to page>

## 3. Containment Steps
```
Step 1: <action>
Step 2: <action>
Step 3: <action>
```

## 4. Evidence to Collect
- [ ] Logs from <source>
- [ ] Instance snapshot
- [ ] Network capture

## 5. Eradication
- [ ] <step>
- [ ] <step>

## 6. Recovery
- [ ] <gate 1>
- [ ] <gate 2>

## 7. Post-Mortem Template
- Incident ID:
- Detection time:
- Containment time:
- Root cause:
- Action items:
```

### Post-Mortem Template (Startup-Friendly)

```markdown
# Post-Mortem: INC-<YYYY>-<NNN>

**Summary:** <one sentence>
**Date:** YYYY-MM-DD
**Severity:** SEV-X
**MTTD:** <time>
**MTTC:** <time>
**MTTR:** <time>

## Timeline
| Time (UTC) | Event |
|------------|-------|
| HH:MM | Detection |
| HH:MM | Triage |
| HH:MM | Containment |
| HH:MM | Eradication |
| HH:MM | Recovery |

## Root Cause (Five Whys)
1. What happened?
2. Why did it happen?
3. Why was that?
4. Why?
5. Why? (Systemic root cause)

## Impact
- Systems affected:
- Data affected:
- Users affected:
- Revenue impact:

## What We Did Well
- 

## What We'd Do Differently
- 

## Action Items
| # | Item | Owner | Due |
|---|------|-------|-----|
| 1 | | | |

## Detection Gap
- Why wasn't this caught by existing monitoring?
```

---

## 5. Incident Classification

### SEV-1 Through SEV-4 Definitions

| Severity | Label | Description | Response Time | SLA | Examples |
|----------|-------|-------------|---------------|-----|----------|
| **SEV-1** | 🔴 Critical | Active data breach, RCE in production, complete service loss due to security event | < 15 min | 24/7 | Attacker exfiltrating database, ransomware encrypting prod servers |
| **SEV-2** | 🟠 High | Confirmed vulnerability with exploit potential, partial service compromise, credentials leaked | < 60 min | Business hours + on-call escalation | PII exposed but not exfiltrated, AWS key committed to public repo |
| **SEV-3** | 🟡 Medium | Unconfirmed potential incident, non-critical misconfiguration, dependency with CVE | < 4 hours | Business hours | Suspicious login pattern, S3 bucket possibly public, Log4j in dependency tree |
| **SEV-4** | 🟢 Low | Low-risk finding, policy violation with no evidence of exploitation | < 1 week | Next business day | Unused IAM key, missing audit log, TLS version too old |

### Escalation Paths

```
SEV-1 ──────────────────────────────────────────────────────────
│  IC: Head of Security or CISO
│  SMEs: All engineering leads, on-call SRE
│  Exec: CTO / CEO notified
│  Legal: GC notified for data incidents
│  Communication: Every 30-min status to exec team
│
├── SEV-2 ─────────────────────────────────────────────────────
│   IC: Security lead or senior SRE
│   SMEs: Affected team's lead engineer
│   Exec: Engineering manager notified
│   Communication: Hourly status update
│
├── SEV-3 ─────────────────────────────────────────────────────
│   IC: Security engineer on call
│   SMEs: On-call developer for the affected service
│   Communication: Daily update during resolution
│
└── SEV-4 ─────────────────────────────────────────────────────
    IC: Security engineer
    Action: Logged as ticket, assigned to sprint
    Communication: Not required
```

### Escalation Rules

- **Auto-escalate** if active containment not completed within SLA for the current SEV level
- **Any responder can escalate** — no permission needed to bump SEV level
- **De-escalation** requires IC + next-level manager approval
- **Time-based escalation:** If SEV-1 not contained in 1 hour, auto-escalate to CISO/CEO

---

## 6. Incident Response Maturity Model

| Level | Label | Characteristics |
|-------|-------|-----------------|
| **L1 — Initial** | Ad-hoc | No formal process, hero-based, post-mortems rare or absent |
| **L2 — Repeatable** | Basic process | Runbooks exist but outdated, some tooling, IC designated per incident |
| **L3 — Defined** | Standardized | Runbooks current and tested, tooling integrated, post-mortems routine |
| **L4 — Measured** | Data-driven | MTTD/MTTC/MTTR tracked, trend analysis, budget for improvements |
| **L5 — Optimizing** | Continuous improvement | Automated containment, proactive threat hunting, cross-team tabletop exercises |

---

## 7. References

- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [Google SRE Book — Managing Incidents](https://sre.google/sre-book/managing-incidents/)
- [AWS Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [PagerDuty Incident Response Docs](https://response.pagerduty.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [FIRST CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Incident Response Playbook](https://owasp.org/www-project-incident-response-playbook/)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [GDPR Breach Notification Requirements](https://gdpr-info.eu/art-33-gdpr/)
- [CISA Incident Response Playbook](https://www.cisa.gov/resources-tools/resources/incident-response-playbook)
