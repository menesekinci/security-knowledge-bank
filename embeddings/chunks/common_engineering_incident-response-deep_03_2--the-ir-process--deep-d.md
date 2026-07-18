---
source: "common/engineering/incident-response-deep.md"
title: "🔴 Incident Response — Deep Engineering Guide"
heading: "2. The IR Process (Deep Dive)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, communication, detection, philosophy, practical, signals]
chunk: 3/22
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