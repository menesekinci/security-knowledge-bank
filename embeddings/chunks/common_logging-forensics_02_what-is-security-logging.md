---
source: "common/logging-forensics.md"
title: "Security Logging & Forensics — Audit Trails, SIEM, Log Injection, GDPR"
heading: "What Is Security Logging?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [categories, checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 2/8
---

## What Is Security Logging?

Security logging is the practice of recording security-relevant events in a system to enable **detection**, **investigation**, and **recovery** from security incidents. Without proper logging, attacks go undetected, forensic analysis is impossible, and compliance requirements (GDPR, SOC 2, PCI DSS, HIPAA) cannot be met.

**The problem:** Most applications log too little (missing critical security events), log incorrectly (no context, no structure), or log dangerously (injectable data, sensitive information).

### What Should Be Logged

| Event Type | Examples | Priority |
|------------|----------|----------|
| **Authentication** | Login success/failure, password changes, MFA events | 🔴 Critical |
| **Authorization** | Access denied, privilege escalation, role changes | 🔴 Critical |
| **Data Access** | Read/write of sensitive data, export operations | 🟠 High |
| **Input Validation** | SQL injection attempts, XSS payloads, invalid input | 🟠 High |
| **Configuration Changes** | Admin settings, firewall rules, user permission changes | 🟠 High |
| **System Events** | Service restarts, errors, crashes, resource exhaustion | 🟡 Medium |
| **API Calls** | Endpoint access, rate limiting, unusual patterns | 🟡 Medium |
| **Network Events** | Connection attempts, DNS lookups, proxy decisions | 🟡 Medium |

---