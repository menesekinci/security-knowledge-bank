# Logging & Monitoring Failures

**CWE:** CWE-778 (Missing Logging), CWE-223 (Omission of Security-relevant Information)
**OWASP Top 10:2021:** A09 — Security Logging and Monitoring Failures

---

## What Are Logging & Monitoring Failures?

This encompasses insufficient logging, missing monitoring, and logging sensitive data. Without proper logging and monitoring, **breaches go undetected** for months (average is 212 days!). Even worse, some breaches are discovered by external researchers, not the affected organization's own monitoring.

## Why Vibe Coding Makes This Worse

- **AI doesn't generate logging code:** Focused on business logic, AI skips `logger.info()` calls for security events
- **AI logs sensitive data:** `logger.error(f"Login failed for {password}")` — leaking secrets to logs
- **No centralized logging:** AI outputs to stdout/console without structured logging
- **Missing alerting:** AI generates logs but no infrastructure for alerting on suspicious patterns
- **Verbose error handling:** AI returns stack traces in HTTP responses instead of logging them internally

## Vulnerable Patterns

### Missing Security Event Logging

```javascript
// 🔴 VULNERABLE: security events not logged
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await authenticate(username, password);
    if (!user) {
        // No log entry for failed login!
        return res.status(401).send('Failed');
    }
    req.session.userId = user.id;
    res.send('OK');
});
```

### Logging Sensitive Data

```python
import logging

# 🔴 VULNERABLE: logging sensitive data
logging.basicConfig(level=logging.INFO)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']  # 🔴 NEVER LOG THIS
    logging.info(f"Login attempt for {username} with password {password}")

    result = authenticate(username, password)
    logging.info(f"Login result for {username}: {result}")
    # Logs end up in: log files, log aggregation (Splunk/ELK), SIEM
    # Anyone with log access sees plaintext passwords!
```

## Secure Logging Patterns

### Structured JSON Logging

```javascript
// ✅ SECURE: structured JSON logging
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'user-service' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

app.post('/login', async (req, res) => {
    const { username } = req.body;

    const result = await authenticate(username, req.body.password);
    if (!result) {
        // ✅ Log authentication failure (without password)
        logger.warn('Authentication failed', {
            event: 'LOGIN_FAILED',
            username,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            timestamp: new Date().toISOString()
        });
        return res.status(401).send('Failed');
    }

    logger.info('Authentication succeeded', {
        event: 'LOGIN_SUCCESS',
        userId: result.user.id,
        username,
        ip: req.ip,
        timestamp: new Date().toISOString()
    });
    req.session.userId = result.user.id;
    res.send('OK');
});
```

### Python Structured Logging

```python
import logging
import json

# ✅ SECURE: structured logging with sensitive data filtered
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        # Mask sensitive fields in logs
        if hasattr(record, 'password'):
            record.password = '***REDACTED***'
        if hasattr(record, 'credit_card'):
            record.credit_card = record.credit_card[-4:]
        return True

logger = logging.getLogger('app')
logger.addFilter(SensitiveDataFilter())

# Use structured logging
import structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

@app.route('/payment', methods=['POST'])
def payment():
    # Log what happened, not the sensitive data
    logger.info("payment_processed",
                user_id=session['user_id'],
                amount=request.json['amount'],
                # ✅ Don't log: credit_card, cvv, billing_address
                card_last4=request.json['card_number'][-4:])
```

### What Security Events Should Be Logged

| Event | Log Level | Required Fields |
|---|---|---|
| Login success | INFO | userId, IP, timestamp, sessionId |
| Login failure | WARN | username, IP, timestamp, reason |
| Password change | INFO | userId, IP, timestamp |
| Account lockout | WARN | username, IP, timestamp |
| Permission denied | WARN | userId, resource, action, IP |
| Data export | INFO | userId, records count, IP |
| Admin action | INFO | adminId, action, target, IP |
| Error/Exception | ERROR | stack trace, userId, IP, requestId |
| Rate limit hit | WARN | userId/IP, endpoint, timestamp |
| Suspicious input | WARN | input sample, IP, endpoint |

### Preventing Log Injection (Log Forging)

Attackers can inject new log entries to confuse investigators:

```javascript
// 🔴 VULNERABLE: log injection
const userInput = req.body.username;  // "user\n[INFO] Login successful: admin"
logger.info(`Login attempt for: ${userInput}`);
// Log file shows: Login attempt for: user
//                   [INFO] Login successful: admin    ← FAKE!
```

```javascript
// ✅ SAFE: sanitize log output
function sanitizeForLog(input) {
    return input.replace(/[\n\r\t]/g, ' ');  // Remove newlines/tabs
}

logger.info(`Login attempt for: ${sanitizeForLog(userInput)}`);
```

---

## Prevention Checklist for AI Prompts

```
✅ LOGGING & MONITORING REQUIREMENTS:
- Log ALL authentication events (success, failure, password changes)
- Log authorization failures (access denied to resources)
- Log all administrative actions with actor details
- NEVER log passwords, credit cards, secrets, or session tokens
- NEVER log full request bodies or stack traces in production responses
- Use structured logging (JSON) — not plain text
- Include correlation IDs (requestId, sessionId) in every log entry
- Set up real-time alerting on security events (failed logins > 5/min)
- Implement immutable logging (write-once, append-only storage)
- Sanitize user input in log messages to prevent log injection
- Use a SIEM or log aggregation tool (ELK, Splunk, Datadog)
- Test that your alerting actually works (fire drills)
- Ensure logs have proper access controls — don't expose them publicly
```

### Monitoring Alert Thresholds

| Alert | Threshold | Severity |
|---|---|---|
| Failed logins | > 5 in 5 min from same IP | High |
| Account enumeration | > 10 different usernames from same IP | Medium |
| Brute force | > 50 failed logins in 1 hour | Critical |
| API key misuse | > 100 4xx in 5 min | High |
| Suspicious geolocation | Login from 2+ countries in 1 hour | High |
| SQL injection attempt | SQL keywords in URL params | Critical |

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Target data breach | N/A | No monitoring of mallware on POS systems — 40M CCs stolen |
| Equifax breach | N/A | Missed logging on unpatched Struts server — 147M records |
| SolarWinds Orion | CVE-2021-35215 | Authenticated insecure deserialization → RCE in Orion Platform (CWE-502); the wider SolarWinds intrusion also featured attackers tampering with logs to evade detection |
| Capital One | N/A (no CVE) | SSRF (WAF misconfiguration) reached the AWS instance-metadata service; no alerting on the anomalous access — 100M records exfiltrated |

> **The Target breach example:** Attackers installed malware on POS systems. The security team had SIEM alerts firing, but no one was monitoring at 2 AM. 40M credit card numbers stolen over 11 days.

---

## References

- [OWASP A09:2021 — Logging and Monitoring Failures](https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Application Logging Vocabulary](https://owasp.org/www-project-application-logging-vocabulary/)
- [CWE-778: Missing Logging](https://cwe.mitre.org/data/definitions/778.html)
