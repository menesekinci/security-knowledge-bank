---
source: "common/logging.md"
title: "Logging & Monitoring Failures"
heading: "Secure Logging Patterns"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, logging, patterns, prevention, secure, vibe, vulnerable, what]
chunk: 5/8
---

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