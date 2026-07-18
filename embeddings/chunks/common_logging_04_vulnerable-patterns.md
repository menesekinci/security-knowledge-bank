---
source: "common/logging.md"
title: "Logging & Monitoring Failures"
heading: "Vulnerable Patterns"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, common-vuln, logging, patterns, prevention, secure, vibe, vulnerable, what]
chunk: 4/8
---

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