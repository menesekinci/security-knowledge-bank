---
source: "common/api-security/webhook-security.md"
title: "Webhook Security"
heading: "3. Retry Bombing & Amplification"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, bombing, overview, replay, retry, signature, table, verification]
chunk: 6/9
---

## 3. Retry Bombing & Amplification

Webhook senders typically retry on failure (e.g., 5xx, timeout). Retry bombing exploits this:

- **Amplification**: Small trigger event causes many retry requests
- **Retry storm**: Malicious slow response causes exponential backoff flood
- **Endpoint exhaustion**: Attacker triggers events that hit your slowest endpoint

### Vulnerable Code (Slow Webhook Processing)

```python
# VULNERABLE: Slow handler causes sender to retry, amplifying load
@app.route('/webhooks/slack', methods=['POST'])
def slack_webhook():
    # Slow processing causes sender to retry
    result = call_external_slow_api(request.json)  # Could take 30s
    return process_result(result)
```

### Secure Code (Fast ACK + Queue)

```python
# SECURE: Fast acknowledgment with async queue processing
import queue
import threading

webhook_queue = queue.Queue()

def webhook_worker():
    """Background worker processes webhooks from queue."""
    while True:
        payload = webhook_queue.get()
        try:
            process_webhook_slow(payload)  # Slow processing here
        except Exception as e:
            log_error(e)
        finally:
            webhook_queue.task_done()

# Start worker thread
threading.Thread(target=webhook_worker, daemon=True).start()

@app.route('/webhooks/slack', methods=['POST'])
def slack_webhook():
    signature = request.headers.get('X-Slack-Signature')
    
    if not verify_signature(request.get_data(), signature):
        return 'Invalid signature', 403
    
    # Acknowledge immediately — sender won't retry
    webhook_queue.put(request.json)
    return 'Accepted', 202  # Fast response
```

### Rate-Limit Webhook Processing

```python
# SECURE: Rate limit webhook processing per source
from collections import defaultdict
from datetime import datetime, timedelta

class WebhookRateLimiter:
    def __init__(self, max_per_minute=60):
        self.max_per_minute = max_per_minute
        self.counts = defaultdict(list)
    
    def allow(self, source_ip):
        now = datetime.now()
        window_start = now - timedelta(minutes=1)
        
        # Clean old entries
        self.counts[source_ip] = [
            t for t in self.counts[source_ip] if t > window_start
        ]
        
        if len(self.counts[source_ip]) >= self.max_per_minute:
            return False
        
        self.counts[source_ip].append(now)
        return True

rate_limiter = WebhookRateLimiter(max_per_minute=100)

@app.route('/webhooks/generic', methods=['POST'])
def generic_webhook():
    if not rate_limiter.allow(request.remote_addr):
        return 'Rate limit exceeded', 429
    # ... process webhook ...
```

---