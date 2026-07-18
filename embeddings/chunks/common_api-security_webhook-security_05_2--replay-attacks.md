---
source: "common/api-security/webhook-security.md"
title: "Webhook Security"
heading: "2. Replay Attacks"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, bombing, overview, replay, retry, signature, table, verification]
chunk: 5/9
---

## 2. Replay Attacks

A replay attack occurs when an attacker intercepts a valid signed webhook payload and re-sends it. Even with valid signatures, the replayed event can trigger duplicate processing (duplicate charges, account updates, etc.).

### Vulnerable Code (No Replay Protection)

```python
# VULNERABLE: No replay protection — same webhook can be replayed
def webhook_handler(request):
    payload = request.json
    # If attacker replays this exact payload, it's processed again!
    process_payment(payload['order_id'], payload['amount'])
    return 'OK', 200
```

### Secure Code (Timestamp + Nonce Replay Protection)

```python
# SECURE: Replay protection with timestamp tolerance and idempotency key
import time
import hashlib
import os
from datetime import datetime, timedelta

# Store processed webhook IDs (in production, use Redis with TTL)
PROCESSED_WEBHOOKS = set()
MAX_AGE_MINUTES = 5

def verify_timestamp(timestamp_str):
    """Verify webhook timestamp is within tolerance window."""
    try:
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        age = datetime.now().astimezone() - timestamp
        return abs(age) < timedelta(minutes=MAX_AGE_MINUTES)
    except (ValueError, TypeError):
        return False

def is_idempotent(webhook_id):
    """Check if webhook has already been processed."""
    if webhook_id in PROCESSED_WEBHOOKS:
        return False
    PROCESSED_WEBHOOKS.add(webhook_id)
    # In production: redis.setex(webhook_id, 3600, 'processed')
    return True

@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.json
    webhook_id = payload.get('id')
    timestamp = payload.get('created')
    
    # 1. Verify signature
    signature = request.headers.get('Stripe-Signature')
    if not verify_signature(request.get_data(), signature):
        return 'Invalid signature', 403
    
    # 2. Reject old webhooks (replay protection)
    if not verify_timestamp(timestamp):
        return 'Timestamp expired', 403
    
    # 3. Check idempotency
    if not is_idempotent(webhook_id):
        return 'Already processed', 200  # OK, already done
    
    process_event(payload)
    return 'OK', 200
```

---