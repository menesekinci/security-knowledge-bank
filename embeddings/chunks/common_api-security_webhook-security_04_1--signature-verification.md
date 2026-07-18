---
source: "common/api-security/webhook-security.md"
title: "Webhook Security"
heading: "1. Signature Verification"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, bombing, overview, replay, retry, signature, table, verification]
chunk: 4/9
---

## 1. Signature Verification

Webhook signatures verify that the payload came from the expected sender and hasn't been tampered with. Common failures:

- **No verification** — endpoint accepts any POST
- **Timing-safe comparison** — timing attacks on signature comparison
- **Signature algorithm confusion** — mixing HMAC-SHA256 vs SHA1
- **Payload normalization mismatch** — signature computed on different string

### Vulnerable Code (No Signature Verification)

```python
# VULNERABLE: Flask webhook endpoint with no signature verification
@app.route('/webhooks/github', methods=['POST'])
def github_webhook():
    payload = request.json
    # No signature check — anyone can POST here!
    process_event(payload['action'], payload['repository']['full_name'])
    return 'OK', 200
```

### Secure Code (Signature Verification)

```python
# SECURE: Webhook signature verification with timing-safe comparison
import hashlib
import hmac
import secrets
import os

WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET')

def verify_signature(payload_body, signature_header):
    """Verify webhook signature using HMAC-SHA256 (timing-safe)."""
    if not signature_header:
        return False
    
    # Compute expected signature
    expected = hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        payload_body,  # Use raw body bytes, not parsed JSON
        hashlib.sha256
    ).hexdigest()
    
    # Timing-safe comparison
    return hmac.compare_digest(f'sha256={expected}', signature_header)

@app.route('/webhooks/github', methods=['POST'])
def github_webhook():
    signature = request.headers.get('X-Hub-Signature-256')
    
    if not verify_signature(request.get_data(), signature):
        return 'Signature verification failed', 403
    
    payload = request.json
    process_event(payload['action'], payload['repository']['full_name'])
    return 'OK', 200
```

---