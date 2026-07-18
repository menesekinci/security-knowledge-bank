# Webhook Security

> **Category:** Common / API Security
> **Last Updated:** July 2026

## Overview

Webhooks are HTTP callbacks that enable real-time event-driven communication between services. Because webhooks typically carry sensitive payloads and operate server-to-server without interactive authentication, they are frequent targets for signature verification bypass, replay attacks, retry bombing, and secret compromise.

---

## Table of Contents

1. [Signature Verification](#1-signature-verification)
2. [Replay Attacks](#2-replay-attacks)
3. [Retry Bombing & Amplification](#3-retry-bombing--amplification)
4. [Secret Rotation](#4-secret-rotation)
5. [CVEs & Real-World Examples](#5-cves--real-world-examples)

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

## 4. Secret Rotation

Webhook secrets must be rotated periodically and immediately after any compromise. Common failures:

- **Hardcoded secrets** in source code or config files
- **No rotation process** — secret unchanged for years
- **Simultaneous rotation** — no overlap period causes delivery failures
- **Leaked in logs** — secret printed during signature verification

### Vulnerable Code (Hardcoded, No Rotation)

```python
# VULNERABLE: Hardcoded webhook secret, no rotation support
WEBHOOK_SECRET = "my-secret-key-12345"  # Same key for 3 years!
```

### Secure Code (Rotation with Dual-Verification)

```python
# SECURE: Dual secret verification for seamless rotation
import os
from datetime import datetime

class WebhookSecretManager:
    def __init__(self):
        self.current_secret = os.environ.get('WEBHOOK_SECRET')
        self.previous_secret = os.environ.get('WEBHOOK_SECRET_PREVIOUS')
        self.last_rotation = datetime.now()
    
    def verify(self, payload_body, signature_header, algorithm='sha256'):
        """Verify with both current and previous secret (gradual rotation)."""
        for secret in [self.current_secret, self.previous_secret]:
            if not secret:
                continue
            expected = hmac.new(
                secret.encode('utf-8'),
                payload_body,
                hashlib.sha256 if algorithm == 'sha256' else hashlib.sha1
            ).hexdigest()
            
            if hmac.compare_digest(f'{algorithm}={expected}', signature_header):
                return True
        return False
    
    def rotate_secret(self):
        """Rotate to a new secret."""
        self.previous_secret = self.current_secret
        self.current_secret = secrets.token_hex(32)  # 256-bit random
        self.last_rotation = datetime.now()
        
        # In production: store in secret manager (AWS Secrets Manager, Vault, etc.)
        store_secret_in_vault('webhook/current', self.current_secret)
        store_secret_in_vault('webhook/previous', self.previous_secret,
                              ttl=timedelta(hours=24))
```

---

## 5. CVEs & Real-World Examples

### GitHub Webhook Secret Exposure (2024)
- **Description**: A GitHub bug exposed webhook secrets to recipient endpoints via response headers. Attackers could read secrets by monitoring webhook delivery responses. The vulnerability affected GitHub.com webhook delivery infrastructure
- **Impact**: Webhook secrets for thousands of repositories potentially leaked
- **Fix**: GitHub rotated affected secrets; recipients advised to rotate secrets
- **Source**: https://exploitr.com/articles/alert-github-bug-exposed-webhook-secrets-to-recipient-endpoints/

### CVE-2025-30066 — GitHub Actions tj-actions/changed-files Supply Chain Attack
- **Description**: In March 2025, the popular GitHub Action `tj-actions/changed-files` was compromised in a supply chain attack. The attacker modified the action to exfiltrate CI/CD secrets (including webhook secrets and deployment keys) from workflow logs
- **Impact**: 23,000+ repositories potentially exposed secrets
- **CVSS**: 9.1 (Critical)
- **Fix**: Rotate all secrets exposed in CI; audit workflow logs for leaked secrets; pin actions by commit hash, not version tag
- **Source**: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066

### MOVEit Webhook Input Validation (2024)
- **Description**: The 2024 MOVEit vulnerability exploited insufficient input validation in webhook handlers, affecting over 2,000 organizations. Attackers sent crafted webhook payloads that triggered SQL injection in the receiving server
- **Affected**: Progress MOVEit Transfer
- **CVSS**: 9.8 (Critical)
- **Fix**: Input validation on all webhook payloads; parameterized queries in handlers
- **Source**: https://www.apisec.ai/blog/securing-webhook-endpoints-best-practices

### Stripe Webhook Replay Attack Pattern (Common Bug Bounty Finding)
- **Description**: Multiple bug bounty reports highlight Stripe webhook integrations that fail to check `created` timestamps or maintain idempotency, allowing attackers to replay old payment webhooks
- **Fix**: Implement timestamp verification (±5 minute tolerance) and always use the webhook ID for idempotency checks
- **Source**: https://stripe.com/docs/webhooks

### Webhook Secret Rotation Negligence (Industry Pattern)
- **Description**: Studies of 100+ SaaS webhook implementations found that 68% had never rotated their webhook signing secrets, and 23% still used example or default secrets from documentation
- **Fix**: Mandate secret rotation every 90 days; use separate secrets per integration
- **Source**: https://www.obsidiansecurity.com/blog/what-is-webhook-security-securing-saas-integrations-2026

---

## References

- [Stripe Webhook Security Documentation](https://stripe.com/docs/webhooks/signatures)
- [Svix — Why Verify Webhooks](https://docs.svix.com/receiving/verifying-payloads/why)
- [Hookdeck — Webhook Security Vulnerability Guide](https://hookdeck.com/webhooks/guides/webhook-security-vulnerabilities-guide)
- [GitHub — Securing Webhooks](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [Obsidian Security — Webhook Security Securing SaaS Integrations 2026](https://www.obsidiansecurity.com/blog/what-is-webhook-security-securing-saas-integrations-2026)
- [Kusari — Webhook Security Best Practices](https://www.kusari.dev/learning-center/webhook-security)
