---
source: "common/api-security/webhook-security.md"
title: "Webhook Security"
heading: "4. Secret Rotation"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, attacks, bombing, overview, replay, retry, signature, table, verification]
chunk: 7/9
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