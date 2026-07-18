---
source: "common/webauthn-security.md"
title: "WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification"
heading: "3. Vulnerable Code Examples"
category: "common-vuln"
language: "common"
severity: "high"
tags: [code, common-vuln, cves, explanation, real, secure, vulnerability, vulnerable]
chunk: 4/9
---

## 3. Vulnerable Code Examples

### 3.1 navigator.credentials.create Without Challenge

```javascript
// VULNERABLE: No server-generated challenge
const credential = await navigator.credentials.create({
  publicKey: {
    rp: { name: "My App" },
    user: {
      id: new Uint8Array([1, 2, 3]),
      name: "user@example.com",
      displayName: "User"
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    // ⚠️ No challenge!
  }
});
```

**Impact:** Attacker can replay registration, bypass user verification.

### 3.2 WebAuthn Without RP ID Validation

```javascript
// VULNERABLE: No rp.id set — defaults to current origin, 
// but server doesn't verify origin
const credential = await navigator.credentials.get({
  publicKey: {
    challenge: new Uint8Array(32),
    allowCredentials: [{ id: credentialId, type: "public-key" }]
    // ⚠️ No rpId, no origin validation on server
  }
});
```

**Impact:** Credentials can be used from any origin. Cross-site credential theft.

### 3.3 Storing Credential ID in localStorage

```javascript
// VULNERABLE: Storing credential metadata in cleartext localStorage
localStorage.setItem('webauthn_credential_id', 
  arrayBufferToBase64(credential.id));
localStorage.setItem('webauthn_credential_type', 'platform');
// ⚠️ Private key material or credential IDs exposed to XSS
```

**Impact:** XSS attack exposes credential references for account takeover.

### 3.4 No Attestation Verification on Backend

```python
# VULNERABLE: Accepting any attestation without verification
@app.route('/register/complete', methods=['POST'])
def register_complete():
    data = request.json
    # ⚠️ Never verifies the attestation statement
    # ⚠️ Never checks the attestation certificate chain
    store_credential(
        user_id=data['user_id'],
        credential_id=data['credential_id'],
        public_key=data['public_key'],
        attestation_object=data['attestation_object']  # stored blindly
    )
    return {"status": "ok"}
```

**Impact:** Attacker can present a forged attestation from a software authenticator.

---