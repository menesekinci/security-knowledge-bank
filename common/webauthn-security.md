# WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification

**Severity:** High  
**CWE:** CWE-287 (Improper Authentication), CWE-613 (Insufficient Session Expiration), CWE-522 (Insufficiently Protected Credentials)  
**AI Risk:** High — AI models frequently generate credential managers that bypass WebAuthn API requirements, implement fake "biometric" auth, or misconfigure Relying Party validation  
**OWASP Top 10:2021:** A01 — Broken Access Control, A07 — Identification and Authentication Failures  

---

## 1. Vulnerability Explanation

WebAuthn (Web Authentication) is a W3C standard API for passwordless and multi-factor authentication using public-key cryptography. It is supported by all major browsers and platforms as part of the FIDO2 project. However, AI-generated code frequently makes critical implementation mistakes that completely negate its security guarantees.

### 1.1 AI Generates Credential Manager Without Origin Validation

The WebAuthn API binds credentials to a specific **origin** (protocol + hostname + port). AI-generated code often stores credential IDs and allows authentication from any origin, making passkeys reusable across attacker-controlled domains.

**AI Prompt:** *"Add passkey login to my app"*  
**AI Output:** DIY crypto using `localStorage` + a hand-rolled challenge instead of `navigator.credentials.create()` / `navigator.credentials.get()` with proper RP ID.

### 1.2 AI Misconfigures WebAuthn RP (Relying Party) ID

The `rp.id` parameter determines which origins are valid for a credential. AI-generated configs frequently:
- Omit `rp.id` entirely (browser defaults to full origin, breaking subdomain usage)
- Set `rp.id` to a wildcard or overly broad value
- Use `rp.id` that doesn't match the serving origin

### 1.3 AI Skips Attestation Verification

WebAuthn attestation proves the authenticator model and firmware version. AI-generated backends often:
- Accept any attestation statement without verification (including "none")
- Never check the attestation certificate chain
- Store attestation as opaque data without validation

### 1.4 AI Stores Passkeys in Insecure Client-Side Storage

Instead of using the platform authenticator (TPM, Secure Enclave, TEE), AI-generated code sometimes:
- Stores private keys in `localStorage` or `IndexedDB`
- Serializes key material to JSON for "backup"
- Uses `sessionStorage` for credential metadata

### 1.5 AI Implements "Fake" Biometric Auth Without Platform APIs

**AI Prompt:** *"Add FaceID login to my web app"*  
**AI Output:** A stored password check disguised as "biometric" authentication, completely bypassing platform biometric APIs (Touch ID, Face ID, Windows Hello, Android BiometricPrompt).

---

## 2. How AI Generates Vulnerable Code

### 2.1 "Add passkey login to my app" → DIY Crypto Instead of WebAuthn

```
AI generates:
- A custom key-pair generator using SubtleCrypto
- Private keys stored in localStorage
- Custom challenge-response protocol over fetch()
- No origin binding
- No attestation
```

This is **not** WebAuthn. It's custom cryptography with zero security guarantees.

### 2.2 "Add FaceID login" → Stored Password Check Instead of Biometric

```
AI generates:
- A "biometric" button that just checks a stored session flag
- A password field disguised as a FaceID scan
- No integration with navigator.credentials or platform APIs
```

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

## 4. Secure Code Fix

### 4.1 Proper WebAuthn Ceremony

**Frontend — Registration:**

```javascript
// SECURE: Proper WebAuthn registration with server challenge
async function registerWithWebAuthn(userId, userName, displayName) {
  // 1. Get challenge and user data from server
  const regOpts = await fetch('/auth/webauthn/register/begin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, userName })
  }).then(r => r.json());
  
  // 2. Decode base64url challenge
  const challenge = base64urlToArrayBuffer(regOpts.challenge);
  const userIdBytes = base64urlToArrayBuffer(regOpts.userId);
  
  // 3. Create credential via WebAuthn API
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: challenge,
      rp: {
        name: "My App",
        id: window.location.hostname  // ✅ Explicit RP ID
      },
      user: {
        id: userIdBytes,
        name: userName,
        displayName: displayName
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }  // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",  // Platform authenticator
        residentKey: "required",              // Discoverable credential
        userVerification: "required"          // Biometric/PIN
      },
      attestation: "direct"  // Request attestation
    }
  });
  
  // 4. Send credential to server for verification
  await fetch('/auth/webauthn/register/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: arrayBufferToBase64url(
          credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64url(
          credential.response.attestationObject)
      }
    })
  });
}

// Utility: ArrayBuffer to base64url
function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

**Backend — Verification:**

```python
# SECURE: Proper WebAuthn registration verification
import base64
import hashlib
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, asymmetric
from webauthn import WebAuthnRP, generate_registration_options, verify_registration_response
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement

RP_ID = "example.com"
RP_NAME = "My App"
ORIGIN = "https://example.com"

rp = WebAuthnRP(rp_id=RP_ID, rp_name=RP_NAME, origin=ORIGIN)

@app.route('/auth/webauthn/register/begin', methods=['POST'])
def register_begin():
    data = request.json
    user_id = data['userId']
    
    # Generate challenge (store in session for verification)
    challenge = secrets.token_bytes(32)
    session['webauthn_challenge'] = base64.b64encode(challenge).decode()
    
    options = generate_registration_options(
        rp=rp,
        user_id=user_id.encode(),
        user_name=data['userName'],
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key="required",
            user_verification=UserVerificationRequirement.REQUIRED
        )
    )
    
    return jsonify({
        'challenge': base64.b64encode(options.challenge).decode(),
        'userId': base64.b64encode(options.user.id).decode()
    })

@app.route('/auth/webauthn/register/complete', methods=['POST'])
def register_complete():
    data = request.json
    
    try:
        # ✅ Verify the registration response
        verification = verify_registration_response(
            credential=WebAuthnCredential(
                id=data['id'],
                raw_id=base64.b64decode(data['rawId']),
                response=data['response'],
                type=data['type']
            ),
            expected_challenge=base64.b64decode(
                session.pop('webauthn_challenge')),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True
        )
        
        # ✅ Store verified credential
        store_credential(
            user_id=session['user_id'],
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count  # For replay detection
        )
        
        return jsonify({"status": "registered"})
        
    except Exception as e:
        # ❌ Verification failed
        return jsonify({"error": str(e)}), 400
```

### 4.2 Conditional UI (Auto-fill) vs Modal

Use Conditional Mediation for seamless passkey login:

```javascript
// SECURE: Conditional UI for passkey autofill
async function conditionalWebAuthn() {
  const challenge = await fetch('/auth/webauthn/login/begin')
    .then(r => r.json());
  
  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: base64urlToArrayBuffer(challenge.challenge),
        rpId: window.location.hostname,
        userVerification: "required",
        mediation: "conditional"  // ✅ Auto-fill in input fields
      }
    });
    
    // Send assertion to server
    await verifyAssertion(assertion);
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      // User dismissed the dialog — that's OK
      console.log('Passkey login cancelled');
    }
  }
}

// Call this on page load
if (PublicKeyCredential && 
    PublicKeyCredential.isConditionalMediationAvailable?.()) {
  conditionalWebAuthn();
}
```

### 4.3 Backend Verification of Attestation

```python
# SECURE: Verify attestation statement
from webauthn.helpers import parse_attestation_object
from webauthn.helpers.structs import AttestationConveyancePreference

# Configure attestation preference
rp = WebAuthnRP(
    rp_id=RP_ID, 
    rp_name=RP_NAME, 
    origin=ORIGIN,
    attestation=AttestationConveyancePreference.DIRECT
)

# During verification, check:
# 1. Attestation type (basic, self, attca, eca, none)
# 2. If "basic" or "attca": verify certificate chain against trusted roots
# 3. Check if the AAGUID is in a known-valid authenticator list
# 4. Reject "none" attestation for high-security deployments
```

---

## 5. Real CVEs (Web-Verified)

| CVE ID | CVSS | Affected | Vulnerability | CWE |
|--------|------|----------|--------------|-----|
| CVE-2020-8236 | 6.8 MEDIUM | Nextcloud Server ≤19.0.1 | WebAuthn PIN requested but not verified during passwordless login — user felt 2FA was active when it wasn't | CWE-287 |
| CVE-2021-32726 | 7.1 HIGH | Nextcloud <19.0.13, <20.0.11, <21.0.3 | WebAuthn tokens not deleted after user deletion — reused username allows previous user account takeover (Nextcloud CNA score; NVD adopted a 9.8 primary) | CWE-708 |
| CVE-2021-32800 | 8.1 HIGH | Nextcloud <20.0.12, <21.0.4, <22.1.0 | WebAuthn 2FA bypass — attacker with password or WebAuthn device key can bypass MFA entirely | CWE-306 |
| CVE-2021-40818 | 9.8 CRITICAL | Glewlwyd SSO ≤2.5.3 | Buffer overflow in FIDO2 signature validation during WebAuthn registration | CWE-120 |
| CVE-2021-38299 | 9.8 CRITICAL | Webauthn Framework <3.2.9, <3.3.4 | Missing user presence check — attacker with physical FIDO2 device access can login without user interaction | CWE-287 |
| CVE-2022-27240 | 9.8 CRITICAL | Glewlwyd SSO 2.x <2.6.2 | Buffer overflow associated with webauthn assertion processing | CWE-120 |
| CVE-2023-49208 | 9.8 CRITICAL | Glewlwyd SSO <2.7.6 | Buffer overflow during FIDO2 credentials validation in webauthn registration | CWE-120 |
| CVE-2025-53102 | 9.8 CRITICAL | Discourse <3.4.7 stable | WebAuthn challenge reuse — the server-generated 2FA challenge is not invalidated/bound to a single ceremony, so a captured challenge-response can be replayed | CWE-384 |
| CVE-2026-28787 | 8.2 HIGH | OneUptime ≤10.0.11 | WebAuthn challenge not stored server-side — no origin binding, replayable credentials | CWE-287 |
| CVE-2026-31835 | 5.4 MEDIUM | Vaultwarden ≤1.35.4 | `validate_webauthn_login()` updates persistent credential metadata (`backup_eligible`/`backup_state`) from unverified `authenticatorData` before signature validation → persistent WebAuthn 2FA DoS (NVD v3.1 5.4; GHSA CVSS 4.0 = 5.3) | CWE-345 |
| CVE-2026-8830 | 4.3 MEDIUM | Keycloak | Authenticated user bypasses WebAuthn policy during credential registration via client-side JS manipulation — server-side policy not enforced | CWE-287 |

---

## 6. Prevention Checklist

- [ ] **Always use `navigator.credentials.create()` / `.get()`** — never hand-roll crypto for passkeys
- [ ] **Set `rp.id` explicitly** to your domain (no wildcards, no subdomain mismatch)
- [ ] **Validate origin server-side** — compare against `expectedOrigin` parameter in every registration and authentication
- [ ] **Store challenge server-side** — never trust the client to provide or store challenges
- [ ] **Require `userVerification: "required"`** — force biometric/PIN for high-security applications
- [ ] **Verify attestation** — for enterprise deployments, verify certificate chain against trusted roots
- [ ] **Check sign count** — monotonic counter to detect cloned authenticators
- [ ] **Use Conditional Mediation** (`mediation: "conditional"`) for seamless UX without modal popups
- [ ] **Never store private keys in localStorage/IndexedDB** — use platform authenticator only
- [ ] **Never implement fake "biometric" auth** — always use platform biometric APIs via WebAuthn
- [ ] **Use the `requireResidentKey` option** for discoverable credentials (passkeys)
- [ ] **Clean up credentials on user deletion** — see CVE-2021-32726
- [ ] **Enforce server-side WebAuthn policies** — don't rely on client-side enforcement (see CVE-2026-8830)

---

## 7. Vibe-Coding Red Flags

| Red Flag | What AI Might Generate | Secure Alternative |
|----------|----------------------|-------------------|
| "Add passkey login to my React app" | Custom `crypto.subtle` key generation + localStorage storage | `navigator.credentials.create()` with platform authenticator |
| "Add FaceID/TouchID login" | A password field + "biometric" CSS styling | WebAuthn with `userVerification: 'required'` + platform authenticator |
| "Store WebAuthn credentials for offline" | Serialize private keys as JSON, store in IndexedDB | Let platform authenticator manage keys; store only credential ID server-side |
| "Generate a challenge" | `Math.random().toString()` or `new Date().getTime()` | `crypto.getRandomValues()` (32 bytes minimum) with server-side storage |
| "Skip attestation for simplicity" | Accept all `attestation: 'none'` responses without checking | Use `attestation: 'direct'` for sensitive deployments |
| "Make WebAuthn work on iframe" | Using WebAuthn inside cross-origin iframe (browser blocks it) | Top-level navigation only; use postMessage to parent window |
| "Backup my passkeys to the cloud" | Upload private key material to a REST API | Platform-managed sync (iCloud Keychain, Google Password Manager, etc.) |
| "Auto-login with passkeys" | Auto-invoke `navigator.credentials.get()` without user gesture | Conditional Mediation (`mediation: 'conditional'`) or user-initiated button |

---

## References

- [W3C WebAuthn Level 2 Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance — WebAuthn Developer Guide](https://fidoalliance.org/developers/)
- [OWASP — WebAuthn Security Considerations](https://cheatsheetseries.owasp.org/cheatsheets/WebAuthn_Cheat_Sheet.html)
- [Mozilla MDN — Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [CVE-2020-8236 — HackerOne Report #924393](https://hackerone.com/reports/924393)
- [CVE-2021-32726 — WebAuthn tokens not deleted on user deletion](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-6qr9-c846-j8mg)
- [CVE-2026-28787 — OneUptime WebAuthn challenge not stored](https://nvd.nist.gov/vuln/detail/CVE-2026-28787)
- [CVE-2026-8830 — Keycloak WebAuthn policy bypass](https://nvd.nist.gov/vuln/detail/CVE-2026-8830)
