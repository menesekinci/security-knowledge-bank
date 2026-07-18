---
source: "common/webauthn-security.md"
title: "WebAuthn / Passkeys / FIDO2 Security — Credential Management, Attestation, RP Verification"
heading: "4. Secure Code Fix"
category: "common-vuln"
language: "common"
severity: "high"
tags: [code, common-vuln, cves, explanation, real, secure, vulnerability, vulnerable]
chunk: 5/9
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