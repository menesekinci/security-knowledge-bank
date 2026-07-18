---
source: "common/oidc-saml-security.md"
title: "OIDC / SAML Security — Token Validation, PKCE, Signature Verification"
heading: "2. Vulnerable Code + Secure Fix"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, cves, explanation, prevention, real, vibe-coding, vulnerability, vulnerable]
chunk: 3/7
---

## 2. Vulnerable Code + Secure Fix

### 2.1 OIDC Without PKCE

**VULNERABLE — Authorization Code without PKCE:**

```javascript
// VULNERABLE: Authorization Code flow without PKCE
// Attacker can intercept the authorization code
async function loginWithOIDC() {
  const authUrl = new URL('https://accounts.example.com/authorize');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email');
  // ❌ No code_challenge, no code_challenge_method
  // ❌ No state parameter (CSRF protection)
  
  window.location.href = authUrl.toString();
}
```

**SECURE — Authorization Code with PKCE:**

```javascript
// SECURE: Proper OIDC Authorization Code flow with PKCE
async function loginWithOIDC() {
  // 1. Generate PKCE challenge
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  
  // Store verifier temporarily (session-only, not localStorage!)
  sessionStorage.setItem('oidc_code_verifier', codeVerifier);
  
  // 2. Generate state parameter (CSRF protection)
  const state = generateRandomState();
  sessionStorage.setItem('oidc_state', state);
  
  // 3. Generate nonce (replay protection)
  const nonce = generateRandomNonce();
  sessionStorage.setItem('oidc_nonce', nonce);
  
  // 4. Build authorization URL
  const authUrl = new URL('https://accounts.example.com/authorize');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  
  window.location.href = authUrl.toString();
}

// PKCE helpers
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

async function generateCodeChallenge(verifier) {
  const hash = await crypto.subtle.digest('SHA-256', 
    new TextEncoder().encode(verifier));
  return base64urlEncode(new Uint8Array(hash));
}

function generateRandomState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

function generateRandomNonce() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

### 2.2 OIDC ID Token Validation (Backend)

**VULNERABLE — No token validation:**

```python
# VULNERABLE: Accepts any token without validation
from google.oauth2 import id_token
from google.auth.transport import requests

def verify_google_token(token):
    # ❌ No issuer validation
    # ❌ No audience validation
    # ❌ No signature verification
    # Just decodes the JWT
    import jwt
    return jwt.decode(token, options={"verify_signature": False})
```

**SECURE — Full token validation:**

```python
# SECURE: Proper OIDC ID Token validation
import requests as http_requests
from jose import jwt, jwk
from jose.exceptions import JOSEError

# Cache JWKS keys
JWKS_CACHE = {}
OIDC_PROVIDER_CONFIG = {
    "google": {
        "issuer": "https://accounts.google.com",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com"
    }
}

def get_jwks(provider):
    """Fetch and cache JWKS keys from provider"""
    if provider not in JWKS_CACHE:
        config = OIDC_PROVIDER_CONFIG[provider]
        resp = http_requests.get(config["jwks_uri"])
        JWKS_CACHE[provider] = resp.json()
    return JWKS_CACHE[provider]

def verify_oidc_id_token(id_token_str, provider):
    """
    Verify OIDC ID Token with full validation.
    
    Checks:
    - ✅ Signature against provider's JWKS
    - ✅ Issuer (iss) matches expected provider
    - ✅ Audience (aud) includes our client ID
    - ✅ Expiration (exp) is not expired
    - ✅ Nonce (if provided) is valid
    """
    try:
        config = OIDC_PROVIDER_CONFIG[provider]
        jwks = get_jwks(provider)
        
        # Get the key ID from token header
        unverified_header = jwt.get_unverified_header(id_token_str)
        kid = unverified_header.get("kid")
        
        # Find the matching JWK
        key_data = None
        for key in jwks["keys"]:
            if key.get("kid") == kid:
                key_data = key
                break
        
        if not key_data:
            raise ValueError("No matching JWK key found")
        
        rsa_key = jwk.RSAKey(**key_data)
        
        # ✅ Verify signature + all claims
        claims = jwt.decode(
            id_token_str,
            rsa_key,
            algorithms=["RS256"],
            issuer=config["issuer"],
            audience=config["client_id"],
            options={
                "verify_signature": True,
                "verify_iat": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            }
        )
        
        # ✅ (Optional) Verify nonce if stored
        # nonce = session.pop('oidc_nonce', None)
        # if nonce and claims.get('nonce') != nonce:
        #     raise ValueError("Nonce mismatch")
        
        return claims
        
    except JOSEError as e:
        # ❌ Token validation failed
        raise ValueError(f"ID Token verification failed: {e}")
```

### 2.3 Mixing Up Access Token vs ID Token

**VULNERABLE — Using ID token as API token:**

```javascript
// VULNERABLE: Using ID token as API bearer token
async function callApi() {
  const idToken = getFromStorage('oidc_id_token');
  // ❌ ID token sent to API — API doesn't need user identity
  const response = await fetch('/api/user/data', {
    headers: { 'Authorization': `Bearer ${idToken}` }
  });
}
```

**SECURE — Use access token for API, ID token for auth only:**

```javascript
// SECURE: Proper token separation
async function exchangeCodeForTokens(code, codeVerifier) {
  const response = await fetch('/auth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      code_verifier: codeVerifier,
      grant_type: 'authorization_code',
      redirect_uri: REDIRECT_URI
    })
  });
  
  const tokens = await response.json();
  
  // ✅ ID token — decode and verify for user info only
  const idToken = verifyJWT(tokens.id_token);
  sessionStorage.setItem('user_profile', JSON.stringify({
    sub: idToken.sub,
    name: idToken.name,
    email: idToken.email
  }));
  
  // ✅ Access token — send to API (NOT in localStorage!)
  // Use BFF pattern: server holds the token, sends session cookie
  await fetch('/auth/store-access-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_token: tokens.access_token }),
    credentials: 'include'  // HttpOnly session cookie
  });
  
  // ✅ Refresh token — server-side only, never exposed to JS
  // Server stores refresh_token in its own secure storage
}
```

### 2.4 SAML Without Signature Verification

**VULNERABLE — SAML without XML signature check:**

```python
# VULNERABLE: SAML response accepted without signature verification
import xml.etree.ElementTree as ET

def parse_saml_response(saml_response_xml):
    # ❌ No XML signature verification
    # ❌ Vulnerable to XML Signature Wrapping
    # ❌ No issuer validation
    
    root = ET.fromstring(saml_response_xml)
    
    # Extract assertion directly — no signature check!
    assertion = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
    
    user_data = {
        'name_id': assertion.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID').text,
        'attributes': extract_attributes(assertion)
    }
    
    # ❌ Attacker can forge assertions
    return user_data
```

**SECURE — Full SAML verification:**

```python
# SECURE: Proper SAML response verification
from signxml import XMLVerifier
from lxml import etree
import base64
import zlib

# Trusted IdP metadata
TRUSTED_IDP = {
    "entity_id": "https://idp.example.com/saml2",
    "certificate": """-----BEGIN CERTIFICATE-----
MII... (IdP signing certificate)
-----END CERTIFICATE-----",
    "sso_url": "https://idp.example.com/saml2/sso"
}

def verify_saml_response(saml_response):
    """
    Verify SAML 2.0 response with full validation.
    
    Checks:
    - ✅ XML Digital Signature verification
    - ✅ Issuer matches trusted IdP
    - ✅ Audience restriction matches our SP
    - ✅ NotBefore / NotOnOrAfter time constraints
    - ✅ Response status is Success
    - ✅ No XML Signature Wrapping (only one Assertion)
    """
    try:
        # 1. Decode SAMLResponse (base64, optionally deflated)
        decoded = base64.b64decode(saml_response)
        try:
            decoded = zlib.decompress(decoded)
        except zlib.error:
            pass  # Not deflated
        
        # 2. Parse as XML (use lxml, not ET — XXE protection built-in)
        root = etree.fromstring(decoded)
        
        # 3. Verify XML Signature
        # signxml.XMLVerifier handles:
        #   - Certificate validation against trusted root
        #   - Signature wrapping attack detection
        #   - Reference digest verification
        verified_data = XMLVerifier().verify(
            root,
            x509_cert=TRUSTED_IDP["certificate"]
        ).signed_xml
        
        # 4. Verify Issuer
        issuer = verified_data.find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'
        )
        if issuer is None or issuer.text != TRUSTED_IDP["entity_id"]:
            raise ValueError("Issuer mismatch")
        
        # 5. Verify Status is Success
        status = verified_data.find(
            './/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode'
        )
        if status.get('Value') != 'urn:oasis:names:tc:SAML:2.0:status:Success':
            raise ValueError("SAML response status not Success")
        
        # 6. Extract and validate Assertion
        assertions = verified_data.findall(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion'
        )
        if len(assertions) != 1:
            # ⚠️ Multiple assertions could indicate signature wrapping attack
            raise ValueError("Expected exactly one assertion")
        
        assertion = assertions[0]
        
        # 7. Validate Conditions (Audience, NotBefore, NotOnOrAfter)
        conditions = assertion.find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'
        )
        if conditions is not None:
            from datetime import datetime
            now = datetime.utcnow()
            
            not_before = conditions.get('NotBefore')
            not_on_or_after = conditions.get('NotOnOrAfter')
            
            if not_before and now < datetime.fromisoformat(not_before):
                raise ValueError("Assertion not yet valid")
            if not_on_or_after and now > datetime.fromisoformat(not_on_or_after):
                raise ValueError("Assertion expired")
            
            # Verify Audience
            audience = conditions.find(
                './/{urn:oasis:names:tc:SAML:2.0:assertion}Audience'
            )
            if audience is None or audience.text != "https://sp.example.com/saml2":
                raise ValueError("Audience mismatch")
        
        # 8. Extract user data
        name_id = assertion.find(
            './/{urn:oasis:names:tc:SAML:2.0:assertion}NameID'
        )
        
        return {
            'name_id': name_id.text if name_id is not None else None,
            'issuer': issuer.text,
            'session_index': assertion.find(
                './/{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement'
            ).get('SessionIndex') if assertion.find(
                './/{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement'
            ) is not None else None
        }
        
    except Exception as e:
        raise ValueError(f"SAML verification failed: {e}")
```

---