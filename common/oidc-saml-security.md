# OIDC / SAML Security — Token Validation, PKCE, Signature Verification

**Severity:** Critical  
**CWE:** CWE-287 (Improper Authentication), CWE-290 (Authentication Bypass by Spoofing), CWE-613 (Insufficient Session Expiration)  
**AI Risk:** High — AI models frequently implement OIDC without PKCE, skip ID token validation, mix up token types, or build SAML with no XML signature verification  
**OWASP Top 10:2021:** A01 — Broken Access Control, A07 — Identification and Authentication Failures  

---

## 1. Vulnerability Explanation

OpenID Connect (OIDC) and Security Assertion Markup Language (SAML) are widely used authentication protocols. Both are cryptographically complex and require precise implementation to be secure. AI-generated code routinely makes critical mistakes that completely undermine authentication guarantees.

### 1.1 AI Implements OIDC Without PKCE

The Authorization Code flow with PKCE (Proof Key for Code Exchange) is the recommended OAuth 2.1 flow. AI-generated code often:
- Uses the Implicit Flow (deprecated in OAuth 2.1)
- Implements Authorization Code flow without PKCE
- Generates a static `code_verifier` or reuses the same value
- Never validates the `code_challenge_method` on the server

**AI Prompt:** *"Add Google login to my React app"*  
**AI Output:** Implicit flow with access token in URL fragment — no PKCE, no client secret.

### 1.2 AI Skips ID Token Validation (Signature, Issuer, Audience)

The ID Token (JWT) from the OIDC provider must be validated for:
- **Signature** — must match the provider's JWKS
- **Issuer (`iss`)** — must match the expected provider
- **Audience (`aud`)** — must include the client ID
- **Expiration (`exp`)** — must not be expired
- **Nonce** — must match the original request

AI-generated code frequently skips all or most of these checks.

### 1.3 AI Mixes Up Access Token vs ID Token

Access tokens are for API authorization. ID tokens are for authentication. AI-generated code often:
- Uses the ID token as an API bearer token
- Sends the access token to the user info endpoint for authentication
- Stores tokens insecurely or in the wrong location

### 1.4 AI Builds SAML Without XML Signature Verification

SAML uses XML Digital Signatures for message integrity. AI-generated SAML implementations often:
- Skip signature verification entirely
- Use vulnerable XML parsers that allow XXE (XML External Entity) attacks
- Fall victim to XML Signature Wrapping (XSW) attacks
- Accept unsigned assertions
- Don't validate the issuer or audience restrictions

### 1.5 AI Stores Tokens Insecurely

- Tokens stored in `localStorage` (accessible to any JavaScript on the origin)
- No use of BFF (Backend for Frontend) pattern
- Tokens included in URLs (logged, leaked via Referer header)
- No refresh token rotation

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

## 3. Real CVEs (Web-Verified)

### OIDC / OAuth CVEs

| CVE ID | CVSS | Affected | Vulnerability | CWE |
|--------|------|----------|--------------|-----|
| CVE-2021-44878 | 7.5 HIGH | pac4j ≤5.3.0 | "none" algorithm accepted for OIDC tokens — unsigned ID tokens trusted by default | CWE-347 |
| CVE-2021-22573 | 7.3 HIGH | Google OAuth IDToken verifier library | ID token signature verification skipped — accepts arbitrarily forged tokens (NVD primary 7.3; secondary 8.7) | CWE-347 |
| CVE-2022-31105 | 8.3 HIGH | Argo CD 0.4.0–2.2.10, 2.3.0–2.3.5, 2.4.0–2.4.4 | Improper certificate validation in OIDC — attacker can spoof any OIDC provider | CWE-295 |
| CVE-2023-27490 | 8.1 HIGH | NextAuth.js <4.20.1 | PKCE bypass in OAuth — authorization code interception without verifier validation | CWE-287 |
| CVE-2024-49755 | 3.1 LOW | Duende IdentityServer | Insufficient cnf claim validation in DPoP access tokens | CWE-287 |
| CVE-2025-4144 | 9.8 CRITICAL | Cloudflare workers-oauth-provider | PKCE implementation flaw — authorization code injection | CWE-287 |
| CVE-2026-28498 | 7.5 HIGH | Authlib <1.6.9 | OIDC token validation vulnerability — insufficient algorithm validation | CWE-347 |
| CVE-2026-11800 | 8.1 HIGH | Keycloak | JWT algorithm confusion in OIDC Authorization Grant flow — signature bypass | CWE-347 |

### SAML CVEs

| CVE ID | CVSS | Affected | Vulnerability | CWE |
|--------|------|----------|--------------|-----|
| CVE-2018-5241 | 9.8 CRITICAL | Symantec ASG 6.6/6.7, ProxySG 6.5/6.6/6.7 | SAML authentication bypass — attacker can forge authentication | CWE-287 |
| CVE-2018-5387 | 7.5 HIGH | Wizkunde SAMLBase | XML DOM traversal and canonicalization misuse — attacker manipulates SAML data without invalidating signature | CWE-347 |
| CVE-2019-3878 | 8.1 HIGH | mod_auth_mellon <0.14.2 | SAML auth bypass when Apache configured as reverse proxy — crafted URL can bypass authentication check | CWE-287 |
| CVE-2019-1006 | 7.5 HIGH | WCF/WIF (.NET) | SAML token signing bypass — arbitrary symmetric keys accepted for signature verification | CWE-347 |
| CVE-2017-11427 | 9.8 CRITICAL | OneLogin PythonSAML ≤2.3.0 | XML DOM traversal/canonicalization — signature bypass via XML manipulation (NVD primary 9.8; secondary 7.7) | CWE-347 |
| CVE-2020-5390 | 7.5 HIGH | PySAML2 <5.0.0 | XML Signature Wrapping (XSW) — enveloped signature not enforced | CWE-347 |
| CVE-2015-5253 | 4.0 MEDIUM | Apache CXF <2.7.18, 3.0.x <3.0.7, 3.1.x <3.1.3 | SAML bypass via crafted response with valid signature from arbitrary user | CWE-287 |
| CVE-2020-2021 | 10.0 CRITICAL | PAN-OS (Palo Alto Networks) | SAML certificate validation bypass when "Validate Identity Provider Certificate" disabled | CWE-295 |
| CVE-2020-27846 | 9.8 CRITICAL | crewjam/saml Go library | Signature verification vulnerability — SAML authentication bypass | CWE-347 |
| CVE-2020-4427 | 9.8 CRITICAL | IBM Data Risk Manager 2.0.1–2.0.6 | SAML authentication bypass via crafted request | CWE-287 |
| CVE-2024-9487 | 9.1 CRITICAL | GitHub Enterprise Server | SAML SSO signature verification bypass — authentication bypass | CWE-347 |
| CVE-2025-59718 | 9.8 CRITICAL | Fortinet FortiOS 7.0.0–7.6.3 | SAML signature verification bypass | CWE-347 |
| CVE-2025-54982 | 9.6 CRITICAL | Zscaler Admin UI | SAML cryptographic signature verification bypass — privilege escalation | CWE-347 |
| CVE-2026-54774 | 7.4 HIGH | CoreWCF <1.8.1, <1.9.1 | SamlSerializer skips final SignatureValue verification | CWE-347 |

---

## 4. Prevention Checklist

### OIDC
- [ ] **Always use Authorization Code + PKCE** (S256 challenge method) — never Implicit Flow
- [ ] **Validate ID Token signature** against provider's JWKS endpoint
- [ ] **Verify `iss` (issuer)** matches the expected OIDC provider URL exactly
- [ ] **Verify `aud` (audience)** includes your client ID
- [ ] **Verify `exp` (expiration)** and `iat` (issued at) timestamps
- [ ] **Use and verify `nonce`** to prevent replay attacks
- [ ] **Use and verify `state`** parameter to prevent CSRF attacks
- [ ] **Never send ID token to APIs** — use access token for API authorization
- [ ] **Never store tokens in `localStorage`** — use BFF (Backend for Frontend) pattern with HttpOnly cookies
- [ ] **Implement refresh token rotation** — invalidate old refresh tokens when new ones are issued
- [ ] **Reject `alg: "none"`** tokens — enforce RS256, ES256, or EdDSA only
- [ ] **Implement client authentication** (client_secret_basic, private_key_jwt) for token endpoint
- [ ] **Limit token lifetime** — access tokens ≤15 minutes, refresh tokens rotated

### SAML
- [ ] **Always verify XML Digital Signature** — never trust unsigned SAML assertions
- [ ] **Use a robust XML parser** with XXE protection enabled (lxml, not xml.etree.ElementTree)
- [ ] **Defend against XML Signature Wrapping** — verify only one Assertion element, validate Reference URI
- [ ] **Verify Issuer** (entity ID) matches the trusted IdP exactly
- [ ] **Verify Audience Restriction** — must include your SP entity ID
- [ ] **Verify time constraints** (NotBefore, NotOnOrAfter) with clock skew tolerance
- [ ] **Verify Response Status** is `Success`
- [ ] **Use `authnRequest` binding** with signed requests when possible
- [ ] **Enforce HTTPS** for all SAML endpoints (SSO URL, ACS URL)
- [ ] **Certificate rotation** — monitor and rotate IdP signing certificates before expiry
- [ ] **Log all SAML authentication attempts** including failures
- [ ] **Avoid `redirect` binding for sensitive assertions** — prefer `POST` binding

---

## 5. Vibe-Coding Red Flags

| Red Flag | What AI Might Generate | Secure Alternative |
|----------|----------------------|-------------------|
| "Add Google login with React" | Implicit flow, access token in URL, no PKCE | Authorization Code + PKCE via BFF pattern |
| "Verify the JWT token" | Just decodes base64, no signature check | Verify signature against JWKS, validate all claims |
| "Send the ID token to my API" | Uses ID token as bearer token for API | Access token for API, ID token for authentication only |
| "Store the token for auto-login" | Saves tokens to localStorage | BFF pattern with HttpOnly session cookie |
| "Add SAML SSO" | Unauthenticated ACS endpoint, no signature verification | Full XML signature verification with XSW defense |
| "Parse the SAML response" | `xml.etree.ElementTree` without XXE protection | lxml with secure defaults, signature verification via signxml |
| "Allow 'none' algorithm for flexibility" | Accepts unsigned tokens | Reject 'none', enforce RS256/ES256/EdDSA |
| "Use the access token to get user info" | Access token sent to UserInfo endpoint (redundant) | ID token already contains user claims; UserInfo optional for additional claims |
| "Skip PKCE for server-side apps" | Hidden assumption: "it's safe because it's confidential" | Always use PKCE — mitigates authorization code interception |
| "Code verifier = 'abc123'" | Static/predictable code verifier | Secure random (32+ bytes), SHA-256 hashed for challenge |
| "Handle SAML metadata automatically" | Auto-imports any IdP metadata without verification | Pin metadata, verify certificates, check entity IDs |

---

## References

- [OpenID Connect Core 1.0 Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 for Browser-Based Apps (BCP)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- [PKCE — RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [SAML V2.0 Core Specification](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [OWASP — SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OWASP — OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2.0_Cheat_Sheet.html)
- [XML Signature Wrapping Attacks](https://www.usenix.org/legacy/event/sec08/tech/full_papers/somorovsky/somorovsky.pdf)
- [CVE-2021-44878 — pac4j OIDC none algorithm](https://nvd.nist.gov/vuln/detail/CVE-2021-44878)
- [CVE-2021-22573 — Google IDToken verifier bypass](https://nvd.nist.gov/vuln/detail/CVE-2021-22573)
- [CVE-2020-27846 — crewjam/saml signature bypass](https://nvd.nist.gov/vuln/detail/CVE-2020-27846)
- [CVE-2024-9487 — GitHub Enterprise SAML bypass](https://nvd.nist.gov/vuln/detail/CVE-2024-9487)
- [CVE-2020-2021 — PAN-OS SAML bypass (CVSS 10.0)](https://nvd.nist.gov/vuln/detail/CVE-2020-2021)
- [CVE-2023-27490 — NextAuth.js PKCE bypass](https://nvd.nist.gov/vuln/detail/CVE-2023-27490)
