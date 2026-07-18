# OAuth 2.0 Security — Implicit Grant, Redirect URI, CSRF, PKCE, Token Leakage

**CWE:** CWE-862 (Missing Authorization), CWE-352 (Cross-Site Request Forgery), CWE-601 (URL Redirection to Untrusted Site)
**OWASP Top 10:2021:** A01 — Broken Access Control, A07 — Identification and Authentication Failures
**CWE Top 25 2024:** CWE-352 (#14 Missing CSRF Protection), CWE-862 (#16 Missing Authorization)

---

## What Is OAuth 2.0?

OAuth 2.0 is an authorization framework that enables third-party applications to obtain limited access to a user's resources on another service without exposing credentials. It is used by virtually every major platform — Google, Facebook, Microsoft, GitHub, Twitter — for both API authorization and delegated authentication (SSO).

**The problem:** OAuth 2.0 is extremely complex, and implementation errors are pervasive. The framework prioritizes flexibility over security, leaving many critical decisions to implementers — who get them wrong at alarming rates.

### Key OAuth Concepts

| Term | Description |
|------|-------------|
| **Resource Owner** | The user who owns the data |
| **Client** | The application requesting access |
| **Authorization Server** | Issues tokens after authentication |
| **Resource Server** | Hosts protected resources, validates tokens |
| **Access Token** | Credential used to access resources |
| **Refresh Token** | Used to obtain new access tokens |
| **Authorization Code** | Temporary code exchanged for tokens |
| **Scope** | Defines the level of access requested |
| **Redirect URI** | Where the user is sent after authorization |
| **State** | Opaque value to prevent CSRF attacks |

---

## Why Vibe Coding Makes This Worse

- **AI assumes OAuth 2.0 is "secure by default"** — It's not. The framework is a toolbox, not a security solution.
- **AI often implements Implicit Grant** — Many AI-generated tutorials still use the deprecated implicit flow.
- **AI skips `state` parameter** — The most common CSRF prevention mechanism is seen as "optional complexity."
- **AI generates loose redirect URI validation** — Pattern matching with `startsWith()` instead of exact match.
- **AI misunderstands PKCE** — Implements the flow without validating the code verifier.

---

## Major OAuth 2.0 Vulnerability Categories

### 1. Implicit Grant Type Risks (Deprecated)

The Implicit Grant returns the access token directly in the URL fragment after redirect. This was designed for SPAs but has been **removed from OAuth 2.1** due to fundamental security flaws.

#### Vulnerabilities

| Risk | Description |
|------|-------------|
| **Token in browser history** | Access token fragments persist in browser history |
| **Token in Referer header** | When navigating from the callback page, the token leaks via `Referer` |
| **Token interception** | Man-in-the-middle attacks on TLS-terminated connections |
| **Token leakage to third parties** | JavaScript from CDNs, extensions, or trackers can read the fragment |
| **No client authentication** | The implicit grant cannot authenticate the client |

**Vulnerable Flow:**
```
User → Client: "Log in with Google"
Client → Auth Server: /authorize?response_type=token&client_id=123&redirect_uri=...
Auth Server → Browser: Redirect with #access_token=eyJhbG...
                     ⚠️ Token visible in URL fragment!
```

**Attack: Token Theft via Referer Header**
```html
<!-- attacker's page loads OAuth redirect -->
<img src="https://client-app.com/oauth/callback#access_token=stolen" />
<!-- When the browser navigates, Referer header leaks the fragment -->
```

**Fixed — Use Authorization Code + PKCE Instead:**
```
User → Client: "Log in with Google"
Client → Auth Server: /authorize?response_type=code&client_id=123&redirect_uri=...
                      &code_challenge=sha256(verifier)&code_challenge_method=S256
Auth Server → Browser: Redirect with ?code=abc123
Client → Auth Server: POST /token with code + code_verifier
Auth Server → Client: {"access_token":"eyJhbG...","refresh_token":"..."}
```

#### OAuth 2.1 Changes (2023+)

| Deprecated in 2.1 | Mandated in 2.1 |
|-------------------|-----------------|
| Implicit Grant | Authorization Code Grant |
| Resource Owner Password Credentials Grant | PKCE for all public clients |
| Non-HTTPS redirect URIs | Exact redirect URI matching |
| Bearer token in URL query | — |

---

### 2. Redirect URI Manipulation

Redirect URI manipulation is the most exploited OAuth vulnerability class. An attacker crafts a request with a modified `redirect_uri` that points to their controlled server, intercepting the authorization code.

#### Attack Vectors

**Open Redirect + OAuth:**
```
https://auth-server.com/authorize?response_type=code&client_id=123
&redirect_uri=https://client-app.com/oauth/callback?next=https://evil.com
```
If the server doesn't validate the full redirect URI, the code leaks to `evil.com`.

**Path Traversal in Redirect URI:**
```
https://auth-server.com/authorize?response_type=code&client_id=123
&redirect_uri=https://client-app.com.evil.com/oauth/callback
```
Subdomain confusion — if validation uses suffix matching.

**URI Scheme Confusion:**
```
https://auth-server.com/authorize?response_type=code&client_id=123
&redirect_uri=https://evil.com/oauth/callback
```
If the server only validates the hostname starts with `client-app.com`.

**Vulnerable Redirect URI Validation (Bad):**
```javascript
// 🔴 VULNERABLE: startsWith allows subdomain takeover
if (redirectUri.startsWith('https://client-app.com')) {
    // Accepts: https://client-app.com.evil.com/...
}
```

**Secure Redirect URI Validation (Good):**
```javascript
// ✅ SAFE: Exact match or parsed URL comparison
const ALLOWED = new URL('https://client-app.com/oauth/callback');
function validateRedirect(uri) {
    try {
        const parsed = new URL(uri);
        return parsed.origin === ALLOWED.origin 
            && parsed.pathname === ALLOWED.pathname
            && parsed.protocol === 'https:';
    } catch {
        return false;
    }
}
```

---

### 3. CSRF with State Parameter

Without a proper `state` parameter, an attacker can perform a CSRF attack against the OAuth flow — binding their own account to the victim's session.

**Attack Scenario:**
1. Attacker creates account on OAuth client using their own social login
2. Attacker captures the authorization code from their own successful flow
3. Attacker crafts a URL that injects their authorization code into the victim's session:
   `https://client-app.com/oauth/callback?code=ATTACKER_CODE`
4. Victim clicks the link → client binds attacker's social account to victim's session

**Vulnerable Code (State Missing):**
```javascript
// 🔴 VULNERABLE: No state parameter
app.get('/auth/login', (req, res) => {
    const authUrl = `https://auth-server.com/authorize?response_type=code&client_id=123&redirect_uri=${CALLBACK}`;
    res.redirect(authUrl); // State not sent!
});

app.get('/oauth/callback', async (req, res) => {
    const { code } = req.query;
    const tokens = await exchangeCode(code);
    const user = await getIdentity(tokens.access_token);
    req.session.userId = user.id; // ⚠️ No CSRF check!
});
```

**Fixed Code (State Required):**
```javascript
// ✅ SAFE: State parameter with cryptographic binding
const crypto = require('crypto');

app.get('/auth/login', (req, res) => {
    const state = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = state; // Store for verification
    
    const authUrl = `https://auth-server.com/authorize?response_type=code&client_id=123&state=${state}&redirect_uri=${CALLBACK}`;
    res.redirect(authUrl);
});

app.get('/oauth/callback', async (req, res) => {
    const { code, state } = req.query;
    
    // ✅ Verify state to prevent CSRF
    if (!state || state !== req.session.oauthState) {
        return res.status(403).send('CSRF detected');
    }
    delete req.session.oauthState;
    
    const tokens = await exchangeCode(code);
    const user = await getIdentity(tokens.access_token);
    req.session.userId = user.id;
});
```

---

### 4. PKCE Misuse

PKCE (Proof Key for Code Exchange, pronounced "pixie") was designed to protect authorization code interception on mobile and native apps. It adds a dynamic secret (`code_verifier`) that only the client knows.

#### PKCE Implementation Pitfalls

| Mistake | Impact |
|---------|--------|
| **Not validating code_verifier** | Server accepts code without PKCE check |
| **Using `plain` transform** | No S256 hashing means static verifier is visible |
| **Reusing code_verifier** | Makes replay attacks possible |
| **Storing verifier insecurely** | SharedPreferences / localStorage leak |
| **Switching to implicit grant** | "PKCE is complex, let's use implicit" — but implicit is deprecated |

**PKCE Flow (Correct):**
```javascript
// ✅ Generate code_verifier and code_challenge
const crypto = require('crypto');

function base64URLEncode(buffer) {
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function generatePKCE() {
    const verifier = base64URLEncode(crypto.randomBytes(32));
    const challenge = base64URLEncode(
        crypto.createHash('sha256').update(verifier).digest()
    );
    return { verifier, challenge };
}

// Step 1: Authorization request with code_challenge
const { verifier, challenge } = generatePKCE();
req.session.pkceVerifier = verifier; // Store for later

const authUrl = `https://auth-server.com/authorize?
  response_type=code&client_id=123&
  code_challenge=${challenge}&
  code_challenge_method=S256&
  redirect_uri=${CALLBACK}`;

// Step 2: Exchange code with code_verifier
app.get('/oauth/callback', async (req, res) => {
    const { code } = req.query;
    
    const tokenResponse = await fetch('https://auth-server.com/token', {
        method: 'POST',
        body: JSON.stringify({
            grant_type: 'authorization_code',
            code,
            client_id: '123',
            code_verifier: req.session.pkceVerifier, // ✅ Required!
            redirect_uri: CALLBACK
        })
    });
    
    const tokens = await tokenResponse.json();
    // ... proceed with tokens
});
```

---

### 5. Token Leakage

Access tokens and refresh tokens are equivalent to passwords — anyone possessing a valid token can access the resources it protects.

#### Token Leakage Vectors

| Vector | Description |
|--------|-------------|
| **URL fragment leakage** | Access token in `#fragment` leaks via Referer |
| **Logs** | Tokens logged in server access logs or error traces |
| **Browser storage** | localStorage accessible by any script from same origin |
| **Mobile app screenshots** | OS screenshot of token on screen during redirect |
| **Deep link hijacking** | Malicious apps intercepting custom scheme URIs |
| **Token in query string** | `?access_token=...` leaks via server logs and Referer |
| **Refresh token rotation** | Without rotation, stolen refresh tokens are forever valid |

**Vulnerable Token Storage:**
```javascript
// 🔴 VULNERABLE: Storing tokens in localStorage
localStorage.setItem('access_token', token);
localStorage.setItem('refresh_token', refreshToken);
// Any XSS on this domain can steal all tokens!

// 🔴 VULNERABLE: Passing token in URL
fetch(`/api/user?token=${token}`)
// Token ends up in server logs, browser history, proxy logs
```

**Secure Token Handling:**
```javascript
// ✅ SAFE: Use HttpOnly cookies for tokens
document.cookie = `access_token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/api`;

// ✅ SAFE: Authorization header (Bearer token)
fetch('/api/user', {
    headers: { 'Authorization': `Bearer ${token}` }
});
```

---

## Prevention Checklist

```
✅ OAUTH 2.0 SECURITY CHECKLIST:
- Use Authorization Code flow with PKCE — NEVER implicit grant
- Always include and validate a cryptographic 'state' parameter
- Perform exact match on redirect_uri (not prefix/suffix/regex)
- Require HTTPS for ALL redirect URIs
- Validate code_challenge_method = S256 (not 'plain')
- Never log tokens or authorization codes
- Store tokens server-side in HttpOnly, Secure, SameSite cookies
- Implement refresh token rotation (old token invalidated on use)
- Set token expiration (access tokens: 1h max; refresh tokens: rotate)
- Validate scope — don't accept elevated permissions without consent
- Bind authorization codes to client_id and redirect_uri
- Rate-limit token endpoints to prevent brute-force
- Use sender-constrained tokens (DPoP, mTLS) for high-security apps
- Monitor for anomalous token usage patterns
```

---

## Real-World CVEs & Incidents

| Vulnerability | CVE / Incident | Impact |
|---------------|---------------|--------|
| **Booking.com OAuth ATO** | Salt Labs 2023 | Account takeover via OAuth implementation flaw in social login |
| **Facebook OAuth ATO** | Y. Sammouda 2022 | Login CSRF via missing state validation on Facebook Login |
| **Microsoft/GitHub OAuth Redirection** | Proofpoint 2026 | Redirect URI abuse enables phishing and malware delivery |
| **Expo OAuth Vulnerability** | Salt Security 2023 | Hundreds of apps using Expo framework vulnerable to OAuth attack |
| **Google OAuth Login CSRF** | Bug bounty 2018 | Missing state in Google Sign-In flow enabled account takeover |
| **PayPal OAuth Scope Escalation** | Bug bounty 2019 | Scope validation bypass allowed elevated API access |
| **Keycloak redirect_uri Validation Bypass** | CVE-2023-6291 | URL-parsing desync bypassed allowed redirect hosts → authorization code / access token theft |
| **Slack OAuth Token Theft** | Bug bounty 2021 | Redirect URI path traversal enabled token interception |

### Case Study 1: Booking.com Account Takeover (2023)

Salt Labs discovered an OAuth implementation vulnerability in Booking.com's social login. The flaw allowed an attacker to **take over any user account** by manipulating the OAuth state parameter. The `state` parameter was generated client-side and not cryptographically bound to the session, enabling an attacker to:

1. Initiate OAuth login with their own Google account
2. Capture the `state` parameter
3. Trick victim into using the attacker's `state`
4. Bind attacker's social account to victim's Booking.com account

**Source:** https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com

### Case Study 2: Microsoft OAuth Redirection Abuse (2026)

Microsoft Threat Intelligence reported that threat actors were actively exploiting OAuth redirection mechanisms in government and public-sector organizations. The attack used:

1. Silent OAuth authentication flows with intentionally invalid scopes
2. Redirect URI manipulation to route tokens to attacker-controlled endpoints
3. Harvested tokens used for lateral movement and data exfiltration

This campaign affected **multiple government agencies** across North America and Europe.

**Source:** https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/

### Case Study 3: OAuth 2.0 Redirect URI Validation Flaws (2023 Research)

A large-scale study published in ACM (Innocenti et al., 2023) analyzed OAuth 2.0 implementations across **over 200 OAuth providers** and found that:

- **64% of providers** had inadequate redirect URI validation
- **27%** accepted redirect URIs with different hosts if the path matched
- **12%** allowed open redirect patterns in the redirect URI
- **8%** had no redirect URI validation at all

**Source:** https://dl.acm.org/doi/fullHtml/10.1145/3627106.3627140

---

## Testing for OAuth Vulnerabilities

**Authorization request tampering:**
```
Manipulate:
- redirect_uri to different origin/path
- response_type from 'code' to 'token' (downgrade to implicit)
- scope to elevated permissions
- state to known value or remove it
```

**Code injection check:**
```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=ATTACKER_CODE&client_id=123&redirect_uri=https://client.com/callback
```

**Tools:**
- Burp Suite — OAuth scanning, interception, replay
- oauth2_proxy security scanner
- OWASP ZAP — OAuth add-on
- Custom curl scripts for redirect URI fuzzing

---

## References

- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2.0_Cheat_Sheet.html)
- [PortSwigger OAuth Vulnerabilities](https://portswigger.net/web-security/oauth)
- [OAuth 2.1 Authorization Framework (RFC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 6819 — OAuth 2.0 Threat Model](https://datatracker.ietf.org/doc/html/rfc6819)
- [Hidden OAuth Attack Vectors (PortSwigger Research)](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OAuth 2.0 vs 2.1 Migration Guide](https://aembit.io/blog/oauth-2-1-guide-migration-security/)
