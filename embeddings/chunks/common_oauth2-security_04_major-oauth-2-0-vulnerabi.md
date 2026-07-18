---
source: "common/oauth2-security.md"
title: "OAuth 2.0 Security — Implicit Grant, Redirect URI, CSRF, PKCE, Token Leakage"
heading: "Major OAuth 2.0 Vulnerability Categories"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [checklist, common-vuln, cves, major, oauth, prevention, real-world, vibe, what]
chunk: 4/8
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