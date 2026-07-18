---
source: "common/websocket.md"
title: "WebSocket Security Vulnerabilities"
heading: "Secure Code Fix"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
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