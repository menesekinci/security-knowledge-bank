#!/usr/bin/env python3
"""Generate L1 planned vulnerability docs (quality templates with real CVE refs)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DOCS: dict[str, str] = {}

DOCS["common/websocket.md"] = r'''# WebSocket Security

> **Severity:** High
> **CWE:** CWE-1385 (Missing Origin Validation in WebSockets), CWE-352 (CSRF-class issues), CWE-319
> **AI Generation Risk:** High — tutorials show bare `ws`/`socket.io` servers without origin or auth checks

---

## Vulnerability Explanation

WebSockets upgrade an HTTP connection to a long-lived bidirectional channel. Common failures:

1. **Missing / weak Origin checks** — browsers send `Origin` on browser-initiated WS; servers that ignore it enable **Cross-Site WebSocket Hijacking (CSWSH)** when cookies authenticate the socket.
2. **Auth only on HTTP page, not on WS handshake** — attacker page opens `wss://victim/app` with victim cookies.
3. **No message schema validation** — JSON commands executed raw → injection / IDOR over the socket.
4. **Cleartext `ws://` in production** — MITM of commands and tokens.
5. **Over-broad CORS + WS** — confused deputies when mixed with cookie sessions.

Unlike REST, there is no automatic CSRF token on every WS frame; security must be explicit at handshake and per-message.

---

## How AI / Vibe Coding Generates This

AI copies chat/tutorial samples:

```js
// Typical AI output
const wss = new WebSocket.Server({ server });
wss.on('connection', (socket) => {
  socket.on('message', (msg) => handle(JSON.parse(msg)); // no auth, no schema
});
```

Models rarely add: origin allowlist, session re-validation, per-message authorization, rate limits, or max payload size.

---

## Vulnerable Code Example

```javascript
// Node + ws — VULNERABLE
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 }); // no verifyClient

wss.on('connection', (ws, req) => {
  // trusts cookie session implicitly via shared process state
  ws.on('message', (raw) => {
    const cmd = JSON.parse(raw);
    db.run(cmd.sql); // attacker-controlled over hijacked socket
  });
});
```

```python
# FastAPI / Starlette-style anti-pattern
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()  # no Origin / user check
    while True:
        data = await ws.receive_json()
        await handle_privileged(data)
```

---

## Secure Code Fix

```javascript
const ALLOWED = new Set(['https://app.example.com']);

const wss = new WebSocket.Server({
  server,
  verifyClient(info, cb) {
    const origin = info.origin || '';
    if (!ALLOWED.has(origin)) return cb(false, 403, 'bad origin');
    const user = sessionFromCookie(info.req);
    if (!user) return cb(false, 401, 'auth');
    info.req.user = user;
    cb(true);
  },
});

wss.on('connection', (ws, req) => {
  ws.on('message', (raw) => {
    const msg = parseAndValidate(raw); // zod/jsonschema
    authorize(req.user, msg);
    handle(msg);
  });
});
```

Checklist principles: authenticate handshake, authorize every message, validate schema, size limits, idle timeouts, prefer `wss://`, ticketing (short-lived WS tokens) over long-lived cookie-only sockets.

---

## Prevention Checklist

- [ ] Allowlist `Origin` (and reject missing Origin for browser clients when appropriate)
- [ ] Re-bind identity at upgrade (session / JWT / ticket); do not assume page auth alone
- [ ] Per-message authorization (IDOR-safe resource IDs)
- [ ] Schema validation + max frame size + rate limit
- [ ] Use `wss://` in production; HSTS on the HTTP side
- [ ] CSRF strategy if cookie auth: SameSite cookies + origin check + optional ticket
- [ ] Log disconnects / auth failures; monitor connection storms

---

## Real-World CVEs / References

| Ref | Notes |
|-----|--------|
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets |
| [PortSwigger — Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) | Canonical CSWSH methodology |
| [OWASP HTML5 Security — WebSockets](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html) | Hardening notes |
| Application bugs often tracked as product CVEs when origin/auth missing (review vendor advisories case-by-case) | |

---

## Vibe-Coding Red Flags

- `new WebSocket.Server({ port })` with no `verifyClient`
- `await ws.accept()` as first line with no user
- `JSON.parse` of WS messages into SQL/shell/eval
- Docs saying "WebSockets are not affected by CSRF" without origin discussion
- Mixing privileged admin events on the same unauthenticated socket as public chat
'''

DOCS["common/zero-day.md"] = r'''# Zero-Day / N-Day Exploits (Operational Risk)

> **Severity:** Critical (when exploitable in your stack)
> **CWE:** Context-dependent (often CWE-94, CWE-502, CWE-787, CWE-918…)
> **AI Generation Risk:** High — models recommend outdated libraries/APIs and invent "secure" patterns that predate known classes of bugs

---

## Vulnerability Explanation

| Term | Meaning |
|------|---------|
| **Zero-day** | Flaw exploited before vendor patch / public fix is available |
| **N-day** | Flaw public (CVE/advisory exists) but **you have not patched** yet |
| **0-day → 1-day** | Weaponization window after disclosure |

For vibe coding teams the dominant risk is usually **n-day + dependency lag**, not elite 0-day research:

1. AI pins old package versions from training data.
2. Generated Docker images ship unpatched base layers.
3. "Works on my machine" skips SCA/CVE gates.
4. Patch Tuesday / GitHub Advisory ignored because codegen "still works".

---

## How AI / Vibe Coding Generates This

- Suggests `log4j:log4j:1.2.17` era patterns or unmaintained forks.
- Copies Stack Overflow snippets with vulnerable default configs.
- Hallucinates that a CVE "only affects old major versions" without checking the advisory range.
- Disables scanners ("too many false positives") in generated CI.

---

## Vulnerable Operational Pattern

```yaml
# AI-generated CI — VULNERABLE process
- run: npm install  # no lockfile audit gate
- run: docker build -t app .  # no base image digest pin, no scan
# no dependabot, no OSV-Scanner, no SBOM
```

```python
# "Just make pickle work" — known dangerous class (not a specific 0-day)
model = pickle.load(open(user_path, "rb"))
```

---

## Secure Process Fix

1. **SBOM + SCA** on every build (OSV-Scanner, npm audit, pip-audit, grype).
2. **Pin digests** for base images; rebuild on CVE feeds.
3. **Emergency patch runbooks** for critical CVEs (owner, SLA, rollback).
4. **AI output review**: any new dependency must pass registry + advisory check.
5. **WAF/virtual patch** only as bridge — not substitute for upgrade.

---

## Prevention Checklist

- [ ] Automated dependency CVE gate (fail CI on Critical/High with exception process)
- [ ] Track KEV (CISA Known Exploited Vulnerabilities) against your SBOM
- [ ] Time-to-patch metrics for Critical
- [ ] Disable AI-suggested abandoned packages
- [ ] Segment internet-facing apps for faster containment
- [ ] Prefer memory-safe rewrites only where risk justifies — still patch native deps

---

## Real-World References (patch-lag / mass exploit)

| Event | ID / Ref | Lesson |
|-------|----------|--------|
| Log4Shell | [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Internet-scale n-day race; AI still proposes JNDI-era logging patterns |
| MOVEit Transfer | [CVE-2023-34362](https://nvd.nist.gov/vuln/detail/CVE-2023-34362) | Rapid mass exploitation after disclosure |
| ProxyLogon era | [CVE-2021-26855](https://nvd.nist.gov/vuln/detail/CVE-2021-26855) | Edge systems unpatched for weeks |
| CISA KEV Catalog | [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Prioritize actively exploited n-days |

No exploit details are provided here — treat disclosures as **patch signals**.

---

## Vibe-Coding Red Flags

- "CVE scanners are noisy, skip them"
- Generating apps without lockfiles
- Copying years-old framework major versions from blog posts
- Claiming "we're not a target" for commodity RCEs
- AI saying a package is safe because "it's popular"
'''

# C/C++ docs
DOCS["languages/c-cpp/double-free.md"] = r'''# Double Free & Heap Corruption

> **Severity:** Critical
> **CWE:** CWE-415 (Double Free), CWE-416 (Use After Free related)
> **AI Generation Risk:** High — AI mismanages ownership across branches/errors

---

## Vulnerability Explanation

Calling `free`/`delete` twice on the same pointer corrupts allocator metadata. Effects range from crash to **arbitrary write / RCE** depending on heap implementation and subsequent allocations. Closely tied to use-after-free when the pointer is not nulled.

---

## How AI / Vibe Coding Generates This

```c
void handler(char *p) {
  if (err) free(p);
  // AI "cleans up" again at end
  free(p); // double free on error path
}
```

Models duplicate cleanup in multiple exit paths without a single owner.

---

## Vulnerable Code Example

```c
char *buf = malloc(n);
if (!buf) return;
if (parse(buf) < 0) {
    free(buf);
    goto done;
}
process(buf);
free(buf);
done:
free(buf); // BUG if parse failed
```

---

## Secure Code Fix

```c
char *buf = malloc(n);
if (!buf) return;
if (parse(buf) < 0) {
    free(buf);
    buf = NULL;
    return;
}
process(buf);
free(buf);
buf = NULL;
```

C++: prefer `std::unique_ptr` / `std::vector` — single owner, no manual double free.

---

## Prevention Checklist

- [ ] One owner per allocation; null after free
- [ ] Prefer RAII (`unique_ptr`, containers)
- [ ] ASan/Valgrind in CI
- [ ] No raw `malloc` in new C++ without review

---

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| [CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) | sudo heap-based buffer overflow (heap discipline class) |
| [CVE-2015-0235](https://nvd.nist.gov/vuln/detail/CVE-2015-0235) | GHOST — glibc heap overflow class |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free |

---

## Vibe-Coding Red Flags

- Multiple `free(p)` in function
- Cleanup in both `goto` paths and fallthrough
- C code "translated" from GC languages by AI without ownership model
'''

DOCS["languages/c-cpp/uninitialized-memory.md"] = r'''# Uninitialized Memory

> **Severity:** High
> **CWE:** CWE-908 (Use of Uninitialized Resource), CWE-457
> **AI Generation Risk:** High — stack structs used before assignment

---

## Vulnerability Explanation

Reading stack/heap memory before initialization leaks prior contents (**info disclosure**) or causes undefined behavior that optimizers weaponize. Classic kernel and crypto bugs involve uninitialized padding.

---

## How AI / Vibe Coding Generates This

```c
struct cfg c;
c.port = 8080; // other fields garbage
start_server(&c);
```

AI initializes "the field it cares about" only.

---

## Vulnerable Code Example

```c
int auth(char *pwd) {
  char secret[32];
  // forgot to load secret
  return memcmp(pwd, secret, 32) == 0; // UMR — leaks / nondeterministic
}
```

---

## Secure Code Fix

```c
struct cfg c;
memset(&c, 0, sizeof c); // or = {0};
c.port = 8080;

// C++
cfg c{};
```

For secrets: always write full buffer; use `explicit_bzero`/`SecureZeroMemory` when wiping.

---

## Prevention Checklist

- [ ] `= {0}` / value initialization
- [ ] `-Wuninitialized` + treat as error
- [ ] MSan in CI for C/C++
- [ ] No partial struct updates without zeroing

---

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) | Heartbleed — over-read of buffer (related memory safety class) |
| [CWE-908](https://cwe.mitre.org/data/definitions/908.html) | Uninitialized resource |

---

## Vibe-Coding Red Flags

- Struct declared then only one field set
- "It works on my machine" with stack garbage luck
- Crypto code without full buffer init
'''

DOCS["languages/c-cpp/type-confusion.md"] = r'''# Type Confusion (C/C++)

> **Severity:** Critical
> **CWE:** CWE-843 (Access of Resource Using Incompatible Type)
> **AI Generation Risk:** Medium–High — unsafe casts to "fix compile errors"

---

## Vulnerability Explanation

Interpreting memory as the wrong type (especially in C++ inheritance / `void*` APIs) breaks invariants → memory corruption or logic bypass. Common in parsers, IPC, and JIT boundaries.

---

## How AI / Vibe Coding Generates This

```cpp
Base *b = factory();
auto *d = static_cast<Derived*>(b); // AI assumes type without check
d->special();
```

Or C:

```c
void *p = read_msg();
struct Admin *a = p; // no tag check
```

---

## Vulnerable Code Example

```cpp
void handle(Message *m) {
  if (m->type == T_A) {
    auto *a = static_cast<MsgA*>(m);
    use(a->field);
  }
  // missing default; corrupted type field → wrong cast
}
```

---

## Secure Code Fix

- Discriminated unions with exhaustive switches
- `dynamic_cast` when RTTI appropriate; prefer `std::variant`
- Explicit tagged protocols for IPC
- Fuzz parsers

```cpp
std::visit([](auto& msg) { ... }, variant_msg);
```

---

## Prevention Checklist

- [ ] No `reinterpret_cast` without threat review
- [ ] Tagged messages + length checks
- [ ] Fuzzing + ASan/UBSan
- [ ] Avoid polymorphic downcasts without checks

---

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| Browser engine type confusion CVEs are routine (e.g. V8/Chrome advisories) — track [Chrome releases](https://chromereleases.googleblog.com/) | |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Type confusion |

---

## Vibe-Coding Red Flags

- `static_cast` to silence compiler
- `void*` soup in new C++ code
- IPC structs without version/tag fields
'''

DOCS["languages/c-cpp/insecure-random.md"] = r'''# Insecure Randomness (C/C++)

> **Severity:** High
> **CWE:** CWE-330, CWE-338
> **AI Generation Risk:** Very High — AI defaults to `rand()` / `srand(time(NULL))`

---

## Vulnerability Explanation

`rand()`, constant seeds, or LCG PRNGs are **not** for security tokens, session IDs, key material, or lottery logic. Predictable values enable session hijack and CSRF token guessing.

---

## How AI / Vibe Coding Generates This

```c
srand(time(NULL));
int token = rand();
```

Appears in countless tutorials; models reproduce it for "OTP" and "API keys".

---

## Vulnerable Code Example

```c
char session_id[9];
sprintf(session_id, "%08x", rand());
```

---

## Secure Code Fix

```c
#include <fcntl.h>
#include <unistd.h>

int secure_random_bytes(void *buf, size_t n) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) return -1;
  size_t off = 0;
  while (off < n) {
    ssize_t r = read(fd, (char*)buf + off, n - off);
    if (r <= 0) { close(fd); return -1; }
    off += (size_t)r;
  }
  close(fd);
  return 0;
}
```

C++17+: `std::random_device` carefully (implementation-defined); prefer OS CSPRNG APIs (`getrandom`, `BCryptGenRandom`, `SecRandomCopyBytes`).

---

## Prevention Checklist

- [ ] Never `rand` for security
- [ ] Use OS CSPRNG
- [ ] Session IDs ≥ 128 bits entropy
- [ ] Code review ban-list: `srand`, `Random()` in .NET sense of non-crypto, etc.

---

## Real-World CVEs / References

| Ref | Notes |
|-----|--------|
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Weak PRNG |
| Historical weak PHP `session` / early Android SecureRandom incidents — prefer modern APIs | |

---

## Vibe-Coding Red Flags

- `srand(time(NULL))` anywhere near auth
- Token generation with `% 1000000`
- "Random" UUID v1 used as secret
'''

DOCS["languages/c-cpp/modern-cpp-pitfalls.md"] = r'''# Modern C++ Pitfalls (AI-Generated)

> **Severity:** High
> **CWE:** CWE-664, CWE-416, CWE-119
> **AI Generation Risk:** High — mixes C with "some" C++ without ownership

---

## Vulnerability Explanation

Modern C++ (11–23) offers RAII, smart pointers, spans, and safer containers — but AI often:

- Uses `new`/`delete` instead of `unique_ptr`
- Captures dangling references in lambdas/coroutines
- Misuses `std::string_view` / `std::span` pointing at temporaries
- Marks everything `noexcept` incorrectly
- Uses `reinterpret_cast` to "make it compile"

---

## How AI / Vibe Coding Generates This

```cpp
std::string_view sv = std::string("temp"); // dangling
std::thread t([&]{ use(local); }); // ref to stack
t.detach();
```

---

## Vulnerable Code Example

```cpp
std::shared_ptr<T> a = std::make_shared<T>();
std::shared_ptr<T> b = a;
a.reset();
// cycles with shared_ptr without weak_ptr → leaks; or incorrect raw observe
```

```cpp
async_task([data = vec.data()]{ /* vec destroyed */ });
```

---

## Secure Code Fix

- `std::unique_ptr` by default; `shared_ptr` only for shared ownership
- `std::weak_ptr` for cycles
- Ensure lambda captures own data (`std::vector` by value / `shared_ptr`)
- `std::span` only with proven lifetime
- Enable `-Wall -Wextra -Werror`, clang-tidy, lifetime analysis

---

## Prevention Checklist

- [ ] No raw owning pointers in new code
- [ ] clang-tidy `cppcoreguidelines-*`
- [ ] ASan/TSan for concurrency
- [ ] Review all `string_view` returns

---

## Real-World CVEs / References

| Ref | Notes |
|-----|--------|
| [C++ Core Guidelines — Resource management](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines) | |
| Lifetime-related CVEs appear across browsers/OS kernels — class risk | |

---

## Vibe-Coding Red Flags

- `new` without matching smart pointer
- `string_view` stored in objects
- `detach()` on threads with refs
- Copy-paste C APIs into C++ without RAII wrappers
'''

# C#
DOCS["languages/csharp/crypto-pitfalls.md"] = r'''# .NET Cryptography Pitfalls

> **Severity:** High
> **CWE:** CWE-327, CWE-328, CWE-330, CWE-916
> **AI Generation Risk:** High — MD5/SHA1, ECB, static IVs, `Random` for tokens

---

## Vulnerability Explanation

AI-generated .NET often uses obsolete crypto:

- `MD5`/`SHA1` for passwords
- `DES`/`RC2`/`Rijndael` managed badly
- `AES` with ECB or fixed IV
- `System.Random` for security tokens
- Hard-coded keys in `appsettings.json`

---

## How AI / Vibe Coding Generates This

```csharp
var hash = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
```

```csharp
var token = new Random().Next(100000, 999999).ToString();
```

---

## Vulnerable Code Example

```csharp
public static string Encrypt(string plain, byte[] key) {
    using var aes = Aes.Create();
    aes.Mode = CipherMode.ECB; // bad
    aes.Key = key;
    // no random IV
    ...
}
```

---

## Secure Code Fix

```csharp
// Passwords
var hash = passwordHasher.HashPassword(user, password); // ASP.NET Identity

// Tokens
var bytes = RandomNumberGenerator.GetBytes(32);

// AES-GCM
using var aes = new AesGcm(key);
aes.Encrypt(nonce, plaintext, ciphertext, tag);
```

Prefer **AES-GCM**, **PBKDF2/Argon2/bcrypt** via vetted libs, **Data Protection API** for app secrets at rest.

---

## Prevention Checklist

- [ ] Ban MD5/SHA1 for security
- [ ] `RandomNumberGenerator` for secrets
- [ ] Data Protection for cookies/tokens at rest
- [ ] No hard-coded keys in source
- [ ] TLS 1.2+ only

---

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| [CVE-2024-0057](https://nvd.nist.gov/vuln/detail/CVE-2024-0057) | .NET X.509 certificate validation issues (crypto/PKI class) |
| [Microsoft — Cryptographic Practices](https://learn.microsoft.com/en-us/dotnet/standard/security/cryptographic-services) | |

---

## Vibe-Coding Red Flags

- `MD5.Create` near passwords
- `new Random()` for session IDs
- ECB mode
- Keys committed in repo
'''

DOCS["languages/csharp/unity-security.md"] = r'''# Unity Game Client Security

> **Severity:** Medium–High (context: cheat, IP, account abuse)
> **CWE:** CWE-602 (Client-Side Enforcement), CWE-311
> **AI Generation Risk:** High — AI puts authoritative game logic on client

---

## Vulnerability Explanation

Unity clients are **hostile environments**. AI-generated multiplayer samples:

- Trust client for scores, inventory, purchases
- Store secrets in `PlayerPrefs` / Assets
- Use easily hookable IL code without server checks
- Insecure network serialization

Server must authoritatively validate all sensitive actions.

---

## How AI / Vibe Coding Generates This

```csharp
// AI "inventory system"
playerGold += reward; // client-side
Save(playerGold);
```

---

## Vulnerable Code Example

```csharp
public void BuyItem(int itemId) {
    if (PlayerPrefs.GetInt("gold") >= price) {
        PlayerPrefs.SetInt("gold", gold - price);
        Grant(itemId); // fully client authoritative
    }
}
```

---

## Secure Code Fix

- Authoritative server (PlayFab, custom backend, dedicated server)
- Signed receipts for IAP
- Don't store long-lived secrets in client
- Assume memory editors exist

```csharp
// Client only sends intent
await api.PurchaseAsync(itemId, sessionToken);
// Server validates currency, grants item
```

---

## Prevention Checklist

- [ ] No trusted economy on client
- [ ] Server-side validation for anti-cheat critical actions
- [ ] Secure storage only for non-sensitive prefs
- [ ] TLS to game backends
- [ ] Review IL2CPP vs Mono exposure as threat model requires

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [OWASP MASVS](https://mas.owasp.org/) | Mobile/game client classes |
| Unity forums / security blogs on client authority | Common cheat patterns |

---

## Vibe-Coding Red Flags

- "Multiplayer" demo without server
- Secrets in ScriptableObjects shipped in builds
- Client-calculated match results accepted by server
'''

DOCS["languages/csharp/process-injection.md"] = r'''# Process Injection & P/Invoke Risks (.NET)

> **Severity:** High–Critical (malware / EDR context)
> **CWE:** CWE-94, CWE-114
> **AI Generation Risk:** Medium — AI copies offensive snippets into "tools"

---

## Vulnerability Explanation

`DllImport`, `LoadLibrary`, writing to external process memory, or generating native shells from C# appears in AI answers for automation — and in malware. Even legitimate apps must:

- Avoid executing untrusted native code
- Not disable security features
- Not load plugins from world-writable paths

---

## How AI / Vibe Coding Generates This

AI pastes process hollowing / `CreateRemoteThread` samples when user asks for "inject DLL for debugging".

---

## Vulnerable Code Example

```csharp
[DllImport("kernel32.dll")]
static extern IntPtr OpenProcess(int access, bool inherit, int pid);
// ... WriteProcessMemory / CreateRemoteThread against arbitrary PID
```

Loading `Assembly.Load(byte[])` from the network without trust is also code injection.

---

## Secure Code Fix

- Don't implement injection APIs in production business apps
- Plugin models: strong-name + path allowlist + sandbox
- `Assembly.Load` only from trusted signed sources
- Prefer IPC over injection for automation

---

## Prevention Checklist

- [ ] Code review ban on remote thread / process memory APIs unless security product
- [ ] Plugin signing
- [ ] No download-and-`Assembly.Load`
- [ ] EDR-friendly design

---

## Real-World References

| Ref | Notes |
|-----|--------|
| MITRE ATT&CK — Process Injection | Technique classification |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Code injection |

---

## Vibe-Coding Red Flags

- User prompt "make a DLL injector" answered with copy-paste malware
- `Assembly.Load(webClient.DownloadData(...))`
- Tools that disable AMSI/ETW in AI snippets
'''

DOCS["languages/php/crypto-misuse.md"] = r'''# PHP Cryptography Misuse

> **Severity:** High
> **CWE:** CWE-327, CWE-916, CWE-328
> **AI Generation Risk:** Very High — `md5($password)`, `sha1`, Mcrypt

---

## Vulnerability Explanation

Legacy PHP crypto in AI training data:

- `md5`/`sha1` password storage
- `mcrypt` (removed)
- Home-rolled AES without HMAC / IV handling
- Weak `rand`/`mt_rand` for tokens

Use `password_hash` / `password_verify` (bcrypt/argon2) and `random_bytes`.

---

## How AI / Vibe Coding Generates This

```php
$hash = md5($password);
// later
if ($hash === md5($_POST['password'])) { ... }
```

---

## Vulnerable Code Example

```php
function api_token() {
    return md5(uniqid()); // predictable / weak
}
```

---

## Secure Code Fix

```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
if (password_verify($password, $hash)) { ... }

$token = bin2hex(random_bytes(32));
```

For encryption: `libsodium` (`sodium_crypto_secretbox`) or carefully reviewed openssl wrappers.

---

## Prevention Checklist

- [ ] `password_hash` only for passwords
- [ ] `random_bytes` for tokens
- [ ] No mcrypt
- [ ] Constant-time compare for raw tokens (`hash_equals`)

---

## Real-World CVEs / References

| Ref | Notes |
|-----|--------|
| [PHP password_hash](https://www.php.net/manual/en/function.password-hash.php) | |
| [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | Password hash with insufficient computational effort |

---

## Vibe-Coding Red Flags

- `md5($password)`
- `uniqid` as session token
- Custom "encrypt" with XOR
'''

DOCS["languages/ruby/session-security.md"] = r'''# Ruby / Rails Session Security

> **Severity:** High
> **CWE:** CWE-384, CWE-613, CWE-565
> **AI Generation Risk:** High — cookie store secrets, no rotation

---

## Vulnerability Explanation

Rails defaults evolved; AI still emits:

- Weak `secret_key_base`
- CookieStore with oversized sensitive data
- Missing `secure`/`httponly`/`SameSite` in custom setups
- No session rotation on login

---

## How AI / Vibe Coding Generates This

```ruby
# config without secure cookies in production
Rails.application.config.session_store :cookie_store, key: '_app'
```

Stores entire user hash including roles in cookie without server-side revocation.

---

## Vulnerable Code Example

```ruby
session[:user_id] = user.id
# no reset_session on privilege change
session[:admin] = true # client-visible cookie store abuse if not integrity-protected properly
```

---

## Secure Code Fix

```ruby
reset_session
session[:user_id] = user.id

# config/environments/production.rb
config.force_ssl = true
# use solid secret_key_base from credentials/ENV
# consider cache/redis store for server-side sessions when revocation needed
```

---

## Prevention Checklist

- [ ] `reset_session` on login
- [ ] Rotate secrets; never commit `secret_key_base`
- [ ] SSL + Secure cookies
- [ ] Minimal session payload
- [ ] CSRF protection enabled

---

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| [CVE-2013-0156](https://nvd.nist.gov/vuln/detail/CVE-2013-0156) | Rails parameter parsing / YAML — shows framework auth surface risk |
| [Rails Security Guide](https://guides.rubyonrails.org/security.html) | Sessions chapter |

---

## Vibe-Coding Red Flags

- Hard-coded `secret_key_base`
- Session fixation (no reset on login)
- Putting PII blobs in cookie store
'''

DOCS["languages/ruby/redos.md"] = r'''# Regular Expression Denial of Service (ReDoS) in Ruby

> **Severity:** High
> **CWE:** CWE-1333
> **AI Generation Risk:** High — "clever" nested quantifiers for validation

---

## Vulnerability Explanation

Pathological regex + untrusted input → catastrophic backtracking → CPU DoS. Ruby's Onigmo engine is a frequent ReDoS target in Rails parameter validation and web scrapers.

---

## How AI / Vibe Coding Generates This

```ruby
email_regex = /^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+$/
```

Or nested `/(a+)+$/` style patterns for "flexible parsing".

---

## Vulnerable Code Example

```ruby
def valid_slug?(s)
  !!(s =~ /^(a+)+$/)
end
valid_slug?("a" * 40 + "!")
```

---

## Secure Code Fix

- Prefer possessive quantifiers / atomic groups where appropriate
- Use parser libraries, not mega-regex
- Timeout regex evaluation
- Length limits **before** regex
- Ruby 3.2+ improvements help but do not excuse bad patterns

```ruby
return false if s.length > 64
# simple character class without nesting
/\A[a-z0-9-]{1,64}\z/
```

---

## Prevention Checklist

- [ ] Input length caps
- [ ] Regex lint (recheck / rake tasks)
- [ ] Timeouts on user-provided patterns
- [ ] Fuzz validators

---

## Real-World CVEs / References

| Ref | Notes |
|-----|--------|
| [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) | |
| Multiple Rails/gem advisories historically for ReDoS — check bundler-audit | |
| [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | |

---

## Vibe-Coding Red Flags

- Nested quantifiers `(a+)+`, `(.*a){x}`
- AI "improved" email regex 3 screens long
- User-controlled regex (`Regexp.new(params[:q])`)
'''

DOCS["languages/ruby/symbol-dos.md"] = r'''# Symbol DoS (Ruby)

> **Severity:** Medium–High
> **CWE:** CWE-400
> **AI Generation Risk:** Medium — `params[:x].to_sym` everywhere

---

## Vulnerability Explanation

Historically, Ruby Symbols were not garbage-collected → converting untrusted strings to symbols exhausted memory (**Symbol DoS**). Modern Ruby GC's symbols better, but **unbounded symbol creation** and hash key pollution remain unhealthy; still avoid `to_sym` on user input.

---

## How AI / Vibe Coding Generates This

```ruby
method = params[:action].to_sym
send(method)
```

---

## Vulnerable Code Example

```ruby
data.each do |k, v|
  options[k.to_sym] = v  # attacker sends millions of unique keys
end
```

---

## Secure Code Fix

```ruby
ALLOWED = %w[show edit update].freeze
action = params[:action]
raise unless ALLOWED.include?(action)
send(action)
```

Use string keys for untrusted data; allowlist before `send`.

---

## Prevention Checklist

- [ ] No `to_sym` on raw params
- [ ] Allowlists for `send`/`public_send`
- [ ] Cap param key counts

---

## Real-World References

| Ref | Notes |
|-----|--------|
| Historical Rails/Symbol GC issues — see Ruby language changelogs | |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Uncontrolled resource consumption |

---

## Vibe-Coding Red Flags

- `params[:x].to_sym` → `send`
- Converting entire JSON keys to symbols without limits
'''

DOCS["languages/ruby/idor-rails.md"] = r'''# IDOR in Rails (Insecure Direct Object Reference)

> **Severity:** High
> **CWE:** CWE-639, CWE-284
> **AI Generation Risk:** Very High — `Model.find(params[:id])` without tenancy checks

---

## Vulnerability Explanation

Classic Rails scaffolding:

```ruby
@doc = Document.find(params[:id])
```

Any authenticated user who can guess IDs reads others' records. AI reproduces scaffold controllers without `current_user` scoping.

---

## How AI / Vibe Coding Generates This

Scaffold + Devise login is assumed "secure enough". Authorization gems omitted.

---

## Vulnerable Code Example

```ruby
def show
  @invoice = Invoice.find(params[:id])
  render json: @invoice
end
```

---

## Secure Code Fix

```ruby
def show
  @invoice = current_user.invoices.find(params[:id])
  # or policy: authorize @invoice
end
```

Use Pundit/CanCanCan; prefer UUIDs **and** authz (UUID ≠ authorization).

---

## Prevention Checklist

- [ ] Scope every query by tenant/user
- [ ] Policy tests per action
- [ ] No global `find` on user-owned resources
- [ ] Audit nested resources (`/users/:u/items/:id`)

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) | |
| Countless bug bounty Rails IDOR reports | Pattern, not one CVE |

---

## Vibe-Coding Red Flags

- Scaffold controllers unchanged
- `find` without `current_user`
- "We use UUIDs so no IDOR"
'''

DOCS["languages/kotlin/data-class-copy.md"] = r'''# Kotlin Data Class `copy()` Risks

> **Severity:** Medium
> **CWE:** CWE-212, CWE-359
> **AI Generation Risk:** High — `user.copy(role = …)` from request bodies

---

## Vulnerability Explanation

Kotlin `data class` generates `copy()` with defaults for unspecified fields. AI maps HTTP bodies into `copy()` allowing attackers to set `isAdmin=true` if the binder includes extra fields (**mass assignment** flavor).

---

## How AI / Vibe Coding Generates This

```kotlin
val updated = existing.copy(
  name = req.name,
  role = req.role // attacker-controlled
)
```

---

## Vulnerable Code Example

```kotlin
data class User(val id: Long, val email: String, val role: String)

fun update(id: Long, body: User) {
  val u = repo.find(id)
  repo.save(u.copy(email = body.email, role = body.role))
}
```

---

## Secure Code Fix

```kotlin
fun update(id: Long, body: UpdateUserRequest) {
  val u = repo.find(id)
  repo.save(u.copy(email = body.email)) // role not in DTO
}
```

Separate request DTOs; never bind domain entity directly.

---

## Prevention Checklist

- [ ] Dedicated request DTOs
- [ ] Deny-list sensitive fields
- [ ] Server-side role changes only by admins with audit
- [ ] Validation annotations on DTOs

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [OWASP Mass Assignment](https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet) | Same class |
| Spring/Kotlin Jackson binding CVEs — review framework advisories | |

---

## Vibe-Coding Red Flags

- `@RequestBody User user`
- `copy()` with entire request object
- Role/permission fields in public DTO
'''

DOCS["languages/kotlin/spring-kotlin-misconfig.md"] = r'''# Spring Boot + Kotlin Misconfiguration

> **Severity:** High
> **CWE:** CWE-16, CWE-1188
> **AI Generation Risk:** High — open actuator, debug, permitAll

---

## Vulnerability Explanation

AI-generated Spring + Kotlin samples:

- `permitAll()` for `/api/**`
- Actuator exposed without auth
- `spring.jpa.show-sql=true` in prod
- Open CORS `*`
- Devtools in production images

---

## How AI / Vibe Coding Generates This

```kotlin
http.authorizeHttpRequests { it.anyRequest().permitAll() }
```

---

## Vulnerable Code Example

```yaml
management.endpoints.web.exposure.include: "*"
spring.security.user.password: admin
```

---

## Secure Code Fix

```kotlin
http.authorizeHttpRequests {
  it.requestMatchers("/actuator/health").permitAll()
  it.requestMatchers("/actuator/**").hasRole("ADMIN")
  it.anyRequest().authenticated()
}
```

Externalize secrets; disable devtools in prod; CSRF strategy for browser clients.

---

## Prevention Checklist

- [ ] Actuator least exposure
- [ ] No default passwords
- [ ] CORS allowlist
- [ ] Profiles: `dev` vs `prod`
- [ ] Dependency CVE scan

---

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| Spring4Shell [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) | Patch posture matters |
| Actuator data leaks in real incidents | Config class risk |
| [Spring Security docs](https://docs.spring.io/spring-security/reference/) | |

---

## Vibe-Coding Red Flags

- `permitAll` skeleton left in prod
- Full actuator exposure
- Hard-coded DB passwords in `application.yml`
'''

# Solidity
DOCS["languages/solidity/integer-overflow.md"] = r'''# Integer Overflow / Underflow (Solidity)

> **Severity:** Critical (historic); Medium if `unchecked` misused on 0.8+
> **SWC:** [SWC-101](https://swcregistry.io/docs/SWC-101)
> **CWE:** CWE-190
> **AI Generation Risk:** High — AI mixes pre-0.8 patterns and reckless `unchecked`

---

## Vulnerability Explanation

Before Solidity **0.8.0**, arithmetic wrapped silently → attackers inflated balances. Since 0.8, ops revert on overflow **unless** inside `unchecked { }`. AI still:

- Generates 0.7.x code
- Puts critical math in `unchecked` "for gas"

---

## How AI / Vibe Coding Generates This

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;
function transfer(uint amt) public {
  balances[msg.sender] -= amt; // underflow → huge balance
  balances[to] += amt;
}
```

---

## Vulnerable Code Example (0.8+)

```solidity
unchecked {
  balance = balance - amount; // may wrap if amount > balance
}
```

---

## Secure Code Fix

```solidity
pragma solidity ^0.8.20;
// default checked math
require(balance >= amount, "bal");
balance -= amount;
```

Use OpenZeppelin `SafeERC20` for token ops; avoid unnecessary `unchecked`.

---

## Prevention Checklist

- [ ] Solidity ≥ 0.8.20
- [ ] Audit every `unchecked`
- [ ] Invariant tests / fuzz (Foundry)
- [ ] No hand-rolled tokens without review

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [SWC-101](https://swcregistry.io/docs/SWC-101) | |
| Multiple 2018-era token bugs from wraparound | Pre-0.8 history |

---

## Vibe-Coding Red Flags

- `pragma solidity ^0.6.0` in new code
- Blind `unchecked` for "gas golf"
- Custom ERC20 math
'''

DOCS["languages/solidity/access-control.md"] = r'''# Access Control Vulnerabilities (Solidity)

> **Severity:** Critical
> **SWC:** [SWC-105](https://swcregistry.io/docs/SWC-105), [SWC-106](https://swcregistry.io/docs/SWC-106)
> **AI Generation Risk:** Very High — missing `onlyOwner`, public `mint`/`withdraw`

---

## Vulnerability Explanation

Sensitive functions (`mint`, `withdraw`, `setOracle`, `upgradeTo`) left `public`/`external` without modifiers. AI generates "working" contracts that anyone can drain.

---

## How AI / Vibe Coding Generates This

```solidity
function withdraw() external {
  payable(msg.sender).transfer(address(this).balance);
}
```

---

## Vulnerable Code Example

```solidity
function setPrice(uint p) external {
  price = p; // no auth — oracle manipulation helper for attacker
}
```

---

## Secure Code Fix

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

function setPrice(uint p) external onlyOwner {
  price = p;
}
```

Prefer OZ `AccessControl` with roles; two-step ownership transfer.

---

## Prevention Checklist

- [ ] Every state-changing sensitive function has access control
- [ ] Tests for unauthorized calls expecting revert
- [ ] No default public upgrade hooks without auth
- [ ] Multisig for admin on mainnet

---

## Real-World References

| Incident | Notes |
|----------|--------|
| Countless "unprotected init/mint" exploits | Common post-mortems |
| [SWC-105](https://swcregistry.io/docs/SWC-105) | Unprotected Ether withdrawal |
| [OpenZeppelin AccessControl](https://docs.openzeppelin.com/contracts/5.x/access-control) | |

---

## Vibe-Coding Red Flags

- `withdraw` without modifier
- `initialize` callable twice
- Owner = EOA single key for large TVL
'''

DOCS["languages/solidity/front-running.md"] = r'''# Front-Running & MEV

> **Severity:** High
> **SWC:** [SWC-114](https://swcregistry.io/docs/SWC-114)
> **AI Generation Risk:** High — naive DEXes / commit-reveal missing

---

## Vulnerability Explanation

Public mempools let searchers reorder/insert txs. AI-coded auctions, swaps, and "first deposit wins" logic get sandwich-attacked.

---

## How AI / Vibe Coding Generates This

```solidity
function buy() external payable {
  require(msg.value >= price);
  owner = msg.sender; // raceable
}
```

---

## Vulnerable Code Example

AMM-style `swap` without slippage bounds → sandwich.

---

## Secure Code Fix

- Slippage `minOut` parameters
- Commit-reveal for bids
- Private orderflow / batch auctions where appropriate
- Deadline parameters

```solidity
function swap(uint amountIn, uint minOut, uint deadline) external {
  require(block.timestamp <= deadline);
  uint out = getAmountOut(amountIn);
  require(out >= minOut, "slippage");
  ...
}
```

---

## Prevention Checklist

- [ ] Slippage + deadline on swaps
- [ ] Design for adversarial ordering
- [ ] Avoid reward logic based solely on tx order

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [SWC-114](https://swcregistry.io/docs/SWC-114) | |
| Flashbots / MEV research literature | Ecosystem reality |

---

## Vibe-Coding Red Flags

- Swap APIs without `minOut`
- On-chain "secret" bids in plaintext calldata
- Price updates then trade in same block design flaws
'''

DOCS["languages/solidity/dos-gas.md"] = r'''# Denial of Service via Gas

> **Severity:** High
> **SWC:** [SWC-128](https://swcregistry.io/docs/SWC-128)
> **AI Generation Risk:** High — unbounded loops over arrays of users

---

## Vulnerability Explanation

```solidity
for (uint i; i < users.length; i++) {
  payable(users[i]).transfer(shares[i]);
}
```

Array growth → exceeds block gas → payouts permanently stuck.

---

## How AI / Vibe Coding Generates This

"Distribute rewards to all stakers" in one tx — classic AI sample.

---

## Secure Code Fix

- Pull-over-push payments
- Pagination / checkpoints
- Cap list sizes

```solidity
function claim() external {
  uint amt = owed[msg.sender];
  owed[msg.sender] = 0;
  (bool ok,) = msg.sender.call{value: amt}("");
  require(ok);
}
```

---

## Prevention Checklist

- [ ] No unbounded loops over user lists in one tx
- [ ] Prefer pull payments
- [ ] Gas tests with large N

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [SWC-128](https://swcregistry.io/docs/SWC-128) | DoS with block gas limit |
| Historical ICO refund loops | |

---

## Vibe-Coding Red Flags

- `for (allUsers)` + external calls
- Admin-only distribute that will brick as users grow
'''

DOCS["languages/solidity/unchecked-calls.md"] = r'''# Unchecked Low-Level Calls

> **Severity:** High
> **SWC:** [SWC-104](https://swcregistry.io/docs/SWC-104)
> **AI Generation Risk:** High — `.call{value:}("")` ignoring success

---

## Vulnerability Explanation

```solidity
addr.call{value: amt}("");
// continues even if failed
```

Funds not transferred but state already updated → accounting desync; or silent failures hide bugs.

---

## How AI / Vibe Coding Generates This

AI uses low-level `call` for "gas stipend control" without `require(success)`.

---

## Secure Code Fix

```solidity
(bool ok, ) = addr.call{value: amt}("");
require(ok, "xfer");
```

Prefer OZ `Payment.sol` patterns / `SafeERC20` for tokens. Still combine with CEI + reentrancy guards when needed ([reentrancy.md](reentrancy.md)).

---

## Prevention Checklist

- [ ] Always check low-level call return
- [ ] CEI pattern
- [ ] ReentrancyGuard on value transfers
- [ ] Prefer high-level transfer helpers carefully (know 2300 gas issues)

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [SWC-104](https://swcregistry.io/docs/SWC-104) | |
| The DAO / reentrancy post-mortems interact with call patterns | See also [reentrancy.md](reentrancy.md) |

---

## Vibe-Coding Red Flags

- `.call` without `require`
- State updates after ignored external calls
'''

DOCS["languages/solidity/weak-randomness.md"] = r'''# Weak On-Chain Randomness

> **Severity:** Critical for games/lotteries
> **SWC:** [SWC-120](https://swcregistry.io/docs/SWC-120)
> **AI Generation Risk:** Very High — `block.timestamp` / `blockhash` "RNG"

---

## Vulnerability Explanation

Validators/miners influence `block.timestamp` and short-horizon `blockhash`. AI lottery contracts using these are exploitable.

---

## How AI / Vibe Coding Generates This

```solidity
winner = players[uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % n];
```

---

## Secure Code Fix

- Chainlink VRF or similar verifiable randomness
- Commit-reveal with economic finality
- Never use block variables alone for high-value randomness

---

## Prevention Checklist

- [ ] No `block.timestamp` RNG for money
- [ ] VRF for production games
- [ ] Document trust model

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [SWC-120](https://swcregistry.io/docs/SWC-120) | |
| Multiple broken Ethereum lottery contracts historically | |

---

## Vibe-Coding Red Flags

- `keccak256(block.timestamp)`
- "Good enough randomness" comments on mainnet code
'''

DOCS["languages/solidity/delegatecall-proxy.md"] = r'''# Delegatecall & Proxy Risks

> **Severity:** Critical
> **SWC:** [SWC-112](https://swcregistry.io/docs/SWC-112)
> **AI Generation Risk:** High — DIY proxies without storage layout discipline

---

## Vulnerability Explanation

`delegatecall` runs callee code in caller storage context. Wrong target or storage collision → full takeover. AI-generated upgradeable proxies often skip:

- Storage gaps
- Initializer protection
- Trusted implementation allowlists

---

## How AI / Vibe Coding Generates This

```solidity
function forward(address impl, bytes memory data) external {
  impl.delegatecall(data); // anyone, any impl
}
```

---

## Secure Code Fix

- Use OpenZeppelin Upgrades plugins / audited proxy patterns (UUPS/Transparent)
- `initialize` only once (`Initializer` modifier)
- Storage layout tests between versions
- Never `delegatecall` to user-supplied address

---

## Prevention Checklist

- [ ] OZ proxy templates only (unless expert audit)
- [ ] Storage gap fields
- [ ] Two-step upgrades + timelock for high TVL
- [ ] Implementation not self-destructable where relevant

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [SWC-112](https://swcregistry.io/docs/SWC-112) | |
| Multiple proxy storage collision post-mortems | |
| [OpenZeppelin Upgrades](https://docs.openzeppelin.com/upgrades-plugins/1.x/) | |

---

## Vibe-Coding Red Flags

- User-controlled `delegatecall` target
- Hand-rolled upgrade without storage audit
- Missing initializer protection
'''


def main() -> None:
    written = []
    skipped = []
    for rel, body in DOCS.items():
        path = ROOT / rel
        if path.exists() and path.stat().st_size > 2000:
            skipped.append((rel, path.stat().st_size))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        text = body.strip() + "\n"
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append((rel, path.stat().st_size))
    print("WRITTEN", len(written))
    for r, s in written:
        print(f"  {s:6d}  {r}")
    print("SKIPPED", len(skipped))
    for r, s in skipped:
        print(f"  {s:6d}  {r}")


if __name__ == "__main__":
    main()
