# 🐘 PHP Session Security

## Example (Dangerous)
```php
// 💀 VULNERABLE — Session fixation:
session_start();
// Session ID is not changed → open to a fixation attack!

// Attacker:
// 1. Creates their own session ID: PHPSESSID=12345
// 2. Sends it to the victim: http://site.com/?PHPSESSID=12345
// 3. When the victim logs in → the attacker uses the same session 💀

// ✅ SECURE:
session_start();
session_regenerate_id(true);  // Change the session ID on login!
```

## Other Risks
```php
// 💀 Predictable session:
session_id(md5($userId));  // Session ID is guessable!

// ✅ The right way:
session_start();  // PHP generates a secure ID automatically

// 💀 Storing the session in a file (default):
// /tmp/sess_XXX — dangerous on shared hosting!

// ✅ Store it in Redis/Memcache:
ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://127.0.0.1:6379');
```

## Prevention
- `session_regenerate_id(true)` — call it on login/logout
- Change the default `session.save_path`
- Add a session timeout
- `session.cookie_httponly = 1`
- `session.cookie_secure = 1` (HTTPS)
- `session.use_strict_mode = 1`

---

**Severity: 🟡 Medium** — Hijack, fixation.
