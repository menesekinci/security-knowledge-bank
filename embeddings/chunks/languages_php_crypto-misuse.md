---
source: "languages/php/crypto-misuse.md"
title: "🟡 PHP Cryptographic Misuse"
category: "language-vuln"
language: "php"
severity: "high"
tags: [code, explanation, language-vuln, php, secure, severity, vulnerability, vulnerable]
---

# 🟡 PHP Cryptographic Misuse

> **Category:** Cryptographic Failures  
> **Language:** PHP  
> **Severity:** High to Critical  
> **CWE:** CWE-327 (Broken Crypto), CWE-328 (Weak Hash), CWE-916 (Password Hash Without Salt/Work Factor), CWE-329 (Not Using Random IV), CWE-338 (Weak PRNG)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🔴 High–Critical |
| **Primary CWE** | CWE-327, CWE-328, CWE-916, CWE-338, CWE-321 (Hard-coded Key) |
| **OWASP** | A02:2021 Cryptographic Failures |

## Vulnerability Explanation

PHP’s long history leaves a trail of **obsolete crypto APIs** that still appear in tutorials and AI output:

1. **`md5()` / `sha1()` for passwords** — fast hashes, GPU-crackable; combined with loose `==` comparison → magic-hash type juggling auth bypass.
2. **`mcrypt_*`** — removed from PHP core (ext-mcrypt unbundled); old CBC examples often use weak modes and static IVs.
3. **Manual “AES” with `openssl_encrypt` mistakes** — ECB mode, reused IV, no authentication (no GCM/HMAC), wrong key lengths, `OPENSSL_ZERO_PADDING` abuse.
4. **`rand()` / `mt_rand()` for tokens** — not CSPRNG; predictable reset links and session IDs.
5. **Homegrown “encryption”** — XOR with secret, Base64-as-security, double MD5.
6. **Hard-coded keys** in `config.php` committed to git.
7. **Ignoring `password_hash` / `password_verify`** despite being the recommended API since PHP 5.5.

Correct modern baseline: `password_hash`/`password_verify` (PASSWORD_ARGON2ID when available), `random_bytes`/`random_int`, `openssl_encrypt` with **AES-256-GCM** (or libsodium `sodium_crypto_secretbox`), constant-time compares via `hash_equals`.

## How AI / Vibe Coding Generates This

```
Prompt: "PHP login system with hashed passwords"
AI: $hash = md5($password);  // or sha1($password.$salt) with weak salt

Prompt: "Encrypt cookie data"
AI: openssl_encrypt($data, 'AES-128-ECB', $key)  // no IV, no auth

Prompt: "Generate password reset token"
AI: md5(uniqid(rand(), true))
```

Training corpora are saturated with WordPress-era and PHP 5 blog posts. Models also mix `password_hash` correctly **then** compare with `==` instead of `password_verify`, reopening timing/type issues.

## Vulnerable Code

```php
<?php
// 💀 Password storage
function register($user, $pass) {
    $hash = md5($pass); // crackable; no salt
    // or: $hash = sha1($salt . $pass);
    mysqli_query($db, "INSERT INTO users (u,p) VALUES ('$user','$hash')");
}

function login($user, $pass) {
    $row = /* fetch */;
    // type juggling risk with scientific notation hashes if using ==
    if ($row['p'] == md5($pass)) {
        return true;
    }
}

// 💀 Predictable token
$token = md5(uniqid(mt_rand(), true));

// 💀 Unauthenticated encryption, static key
function encrypt($plaintext) {
    $key = '0123456789abcdef'; // hard-coded
    return openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, str_repeat("\0", 16));
}

// 💀 mcrypt legacy (removed from modern PHP)
// $c = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
```

## Secure Fix

```php
<?php
// ✅ Password hashing (PHP core)
function register_user(PDO $pdo, string $user, string $pass): void {
    $hash = password_hash($pass, PASSWORD_ARGON2ID); // or PASSWORD_DEFAULT
    $stmt = $pdo->prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
    $stmt->execute([$user, $hash]);
}

function verify_user(PDO $pdo, string $user, string $pass): bool {
    $stmt = $pdo->prepare('SELECT password_hash FROM users WHERE username = ?');
    $stmt->execute([$user]);
    $hash = $stmt->fetchColumn();
    if ($hash === false) {
        // dummy hash to reduce user-enumeration timing (optional)
        password_verify($pass, '$argon2id$v=19$m=65536,t=4,p=1$...');
        return false;
    }
    return password_verify($pass, $hash);
}

// ✅ CSPRNG tokens
$token = bin2hex(random_bytes(32));

// ✅ AES-256-GCM
function encrypt_gcm(string $plaintext, string $key): string {
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $cipher);
}

function decrypt_gcm(string $blob, string $key): string|false {
    $raw = base64_decode($blob, true);
    if ($raw === false || strlen($raw) < 28) return false;
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $cipher = substr($raw, 28);
    return openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
}

// Prefer libsodium when available:
// sodium_crypto_secretbox / sodium_crypto_pwhash
```

## Prevention Checklist

- [ ] Passwords: **only** `password_hash` / `password_verify` (Argon2id preferred)
- [ ] Never `md5`/`sha1`/`crc32` for credentials or security tokens
- [ ] Tokens: `random_bytes` / `random_int` — never `rand`, `mt_rand`, `uniqid`
- [ ] Compare secrets with `hash_equals` (not `==` / `===` on hashes alone for auth — use `password_verify`)
- [ ] Symmetric crypto: AES-GCM or libsodium secretbox; unique IV/nonce; never ECB
- [ ] Keys from env / secrets manager; rotate; never commit
- [ ] Ban `mcrypt_*` in code review; upgrade legacy data offline
- [ ] Enable `password_needs_rehash` on login to migrate algorithms
- [ ] Static analysis: Psalm/PHPStan custom rules or Semgrep for `md5($password)` patterns

## Real CVEs / Case References

Application-level PHP crypto bugs are often **not single CVEs** but recurring patterns; related platform/history:

| Reference | Summary | Link |
|-----------|---------|------|
| **password_hash documentation** | Official PHP guidance replacing ad-hoc MD5/SHA password schemes | https://www.php.net/manual/en/function.password-hash.php |
| **Type juggling + MD5** | Loose comparison with `0e…` MD5/SHA1 digests enables auth bypass when apps use `==` on hashes (language footgun widely exploited in CTFs/apps) | See also this bank: [type-juggling.md](type-juggling.md) |
| **CVE-2013-0156 (ecosystem parallel)** | Rails YAML/object injection era shows how popular web stacks fail when untrusted data hits powerful parsers — PHP’s analog is `unserialize` + weak crypto for signed cookies | https://nvd.nist.gov/vuln/detail/CVE-2013-0156 |
| **WordPress / plugin history** | Countless plugins store weak password hashes or hard-code keys; treat plugin CVEs as recurring crypto-misuse class | Track per-plugin NVD entries; bank: [wordpress-security.md](wordpress-security.md) |

Practical “famous” pattern: **`md5($password)` + `==`** remains one of the highest-frequency AI/PHP auth failures even without a single umbrella CVE.

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| `md5($password)` / `sha1($password)` | Offline cracking |
| `$hash == md5($input)` | Magic hash / type juggling |
| `mt_rand` / `uniqid` tokens | Predictable resets |
| `AES-*-ECB` or zero IV CBC | Pattern leak / malleability |
| `mcrypt_` in new code | Dead extension, bad defaults |
| Base64 “encryption” | Encoding ≠ crypto |
| Key in `config.php` in repo | Total compromise on leak |
| `openssl_encrypt` without tag/HMAC | Ciphertext bit-flips |

**Prompt:**  
*“Use password_hash/password_verify (Argon2id). Tokens via random_bytes. Encrypt with AES-256-GCM or sodium. Never md5/sha1 for passwords. Never == for hash checks.”*

---

**Severity: 🔴 High–Critical** — credential dumps cracked en masse, account takeover.  
**CWE: CWE-327 / CWE-328 / CWE-916 / CWE-338**
