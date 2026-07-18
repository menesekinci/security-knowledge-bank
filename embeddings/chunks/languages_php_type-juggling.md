---
source: "languages/php/type-juggling.md"
title: "🐘 PHP Type Juggling (Loose Comparison)"
category: "language-vuln"
language: "php"
severity: "medium"
tags: [code, coding, known, language-vuln, magic, php, prevention, secure, vibe, what]
---

# 🐘 PHP Type Juggling (Loose Comparison)

## What Is It?

PHP's `==` (loose comparison) operator **automatically converts types** before comparing. This leads to unexpected matches. Especially:
- `"admin" == 0` → `true` **only on PHP < 8.0**
- `"123abc" == 123` → `true`!
- `"0e12345" == "0e67890"` → `true`! (numeric-string "magic hash" juggle)

> **PHP version matters.** Before PHP 8.0, comparing a **non-numeric** string to a number cast the string to a number (`"admin"` → `0`), so `"admin" == 0` was `true` — a classic auth-bypass. **PHP 8.0 changed this** (RFC: Saner string-to-number comparisons): a number vs. a non-numeric string now compares the number as a string, so `0 == "admin"` is **`false`** on PHP 8+. The `0e…` **magic-hash** collisions below still work on all versions, because both sides are *numeric* strings (`"0e123" == "0e456"` compares them as the number 0).

## Vibe Coding Connection

```
Prompt: "Write admin login check"
AI:
```

```php
// 💀 VULNERABLE — Loose Comparison
function checkAdmin($userId) {
    // User input '0' string
    if ($userId == "admin") {  // == used!
        return true;
    }
    return false;
}

// On PHP < 8.0, if user sends userId=0 (integer):
//   $userId == "admin"  →  0 == "admin"  →  "admin" cast to 0  →  true! 💀
// On PHP >= 8.0 this is false ("admin" is compared as a string).
// The reliable cross-version bypass is the magic-hash trick below.
```

```php
// More dangerous example — hash comparison:
if ($stored_hash != md5($password)) {  // != (loose)
    // "0e123" == "0e456" → true!
    // Both are scientific notation, 0^x = 0
}

// Known magic hashes with MD5:
// "240610708" → md5: "0e462097431906509019562988736854" → parsed as 0
// "0e" followed by only digits is read as 0 × 10^n = 0, so two such
// hashes compare EQUAL with ==. Using these you can match any account!
```

## Secure Code

```php
// ✅ SECURE — Strict Comparison
if ($userId === "admin") {  // === checks string vs string
    // ...
}

// ✅ Hash comparison:
if (hash_equals($stored_hash, md5($password))) {
    // hash_equals — timing attack protected strict comparison
}
```

## Known Magic Hashes

| Input | MD5 Hash | Type Juggling? |
|-------|----------|----------------|
| `240610708` | `0e462097431906509019562988736854` | ✅ (`0e` + all digits) |
| `QNKCDZO` | `0e830400451993494058024219903391` | ✅ (`0e` + all digits) |
| `aabg7XSs` | `0e087386482136013740957780965295` | ✅ (`0e` + all digits) |

> All three values above are verified real MD5 magic hashes: the digest is `0e` followed **only by digits**, so PHP's `==` reads it as the number 0 and any two of them compare equal. A hash like `0e…` that contains a **letter** after the `0e` (e.g. `0e12ab…`) is **not** a magic hash — it's treated as a normal string.

Similar magic hashes exist for SHA-1 (also of the form `0e` + all digits).

## Prevention

| Rule | Description |
|------|-------------|
| Use `===` (never `==`) | Strict type comparison |
| `in_array($val, $arr, true)` | Strict flag required |
| `strcmp()` caution | Returns null if you pass an array |
| Use `hash_equals()` | Timing attack + type safe |

## Critical Rule for Vibe Coding
```
NEVER use == in PHP. Always use ===.
Set strict flag to TRUE in in_array, array_search, strcmp functions.
Use hash_equals for password hash comparison.
```

---

**Severity: 🔴 Critical** — Authentication bypass, admin takeover.
**CWE: CWE-843 (Type Confusion)**
