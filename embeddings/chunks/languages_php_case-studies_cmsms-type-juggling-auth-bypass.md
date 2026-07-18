---
source: "languages/php/case-studies/cmsms-type-juggling-auth-bypass.md"
title: "CMS Made Simple: PHP Type Juggling Authentication Bypass → RCE"
category: "case-study"
language: "php"
severity: "high"
tags: [case-study, cause, chain, exploitation, impact, overview, php, root, takeaways]
---

# CMS Made Simple: PHP Type Juggling Authentication Bypass → RCE

**Language:** PHP
**Vulnerability Type:** Weak Type Comparison (Loose `==` vs Strict `===`)
**CVE:** N/A (Fixed in CMSMS 2.2.7)
**Date:** Discovered 2018

## Overview

Security researcher **Sven Morgenroth** discovered an authentication bypass vulnerability in **CMS Made Simple (CMSMS)** caused by PHP's loose comparison operator (`==`) being used to compare password hashes. The vulnerability allowed an attacker to bypass login authentication entirely, and from there escalate to **full Remote Code Execution (RCE)** via the CMS's module upload functionality.

This case is a perfect illustration of why a single missing character (the extra `=` in `===`) can compromise an entire application.

## Root Cause

### PHP Type Juggling

PHP's loose comparison operator `==` performs "type juggling" — it attempts to convert both operands to the same type before comparing. This leads to counterintuitive results:

```php
'test' == 0       // true! PHP converts "test" to 0
'test' == true    // true! PHP treats non-empty strings as true
```

When comparing a string to an integer, PHP converts the string to an integer by looking at its beginning. If the string doesn't start with a number, it converts to `0`. So:

```php
var_dump(md5('anything') == 0); // true if the hash starts with '0e...'
```

### The CMSMS Vulnerability

In CMSMS, the authentication check function `_check_passhash` compared the computed password hash with the stored hash using **loose comparison** (`==`) instead of strict comparison (`===`):

```php
// Vulnerable code (loose comparison)
if ($hash_from_cookie == $computed_hash) {
    // authenticated
}
```

The researcher found that by manipulating cookie values and exploiting the `0e...` PHP hash comparison quirk (where `0eXXXXX` == `0eYYYYY` in loose comparison because both are treated as `0` in scientific notation), an attacker could bypass the password check.

Specifically, if the computed hash started with `0e` followed by only digits, PHP's loose comparison would treat it as `0` in scientific notation — and any other hash starting with `0e` would also equal `0`. This meant the attacker could forge a cookie that would authenticate them without knowing the actual password.

## Exploitation Chain

1. **Authentication Bypass:** Craft a cookie that exploits the `0e...` hash comparison weakness to bypass the login check
2. **Admin Access:** Gain access to the CMSMS admin panel without valid credentials
3. **RCE via Module Upload:** Upload a malicious XML module containing a PHP web shell
4. **Full Server Compromise:** Execute arbitrary commands on the server

The researcher wrote a Metasploit module to automate this full chain.

## Impact

- Complete authentication bypass — access to the admin panel with no password
- Full remote code execution via module upload
- Server compromise, data theft, site defacement

## Key Takeaways for Developers

1. **Use strict comparison (`===`) for security-critical checks.** Password hashes, authentication tokens, session IDs — always use `===` to compare these.
2. **Beware PHP's `0e...` hash problem.** Use `hash_equals()` for timing-safe hash comparison, not even `===` (which is not timing-safe).
3. **Never assume "it works" is "it's secure."** Loose comparison might give the right result 99.9% of the time — but that 0.1% can cost you everything.
4. **Even a single character matters.** The difference between `==` and `===` is literally one character but the security gap is enormous.

## References

- [Invicti - Type Juggling Authentication Bypass in CMS Made Simple](https://www.invicti.com/blog/web-security/type-juggling-authentication-bypass-cms-made-simple)
- [CMSMS Official Site](https://www.cmsmadesimple.org/)
- [PHP Type Juggling Vulnerability - Vickie Li's Blog](https://vickieli.dev/insecure%20deserialization/php-type-juggling/)
- [OWASP - PHP Type Juggling](https://owasp.org/www-community/vulnerabilities/PHP_Type_Juggling)
