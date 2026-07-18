---
source: "languages/php/laravel-security.md"
title: "🐘 Laravel Security Deep Dive"
category: "language-vuln"
language: "php"
severity: "medium"
tags: [eloquent, environment, general, language-vuln, laravel, livewire, mass, php, serialization, vulnerabilities]
---

# 🐘 Laravel Security Deep Dive

> Laravel is PHP's most popular framework. These are the most common traps AI falls into during Vibe Coding.

## 1. Eloquent Mass Assignment

Mass assignment occurs when all request data is directly passed to a model during creation. An attacker can modify sensitive columns by sending fields that are not in the form.

### Vulnerable Code

```php
// 💀 DANGEROUS — No mass assignment protection
$user = User::create($request->all());
// Attacker adds: "is_admin": 1 → Becomes Admin!

// 💀 DANGEROUS — $guarded empty
class User extends Model
{
    protected $guarded = [];  // All fields are assignable!
}
```

### Secure Code

```php
// ✅ SECURE — Use $fillable
class User extends Model
{
    protected $fillable = ['name', 'email', 'password'];
}

// ✅ SECURE — Only assign the fields that are needed
$user = User::create($request->only(['name', 'email', 'password']));
```

### CVE-2025-27515: Laravel File Validation Bypass

**CVE:** CVE-2025-27515
**CVSS:** 5.3 (Medium)
**Source:** https://nvd.nist.gov/vuln/detail/cve-2025-27515

When wildcard validation is used (like `'photos.*'`), a malicious request crafted by the user can bypass the validation rules.

**GitHub Advisory:** https://github.com/advisories/GHSA-78fx-h6xr-vch4

## 2. Environment (.env) File Leak & APP_KEY Exploitation

### CVE-2024-52301: Laravel Environment Manipulation

**CVE:** CVE-2024-52301
**CVSS:** 7.5 (High)
**Source:** https://nvd.nist.gov/vuln/detail/cve-2024-52301

Using Laravel's environment-changing feature through query strings, an attacker can make the application run in `local` environment instead of `production`. This activates debug mode and leads to leakage of sensitive information.

**Detailed Analysis:**
- https://ahmed-al-ahmed.com/posts/cve-2024-52301-laravel-framework-environment-manipulation/
- https://securinglaravel.com/laravel-security-notice-laravel-environment-manipulation-via-query-string/

```php
// Vulnerable code before Laravel 6.20.45
$app->loadEnvironmentFrom($request->input('env'));

// Attacker: ?env=production → can change the environment via query
```

### CVE-2018-15133: Laravel APP_KEY Unserialize RCE

**CVE:** CVE-2018-15133
**CVSS:** 9.8 (Critical)
**Source:** https://nvd.nist.gov/vuln/detail/cve-2018-15133

In Laravel Framework versions 5.5.40 and 5.6.x < 5.6.30, RCE via insecure unserialize call through the `X-XSRF-TOKEN` cookie.

```php
// Laravel's vulnerable cookie decryption process
$payload = $this->decryptCookie($request->cookies->get('XSRF-TOKEN'));
// The serialized PHP object sent by the attacker is automatically unserialized
```

**PoC:** https://www.exploit-db.com/exploits/47129
**Source:** https://github.com/aljavier/exploit_laravel_cve-2018-15133

### CVE-2024-55556: Crater Invoice APP_KEY RCE

**CVE:** CVE-2024-55556
**CVSS:** 9.8 (Critical)
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-55556

In the Laravel-based Crater Invoice application, an unauthenticated attacker with knowledge of the APP_KEY can achieve RCE.

**Details:** https://op-c.net/blog/laravel-app_key-rce-vulnerability-cve-2018-15133-cve-2024-55556/
**Finding:** https://blog.gitguardian.com/exploiting-public-app_key-leaks/

Through collaboration between **Synacktiv** and **GitGuardian**, APP_KEY leakage was detected in 600+ applications.

## 3. Serialization Vulnerabilities

Serialization in Laravel is commonly used in session, cache, and cookie management.

### Vulnerable Code

```php
// 💀 DANGEROUS — Insecure serialization
$userData = unserialize($request->cookie('user_data'));
// POP chain can achieve RCE

// 💀 DANGEROUS — Serialized data in cache
$data = unserialize(Cache::get('user_' . $id));
```

### Secure Code

```php
// ✅ SECURE — Use JSON
$userData = json_decode($request->cookie('user_data'), true);

// ✅ SECURE — Laravel's encrypted cookie
Cookie::queue('user_data', Crypt::encrypt($data));
```

## 4. Livewire RCE: CVE-2025-54068

**CVE:** CVE-2025-54068
**CVSS:** 9.8 (Critical)
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-54068

Pre-auth RCE via insecure unmarshaling (deserialization) in Laravel Livewire v3. Affects all versions from 3.0.0-beta.1 through 3.6.3.

**Impact:** 6,000+ applications were found to be compromised. 1,851+ database dumps were stolen.

**Sources:**
- https://www.synacktiv.com/en/advisories/livewire-remote-command-execution-through-unmarshaling
- https://www.imperva.com/blog/cve-2025-54068-laravel-livewire-credential-theft-campaign-6000-applications-compromised/
- https://hadrian.io/blog/livewire-to-livepyre---exploitation-of-an-rce-in-mere-minutes

## General Laravel Security Measures

```php
// ✅ APP_KEY security
// Add .env file to PUBLIC .gitignore
// NEVER push APP_KEY to a public repo

// ✅ Debug mode
// APP_DEBUG=false in production
// To protect against CVE-2024-52301

// ✅ Mass Assignment
class User extends Model {
    protected $fillable = ['name', 'email', 'password'];
    // is_admin is NOT FILLABLE!
}

// ✅ Query Builder SQL Injection
$users = DB::table('users')
    ->where('name', $request->input('name'))  // Parameter binding
    ->get();
```

## Sources

- https://owasp.org/www-project-cheat-sheets/cheatsheets/Laravel_Cheat_Sheet.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-52301
- https://nvd.nist.gov/vuln/detail/CVE-2018-15133
- https://nvd.nist.gov/vuln/detail/CVE-2024-55556
- https://nvd.nist.gov/vuln/detail/CVE-2025-54068
- https://feedly.com/cve/vendors/laravel
- https://securinglaravel.com/
- https://blog.gitguardian.com/exploiting-public-app_key-leaks/
