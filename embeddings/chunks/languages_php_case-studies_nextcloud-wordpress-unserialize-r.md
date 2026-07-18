---
source: "languages/php/case-studies/nextcloud-wordpress-unserialize-rce-via-cookies.md"
title: "Nextcloud WordPress Site: unserialize() RCE via Cookies"
category: "case-study"
language: "php"
severity: "high"
tags: [case-study, cause, exploit, impact, overview, php, remediation, root]
---

# Nextcloud WordPress Site: unserialize() RCE via Cookies

**Language:** PHP (WordPress, Custom Theme)
**Vulnerability Type:** PHP Object Injection (Insecure Deserialization)
**Disclosed via:** HackerOne Bug Bounty
**Date:** 2024

## Overview

In a real-world bug bounty finding documented by HackerOne, security researcher **Lukas Reschke** discovered a critical **Remote Code Execution (RCE)** vulnerability on **Nextcloud's WordPress website**. The bug existed in the custom WordPress theme Nextcloud had developed and was caused by calling `unserialize()` on user-controlled cookie data.

This case is a textbook example of how insecure deserialization in PHP can lead to full server compromise — even in a well-known, security-conscious company like Nextcloud.

## Root Cause

The vulnerable code was found in Nextcloud's custom WordPress theme. The function `nc_change_nf_default_value` read user input from a cookie and deserialized it without validation:

```php
function nc_change_nf_default_value( $default_value, $field_type, $field_settings ) {
    if(isset($_COOKIE['nc_form_fields'])){
        $nc_form_fields = unserialize(base64_decode($_COOKIE['nc_form_fields']));
        // ... use the deserialized data
    }
}
```

A second location in the same theme contained the same vulnerability pattern:

```php
if(isset($_COOKIE['nc_form_fields'])){
    $nc_form_fields = unserialize(base64_decode($_COOKIE['nc_form_fields']));
    // ...
}
```

The form fields were base64-encoded, serialized PHP data stored in a cookie — entirely controlled by the user.

## The Exploit

The researcher used the `phpggc` tool (PHP Generic Gadget Chains) to generate a payload. Since **Monolog** (a popular PHP logging library) was installed as a dependency, the researcher used a Monolog-based gadget chain.

The decoded payload:

```
O:37:"Monolog\Handler\FingersCrossedHandler":4:{
  s:16:"*passthruLevel";i:0;
  s:10:"*handler";r:1;
  s:9:"*buffer";a:1:{i:0;a:2:{i:0;s:2:"id";s:5:"level";i:100;}}
  s:13:"*processors";a:2:{i:0;s:3:"pos";i:1;s:6:"system";}
}
```

This payload uses Monolog's `FingersCrossedHandler` class, whose constructor allows setting an arbitrary callback function. By setting the `processors` property to call `system` with `id` as the argument, the researcher achieved command execution.

Even without Monolog, **WordPress itself contains gadget chains** that can be used for RCE via insecure deserialization.

## Impact

- Full remote code execution on Nextcloud's WordPress server
- Potential data breach (access to customer credentials, PII, API keys)
- Service disruption or defacement
- Web skimming attacks (injecting payment card stealers)

## Remediation

Nextcloud patched the vulnerability within **a few days** of the report by replacing `unserialize()` with safer alternatives (like JSON encoding/decoding) that don't support object instantiation.

## Key Takeaways for Developers

1. **Search your codebase for `unserialize()` calls.** Use `rg -F 'unserialize(' .` to find every occurrence.
2. **Check if user input reaches `unserialize()`.** Common sources: `$_COOKIE`, `$_GET`, `$_POST`, `$_REQUEST`.
3. **Gadget chains exist everywhere.** Even if you don't use "dangerous" libraries, popular tools like Monolog, WordPress core, and Symfony all contain usable gadgets.
4. **Use `json_decode()` instead.** JSON deserialization doesn't instantiate objects and is safe for untrusted data.
5. **Consider manual code review or automated SAST scanning** to catch these vulnerabilities before they reach production.

## References

- [HackerOne - How Serialized Cookies Led to RCE on a WordPress Website](https://www.hackerone.com/blog/how-serialized-cookies-led-rce-wordpress-website)
- [HackerOne Report #2248328](https://hackerone.com/reports/2248328)
- [phpggc - PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
- [OWASP - PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)
