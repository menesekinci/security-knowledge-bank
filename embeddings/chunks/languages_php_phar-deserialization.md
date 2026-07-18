---
source: "languages/php/phar-deserialization.md"
title: "🐘 PHP phar:// Deserialization"
category: "language-vuln"
language: "php"
severity: "critical"
tags: [cve-2023-28115, knplabs, language-vuln, php, prevention, what]
---

# 🐘 PHP phar:// Deserialization

## What Is It?
PHP's `phar://` stream wrapper automatically calls `unserialize()` on the **metadata** inside a .phar file. RCE without ever calling `unserialize()`!

## How It Works
```php
// VULNERABLE — no unserialize() call but RCE:
$path = "phar://uploads/avatar.phar/test.txt";
file_get_contents($path);  // phar:// → metadata → unserialize() automatic!
```

Attacker:
1. Creates a malicious .phar file (POP chain in metadata)
2. Uploads the file (looks like an image)
3. When accessed via `phar://` → RCE 💀

## CVE-2023-28115 — KnpLabs Snappy phar:// deserialization (CVSS 9.8)
Snappy (the PHP wkhtmltopdf/wkhtmltoimage wrapper, < 1.4.2) passed a user-controlled path into `file_exists()` **without checking the stream protocol**. Supplying a `phar://` path triggers automatic `unserialize()` of the Phar metadata, instantiating arbitrary PHP objects — remote code execution when a suitable POP gadget chain (e.g. from Laravel/Symfony) is present. Fixed in 1.4.2 by rejecting non-standard protocols.

## Prevention
- Disable phar:// with `stream_wrapper_unregister('phar')`
- File upload validation: detect and block phar files
- `is_phar()` check: verify if file is a phar
- Use PHP 8.0+ (extra checks for phar metadata deserialization)

```php
// SAFE — disable phar://:
if (/* you don't use phar */) {
    stream_wrapper_unregister('phar');
}

// Or path check:
$ext = pathinfo($path, PATHINFO_EXTENSION);
if (in_array($ext, ['phar', 'phar.gz'])) {
    throw new SecurityException("Phar files not allowed");
}
```

**Severity: 🔴 Critical** — RCE without calling unserialize().
**Source:** CVE-2023-28115 — https://nvd.nist.gov/vuln/detail/CVE-2023-28115
