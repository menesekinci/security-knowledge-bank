---
source: "languages/php/unserialize-rce.md"
title: "🐘 PHP Unserialize RCE"
category: "language-vuln"
language: "php"
severity: "critical"
tags: [code, coding, example, language-vuln, php, prevention, secure, vibe, what]
---

# 🐘 PHP Unserialize RCE

## What Is It?

PHP's `unserialize()` function creates a PHP object from a serialized string.
Magic methods (`__wakeup`, `__destruct`, `__toString`, `__call`)
are called automatically. An attacker can chain magic methods of legitimate classes
(POP chain - Property Oriented Programming) to achieve RCE.

## Vibe Coding Connection

```
Prompt: "Read user data from session"
AI:
```

```php
// 💀 VULNERABLE:
function loadUser($sessionData) {
    return unserialize(base64_decode($sessionData));  // RCE!
}
```

## Example: POP Chain

```php
// A legitimate class:
class Logger {
    public $filename;
    
    public function __destruct() {
        file_put_contents($this->filename, "<?php system(\$_GET['cmd']); ?>");
    }
}

// The attacker crafts the following payload:
// $log = new Logger();
// $log->filename = 'shell.php';
// echo base64_encode(serialize($log));
// 
// When the application unserializes → Logger.__destruct() → shell.php is written 💀

// In real-world scenarios, much more complex chains are used:
// phpggc SwiftMailer RCE system 'id'
// phpggc Laravel RCE system 'cat /etc/passwd'
```

## Secure Code

```php
// ✅ SECURE:
function loadUser($jsonData) {
    return json_decode(base64_decode($jsonData), true);
}

// ✅ If mandatory, use whitelist:
$user = unserialize($data, ['allowed_classes' => ['MyApp\\User']]);
```

## Prevention
- Don't use `unserialize()`, use `json_decode()`
- Keep old libraries (guzzle, monolog, swiftmailer) up to date

---

**Severity: 🔴 Critical** — Direct RCE.
**CWE: CWE-502**
