# 🐘 PHP Command Injection

## What Is It?
Passing user input directly to shell commands via `system()`, `exec()`, `shell_exec()`, `passthru()`, or the backtick (`` ` ``) operator in PHP.

## Example
```php
// 💀 VULNERABLE:
$domain = $_GET['domain'];
echo shell_exec("ping -c 1 " . $domain);
// domain = "127.0.0.1; rm -rf /" → 💀

// ✅ SECURE:
$domain = $_GET['domain'];
// Input validation:
if (!preg_match('/^[a-zA-Z0-9.-]+$/', $domain)) {
    die("Invalid domain");
}
$output = shell_exec("ping -c 1 " . escapeshellarg($domain));
echo htmlspecialchars($output);
```

## Function Comparison
| Function | Usage |
|----------|-------|
| `system()` | Outputs directly |
| `exec()` | Returns output as array |
| `shell_exec()` / `` ` `` | Returns output as string |
| `passthru()` | Outputs binary data |

## Prevention
- Use `escapeshellarg()` (escapes each argument)
- `escapeshellcmd()` escapes the entire command
- Use a library like `symfony/process` if possible
- Always validate input

---

**Severity: 🔴 Critical** — RCE.
**CWE: CWE-78**
