# 🐘 PHP File Upload Bypass

## Example (Dangerous)
```php
// 💀 VULNERABLE:
$target = "uploads/" . basename($_FILES["file"]["name"]);
move_uploaded_file($_FILES["file"]["tmp_name"], $target);
// Attacker: uploads shell.php.png → executes despite the .png extension!
```

## Secure Code
```php
// ✅ SECURE:
function handleUpload(array $file): string {
    // 1. Extension whitelist:
    $allowed = ['jpg', 'png', 'gif', 'pdf'];
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed)) {
        throw new Exception("Invalid file type");
    }
    
    // 2. MIME type check:
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file['tmp_name']);
    $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (!in_array($mime, $allowed_mimes)) {
        throw new Exception("Invalid MIME type");
    }
    
    // 3. Size check:
    if ($file['size'] > 5 * 1024 * 1024) {
        throw new Exception("File too large");
    }
    
    // 4. Secure name:
    $newName = bin2hex(random_bytes(16)) . '.' . $ext;
    
    move_uploaded_file($file['tmp_name'], "uploads/" . $newName);
    return $newName;
}
```

## Prevention
- Extension whitelist (NOT blacklist!)
- MIME type check (with finfo, NOT $_FILES['type'])
- Size limit
- Regenerate the file name (random)
- Disable PHP execution in the uploads directory (`.htaccess`)
- Scan for AV/malware

---

**Severity: 🔴 Critical** — Webshell → RCE.
