# 🐘 PHP Security Hardening Checklist

> Items to check in every PHP project before deployment.

## ✅ php.ini
- [ ] `allow_url_include = Off`
- [ ] `allow_url_fopen = Off` (if not needed)
- [ ] `display_errors = Off` (production)
- [ ] `expose_php = Off`
- [ ] `session.use_strict_mode = 1`
- [ ] `session.use_only_cookies = 1`
- [ ] `session.cookie_httponly = 1`
- [ ] `session.cookie_secure = 1` (HTTPS)
- [ ] `disable_functions = exec,system,passthru,shell_exec,popen,proc_open`

## ✅ Code Security
- [ ] Is `unserialize()` not used? (if used, is there a whitelist?)
- [ ] No `eval()`, `assert()`, `create_function()`?
- [ ] No remnants of `extract()`, `parse_str()`, `register_globals`?
- [ ] Is type juggling prevented? (`===` used?)
- [ ] Is `md5()` / `sha1()` not used? (is `password_hash` used?)

## ✅ File Operations
- [ ] File upload: is there an extension whitelist?
- [ ] File upload: is MIME type check (finfo) performed?
- [ ] File upload: is PHP execution disabled via .htaccess?
- [ ] File path: is there dynamic path control for `include/require`?
- [ ] Has `phar://` stream wrapper risk been assessed?

## ✅ Database
- [ ] Are PDO prepared statements used?
- [ ] `mysqli_real_escape_string()` alone is NOT a security measure!
- [ ] Are parameters used in raw queries?

## ✅ Web
- [ ] Is there a CSP header?
- [ ] Is session regeneration performed? (`session_regenerate_id(true)`)
- [ ] Is there a CSRF token?

## 🛡️ Vibe Coding Extra
- [ ] Were outdated PHP 4/5 codes (ereg, mysql_) recommended by AI rejected?
- [ ] Was AI's `==` usage replaced with `===`?
- [ ] Was AI's `unserialize()` usage replaced with `json_decode`?
