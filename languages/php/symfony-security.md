# 🐘 Symfony Security Deep Dive

> Symfony is a widely used framework in enterprise PHP applications.
> YAML routing, ExpressionLanguage, and Security components carry unique risks.

## 1. YAML Routing & Configuration Security

Symfony uses YAML for routing and service configuration. Critical security vulnerabilities have been found in the YAML parser in the past.

### CVE-2026-45304: YAML Parser "Billion Laughs" DoS

**CVE:** CVE-2026-45304
**CVSS:** 7.5 (High)
**Source:** https://github.com/advisories/GHSA-4qpc-3hr4-r2p4

A "Billion Laughs" (XML bomb) style DoS vulnerability in Symfony's YAML parser via recursive collection-alias expansion. A few kilobytes of input can lead to gigabytes of memory consumption.

```yaml
# 💀 CVE-2026-45304 PoC — "Billion Laughs"
&1 ["&1 ", &1 ]
# Small input → exponentially growing memory consumption
```

**Details:** https://symfony.com/blog/cve-2026-45304-yaml-parser-exponential-memory-allocation-via-recursive-collection-alias-expansion-billion-laughs
**Security Audit:** https://www.shielder.com/blog/2026/06/symfony-yaml-security-audit/

### CVE-2026-45133: YAML Parser Stack Exhaustion

**CVE:** CVE-2026-45133
**CVSS:** 7.5 (High)
**Source:** https://symfony.com/blog/cve-2026-45133-yaml-parser-stack-exhaustion-via-unbounded-recursion-in-nested-blocks-sequences-and-mappings

Stack exhaustion via unbounded recursion in nested blocks, sequences, and mappings.

### Vulnerable YAML Usage

```php
// 💀 DANGEROUS — Loading YAML from user input
use Symfony\Component\Yaml\Yaml;

$config = Yaml::parse($userInput);  // CVE-2026-45304!
```

### Secure YAML Usage

```php
// ✅ SAFE — Use Symfony 5.4.52+
// Limit alias expansion with YAML flag
$config = Yaml::parse($userInput, Yaml::PARSE_CUSTOM_TAGS);
```

## 2. ExpressionLanguage Component Security

Symfony's `ExpressionLanguage` component evaluates string expressions at runtime. Incorrect usage can lead to RCE.

### Vulnerable ExpressionLanguage Usage

```php
// 💀 DANGEROUS — User input as expression
use Symfony\Component\ExpressionLanguage\ExpressionLanguage;

$el = new ExpressionLanguage();
$result = $el->evaluate($userInput);  // RCE!
// Input: "system('cat /etc/passwd')" → direct command execution
```

### CVE-2024-XXXX: ExpressionLanguage Sandbox Bypass

Sandbox bypass vulnerabilities in Symfony ExpressionLanguage are periodically discovered. Even when using `SourcePolicyInterface`, an attacker can call PHP functions through template rendering capabilities.

**Source:** https://sca.analysiscenter.veracode.com/vulnerability-database/security/remote-code-execution-rce/php/sid-13651

### Secure ExpressionLanguage

```php
// ✅ SAFE — Use expressions in a limited way
$el = new ExpressionLanguage();
$el->registerProvider(new MySafeProvider());

// ✅ SAFE — Only allow specific functions
$el->setFunctions([
    new ExpressionFunction('my_func', function() {
        return 'allowed';
    }, function() {
        return 'allowed';
    })
]);
```

## 3. Security Component & Authentication

### CVE-2025-64500: PATH_INFO Authorization Bypass

**CVE:** CVE-2025-64500
**CVSS:** 7.5 (High)
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-64500

Authorization bypass due to Symfony's HttpFoundation component incorrectly parsing PATH_INFO. Affects Symfony <5.4.50, <6.4.29, <7.3.7.

```php
// 💀 Vulnerable — PATH_INFO parsing error
// Attacker can write /admin/anything/settings instead of /admin/settings
// Authorization check can be bypassed
```

**GitHub Advisory:** https://github.com/advisories/GHSA-3rg7-wf37-54rm

### CVE-2022-39261: Twig Path Traversal

**CVE:** CVE-2022-39261
**CVSS:** 7.5 (High)
**Source:** https://www.sentinelone.com/vulnerability-database/cve-2022-39261/

Path traversal vulnerability in Symfony's Twig render. Template file paths can be manipulated to read sensitive files.

## 4. Routing YAML Security Precautions

```yaml
# ✅ SAFE — Symfony routing
app_admin:
    path: /admin/{page}
    controller: App\Controller\AdminController::index
    defaults: { page: 'dashboard' }
    requirements:
        page: 'dashboard|users|settings'  # Strict regex control
    # ✅ Authorization
    options:
        expose: true
    methods: GET
```

### Vulnerable Routing

```yaml
# 💀 DANGEROUS — Unrestricted routing
app_dynamic:
    path: /{controller}/{action}
    # Attacker can call any controller/action
```

## 5. Serialization & Deserialization

Symfony's Serializer component can be used for insecure deserialization.

```php
// 💀 DANGEROUS — Insecure deserialization
use Symfony\Component\Serializer\Serializer;

$serializer = new Serializer([new ObjectNormalizer()]);
$result = $serializer->deserialize(
    $userInput,
    'App\Entity\User', 
    'json'
);
// ObjectNormalizer can access all properties by default
```

## General Symfony Security Measures

```yaml
# security.yaml — ✅ SAFE
security:
    access_control:
        - { path: '^/admin', roles: ROLE_ADMIN }
        - { path: '^/api', roles: IS_AUTHENTICATED }
    
    # Brute force protection
    access_denied_url: /403
    
    # Session security
    session:
        cookie_secure: true
        cookie_httponly: true
        cookie_samesite: strict
```

## Resources

- https://symfony.com/blog/category/security-advisories
- https://github.com/symfony/symfony/security/advisories
- https://nvd.nist.gov/vuln/detail/CVE-2025-64500
- https://github.com/advisories/GHSA-3rg7-wf37-54rm
- https://github.com/advisories/GHSA-4qpc-3hr4-r2p4
- https://symfony.com/blog/cve-2026-45304-yaml-parser-exponential-memory-allocation-via-recursive-collection-alias-expansion-billion-laughs
- https://app.opencve.io/cve/?vendor=symfony
- https://phpadvisories.app/vendor/symfony
