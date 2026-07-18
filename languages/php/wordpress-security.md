# 🐘 WordPress Plugin Security

> WordPress powers ~43% of all websites. The plugin ecosystem is the biggest security risk.
> In 2025, **11,334 new security vulnerabilities** were discovered in the WordPress ecosystem (42% increase over 2024).

## 1. SQL Injection in WP_Query & $wpdb

SQL Injection in WordPress typically occurs when `$wpdb->prepare()` is not used correctly or when direct user input is added to `WP_Query`.

### Vulnerable WP_Query Usage

```php
// 💀 DANGEROUS — SQL Injection via WP_Query
$posts = new WP_Query([
    'post_type' => 'product',
    'orderby' => $_GET['orderby']  // Direct user input
]);
// Input: orderby=1, (SELECT 123 FROM SLEEP(5)) — time-based SQLi
```

### Vulnerable $wpdb Usage

```php
// 💀 DANGEROUS — Direct SQL query
global $wpdb;
$results = $wpdb->get_results(
    "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE '%" . $_GET['search'] . "%'"
);
// SQL Injection!
```

### Secure WP_Query

```php
// ✅ SAFE — Only allowed orderby values
$allowed_orderby = ['date', 'title', 'rand'];
$orderby = in_array($_GET['orderby'], $allowed_orderby) 
    ? $_GET['orderby'] 
    : 'date';

$posts = new WP_Query([
    'post_type' => 'product',
    'orderby' => $orderby,
]);
```

### Secure $wpdb

```php
// ✅ SAFE — prepared statement
global $wpdb;
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE %s",
        '%' . $_GET['search'] . '%'
    )
);
```

## 2. WordPress Plugins - SQL Injection CVEs 2025

### CVE-2025-9807: The Events Calendar SQLi

**CVE:** CVE-2025-9807
**CVSS:** 7.5 (High)
**Affected:** The Events Calendar < 6.15.1.1
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-9807

Time-based SQL Injection in the `s` parameter of The Events Calendar plugin, which has 200,000+ active installations. Does not require authentication.

```php
// 💀 Vulnerable code (simulation)
$search = $_GET['s'];
$query = $wpdb->prepare("SELECT * FROM events WHERE title LIKE '%$search%'");
// Insufficient escaping in the 's' parameter
```

**Details:** https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/the-events-calendar
**WPScan:** https://wpscan.com/vulnerability/46854e0d-b84e-4cd2-a435-60184bd3a6e1/

### CVE-2025-12197: The Events Calendar Blind SQLi

**CVE:** CVE-2025-12197
**CVSS:** 7.5 (High)
**Affected:** The Events Calendar 6.15.1.1 - 6.15.9
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-12197

Blind SQL Injection — a new attack vector in versions where CVE-2025-9807 was not fully patched.

**Details:** https://zeropath.com/blog/cve-2025-12197-events-calendar-sql-injection-summary

### CVE-2025-4396: Relevanssi SQLi

**CVE:** CVE-2025-4396
**CVSS:** 9.8 (Critical)
**Affected:** Relevanssi - A Better Search < 4.24.4 (Free), < 2.27.5 (Premium)
**Source:** https://nvd.nist.gov/vuln/detail/cve-2025-4396

Critical SQL Injection actively exploited by 16,500+ IPs. Time-based SQLi in `cats` and `tags` parameters.

**Details:** https://www.crowdsec.net/vulntracking-report/cve-2025-4396-wordpress-relevanssi-sql-injection
**Wordfence:** https://www.wordfence.com/threat-intel/vulnerabilities/detail/relevanssi-4244-free-and-2274-premium-unauthenticated-sql-injection

### CVE-2025-1702: Ultimate Member SQLi

**CVE:** CVE-2025-1702
**CVSS:** 7.5 (High)
**Affected:** Ultimate Member < 2.10.1
**Source:** https://nvd.nist.gov/vuln/detail/cve-2025-1702

Blind SQL Injection in the Ultimate Member plugin with 200,000+ active installations. Insufficient escaping in the user search parameter.

**Details:** https://dbugs.ptsecurity.com/vulnerability/PT-2025-9829

### CVE-2025-3951: WP-Optimize SQLi

**CVE:** CVE-2025-3951
**CVSS:** 6.4 (Medium)
**Affected:** WP-Optimize < 4.2.0
**Source:** https://nvd.nist.gov/vuln/detail/cve-2025-3951

SQL Injection in the image compression status check for users with admin role.

**WPScan:** https://wpscan.com/vulnerability/220c195f-3df3-4883-8e0b-a0cf019e6323/

## 3. WordPress Plugin RCE CVEs

### CVE-2025-7384: Contact Form Entries RCE

**CVE:** CVE-2025-7384
**CVSS:** 9.8 (Critical)
**Affected:** Database for Contact Form 7, WPforms, Elementor forms < 1.0.5
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-7384

PHP Object Injection vulnerability affecting 70,000+ sites. RCE without authentication.

**Details:** https://hadrian.io/blog/cve-2025-7384-critical-wordpress-plugin-unauthenticated-rce

## 4. General WordPress Security Measures

### SQL Injection Protection in Plugin Development

```php
// ✅ SAFE — Secure query with WP_Query
$args = [
    'post_type' => 'product',
    's' => sanitize_text_field($_GET['search']),
    'orderby' => 'date',
    'order' => 'DESC'
];
$query = new WP_Query($args);

// ✅ SAFE — Custom table queries
global $wpdb;
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}my_table 
         WHERE name = %s AND status = %d",
        $name,
        $status
    )
);
```

### WordPress Hardening

```php
// wp-config.php — ✅ SAFE
define('DISALLOW_FILE_EDIT', true);  // Disable plugin/theme editor
define('WP_AUTO_UPDATE_CORE', true); // Automatic updates
define('FORCE_SSL_ADMIN', true);     // Force SSL on admin panel

// .htaccess — ✅ XML-RPC protection
// <Files xmlrpc.php>
// Order Deny,Allow
// Deny from all
// </Files>
```

## Resources

- https://patchstack.com/whitepaper/state-of-wordpress-security-in-2026/
- https://wpscan.com/
- https://www.wordfence.com/
- https://nvd.nist.gov/
- https://www.crowdsec.net/vulntracking-report/cve-2025-4396-wordpress-relevanssi-sql-injection
- https://zeropath.com/blog/cve-2025-12197-events-calendar-sql-injection-summary
- https://www.infosecurity-magazine.com/news/wordpress-sql-injection-flaw-40000/
