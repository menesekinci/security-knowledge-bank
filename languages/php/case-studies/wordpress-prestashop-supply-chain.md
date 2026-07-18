# GoDaddy (2021) — WordPress PHP Supply Chain

## 📅 When Did It Happen?
September 2021 (discovery: November 2021)

## 🎯 Target System
GoDaddy hosting — WordPress hosting customers (1.2M+ active sites)

## 🔴 What Happened?
A vulnerability in GoDaddy's Managed WordPress hosting environment was exploited via a **compromised provisioning system**.
- Attackers gained access using a compromised credential and exposed customer data
- Up to ~1.2 million active and inactive Managed WordPress customers were affected
- The breach exposed customer email addresses/numbers, the original WordPress Admin password set at provisioning, sFTP/database usernames and passwords, and (for some) SSL private keys — a **credential/data exposure**, not an SEO-spam PHP injection (that conflates it with the separate PrestaShop skimmer campaign below)

A more serious PHP case in the same family:
**PrestaShop (July 2022, CVE-2022-36408)**: A previously-unknown vulnerability chain (SQL injection + MySQL Smarty cache injection, related to CVE-2022-31181) was exploited in the wild to drop a `blm.php` web shell and inject a **credit-card skimmer** into checkout pages of PrestaShop stores. Affected PrestaShop 1.6.0.10 through 1.7.x before 1.7.8.7.

## 🧠 Root Cause (PrestaShop)
1. **SQL injection**: an unknown vulnerability chain in stores exposing a vulnerable module (or old PrestaShop)
2. **MySQL Smarty cache storage injection**: escalated the SQLi to remote code execution
3. **Web shell drop**: a POST to the vulnerable endpoint + a GET to the homepage created `blm.php` at the web root
4. **Credit card skimmer**: malicious code injected into checkout to steal payment data (a skimmer was found hidden in the One Page Checkout module)

## 💥 Impact
- PrestaShop stores running vulnerable versions/modules were compromised in the wild starting July 2022
- Customer payment/card information was stolen from affected checkout pages
- PrestaShop released an emergency fix (upgrade to 1.7.8.7) and guidance to disable MySQL Smarty cache
- Note: no reliable public figure supports "300,000+ sites" or a "$100M+" cost — those numbers are not documented and are omitted here

## 🎓 Lessons Learned
- **Track CMS/module updates**
- **Keep PHP file permissions strict** (644 files, 755 directories)
- **Use file integrity monitoring** (get notified when files change)
- **Keep auto-update enabled** (but test on staging)
- **Use a web application firewall (WAF)**

## Vibe Coding Connection
When generating PHP/WordPress code with AI:
- AI may suggest old WordPress plugin APIs
- Check CVE status for every plugin AI recommends
- Recommend security plugins (Wordfence, Sucuri)

## 🔗 Source
- https://thehackernews.com/2022/07/hackers-exploit-prestashop-zero-day-to.html (PrestaShop, July 2022)
- https://securityonline.info/cve-2022-36408-zero-day-prestashop-sql-injection-vulnerability/ (CVE-2022-36408)
- https://www.bleepingcomputer.com/news/security/godaddy-hackers-stole-source-code-installed-malware-in-multiyear-breach/ (GoDaddy breach context)
