---
source: "languages/kotlin/android-security-deep.md"
title: "Android Security Deep Dive"
heading: "5. CVEs & Real-World Examples"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [content, intent, interception, javascript, kotlin, language-vuln, overview, provider, table, webview]
chunk: 8/9
---

## 5. CVEs & Real-World Examples

### CVE-2025-48593 — Android Bluetooth (HFP client) Use-After-Free RCE
- **Description**: Use-after-free (CWE-416) in `bta_hf_client_cb_init` of `bta_hf_client_main.cc`, the Android Bluetooth stack's Hands-Free Profile (HFP) client. A crafted Bluetooth interaction can corrupt memory and lead to remote code execution with no user interaction and no additional execution privileges. It is a Bluetooth-range (adjacent) flaw — **not** a "media framework zero-click" bug
- **Affected**: Android 13, 14, 15, and 16 (Bluetooth module; devices acting as HFP audio endpoints — headsets, watches, cars — are notably exposed)
- **CVSS**: 8.0 (High) — `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` per the Android/GHSA advisory (NVD lists a 7.8 local-vector variant; an earlier 9.8 estimate was revised)
- **Fix**: Patched in the Android Security Bulletin — **November 2025** (patch level 2025-11-01)
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-48593 · https://github.com/advisories/GHSA-frwr-8p82-qrjm

### CVE-2025-27363 — FreeType Out-of-Bounds Write (font parsing)
- **Description**: Out-of-bounds write in **FreeType** ≤ 2.13.0 when parsing subglyph structures in TrueType GX and variable font files. A signed short value is incorrectly cast to an unsigned long, wrapping around and allocating an undersized heap buffer, after which up to six signed-long values are written past its end — enabling control-flow hijack and arbitrary code execution. FreeType is the font-rendering library used by Android (and many other platforms); this is **not** an "Android kernel" bug
- **Affected**: Any app/OS loading TrueType GX / variable fonts via FreeType ≤ 2.13.0 (Android ships FreeType; fixed in FreeType 2.13.3). Reported exploited in the wild — listed in CISA KEV
- **CVSS**: 8.1 (High)
- **Fix**: Update FreeType to 2.13.3+ / apply the vendor (Android) security patch that ships the fixed FreeType
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-27363 · https://thehackernews.com/2025/03/meta-warns-of-freetype-vulnerability.html

### Microsoft — Android SDK Intent Redirection (2025-2026)
- **Description**: A severe Android intent-redirection vulnerability discovered in a widely deployed third-party SDK. The SDK's exported activity accepted arbitrary intents and forwarded them without validation, allowing malicious apps to access internal components and sensitive user data across millions of apps
- **Impact**: Over 1 billion app installs affected
- **Fix**: SDK vendor patched; apps should validate intent sources
- **Source**: https://www.microsoft.com/en-us/security/blog/2026/04/09/intent-redirection-vulnerability-third-party-sdk-android/

### WebView JavaScript Bridge RCE (Multiple Bug Bounty Reports)
- **Description**: Numerous bug bounty reports document Android apps with `addJavascriptInterface` exposing dangerous methods while loading untrusted URLs. This remains one of the most common high-severity Android findings
- **Impact**: Full data access, command execution, credential theft
- **Fix**: Never expose `@JavascriptInterface` methods that perform dangerous operations; validate all inputs; restrict loaded URLs to HTTPS
- **Source**: https://medium.com/@youssefhussein212103168/exploiting-insecure-android-webview-with-javascript-interface-a4d3abf9ec09

### CVE-2024-XXXX — Multiple Samsung WebView RCE (2024)
- **Description**: Multiple Samsung devices shipped with WebView versions vulnerable to RCE through exposed JavaScript interfaces in pre-installed applications. Attackers could exploit these via malicious websites
- **Affected**: Samsung Galaxy devices with unpatched pre-installed apps
- **CVSS**: 8.8 (High)
- **Fix**: Samsung released patches through Galaxy Store
- **Source**: https://www.hkcert.org/security-bulletin/android-multiple-vulnerabilities_20260303

### Content Provider SQL Injection (Common Pattern)
- **Description**: Multiple bug bounty reports demonstrate Android Content Providers with SQL injection vulnerabilities. Attackers exploit improperly parameterized queries in `query()`, `insert()`, `update()`, and `delete()` methods
- **CVSS**: Varies (7.5-9.1)
- **Fix**: Always use parameterized queries (`?` placeholders); validate URI paths; restrict provider permissions
- **Source**: https://blog.ostorlab.co/android-sql-contentProvider-sql-injections.html

---