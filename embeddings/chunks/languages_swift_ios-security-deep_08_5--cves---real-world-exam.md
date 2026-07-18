---
source: "languages/swift/ios-security-deep.md"
title: "iOS Security Deep Dive"
heading: "5. CVEs & Real-World Examples"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [accessibility, data, keychain, language-vuln, overview, protection, swift, table, transport]
chunk: 8/9
---

## 5. CVEs & Real-World Examples

### CVE-2025-24204 — macOS gcore Keychain Memory Read
- **Description**: Apple mistakenly granted the `/usr/bin/gcore` utility the `com.apple.system-task-ports.read` entitlement, allowing it to read the memory of **any process** — including the Keychain process, decrypted iOS app data, and other protected memory — even with System Integrity Protection (SIP) enabled
- **Affected**: macOS, but impacted iOS app security (keychain and app data decryptable)
- **CVSS**: 7.5 (High)
- **Fix**: Apple removed the entitlement in macOS Sequoia 15.2 update
- **Source**: https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/

### CVE-2025-24085 — iOS Kernel Jailbreak (17.0)
- **Description**: Powerful kernel vulnerability in iOS 17.0 used by jailbreak developers. The bug allowed arbitrary kernel memory read/write, defeating all security mitigations including PAC and KASLR. This was eventually patched in iOS 18.3
- **Affected**: iOS 17.0 through 17.4
- **CVSS**: 8.8 (High)
- **Fix**: Update to iOS 18.3+
- **Source**: https://www.youtube.com/watch?v=yKfdq1ZyuA8

### CVE-2024-23265 — iOS libxpc Memory Corruption
- **Description**: A memory corruption vulnerability in libxpc discovered by Pangu Lab. Could allow a malicious application to execute arbitrary code with system privileges
- **Affected**: iOS 17.4 and earlier
- **CVSS**: 7.8 (High)
- **Fix**: Patched in iOS 17.4
- **Source**: https://support.apple.com/en-us/120893

### DeepSeek iOS App ATS Disabled (2025)
- **Description**: Security researchers discovered that DeepSeek's iOS app had App Transport Security completely disabled (`NSAllowsArbitraryLoads = true`). This meant all network communication from the app could be intercepted over unencrypted HTTP, exposing user queries and AI responses to man-in-the-middle attacks
- **Impact**: Sensitive user data (conversations, personal information) transmitted in cleartext
- **Fix**: Enable ATS; use certificate pinning for API endpoints
- **Source**: https://hawk-eye.io/2025/02/weekly-threat-landscape-digest-week-6/

### CVE-2025-43529 — WebKit Zero-Day (Targeted Attacks)
- **Description**: A WebKit use-after-free vulnerability being exploited in extremely sophisticated attacks against specific targeted individuals. Could lead to arbitrary code execution when visiting a malicious website
- **Affected**: iOS devices (all versions prior to patch)
- **CVSS**: 9.8 (Critical)
- **Fix**: Update to latest iOS security patch
- **Source**: https://www.hkcert.org/security-bulletin/apple-products-multiple-vulnerabilities_20251215

---