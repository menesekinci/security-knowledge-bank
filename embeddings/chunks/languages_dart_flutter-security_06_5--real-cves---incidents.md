---
source: "languages/dart/flutter-security.md"
title: "🔴 Flutter Security"
heading: "5. Real CVEs / Incidents"
category: "language-vuln"
language: "common"
severity: "high"
tags: [code, cves, explanation, language-vuln, real, secure, vulnerability, vulnerable]
chunk: 6/9
---

## 5. Real CVEs / Incidents

### Flutter Package CVEs

| CVE | Package | Type | Severity | Patch | Description |
|-----|---------|------|----------|-------|-------------|
| **CVE-2024-54461** | `file_selector_android` | Path Traversal (CWE-23) | 7.1 High | 0.5.1+12 | Unsanitized filenames from malicious document providers allow path traversal |
| **CVE-2024-54462** | `image_picker_android` | Path Traversal (CWE-23) | 7.1 High | 0.8.12+18 | Unsanitized filenames from malicious document providers allow path traversal |
| **CVE-2026-27704** | `dart pub` | Zip Slip / Path Traversal (CWE-22, CWE-59) | 7.8 High | Dart 3.11.0 / Flutter 3.41.0 | Symlink traversal via malicious pub packages — can write files outside pub cache |
| **CVE-2025-65112** | PubNet (Dart package service) | Auth Bypass (CWE-862) | 9.4 Critical | 1.1.3 | Unauthenticated package upload enabling supply chain attacks |

### Supply Chain Incidents

- **CVE-2025-65112 — PubNet Auth Bypass**: A self-hosted Dart/Flutter package registry allowed unauthenticated users to upload packages via `/api/storage/upload`. Attackers could masquerade as legitimate package authors, enabling identity spoofing, privilege escalation, and supply chain attacks. CVSS 9.4 (Critical).
  - Source: https://nvd.nist.gov/vuln/detail/CVE-2025-65112

- **CVE-2026-27704 — Dart Pub Zip Slip**: The Dart package manager's extraction logic did not normalize symlink paths before writing files. A malicious package could use symlinks to write files outside the pub cache directory, enabling arbitrary code execution during package resolution.
  - Source: https://nvd.nist.gov/vuln/detail/CVE-2026-27704

### FlutterShell / Malware

- **Operation FlutterBridge (2026)**: A macOS malvertising campaign distributing "FlutterShell" — a backdoor built using the Flutter framework that passed Apple notarization. The malware registered `flutterInvoke` JavaScript channels for C2 communication, exploiting WebView to exfiltrate data from infected macOS systems.
  - Source: https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/

### Dependency-Related CVEs

| CVE | Component | Impact | Description |
|-----|-----------|--------|-------------|
| CVE-2023-2136 | Skia (rendering engine) | High (RCE) | Integer overflow in Skia via crafted image — impacts any Flutter app rendering untrusted images |
| CVE-2022-3445 | Skia (rendering engine) | High (RCE) | Heap buffer overflow in Skia — affects Flutter's Impeller/Skia renderer |

---