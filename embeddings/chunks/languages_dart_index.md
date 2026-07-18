---
source: "languages/dart/index.md"
title: "🎯 Dart / Flutter Security"
category: "language-vuln"
language: "common"
severity: "critical"
tags: [contents, language-vuln, references, risk]
---

# 🎯 Dart / Flutter Security

> AI-generated mobile apps often have critical security gaps. Flutter's AOT compilation and cross-platform nature introduce unique risks that traditional mobile security tooling often misses.

## 📋 Contents

1. [🔴 Flutter Security](flutter-security.md) — Common mistakes, insecure storage, WebView, deep linking, Firebase exposure, and AI/vibe-coding risk patterns
2. [🛡️ Hardening Checklist](hardening-checklist.md) — Actionable 15-item checklist for hardening Flutter/Dart applications

## Key Risk Areas at a Glance

| Risk | Severity | CWE | AI Generation Risk |
|------|----------|-----|-------------------|
| Hardcoded API Keys / Secrets | **High** | CWE-312, CWE-798 | Very High |
| Insecure Local Storage | **High** | CWE-312, CWE-276 | High |
| WebView XSS / JS Bridge | **High** | CWE-79, CWE-94 | High |
| Deep Link Hijacking | **Medium** | CWE-287, CWE-601 | Medium |
| Firebase / Backend Config Leak | **High** | CWE-200 | Very High |
| Supply Chain / Package Poisoning | **Critical** | CWE-862, CWE-345 | Medium |
| Dart VM / FlutterShell Injection | **High** | CWE-22, CWE-59 | Low |

## References

- [Flutter Security Docs](https://docs.flutter.dev/security)
- [Flutter Security False Positives](https://docs.flutter.dev/reference/security-false-positives)
- [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/)
- [OWASP MASVS](https://mas.owasp.org/)
- [8ksec — Securing Flutter Applications](https://8ksec.io/securing-flutter-applications/)
- [Appknox — Flutter App Security Testing](https://www.appknox.com/blog/flutter-app-security-testing-why-most-tools-fail-what-works)
- [Ostorlab — Flutter App Security Checklist](https://docs.ostorlab.co/security/flutter_app_security_checklist.html)
- [Flutter Security Advisories (GitHub)](https://github.com/flutter/flutter/security)
- [Dart SDK Security Advisories (GitHub)](https://github.com/dart-lang/sdk/security)
- [OpenCVE — Flutter CVEs](https://app.opencve.io/cve/?vendor=flutter)

---
*Auto-refreshed index — Last updated: 2026-07-17*
