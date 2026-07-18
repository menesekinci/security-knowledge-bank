---
source: "languages/go/case-studies/boltdb-typosquat-supply-chain-attack.md"
title: "BoltDB Typosquat: Go Supply Chain Attack Exploiting Module Proxy Caching"
category: "case-study"
language: "go"
severity: "high"
tags: [case-study, go, impact, lesson, remediation, summary]
---

# BoltDB Typosquat: Go Supply Chain Attack Exploiting Module Proxy Caching

**Date:** Discovered February 2025 (malicious package published November 2021)  
**Package:** `github.com/boltdb-go/bolt` (typosquat of `github.com/boltdb/bolt`)  
**Type:** Software Supply Chain Attack / Typosquatting

## Summary

Socket researchers discovered a malicious Go package that typosquatted the widely used BoltDB database module. The package `github.com/boltdb-go/bolt` contained a backdoor enabling remote code execution via a C2 server. The malware exploited Go Module Proxy's **indefinite caching** to persist undetected for over **3 years**. After the package was cached by the Go Module Mirror, the threat actor rewrote GitHub tags to point to clean code, hiding the malware from manual review.

## How It Worked

1. **Typosquatting**: The threat actor (GitHub alias "boltdb-go") created `github.com/boltdb-go/bolt` to impersonate the legitimate `github.com/boltdb/bolt`.

2. **Malicious version `v1.3.1`** was published to GitHub in November 2021, triggering the Go Module Proxy to fetch and cache it indefinitely.

3. **Tag rewriting**: After the Go Module Mirror cached the malicious version, the threat actor rewrote the `v1.3.1` git tag to point to clean code. Manual inspection of GitHub would show benign code, but the Go Module Proxy would continue serving the cached malicious version.

4. **Backdoor capability**: Remote code execution, C2 communication to `49.12.198[.]231:20022`, full system compromise.

## Impact

- First documented instance of a malicious actor exploiting Go Module Mirror's indefinite caching
- Remained undetected for **3+ years** (November 2021 to February 2025)
- BoltDB is trusted by organizations including **Shopify** and **Heroku**, with 8,367+ dependent packages
- Over 80 unresolved issues in the original repo since 2015 — the legitimate BoltDB is essentially unmaintained
- Potentially impacted **thousands of organizations**

## Key Lesson

Go's Module Proxy caching is designed for availability and performance, but it can be **weaponized** by attackers. Once a malicious module is cached, it persists even if the source repository is cleaned. The `.info` file on the Go Module Mirror lacked the resolved git commit SHA that would link back to the malicious code. Developers should **verify module checksums**, use `go.sum`, and consider private module proxies for enterprise use.

## Remediation

- Google removed the module from the Go Module Proxy and GitHub
- Added to the Go vulnerability database (GO-2025-3451)
- Fixes being explored via Capslock (capability analysis) and deps.dev comparisons

## References

- https://socket.dev/blog/malicious-package-exploits-go-module-proxy-caching-for-persistence
- https://snyk.io/blog/go-malicious-package-alert/
- https://thehackernews.com/2025/02/malicious-go-package-exploits-module.html
- https://arstechnica.com/security/2025/02/backdoored-package-in-go-mirror-site-went-unnoticed-for-3-years/
- https://pkg.go.dev/vuln/GO-2025-3451
