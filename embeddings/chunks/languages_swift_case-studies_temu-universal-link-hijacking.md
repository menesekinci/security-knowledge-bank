---
source: "languages/swift/case-studies/temu-universal-link-hijacking.md"
title: "Temu Universal Link Hijacking via Misconfigured AASA File"
category: "case-study"
language: "swift"
severity: "high"
tags: [attack, case-study, cause, details, impact, overview, root, scenario, swift, technical]
---

# Temu Universal Link Hijacking via Misconfigured AASA File

**Language:** Swift / iOS
**Vulnerability Type:** Universal Link Hijacking, AASA Misconfiguration
**Platform:** iOS
**Date:** 2024
**Platform:** Temu iOS App
**Researcher:** M. Habib (HackerOne Temu Bounty Program)

## Overview

Security researcher M. Habib discovered that Temu's iOS app had a **severely misconfigured `apple-app-site-association` (AASA) file** that allowed Universal Link Hijacking. The AASA file's overly broad path matching (`paths: ["*"]`) meant that any iOS app with the same team ID association could intercept Temu's universal links, enabling phishing attacks, session hijacking, and unauthorized tracking.

## Root Cause

Temu's AASA file used a wildcard (`*`) for all paths, which is the most permissive possible configuration. This effectively made Universal Links as insecure as custom URL schemes — any app that could claim association with the domain could intercept any link.

## Technical Details

### Vulnerable AASA File
```json
// https://temu.com/apple-app-site-association
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.temu",
      "paths": ["*"]  // ⚠️ ALL paths match — completely permissive!
    }]
  }
}
```

**What this means:**
- ALL universal links sent to Temu's domain match the AASA file
- If another iOS app somehow registers association with the same domain (or an attacker exploits a CDN misconfiguration), they can intercept ALL links
- The `*` wildcard means no path restriction exists — `/product/*`, `/search/*`, `/payment/*` all match equally

### Comparison: Secure AASA
```json
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.temu",
      "paths": ["/product/*", "/search/*", "/account/*", "NOT /admin/*", "NOT /internal/*"]
    }]
  }
}
```

A secure AASA file should:
1. List **explicit path patterns** instead of `*`
2. Use `NOT` prefixes to exclude sensitive paths
3. Be the minimum set of paths required by the app

## Attack Scenario

1. A malicious app registers the same domain association via a compromised CDN or DNS misconfiguration
2. User clicks a legitimate Temu universal link (e.g., from a marketing email)
3. iOS routes the link to the malicious app instead of Temu
4. Malicious app presents a phishing UI mimicking Temu's login/checkout
5. User enters credentials — attacker captures them
6. App then redirects to legitimate Temu to avoid suspicion

## Impact

- **Phishing**: Users redirected to fake versions of the app
- **Session Hijacking**: If deep links contain session tokens
- **Tracking**: Malicious app can collect click data and user behavior
- **Reputation Damage**: Users lose trust in the app's security

## Fix

Temu needed to restrict their AASA file to specific path patterns:

```json
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.temu",
      "paths": [
        "/product/*",
        "/search/*",
        "/account/*",
        "/order/*",
        "/category/*",
        "NOT /admin/*",
        "NOT /internal/*"
      ]
    }]
  }
}
```

## Secure AASA Configuration Checklist

- [ ] NO wildcard (`*`) paths — always use explicit patterns
- [ ] Exclude sensitive paths with `NOT` prefix
- [ ] Define the minimum set of paths needed by the app
- [ ] Verify AASA file is served with `Content-Type: application/json` over HTTPS
- [ ] Use Apple's `apple-app-site-association` validation tool
- [ ] Test with `swcutil` command-line tool

## References

- [Original Blog — Universal Link Hijacking via Misconfigured AASA on Temu.com](https://medium.com/@m.habibgpi/universal-link-hijacking-via-misconfigured-aasa-file-on-temu-com-eadfcb745e4e)
- [Apple — Supporting Universal Links](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app)
- [Apple — AASA File Format](https://developer.apple.com/documentation/bundleresources/applinks)
- [HackTricks — iOS Universal Links](https://hacktricks.wiki/en/mobile-pentesting/ios-pentesting/ios-universal-links.html)
- [Temu HackerOne Bounty Program](https://hackerone.com/temu)
