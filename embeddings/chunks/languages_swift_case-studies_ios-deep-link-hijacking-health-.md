---
source: "languages/swift/case-studies/ios-deep-link-hijacking-health-app.md"
title: "iOS Deep Link Hijacking — Health App Custom URL Schemes ($5,000 Bounty)"
category: "case-study"
language: "swift"
severity: "high"
tags: [case-study, cause, details, impact, overview, root, secure, swift, technical]
---

# iOS Deep Link Hijacking — Health App Custom URL Schemes ($5,000 Bounty)

**Language:** Swift / iOS
**Vulnerability Type:** Deep Link Hijacking, URL Scheme Exploitation
**Bounty:** $5,000
**Date:** 2024
**Researcher:** Aditya Dixit (Cobalt Labs, HackerOne)
**Platform:** iOS Health Application (anonymized as "MedVault")

## Overview

During a penetration test of an iOS health application ("MedVault"), security researcher Aditya Dixit discovered that the app exclusively used **custom URL schemes** for deep linking — with **no Universal Links implementation**. Any malicious app on the same device could register the same URL schemes and intercept all deep links, including those carrying sensitive medical data parameters.

## Root Cause

The app relied entirely on custom URL schemes (`medvault://` and `com.novahealth.medvault://`) for all deep linking functionality. Custom URL schemes have **no ownership verification** — iOS uses a first-come-first-served model. If two apps register the same scheme, there is no guarantee the correct app receives the link.

Additionally, the app passed **sensitive medical record IDs** directly in the URL without source validation.

## Technical Details

### App's Registered Schemes (Info.plist)
```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>medvault</string>
            <string>com.novahealth.medvault</string>
        </array>
    </dict>
</array>
```

### Deep Link Handler (Vulnerable)
```swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
        return false
    }
    
    // ⚠️ No source validation — just handles any URL
    switch components.host {
    case "dashboard":
        navigateToDashboard()
    case "symptom":
        // ⚠️ Passes record ID directly without authorization
        if let recordId = components.queryItems?.first(where: { $0.name == "existingSymptomRecordId" })?.value {
            navigateToSymptomReport(recordId: recordId)
        }
    case "report":
        if let reportId = components.queryItems?.first(where: { $0.name == "erReportId" })?.value {
            generateERReport(reportId: reportId)
        }
    default:
        break
    }
    return true
}
```

### Frida Proof of Concept

The researcher used Frida to hook into iOS URL handling and validate interception:

```javascript
// Frida script to intercept deep links
Interceptor.attach(
    ObjC.classes.UIApplication['- openURL:options:completionHandler:'].implementation,
    {
        onEnter: function(args) {
            var url = ObjC.Object(args[2]).absoluteString().toString();
            console.log('[>] Intercepted URL: ' + url);
            // Attacker can now read and modify the URL
        }
    }
);
```

## Impact

- **Sensitive medical data exposure**: Clinical record IDs, symptom reports, ER documents
- **Phishing**: Malicious app could present a fake login screen after intercepting a legitimate link
- **Session hijacking**: Deep links containing session tokens could be stolen
- **Any app on the device could intercept links**, regardless of permissions

## Fix / Secure Code

```swift
// 1. Implement Universal Links with apple-app-site-association (AASA) file
// Host at https://medvault.com/apple-app-site-association
{
  "applinks": {
    "apps": [],
    "details": [{
      "appID": "TEAMID.com.novahealth.medvault",
      "paths": ["/dashboard/*", "/symptom/*", "/report/*"]
    }]
  }
}

// 2. Validate source in deep link handler
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // Check if this is a Universal Link (trusted) or custom scheme (untrusted)
    guard let sourceApp = options[.sourceApplication] as? String else {
        // No source — likely a custom URL scheme from unknown origin
        // Treat as untrusted
        return handleUntrustedDeepLink(url)
    }
    
    // Verify source is our own app or a trusted system app
    guard isTrustedSource(sourceApp) else {
        return false
    }
    
    return handleDeepLink(url)
}

func handleUntrustedDeepLink(_ url: URL) -> Bool {
    // Force re-authentication for untrusted links
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let host = components.host else {
        return false
    }
    
    // Only allow navigation to non-sensitive screens
    switch host {
    case "public-landing":
        navigateToLandingPage()
        return true
    default:
        // Require authentication for everything else
        presentLoginScreen {
            self.handleDeepLink(url)
        }
        return false
    }
}
```

## Lessons

1. **Universal Links are mandatory for production iOS apps** — custom URL schemes are inherently insecure
2. **Validate link source** — never trust the URL alone, verify who sent it
3. **Sensitive parameters in URLs** (medical record IDs, session tokens) are leakable
4. **Frida hooking confirms** how easy deep link interception is
5. **Deep links should not be the primary auth mechanism** — always re-verify authorization server-side

## References

- [Original Blog Post — Aditya Dixit](https://blog.dixitaditya.com/hijacking-ios-deep-links-in-a-health-app-using-custom-url-schemes)
- [Apple — Supporting Universal Links](https://developer.apple.com/ios/universal-links/)
- [Apple — Allowing Apps to Register URL Schemes](https://developer.apple.com/documentation/xcode/allowing_apps_to_register_url_schemes)
- [OWASP iOS Deep Link Testing](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Custom URL Schemes — Security Risks](https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content)
