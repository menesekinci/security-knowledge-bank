---
source: "languages/swift/swiftui-security.md"
title: "🍎 SwiftUI Security Guide"
heading: "4. ATS (App Transport Security)"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [data, deep, injection, language-vuln, navigationlink, preview, swift, swiftui]
chunk: 5/9
---

## 4. ATS (App Transport Security)

```xml
<!-- VULNERABLE: Complete ATS disable — DeepSeek case (Feb 2025) -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- ALLOWED: all HTTP traffic in cleartext! -->
</dict>

<!-- SECURE: Allow specific domains only -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.myapp.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSIncludesSubdomains</key>
            <false/>
        </dict>
    </dict>
</dict>

<!-- BEST: Use certificate pinning -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.myapp.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSPinnedLeafIdentities</key>
            <array>
                <dict>
                    <key>SPKI-SHA256-Base64</key>
                    <string>base64EncodedPublicKeyHash==</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

---