---
source: "languages/swift/case-studies/ios-case-studies.md"
title: "iOS / Swift Case Studies"
heading: "Case Study 2: DeepSeek iOS App — ATS Disabled, Data Sent over HTTP"
category: "case-study"
language: "swift"
severity: "critical"
tags: [case, case-study, references, study, swift]
chunk: 3/6
---

## Case Study 2: DeepSeek iOS App — ATS Disabled, Data Sent over HTTP

### Incident Overview
- **Date**: February 2025
- **Platform**: iOS
- **Severity**: High (all network traffic sent in cleartext)

### Description
Security researchers discovered that the DeepSeek AI iOS application had **App Transport Security (ATS) completely disabled**. The `Info.plist` contained `NSAllowsArbitraryLoads = true`, meaning all network communication — including user chat messages, prompts, and responses — could be intercepted over unencrypted HTTP.

### Root Cause
The developer set `NSAllowsArbitraryLoads` to `true` in the app's Info.plist, disabling all ATS protections. This allowed the app to make plaintext HTTP requests to backend servers.

### Impact
- User conversations with the AI assistant transmitted in cleartext
- Man-in-the-middle attacks could read, modify, or inject prompts/responses
- Sensitive personal data (if any in conversations) exposed to network attackers
- Widespread news coverage damaged user trust

### Technical Details
```xml
<!-- DEEPSEEK's vulnerable Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- All cleartext HTTP allowed -->
</dict>
```

### Lessons for iOS Developers
1. **Never disable ATS completely** in production apps
2. Use granular exceptions only for legacy services that truly cannot support HTTPS
3. Use **certificate pinning** for your API endpoints
4. Test ATS enforcement before shipping: `nscurl --ats-diagnostics https://api.example.com`

### Sources
- https://hawk-eye.io/2025/02/weekly-threat-landscape-digest-week-6/
- https://developer.apple.com/documentation/security/preventing-insecure-network-connections

---