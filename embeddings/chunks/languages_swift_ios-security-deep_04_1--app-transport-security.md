---
source: "languages/swift/ios-security-deep.md"
title: "iOS Security Deep Dive"
heading: "1. App Transport Security (ATS)"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [accessibility, data, keychain, language-vuln, overview, protection, swift, table, transport]
chunk: 4/9
---

## 1. App Transport Security (ATS)

ATS enforces HTTPS connections by default since iOS 9. Disabling ATS opens the app to man-in-the-middle attacks. A notable case: in 2025, **DeepSeek's iOS app was found to have ATS disabled**, allowing sensitive data to be sent over unencrypted HTTP.

### Vulnerable Info.plist (ATS Disabled)

```xml
<!-- VULNERABLE: ATS completely disabled — all HTTP allowed -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

### Secure Info.plist (Granular Exceptions)

```xml
<!-- SECURE: Specific exceptions only -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.legacy-service.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.2</string>
            <key>NSRequiresCertificateTransparency</key>
            <true/>
        </dict>
    </dict>
</dict>
```

### ATS Enforcement in Code

```swift
// SECURE: Force HTTPS in network requests
import Foundation

class SecureURLSession {
    static func create() -> URLSession {
        let config = URLSessionConfiguration.default
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        config.requiresCertificateTransparency = true
        config.httpAdditionalHeaders = [
            "X-Forwarded-Proto": "https"
        ]
        return URLSession(configuration: config)
    }
}

// SECURE: Validate server trust
class PinningURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Certificate pinning
        let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
        SecTrustSetPolicies(serverTrust, policies as CFTypeRef)
        
        var result: CFError?
        let isTrusted = SecTrustEvaluateWithError(serverTrust, &result)
        
        if isTrusted {
            // Verify pinned certificate
            if let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                let serverCertData = SecCertificateCopyData(serverCert) as Data
                let pinnedCertData = getPinnedCertificateData()
                
                if serverCertData == pinnedCertData {
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                    return
                }
            }
        }
        
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

---