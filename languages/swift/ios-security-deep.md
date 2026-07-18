# iOS Security Deep Dive

> **Category:** Languages / Swift
> **Last Updated:** July 2026

## Overview

This deep dive covers iOS-specific security issues that Swift developers must understand: App Transport Security (ATS), data protection APIs, Keychain accessibility classes, jailbreak detection (and its pitfalls), and CVE-backed examples.

---

## Table of Contents

1. [App Transport Security (ATS)](#1-app-transport-security-ats)
2. [Data Protection](#2-data-protection)
3. [Keychain Accessibility](#3-keychain-accessibility)
4. [Jailbreak Detection](#4-jailbreak-detection)
5. [CVEs & Real-World Examples](#5-cves--real-world-examples)

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

## 2. Data Protection

iOS Data Protection encrypts files using class-based encryption tied to device lock state.

### File Protection Classes

| Class | Description | When accessible |
|---|---|---|
| `Complete` | Encrypted until device unlocked | After first unlock |
| `CompleteUnlessOpen` | File openable while locked, new writes encrypted | Mixed |
| `CompleteUntilFirstUserAuthentication` | Encrypted until first unlock after boot | After first unlock |
| `NoProtection` | No encryption (⚠️) | Always |

### Vulnerable File Protection

```swift
// VULNERABLE: No data protection on sensitive file
import Foundation

class InsecureDataStorage {
    func saveToken(_ token: String) {
        let filePath = getDocumentsDirectory().appendingPathComponent("auth_token.dat")
        
        // No protection attributes — file is accessible even when device is locked!
        try? token.write(to: filePath, atomically: true, encoding: .utf8)
    }
    
    // Also vulnerable: UserDefaults for sensitive data
    func saveToUserDefaults(_ token: String) {
        UserDefaults.standard.set(token, forKey: "auth_token")
        // UserDefaults is NOT encrypted!
    }
}
```

### Secure File Protection

```swift
// SECURE: Data protection on sensitive files
import Foundation

class SecureDataStorage {
    func saveSensitiveData(_ data: Data, filename: String) throws {
        let filePath = getDocumentsDirectory().appendingPathComponent(filename)
        
        // Write with complete protection
        try data.write(to: filePath, options: .completeFileProtection)
    }
    
    func saveTokenToKeychain(_ token: String, service: String, account: String) throws {
        // Use Keychain instead of files for tokens
        let data = token.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
}

// File protection for Core Data
let container = NSPersistentContainer(name: "AppData")
container.loadPersistentStores { description, error in
    // Core Data automatically uses NSFileProtectionComplete
    // But verify:
    let storeURL = description.url!
    let resourceValues = try? (storeURL as NSURL).resourceValues(forKeys: [
        URLResourceKey.fileProtectionKey
    ])
    assert(resourceValues?[URLResourceKey.fileProtectionKey] as? String == 
           URLFileProtection.complete.rawValue)
}
```

---

## 3. Keychain Accessibility

The iOS Keychain provides encrypted storage for small secrets. The `kSecAttrAccessible` attribute controls when the item is accessible.

### Keychain Accessibility Levels

| kSecAttrAccessible value | Security | Use case |
|---|---|---|
| `kSecAttrAccessibleAlways` | 🚫 Lowest | Never use — accessible even when locked |
| `kSecAttrAccessibleAlwaysThisDeviceOnly` | 🚫 Low | Never use — accessible when locked, not backed up |
| `kSecAttrAccessibleWhenUnlocked` | ✅ Good | Default — accessible when device unlocked |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | ✅ Better | Same + not backed up to iCloud |
| `kSecAttrAccessibleAfterFirstUnlock` | ⚠️ Use carefully | Accessible after first boot unlock |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | ⚠️ | Same + not backed up |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | 🔒 Best | Requires device passcode |

### Vulnerable Keychain Usage

```swift
// VULNERABLE: Using "Always" accessibility — accessible when locked!
import Security

class InsecureKeychain {
    func savePassword(_ password: String, for account: String) {
        let data = password.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            // VULNERABLE: Accessible even when device is locked!
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        ]
        
        SecItemAdd(query as CFDictionary, nil)
    }
}
```

### Secure Keychain Usage

```swift
// SECURE: Proper keychain accessibility
import Foundation
import Security
import LocalAuthentication

class SecureKeychainManager {
    
    /// Save data with biometric protection (requires FaceID/TouchID + passcode)
    @available(iOS 11.3, *)
    func saveWithBiometrics(_ data: Data, for key: String) throws {
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            nil
        )
        
        guard let accessControl = accessControl else {
            throw KeychainError.accessControlFailed
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
            kSecUseAuthenticationContext as String: LAContext(),
        ]
        
        var status = SecItemAdd(query as CFDictionary, nil)
        
        if status == errSecDuplicateItem {
            // Update existing item
            let updateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: key,
            ]
            let attributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessControl as String: accessControl,
            ]
            status = SecItemUpdate(updateQuery as CFDictionary, attributes as CFDictionary)
        }
        
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
    
    /// Save without biometrics, but with device-only scope
    func saveDeviceOnly(_ data: Data, for key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false, // Don't sync to iCloud
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
}
```

---

## 4. Jailbreak Detection

Jailbreak detection attempts to identify if the device is jailbroken. However, it is **not a security control** — it's easily bypassed and can give a false sense of security.

### Anti-Pattern: Jailbreak Detection as a Security Control

```swift
// NOT RECOMMENDED: Jailbreak detection can be bypassed
class JailbreakDetector {
    static func isJailbroken() -> Bool {
        // Check for Cydia
        if UIApplication.shared.canOpenURL(URL(string: "cydia://")!) {
            return true
        }
        
        // Check for common jailbreak files
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
        ]
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        return false
    }
}

// Bad: Using jailbreak detection as the ONLY security control
if JailbreakDetector.isJailbroken() {
    exit(0)  // Can trivially be bypassed with hooking
}
```

### Better Approach: Runtime Integrity + Keychain

```swift
// BETTER: Combine integrity checks with real security controls
class RuntimeSecurityManager {
    
    static func verifyEnvironment() -> SecurityLevel {
        let level = SecurityLevel()
        
        // 1. Check for debugger (more reliable than jailbreak check)
        level.isDebugged = isDebuggerAttached()
        
        // 2. Check signature integrity
        level.signatureValid = verifyCodeSignature()
        
        // 3. Real security: use hardware-backed keys
        level.secureEnclaveAvailable = isSecureEnclaveAvailable()
        
        // 4. Don't crash/exit — degrade gracefully
        if level.isDebugged {
            // Log and report, but don't terminate
            logSecurityEvent(.debuggerDetected)
        }
        
        return level
    }
    
    private static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // Secure Enclave key usage (real protection)
    static func createSecureKey() -> SecKey? {
        guard isSecureEnclaveAvailable() else { return nil }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: "com.app.securekey",
                kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
                    nil,
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                    .privateKeyUsage,
                    nil
                )!
            ]
        ]
        
        return SecKeyCreateRandomKey(attributes as CFDictionary, nil)
    }
}
```

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

## References

- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Apple — Keychain Data Protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [Apple — About iOS Security Content](https://support.apple.com/en-us/120893)
- [OWASP iOS Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [NIST — Mobile Threat Catalogue](https://pages.nist.gov/mobile-threat-catalogue/)
- [HawkEye — DeepSeek ATS Disabled](https://hawk-eye.io/2025/02/weekly-threat-landscape-digest-week-6/)
- [HelpNetSecurity — CVE-2025-24204 macOS gcore](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
