---
source: "languages/swift/ios-security-deep.md"
title: "iOS Security Deep Dive"
heading: "4. Jailbreak Detection"
category: "language-vuln"
language: "swift"
severity: "medium"
tags: [accessibility, data, keychain, language-vuln, overview, protection, swift, table, transport]
chunk: 7/9
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