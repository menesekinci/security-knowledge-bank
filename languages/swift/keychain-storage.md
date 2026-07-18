# 🟡 Swift Keychain & Credential Storage

## What Is It?
On iOS, sensitive data (tokens, passwords) should be stored in **Keychain**.
AI's most common mistake: using **UserDefaults or plain text files**.

## Example
```swift
// 💀 VULNERABLE:
UserDefaults.standard.set(apiToken, forKey: "auth_token")
// UserDefaults is NOT ENCRYPTED! Readable on jailbroken phones.

// ✅ SECURE (Keychain):
import Security

func saveToken(_ token: String) {
    let data = Data(token.utf8)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "auth_token",
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemAdd(query as CFDictionary, nil)
}
```

## Prevention
- Never store tokens/passwords in UserDefaults
- Use Keychain with the correct access level (`ThisDeviceOnly`)
- Add Biometric (FaceID/TouchID)
- Control Keychain's iCloud sync

---

**Severity: 🔴 Critical** — Credential leak.
