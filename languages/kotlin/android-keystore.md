# 🟠 Kotlin Android Keystore Misuse

## Example
```kotlin
// 💀 VULNERABLE — key in SharedPreferences:
val prefs = getSharedPreferences("my_app", Context.MODE_PRIVATE)
prefs.edit().putString("api_key", "sk-12345...").apply()
// On a rooted phone, /data/data/.../shared_prefs/ can be read!

// ✅ SECURE — Android Keystore:
val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
}

// Create the key:
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("my_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
     .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
     .setUserAuthenticationRequired(true)  // Biometric required!
     .build()
)
keyGenerator.generateKey()
```

## Prevention
- Never store API keys in SharedPreferences/plain text
- Use Android Keystore (hardware-backed)
- Add biometric authentication
- Use EncryptedSharedPreferences

---

**Severity: 🟠 High** — Credential leak.
