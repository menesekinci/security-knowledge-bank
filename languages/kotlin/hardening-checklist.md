# 🌊 Kotlin / Android Security Hardening Checklist

> Items to check in every Kotlin/Android project before deployment.

## ✅ Data Storage
- [ ] Is sensitive data in EncryptedSharedPreferences / Android Keystore?
- [ ] No API key/token in SharedPreferences?
- [ ] Is SQLite Database encrypted? (SQLCipher)
- [ ] Are internal storage files created with MODE_PRIVATE?

## ✅ Network
- [ ] Is Network Security Config defined? (AndroidManifest)
- [ ] Is SSL Pinning implemented?
- [ ] Are ATS-like settings configured? (cleartext traffic disabled?)
- [ ] Is WebView JavaScript bridge security-checked?

## ✅ Authentication
- [ ] Is Biometric (FaceID/Fingerprint) correctly implemented?
- [ ] Is token storage in Keychain/Keystore?
- [ ] Is deep link validation performed?
- [ ] Are Android App Links correctly configured?

## ✅ Code
- [ ] Is `!!` operator minimized? (?: elvis used?)
- [ ] Is `lateinit var` used without initialization?
- [ ] Is ProGuard/R8 obfuscation active?
- [ ] Is `PendingIntent` FLAG_IMMUTABLE used? (Android 12+)
- [ ] Are implicit intents security-checked?

## ✅ Android Specific
- [ ] Is APK signature scheme v2/v3 used?
- [ ] Are export activities justified? (`android:exported`)
- [ ] Is there Content Provider URI permission control?
- [ ] Are broadcast receivers security-checked?
- [ ] Has notification trampolining risk been assessed?

## 🛡️ Vibe Coding Extra
- [ ] Was AI's `!!` usage replaced with optional binding?
- [ ] Was AI's SharedPreferences recommendation replaced with EncryptedPreferences?
- [ ] Is AI's WebView JavaScript bridge security-checked?
