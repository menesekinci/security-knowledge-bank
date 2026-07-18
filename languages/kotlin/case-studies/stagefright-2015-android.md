# Kotlin Android — Stagefright (2015)

## 📅 When Did It Happen?
July 2015

## 🎯 Target System
Android — Stagefright media library (written in C++, called from Kotlin/Java)

## 🔴 What Happened?
Stagefright is Android's media playback engine (written in C/C++). An attacker could achieve RCE on an Android device by sending a specially crafted **MMS message**.
- The user **doesn't need to do anything** — MMS was processed automatically
- The attacker only needed to know your phone number
- 950 million Android devices were affected

**Kotlin connection**: Even though modern Android development uses Kotlin, the native C/C++ code still carries the same risk. Kotlin/Java → JNI → C/C++ calls are the weak link in the security chain.

## 🧠 Root Cause
```cpp
// Vulnerability in Stagefright (simplified):
void parseMetaData(const uint8_t* data, size_t size) {
    uint32_t chunkSize = readUint32(data);  // Controlled by the user!
    
    // NO SIZE CHECK!
    uint8_t* buffer = new uint8_t[chunkSize];  // Heap overflow!
    memcpy(buffer, data + 4, chunkSize);
}
```

## 💥 Impact
- 950M Android devices affected
- Google published an emergency security update (started the monthly Security Patch system)
- Every fix in Stagefright introduced another bug (CVE-2015-3864, CVE-2015-6602...)
- The Android security model was completely overhauled

## 🎓 Lessons Learned
- **JNI/native code is the most risky point** — even if Kotlin/Java is safe, native C/C++ can explode
- **Input validation** at every layer (Java, JNI, C++)
- **Memory-safe languages** (Rust) started being used in Android (Android 12+)
- **Install security updates**

## Vibe Coding Connection
When AI generates Kotlin/Android code:
- AI has a high risk of skipping buffer overflow checks in JNI calls
- Extra caution needed in projects containing native code
- Add "check buffer sizes in JNI" to the prompt

## 🔗 References
- https://blog.zimperium.com/experts-found-a-unicorn-in-the-heart-of-android/
- CVE-2015-1538: https://nvd.nist.gov/vuln/detail/CVE-2015-1538
