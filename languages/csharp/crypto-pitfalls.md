# 🔴 Insecure Cryptography in .NET (C#)

> **Category:** Cryptographic Failures  
> **Language:** C# / .NET  
> **Severity:** High to Critical  
> **CWE:** CWE-327 (Broken/Risky Crypto Algorithm), CWE-328 (Weak Hash), CWE-330 (Insufficient Randomness), CWE-347 (Improper Verification of Cryptographic Signature)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🔴 High–Critical (context-dependent: auth bypass, token forgery, data exposure) |
| **Primary CWE** | CWE-327, CWE-328, CWE-330, CWE-347, CWE-916 (password hashing without salt/work factor) |
| **OWASP** | A02:2021 Cryptographic Failures |

## Vulnerability Explanation

.NET applications frequently misuse cryptography in ways that look “secure enough” in demos but fail under real attack:

1. **Legacy algorithms** — MD5, SHA-1, DES, TripleDES, RC2 for integrity or confidentiality.
2. **Wrong tool for the job** — using `SHA256.HashData` for passwords instead of a password-based KDF (PBKDF2 / Argon2 / scrypt via libraries).
3. **Static or hardcoded IVs/keys** — AES with a fixed IV, keys embedded in source or config committed to git.
4. **Non-authenticated encryption** — AES-CBC without HMAC (or Encrypt-then-MAC) enabling padding oracle / ciphertext malleability.
5. **Weak RNG** — `System.Random` or `Guid.NewGuid()` for security tokens, session IDs, CSRF tokens, password reset codes.
6. **Certificate / chain validation bypass** — `ServerCertificateCustomValidationCallback` that always returns `true`, or incomplete X.509 chain checks.
7. **Obsolete APIs** — older `RijndaelManaged`, default ECB modes in sample code, manual padding.

Modern .NET provides solid primitives (`AesGcm`, `RandomNumberGenerator`, `Rfc2898DeriveBytes` / `PasswordHasher`, ASP.NET Core Data Protection). The vulnerability is almost always **API misuse**, not a bug in the BCL itself.

## How AI / Vibe Coding Generates This

```
Prompt: "Encrypt user PII before saving to SQL Server"
AI: uses Aes.Create(), Mode=CBC, fixed IV = zeros or Encoding.UTF8.GetBytes("1234567890123456"),
    key from appsettings "SecretKey123", no MAC → padding oracle + key leak risk

Prompt: "Hash passwords for login"
AI: Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)))
    — no salt, no work factor, GPU-crackable

Prompt: "Generate API key / OTP"
AI: new Random().Next(100000, 999999) or Guid.NewGuid().ToString()
```

Training data is full of Stack Overflow snippets from 2010–2018: MD5 checksums, `RNGCryptoServiceProvider` copy-paste with bugs, `ServicePointManager.ServerCertificateValidationCallback = delegate { return true; }`. Models reproduce these patterns because they “compile and work.”

## Vulnerable Code

```csharp
// 💀 WEAK password "hash"
public static string HashPassword(string password)
{
    using var sha = SHA256.Create();
    return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(password)));
}

// 💀 Predictable token
public static string CreateResetToken()
{
    var rng = new Random(); // process-wide, seedable, not crypto-safe
    return rng.Next(100000, 999999).ToString();
}

// 💀 AES-CBC fixed IV, no authentication
public static byte[] EncryptPii(string plaintext, byte[] key)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.Mode = CipherMode.CBC;
    aes.IV = new byte[16]; // all zeros — same plaintext → same ciphertext
    using var enc = aes.CreateEncryptor();
    return enc.TransformFinalBlock(Encoding.UTF8.GetBytes(plaintext), 0, plaintext.Length);
}

// 💀 TLS validation disabled (common in "just make it work" AI output)
handler.ServerCertificateCustomValidationCallback =
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
```

## Secure Fix

```csharp
// ✅ Password hashing (ASP.NET Core Identity style or standalone)
using Microsoft.AspNetCore.Identity;
var hasher = new PasswordHasher<object>();
string hash = hasher.HashPassword(null!, password);
// verify: hasher.VerifyHashedPassword(null!, hash, password)

// Or PBKDF2 explicitly:
byte[] salt = RandomNumberGenerator.GetBytes(16);
byte[] derived = Rfc2898DeriveBytes.Pbkdf2(
    password, salt, iterations: 600_000, HashAlgorithmName.SHA256, outputLength: 32);

// ✅ Crypto-safe tokens
string token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

// ✅ AES-GCM (authenticated encryption)
public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptAesGcm(byte[] key, byte[] plaintext)
{
    byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
    byte[] ciphertext = new byte[plaintext.Length];
    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
    using var gcm = new AesGcm(key, tag.Length);
    gcm.Encrypt(nonce, plaintext, ciphertext, tag);
    return (ciphertext, nonce, tag);
}

// ✅ Prefer ASP.NET Core Data Protection for app secrets/cookies
// services.AddDataProtection().PersistKeysTo...();
```

Prefer **Data Protection API**, **Identity password hasher**, **AesGcm**, and **RandomNumberGenerator**. Never roll your own password scheme.

## Prevention Checklist

- [ ] Passwords: only PBKDF2 / bcrypt / Argon2 / Identity `PasswordHasher` — never raw MD5/SHA-*
- [ ] Secrets & tokens: `RandomNumberGenerator` only — never `System.Random` / `Guid` for security
- [ ] Symmetric crypto: AES-GCM (or AES-CBC + HMAC Encrypt-then-MAC); unique nonce/IV per message
- [ ] Keys: length ≥ 128-bit (prefer 256); store in Key Vault / DPAPI / env — never source control
- [ ] TLS: never disable certificate validation in production; pin only with deliberate allow-list + rotation
- [ ] Algorithms: ban MD5, SHA-1 (integrity), DES/3DES, RC4, ECB mode via code review / analyzers
- [ ] Use `Microsoft.AspNetCore.Cryptography.KeyDerivation` or well-reviewed libraries
- [ ] Enable CA / security analyzers (CA5350, CA5351, etc.) and fail CI on findings

## Real CVEs / Case References

| CVE / Advisory | Summary | Link |
|----------------|---------|------|
| **CVE-2024-0057** | .NET / .NET Framework / Visual Studio **security feature bypass** around X.509 chain building APIs when apps do not fully validate certificates — classic incomplete crypto/PKI validation class of bug | https://nvd.nist.gov/vuln/detail/CVE-2024-0057 |
| **CVE-2020-1147** | .NET Framework / SharePoint / VS RCE via unsafe XML/`DataSet`/`DataTable` deserialization paths (often chained with legacy formatters) — shows how “trusted” platform serialization + crypto-adjacent trust assumptions fail | https://nvd.nist.gov/vuln/detail/CVE-2020-1147 |
| **BinaryFormatter removal (.NET 9)** | Microsoft deprecated and removed `BinaryFormatter` due to inherent unsafe deserialization (not a single CVE, but the platform response to years of CWE-502 issues) | https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide |
| **MSRC CVE-2024-0057 advisory** | Official impact and updates for certificate chain validation bypass | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0057 |

Related in this bank: [aspnet-data-protection.md](aspnet-data-protection.md), [deserialization.md](deserialization.md), [2024-cve-roundup-dotnet.md](2024-cve-roundup-dotnet.md).

## Vibe Coding Red Flags

| Red flag in AI output | Why it matters |
|----------------------|----------------|
| `MD5` / `SHA1` / `SHA256(password)` | Password cracking / collision / no salt |
| `new Random()` for tokens, OTP, keys | Predictable stream after seed leak |
| Fixed IV / `"mysecretkey12345"` in code | Total crypto collapse if binary is reverse-engineered |
| `CipherMode.ECB` or default CBC without MAC | Block patterns / padding oracles |
| `DangerousAcceptAnyServerCertificateValidator` | MITM |
| `RijndaelManaged` copy-paste from 2012 blog | Obsolete patterns, wrong defaults |
| “Simple AES encrypt decrypt helper” one-liners | Almost always missing key management + AEAD |
| Comment: `// TODO: use real key in prod` shipped | Keys never rotated, still weak |

**Rule of thumb for prompts:**  
*“Use AesGcm or ASP.NET Data Protection; PasswordHasher for passwords; RandomNumberGenerator for tokens; never disable TLS validation; never MD5/SHA for passwords.”*

---

**Severity: 🔴 High–Critical** — credential compromise, session forgery, MITM, mass PII exposure.  
**CWE: CWE-327 / CWE-328 / CWE-330 / CWE-347**
