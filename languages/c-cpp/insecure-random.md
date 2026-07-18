# Insecure Randomness (C/C++)

> **Severity:** High
> **CWE:** CWE-330 (Use of Insufficiently Random Values), CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator)
> **AI Generation Risk:** Very High — AI defaults to `rand()` / `srand(time(NULL))`

---

## Vulnerability Explanation

`rand()`, constant seeds, or LCG (Linear Congruential Generator) PRNGs are **not** suitable for security-sensitive contexts: session tokens, API keys, password reset links, CSRF tokens, cryptographic key material, or lottery/payment logic. The values they produce are predictable — if an attacker knows (or can guess) the seed and the algorithm, they can reconstruct the entire sequence.

Key weaknesses of `rand()`:

- **Deterministic LCG:** Uses `state = state * 1103515245 + 12345` (glibc) — fully reversible with a few outputs
- **Small state space:** Typically 31 or 32 bits — brute-forceable
- **`time(NULL)` seed:** Granularity of 1 second — an attacker narrows the seed to a tiny window
- **Thread-safety issues:** `rand()` uses global mutable state — undefined behavior under concurrent access
- **Poor statistical distribution:** Fails Diehard/Dieharder tests for randomness

Beyond `rand()`, common insecure patterns include:

- Sleep-based seeding: `srand(time(NULL) + getpid());` — still just ~1M combinations
- `std::mt19937` for security: Mersenne Twister is **not** a CSPRNG — its 624-byte state can be cloned after observing 624 consecutive outputs
- `std::default_random_engine` — implementation-defined, often a simple LCG
- Hardware RNG fallback: using `/dev/random` blocking incorrectly, or falling back to `rand()` when `/dev/urandom` is unavailable
- Seeding once at startup and assuming the sequence is "random enough" for the entire lifetime of the process

### Prediction Attack Vector

For `srand(time(NULL))`, an attacker can:

1. Record the server's timestamp from HTTP Date headers or TLS timestamps
2. Try seeds ±2 seconds around that time
3. Regenerate the first `rand()` call output
4. Predict the session ID or token

### Windows-Specific Concerns

On Windows, `rand()` is even weaker — MSVC's implementation uses a simple LCG with modulus 2^31. Better alternatives:

- **CryptGenRandom / BCryptGenRandom** (Win32 CSPRNG) — the correct Windows API
- **RtlGenRandom** (SystemFunction036) — simpler but deprecated
- **`/dev/urandom`** — available via WSL or MSYS; also use `getrandom()` on Linux
- **C++11 `std::random_device`** — may be deterministic on some MSVC implementations (check your standard library)

---

## How AI / Vibe Coding Generates This

```c
srand(time(NULL));
int token = rand();
```

Appears in countless tutorials; models reproduce it for "OTP" and "API keys".

```cpp
// AI-generated "secure token" — actually trivial to predict
#include <cstdlib>
#include <ctime>

std::string generate_token() {
    srand(static_cast<unsigned>(time(nullptr)));
    int val = rand();
    return std::to_string(val);
}
```

Models trained on StackOverflow data frequently suggest:

- `srand(time(0))` for "unique" identifiers
- `rand() % N` for "random selection" in security contexts
- `std::default_random_engine` seeded with `time(0)` in "encryption" code
- Rolling-your-own XOR-shift or LCG for "lightweight crypto"

---

## Vulnerable Code Example

```c
// Session ID generation — 8 hex chars from rand() = 32 bits entropy
char session_id[9];
sprintf(session_id, "%08x", rand()); // Predictable within seconds
```

```cpp
// C++17 AI-generated "random password" — all predictable
#include <random>
#include <iostream>

std::string generate_password(int len) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(std::random_device{}()); // std::random_device may be deterministic!
    std::uniform_int_distribution<> dist(0, sizeof(charset)-2);
    std::string pwd;
    for (int i = 0; i < len; i++) pwd += charset[dist(rng)];
    return pwd;
}
```

**Why this is still weak:** `std::random_device` on some platforms (MinGW, older MSVC) returns a deterministic sequence — it is not guaranteed to be a CSPRNG. The C++ standard only says it should be "non-deterministic" where possible, but does not mandate cryptographic quality.

```c
// Router WPS PIN generation — real-world (CVE-2016-10180)
srand(time(0));
unsigned int pin = rand(); // D-Link DWR-932B
```

---

## Secure Code Fix

### Linux / POSIX (recommended — uses OS CSPRNG)

```c
#include <fcntl.h>
#include <unistd.h>

int secure_random_bytes(void *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (char*)buf + off, n - off);
        if (r <= 0) { close(fd); return -1; }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}
```

### Linux with `getrandom()` (modern, no fd leak risk)

```c
#include <linux/random.h>
#include <sys/random.h>

int secure_random_bytes(void *buf, size_t n) {
    return getrandom(buf, n, 0) == (ssize_t)n ? 0 : -1;
}
```

### Windows — `BCryptGenRandom`

```c
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

int secure_random_bytes(void *buf, size_t n) {
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
           >= 0 ? 0 : -1;
}
```

### Windows — `CryptGenRandom` (legacy)

```c
#include <windows.h>
#include <wincrypt.h>

int secure_random_bytes(void *buf, size_t n) {
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return -1;
    BOOL ok = CryptGenRandom(hProv, (DWORD)n, (BYTE*)buf);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
}
```

### C++17+ with guaranteed CSPRNG wrapper

```cpp
#include <array>
#include <algorithm>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

std::array<unsigned char, 32> generate_secure_key() {
    std::array<unsigned char, 32> key;
#if defined(_WIN32)
    if (BCryptGenRandom(NULL, key.data(), (ULONG)key.size(),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::system_error(errno, std::generic_category(), "BCryptGenRandom");
#else
    if (getrandom(key.data(), key.size(), 0) != (ssize_t)key.size())
        throw std::system_error(errno, std::generic_category(), "getrandom");
#endif
    return key;
}
```

### C++ — if you must use `<random>`, always verify `std::random_device::entropy()`

```cpp
#include <random>
#include <iostream>

std::random_device rd;
if (rd.entropy() < 32.0) {
    std::cerr << "Warning: random_device entropy too low — consider OS CSPRNG\n";
    // Fall back to OS-specific API
}
```

**Rule of thumb:** For security contexts, bypass `<random>` entirely and call the OS CSPRNG.

---

## Prevention Checklist

- [ ] Never `rand()` / `srand()` for security
- [ ] Use OS CSPRNG: `/dev/urandom`, `getrandom()`, `BCryptGenRandom`, `SecRandomCopyBytes`
- [ ] Session IDs / tokens must have ≥ 128 bits of entropy
- [ ] Code review ban-list: `srand`, `rand`, `mt19937` for security, `std::default_random_engine`
- [ ] Verify `std::random_device::entropy()` on every platform you target
- [ ] Never use `time()` as seed for security PRNG — attacker can narrow to ±1 second
- [ ] Avoid sleep-based "randomization" — `srand(time(NULL) + usleep(rand()%1000))` is still predictable
- [ ] Test with `ent` or Dieharder on your RNG output before relying on it for crypto
- [ ] Use `secrets`-style API where available (Python `secrets`, C++ wrapper over OS CSPRNG)
- [ ] Guard against fd exhaustion: always check `/dev/urandom` open/read return values

---

## Real-World CVEs / References

| CVE | Vulnerability | Impact | Ref |
|-----|--------------|--------|-----|
| CVE-2008-0166 | Debian OpenSSL PRNG broken by patched-out entropy calls | SSH keys reduced to ~32768 possibilities; millions of keys compromised globally | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2008-0166), [Debian DSA-1571](https://www.debian.org/security/2008/dsa-1571), [badkeys.info](https://badkeys.info/docs/debian.html) |
| CVE-2013-7372 | Android `SecureRandom` incorrect offset — predictable Bitcoin wallet key generation | Bitcoin wallets on Android compromised; cryptocurrency theft | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2013-7372), [Guardian report](https://www.theguardian.com/technology/2013/aug/15/google-android-bitcoin-securerandom-vulnerability) |
| CVE-2016-10180 | D-Link DWR-932B router WPS PIN uses `srand(time(0))` | Predictable WPS PIN via epoch-time seed (CVSS 7.5) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2016-10180), [CWE-337](https://cwe.mitre.org/data/definitions/337.html) |
| CVE-2022-39218 | Fastly Compute@Edge JS runtime uses fixed random seed for WebAssembly `Math.random` | Attacker can predict random numbers to bypass cryptographic controls | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-39218) |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Use of Cryptographically Weak Pseudo-Random Number Generator | Category reference | |
| [CWE-335](https://cwe.mitre.org/data/definitions/335.html) | Incorrect Usage of Seeds in Pseudo-Random Number Generator | Category reference | |

The Debian OpenSSL bug (CVE-2008-0166) remains the most devastating RNG failure in history. A single line change — commenting out `#define DEVRANDOM` — made all OpenSSL keys generated on Debian/Ubuntu systems between September 2006 and May 2008 predictable. Compromised keys are still found in the wild on IoT devices running outdated firmware, and the [badkeys](https://badkeys.info/) project maintains a database of affected keys.

---

## Vibe-Coding Red Flags

- `srand(time(NULL))` anywhere near authentication, tokens, or keys
- Token generation with `% 1000000` or `% 99999` — tiny output space
- "Random" UUID v1 used as a secret — v1 is timestamp-based and fully predictable
- `rand()` casting to `char` for password generation — trivial to brute-force
- `std::mt19937` seeded with `std::random_device{}()` used for "encryption" or "token generation"
- Self-rolled PRNGs (XOR-shift, LCG hand-tuned) in security contexts
- `std::random_device {}()` used without checking `entropy()`
- Hardcoded or file-loaded seeds for "deterministic testing" deployed to production
- Using `std::shuffle` for "random" selection from a deck of cards or lottery numbers
- Sleeping between `srand` calls to "add randomness" — this only changes the seed by < 10 values
