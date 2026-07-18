---
source: "languages/c-cpp/insecure-random.md"
title: "Insecure Randomness (C/C++)"
heading: "Secure Code Fix"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 5/8
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