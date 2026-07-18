---
source: "languages/c-cpp/uninitialized-memory.md"
title: "Uninitialized Memory Use (C/C++)"
heading: "Vulnerable Code Example (realistic)"
category: "language-vuln"
language: "c-cpp"
severity: "high"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example (realistic)

### C — stack + heap info leak

```c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct UserResponse {
    int uid;
    int role;
    char name[32];
    /* padding may exist */
    char token[32];
};

/* 🔴 Sends entire struct including uninitialized token/padding */
void handle_login(int client_fd, int uid, const char *name) {
    struct UserResponse resp;  /* uninitialized */
    resp.uid = uid;
    resp.role = 1;
    strncpy(resp.name, name, sizeof(resp.name) - 1);
    resp.name[sizeof(resp.name) - 1] = '\0';
    /* forgot token and padding */

    write(client_fd, &resp, sizeof(resp));  /* 🔴 leak */
}

char *build_packet(size_t n) {
    char *buf = malloc(n);     /* 🔴 uninitialized heap */
    if (!buf) return NULL;
    /* only fill first 4 bytes */
    buf[0] = 'O'; buf[1] = 'K'; buf[2] = '\n'; buf[3] = '\0';
    return buf; /* caller may send all n bytes */
}

int check_access(void) {
    int allowed;               /* 🔴 uninitialized */
    if (getuid() == 0) {
        allowed = 1;
    }
    /* non-root: allowed never set */
    return allowed;            /* UB / random allow */
}
```

### C++ — trivial member left cold

```cpp
struct Config {
    bool enforce_tls;
    int max_conn;
    // AI forgot constructors
};

bool start_server(Config c) {
    if (c.enforce_tls) { /* 🔴 indeterminate if default-constructed poorly */
        /* ... */
    }
    return true;
}

void vibe() {
    Config c; // members uninitialized for this trivial layout
    start_server(c);
}
```

---