---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "Out-of-Bounds Read"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 6/10
---

## Out-of-Bounds Read

Reading memory outside allocated buffer bounds — leaks sensitive data.

### Vulnerable Code

```c
int secret_key = 0xDEADBEEF;  // Sensitive data on stack

void read_array(int index) {
    int data[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    // 🔴 VULNERABLE: no bounds check
    int value = data[index];  // If index = -1 or index > 9 → reads adjacent memory
    printf("Value: %d\n", value);
    // index = -1 might read secret_key!
}

// Heartbleed bug was exactly this — reading extra bytes from a buffer
```

### Fixed Code

```c
void read_array(int index) {
    int data[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    // ✅ SAFE: bounds check
    if (index < 0 || index >= 10) {
        fprintf(stderr, "Index out of bounds\n");
        return;
    }
    int value = data[index];
    printf("Value: %d\n", value);
}
```

---