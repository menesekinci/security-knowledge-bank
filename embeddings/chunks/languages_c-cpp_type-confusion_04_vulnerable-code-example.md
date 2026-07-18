---
source: "languages/c-cpp/type-confusion.md"
title: "Type Confusion (C/C++)"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

```cpp
// Type confusion via untrusted message dispatch
struct Message { int type; char data[64]; };
struct LoginMsg  { char user[32]; char pass[32]; };
struct AdminMsg  { char command[64]; };

void dispatch(Message *m) {
    if (m->type == 1) {
        auto *login = static_cast<LoginMsg*>(static_cast<void*>(m));
        process_login(login);
    } else if (m->type == 2) {
        auto *admin = static_cast<AdminMsg*>(static_cast<void*>(m));
        execute(admin->command); // Attacker sets type=2 with LoginMsg payload
    }
    // No default/else — corrupted type field or type=3 passes silently
}
```

**Windows kernel-mode example:**

```c
// KMDF driver vulnerable to type confusion
NTSTATUS DispatchIoControl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = stack->Parameters.DeviceIoControl.Type3InputBuffer; // void*
    
    // No type discrimination — casts based on IoControlCode only
    struct RequestA *reqA = (struct RequestA*)buf;
    struct RequestB *reqB = (struct RequestB*)buf; // same buffer, different layout
}
```

---