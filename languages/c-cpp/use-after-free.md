# 🔴 Use-After-Free

## What Is It?

Continuing to access a memory block **after** it has been freed with `free()` or `delete`
through a pointer that still points to that location.

## Why Is It Common in Vibe Coding?

AI, especially with C legacy code or incorrect C++ patterns:
1. Forgets to set pointer to NULL after `free()`
2. Uses raw pointer + delete instead of `std::unique_ptr`
3. Captures dangling references in lambdas/callbacks
4. Doesn't resolve shared pointer cycles

## Example

```cpp
// 💀 AI's "handler":
class UserData {
public:
    std::string name;
    void process() { /* ... */ }
};

void handle_user() {
    UserData* user = new UserData();
    user->name = "admin";
    
    // ... some operations ...
    
    delete user;  // user is now freed!
    
    // Later:
    user->process();  // 💀 USE-AFTER-FREE!
    // user has been freed but is still being used
    // Either appears to work or crashes (UB)
}
```

## How It Works?

```
1. malloc() → [==== USERDATA ====] ← pointer points here
2. free()  → [===== FREE ========] ← memory freed, pointer still at old address
3. Attacker: malloc(can_exploit) → [== EXPLOIT DATA ==] ← SAME MEMORY!
4. user->process() → [== EXPLOIT DATA ==] ← security vulnerability 💀
```

## Secure Code

```cpp
// ✅ With modern C++:
void handle_user() {
    auto user = std::make_unique<UserData>();
    user->name = "admin";
    user->process();
    // unique_ptr automatically deletes, you cannot use it after
}

// ✅ Raw pointer rule:
delete user;
user = nullptr;  // Set to NULL!
// If you try to use user later → nullptr exception (safe crash)
```

## Prevention Methods

| What to Do? | Why? |
|-------------|------|
| Use smart pointers instead of raw pointer + delete | unique_ptr/shared_ptr manage automatically |
| Set pointer to nullptr after free/delete | Double use → crash (not exploit) |
| Test with sanitizers | Catch UAF with `-fsanitize=address` |
| Use `std::weak_ptr` | Break shared_ptr cycles |

---

**Severity: 🔴 Critical** — Heap manipulation leads to RCE.
**CWE: CWE-416 (Use After Free)**
