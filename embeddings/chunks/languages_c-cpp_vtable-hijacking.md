---
source: "languages/c-cpp/vtable-hijacking.md"
title: "🔴 VTable Hijacking via Type Confusion"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, chrome, cve-2024-5274, cve-2025-13223, cve-2025-13224, does, hijacking, language-vuln, vtable, what]
---

# 🔴 VTable Hijacking via Type Confusion

## What Is It?

In C++, virtual functions are dispatched through a **vtable** (virtual method table) pointer. Each polymorphic object carries a vtable pointer (vptr) in its memory.

**VTable hijacking** is when an attacker modifies an object's vptr to redirect virtual function calls to a table they control.

## How Does It Appear in Vibe Coding?

```
Prompt: "Write a polymorphic plugin system"
AI: "Uses base class + virtual functions.
     But doesn't consider downcast safety!"
```

## 1. VTable Hijacking via Type Confusion

Type confusion occurs when an object is used as the wrong type. In C++, this happens when `static_cast` or C-style cast is used instead of `dynamic_cast`.

### Vulnerable Code

```cpp
// 💀 DANGEROUS — static_cast instead of dynamic_cast
struct Base {
    virtual void doSomething() { std::cout << "Base\n"; }
};

struct Derived : Base {
    virtual void doSomething() override { std::cout << "Derived\n"; }
    void secretMethod() { /* sensitive operation */ }
};

void process(Base* obj) {
    // static_cast — NO runtime type check!
    Derived* d = static_cast<Derived*>(obj);
    d->secretMethod();  // If obj is not Derived, UB!
}

// Attacker:
Base b;
process(&b);  // static_cast to Derived* → vtable corruption!
```

## 2. CVE-2024-5274: Chrome V8 Type Confusion (Exploited in Wild)

**CVE:** CVE-2024-5274
**CVSS:** 8.8 (High)
**Source:** https://nvd.nist.gov/vuln/detail/cve-2024-5274

A type confusion vulnerability in the Google Chrome V8 JavaScript engine. A rare bug in the parser module allowed attackers to mislead the TurboFan JIT compiler into creating an object of the wrong type.

**All versions before Chrome 125.0.6422.112 are affected. Exploited in the wild.**

```
Vulnerability mechanism:
1. Deceive V8 parser → wrong type information
2. TurboFan JIT → wrong optimization
3. VTable-like dispatch bypass → RCE
```

**Source:** https://www.helpnetsecurity.com/2024/05/24/cve-2024-5274/
**Details:** https://www.darknavy.org/blog/cve_2024_5274_a_minor_flaw_in_v8_parser_leading_to_catastrophes/

## 3. CVE-2025-13223 & CVE-2025-13224: Chrome V8 Zero-Day Type Confusion

**CVE:** CVE-2025-13223 / CVE-2025-13224
**CVSS:** 8.8 (High)
**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-13223

Chrome V8 type confusion zero-day. CVE-2025-13223 **exploited in the wild** and added to the CISA KEV catalog.

```
Affected: Google Chrome < 142.0.7444.175
CVSS: 8.8 (High)
KEV: CISA Known Exploited Vulnerabilities
```

**Details:** https://www.sentrium.co.uk/labs/google-chrome-v8-type-confusion-zero-day-vulnerabilities-cve-2025-13223-cve-2025-13224
**CISA KEV:** https://windowsforum.com/threads/cve-2025-13223-kev-elevates-chrome-v8-type-confusion-to-urgent-priority.390216/

## 4. Classic VTable Hijacking Attack

```cpp
// 💀 DANGEROUS — VTable hijacking via buffer overflow
struct Animal {
    virtual void speak() { std::cout << "Animal\n"; }
};

struct Dog : Animal {
    virtual void speak() override { std::cout << "Woof!\n"; }
};

// Attacker's own vtable
struct FakeVtable {
    virtual void speak() {
        // Attacker's code
        system("calc.exe");
    }
};

void exploit() {
    Dog dog;
    // Change the vptr of dog object via buffer overflow
    // dog's vptr → points to FakeVtable's vtable
    Dog* dog_ptr = &dog;
    
    // Overflow (in a real exploit, heap overflow etc.)
    char buffer[sizeof(Dog)];
    FakeVtable fake;
    memcpy(buffer, &fake, sizeof(FakeVtable));  // vptr overwrite
    memcpy(dog_ptr, buffer, sizeof(Dog*));
    
    dog.speak();  // Not "Woof!" — "calc.exe" runs!
}
```

## 5. Real-World Exploit: VTable Hijacking in C++ Applications

### Web Browsers

VTable hijacking is most commonly used in web browsers:
- **Chrome** V8 engine — type confusion → vtable hijack → RCE
- **Firefox** SpiderMonkey — similar techniques
- **Internet Explorer** — MSHTML vtable hijacking

**Source:** https://cs.brown.edu/people/vpk/papers/vtpin.acsac16.pdf
**VTPin:** Binary-level solution for vtable hijacking protection

## 6. Protection Against VTable Hijacking

### C++ Level

```cpp
// ✅ SAFE — Use dynamic_cast
void process(Base* obj) {
    Derived* d = dynamic_cast<Derived*>(obj);
    if (!d) {
        throw std::runtime_error("Wrong type!");
    }
    d->secretMethod();
}

// ✅ SAFE — Mark classes as final
struct Base {
    virtual void doSomething() = 0;
    virtual ~Base() = default;
};

struct Derived final : Base {  // final — no further inheritance
    void doSomething() override { /* ... */ }
};
```

### Compiler Level

```cpp
// ✅ SAFE — CFG (Control Flow Guard) — MSVC
// Compile with /guard:cf

// ✅ SAFE — CFI (Control Flow Integrity) — Clang
// Compile with -fsanitize=cfi

// ✅ SAFE — SafeStack + CFI
// Compile with -fsanitize=safe-stack -fsanitize=cfi
```

### Binary Level

- **VTPin**: Binary instrumentation that protects vtable pointers
- **VTGuard**: MSVC's vtable integrity protection
- **CFG**: Windows Control Flow Guard

## 7. Real-World VTable Exploits

| CVE | Product | Year | Details |
|-----|---------|------|---------|
| CVE-2024-5274 | Chrome V8 | 2024 | Type confusion → RCE (wild) |
| CVE-2025-13223 | Chrome V8 | 2025 | Type confusion → RCE (wild, KEV) |
| CVE-2025-13224 | Chrome V8 | 2025 | Type confusion (internal) |
| CVE-2024-0517 | Chrome V8 | 2024 | OOB write → vtable corruption |

## References

- https://nvd.nist.gov/vuln/detail/cve-2024-5274
- https://nvd.nist.gov/vuln/detail/CVE-2025-13223
- https://cs.brown.edu/people/vpk/papers/vtpin.acsac16.pdf
- https://www.ndss-symposium.org/wp-content/uploads/2025-53-paper.pdf
- https://nebelwelt.net/files/18SyScan360-presentation.pdf
- https://defuse.ca/exploiting-cpp-vtables.htm
- https://download.vusec.net/papers/vtpin_acsac16.pdf
