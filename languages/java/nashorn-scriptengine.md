# ☕ Java Nashorn ScriptEngine Abuse

## What Is It?
Nashorn is the JavaScript engine that came with Java 8+. It was deprecated in Java 15 and removed in Java 17. It was replaced by GraalVM JavaScript. Both have **sandbox escape** vulnerabilities.

## CVE-2024-20926 — Nashorn Sandbox Bypass
The Nashorn engine in Java 8 can bypass its sandbox when executing untrusted JavaScript code.
```java
// VULNERABLE:
ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
engine.eval(userInput);  // RCE!
// userInput = "java.lang.Runtime.getRuntime().exec('id')"
```

## CVE-2025-30761 — Nashorn Restriction Bypass (CVSS 5.9)
A restriction bypass in the JDK **Nashorn** engine (Oracle Java SE 8u451, 11.0.27; GraalVM EE 21.3.14). In a restricted Nashorn execution environment it allows reaching arbitrary Java objects and can lead to code execution. It is hard to exploit (high attack complexity) and impacts integrity only — a Medium-severity issue, **not** a 9.8 critical. Vector: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N`.

## Prevention Methods
- Do NOT use Nashorn/GraalVM ScriptEngine for untrusted input
- If you need a JavaScript engine: use context sandbox + `ClassFilter`
- Use Java 17+ (no Nashorn)
- For GraalVM: set `Context.Builder` with `allowAllAccess(false)`
- Use pre-compiled policy + allow list instead of ScriptEngine

```java
// SAFE GraalVM:
Context ctx = Context.newBuilder("js")
    .allowAllAccess(false)           // Block JVM access
    .allowHostAccess(HostAccess.NONE) // No host class access
    .allowIO(false)                   // No I/O
    .allowCreateThread(false)         // No threads
    .build();
ctx.eval("js", userInput);
```

**References:**
- CVE-2024-20926: https://nvd.nist.gov/vuln/detail/CVE-2024-20926
- CVE-2025-30761: NVD
