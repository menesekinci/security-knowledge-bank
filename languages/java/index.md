# Java Security Overview (Enterprise Focus)

## Introduction

Java has been a cornerstone of enterprise development for over 25 years. Its security model is built around the **Java Virtual Machine (JVM)**, which provides memory safety (no buffer overflows, no use-after-free), bytecode verification, a strong type system, and the Security Manager (deprecated in JDK 17+). However, Java's extensive ecosystem and enterprise focus introduce unique vulnerability classes that AI-generated code regularly exploits.

## What Java Does Well for Security

- **Memory safety** — JVM eliminates buffer overflows, use-after-free, and double-free
- **Bytecode verification** — Class files are validated before execution
- **Strong typing** — Prevents type confusion at the language level
- **Standard crypto APIs** — JCA/JCE provides audited cryptographic primitives
- **Rich ecosystem** — Maven/Gradle with dependency management, mature security tooling (OWASP Dependency-Check, Snyk)
- **TLS by default** — `HttpsURLConnection` uses TLS

## The Java Security Gap

Java's biggest security weaknesses stem from its **enterprise framework ecosystem** and **legacy compatibility**:

1. **Deserialization** — Java's native serialization is inherently dangerous; RCE via gadget chains
2. **Expression languages** — SpEL, OGNL, MVEL injection in Spring/Struts
3. **XML processing** — XXE (XML External Entity) injection is enabled by default in many parsers
4. **JNDI injection** — Log4Shell (CVE-2021-44228) exploited JNDI lookups from log messages
5. **Reflection** — Powerful but can bypass access controls
6. **Verbose error handling** — Stack traces can leak implementation details
7. **Legacy crypto** — Support for weak algorithms for backward compatibility

## Why AI/Vibe Coding Makes Java Less Secure

AI models generate Java code that:

1. **Uses Spring Boot autoconfiguration** without understanding security implications — actuators on public endpoints, default secrets, H2 console exposed
2. **Skips input validation** — `@RequestParam String input` without `@Valid` or sanitization
3. **Uses raw JDBC / JPA** without parameterized queries
4. **Writes custom deserialization** code or uses `readObject()` on untrusted streams
5. **Disables security features** — `@EnableWebSecurity` with `permitAll()`, SSL verification disabled
6. **Imports outdated libraries** — Commons Collections 3.2.1 (deserialization RCE), Log4j < 2.17

## Key Vulnerability Categories in Java

| Category | Severity | Real-World Impact |
|---|---|---|
| Deserialization RCE | Critical | Commons-Collections, Fastjson, Jackson gadget chains |
| Log4Shell (JNDI injection) | Critical | CVE-2021-44228 — 10/10 CVSS, global incident |
| SpEL/OGNL injection | Critical | Spring4Shell, Struts2 RCE |
| Spring misconfiguration | High | Actuator leaks, autoconfiguration, H2 console |
| SQL injection | High | JDBC, JPA/Hibernate misuse |
| XXE | High | XML parsers enabled by default |
| JWT misuse | High | `algorithm: none`, weak keys |
| Supply chain | Critical | Maven Central typosquatting, dependency confusion |

## Real-World Incidents

- **CVE-2021-44228 (Log4Shell)**: CVSS 10.0 — JNDI injection in Log4j 2.x allowed unauthenticated RCE on millions of servers. The most impactful CVE of the 2020s.
- **CVE-2022-22965 (Spring4Shell)**: CVSS 9.8 — Spring Core RCE via class injection through data binding.
- **CVE-2021-45105 (Log4j DoS)**: CVSS 5.9 — Uncontrolled recursion from **self-referential Thread Context Map lookups** (not JNDI) caused a denial of service in Log4j 2.x.
- **CVE-2024-38808 (Spring SpEL)**: CVSS 4.3 — a crafted SpEL expression causes a **denial of service** (not RCE) in Spring Framework, only when the app evaluates user-supplied SpEL.
- **CVE-2015-7501 (Commons Collections)**: CVSS 9.8 — The deserialization gadget chain that started it all; allowed RCE on any Java app that deserializes untrusted data with Commons Collections 3.x on the classpath.

## Java-Specific Security Tools

| Tool | Purpose |
|---|---|
| OWASP Dependency-Check | Maven/Gradle plugin for known CVEs |
| Snyk | Commercial dependency scanning |
| FindSecBugs (SpotBugs + plugin) | Static analysis for security patterns |
| Semgrep | Customizable SAST rules for Java |
| Contrast Assess | IAST (Interactive Application Security Testing) |
| JDeps | Built-in dependency analysis |
| OWASP ZAP | DAST for Java web applications |

## Prevention Checklist

1. **Never deserialize untrusted data** — Use JSON/Protobuf instead of Java serialization
2. **Update Log4j to 2.17+** — And set `log4j2.formatMsgNoLookups=true`
3. **Use `@Valid` and Bean Validation** — Never accept raw `@RequestParam String`
4. **Disable Spring Boot actuator endpoints** in production — Or secure them behind authentication
5. **Use parameterized queries** — Always `PreparedStatement`, never `Statement` with concatenated SQL
6. **Disable XXE** — XML parsers must be configured with `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
7. **Restrict JNDI** — Set `com.sun.jndi.rmi.object.trustURLCodebase=false`
8. **Use modern crypto** — AES-GCM, SHA-256+, TLS 1.2+; avoid DES, RC4, MD5
9. **Run OWASP Dependency-Check** in CI — `mvn org.owasp:dependency-check-maven:check`
10. **Pin dependency versions** — Never use `[1.0,)` ranges; prefer `1.0.x`
