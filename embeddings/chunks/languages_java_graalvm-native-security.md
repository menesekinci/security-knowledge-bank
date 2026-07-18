---
source: "languages/java/graalvm-native-security.md"
title: "☕ GraalVM Native Image Security"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [config, dynamic, java, language-vuln, limits, prevention, proxy, reflection, serialization, what]
---

# ☕ GraalVM Native Image Security

## What Is It?
GraalVM native image compiles Java bytecode **AOT (Ahead-of-Time)**. Java features like reflection, serialization, and dynamic class loading are **limited** or require special configuration.

## Reflection Config
Reflection does not work in native images — you cannot access classes unknown at compile-time at runtime.
```java
// VULNERABLE assumption:
// "Native image is safe because it blocks reflection"

// Reality: you can enable it via reflection-config.json
// If json has {"name":"java.lang.Runtime"} → RCE!
```

## Serialization Limits
Serialization in native images is done via JSON or custom serializers.
- Java native serialization (ObjectInputStream) **does not work**
- But if `SerializationFeature` is enabled, the risk returns

## Dynamic Proxy
Dynamic proxy in native images requires special configuration. Missing configuration = runtime crash.

## Prevention
- Whitelist only the classes you need in `reflect-config.json`
- Don't use serialization (not available in native image anyway)
- Update libraries with `unsafe` access (Log4j, Spring)
- Native image has no dynamic class loading — use this as a security advantage
- Test with `-H:+ReportUnsupportedElementsAtRuntime`

**Source:** GraalVM Security Guide, CVE-2025-30761
