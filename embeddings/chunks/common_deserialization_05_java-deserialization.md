---
source: "common/deserialization.md"
title: "Insecure Deserialization — Pickle, YAML, Java Serialization, JSON Attacks"
heading: "Java Deserialization"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [common-vuln, deserialization, java, pickle, python, vibe, what, yaml]
chunk: 5/10
---

## Java Deserialization

Java serialization is one of the **most exploited deserialization vectors** in history. Applications deserializing `ObjectInputStream` from untrusted sources can be exploited using "gadget chains" (popularized by ysoserial).

### Vulnerable Code

```java
import java.io.*;

// 🔴 VULNERABLE: direct deserialization from user input
public void deserializeUserData(byte[] userData) throws Exception {
    ByteArrayInputStream bis = new ByteArrayInputStream(userData);
    ObjectInputStream ois = new ObjectInputStream(bis);
    Object obj = ois.readObject();  // Can execute arbitrary code!
    ois.close();
}

// Used like: deserializeUserData(request.getParameter("data").getBytes());
```

### Fixed Code

```java
// ✅ SAFE: Validate before deserializing
public class SafeDeserializer {
    // Allowlist of safe classes
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "java.lang.String",
        "java.util.ArrayList",
        "java.util.HashMap",
        "com.myapp.UserProfile"
    );

    public static Object safeDeserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        // ✅ Use a filtered ObjectInputStream
        FilteredObjectInputStream ois = new FilteredObjectInputStream(bis);
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }

    // Custom ObjectInputStream with class filtering
    static class FilteredObjectInputStream extends ObjectInputStream {
        public FilteredObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException {
            if (!ALLOWED_CLASSES.contains(desc.getName())) {
                throw new InvalidClassException(
                    "Blocked class: " + desc.getName()
                );
            }
            return super.resolveClass(desc);
        }
    }
}
```

**Better approach:** Use a safe serialization format.

```java
// ✅ SAFEST: Use JSON instead of Java serialization
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
// Disable default typing (which enables polymorphic deserialization)
mapper.disableDefaultTyping();

// Serialize
String json = mapper.writeValueAsString(myObject);

// Deserialize
MyObject obj = mapper.readValue(json, MyObject.class);
```

---