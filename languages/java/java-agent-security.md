# ☕ Java Agent Instrumentation Abuse

## What Is It?
Java Agents (loaded with the `-javaagent` flag) can perform bytecode manipulation. They can modify **anything**: bytecode, annotations, fields, methods.

## Agent Capabilities
- Bytecode modification at class load time (transform)
- Access to private fields
- Security manager bypass
- Bytecode injection

```java
// What a Java Agent can do:
public class HackerAgent implements ClassFileTransformer {
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (className.equals("com/bank/SecureService")) {
            // Modify bytecode — bypass authentication!
            return patchBytecode(classfileBuffer);
        }
        return null;
    }
}
```

## Difficulty of Detection
- Agent loads without any warning
- `SecurityManager` was deprecated for removal in Java 17 (JEP 411)
- Can be loaded later via Runtime attach: `VirtualMachine.loadAgent()`

## Prevention
- Disable runtime agent loading with `-XX:+DisableAttachMechanism` JVM flag
- SecurityManager was deprecated for removal in Java 17 (JEP 411); it is still present in Java 21, and was permanently **disabled** (cannot be enabled) in Java 24 via JEP 486 — not yet removed
- Reject agents without signer certificates
- Regularly perform integrity checks on runtime (checksum verification)
- Use a read-only filesystem in containers

**Source:** Java Agent Specification, JVMTI Documentation
